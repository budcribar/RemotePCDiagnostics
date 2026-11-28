using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Core.VideoPlayback;

/// <summary>
/// Playback stress: plays copies of the bundled clip at once, each on its own decoder and thread, paced to real time like a player (decoding
/// at most <see cref="VideoPlaybackOptions.Lookahead"/> ahead). Each frame is timed against the moment it is due: after it = late, more than a
/// frame after it = dropped. Audio is paced the same way and a late audio buffer counts as a glitch (a gap you would hear). Once a second the
/// run reads this app's video decode engine load and the GPU temperature, and adds or removes streams to match <c>targetStreams</c>. It
/// stops at the time limit, on Cancel, on a driver reset, or at a critical temperature, and always stops and frees every decoder.
/// </summary>
public sealed class VideoPlaybackTest(
    IVideoPlaybackSource source, ISensorProvider? sensors = null, IStressClock? clock = null, Func<int, IStressClock>? streamClock = null, ILogger? log = null)
{
    public async Task<VideoPlaybackResult> RunAsync(VideoPlaybackOptions o, Func<int> targetStreams, IProgress<VideoPlaybackProgress>? progress, CancellationToken ct)
    {
        var clk = clock ?? new StopwatchStressClock();
        var start = clk.Elapsed;
        var duration = VideoPlaybackOptions.ClampDuration(o.Duration);
        var clip = source.Clip;
        if (clip is null)
            return new VideoPlaybackResult(VideoPlaybackOutcome.CouldNotRun, TimeSpan.Zero, null, [], 0, null, null, null, null, "The test video is missing from this install. Reinstall the app.");

        var streams = new List<Stream>();
        var finished = new List<VideoStreamResult>();
        IGpuEngineMeter? meter = null;
        try { meter = source.OpenEngineMeter(); meter.Sample(); }
        catch (Exception ex) { log.Info($"Video playback: engine counters unavailable: {ex.Message}"); meter?.Dispose(); meter = null; }

        var sensorsOk = SensorsAvailable();
        double? startTemp = null, maxTemp = null, lastTemp = null, lastDecode = null, decodePeak = null;
        double decodeSum = 0;
        int decodeSamples = 0, most = 0, openCap = VideoPlaybackOptions.MaxStreams;
        bool hot = false, stopped = false;
        VideoPlaybackOutcome? fatal = null;
        string? reason = null;
        if (sensorsOk) { var (t, _) = ReadSensors(); startTemp = maxTemp = lastTemp = t; }
        log.Info($"Video playback: start clip={clip.Label} streams={o.Streams} duration={duration}");

        try
        {
            var nextIndex = 1;
            while (true)
            {
                if (ct.IsCancellationRequested) { stopped = true; break; }
                var elapsed = clk.Elapsed - start;
                if (elapsed >= duration) break;

                // Collect streams that ended by themselves (decoder failure, driver reset): either fails the run, so it stops there.
                foreach (var s in streams.Where(s => s.Done).ToList())
                {
                    streams.Remove(s);
                    var r = await s.StopAsync(VideoStreamEnd.Finished, o.StopTimeout).ConfigureAwait(false);
                    finished.Add(r);
                    if (r.End == VideoStreamEnd.DriverReset) { fatal = VideoPlaybackOutcome.DriverReset; reason = $"Stream {r.Index}: {r.Error}"; }
                    else if (r.End == VideoStreamEnd.Crashed && fatal is null) { fatal = VideoPlaybackOutcome.DecoderCrashed; reason = $"Stream {r.Index}: {r.Error}"; }
                }
                if (fatal is not null) break;

                // Match the number of streams the person asked for (+ and − work while it runs).
                var want = Math.Min(VideoPlaybackOptions.ClampStreams(targetStreams()), openCap);
                while (streams.Count < want)
                {
                    Stream s;
                    try { s = Stream.Start(nextIndex, source.OpenStream(nextIndex), o, streamClock?.Invoke(nextIndex) ?? new StopwatchStressClock(), elapsed, ct, log); }
                    catch (VideoPlaybackUnavailableException ex) when (streams.Count == 0 && finished.Count == 0)
                    {
                        log.Info($"Video playback: can't decode the clip: {ex.Message}");
                        return new VideoPlaybackResult(ex.NotSupported ? VideoPlaybackOutcome.NotSupported : VideoPlaybackOutcome.CouldNotRun, TimeSpan.Zero, clip, [], 0, null, null, startTemp, maxTemp, ex.Message);
                    }
                    catch (GpuDeviceLostException ex) { fatal = VideoPlaybackOutcome.DriverReset; reason = ex.Message; break; }
                    catch (Exception ex)
                    {
                        // More streams than the decoder can open: keep what runs and say so; at the very start it is a failure to run.
                        log.Warn($"Video playback: stream {nextIndex} didn't open: {ex.Message}");
                        if (streams.Count == 0 && finished.Count == 0)
                            return new VideoPlaybackResult(VideoPlaybackOutcome.CouldNotRun, TimeSpan.Zero, clip, [], 0, null, null, startTemp, maxTemp, "The video decoder didn't start: " + ex.Message);
                        reason ??= $"Only {streams.Count} streams could be opened at once ({ex.Message}).";
                        openCap = streams.Count; // don't retry every second
                        break;
                    }
                    streams.Add(s);
                    nextIndex++;
                }
                if (fatal is not null) break;
                while (streams.Count > want)
                {
                    var s = streams[^1];
                    streams.RemoveAt(streams.Count - 1);
                    finished.Add(await s.StopAsync(VideoStreamEnd.Removed, o.StopTimeout).ConfigureAwait(false));
                }
                most = Math.Max(most, streams.Count);

                if (meter is not null)
                {
                    try
                    {
                        var self = source.SelfProcessId;
                        var loads = meter.Sample().Where(l => l.ProcessId == self && l.IsVideoDecode).ToList();
                        // An engine type can have several instances (one per engine); the busiest is the load to show.
                        var d = loads.Count == 0 ? 0 : loads.Max(l => l.Percent);
                        lastDecode = d;
                        if (elapsed > TimeSpan.Zero) { decodeSum += d; decodeSamples++; decodePeak = Math.Max(decodePeak ?? 0, d); }
                    }
                    catch (Exception ex) { log.Info($"Video playback: engine sample failed: {ex.Message}"); }
                }
                if (sensorsOk)
                {
                    var (t, critical) = ReadSensors();
                    lastTemp = t;
                    if (t is { } tv) maxTemp = Math.Max(maxTemp ?? tv, tv);
                    if (critical) { hot = true; log.Warn("Video playback: stopping, critical temperature"); break; }
                }

                progress?.Report(new VideoPlaybackProgress(elapsed, duration, want, [.. finished, .. streams.Select(s => s.Result())], lastDecode, lastTemp));
                try { await clk.DelayAsync(o.Tick, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { stopped = true; break; }
            }
        }
        finally
        {
            foreach (var s in streams) finished.Add(await s.StopAsync(VideoStreamEnd.Finished, o.StopTimeout).ConfigureAwait(false));
            meter?.Dispose();
        }

        var ran = clk.Elapsed - start;
        var ordered = finished.OrderBy(s => s.Index).ToList();
        if (ordered.FirstOrDefault(s => s.End == VideoStreamEnd.Hung) is { } hung && fatal is null)
        {
            fatal = VideoPlaybackOutcome.DecoderCrashed;
            reason = $"Stream {hung.Index}'s decoder stopped responding.";
        }
        var result = new VideoPlaybackResult(VideoPlaybackOutcome.Passed, ran, clip, ordered, most,
            decodeSamples == 0 ? null : Math.Round(decodeSum / decodeSamples, 1), decodePeak is { } p ? Math.Round(p, 1) : null, startTemp, maxTemp, reason);
        var outcome = fatal ?? (stopped ? VideoPlaybackOutcome.Cancelled
            : result.WorstStreamDroppedPercent > o.DropFailPercent ? VideoPlaybackOutcome.TooManyDropped
            : hot ? VideoPlaybackOutcome.Overheated
            : result.SoftwareDecode ? VideoPlaybackOutcome.SoftwareDecode
            : result.Frames == 0 ? VideoPlaybackOutcome.CouldNotRun
            : VideoPlaybackOutcome.Passed);
        if (outcome == VideoPlaybackOutcome.CouldNotRun && result.Frames == 0) result = result with { Reason = reason ?? "No video frames were decoded." };
        log.Info($"Video playback: done outcome={outcome} streams={ordered.Count} most={most} frames={result.Frames} dropped={result.DroppedFrames} late={result.LateFrames} "
            + $"audioGlitches={result.AudioGlitches} decode={result.DecodeEngineAveragePercent}/{result.DecodeEnginePeakPercent}% maxTemp={maxTemp}");
        return result with { Outcome = outcome };
    }

    private bool SensorsAvailable()
    {
        if (sensors is null) return false;
        try { return sensors.CheckAvailability().IsAvailable; }
        catch (Exception ex) { log.Info($"Video playback: sensors unavailable: {ex.Message}"); return false; }
    }

    /// <summary>The GPU temperature (null when the PC reports none) and whether anything is at a critical temperature.</summary>
    private (double? Temp, bool Critical) ReadSensors()
    {
        try
        {
            var temps = sensors!.Read().Readings.Where(r => r.SensorType == SensorKind.Temperature && r.IsLive).ToList();
            var gpu = temps.Where(r => r.HardwareType == HardwareKind.Gpu).ToList();
            return (gpu.Count == 0 ? null : gpu.Max(r => r.Value), temps.Any(r => SensorThresholds.Evaluate(r) == SensorLevel.Critical));
        }
        catch (Exception ex) { log.Info($"Video playback: sensor read failed: {ex.Message}"); return (null, false); }
    }

    /// <summary>
    /// One stream: its own thread (a decoder call blocks), paced on its own clock. Counts are written by the stream thread and read by the
    /// run loop, so they are updated with Interlocked/Volatile and read as a snapshot.
    /// </summary>
    internal sealed class Stream
    {
        private readonly int _index;
        private readonly IVideoStreamDecoder _decoder;
        private readonly VideoPlaybackOptions _o;
        private readonly IStressClock _clock;
        private readonly TimeSpan _startedAt;
        private readonly ILogger? _log;
        private readonly CancellationTokenSource _stop;
        private Task _task = Task.CompletedTask;
        private long _frames, _late, _dropped, _onChip, _audio, _glitches, _worstLagTicks, _ranTicks;
        private volatile int _end = -1;
        private volatile string? _error;

        private Stream(int index, IVideoStreamDecoder decoder, VideoPlaybackOptions o, IStressClock clock, TimeSpan startedAt, CancellationToken ct, ILogger? log)
        {
            (_index, _decoder, _o, _clock, _startedAt, _log) = (index, decoder, o, clock, startedAt, log);
            _stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        }

        public static Stream Start(int index, IVideoStreamDecoder decoder, VideoPlaybackOptions o, IStressClock clock, TimeSpan startedAt, CancellationToken ct, ILogger? log)
        {
            var s = new Stream(index, decoder, o, clock, startedAt, ct, log);
            s._task = Task.Factory.StartNew(s.Loop, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
            return s;
        }

        /// <summary>The stream ended by itself (its decoder failed or the driver was reset).</summary>
        public bool Done => _task.IsCompleted;

        private void Loop()
        {
            var ct = _stop.Token;
            var start = _clock.Elapsed;
            var framePeriod = TimeSpan.FromSeconds(1 / Math.Max(1, _decoder.Info.FramesPerSecond));
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    var s = _decoder.Next();
                    var now = _clock.Elapsed - start;
                    var lag = now - s.Timestamp;
                    if (s.Kind == DecodedSampleKind.Video)
                    {
                        Interlocked.Increment(ref _frames);
                        if (s.OnGraphicsChip) Interlocked.Increment(ref _onChip);
                        if (lag > framePeriod) Interlocked.Increment(ref _dropped);
                        else if (lag > TimeSpan.Zero) Interlocked.Increment(ref _late);
                        if (lag.Ticks > Interlocked.Read(ref _worstLagTicks)) Interlocked.Exchange(ref _worstLagTicks, lag.Ticks);
                    }
                    else
                    {
                        Interlocked.Increment(ref _audio);
                        if (lag > TimeSpan.Zero) Interlocked.Increment(ref _glitches);
                    }
                    Interlocked.Exchange(ref _ranTicks, now.Ticks);
                    var wait = s.Timestamp - _o.Lookahead - now;
                    if (wait > TimeSpan.Zero)
                    {
                        try { _clock.DelayAsync(wait, ct).GetAwaiter().GetResult(); }
                        catch (OperationCanceledException) { break; }
                    }
                }
            }
            catch (GpuDeviceLostException ex)
            {
                _error = ex.Message;
                _end = (int)VideoStreamEnd.DriverReset;
                _log.Warn($"Video playback: stream {_index}: graphics driver reset: {ex.Message}");
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                _error = ex.Message;
                _end = (int)VideoStreamEnd.Crashed;
                _log.Warn($"Video playback: stream {_index}: decoder failed: {ex}");
            }
            catch (Exception ex)
            {
                _log.Info($"Video playback: stream {_index}: stopped with {ex.GetType().Name}: {ex.Message}");
            }
            finally
            {
                Interlocked.Exchange(ref _ranTicks, Math.Max(Interlocked.Read(ref _ranTicks), (_clock.Elapsed - start).Ticks));
            }
        }

        public VideoStreamResult Result(VideoStreamEnd? end = null) => new(_index, _startedAt, TimeSpan.FromTicks(Interlocked.Read(ref _ranTicks)),
            Interlocked.Read(ref _frames), Interlocked.Read(ref _late), Interlocked.Read(ref _dropped), Interlocked.Read(ref _onChip),
            Interlocked.Read(ref _audio), Interlocked.Read(ref _glitches), TimeSpan.FromTicks(Math.Max(0, Interlocked.Read(ref _worstLagTicks))),
            _decoder.Info.DecoderName, _end >= 0 ? (VideoStreamEnd)_end : end ?? VideoStreamEnd.Finished, _error);

        /// <summary>Stops the stream and frees its decoder. A decoder stuck in a call longer than <paramref name="timeout"/> is Hung; it is freed
        /// when that call returns.</summary>
        public async Task<VideoStreamResult> StopAsync(VideoStreamEnd end, TimeSpan timeout)
        {
            _stop.Cancel();
            var stoppedInTime = await Task.WhenAny(_task, Task.Delay(timeout)).ConfigureAwait(false) == _task;
            if (!stoppedInTime)
            {
                _log.Warn($"Video playback: stream {_index} didn't stop within {timeout.TotalSeconds:0} s");
                _ = _task.ContinueWith(_ => Free(), TaskScheduler.Default);
                return Result() with { End = VideoStreamEnd.Hung, Error = "The decoder stopped responding." };
            }
            Free();
            return Result(end);
        }

        private void Free()
        {
            try { _decoder.Dispose(); } catch (Exception ex) { _log.Info($"Video playback: stream {_index}: dispose failed: {ex.Message}"); }
            _stop.Dispose();
        }
    }
}
