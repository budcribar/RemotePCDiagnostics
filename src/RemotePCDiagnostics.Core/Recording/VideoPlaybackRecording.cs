using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using RemotePCDiagnostics.Core.Stress;
using RemotePCDiagnostics.Core.VideoPlayback;

namespace RemotePCDiagnostics.Core.Recording;

/// <summary>
/// Passes the video playback test to the real decoders and counters and records what they answered (<see cref="RecordedCall.VideoKind"/>): the
/// clip, each stream's decoder, the first <see cref="MaxSamples"/> samples of each stream with how long each took to decode (so a replay is as
/// late as the PC was), how the stream ended, the engine loads, the process CPU times and the media sessions.
/// </summary>
public sealed class RecordingVideoPlaybackSource(IVideoPlaybackSource inner, CallRecorder recorder) : IVideoPlaybackSource
{
    public const int MaxSamples = 2000;

    public VideoClipInfo? Clip
    {
        get
        {
            var clip = inner.Clip;
            recorder.Add(RecordedCall.FromVideo(VideoPlaybackKeys.Clip, clip is null ? null : JsonSerializer.Serialize(clip), clip is null ? "missing" : null));
            return clip;
        }
    }

    public int SelfProcessId => inner.SelfProcessId;
    public int LogicalProcessors => inner.LogicalProcessors;

    public IVideoStreamDecoder OpenStream(int index)
    {
        try
        {
            var d = inner.OpenStream(index);
            recorder.Add(RecordedCall.FromVideo(VideoPlaybackKeys.Open(index), JsonSerializer.Serialize(d.Info)));
            return new Decoder(d, index, recorder);
        }
        catch (Exception ex)
        {
            recorder.Add(RecordedCall.FromVideo(VideoPlaybackKeys.Open(index), null, VideoPlaybackKeys.ErrorText(ex)));
            throw;
        }
    }

    public IGpuEngineMeter OpenEngineMeter() => new Meter(inner.OpenEngineMeter(), inner.SelfProcessId, recorder);

    public IReadOnlyList<MediaProcess> ReadProcesses()
    {
        var list = inner.ReadProcesses();
        recorder.Add(RecordedCall.FromVideo(VideoPlaybackKeys.Processes, JsonSerializer.Serialize(new ProcessesAnswer(inner.SelfProcessId, inner.LogicalProcessors, list))));
        return list;
    }

    public IReadOnlyList<MediaSessionInfo> ReadMediaSessions()
    {
        var list = inner.ReadMediaSessions();
        recorder.Add(RecordedCall.FromVideo(VideoPlaybackKeys.Sessions, JsonSerializer.Serialize(list)));
        return list;
    }

    internal sealed record ProcessesAnswer(int Self, int Cores, IReadOnlyList<MediaProcess> Processes);
    internal sealed record EnginesAnswer(int Self, IReadOnlyList<GpuEngineLoad> Loads);
    /// <summary>One stream's samples: kind (v/a), timestamp, decode time in ms, on the graphics chip; and the error it ended with.</summary>
    internal sealed record SamplesAnswer(List<RecordedSample> Samples, string? Error);
    internal sealed record RecordedSample(char K, double T, double D, bool G);

    private sealed class Meter(IGpuEngineMeter inner, int self, CallRecorder recorder) : IGpuEngineMeter
    {
        public IReadOnlyList<GpuEngineLoad> Sample()
        {
            var loads = inner.Sample();
            recorder.Add(RecordedCall.FromVideo(VideoPlaybackKeys.Engines, JsonSerializer.Serialize(new EnginesAnswer(self, loads))));
            return loads;
        }

        public void Dispose() => inner.Dispose();
    }

    private sealed class Decoder(IVideoStreamDecoder inner, int index, CallRecorder recorder) : IVideoStreamDecoder
    {
        private readonly List<RecordedSample> _samples = [];
        private string? _error;
        private int _saved;
        public VideoStreamInfo Info => inner.Info;

        public DecodedSample Next()
        {
            var sw = Stopwatch.StartNew();
            try
            {
                var s = inner.Next();
                if (_samples.Count < MaxSamples)
                    _samples.Add(new RecordedSample(s.Kind == DecodedSampleKind.Audio ? 'a' : 'v', Math.Round(s.Timestamp.TotalMilliseconds, 2), Math.Round(sw.Elapsed.TotalMilliseconds, 2), s.OnGraphicsChip));
                return s;
            }
            catch (Exception ex)
            {
                _error = VideoPlaybackKeys.ErrorText(ex);
                Save();
                throw;
            }
        }

        private void Save()
        {
            if (Interlocked.Exchange(ref _saved, 1) == 0)
                recorder.Add(RecordedCall.FromVideo(VideoPlaybackKeys.Samples(index), JsonSerializer.Serialize(new SamplesAnswer(_samples, _error))));
        }

        public void Dispose()
        {
            Save();
            inner.Dispose();
        }
    }
}

/// <summary>The keys of the video playback test's answers in a recording.</summary>
public static class VideoPlaybackKeys
{
    public const string Clip = "clip", Engines = "engines", Processes = "processes", Sessions = "sessions";
    public const string LostPrefix = "lost: ", UnsupportedPrefix = "unsupported: ", CouldNotRunPrefix = "unavailable: ";
    public static string Open(int index) => "open\n" + index.ToString(CultureInfo.InvariantCulture);
    public static string Samples(int index) => "samples\n" + index.ToString(CultureInfo.InvariantCulture);

    public static string ErrorText(Exception ex) => ex switch
    {
        GpuDeviceLostException => LostPrefix + ex.Message,
        VideoPlaybackUnavailableException { NotSupported: true } => UnsupportedPrefix + ex.Message,
        VideoPlaybackUnavailableException => CouldNotRunPrefix + ex.Message,
        _ => ex.Message,
    };

    public static Exception ToException(string error) =>
        error.StartsWith(LostPrefix, StringComparison.Ordinal) ? new GpuDeviceLostException(error[LostPrefix.Length..])
        : error.StartsWith(UnsupportedPrefix, StringComparison.Ordinal) ? new VideoPlaybackUnavailableException(error[UnsupportedPrefix.Length..])
        : error.StartsWith(CouldNotRunPrefix, StringComparison.Ordinal) ? new VideoPlaybackUnavailableException(error[CouldNotRunPrefix.Length..], notSupported: false)
        : new InvalidOperationException(error);
}

/// <summary>
/// The video playback test from a recording. Each stream plays its recorded samples again, waiting as long as each took to decode, then loops
/// them; one that ended with an error ends with it again. A stream the recording doesn't have plays stream 1's samples. The engine loads,
/// processes and sessions come back in the order they were recorded, with this app's recorded process id.
/// </summary>
internal sealed class ReplayVideoPlaybackSource(RecordingReplay replay) : IVideoPlaybackSource
{
    private int? _self, _cores;

    public VideoClipInfo? Clip => replay.AnswerFor(RecordingReplay.VideoKey(VideoPlaybackKeys.Clip), "video clip") is { StdOut: { } json }
        ? JsonSerializer.Deserialize<VideoClipInfo>(json) : null;

    public int SelfProcessId => _self ??= replay.PeekFor(RecordingReplay.VideoKey(VideoPlaybackKeys.Processes)) is { StdOut: { } json }
        ? JsonSerializer.Deserialize<RecordingVideoPlaybackSource.ProcessesAnswer>(json)!.Self
        : replay.PeekFor(RecordingReplay.VideoKey(VideoPlaybackKeys.Engines)) is { StdOut: { } e } ? JsonSerializer.Deserialize<RecordingVideoPlaybackSource.EnginesAnswer>(e)!.Self : -1;

    public int LogicalProcessors => _cores ??= replay.PeekFor(RecordingReplay.VideoKey(VideoPlaybackKeys.Processes)) is { StdOut: { } json }
        ? JsonSerializer.Deserialize<RecordingVideoPlaybackSource.ProcessesAnswer>(json)!.Cores : 1;

    public IVideoStreamDecoder OpenStream(int index)
    {
        var at = replay.PeekFor(RecordingReplay.VideoKey(VideoPlaybackKeys.Open(index))) is null ? 1 : index;
        var open = replay.AnswerFor(RecordingReplay.VideoKey(VideoPlaybackKeys.Open(at)), $"video open {at}")
            ?? throw new VideoPlaybackUnavailableException("Not in the recording.", notSupported: false);
        if (open.Error is { } error) throw VideoPlaybackKeys.ToException(error);
        var info = JsonSerializer.Deserialize<VideoStreamInfo>(open.StdOut!)!;
        var samples = replay.PeekFor(RecordingReplay.VideoKey(VideoPlaybackKeys.Samples(at))) is { StdOut: { } s }
            ? JsonSerializer.Deserialize<RecordingVideoPlaybackSource.SamplesAnswer>(s)! : new RecordingVideoPlaybackSource.SamplesAnswer([], null);
        return new Decoder(info, samples);
    }

    public IGpuEngineMeter OpenEngineMeter() => new Meter(replay);

    public IReadOnlyList<MediaProcess> ReadProcesses() =>
        replay.AnswerFor(RecordingReplay.VideoKey(VideoPlaybackKeys.Processes), "video processes") is { StdOut: { } json }
            ? JsonSerializer.Deserialize<RecordingVideoPlaybackSource.ProcessesAnswer>(json)!.Processes : [];

    public IReadOnlyList<MediaSessionInfo> ReadMediaSessions() =>
        replay.AnswerFor(RecordingReplay.VideoKey(VideoPlaybackKeys.Sessions), "video sessions") is { StdOut: { } json }
            ? JsonSerializer.Deserialize<List<MediaSessionInfo>>(json) ?? [] : [];

    private sealed class Meter(RecordingReplay replay) : IGpuEngineMeter
    {
        public IReadOnlyList<GpuEngineLoad> Sample() =>
            replay.AnswerFor(RecordingReplay.VideoKey(VideoPlaybackKeys.Engines), "video engines") is { StdOut: { } json }
                ? JsonSerializer.Deserialize<RecordingVideoPlaybackSource.EnginesAnswer>(json)!.Loads : [];

        public void Dispose() { }
    }

    private sealed class Decoder(VideoStreamInfo info, RecordingVideoPlaybackSource.SamplesAnswer answer) : IVideoStreamDecoder
    {
        private int _next;
        private TimeSpan _offset;
        public VideoStreamInfo Info => info;

        public DecodedSample Next()
        {
            if (_next >= answer.Samples.Count)
            {
                if (answer.Error is { } error) throw VideoPlaybackKeys.ToException(error);
                if (answer.Samples.Count == 0) throw new InvalidOperationException("No samples in the recording.");
                // Loop: the next pass starts one frame after the last recorded sample.
                _offset += TimeSpan.FromMilliseconds(answer.Samples[^1].T + 1000 / Math.Max(1, info.FramesPerSecond));
                _next = 0;
            }
            var s = answer.Samples[_next++];
            if (s.D >= 1) Thread.Sleep(TimeSpan.FromMilliseconds(s.D));
            return new DecodedSample(s.K == 'a' ? DecodedSampleKind.Audio : DecodedSampleKind.Video, _offset + TimeSpan.FromMilliseconds(s.T), s.G);
        }

        public void Dispose() { }
    }
}
