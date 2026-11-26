using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using NAudio.CoreAudioApi;
using NAudio.Wave;
using RemotePCDiagnostics.Core.Audio;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// NAudio/WASAPI implementation of <see cref="IAudioIo"/> (shared mode, no OS dialogs). Mic and loopback capture use a polled
/// <see cref="AudioClient"/> so raw mode (IAudioClient2::SetClientProperties, AUDCLNT_STREAMOPTIONS_RAW) can be requested before
/// Initialize; playback uses <see cref="WasapiOut"/> at the device mix rate.
/// </summary>
public sealed class WasapiAudioIo(ILogger? log = null) : IAudioIo
{
    /// <summary>PKEY_Device_EnumeratorName ("USB", "BTHENUM", "HDAUDIO"…).</summary>
    private static readonly PropertyKey EnumeratorName = new(new Guid("a45c254e-df1c-4efd-8020-67d146a850e0"), 24);
    private static readonly Guid IeeeFloatSubtype = new("00000003-0000-0010-8000-00aa00389b71");
    private const int E_ACCESSDENIED = unchecked((int)0x80070005);
    private const int AUDCLNT_E_DEVICE_IN_USE = unchecked((int)0x8889000A);
    private const int AUDCLNT_E_DEVICE_INVALIDATED = unchecked((int)0x88890004);

    private void Log(string m) => log.Info("Audio: " + m);
    private void LogWarn(string m) => log.Warn("Audio: " + m);

    /// <summary>What a test changed on one endpoint so it could be heard, to put back afterwards.</summary>
    private sealed record LevelChange(MMDevice Device, string What, bool WasMuted, float? PreviousLevel);

    /// <summary>Unmutes the endpoint and raises its level to <paramref name="setTo"/> when below <paramref name="minLevel"/>, for the test only:
    /// <see cref="RestoreLevels"/> puts both back. Null when nothing was changed.</summary>
    private LevelChange? EnsureAudible(MMDevice dev, string what, float minLevel, float setTo)
    {
        try
        {
            var vol = dev.AudioEndpointVolume;
            if (vol is null) return null;
            var wasMuted = vol.Mute;
            float? prev = null;
            if (wasMuted)
            {
                vol.Mute = false;
                Log($"{what} on '{dev.FriendlyName}' was muted. Unmuted for the audio test.");
            }
            if (vol.MasterVolumeLevelScalar < minLevel)
            {
                prev = vol.MasterVolumeLevelScalar;
                vol.MasterVolumeLevelScalar = setTo;
                Log($"{what} volume on '{dev.FriendlyName}' was {prev:P0}. Turned up to {setTo:P0} for the audio test.");
            }
            return wasMuted || prev is not null ? new LevelChange(dev, what, wasMuted, prev) : null;
        }
        catch (Exception ex)
        {
            LogWarn($"Could not inspect/adjust {what.ToLowerInvariant()} volume: {ex.Message}");
            return null;
        }
    }

    /// <summary>Puts back what <see cref="EnsureAudible"/> changed, and says so: a muted or nearly silent device is often the real fault.</summary>
    private string? RestoreLevels(params LevelChange?[] changes)
    {
        var notes = new List<string>();
        foreach (var c in changes)
        {
            if (c is null) continue;
            var found = c.WasMuted && c.PreviousLevel is { } p ? $"muted and its volume was {p:P0}"
                : c.WasMuted ? "muted" : $"at {c.PreviousLevel:P0} volume";
            try
            {
                var vol = c.Device.AudioEndpointVolume;
                if (c.PreviousLevel is { } level) vol.MasterVolumeLevelScalar = level;
                if (c.WasMuted) vol.Mute = true;
                notes.Add($"The {c.What.ToLowerInvariant()} was {found}. It was changed for the test and put back afterwards.");
            }
            catch (Exception ex)
            {
                LogWarn($"Could not restore {c.What.ToLowerInvariant()} volume: {ex.Message}");
                notes.Add($"The {c.What.ToLowerInvariant()} was {found}. It was changed for the test and couldn't be put back.");
            }
        }
        return notes.Count == 0 ? null : string.Join(" ", notes);
    }

    private static string? Join(string? a, string? b) => a is null ? b : b is null ? a : a + " " + b;

    public IReadOnlyList<AudioDevice> ListDevices()
    {
        var list = new List<AudioDevice>();
        using var en = new MMDeviceEnumerator();
        foreach (var (flow, kind) in new[] { (DataFlow.Render, AudioFlow.Output), (DataFlow.Capture, AudioFlow.Input) })
        {
            string? defaultId = null;
            try { if (en.TryGetDefaultAudioEndpoint(flow, Role.Multimedia, out var d)) { defaultId = d.ID; d.Dispose(); } } catch (Exception ex) { Log($"default {flow}: {ex.Message}"); }
            using var col = en.EnumerateAudioEndPoints(flow, DeviceState.Active);
            foreach (var dev in col)
            {
                try
                {
                    string? enumerator = null;
                    try { if (dev.Properties.TryGetValue<string>(EnumeratorName, out var v)) enumerator = v; } catch { }
                    var name = dev.FriendlyName;
                    list.Add(new AudioDevice(dev.ID, name, kind, AudioDevice.GuessBus(enumerator, name), dev.ID == defaultId));
                }
                catch (Exception ex) { LogWarn($"device read failed: {ex.Message}"); }
                finally { dev.Dispose(); }
            }
        }
        return list;
    }

    public bool IsMicrophoneBlockedByPrivacy()
    {
        // The same three switches the Sound check reads: device-wide (HKLM), the user's, and "Let desktop apps access your microphone".
        try { return CapturePrivacy.ReadAsync(new RemotePCDiagnostics.Core.DataSources.SystemRegistrySource(), CapturePrivacy.Microphone).GetAwaiter().GetResult().Blocked; }
        catch { return false; }
    }

    public Task<PlayCaptureResult> PlayAndCaptureAsync(PlayCaptureRequest r, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            using var en = new MMDeviceEnumerator();
            using var outDev = Device(en, r.OutputId, DataFlow.Render);
            using var inDev = Device(en, r.InputId, DataFlow.Capture);
            var speakerChange = EnsureAudible(outDev, "Speaker", 0.5f, 0.5f);
            var micChange = EnsureAudible(inDev, "Microphone", 0.6f, 0.8f);
            string? note = null;
            try
            {
            var toneTime = TimeSpan.FromSeconds((double)r.Tone.Length / r.SampleRate);

            async Task<Capture?> PlayWith(bool mic, bool loop)
            {
                using var micCap = mic ? Capture.Open(inDev, loopback: false, raw: r.RequestRawMic, log) : null;
                Capture? loopCap = null;
                if (loop)
                {
                    try { loopCap = Capture.Open(outDev, loopback: true, raw: false, log); }
                    catch (Exception ex) when (ex is not OperationCanceledException) { Log($"loopback unavailable: {ex.Message}"); note = "The app couldn't record the speaker output on this PC, so only the microphone was checked."; }
                }
                try
                {
                    micCap?.Start(); loopCap?.Start();
                    await Task.Delay(r.LeadIn, ct).ConfigureAwait(false);
                    var pos = 0;
                    await PlayAsync(outDev, r.SampleRate, span =>
                    {
                        var n = Math.Min(span.Length, r.Tone.Length - pos);
                        r.Tone.AsSpan(pos, n).CopyTo(span);
                        pos += n;
                        return n;
                    }, toneTime + TimeSpan.FromSeconds(2), ct).ConfigureAwait(false);
                    await Task.Delay(r.Tail, ct).ConfigureAwait(false);
                    micCap?.Stop(); loopCap?.Stop();
                    if (mic) { _micRaw = micCap!.RawApplied; _mic = micCap.Samples(); _micRate = micCap.SampleRate; }
                    return loopCap;
                }
                catch { loopCap?.Dispose(); throw; }
            }

            Capture? lc;
            if (r.HalfDuplex)
            {
                // One recording at a time: loopback pass, then microphone pass (two tone plays).
                lc = await PlayWith(mic: false, loop: true).ConfigureAwait(false);
                await PlayWith(mic: true, loop: false).ConfigureAwait(false);
            }
            else lc = await PlayWith(mic: true, loop: true).ConfigureAwait(false);
            PlayCaptureResult result;
            using (lc)
                result = new PlayCaptureResult(_mic, _micRate, lc?.Samples(), lc?.SampleRate ?? 0, _micRaw, note);
            return result with { Note = Join(result.Note, RestoreLevels(speakerChange, micChange)) };
            }
            finally
            {
                // Put back on cancel and error too (a second restore after the normal path is harmless: same values).
                RestoreLevels(speakerChange, micChange);
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { throw Map(ex); }
    }, ct);

    public Task<int> PlayOnChannelAsync(PlayChannelRequest r, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            // Mute and volume are left as they are: the person should hear what an app would (a muted speaker is the finding).
            using var en = new MMDeviceEnumerator();
            using var outDev = Device(en, r.OutputId, DataFlow.Render);
            var pos = 0;
            var only = r.Channel == AudioChannel.Left ? 0 : 1;
            var channels = await PlayAsync(outDev, r.SampleRate, span =>
            {
                var n = Math.Min(span.Length, r.Tone.Length - pos);
                r.Tone.AsSpan(pos, n).CopyTo(span);
                pos += n;
                return n;
            }, TimeSpan.FromSeconds((double)r.Tone.Length / r.SampleRate) + TimeSpan.FromSeconds(2), ct, only).ConfigureAwait(false);
            Log($"test sound on the {r.Channel.ToString().ToLowerInvariant()} channel of '{outDev.FriendlyName}' ({channels} channels)");
            return channels;
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { throw Map(ex); }
    }, ct);

    // Per-call state for PlayAndCaptureAsync (calls never overlap: DiagnosticsService runs a module once at a time).
    private float[] _mic = [];
    private int _micRate;
    private bool _micRaw;

    public Task<MonitorResult> MonitorAsync(MonitorRequest r, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            using var en = new MMDeviceEnumerator();
            using var outDev = Device(en, r.OutputId, DataFlow.Render);
            using var inDev = Device(en, r.InputId, DataFlow.Capture);
            var speakerChange = EnsureAudible(outDev, "Speaker", 0.5f, 0.5f);
            var micChange = EnsureAudible(inDev, "Microphone", 0.6f, 0.8f);
            try
            {
            using var stop = new CancellationTokenSource();
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, stop.Token);
            var queue = new ConcurrentQueue<float[]>();
            var stoppedEarly = false;
            var keep = r.HalfDuplex ? new List<float[]>() : null;
            var micRate = 0;
            using var mic = Capture.Open(inDev, loopback: false, raw: r.RequestRawMic, log, block =>
            {
                var blockGain = r.ProcessBlock(block, micRate);
                var gain = r.HalfDuplex ? 1.0f : AudioMath.ClampMonitorGain(blockGain);
                if (!r.HalfDuplex && gain <= 0) { stoppedEarly = true; try { stop.Cancel(); } catch { } return; }
                var scaled = new float[block.Length];
                for (var i = 0; i < block.Length; i++) scaled[i] = block[i] * gain;
                if (keep is not null) keep.Add(scaled);
                else { queue.Enqueue(scaled); while (queue.Count > 25) queue.TryDequeue(out _); } // keep monitor latency bounded
            }, keepSamples: false);
            micRate = mic.SampleRate;
            mic.Start();
            if (r.HalfDuplex)
            {
                try { await Task.Delay(r.Duration, linked.Token).ConfigureAwait(false); } catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
                mic.Stop();
                ct.ThrowIfCancellationRequested();
                var all = keep!.SelectMany(b => b).ToArray();
                AudioMath.ApplyFadeIn(all, mic.SampleRate / 5);
                var pos = 0;
                await PlayAsync(outDev, mic.SampleRate, span =>
                {
                    var n = Math.Min(span.Length, all.Length - pos);
                    all.AsSpan(pos, n).CopyTo(span);
                    pos += n;
                    return n;
                }, r.Duration + TimeSpan.FromSeconds(2), ct).ConfigureAwait(false);
            }
            else
            {
                // Pre-buffer a few blocks (~30-60 ms) so playback has a stable cushion and doesn't underflow at start
                var prebufferUntil = DateTime.UtcNow.AddMilliseconds(500);
                while (queue.Count < 3 && !linked.IsCancellationRequested && DateTime.UtcNow < prebufferUntil)
                {
                    await Task.Delay(10, linked.Token).ConfigureAwait(false);
                }

                float[]? cur = null; var curPos = 0; var played = 0; var fade = mic.SampleRate / 5;
                try
                {
                    await PlayAsync(outDev, mic.SampleRate, span =>
                    {
                        if (linked.IsCancellationRequested) return 0;
                        for (var i = 0; i < span.Length; i++)
                        {
                            if (cur is null || curPos >= cur.Length)
                            {
                                if (!queue.TryDequeue(out cur))
                                {
                                    var spun = 0;
                                    while (!queue.TryDequeue(out cur) && spun < 10)
                                    {
                                        Thread.SpinWait(50);
                                        spun++;
                                    }
                                    if (cur is null)
                                    {
                                        span[i] = 0;
                                        continue;
                                    }
                                }
                                curPos = 0;
                            }
                            var v = cur[curPos++];
                            if (played < fade) v *= (float)(0.5 - 0.5 * Math.Cos(Math.PI * played / fade));
                            played++;
                            span[i] = v;
                        }
                        return span.Length;
                    }, r.Duration, linked.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
                mic.Stop();
                ct.ThrowIfCancellationRequested();
            }
            return new MonitorResult(mic.SampleRate, mic.RawApplied, stoppedEarly, RestoreLevels(speakerChange, micChange));
            }
            finally { RestoreLevels(speakerChange, micChange); }
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { throw Map(ex); }
    }, ct);

    private static MMDevice Device(MMDeviceEnumerator en, string? id, DataFlow flow)
    {
        if (!string.IsNullOrEmpty(id)) return en.GetDevice(id);
        return en.TryGetDefaultAudioEndpoint(flow, Role.Multimedia, out var d) ? d : throw new AudioDeviceException(flow == DataFlow.Render ? "no speaker was found" : "no microphone was found");
    }

    private Exception Map(Exception ex)
    {
        Log("error: " + ex);
        var hr = (ex as COMException)?.HResult ?? ex.InnerException?.HResult ?? ex.HResult;
        if (ex is AudioAccessDeniedException or AudioDeviceException) return ex;
        if (ex is UnauthorizedAccessException || hr == E_ACCESSDENIED) return new AudioAccessDeniedException(AudioVerdicts.PrivacyMessage, ex);
        if (hr == AUDCLNT_E_DEVICE_IN_USE) return new AudioDeviceException("it's being used by another app in exclusive mode", ex);
        if (hr == AUDCLNT_E_DEVICE_INVALIDATED) return new AudioDeviceException("it was unplugged or disabled during the test", ex);
        return new AudioDeviceException(ex.Message, ex);
    }

    /// <summary>
    /// Plays mono samples (from <paramref name="fill"/>, at <paramref name="sourceRate"/>) on the device at its mix format with linear
    /// resampling; returns when the source ends, <paramref name="maxTime"/> passes or <paramref name="ct"/> fires.
    /// </summary>
    /// <param name="onlyChannel">Plays on this channel only (0 = left, 1 = right) and keeps the others silent; null = every channel.</param>
    /// <returns>The device's channel count.</returns>
    private static async Task<int> PlayAsync(MMDevice dev, int sourceRate, Func<Span<float>, int> fill, TimeSpan maxTime, CancellationToken ct, int? onlyChannel = null)
    {
        WaveFormat mix;
        using (var probe = dev.CreateAudioClient()) mix = probe.MixFormat;
        var provider = new MonoProvider(WaveFormat.CreateIeeeFloatWaveFormat(mix.SampleRate, mix.Channels), sourceRate, fill,
            onlyChannel is { } c && mix.Channels > 1 ? Math.Min(c, mix.Channels - 1) : null);
#pragma warning disable CS0618 // WasapiOut still works in NAudio 3.x; WasapiPlayer is newer but untested here.
        using var player = new WasapiOut(dev, AudioClientShareMode.Shared, true, 100);
#pragma warning restore CS0618
        var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        player.PlaybackStopped += (_, e) => { if (e.Exception is { } x) done.TrySetException(x); else done.TrySetResult(); };
        player.Init(provider);
        player.Play();
        try { await done.Task.WaitAsync(maxTime + TimeSpan.FromMilliseconds(500), ct).ConfigureAwait(false); }
        catch (TimeoutException) { }
        finally { try { player.Stop(); } catch { } }
        return mix.Channels;
    }

    private sealed class MonoProvider(WaveFormat format, int sourceRate, Func<Span<float>, int> fill, int? onlyChannel = null) : IWaveProvider
    {
        private readonly double _step = (double)sourceRate / format.SampleRate;
        private float[] _src = new float[4096];
        private int _srcLen;
        private double _pos;
        private bool _ended;
        public WaveFormat WaveFormat => format;

        public int Read(Span<byte> buffer)
        {
            var ch = format.Channels;
            var outF = MemoryMarshal.Cast<byte, float>(buffer);
            var frames = outF.Length / ch;
            var written = 0;
            for (; written < frames; written++)
            {
                var i = (int)_pos;
                if (i + 1 >= _srcLen && !Refill()) break;
                i = (int)_pos;
                var frac = (float)(_pos - i);
                var v = _src[i] + (_src[Math.Min(i + 1, _srcLen - 1)] - _src[i]) * frac;
                for (var c = 0; c < ch; c++) outF[written * ch + c] = onlyChannel is { } only && c != only ? 0f : v;
                _pos += _step;
            }
            return written * ch * sizeof(float);
        }

        /// <summary>Keeps the last sample for interpolation and appends more source; false at end of source.</summary>
        private bool Refill()
        {
            if (_ended) return false;
            var keepFrom = Math.Max(0, (int)_pos);
            var keep = Math.Max(0, _srcLen - keepFrom);
            Array.Copy(_src, keepFrom, _src, 0, keep);
            _pos -= keepFrom; _srcLen = keep;
            var n = fill(_src.AsSpan(_srcLen, _src.Length - _srcLen));
            if (n <= 0) { _ended = true; return false; }
            _srcLen += n;
            return (int)_pos + 1 < _srcLen;
        }
    }

    /// <summary>Polled shared-mode WASAPI capture (mic or loopback), down-mixed to mono floats.</summary>
    private sealed class Capture : IDisposable
    {
        private readonly AudioClient _client;
        private readonly AudioCaptureClient _cc;
        private readonly WaveFormat _fmt;
        private readonly bool _isFloat;
        private readonly Action<float[]>? _onBlock;
        private readonly List<float>? _samples;
        private CancellationTokenSource? _stop;
        private Task? _loop;
        public bool RawApplied { get; }
        public int SampleRate => _fmt.SampleRate;

        private Capture(AudioClient client, WaveFormat fmt, bool raw, Action<float[]>? onBlock, bool keepSamples)
        {
            _client = client; _fmt = fmt; RawApplied = raw; _onBlock = onBlock;
            _samples = keepSamples ? new List<float>(fmt.SampleRate * 10) : null;
            _isFloat = fmt.BitsPerSample == 32 && (fmt.Encoding == WaveFormatEncoding.IeeeFloat || fmt is WaveFormatExtensible { SubFormat: var g } && g == IeeeFloatSubtype);
            _cc = client.AudioCaptureClient;
        }

        public static Capture Open(MMDevice dev, bool loopback, bool raw, ILogger? log, Action<float[]>? onBlock = null, bool keepSamples = true)
        {
            var client = dev.CreateAudioClient();
            var rawApplied = false;
            if (raw && !loopback && client.SupportsAudioClient2)
            {
                try { client.SetClientProperties(AudioStreamCategory.Other, AudioClientStreamOptions.Raw); rawApplied = true; }
                catch (Exception ex) { log.Info($"raw mode not supported on '{dev.FriendlyName}': {ex.Message}"); }
            }
            var fmt = client.MixFormat;
            const long bufferHns = 2_000_000; // 200 ms
            try { client.Initialize(AudioClientShareMode.Shared, loopback ? AudioClientStreamFlags.Loopback : AudioClientStreamFlags.None, bufferHns, 0, fmt, Guid.Empty); }
            catch (Exception ex) when (rawApplied && ex is COMException ce && ce.HResult != E_ACCESSDENIED)
            {
                log.Warn($"initialize with raw mode failed on '{dev.FriendlyName}' ({ex.Message}), retrying without");
                client.Dispose();
                client = dev.CreateAudioClient();
                rawApplied = false;
                fmt = client.MixFormat;
                client.Initialize(AudioClientShareMode.Shared, AudioClientStreamFlags.None, bufferHns, 0, fmt, Guid.Empty);
            }
            return new Capture(client, fmt, rawApplied, onBlock, keepSamples);
        }

        public void Start()
        {
            _stop = new CancellationTokenSource();
            var token = _stop.Token;
            _client.Start();
            _loop = Task.Run(() => { while (!token.IsCancellationRequested) { Drain(); Thread.Sleep(10); } Drain(); });
        }

        private void Drain()
        {
            var ch = _fmt.Channels; var bps = _fmt.BitsPerSample / 8; var frameBytes = ch * bps;
            while (_cc.GetNextPacketSize() > 0)
            {
                var ptr = _cc.GetBuffer(out var frames, out var flags);
                var mono = new float[frames];
                if ((flags & AudioClientBufferFlags.Silent) == 0 && frames > 0)
                {
                    var bytes = new byte[frames * frameBytes];
                    Marshal.Copy(ptr, bytes, 0, bytes.Length);
                    for (var f = 0; f < frames; f++)
                    {
                        double sum = 0;
                        for (var c = 0; c < ch; c++) sum += Sample(bytes, f * frameBytes + c * bps, bps);
                        mono[f] = (float)(sum / ch);
                    }
                }
                _cc.ReleaseBuffer(frames);
                _samples?.AddRange(mono);
                _onBlock?.Invoke(mono);
            }
        }

        private float Sample(byte[] b, int o, int bps) => bps switch
        {
            4 when _isFloat => BitConverter.ToSingle(b, o),
            4 => BitConverter.ToInt32(b, o) / 2147483648f,
            3 => ((b[o] << 8 | b[o + 1] << 16 | b[o + 2] << 24) >> 8) / 8388608f,
            2 => BitConverter.ToInt16(b, o) / 32768f,
            _ => 0,
        };

        public void Stop()
        {
            if (_stop is null) return;
            _stop.Cancel();
            try { _loop?.Wait(TimeSpan.FromSeconds(2)); } catch { }
            try { _client.Stop(); } catch { }
            _stop.Dispose();
            _stop = null;
        }

        public float[] Samples() => _samples?.ToArray() ?? [];

        public void Dispose()
        {
            Stop();
            try { _cc.Dispose(); } catch { }
            try { _client.Dispose(); } catch { }
        }
    }
}
