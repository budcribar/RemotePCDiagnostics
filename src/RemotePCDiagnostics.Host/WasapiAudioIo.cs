using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using NAudio.CoreAudioApi;
using NAudio.Wave;
using RemotePCDiagnostics.Core.Audio;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// NAudio/WASAPI implementation of <see cref="IAudioIo"/> (shared mode, no OS dialogs). Mic and loopback capture use a polled
/// <see cref="AudioClient"/> so raw mode (IAudioClient2::SetClientProperties, AUDCLNT_STREAMOPTIONS_RAW) can be requested before
/// Initialize; playback uses <see cref="WasapiOut"/> at the device mix rate.
/// </summary>
public sealed class WasapiAudioIo(Action<string>? log = null) : IAudioIo
{
    /// <summary>PKEY_Device_EnumeratorName ("USB", "BTHENUM", "HDAUDIO"…).</summary>
    private static readonly PropertyKey EnumeratorName = new(new Guid("a45c254e-df1c-4efd-8020-67d146a850e0"), 24);
    private static readonly Guid IeeeFloatSubtype = new("00000003-0000-0010-8000-00aa00389b71");
    private const int E_ACCESSDENIED = unchecked((int)0x80070005);
    private const int AUDCLNT_E_DEVICE_IN_USE = unchecked((int)0x8889000A);
    private const int AUDCLNT_E_DEVICE_INVALIDATED = unchecked((int)0x88890004);
    private const string ConsentKey = @"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone";

    private void Log(string s) { try { log?.Invoke("Audio: " + s); } catch { } }

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
                catch (Exception ex) { Log($"device read failed: {ex.Message}"); }
                finally { dev.Dispose(); }
            }
        }
        return list;
    }

    public bool IsMicrophoneBlockedByPrivacy()
    {
        static bool Deny(RegistryKey root, string path)
        {
            try { using var k = root.OpenSubKey(path); return string.Equals(k?.GetValue("Value") as string, "Deny", StringComparison.OrdinalIgnoreCase); }
            catch { return false; }
        }
        // Device-wide switch (HKLM), the user's switch, and "Let desktop apps access your microphone" (NonPackaged).
        return Deny(Registry.LocalMachine, ConsentKey) || Deny(Registry.CurrentUser, ConsentKey) || Deny(Registry.CurrentUser, ConsentKey + @"\NonPackaged");
    }

    public Task<PlayCaptureResult> PlayAndCaptureAsync(PlayCaptureRequest r, CancellationToken ct) => Task.Run(async () =>
    {
        try
        {
            using var en = new MMDeviceEnumerator();
            using var outDev = Device(en, r.OutputId, DataFlow.Render);
            using var inDev = Device(en, r.InputId, DataFlow.Capture);
            string? note = null;
            var toneTime = TimeSpan.FromSeconds((double)r.Tone.Length / r.SampleRate);

            async Task<Capture?> PlayWith(bool mic, bool loop)
            {
                using var micCap = mic ? Capture.Open(inDev, loopback: false, raw: r.RequestRawMic, Log) : null;
                Capture? loopCap = null;
                if (loop)
                {
                    try { loopCap = Capture.Open(outDev, loopback: true, raw: false, Log); }
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
            using (lc)
                return new PlayCaptureResult(_mic, _micRate, lc?.Samples(), lc?.SampleRate ?? 0, _micRaw, note);
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
            using var stop = new CancellationTokenSource();
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, stop.Token);
            var queue = new ConcurrentQueue<float[]>();
            var stoppedEarly = false;
            var keep = r.HalfDuplex ? new List<float[]>() : null;
            var micRate = 0;
            using var mic = Capture.Open(inDev, loopback: false, raw: r.RequestRawMic, Log, block =>
            {
                var gain = AudioMath.ClampMonitorGain(r.ProcessBlock(block, micRate));
                if (gain <= 0) { stoppedEarly = true; try { stop.Cancel(); } catch { } return; }
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
                float[]? cur = null; var curPos = 0; var played = 0; var fade = mic.SampleRate / 5;
                try
                {
                    await PlayAsync(outDev, mic.SampleRate, span =>
                    {
                        if (linked.IsCancellationRequested) return 0;
                        for (var i = 0; i < span.Length; i++)
                        {
                            if (cur is null || curPos >= cur.Length) { if (!queue.TryDequeue(out cur)) { cur = null; span[i] = 0; continue; } curPos = 0; }
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
            return new MonitorResult(mic.SampleRate, mic.RawApplied, stoppedEarly);
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
    private static async Task PlayAsync(MMDevice dev, int sourceRate, Func<Span<float>, int> fill, TimeSpan maxTime, CancellationToken ct)
    {
        WaveFormat mix;
        using (var probe = dev.CreateAudioClient()) mix = probe.MixFormat;
        var provider = new MonoProvider(WaveFormat.CreateIeeeFloatWaveFormat(mix.SampleRate, mix.Channels), sourceRate, fill);
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
    }

    private sealed class MonoProvider(WaveFormat format, int sourceRate, Func<Span<float>, int> fill) : IWaveProvider
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
                for (var c = 0; c < ch; c++) outF[written * ch + c] = v;
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

        public static Capture Open(MMDevice dev, bool loopback, bool raw, Action<string> log, Action<float[]>? onBlock = null, bool keepSamples = true)
        {
            var client = dev.CreateAudioClient();
            var rawApplied = false;
            if (raw && !loopback && client.SupportsAudioClient2)
            {
                try { client.SetClientProperties(AudioStreamCategory.Other, AudioClientStreamOptions.Raw); rawApplied = true; }
                catch (Exception ex) { log($"raw mode not supported on '{dev.FriendlyName}': {ex.Message}"); }
            }
            var fmt = client.MixFormat;
            const long bufferHns = 2_000_000; // 200 ms
            try { client.Initialize(AudioClientShareMode.Shared, loopback ? AudioClientStreamFlags.Loopback : AudioClientStreamFlags.None, bufferHns, 0, fmt, Guid.Empty); }
            catch (Exception ex) when (rawApplied && ex is COMException ce && ce.HResult != E_ACCESSDENIED)
            {
                log($"initialize with raw mode failed on '{dev.FriendlyName}' ({ex.Message}), retrying without");
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
