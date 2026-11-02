using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Audio;

namespace RemotePCDiagnostics.Tests;

public class AudioTests
{
    private const int Rate = 48000;

    private static float[] Tone(double dbfs, double seconds = 1, double freq = 1000) =>
        AudioMath.GenerateTone(freq, Rate, TimeSpan.FromSeconds(seconds), dbfs, TimeSpan.FromMilliseconds(20));

    private static float[] Noise(double dbfs, int n, int seed = 1)
    {
        var rnd = new Random(seed);
        var amp = AudioMath.FromDbfs(dbfs) * Math.Sqrt(3); // uniform noise RMS = amp/√3
        return Enumerable.Range(0, n).Select(_ => (float)((rnd.NextDouble() * 2 - 1) * amp)).ToArray();
    }

    /// <summary>Gaussian noise (crest factor ~12 dB, like speech or room noise).</summary>
    private static float[] Gaussian(double dbfs, int n, int seed = 1)
    {
        var rnd = new Random(seed);
        var sd = AudioMath.FromDbfs(dbfs);
        return Enumerable.Range(0, n).Select(_ => (float)(sd * Math.Sqrt(-2 * Math.Log(1 - rnd.NextDouble())) * Math.Cos(2 * Math.PI * rnd.NextDouble()))).ToArray();
    }

    private static float[] Mix(float[] a, float[] b) => a.Zip(b, (x, y) => x + y).ToArray();

    [Fact]
    public void Tone_present_is_detected_with_high_snr()
    {
        var m = ToneAnalyzer.Analyze(Mix(Tone(-20), Noise(-70, Rate)), Rate, 1000);
        Assert.True(m.ToneDetected);
        Assert.True(m.SnrDb > 30, $"snr {m.SnrDb}");
        Assert.InRange(m.ToneDbfs, -24, -22); // -20 dBFS peak sine = -23 dBFS RMS
        Assert.False(m.Clipped);
    }

    [Fact]
    public void Tone_absent_is_not_detected()
    {
        var m = ToneAnalyzer.Analyze(Noise(-40, Rate), Rate, 1000);
        Assert.False(m.ToneDetected);
    }

    [Fact]
    public void Wrong_frequency_is_not_detected()
    {
        var m = ToneAnalyzer.Analyze(Tone(-20, 1, 3000), Rate, 1000);
        Assert.False(m.ToneDetected);
    }

    [Fact]
    public void Tone_buried_in_noise_is_not_detected_but_moderate_noise_is_ok()
    {
        Assert.False(ToneAnalyzer.Analyze(Mix(Tone(-50), Noise(-20, Rate)), Rate, 1000).ToneDetected);
        Assert.True(ToneAnalyzer.Analyze(Mix(Tone(-20), Noise(-45, Rate)), Rate, 1000).ToneDetected);
    }

    [Fact]
    public void Silence_is_digital_silence()
    {
        var m = ToneAnalyzer.Analyze(new float[Rate], Rate, 1000);
        Assert.True(m.DigitalSilence);
        Assert.False(m.ToneDetected);
        Assert.Equal(AudioMath.SilenceDbfs, m.PeakDbfs);
        Assert.True(ToneAnalyzer.Analyze([], Rate, 1000).DigitalSilence);
    }

    [Fact]
    public void Clipped_tone_is_flagged()
    {
        var clipped = Enumerable.Range(0, Rate).Select(i => (float)Math.Clamp(2 * Math.Sin(2 * Math.PI * 1000 * i / Rate), -1, 1)).ToArray();
        var m = ToneAnalyzer.Analyze(clipped, Rate, 1000);
        Assert.True(m.Clipped);
        Assert.True(m.ToneDetected);
        Assert.Equal(AudioVerdict.PassClipped, AudioVerdicts.Decide(true, m.ToneDetected, m.Clipped));
    }

    [Fact]
    public void Tone_with_leading_silence_is_still_detected()
    {
        var buf = new float[Rate].Concat(Tone(-30, 0.5)).Concat(new float[Rate]).ToArray();
        Assert.True(ToneAnalyzer.Analyze(buf, Rate, 1000).ToneDetected);
    }

    [Theory]
    [InlineData(true, true, false, false, AudioVerdict.Pass)]
    [InlineData(true, true, true, false, AudioVerdict.PassClipped)]
    [InlineData(true, false, false, false, AudioVerdict.MicDidNotHear)]
    [InlineData(false, true, false, false, AudioVerdict.PassLoopbackMissing)]
    [InlineData(false, false, false, false, AudioVerdict.NoOutput)]
    [InlineData(null, true, false, false, AudioVerdict.Pass)]
    [InlineData(null, false, false, false, AudioVerdict.NotHeardUnknownOutput)]
    [InlineData(true, true, false, true, AudioVerdict.MicAccessDenied)]
    [InlineData(false, false, false, true, AudioVerdict.MicAccessDenied)]
    public void Decision_table(bool? loop, bool mic, bool clipped, bool denied, AudioVerdict expected) =>
        Assert.Equal(expected, AudioVerdicts.Decide(loop, mic, clipped, denied));

    [Fact]
    public void Verdict_status_and_wording()
    {
        Assert.Equal(DiagnosticStatus.Ok, AudioVerdicts.StatusOf(AudioVerdict.Pass));
        Assert.Equal(DiagnosticStatus.Error, AudioVerdicts.StatusOf(AudioVerdict.MicDidNotHear));
        Assert.Equal(DiagnosticStatus.Error, AudioVerdicts.StatusOf(AudioVerdict.NoOutput));
        Assert.Equal(DiagnosticStatus.Warning, AudioVerdicts.StatusOf(AudioVerdict.NoDevice));
        Assert.Contains("Privacy & security > Microphone", AudioVerdicts.MessageOf(AudioVerdict.MicAccessDenied));
        var m = AudioVerdicts.MessageOf(AudioVerdict.MicDidNotHear);
        Assert.Contains("speaker", m); Assert.Contains("volume", m); Assert.Contains("microphone muted", m);
        foreach (var v in Enum.GetValues<AudioVerdict>()) Assert.False(string.IsNullOrWhiteSpace(AudioVerdicts.MessageOf(v)));
    }

    [Fact]
    public void Evaluate_combines_mic_and_loopback()
    {
        var tone = Mix(Tone(-25), Noise(-70, Rate));
        var quiet = Noise(-70, Rate, 2);
        Assert.Equal(AudioVerdict.Pass, SpeakerToMicModule.Evaluate(new(tone, Rate, tone, Rate, true), "o", "i", false, false).Verdict);
        Assert.Equal(AudioVerdict.MicDidNotHear, SpeakerToMicModule.Evaluate(new(quiet, Rate, tone, Rate, true), "o", "i", false, false).Verdict);
        Assert.Equal(AudioVerdict.NoOutput, SpeakerToMicModule.Evaluate(new(quiet, Rate, quiet, Rate, true), "o", "i", false, false).Verdict);
        // Privacy deny + digital silence from the mic = access denied, not a hardware fault.
        Assert.Equal(AudioVerdict.MicAccessDenied, SpeakerToMicModule.Evaluate(new(new float[Rate], Rate, tone, Rate, true), "o", "i", false, true).Verdict);
        var noRaw = SpeakerToMicModule.Evaluate(new(tone, Rate, null, 0, false), "o", "i", false, false);
        Assert.Equal(AudioVerdict.Pass, noRaw.Verdict);
        Assert.Null(noRaw.Loopback);
        Assert.Contains("Raw microphone mode", noRaw.Notice);
    }

    [Fact]
    public void Generated_tone_is_capped_at_minus_12_dbfs()
    {
        var t = AudioMath.GenerateTone(1000, Rate, TimeSpan.FromSeconds(1), levelDbfs: 0);
        Assert.True(AudioMath.Peak(t) <= AudioMath.MaxToneAmplitude + 1e-6);
        Assert.InRange(AudioMath.ToDbfs(AudioMath.Peak(t)), -12.1, -11.9);
        var quiet = AudioMath.GenerateTone(1000, Rate, TimeSpan.FromSeconds(1), levelDbfs: -30);
        Assert.InRange(AudioMath.ToDbfs(AudioMath.Peak(quiet)), -30.1, -29.9);
    }

    [Fact]
    public void Monitor_gain_is_capped()
    {
        Assert.Equal(AudioMath.MaxMonitorGain, AudioMath.ClampMonitorGain(5));
        Assert.Equal(0, AudioMath.ClampMonitorGain(-1));
        Assert.Equal(0, AudioMath.ClampMonitorGain(float.NaN));
        Assert.Equal(AudioMath.MaxMonitorGain, new MonitorController(Rate, 10).CurrentGain);
    }

    [Fact]
    public void Fade_in_and_out_shape()
    {
        const int total = 1000, fade = 100;
        Assert.Equal(0, AudioMath.FadeGain(0, total, fade), 6);
        Assert.Equal(0.5, AudioMath.FadeGain(50, total, fade), 6);
        Assert.Equal(1, AudioMath.FadeGain(500, total, fade), 6);
        Assert.Equal(0, AudioMath.FadeGain(total - 1, total, fade), 6);
        for (var i = 1; i < fade; i++) Assert.True(AudioMath.FadeGain(i, total, fade) >= AudioMath.FadeGain(i - 1, total, fade));
        var t = AudioMath.GenerateTone(1000, Rate, TimeSpan.FromSeconds(1)); // default 200 ms fade
        Assert.True(AudioMath.Peak(t.AsSpan(0, 480)) < 0.01);
        Assert.True(AudioMath.Peak(t.AsSpan(t.Length - 480)) < 0.01);
        var buf = Enumerable.Repeat(1f, 200).ToArray();
        AudioMath.ApplyFadeIn(buf, 100);
        Assert.Equal(0, buf[0]); Assert.Equal(1, buf[150]);
    }

    private static IEnumerable<float[]> Blocks(float[] s, int block = Rate / 50)
    {
        for (var o = 0; o + block <= s.Length; o += block) yield return s[o..(o + block)];
    }

    [Fact]
    public void Howl_detector_ignores_speech_like_noise()
    {
        var d = new HowlDetector(Rate);
        foreach (var b in Blocks(Gaussian(-20, Rate * 2))) Assert.Equal(HowlAction.None, d.Feed(b));
        Assert.False(d.FeedbackDetected);
    }

    [Fact]
    public void Howl_detector_stops_on_sustained_loud_peak()
    {
        var d = new HowlDetector(Rate);
        var loud = Enumerable.Range(0, Rate).Select(i => (float)(Math.Sin(2 * Math.PI * 2500 * i / Rate) * 0.9 + (i % 7 == 0 ? 0.09 : 0))).ToArray();
        var actions = Blocks(loud).Select(b => d.Feed(b)).ToList();
        Assert.True(d.FeedbackDetected);
        Assert.Contains(HowlAction.Stop, actions);
    }

    [Fact]
    public void Howl_detector_stops_on_growing_narrowband_tone()
    {
        var d = new HowlDetector(Rate);
        var block = Rate / 50;
        HowlAction last = HowlAction.None;
        for (var k = 0; k < 10 && last != HowlAction.Stop; k++)
        {
            var amp = AudioMath.FromDbfs(-28 + 2 * k); // grows 2 dB per block, stays below -3 dBFS peak until the end
            var b = Enumerable.Range(0, block).Select(i => (float)(amp * Math.Sin(2 * Math.PI * 1200 * (k * block + i) / Rate))).ToArray();
            last = d.Feed(b);
        }
        Assert.Equal(HowlAction.Stop, last);
        Assert.True(d.FeedbackDetected);
    }

    [Fact]
    public void Steady_tone_ducks_but_does_not_stop()
    {
        var c = new MonitorController(Rate, 0.5f);
        foreach (var b in Blocks(Tone(-15, 1))) c.Process(b);
        Assert.False(c.FeedbackDetected);
        Assert.True(c.Ducked);
        Assert.True(c.CurrentGain < 0.5f);
        Assert.InRange(c.PeakDbfs, -15.1, -14.9);
    }

    [Fact]
    public void Monitor_controller_returns_zero_gain_on_feedback()
    {
        var c = new MonitorController(Rate, 0.5f);
        var loud = Enumerable.Repeat(0.95f, Rate).Select((v, i) => i % 2 == 0 ? v : -v).ToArray();
        var gains = Blocks(loud).Select(b => c.Process(b)).ToList();
        Assert.True(c.FeedbackDetected);
        Assert.Equal(0, gains[^1]);
    }

    [Fact]
    public void Bus_guess()
    {
        Assert.Equal(AudioBus.Usb, AudioDevice.GuessBus("USB", "Headset"));
        Assert.Equal(AudioBus.Bluetooth, AudioDevice.GuessBus("BTHENUM", "x"));
        Assert.Equal(AudioBus.Bluetooth, AudioDevice.GuessBus(null, "Headset (Bluetooth Hands-Free)"));
        Assert.Equal(AudioBus.Internal, AudioDevice.GuessBus("HDAUDIO", "Speakers"));
        Assert.Equal(AudioBus.Unknown, AudioDevice.GuessBus(null, "Speakers"));
        Assert.Equal("Headset (USB) — Windows default", new AudioDevice("1", "Headset", AudioFlow.Input, AudioBus.Usb, true).Label);
    }

    // ---- Module level: CI has no audio devices, so these use the no-device path or a fake. ----

    [Fact]
    public async Task No_device_is_a_skip_not_a_crash()
    {
        var s2m = new SpeakerToMicModule(new NullAudioIo());
        Assert.False(s2m.IncludeInRunAll);
        Assert.True((await s2m.CheckAvailabilityAsync()).IsAvailable);
        var r = await s2m.RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Warning, r.Status);
        Assert.Equal(AudioVerdict.NoDevice, Assert.IsType<SpeakerToMicReport>(r.Payload).Verdict);
        Assert.StartsWith("Skipped", r.Message);

        var m2s = new MicToSpeakerModule(new NullAudioIo());
        var r2 = await m2s.RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Warning, r2.Status);
        Assert.StartsWith("Skipped", r2.Message);
        Assert.Null(m2s.Confirm(r2, true));
    }

    [Fact]
    public async Task Audio_tests_are_not_in_run_all_and_run_through_diagnostics_service()
    {
        var store = new ResultStore();
        var svc = new DiagnosticsService(store, [new SpeakerToMicModule(new NullAudioIo()), new MicToSpeakerModule(new NullAudioIo())]);
        Assert.Empty(await svc.RunAllAsync());
        var r = await svc.RunAsync(SpeakerToMicModule.ModuleName);
        Assert.Equal(DiagnosticStatus.Warning, r.Status);
        var screen = new ChecksScreenState(svc, store);
        Assert.Contains(screen.StressModules, m => m.Name == SpeakerToMicModule.ModuleName);
        Assert.False(screen.IsSelected(SpeakerToMicModule.ModuleName));
        Assert.False(screen.IsSelected(MicToSpeakerModule.ModuleName));
        Assert.True(ChecksScreenState.IsSeparateStep(svc.Modules[0]));
    }

    private sealed class FakeIo(Func<PlayCaptureRequest, PlayCaptureResult>? play = null, Func<MonitorRequest, MonitorResult>? monitor = null, bool privacy = false) : IAudioIo
    {
        public List<bool> MonitorHalfDuplex { get; } = [];
        public IReadOnlyList<AudioDevice> ListDevices() =>
        [
            new("out1", "Speakers", AudioFlow.Output, AudioBus.Internal, true),
            new("in1", "Microphone Array", AudioFlow.Input, AudioBus.Internal, true),
        ];
        public bool IsMicrophoneBlockedByPrivacy() => privacy;
        public Task<PlayCaptureResult> PlayAndCaptureAsync(PlayCaptureRequest r, CancellationToken ct) => Task.FromResult(play!(r));
        public Task<MonitorResult> MonitorAsync(MonitorRequest r, CancellationToken ct) { MonitorHalfDuplex.Add(r.HalfDuplex); return Task.FromResult(monitor!(r)); }
    }

    [Fact]
    public async Task Speaker_to_mic_passes_with_fake_loop_and_uses_capped_tone()
    {
        PlayCaptureRequest? seen = null;
        var io = new FakeIo(play: r => { seen = r; var t = Mix(r.Tone, Noise(-70, r.Tone.Length)); return new(t, r.SampleRate, r.Tone, r.SampleRate, true); });
        var r = await new SpeakerToMicModule(io).RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        Assert.Equal("out1", seen!.OutputId);
        Assert.True(seen.RequestRawMic);
        Assert.True(AudioMath.Peak(seen.Tone) <= AudioMath.MaxToneAmplitude + 1e-6);
    }

    [Fact]
    public async Task Access_denied_shows_privacy_message()
    {
        var io = new FakeIo(play: _ => throw new AudioAccessDeniedException("denied"), monitor: _ => throw new UnauthorizedAccessException());
        var r = await new SpeakerToMicModule(io).RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Error, r.Status);
        Assert.Equal(AudioVerdicts.PrivacyMessage, r.Message);
        var r2 = await new MicToSpeakerModule(io).RefreshAsync(null);
        Assert.Equal(AudioVerdicts.PrivacyMessage, r2.Message);
    }

    [Fact]
    public async Task Mic_to_speaker_feedback_retries_half_duplex_and_manual_confirm()
    {
        var calls = 0;
        var io = new FakeIo(monitor: r =>
        {
            calls++;
            var block = Rate / 50;
            for (var k = 0; k < 50; k++)
            {
                var b = r.HalfDuplex
                    ? Gaussian(-25, block, k + 1)
                    : Enumerable.Range(0, block).Select(i => (float)(0.95 * Math.Sin(2 * Math.PI * 900 * (k * block + i) / Rate))).ToArray();
                if (r.ProcessBlock(b, Rate) <= 0) return new MonitorResult(Rate, true, true);
            }
            return new MonitorResult(Rate, true, false);
        });
        var m = new MicToSpeakerModule(io);
        var r = await m.RefreshAsync(null);
        Assert.Equal(new[] { false, true }, io.MonitorHalfDuplex);
        var rep = Assert.IsType<MicToSpeakerReport>(r.Payload);
        Assert.True(rep.HalfDuplex);
        Assert.False(rep.FeedbackDetected);
        Assert.Equal(MicToSpeakerModule.FeedbackRetriedNotice, rep.Notice);
        Assert.Equal(DiagnosticStatus.Warning, r.Status); // waiting for the person's answer
        DiagnosticResult? raised = null;
        m.Updated += (_, u) => raised = u;
        Assert.Equal(DiagnosticStatus.Ok, m.Confirm(r, true)!.Status);
        Assert.Equal(DiagnosticStatus.Ok, raised!.Status);
        Assert.Equal(DiagnosticStatus.Error, m.Confirm(r, false)!.Status);
    }

    [Fact]
    public async Task Mic_to_speaker_silent_mic_is_an_error()
    {
        var io = new FakeIo(monitor: r => { r.ProcessBlock(new float[960], Rate); return new MonitorResult(Rate, false, false); });
        var r = await new MicToSpeakerModule(io).RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Error, r.Status);
        Assert.Contains("no sound", r.Message);
    }

    [Fact]
    public async Task Cancel_returns_cancelled_result()
    {
        var io = new FakeIo(play: _ => throw new OperationCanceledException());
        var m = new SpeakerToMicModule(io);
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var r = await m.RefreshAsync(null, cts.Token);
        Assert.True(r.Cancelled);
    }
}
