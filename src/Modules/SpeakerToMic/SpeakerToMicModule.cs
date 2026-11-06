using System.Diagnostics;

namespace RemotePCDiagnostics.Core.Audio;

/// <summary>Plays a capped, faded 1 kHz tone while recording the microphone and the speaker output (loopback), then decides automatically.</summary>
public sealed class SpeakerToMicModule(IAudioIo io, ILogger? log = null) : AudioModuleBase(io, log)
{
    public const string ModuleName = ModuleSlugs.SpeakerToMic;
    public const double FrequencyHz = 1000;
    public const int SampleRate = 48000;
    public static readonly TimeSpan ToneDuration = TimeSpan.FromSeconds(3);
    public static readonly TimeSpan Fade = TimeSpan.FromMilliseconds(200);
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.SpeakerToMic;
    public override string DisplayName => "Speaker to microphone test";

    protected override async Task<DiagnosticResult> RunCoreAsync(IProgress<string>? progress, CancellationToken ct)
    {
        var output = Pick(AudioFlow.Output, Settings.OutputId);
        var input = Pick(AudioFlow.Input, Settings.InputId);
        if (output is null || input is null)
        {
            Log($"{Name}: skipped, output={(output is null ? "none" : output.Name)} input={(input is null ? "none" : input.Name)}");
            var none = new SpeakerToMicReport(AudioVerdict.NoDevice, output?.Name ?? "None found", input?.Name ?? "None found", ToneMeasurement.Empty, null, FrequencyHz, Settings.HalfDuplex, false,
                output is null && input is null ? "No speaker and no microphone were found." : output is null ? "No speaker / audio output was found." : "No microphone was found.");
            return Result(none);
        }
        var privacy = SafePrivacy();
        var tone = AudioMath.GenerateTone(FrequencyHz, SampleRate, ToneDuration, AudioMath.MaxToneDbfs, Fade);
        var req = new PlayCaptureRequest(output.Id, input.Id, tone, SampleRate, Settings.HalfDuplex, true, TimeSpan.FromMilliseconds(300), TimeSpan.FromMilliseconds(500));
        progress?.Report("Playing the test tone and listening…");
        Log($"{Name}: start out='{output.Name}' in='{input.Name}' halfDuplex={Settings.HalfDuplex} privacyDeny={privacy}");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(Timeout);
        PlayCaptureResult cap;
        var sw = Stopwatch.StartNew();
        try { cap = await Io.PlayAndCaptureAsync(req, timeout.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            LogWarn($"{Name}: timed out after {sw.ElapsedMilliseconds} ms");
            return new DiagnosticResult(Name, DiagnosticStatus.Error, "The audio test didn't finish in time. Please try again.", DateTimeOffset.Now);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            var denied = IsAccessDenied(ex) || privacy;
            var rep = new SpeakerToMicReport(denied ? AudioVerdict.MicAccessDenied : AudioVerdict.NoOutput, output.Name, input.Name, ToneMeasurement.Empty, null, FrequencyHz, Settings.HalfDuplex, false, null);
            return denied ? Fail(new AudioAccessDeniedException(ex.Message, ex), rep) : Fail(ex, rep);
        }
        var report = Evaluate(cap, output.Name, input.Name, Settings.HalfDuplex, privacy);
        Log($"{Name}: {report.Verdict} mic tone={report.Mic.ToneDbfs:0.0} dBFS snr={report.Mic.SnrDb:0.0} dB peak={report.Mic.PeakDbfs:0.0}; loopback {(report.Loopback is { } l ? $"tone={l.ToneDbfs:0.0} snr={l.SnrDb:0.0}" : "n/a")}; raw={cap.RawMicApplied} {cap.Note}");
        return Result(report);
    }

    /// <summary>Analysis + decision table, separated from hardware for tests.</summary>
    public static SpeakerToMicReport Evaluate(PlayCaptureResult cap, string output, string input, bool halfDuplex, bool privacyDeny)
    {
        var mic = ToneAnalyzer.Analyze(cap.Mic, cap.MicSampleRate, FrequencyHz);
        var loop = cap.Loopback is null ? null : ToneAnalyzer.Analyze(cap.Loopback, cap.LoopbackSampleRate, FrequencyHz);
        // A privacy block on desktop apps can show up as pure digital silence rather than an error.
        var denied = privacyDeny && mic.DigitalSilence;
        var verdict = AudioVerdicts.Decide(loop?.ToneDetected, mic.ToneDetected, mic.Clipped, denied);
        var notice = cap.RawMicApplied ? null : "Raw microphone mode isn't supported by this driver, so Windows sound effects (such as echo cancellation) may have softened the tone.";
        if (cap.Note is { Length: > 0 } n) notice = notice is null ? n : notice + " " + n;
        return new SpeakerToMicReport(verdict, output, input, mic, loop, FrequencyHz, halfDuplex, cap.RawMicApplied, notice);
    }

    private bool SafePrivacy() { try { return Io.IsMicrophoneBlockedByPrivacy(); } catch { return false; } }

    private DiagnosticResult Result(SpeakerToMicReport r) =>
        new DiagnosticResult<SpeakerToMicReport>(Name, AudioVerdicts.StatusOf(r.Verdict), AudioVerdicts.MessageOf(r.Verdict), DateTimeOffset.Now, r);
}
