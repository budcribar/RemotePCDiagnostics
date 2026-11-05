using System.Diagnostics;

namespace RemotePCDiagnostics.Core.Audio;

/// <summary>Settings chosen on the page (shared by the local window and a remote technician).</summary>
public sealed class AudioTestSettings
{
    /// <summary>Null = Windows default device.</summary>
    public string? OutputId { get; set; }
    public string? InputId { get; set; }
    public bool HalfDuplex { get; set; }
}

/// <summary>Audio tests: on-demand, own page, not in Run All and not part of the stress run (like the security audit).</summary>
public interface IAudioTestModule : IDiagnosticModule
{
    AudioTestSettings Settings { get; }
    IReadOnlyList<AudioDevice> Devices(AudioFlow flow);
    void Cancel();
}

public sealed record SpeakerToMicReport(AudioVerdict Verdict, string Output, string Input, ToneMeasurement Mic, ToneMeasurement? Loopback,
    double FrequencyHz, bool HalfDuplex, bool RawMic, string? Notice)
{
    public bool OfferHalfDuplex => Verdict == AudioVerdict.Feedback;
}

public sealed record MicToSpeakerReport(string Output, string Input, double MicPeakDbfs, double MicRmsDbfs, TimeSpan Duration, bool HalfDuplex, bool RawMic,
    bool FeedbackDetected, bool GainReduced, bool MicHeardSomething, bool? HeardByTechnician, string? Notice)
{
    public bool OfferHalfDuplex => FeedbackDetected;
}

/// <summary>Shared plumbing for both audio modules (device lookup, cancel, error mapping).</summary>
public abstract class AudioModuleBase : IAudioTestModule
{
    protected readonly IAudioIo Io;
    protected readonly Action<string>? LogSink;
    private CancellationTokenSource? _runCts;
    private readonly object _gate = new();

    protected AudioModuleBase(IAudioIo io, Action<string>? log) { Io = io; LogSink = log; }

    public abstract string Name { get; }
    public abstract Guid Id { get; }
    public abstract string DisplayName { get; }
    public bool IncludeInRunAll => false;
    public AudioTestSettings Settings { get; } = new();
    public event EventHandler<DiagnosticResult>? Updated;
    protected void Raise(DiagnosticResult r) => Updated?.Invoke(this, r);
    protected void Log(string s) { try { LogSink?.Invoke(s); } catch { } }

    public IReadOnlyList<AudioDevice> Devices(AudioFlow flow)
    {
        try { return Io.ListDevices().Where(d => d.Flow == flow).ToList(); }
        catch (Exception ex) { Log($"{Name}: device list failed: {ex.Message}"); return []; }
    }

    /// <summary>Selected device, else the Windows default, else the first one; null = none present.</summary>
    protected AudioDevice? Pick(AudioFlow flow, string? id)
    {
        var list = Devices(flow);
        return list.FirstOrDefault(d => id is not null && d.Id == id) ?? list.FirstOrDefault(d => d.IsDefault) ?? list.FirstOrDefault();
    }

    public void Cancel() { lock (_gate) { try { _runCts?.Cancel(); } catch (ObjectDisposedException) { } } }

    public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken = default) => Task.FromResult(ModuleAvailability.Available);

    public async Task<DiagnosticResult> RefreshAsync(IProgress<string>? progress, CancellationToken cancellationToken = default)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        lock (_gate) _runCts = cts;
        try { return await RunCoreAsync(progress, cts.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) when (cts.IsCancellationRequested)
        {
            return new DiagnosticResult(Name, DiagnosticStatus.Warning, $"The {DisplayName.ToLowerInvariant()} was cancelled.", DateTimeOffset.Now) { Cancelled = true };
        }
        finally { lock (_gate) _runCts = null; }
    }

    protected abstract Task<DiagnosticResult> RunCoreAsync(IProgress<string>? progress, CancellationToken ct);

    protected static bool IsAccessDenied(Exception ex) => ex is AudioAccessDeniedException or UnauthorizedAccessException;

    protected DiagnosticResult Fail(Exception ex, object? payload)
    {
        Log($"{Name}: {ex}");
        if (IsAccessDenied(ex)) return new DiagnosticResult(Name, DiagnosticStatus.Error, AudioVerdicts.PrivacyMessage, DateTimeOffset.Now, payload);
        var msg = ex is AudioDeviceException ? $"Couldn't use the audio device: {ex.Message}" : "The audio test couldn't finish on this PC. Please try again.";
        return new DiagnosticResult(Name, DiagnosticStatus.Error, msg, DateTimeOffset.Now, payload);
    }
}

/// <summary>Plays a capped, faded 1 kHz tone while recording the microphone and the speaker output (loopback), then decides automatically.</summary>
public sealed class SpeakerToMicModule(IAudioIo io, Action<string>? log = null) : AudioModuleBase(io, log)
{
    public const string ModuleName = "SpeakerToMic";
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
            Log($"{Name}: timed out after {sw.ElapsedMilliseconds} ms");
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

/// <summary>Plays the microphone back through the speakers (live monitor) with a capped gain and a feedback brake. The audible part is the technician's call.</summary>
public sealed class MicToSpeakerModule(IAudioIo io, Action<string>? log = null) : AudioModuleBase(io, log)
{
    public const string ModuleName = "MicToSpeaker";
    public static readonly TimeSpan DefaultDuration = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan[] DurationChoices = [TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(20), TimeSpan.FromSeconds(30)];
    /// <summary>Mic peak below this = the microphone heard nothing.</summary>
    public const double SilentPeakDbfs = -60;
    public const string FeedbackRetriedNotice = "Feedback (howling) was detected while playing live, so it was stopped and run again as half-duplex (record, then play back).";

    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.MicToSpeaker;
    public override string DisplayName => "Microphone to speaker test";
    public TimeSpan Duration { get; set; } = DefaultDuration;
    public float Gain { get; set; } = AudioMath.MaxMonitorGain;

    protected override async Task<DiagnosticResult> RunCoreAsync(IProgress<string>? progress, CancellationToken ct)
    {
        var output = Pick(AudioFlow.Output, Settings.OutputId);
        var input = Pick(AudioFlow.Input, Settings.InputId);
        var duration = Duration <= TimeSpan.Zero ? DefaultDuration : Duration > TimeSpan.FromMinutes(2) ? TimeSpan.FromMinutes(2) : Duration;
        if (output is null || input is null)
        {
            var none = new MicToSpeakerReport(output?.Name ?? "None found", input?.Name ?? "None found", AudioMath.SilenceDbfs, AudioMath.SilenceDbfs, duration, Settings.HalfDuplex, false, false, false, false, null,
                output is null && input is null ? "No speaker and no microphone were found." : output is null ? "No speaker / audio output was found." : "No microphone was found.");
            return new DiagnosticResult<MicToSpeakerReport>(Name, DiagnosticStatus.Warning, AudioVerdicts.MessageOf(AudioVerdict.NoDevice), DateTimeOffset.Now, none);
        }
        var privacy = false;
        try { privacy = Io.IsMicrophoneBlockedByPrivacy(); } catch { }
        MonitorController? ctl = null;
        var req = new MonitorRequest(output.Id, input.Id, duration, Settings.HalfDuplex, true, (block, rate) =>
        {
            ctl ??= new MonitorController(rate, Gain);
            return ctl.Process(block);
        });
        progress?.Report(Settings.HalfDuplex ? "Recording, then playing it back…" : "Playing the microphone through the speakers…");
        Log($"{Name}: start out='{output.Name}' in='{input.Name}' duration={duration} halfDuplex={Settings.HalfDuplex} gain={AudioMath.ClampMonitorGain(Gain)}");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(duration * 3 + TimeSpan.FromSeconds(20));
        MonitorResult res;
        try { res = await Io.MonitorAsync(req, timeout.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new DiagnosticResult(Name, DiagnosticStatus.Error, "The audio test didn't finish in time. Please try again.", DateTimeOffset.Now);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return IsAccessDenied(ex) || privacy ? Fail(new AudioAccessDeniedException(ex.Message, ex), null) : Fail(ex, null);
        }
        var halfDuplex = Settings.HalfDuplex;
        string? retryNote = null;
        if (ctl is { FeedbackDetected: true } && !halfDuplex)
        {
            // Howling in full duplex: retry once as half-duplex (record, then play back), which cannot feed back.
            Log($"{Name}: feedback detected in full duplex, retrying half-duplex");
            progress?.Report("Feedback detected: recording, then playing it back…");
            halfDuplex = true;
            ctl = null;
            try { res = await Io.MonitorAsync(req with { HalfDuplex = true }, timeout.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                return new DiagnosticResult(Name, DiagnosticStatus.Error, "The audio test didn't finish in time. Please try again.", DateTimeOffset.Now);
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { return Fail(ex, null); }
            retryNote = FeedbackRetriedNotice;
        }
        var report = Evaluate(ctl, output.Name, input.Name, duration, halfDuplex, res, privacy);
        if (retryNote is not null && report.Notice != AudioVerdicts.PrivacyMessage) report = report with { Notice = report.Notice is null ? retryNote : retryNote + " " + report.Notice };
        Log($"{Name}: peak={report.MicPeakDbfs:0.0} rms={report.MicRmsDbfs:0.0} feedback={report.FeedbackDetected} ducked={report.GainReduced} raw={res.RawMicApplied} {res.Note}");
        return ToResult(report);
    }

    public static MicToSpeakerReport Evaluate(MonitorController? ctl, string output, string input, TimeSpan duration, bool halfDuplex, MonitorResult res, bool privacyDeny)
    {
        var peak = ctl?.PeakDbfs ?? AudioMath.SilenceDbfs;
        var notice = res.Note;
        if (privacyDeny && peak <= AudioMath.SilenceDbfs) notice = AudioVerdicts.PrivacyMessage;
        return new MicToSpeakerReport(output, input, peak, ctl?.RmsDbfs ?? AudioMath.SilenceDbfs, duration, halfDuplex, res.RawMicApplied,
            ctl?.FeedbackDetected ?? false, ctl?.Ducked ?? false, peak > SilentPeakDbfs, null, notice);
    }

    public DiagnosticResult ToResult(MicToSpeakerReport r)
    {
        var (status, msg) = r switch
        {
            { Notice: AudioVerdicts.PrivacyMessage } => (DiagnosticStatus.Error, AudioVerdicts.PrivacyMessage),
            { FeedbackDetected: true } => (DiagnosticStatus.Warning, AudioVerdicts.MessageOf(AudioVerdict.Feedback)),
            { MicHeardSomething: false } => (DiagnosticStatus.Error, "The microphone picked up no sound. Check that it isn't muted and its level isn't at zero."),
            { HeardByTechnician: true } => (DiagnosticStatus.Ok, "Passed: the microphone picked up sound and it was heard through the speakers."),
            { HeardByTechnician: false } => (DiagnosticStatus.Error, "The microphone picked up sound, but it wasn't heard through the speakers. Check the speaker, volume and mute."),
            _ => (DiagnosticStatus.Warning, "The microphone picked up sound. Did you hear it through the speakers? Choose I heard it or I didn't hear it."),
        };
        return new DiagnosticResult<MicToSpeakerReport>(Name, status, msg, DateTimeOffset.Now, r);
    }

    /// <summary>Records the person's "I heard it" / "I didn't hear it" answer on the latest result.</summary>
    public DiagnosticResult? Confirm(DiagnosticResult latest, bool heard)
    {
        if (latest.Payload is not MicToSpeakerReport r || r.FeedbackDetected || !r.MicHeardSomething) return null;
        var updated = ToResult(r with { HeardByTechnician = heard });
        Log($"{Name}: manual result heard={heard}");
        Raise(updated);
        return updated;
    }
}
