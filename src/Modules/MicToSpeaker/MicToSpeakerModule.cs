using System.Diagnostics;

namespace RemotePCDiagnostics.Core.Audio;

/// <summary>Plays the microphone back through the speakers (live monitor) with a capped gain and a feedback brake. The audible part is the remote user's call.</summary>
public sealed class MicToSpeakerModule(IAudioIo io, ILogger? log = null) : AudioModuleBase(io, log)
{
    public const string ModuleName = ModuleSlugs.MicToSpeaker;
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
