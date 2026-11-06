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
    protected readonly ILogger? LogSink;
    private CancellationTokenSource? _runCts;
    private readonly object _gate = new();

    protected AudioModuleBase(IAudioIo io, ILogger? log) { Io = io; LogSink = log; }

    public abstract string Name { get; }
    public abstract Guid Id { get; }
    public abstract string DisplayName { get; }
    public bool IncludeInRunAll => false;
    public AudioTestSettings Settings { get; } = new();
    public event EventHandler<DiagnosticResult>? Updated;
    protected void Raise(DiagnosticResult r) => Updated?.Invoke(this, r);
    protected void Log(string m) => LogSink.Info(m);
    protected void LogWarn(string m) => LogSink.Warn(m);
    protected void LogError(string m) => LogSink.Error(m);

    public IReadOnlyList<AudioDevice> Devices(AudioFlow flow)
    {
        try { return Io.ListDevices().Where(d => d.Flow == flow).ToList(); }
        catch (Exception ex) { LogWarn($"{Name}: device list failed: {ex.Message}"); return []; }
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
        LogError($"{Name}: {ex}");
        if (IsAccessDenied(ex)) return new DiagnosticResult(Name, DiagnosticStatus.Error, AudioVerdicts.PrivacyMessage, DateTimeOffset.Now, payload);
        var msg = ex is AudioDeviceException ? $"Couldn't use the audio device: {ex.Message}" : "The audio test couldn't finish on this PC. Please try again.";
        return new DiagnosticResult(Name, DiagnosticStatus.Error, msg, DateTimeOffset.Now, payload);
    }
}
