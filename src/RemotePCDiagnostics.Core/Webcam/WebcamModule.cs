using System.Diagnostics;

namespace RemotePCDiagnostics.Core.Webcam;

/// <summary>Webcam test: on-demand, own page, not in Run All and not part of the stress run (like the audio tests).</summary>
public interface IWebcamTestModule : IPerDeviceModule
{
    /// <summary>Null = first camera. Used by the module-wide <see cref="IDiagnosticModule.RefreshAsync"/>; a per-device run names its camera.</summary>
    string? DeviceId { get; set; }
    TimeSpan Duration { get; set; }
    IReadOnlyList<WebcamDevice> Devices();
    void Cancel();
}

public sealed record WebcamReport(WebcamVerdict Verdict, string Device, WebcamBus Bus, int Width, int Height, double RequestedFps, string? Format,
    TimeSpan Duration, WebcamStats Stats, string? Notice);

/// <summary>
/// Opens a camera for a short fixed window, analyses the frames in memory (nothing is saved or sent) and decides automatically. One instance per
/// camera; a PC without a camera doesn't show the test. The instance key comes from the camera's device interface id (stable across reboots
/// while the camera stays on the same port).
/// </summary>
public sealed class WebcamTestModule(IWebcamIo io, Action<string>? log = null) : IWebcamTestModule
{
    public const string ModuleName = ModuleSlugs.Webcam;
    public static readonly TimeSpan DefaultDuration = TimeSpan.FromSeconds(5);
    public static readonly TimeSpan[] DurationChoices = [TimeSpan.FromSeconds(3), TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(10)];
    /// <summary>Hard cap on the capture window, whatever is asked for.</summary>
    public static readonly TimeSpan MaxDuration = TimeSpan.FromSeconds(30);
    /// <summary>Extra time allowed for opening and closing the camera before the run times out.</summary>
    public static readonly TimeSpan OpenCloseAllowance = TimeSpan.FromSeconds(15);
    public const int MaxWidth = 1280, MaxHeight = 720, MaxFps = 30;

    private CancellationTokenSource? _runCts;
    private readonly object _gate = new();

    public string Name => ModuleName;
    public Guid Id => ModuleIds.Webcam;
    public string DisplayName => "Webcam test";
    public bool IncludeInRunAll => false;
    public string? DeviceId { get; set; }
    public TimeSpan Duration { get; set; } = DefaultDuration;
    public event EventHandler<DiagnosticResult>? Updated { add { } remove { } }
    private void Log(string s) { try { log?.Invoke(s); } catch { } }

    public static TimeSpan ClampDuration(TimeSpan d) => d <= TimeSpan.Zero ? DefaultDuration : d > MaxDuration ? MaxDuration : d;

    public IReadOnlyList<WebcamDevice> Devices()
    {
        try { return io.ListDevices(); }
        catch (Exception ex) { Log($"{Name}: device list failed: {ex.Message}"); return []; }
    }

    public void Cancel() { lock (_gate) { try { _runCts?.Cancel(); } catch (ObjectDisposedException) { } } }

    public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken = default) => Task.FromResult(ModuleAvailability.Available);

    public static ModuleInstance InstanceOf(WebcamDevice d) => new(InstanceKeys.From(d.Id), d.Label, d.Id);

    /// <summary>Lists cameras without opening any of them.</summary>
    public async Task<ModuleDetection> DetectAsync(CancellationToken ct = default)
    {
        var list = await Task.Run(Devices, ct).ConfigureAwait(false);
        return list.Count == 0 ? ModuleDetection.NotApplicable("No camera found") : ModuleDetection.For(list.Select(InstanceOf));
    }

    /// <summary>Tests the camera <paramref name="instance"/> names (its <see cref="ModuleInstance.Details"/> is the device id).</summary>
    public Task<DiagnosticResult> RefreshAsync(ModuleInstance instance, IProgress<string>? progress, CancellationToken cancellationToken = default) =>
        RunGuardedAsync(instance.Details ?? DeviceId, progress, cancellationToken);

    public Task<DiagnosticResult> RefreshAsync(IProgress<string>? progress, CancellationToken cancellationToken = default) =>
        RunGuardedAsync(DeviceId, progress, cancellationToken);

    private async Task<DiagnosticResult> RunGuardedAsync(string? deviceId, IProgress<string>? progress, CancellationToken cancellationToken)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        lock (_gate) _runCts = cts;
        try { return await RunCoreAsync(deviceId, progress, cts.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) when (cts.IsCancellationRequested)
        {
            return new DiagnosticResult(Name, DiagnosticStatus.Warning, "The webcam test was cancelled.", DateTimeOffset.Now) { Cancelled = true };
        }
        finally { lock (_gate) _runCts = null; }
    }

    private async Task<DiagnosticResult> RunCoreAsync(string? deviceId, IProgress<string>? progress, CancellationToken ct)
    {
        var list = Devices();
        var dev = list.FirstOrDefault(d => deviceId is not null && d.Id == deviceId) ?? list.FirstOrDefault();
        var duration = ClampDuration(Duration);
        if (dev is null)
        {
            Log($"{Name}: skipped, no camera");
            return Result(new WebcamReport(WebcamVerdict.NoDevice, "None found", WebcamBus.Unknown, 0, 0, 0, null, duration, WebcamStats.Empty, null));
        }
        var privacy = false;
        try { privacy = io.IsCameraBlockedByPrivacy(); } catch { }
        var analyzer = new WebcamAnalyzer(MaxFps);
        var gate = new object();
        var req = new WebcamCaptureRequest(dev.Id, duration, MaxWidth, MaxHeight, MaxFps, f => { lock (gate) analyzer.Add(f); });
        progress?.Report("Capturing from the camera…");
        Log($"{Name}: start '{dev.Name}' ({dev.Bus}) duration={duration} privacyDeny={privacy}");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(duration + OpenCloseAllowance);
        var sw = Stopwatch.StartNew();
        WebcamCaptureResult cap;
        try { cap = await io.CaptureAsync(req, timeout.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            Log($"{Name}: timed out after {sw.ElapsedMilliseconds} ms");
            return new DiagnosticResult(Name, DiagnosticStatus.Error, "The webcam test didn't finish in time. Please try again.", DateTimeOffset.Now);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            var v = WebcamVerdicts.FromException(ex, privacy);
            Log($"{Name}: {v}: {ex}");
            return Result(new WebcamReport(v, dev.Name, dev.Bus, 0, 0, 0, null, duration, WebcamStats.Empty, null));
        }
        WebcamStats stats;
        lock (gate) stats = analyzer.Result(duration);
        var report = Evaluate(stats, dev, cap, duration, privacy);
        Log($"{Name}: {report.Verdict} frames={stats.Frames} fps={stats.Fps} {cap.Width}x{cap.Height} mean={stats.MeanBrightness} std={stats.MeanContrast} black={stats.BlackFraction:0.00} frozen={stats.FrozenFraction:0.00} over={stats.OverexposedFraction:0.00} stalls={stats.Stalls} {cap.Note}");
        return Result(report);
    }

    /// <summary>Decision table on the analysed capture, separated from hardware for tests.</summary>
    public static WebcamReport Evaluate(WebcamStats stats, WebcamDevice dev, WebcamCaptureResult cap, TimeSpan duration, bool privacyDeny)
    {
        var v = WebcamVerdicts.Decide(stats);
        // Some drivers deliver black frames instead of an error when the privacy switch is off.
        if (privacyDeny && v is WebcamVerdict.NoFrames or WebcamVerdict.AllBlack) v = WebcamVerdict.AccessDenied;
        return new WebcamReport(v, dev.Name, dev.Bus, cap.Width, cap.Height, cap.RequestedFps, cap.Format, duration, stats, cap.Note);
    }

    private DiagnosticResult Result(WebcamReport r)
    {
        var res = new DiagnosticResult<WebcamReport>(Name, WebcamVerdicts.StatusOf(r.Verdict), WebcamVerdicts.MessageOf(r.Verdict, r.Stats), DateTimeOffset.Now, r);
        return res;
    }
}
