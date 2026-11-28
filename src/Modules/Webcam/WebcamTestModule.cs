using System.Diagnostics;
using RemotePCDiagnostics.Core.DataSources;

namespace RemotePCDiagnostics.Core.Webcam;

/// <summary>
/// Opens a camera for a short fixed window, analyses the frames in memory (nothing is saved or sent) and decides automatically. One instance per
/// camera; a PC without a camera doesn't show the test. The instance key comes from the camera's device interface id (stable across reboots
/// while the camera stays on the same port).
/// </summary>
/// <remarks>Also lists what the camera offers (formats against the class its name claims, and its controls), names the app holding a busy
/// camera (from the camera privacy store, read through <see cref="IRegistrySource"/>) and tests an IR (Windows Hello) camera as its own
/// instance.</remarks>
public sealed class WebcamTestModule(IWebcamIo io, ILogger? log = null, IRegistrySource? registry = null) : OnDemandModuleBase(log), IWebcamTestModule
{
    public const string ModuleName = ModuleSlugs.Webcam;
    public static readonly TimeSpan DefaultDuration = TimeSpan.FromSeconds(5);
    public static readonly TimeSpan[] DurationChoices = [TimeSpan.FromSeconds(3), TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(10)];
    /// <summary>Hard cap on the capture window, whatever is asked for.</summary>
    public static readonly TimeSpan MaxDuration = TimeSpan.FromSeconds(30);
    /// <summary>Extra time allowed for opening and closing the camera before the run times out.</summary>
    public static readonly TimeSpan OpenCloseAllowance = TimeSpan.FromSeconds(15);
    public const int MaxWidth = 1280, MaxHeight = 720, MaxFps = 30;

    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.Webcam;
    public override string DisplayName => "Webcam test";
    public string? DeviceId { get; set; }
    public TimeSpan Duration { get; set; } = DefaultDuration;

    public static TimeSpan ClampDuration(TimeSpan d) => d <= TimeSpan.Zero ? DefaultDuration : d > MaxDuration ? MaxDuration : d;

    public IReadOnlyList<WebcamDevice> Devices()
    {
        try { return io.ListDevices(); }
        catch (Exception ex) { LogWarn($"{Name}: device list failed: {ex.Message}"); return []; }
    }

    public static ModuleInstance InstanceOf(WebcamDevice d) => new(InstanceKeys.From(d.Id), d.Label, d.Id);

    /// <summary>Lists cameras without opening any of them.</summary>
    public async Task<ModuleDetection> DetectAsync(CancellationToken ct = default)
    {
        var list = await Task.Run(Devices, ct).ConfigureAwait(false);
        return list.Count == 0 ? ModuleDetection.NotApplicable("No camera found") : ModuleDetection.For(list.Select(InstanceOf));
    }

    /// <summary>Tests the camera <paramref name="instance"/> names (its <see cref="ModuleInstance.Details"/> is the device id).</summary>
    public Task<DiagnosticResult> RefreshAsync(ModuleInstance instance, IProgress<string>? progress, CancellationToken ct = default) =>
        RunGuardedAsync(token => RunCoreAsync(instance.Details ?? DeviceId, progress, token), ct);

    protected override Task<DiagnosticResult> RunCoreAsync(IProgress<string>? progress, CancellationToken ct) =>
        RunCoreAsync(DeviceId, progress, ct);

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
        var failed = new WebcamReport(WebcamVerdict.DeviceError, dev.Name, dev.Bus, 0, 0, 0, null, duration, WebcamStats.Empty, null) { Kind = dev.Kind };
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
            LogWarn($"{Name}: timed out after {sw.ElapsedMilliseconds} ms");
            return new DiagnosticResult(Name, DiagnosticStatus.Error, "The webcam test didn't finish in time. Please try again.", DateTimeOffset.Now);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            var v = WebcamVerdicts.FromException(ex, privacy);
            LogError($"{Name}: {v}: {ex}");
            var holders = v == WebcamVerdict.Busy ? await HoldersAsync(ct).ConfigureAwait(false) : [];
            return Result(failed with { Verdict = v, Holders = holders });
        }
        WebcamStats stats;
        lock (gate) stats = analyzer.Result(duration);
        var report = Evaluate(stats, dev, cap, duration, privacy);
        // Read in shared mode: another app has the camera, so say which one.
        if (cap.Note is not null) report = report with { Holders = await HoldersAsync(ct).ConfigureAwait(false) };
        Log($"{Name}: {report.Verdict} frames={stats.Frames} fps={stats.Fps} {cap.Width}x{cap.Height} mean={stats.MeanBrightness} std={stats.MeanContrast} black={stats.BlackFraction:0.00} frozen={stats.FrozenFraction:0.00} over={stats.OverexposedFraction:0.00} stalls={stats.Stalls} formats={report.Formats.Count} max={report.Capability?.MaxWidth}x{report.Capability?.MaxHeight} class={report.Capability?.ClassName} unreadable={string.Join("+", WebcamControls.Unreadable(report.Controls).Select(c => c.Name))} holders={report.Holders.Count} {cap.Note}");
        return Result(report);
    }

    /// <summary>The apps Windows lists as using the camera (this app left out); empty without a registry source or when it can't be read.</summary>
    private async Task<IReadOnlyList<WebcamHolder>> HoldersAsync(CancellationToken ct)
    {
        if (registry is null) return [];
        try { return await WebcamHolders.ReadAsync(registry, Path.GetFileNameWithoutExtension(Environment.ProcessPath), ct).ConfigureAwait(false); }
        catch (Exception ex) when (ex is not OperationCanceledException) { LogWarn($"{Name}: holders: {ex.Message}"); return []; }
    }

    /// <summary>Decision table on the analysed capture, separated from hardware for tests.</summary>
    public static WebcamReport Evaluate(WebcamStats stats, WebcamDevice dev, WebcamCaptureResult cap, TimeSpan duration, bool privacyDeny)
    {
        var v = WebcamVerdicts.Decide(stats, dev.Kind);
        // Some drivers deliver black frames instead of an error when the privacy switch is off.
        if (privacyDeny && v is WebcamVerdict.NoFrames or WebcamVerdict.AllBlack) v = WebcamVerdict.AccessDenied;
        var formats = WebcamCapabilities.Distinct(cap.Formats);
        var caps = formats.Count == 0 ? null : WebcamCapabilities.Assess(dev.Name, dev.Kind, formats);
        v = WebcamVerdicts.WithCapabilities(v, caps, cap.Controls);
        return new WebcamReport(v, dev.Name, dev.Bus, cap.Width, cap.Height, cap.RequestedFps, cap.Format, duration, stats, cap.Note)
        {
            Kind = dev.Kind,
            Formats = formats,
            Capability = caps,
            Controls = cap.Controls,
        };
    }

    private DiagnosticResult Result(WebcamReport r) =>
        new DiagnosticResult<WebcamReport>(Name, WebcamVerdicts.StatusOf(r), WebcamVerdicts.MessageOf(r), DateTimeOffset.Now, r);
}
