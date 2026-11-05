using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Core.Stress;

/// <summary>
/// On-demand GPU stress test. Never auto-runs and is excluded from Run All; runs only when the user presses Start. One instance per hardware
/// GPU (an integrated and a discrete GPU are stressed one after the other); when the factory can't list adapters, one run on the first GPU.
/// </summary>
public sealed class GpuStressModule(IGpuDeviceFactory factory, ISensorProvider sensors, Action<string>? log = null, Func<IStressClock>? clockFactory = null)
    : StressModuleBase<GpuStressProgress, GpuStressReport>(log), IStressSuiteModule, IPerDeviceModule, IInstanceSummary
{
    /// <summary>The single instance used when adapters can't be listed.</summary>
    public const string FirstGpuKey = "first-gpu";
    private string? _adapterId;
    public const string ModuleName = "GpuStress";
    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.GpuStress;
    public override string DisplayName => "Graphics (GPU) stress test";
    string IStressSuiteModule.SuiteName => "GPU";
    // Report(): the module result of a per-GPU run carries the combined report (see Combine).
    bool IStressSuiteModule.IsUnavailableResult(DiagnosticResult r) => r.Report() is GpuStressReport { Outcome: GpuStressOutcome.NoGpu };
    bool IStressSuiteModule.IsCouldNotRunResult(DiagnosticResult r) => r.Report() is GpuStressReport { Outcome: GpuStressOutcome.Failed } or Exception;
    bool IStressSuiteModule.IsOverheatedResult(DiagnosticResult r) => r.Report() is GpuStressReport { Outcome: GpuStressOutcome.Overheated };
    bool IStressSuiteModule.IsStoppedByUserResult(DiagnosticResult r) => r.Report() is GpuStressReport { Outcome: GpuStressOutcome.StoppedByUser };

    public static ModuleInstance InstanceOf(GpuAdapterInfo a) => new(InstanceKeys.From(a.Id ?? a.Name), a.Name, a.Id);

    /// <summary>Lists the hardware GPUs without opening them. Never hides the test: with no list, one run reports what it finds.</summary>
    public Task<ModuleDetection> DetectAsync(CancellationToken ct = default)
    {
        IReadOnlyList<GpuAdapterInfo> list;
        try { list = factory.ListAdapters().Where(a => !a.IsSoftware && a.Id is not null).ToList(); }
        catch (Exception ex) { try { log?.Invoke($"{Name}: adapter list failed: {ex.Message}"); } catch { } list = []; }
        return Task.FromResult(list.Count == 0 ? ModuleDetection.For([new ModuleInstance(FirstGpuKey, "Graphics")]) : ModuleDetection.For(list.Select(InstanceOf)));
    }

    /// <summary>Stresses the GPU <paramref name="instance"/> names (its <see cref="ModuleInstance.Details"/> is the adapter id).</summary>
    public async Task<DiagnosticResult> RefreshAsync(ModuleInstance instance, IProgress<string>? progress, CancellationToken cancellationToken = default)
    {
        _adapterId = instance.Key == FirstGpuKey ? null : instance.Details;
        try { return await RefreshAsync(progress, cancellationToken).ConfigureAwait(false); }
        finally
        {
            _adapterId = null;
            // Let go of this GPU before the next one starts (the next run replaces the cleanup list).
            try { await CleanupAsync().ConfigureAwait(false); } catch (Exception ex) { try { log?.Invoke($"{Name}: cleanup failed: {ex.Message}"); } catch { } }
        }
    }

    /// <summary>The report the page shows: a GPU the user stopped on, else the worst GPU's report.</summary>
    public object? Combine(IReadOnlyList<DiagnosticResult> instanceResults)
    {
        var reports = instanceResults.Where(r => r.Payload is GpuStressReport).ToList();
        if (reports.Count == 0) return null;
        return (reports.FirstOrDefault(r => r.Payload is GpuStressReport { Outcome: GpuStressOutcome.StoppedByUser })
            ?? reports.OrderByDescending(r => r.Status switch { DiagnosticStatus.Error => 2, DiagnosticStatus.Warning => 1, _ => 0 }).First()).Payload;
    }

    public GpuStressOptions? Options { get; set; }

    protected override Task<GpuStressReport> RunTestAsync(StressCleanup cleanup, IProgress<GpuStressProgress> progress, CancellationToken cancellationToken)
    {
        var opts = (Options ?? new GpuStressOptions()) with { Duration = Duration };
        if (_adapterId is { } id) opts = opts with { AdapterId = id };
        var test = new GpuStressTest(factory, sensors, clockFactory?.Invoke(), log, cleanup);
        return test.RunAsync(opts, progress, cancellationToken);
    }

    protected override (DiagnosticStatus Status, string Headline) Describe(GpuStressReport report) => (ToStatus(report.Outcome), report.Headline);

    public static DiagnosticStatus ToStatus(GpuStressOutcome o) => o switch
    {
        GpuStressOutcome.Passed => DiagnosticStatus.Ok,
        GpuStressOutcome.StoppedByUser or GpuStressOutcome.NoGpu or GpuStressOutcome.SoftwareOnly => DiagnosticStatus.Warning,
        _ => DiagnosticStatus.Error,
    };
}
