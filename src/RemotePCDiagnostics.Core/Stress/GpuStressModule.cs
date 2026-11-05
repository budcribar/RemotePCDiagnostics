using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Core.Stress;

/// <summary>On-demand GPU stress test. Never auto-runs and is excluded from Run All; runs only when the user presses Start.</summary>
public sealed class GpuStressModule(IGpuDeviceFactory factory, ISensorProvider sensors, Action<string>? log = null, Func<IStressClock>? clockFactory = null) : StressModuleBase<GpuStressProgress, GpuStressReport>(log), IStressSuiteModule
{
    public const string ModuleName = "GpuStress";
    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.GpuStress;
    public override string DisplayName => "Graphics (GPU) stress test";
    string IStressSuiteModule.SuiteName => "GPU";
    bool IStressSuiteModule.IsUnavailableResult(DiagnosticResult r) => r.Payload is GpuStressReport { Outcome: GpuStressOutcome.NoGpu };
    bool IStressSuiteModule.IsCouldNotRunResult(DiagnosticResult r) => r.Payload is GpuStressReport { Outcome: GpuStressOutcome.Failed } or Exception;
    bool IStressSuiteModule.IsOverheatedResult(DiagnosticResult r) => r.Payload is GpuStressReport { Outcome: GpuStressOutcome.Overheated };
    bool IStressSuiteModule.IsStoppedByUserResult(DiagnosticResult r) => r.Payload is GpuStressReport { Outcome: GpuStressOutcome.StoppedByUser };

    public GpuStressOptions? Options { get; set; }

    protected override Task<GpuStressReport> RunTestAsync(StressCleanup cleanup, IProgress<GpuStressProgress> progress, CancellationToken cancellationToken)
    {
        var opts = (Options ?? new GpuStressOptions()) with { Duration = Duration };
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
