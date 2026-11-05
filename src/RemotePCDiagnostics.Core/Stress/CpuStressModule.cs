using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Core.Stress;

/// <summary>On-demand CPU stress test module. Never auto-runs and is excluded from Run All; runs only when the user presses Start.</summary>
public sealed class CpuStressModule(ISensorProvider sensors, Action<string>? log = null, Func<IStressClock>? clockFactory = null, ICpuWorkload? workload = null, IEcFanSource? ecFan = null) : StressModuleBase<CpuStressProgress, CpuStressReport>(log), IStressSuiteModule
{
    public const string ModuleName = "CpuStress";
    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.CpuStress;
    public override string DisplayName => "CPU stress test";
    string IStressSuiteModule.SuiteName => "CPU";
    bool IStressSuiteModule.IsOverheatedResult(DiagnosticResult r) => r.Payload is CpuStressReport { Outcome: CpuStressOutcome.Overheated };
    bool IStressSuiteModule.IsStoppedByUserResult(DiagnosticResult r) => r.Payload is CpuStressReport { Outcome: CpuStressOutcome.StoppedByUser };

    /// <summary>Optional overrides (tests).</summary>
    public CpuStressOptions? Options { get; set; }

    protected override async Task<CpuStressReport> RunTestAsync(StressCleanup cleanup, IProgress<CpuStressProgress> progress, CancellationToken cancellationToken)
    {
        try { ecFan?.SetStressLogging(true); } catch { /* log-only diagnostic */ }
        try
        {
            var opts = (Options ?? new CpuStressOptions()) with { Duration = Duration };
            var test = new CpuStressTest(sensors, clockFactory?.Invoke(), workload, log, cleanup);
            return await test.RunAsync(opts, progress, cancellationToken).ConfigureAwait(false);
        }
        finally { try { ecFan?.SetStressLogging(false); } catch { /* log-only diagnostic */ } }
    }

    protected override (DiagnosticStatus Status, string Headline) Describe(CpuStressReport report) => (ToStatus(report.Outcome), report.Headline);

    public static DiagnosticStatus ToStatus(CpuStressOutcome o) => o switch
    {
        CpuStressOutcome.Passed => DiagnosticStatus.Ok,
        CpuStressOutcome.StoppedByUser or CpuStressOutcome.Throttled => DiagnosticStatus.Warning,
        _ => DiagnosticStatus.Error,
    };
}
