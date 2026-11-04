using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Core.Stress;

/// <summary>On-demand memory test. Never auto-runs and is excluded from Run All; runs only when the user presses Start.</summary>
public sealed class MemoryTestModule(IMemoryInfo memory, IMemTestHelperLauncher launcher, ISensorProvider sensors,
    IWindowsMemoryDiagnosticLauncher? windowsDiagnostic = null, Action<string>? log = null, Func<IStressClock>? clockFactory = null) : StressModuleBase<MemoryTestProgress, MemoryTestReport>(log), IStressSuiteModule
{
    public const string ModuleName = "MemoryTest";
    public override string Name => ModuleName;
    public override string DisplayName => "Memory test";
    string IStressSuiteModule.SuiteName => "Memory";
    object IStressSuiteModule.SaveSuiteSettings() => (Mode, Duration);
    void IStressSuiteModule.RestoreSuiteSettings(object saved) { var (m, d) = ((MemoryTestMode, TimeSpan))saved; Mode = m; Duration = d; }
    /// <summary>Short: quick mode for 1 minute. Extended: full mode for 5 minutes.</summary>
    void IStressSuiteModule.ApplySuiteMode(StressSuiteMode mode)
    {
        Mode = mode == StressSuiteMode.Extended ? MemoryTestMode.Full : MemoryTestMode.Quick;
        Duration = StressSuite.PerTestDuration(mode);
    }
    bool IStressSuiteModule.IsOverheatedResult(DiagnosticResult r) => r.Payload is MemoryTestReport { Outcome: MemoryTestOutcome.Overheated };
    bool IStressSuiteModule.IsCouldNotRunResult(DiagnosticResult r) => r.Payload is MemoryTestReport { CouldNotRun: true } or Exception;
    bool IStressSuiteModule.IsStoppedByUserResult(DiagnosticResult r) => r.Payload is MemoryTestReport { Outcome: MemoryTestOutcome.StoppedByUser };

    public MemoryTestMode Mode { get; set; } = MemoryTestMode.Quick;
    protected override TimeSpan DefaultDuration => MemoryTestOptions.DefaultDuration(MemoryTestMode.Quick);
    public MemoryTestOptions? Options { get; set; }
    public bool CanLaunchWindowsDiagnostic => windowsDiagnostic is not null;

    /// <summary>Planned test size for a mode right now (null = not enough free memory).</summary>
    public long? PlannedBytes(MemoryTestMode mode)
    {
        try { return MemorySizing.Plan(memory.Read().Available, mode); }
        catch (Exception ex) { log?.Invoke($"Memory test: memory status failed: {ex.Message}"); return null; }
    }

    /// <summary>Opens Windows Memory Diagnostic. Call only after the user confirmed (it offers to restart the PC).</summary>
    public bool LaunchWindowsMemoryDiagnostic() => windowsDiagnostic?.Launch() ?? false;

    protected override Task<MemoryTestReport> RunTestAsync(StressCleanup cleanup, IProgress<MemoryTestProgress> progress, CancellationToken cancellationToken)
    {
        var opts = (Options ?? new MemoryTestOptions()) with { Mode = Mode, Duration = Duration };
        var test = new MemoryTest(memory, launcher, sensors, clockFactory?.Invoke(), log, cleanup);
        return test.RunAsync(opts, progress, cancellationToken);
    }

    protected override (DiagnosticStatus Status, string Headline) Describe(MemoryTestReport report) => (ToStatus(report.Outcome), report.Headline);

    public static DiagnosticStatus ToStatus(MemoryTestOutcome o) => o switch
    {
        MemoryTestOutcome.Passed => DiagnosticStatus.Ok,
        MemoryTestOutcome.StoppedByUser or MemoryTestOutcome.CouldNotRun or MemoryTestOutcome.Failed => DiagnosticStatus.Warning,
        _ => DiagnosticStatus.Error,
    };
}
