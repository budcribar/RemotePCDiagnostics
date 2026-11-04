using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Core.Stress;

/// <summary>On-demand disk speed test. Never auto-runs and is excluded from Run All; runs only when the user presses Start.</summary>
public sealed class DiskSpeedModule(IDiskTestFileSystem fs, ISensorProvider sensors, Action<string>? log = null, Func<IStressClock>? clockFactory = null) : StressModuleBase<DiskSpeedProgress, DiskSpeedReport>(log), IStressSuiteModule
{
    public const string ModuleName = "DiskSpeed";
    public override string Name => ModuleName;
    public override string DisplayName => "Disk speed test";
    string IStressSuiteModule.SuiteName => "Disk";
    bool IStressSuiteModule.IsCouldNotRunResult(DiagnosticResult r) => r.Payload is DiskSpeedReport { Outcome: DiskSpeedOutcome.Failed } or Exception;
    bool IStressSuiteModule.IsOverheatedResult(DiagnosticResult r) => r.Payload is DiskSpeedReport { Outcome: DiskSpeedOutcome.Overheated };
    bool IStressSuiteModule.IsStoppedByUserResult(DiagnosticResult r) => r.Payload is DiskSpeedReport { Outcome: DiskSpeedOutcome.StoppedByUser };

    public long SizeBytes { get; set; } = DiskSpeedOptions.GB;
    /// <summary>Null = system drive.</summary>
    public string? DriveRoot { get; set; }
    public DiskSpeedOptions? Options { get; set; }

    public IReadOnlyList<TestDrive> ListDrives()
    {
        try { return fs.GetFixedDrives(); }
        catch (Exception ex) { log?.Invoke($"Disk speed: listing drives failed: {ex.Message}"); return []; }
    }

    protected override Task<DiskSpeedReport> RunTestAsync(StressCleanup cleanup, IProgress<DiskSpeedProgress> progress, CancellationToken cancellationToken)
    {
        var opts = (Options ?? new DiskSpeedOptions()) with { Duration = Duration, RequestedSizeBytes = SizeBytes, DriveRoot = DriveRoot };
        var test = new DiskSpeedTest(fs, sensors, clockFactory?.Invoke(), log, cleanup);
        return test.RunAsync(opts, progress, cancellationToken);
    }

    protected override (DiagnosticStatus Status, string Headline) Describe(DiskSpeedReport report) => (ToStatus(report.Outcome), report.Headline);

    public static DiagnosticStatus ToStatus(DiskSpeedOutcome o) => o switch
    {
        DiskSpeedOutcome.Passed => DiagnosticStatus.Ok,
        DiskSpeedOutcome.SlowDrive or DiskSpeedOutcome.StoppedByUser or DiskSpeedOutcome.NotEnoughSpace => DiagnosticStatus.Warning,
        _ => DiagnosticStatus.Error,
    };
}
