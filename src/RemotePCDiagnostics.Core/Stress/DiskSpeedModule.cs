using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Core.Stress;

/// <summary>On-demand disk speed test. Never auto-runs and is excluded from Run All; runs only when the user presses Start.</summary>
public sealed class DiskSpeedModule(IDiskTestFileSystem fs, ISensorProvider sensors, Action<string>? log = null, Func<IStressClock>? clockFactory = null) : IDiagnosticModule
{
    public const string ModuleName = "DiskSpeed";
    public string Name => ModuleName;
    public string DisplayName => "Disk speed test";
    public bool IncludeInRunAll => false;
    public event EventHandler<DiagnosticResult>? Updated;
    public event EventHandler<DiskSpeedProgress>? ProgressChanged;

    public TimeSpan Duration { get; set; } = TimeSpan.FromMinutes(1);
    public long SizeBytes { get; set; } = DiskSpeedOptions.GB;
    /// <summary>Null = system drive.</summary>
    public string? DriveRoot { get; set; }
    public DiskSpeedOptions? Options { get; set; }
    public DiskSpeedProgress? LastProgress { get; private set; }

    private CancellationTokenSource? _stop;

    public IReadOnlyList<TestDrive> ListDrives()
    {
        try { return fs.GetFixedDrives(); }
        catch (Exception ex) { log?.Invoke($"Disk speed: listing drives failed: {ex.Message}"); return []; }
    }

    public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken = default) => Task.FromResult(ModuleAvailability.Available);

    public void Stop() => _stop?.Cancel();

    public async Task<DiagnosticResult> RefreshAsync(IProgress<string>? progress, CancellationToken cancellationToken = default)
    {
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _stop = stop;
        try
        {
            LastProgress = null;
            var opts = (Options ?? new DiskSpeedOptions()) with { Duration = Duration, RequestedSizeBytes = SizeBytes, DriveRoot = DriveRoot };
            var test = new DiskSpeedTest(fs, sensors, clockFactory?.Invoke(), log);
            var report = await test.RunAsync(opts, new P(x => { LastProgress = x; ProgressChanged?.Invoke(this, x); }), stop.Token).ConfigureAwait(false);
            return new DiagnosticResult<DiskSpeedReport>(Name, ToStatus(report.Outcome), report.Headline, DateTimeOffset.Now, report);
        }
        finally { _stop = null; }
    }

    public static DiagnosticStatus ToStatus(DiskSpeedOutcome o) => o switch
    {
        DiskSpeedOutcome.Passed => DiagnosticStatus.Ok,
        DiskSpeedOutcome.SlowDrive or DiskSpeedOutcome.StoppedByUser or DiskSpeedOutcome.NotEnoughSpace => DiagnosticStatus.Warning,
        _ => DiagnosticStatus.Error,
    };

    private sealed class P(Action<DiskSpeedProgress> a) : IProgress<DiskSpeedProgress> { public void Report(DiskSpeedProgress v) => a(v); }

    internal void RaiseUpdated(DiagnosticResult r) => Updated?.Invoke(this, r);
}
