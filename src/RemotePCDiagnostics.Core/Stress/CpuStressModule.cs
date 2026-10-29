using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Core.Stress;

/// <summary>On-demand CPU stress test module. Never auto-runs and is excluded from Run All; runs only when the user presses Start.</summary>
public sealed class CpuStressModule(ISensorProvider sensors, Action<string>? log = null, Func<IStressClock>? clockFactory = null, ICpuWorkload? workload = null) : IDiagnosticModule
{
    public const string ModuleName = "CpuStress";
    public string Name => ModuleName;
    public string DisplayName => "CPU stress test";
    public bool IncludeInRunAll => false;
    public event EventHandler<DiagnosticResult>? Updated;

    /// <summary>Raised with live progress while a run is in progress.</summary>
    public event EventHandler<CpuStressProgress>? ProgressChanged;

    public TimeSpan Duration { get; set; } = TimeSpan.FromMinutes(1);
    /// <summary>Optional overrides (tests).</summary>
    public CpuStressOptions? Options { get; set; }
    public CpuStressProgress? LastProgress { get; private set; }

    private CancellationTokenSource? _stop;

    public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken = default) => Task.FromResult(ModuleAvailability.Available);

    /// <summary>Asks a running test to stop (the user pressed Stop).</summary>
    public void Stop() => _stop?.Cancel();

    public async Task<DiagnosticResult> RefreshAsync(IProgress<string>? progress, CancellationToken cancellationToken = default)
    {
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _stop = stop;
        try
        {
            LastProgress = null;
            var opts = (Options ?? new CpuStressOptions()) with { Duration = Duration };
            var test = new CpuStressTest(sensors, clockFactory?.Invoke(), workload, log);
            var p = new InlineProgress(x => { LastProgress = x; ProgressChanged?.Invoke(this, x); });
            var report = await test.RunAsync(opts, p, stop.Token).ConfigureAwait(false);
            return new DiagnosticResult<CpuStressReport>(Name, ToStatus(report.Outcome), report.Headline, DateTimeOffset.Now, report);
        }
        finally { _stop = null; }
    }

    public static DiagnosticStatus ToStatus(CpuStressOutcome o) => o switch
    {
        CpuStressOutcome.Passed => DiagnosticStatus.Ok,
        CpuStressOutcome.StoppedByUser or CpuStressOutcome.Throttled => DiagnosticStatus.Warning,
        _ => DiagnosticStatus.Error,
    };

    private sealed class InlineProgress(Action<CpuStressProgress> a) : IProgress<CpuStressProgress>
    {
        public void Report(CpuStressProgress value) => a(value);
    }

    internal void RaiseUpdated(DiagnosticResult r) => Updated?.Invoke(this, r);
}
