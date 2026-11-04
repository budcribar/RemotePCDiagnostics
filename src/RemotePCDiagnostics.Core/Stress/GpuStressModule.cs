using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Core.Stress;

/// <summary>On-demand GPU stress test. Never auto-runs and is excluded from Run All; runs only when the user presses Start.</summary>
public sealed class GpuStressModule(IGpuDeviceFactory factory, ISensorProvider sensors, Action<string>? log = null, Func<IStressClock>? clockFactory = null) : IStressSuiteModule
{
    public const string ModuleName = "GpuStress";
    public string Name => ModuleName;
    public string DisplayName => "Graphics (GPU) stress test";
    public bool IncludeInRunAll => false;
    public event EventHandler<DiagnosticResult>? Updated;
    string IStressSuiteModule.SuiteName => "GPU";
    bool IStressSuiteModule.IsUnavailableResult(DiagnosticResult r) => r.Payload is GpuStressReport { Outcome: GpuStressOutcome.NoGpu };
    bool IStressSuiteModule.IsCouldNotRunResult(DiagnosticResult r) => r.Payload is GpuStressReport { Outcome: GpuStressOutcome.Failed } or Exception;
    bool IStressSuiteModule.IsOverheatedResult(DiagnosticResult r) => r.Payload is GpuStressReport { Outcome: GpuStressOutcome.Overheated };
    bool IStressSuiteModule.IsStoppedByUserResult(DiagnosticResult r) => r.Payload is GpuStressReport { Outcome: GpuStressOutcome.StoppedByUser };
    public event EventHandler<GpuStressProgress>? ProgressChanged;

    public TimeSpan Duration { get; set; } = TimeSpan.FromMinutes(1);
    public GpuStressOptions? Options { get; set; }
    public GpuStressProgress? LastProgress { get; private set; }

    private CancellationTokenSource? _stop;
    private StressCleanup? _cleanup;
    private readonly object _gate = new();

    public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken = default) => Task.FromResult(ModuleAvailability.Available);

    /// <summary>Gives back what the last run still holds (worker threads, helper process, temp file, device). Safe to call repeatedly.</summary>
    public Task CleanupAsync() => _cleanup?.RunAsync() ?? Task.CompletedTask;

    public void Stop()
    {
        lock (_gate) { try { _stop?.Cancel(); } catch (ObjectDisposedException) { } }
    }

    public async Task<DiagnosticResult> RefreshAsync(IProgress<string>? progress, CancellationToken cancellationToken = default)
    {
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        lock (_gate) _stop = stop;
        try
        {
            LastProgress = null;
            var opts = (Options ?? new GpuStressOptions()) with { Duration = Duration };
            var cleanup = _cleanup = new StressCleanup(log);
            var test = new GpuStressTest(factory, sensors, clockFactory?.Invoke(), log, cleanup);
            var report = await test.RunAsync(opts, new P(x => { LastProgress = x; ProgressChanged?.Invoke(this, x); }), stop.Token).ConfigureAwait(false);
            return new DiagnosticResult<GpuStressReport>(Name, ToStatus(report.Outcome), report.Headline, DateTimeOffset.Now, report);
        }
        finally { lock (_gate) _stop = null; }
    }

    public static DiagnosticStatus ToStatus(GpuStressOutcome o) => o switch
    {
        GpuStressOutcome.Passed => DiagnosticStatus.Ok,
        GpuStressOutcome.StoppedByUser or GpuStressOutcome.NoGpu or GpuStressOutcome.SoftwareOnly => DiagnosticStatus.Warning,
        _ => DiagnosticStatus.Error,
    };

    private sealed class P(Action<GpuStressProgress> a) : IProgress<GpuStressProgress> { public void Report(GpuStressProgress v) => a(v); }

    internal void RaiseUpdated(DiagnosticResult r) => Updated?.Invoke(this, r);
}
