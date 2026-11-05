namespace RemotePCDiagnostics.Core.Stress;

/// <summary>
/// What every on-demand stress test module shares: the Stop token, progress forwarding, the <see cref="StressCleanup"/> registry that
/// <see cref="CleanupAsync"/> drains, and the module plumbing (never in Run All, default 1 minute). A concrete module only says how to run
/// its test (<see cref="RunTestAsync"/>) and how to describe a finished report (<see cref="Describe"/>).
/// </summary>
public abstract class StressModuleBase<TProgress, TReport>(ILogger? log) : IStressSuiteModule
    where TProgress : class
{
    private CancellationTokenSource? _stop;
    private StressCleanup? _cleanup;
    private TimeSpan? _duration;
    private readonly object _gate = new();

    /// <summary>The module's logger (null: nothing is logged).</summary>
    protected ILogger? Logger => log;

    public abstract string Name { get; }
    public abstract Guid Id { get; }
    public abstract string DisplayName { get; }
    public bool IncludeInRunAll => false;
    public event EventHandler<DiagnosticResult>? Updated;

    /// <summary>Raised with live progress while a run is in progress.</summary>
    public event EventHandler<TProgress>? ProgressChanged;
    /// <summary>The most recent progress of the current or last run (null before the first report).</summary>
    public TProgress? LastProgress { get; private set; }

    protected virtual TimeSpan DefaultDuration => TimeSpan.FromMinutes(1);
    public TimeSpan Duration { get => _duration ?? DefaultDuration; set => _duration = value; }

    public virtual Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken = default) => Task.FromResult(ModuleAvailability.Available);

    /// <summary>Builds and runs this module's test. Register everything the test holds with <paramref name="cleanup"/> (the test does this).</summary>
    protected abstract Task<TReport> RunTestAsync(StressCleanup cleanup, IProgress<TProgress> progress, CancellationToken cancellationToken);

    /// <summary>Status and headline for a finished report.</summary>
    protected abstract (DiagnosticStatus Status, string Headline) Describe(TReport report);

    /// <summary>Asks a running test to stop (the user pressed Stop, or the runner's watchdog fired).</summary>
    public void Stop()
    {
        lock (_gate) { try { _stop?.Cancel(); } catch (ObjectDisposedException) { } }
    }

    /// <summary>Gives back what the last run still holds (worker threads, helper process, temp file, device). Safe to call repeatedly.</summary>
    public Task CleanupAsync() => _cleanup?.RunAsync() ?? Task.CompletedTask;

    public async Task<DiagnosticResult> RefreshAsync(IProgress<string>? progress, CancellationToken cancellationToken = default)
    {
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        lock (_gate) _stop = stop;
        try
        {
            LastProgress = null;
            var cleanup = _cleanup = new StressCleanup(log);
            var p = new InlineProgress(x => { LastProgress = x; ProgressChanged?.Invoke(this, x); });
            var report = await RunTestAsync(cleanup, p, stop.Token).ConfigureAwait(false);
            var (status, headline) = Describe(report);
            return new DiagnosticResult<TReport>(Name, status, headline, DateTimeOffset.Now, report);
        }
        finally { lock (_gate) _stop = null; }
    }

    protected internal void RaiseUpdated(DiagnosticResult r) => Updated?.Invoke(this, r);

    private sealed class InlineProgress(Action<TProgress> a) : IProgress<TProgress> { public void Report(TProgress value) => a(value); }
}
