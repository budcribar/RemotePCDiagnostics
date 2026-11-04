using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Core.Stress;

/// <summary>On-demand memory test. Never auto-runs and is excluded from Run All; runs only when the user presses Start.</summary>
public sealed class MemoryTestModule(IMemoryInfo memory, IMemTestHelperLauncher launcher, ISensorProvider sensors,
    IWindowsMemoryDiagnosticLauncher? windowsDiagnostic = null, Action<string>? log = null, Func<IStressClock>? clockFactory = null) : IStressSuiteModule
{
    public const string ModuleName = "MemoryTest";
    public string Name => ModuleName;
    public string DisplayName => "Memory test";
    public bool IncludeInRunAll => false;
    public event EventHandler<DiagnosticResult>? Updated;
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
    public event EventHandler<MemoryTestProgress>? ProgressChanged;

    public MemoryTestMode Mode { get; set; } = MemoryTestMode.Quick;
    public TimeSpan Duration { get; set; } = MemoryTestOptions.DefaultDuration(MemoryTestMode.Quick);
    public MemoryTestOptions? Options { get; set; }
    public MemoryTestProgress? LastProgress { get; private set; }
    public bool CanLaunchWindowsDiagnostic => windowsDiagnostic is not null;

    private CancellationTokenSource? _stop;
    private StressCleanup? _cleanup;
    private readonly object _gate = new();

    /// <summary>Planned test size for a mode right now (null = not enough free memory).</summary>
    public long? PlannedBytes(MemoryTestMode mode)
    {
        try { return MemorySizing.Plan(memory.Read().Available, mode); }
        catch (Exception ex) { log?.Invoke($"Memory test: memory status failed: {ex.Message}"); return null; }
    }

    /// <summary>Opens Windows Memory Diagnostic. Call only after the user confirmed (it offers to restart the PC).</summary>
    public bool LaunchWindowsMemoryDiagnostic() => windowsDiagnostic?.Launch() ?? false;

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
            var opts = (Options ?? new MemoryTestOptions()) with { Mode = Mode, Duration = Duration };
            var cleanup = _cleanup = new StressCleanup(log);
            var test = new MemoryTest(memory, launcher, sensors, clockFactory?.Invoke(), log, cleanup);
            var report = await test.RunAsync(opts, new P(x => { LastProgress = x; ProgressChanged?.Invoke(this, x); }), stop.Token).ConfigureAwait(false);
            return new DiagnosticResult<MemoryTestReport>(Name, ToStatus(report.Outcome), report.Headline, DateTimeOffset.Now, report);
        }
        finally { lock (_gate) _stop = null; }
    }

    public static DiagnosticStatus ToStatus(MemoryTestOutcome o) => o switch
    {
        MemoryTestOutcome.Passed => DiagnosticStatus.Ok,
        MemoryTestOutcome.StoppedByUser or MemoryTestOutcome.CouldNotRun or MemoryTestOutcome.Failed => DiagnosticStatus.Warning,
        _ => DiagnosticStatus.Error,
    };

    private sealed class P(Action<MemoryTestProgress> a) : IProgress<MemoryTestProgress> { public void Report(MemoryTestProgress v) => a(v); }

    internal void RaiseUpdated(DiagnosticResult r) => Updated?.Invoke(this, r);
}
