namespace RemotePCDiagnostics.Core.Stress;

/// <summary>
/// The one place a page starts, stops and times a stress test, so the page only shows what this reports. It goes through
/// <see cref="DiagnosticsService"/>, so the rules stay those of every other run: a test starts only when no stress test or stress
/// suite is running; Stop ends the whole stress suite when one is running (the user stopping a test stops the run), as well as
/// the test itself; a test that fails inside the suite doesn't stop it (the suite decides that, not the runner).
/// </summary>
/// <remarks>Its events come from the test's and the suite's own threads; a Blazor page passes them on with InvokeAsync.</remarks>
public sealed class StressTestRunner<TProgress, TReport> : IDisposable
    where TProgress : class
{
    private readonly DiagnosticsService _diagnostics;
    private readonly ResultStore _store;
    private int _disposed;

    public StressTestRunner(DiagnosticsService diagnostics, ResultStore store, StressModuleBase<TProgress, TReport> module)
    {
        _diagnostics = diagnostics;
        _store = store;
        Module = module;
        module.ProgressChanged += OnProgress;
        diagnostics.StressSuiteProgressChanged += OnSuite;
    }

    public StressModuleBase<TProgress, TReport> Module { get; }

    /// <summary>The test reported progress, or the stress suite moved on: show the runner's state again.</summary>
    public event EventHandler? Changed;

    /// <summary>The stress suite finished. The suite puts each test's own settings back when it ends, so a page reads them again
    /// (raised before <see cref="Changed"/>).</summary>
    public event EventHandler? SuiteFinished;

    /// <summary>The test's latest result.</summary>
    public DiagnosticResult Result => _store.Get(Module.Name);

    /// <summary>The test is running, on its own or inside the stress suite.</summary>
    public bool IsRunning => Result.Status == DiagnosticStatus.Running;

    /// <summary>Another stress test, or the stress suite between tests, is running, so this one can't start.</summary>
    public bool IsOtherBusy => _diagnostics.IsAnyStressRunning && !IsRunning;

    /// <summary>A stress suite is running (this test may or may not be the one running in it).</summary>
    public bool IsSuiteRunning => _diagnostics.IsStressSuiteRunning;

    /// <summary>Whether a Start would start the test now.</summary>
    public bool CanStart => !_diagnostics.IsRunning(Module.Name) && !_diagnostics.IsAnyStressRunning;

    /// <summary>Whether the page shows Stop instead of Start: the test or the stress suite is running.</summary>
    public bool CanStop => IsRunning || IsSuiteRunning;

    /// <summary>The test's latest progress while it runs; null when it isn't running.</summary>
    public TProgress? Progress => IsRunning ? Module.LastProgress : null;

    /// <summary>The running test's progress in the shape every stress page shows (headline, bar, facts, problem); null when it isn't running.</summary>
    public LiveProgress? LiveProgress => IsRunning ? Module.LiveProgress : null;

    /// <summary>How far through its time the running test is, 0 to 1 (0 when it isn't running or hasn't reported yet).</summary>
    public double Fraction => Progress is IStressProgress p ? p.Fraction : 0;

    /// <summary>Elapsed time of the running test, or null.</summary>
    public TimeSpan? Elapsed => Progress is IStressProgress p ? p.Elapsed : null;

    /// <summary>"1:05 of 5:00" while the test runs; "Starting…" before its first report; null when it isn't running.</summary>
    public string? TimeText => !IsRunning ? null : Progress is IStressProgress p ? LiveProgress.OfTotal(p) : "Starting…";

    /// <summary>Starts the test when <see cref="CanStart"/>. <paramref name="applySettings"/> runs first, to put the page's choices
    /// (duration, drive, mode...) on the module. Returns whether the test started.</summary>
    public bool Start(Action? applySettings = null)
    {
        if (!CanStart) return false;
        applySettings?.Invoke();
        _ = _diagnostics.RunAsync(Module.Name);
        return true;
    }

    /// <summary>Stops the test, and the whole stress suite when one is running.</summary>
    public void Stop()
    {
        if (_diagnostics.IsStressSuiteRunning) _diagnostics.CancelStressSuite();
        Module.Stop();
    }

    private void OnProgress(object? sender, TProgress p) => Changed?.Invoke(this, EventArgs.Empty);

    private void OnSuite(object? sender, StressSuiteProgress p)
    {
        if (p.Finished) SuiteFinished?.Invoke(this, EventArgs.Empty);
        Changed?.Invoke(this, EventArgs.Empty);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        Module.ProgressChanged -= OnProgress;
        _diagnostics.StressSuiteProgressChanged -= OnSuite;
    }
}
