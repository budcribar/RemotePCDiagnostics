using System.Collections.Concurrent;

namespace RemotePCDiagnostics.Core;

/// <summary>Registers modules and runs them independently, recording results in the store.</summary>
public sealed class DiagnosticsService
{
    /// <summary>Optional log sink (the Host passes App.Log).</summary>
    public Action<string>? Log { get; set; }
    private int _suiteRunning;
    private readonly ConcurrentDictionary<string, (DateTimeOffset Stamp, string Label)> _suiteLabels = new(StringComparer.OrdinalIgnoreCase);
    private CancellationTokenSource? _suiteCts;

    /// <summary>True while a stress suite is running (both dashboard run buttons are disabled).</summary>
    public bool IsStressSuiteRunning => Volatile.Read(ref _suiteRunning) == 1;
    /// <summary>True while a stress suite or any individual stress test module is running.</summary>
    public bool IsAnyStressRunning => IsStressSuiteRunning || StressSuite.Order.Any(IsRunning);
    /// <summary>Latest suite progress, so a page opened mid-run can show it.</summary>
    public StressSuiteProgress? LastStressSuiteProgress { get; private set; }
    /// <summary>Raised on every suite progress change.</summary>
    public event EventHandler<StressSuiteProgress>? StressSuiteProgressChanged;

    /// <summary>"short run"/"extended run" when the module's current result came from the stress suite; otherwise null.</summary>
    public string? StressRunLabel(string moduleName) =>
        _suiteLabels.TryGetValue(moduleName, out var l) && _store.Get(moduleName).Timestamp == l.Stamp ? l.Label : null;

    /// <summary>"short run"/"extended run" while a stress suite is running; otherwise null (for result logging).</summary>
    public string? CurrentSuiteLabel { get; private set; }

    /// <summary>Cancels a running stress suite (stops the current test and ends the sequence).</summary>
    public void CancelStressSuite()
    {
        lock (_gate) { try { _suiteCts?.Cancel(); } catch (ObjectDisposedException) { } }
    }

    private readonly List<IDiagnosticModule> _modules = new();
    private readonly ResultStore _store;
    private readonly ConcurrentDictionary<string, Task<DiagnosticResult>> _inFlight = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    public DiagnosticsService(ResultStore store, IEnumerable<IDiagnosticModule>? modules = null)
    {
        _store = store;
        foreach (var m in modules ?? []) Register(m);
    }

    public IReadOnlyList<IDiagnosticModule> Modules => _modules;

    public void Register(IDiagnosticModule module)
    {
        if (_modules.Any(m => string.Equals(m.Name, module.Name, StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException($"Module '{module.Name}' already registered.");
        _modules.Add(module);
        module.Updated += (_, r) => _store.Set(MarkStopped(module, r));
        _store.Set(DiagnosticResult.NotRun(module.Name));
    }

    /// <summary>Stress tests know from their own report (not the message) when the user stopped them: flag it as cancelled.</summary>
    private static DiagnosticResult MarkStopped(IDiagnosticModule module, DiagnosticResult r) =>
        !r.Cancelled && module is IStressSuiteModule stress && stress.IsStoppedByUserResult(r) ? r with { Cancelled = true } : r;

    public async Task<DiagnosticResult> RunAsync(string moduleName, IProgress<string>? progress = null, CancellationToken ct = default)
    {
        var module = _modules.FirstOrDefault(m => string.Equals(m.Name, moduleName, StringComparison.OrdinalIgnoreCase))
            ?? throw new ArgumentException($"Unknown module '{moduleName}'.", nameof(moduleName));
        return await RunAsync(module, progress, ct).ConfigureAwait(false);
    }

    /// <summary>Runs every module concurrently; a slow or failing module does not block the others.
    /// On-demand modules (<see cref="IDiagnosticModule.IncludeInRunAll"/> false, e.g. stress tests) are skipped.</summary>
    public Task<DiagnosticResult[]> RunAllAsync(CancellationToken ct = default)
    {
        var modules = _modules.Where(m => m.IncludeInRunAll).ToArray();
        return Task.WhenAll(modules.Select(m => RunAsync(m, null, ct)));
    }

    private void MarkRunning(IDiagnosticModule module) =>
        _store.Set(new DiagnosticResult(module.Name, DiagnosticStatus.Running, "Running…", DateTimeOffset.Now));

    /// <summary>True while a run of the module is in flight.</summary>
    public bool IsRunning(string moduleName) => _inFlight.ContainsKey(moduleName);

    /// <summary>Starts a run unless one is already in progress, in which case the in-flight task is returned (no double-runs).</summary>
    private Task<DiagnosticResult> RunAsync(IDiagnosticModule module, IProgress<string>? progress, CancellationToken ct)
    {
        Task<DiagnosticResult> task;
        lock (_gate)
        {
            if (!_inFlight.TryGetValue(module.Name, out var existing))
            {
                MarkRunning(module);
                var tcs = new TaskCompletionSource<DiagnosticResult>(TaskCreationOptions.RunContinuationsAsynchronously);
                _inFlight[module.Name] = existing = tcs.Task;
                _ = Task.Run(async () =>
                {
                    try { tcs.SetResult(await RunCoreAsync(module, progress, ct).ConfigureAwait(false)); }
                    catch (Exception ex) { tcs.SetException(ex); }
                    finally { _inFlight.TryRemove(module.Name, out _); }
                }, CancellationToken.None);
                return existing;
            }
            task = existing;
        }
        return ct.CanBeCanceled ? task.WaitAsync(ct) : task;
    }

    private async Task<DiagnosticResult> RunCoreAsync(IDiagnosticModule module, IProgress<string>? progress, CancellationToken ct)
    {
        DiagnosticResult result;
        try
        {
            var availability = await module.CheckAvailabilityAsync(ct).ConfigureAwait(false);
            result = availability.IsAvailable
                ? await module.RefreshAsync(progress, ct).ConfigureAwait(false)
                : new DiagnosticResult(module.Name, DiagnosticStatus.Error, availability.Reason ?? "Unavailable", DateTimeOffset.Now, availability);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            result = new DiagnosticResult(module.Name, DiagnosticStatus.Warning, "Cancelled", DateTimeOffset.Now) { Cancelled = true };
        }
        catch (Exception ex)
        {
            result = new DiagnosticResult(module.Name, DiagnosticStatus.Error, ex.Message, DateTimeOffset.Now, ex);
        }
        result = MarkStopped(module, result);
        _store.Set(result);
        return result;
    }

    /// <summary>Runs the quick checks (<see cref="RunAllAsync"/>) and then the stress tests one after another
    /// (CPU, Memory, Disk, GPU, Network; never in parallel). Each test's Duration (and mode) is set for the run and
    /// restored afterwards. Unavailable tests are skipped; an overheated or failed test stops the sequence.
    /// Throws <see cref="InvalidOperationException"/> if a suite is already running.</summary>
    /// <param name="only">When set, only these stress tests run (suite order kept).</param>
    /// <param name="runQuickChecks">False skips the Run All quick checks before the stress tests.</param>
    public async Task<StressSuiteResult> RunStressSuiteAsync(StressSuiteMode mode, IProgress<StressSuiteProgress>? progress, CancellationToken ct = default,
        IReadOnlyCollection<string>? only = null, bool runQuickChecks = true)
    {
        if (Interlocked.CompareExchange(ref _suiteRunning, 1, 0) != 0)
            throw new InvalidOperationException("A stress test run is already in progress.");
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        lock (_gate) _suiteCts = cts;
        var modules = StressSuite.Order
            .Where(n => only is null || only.Contains(n, StringComparer.OrdinalIgnoreCase))
            .Select(n => _modules.FirstOrDefault(m => string.Equals(m.Name, n, StringComparison.OrdinalIgnoreCase)) as IStressSuiteModule)
            .Where(m => m is not null).Cast<IStressSuiteModule>().ToList();
        var steps = modules.Select(m => new StressSuiteStep(m.Name, m.SuiteName, StressSuiteStepState.Pending)).ToArray();
        var label = StressSuite.RunLabel(mode);
        void Report(int index, bool finished, string? message)
        {
            var p = new StressSuiteProgress(mode, index, steps.Length, index > 0 && index <= steps.Length ? steps[index - 1].DisplayName : null, steps.ToArray(), finished, message);
            LastStressSuiteProgress = p;
            try { progress?.Report(p); } catch { }
            try { StressSuiteProgressChanged?.Invoke(this, p); } catch { }
        }
        StressSuiteResult Finish(StressSuiteOutcome outcome, string message, int from)
        {
            for (int j = from; j < steps.Length; j++)
                if (steps[j].State is StressSuiteStepState.Pending or StressSuiteStepState.Running)
                    steps[j] = steps[j] with { State = StressSuiteStepState.NotRun, Message = "Not run" };
            Report(steps.Length, true, message);
            CurrentSuiteLabel = null;
            Log?.Invoke($"Stress suite ({label}) finished: {outcome} - {message} Steps: {string.Join("; ", steps.Select(s => $"{s.DisplayName}={s.State}"))}");
            return new StressSuiteResult(mode, outcome, steps.ToArray(), message);
        }
        try
        {
            CurrentSuiteLabel = label;
            Log?.Invoke($"Stress suite ({label}) started");
            Report(0, false, null);
            if (runQuickChecks) await RunAllAsync(cts.Token).ConfigureAwait(false);
            for (int i = 0; i < modules.Count; i++)
            {
                var m = modules[i];
                if (cts.IsCancellationRequested) return Finish(StressSuiteOutcome.Cancelled, "Stress tests cancelled.", i);
                steps[i] = steps[i] with { State = StressSuiteStepState.Running };
                Report(i + 1, false, null);
                ModuleAvailability availability;
                try { availability = await m.CheckAvailabilityAsync(cts.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) when (cts.IsCancellationRequested) { return Finish(StressSuiteOutcome.Cancelled, "Stress tests cancelled.", i); }
                catch (Exception ex) { availability = ModuleAvailability.Unavailable(ex.Message); }
                if (!availability.IsAvailable)
                {
                    steps[i] = steps[i] with { State = StressSuiteStepState.Skipped, Message = "Skipped: not available on this PC" };
                    Log?.Invoke($"Stress suite: {m.Name} skipped (unavailable: {availability.Reason})");
                    continue;
                }
                var saved = m.SaveSuiteSettings();
                DiagnosticResult r;
                try
                {
                    m.ApplySuiteMode(mode);
                    using (cts.Token.Register(() => { try { m.Stop(); } catch { } }))
                        r = await RunAsync(m, null, cts.Token).ConfigureAwait(false);
                }
                finally
                {
                    try { m.RestoreSuiteSettings(saved); } catch (Exception ex) { Log?.Invoke($"Stress suite: restoring {m.Name} settings failed: {ex.Message}"); }
                }
                _suiteLabels[m.Name] = (r.Timestamp, label);
                if (cts.IsCancellationRequested || m.IsStoppedByUserResult(r))
                {
                    steps[i] = steps[i] with { State = StressSuiteStepState.NotRun, Message = "Stopped" };
                    return Finish(StressSuiteOutcome.Cancelled, "Stress tests cancelled.", i + 1);
                }
                if (m.IsUnavailableResult(r))
                {
                    steps[i] = steps[i] with { State = StressSuiteStepState.Skipped, Message = "Skipped: not available on this PC" };
                    continue;
                }
                if (r.Status == DiagnosticStatus.Error || m.IsOverheatedResult(r))
                {
                    var hot = m.IsOverheatedResult(r);
                    steps[i] = steps[i] with { State = StressSuiteStepState.Problem, Message = r.Message };
                    return Finish(StressSuiteOutcome.StoppedOnProblem, hot
                        ? $"Stress tests stopped: the PC got too hot during the {m.SuiteName} test. The remaining tests were not run."
                        : $"Stress tests stopped: the {m.SuiteName} test found a problem. The remaining tests were not run.", i + 1);
                }
                steps[i] = steps[i] with { State = r.Status == DiagnosticStatus.Ok ? StressSuiteStepState.Passed : StressSuiteStepState.Problem, Message = r.Message };
            }
            return Finish(StressSuiteOutcome.Completed, $"Stress tests finished ({label}).", steps.Length);
        }
        catch (OperationCanceledException) when (cts.IsCancellationRequested)
        {
            return Finish(StressSuiteOutcome.Cancelled, "Stress tests cancelled.", 0);
        }
        finally
        {
            lock (_gate) _suiteCts = null;
            Volatile.Write(ref _suiteRunning, 0);
        }
    }
}
