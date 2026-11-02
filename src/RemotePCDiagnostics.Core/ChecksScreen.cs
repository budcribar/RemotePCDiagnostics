using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Security;

namespace RemotePCDiagnostics.Core;

public enum CheckGroup { Checks, Stress }
public enum RowKind { NotRun, Running, Passed, Warning, Critical, Cancelled, Unavailable }

/// <summary>Row display rules for the Checks &amp; Tests screen.</summary>
public static class CheckRows
{
    public static RowKind KindOf(DiagnosticResult r) => r.Status switch
    {
        DiagnosticStatus.NotRun => RowKind.NotRun,
        DiagnosticStatus.Running => RowKind.Running,
        _ => IsCancelled(r) ? RowKind.Cancelled : ResultEventLogger.Outcome(r) switch
        {
            "OK" => RowKind.Passed, "Warning" => RowKind.Warning, "Critical" => RowKind.Critical,
            "Cancelled" => RowKind.Cancelled, "Unavailable" => RowKind.Unavailable, _ => RowKind.NotRun,
        },
    };

    private static bool IsCancelled(DiagnosticResult r) => ResultEventLogger.IsCancelled(r) || Cancellation.IsCancelled(r);

    public static string Text(RowKind k) => k switch
    {
        RowKind.Passed => "Passed", RowKind.Warning => "Warning", RowKind.Critical => "Critical", RowKind.Running => "Running…",
        RowKind.Cancelled => "Cancelled", RowKind.Unavailable => "Unavailable", _ => "Not run",
    };

    /// <summary>"Passed (short run)": the mode the result actually ran in (never the currently selected mode).</summary>
    public static string Label(RowKind k, string? runLabel) =>
        runLabel is { Length: > 0 } && k is RowKind.Passed or RowKind.Warning or RowKind.Critical ? $"{Text(k)} ({runLabel})" : Text(k);

    /// <summary>Existing chip CSS kind (chip-ok / chip-warn / chip-err / chip-run / chip-na).</summary>
    public static string ChipKind(RowKind k) => k switch
    {
        RowKind.Passed => "ok", RowKind.Warning => "warn", RowKind.Critical => "err", RowKind.Running => "run", _ => "na",
    };

    public static string DotKind(RowKind k) => k switch
    {
        RowKind.Passed => "ok", RowKind.Warning => "warning", RowKind.Critical => "error", RowKind.Running => "running", _ => "neutral",
    };

    /// <summary>Group pills, e.g. [(ok,"5 passed"), (warn,"1 warning"), (na,"2 not run")]; zero counts omitted.</summary>
    public static IReadOnlyList<(string Kind, string Text)> Pills(IEnumerable<RowKind> kinds)
    {
        var list = kinds.ToList();
        var order = new (RowKind K, string Word)[]
        {
            (RowKind.Running, "running"), (RowKind.Passed, "passed"), (RowKind.Warning, "warning"), (RowKind.Critical, "critical"),
            (RowKind.Cancelled, "cancelled"), (RowKind.Unavailable, "unavailable"), (RowKind.NotRun, "not run"),
        };
        return order.Select(o => (o.K, N: list.Count(k => k == o.K))).Where(x => x.N > 0)
            .Select(x => (ChipKind(x.K), $"{x.N} {order.First(o => o.K == x.K).Word}")).ToList();
    }
}

/// <summary>Group run progress for the banner.</summary>
public sealed record GroupRunProgress(CheckGroup Group, int Index, int Total, string Current);

/// <summary>
/// Shared state of the Checks &amp; Tests screen (one instance per app, so the local window and a remote technician see the
/// same selection, runs and progress). Runs go through <see cref="DiagnosticsService"/> like every other page.
/// </summary>
public sealed class ChecksScreenState
{
    private readonly DiagnosticsService _diag;
    private readonly object _gate = new();
    private readonly HashSet<string> _selected = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, (DiagnosticResult Result, string? RunLabel)> _lastCompleted = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string?> _runLabels = new(StringComparer.OrdinalIgnoreCase);
    private CancellationTokenSource? _cts;

    public event Action? Changed;

    private readonly Preferences.PreferencesService? _prefs;

    public ChecksScreenState(DiagnosticsService diag, ResultStore store, Preferences.PreferencesService? prefs = null)
    {
        _diag = diag;
        _prefs = prefs;
        var saved = prefs?.Current;
        if (saved?.SelectedModules is { } sel)
            foreach (var m in ChecksModules.Concat(StressModules).Where(m => sel.Contains(m.Name, StringComparer.OrdinalIgnoreCase))) _selected.Add(m.Name);
        else
        {
            foreach (var m in ChecksModules) _selected.Add(m.Name);
            foreach (var m in StressModules.Where(m => !IsSeparateStep(m))) _selected.Add(m.Name);
        }
        if (saved?.ChecksCollapsed is { } cc) _collapsedChecks = cc;
        if (saved?.StressCollapsed is { } sc) _collapsedStress = sc;
        if (Enum.TryParse<StressSuiteMode>(saved?.StressMode, out var mode)) _mode = mode;
        store.Changed += (_, r) => OnResult(r);
        foreach (var r in store.Snapshot.Values) OnResult(r);
    }

    public IReadOnlyList<IDiagnosticModule> ChecksModules => _diag.Modules.Where(m => m.IncludeInRunAll).ToList();

    /// <summary>Stress tests in suite order, then the security audit and the audio tests (separate steps that run on their own after them when selected).</summary>
    public IReadOnlyList<IDiagnosticModule> StressModules =>
        StressSuite.Order.Select(n => _diag.Modules.FirstOrDefault(m => string.Equals(m.Name, n, StringComparison.OrdinalIgnoreCase))).OfType<IDiagnosticModule>()
            .Concat(_diag.Modules.Where(m => m.Name == SecurityAuditModule.ModuleName))
            .Concat(_diag.Modules.OfType<Audio.IAudioTestModule>())
            .Concat(_diag.Modules.OfType<Webcam.IWebcamTestModule>())
            .Concat(_diag.Modules.OfType<Npu.INpuTestModule>()).ToList();

    /// <summary>Security audit and audio tests: listed with the stress tests but never part of the stress run, and not ticked by default.</summary>
    public static bool IsSeparateStep(IDiagnosticModule m) => m.Name == SecurityAuditModule.ModuleName || m is Audio.IAudioTestModule || m is Webcam.IWebcamTestModule
        || m is Npu.INpuTestModule;

    public IReadOnlyList<IDiagnosticModule> Modules(CheckGroup g) => g == CheckGroup.Checks ? ChecksModules : StressModules;

    private bool _collapsedChecks = true, _collapsedStress = true;
    public bool CollapsedChecks { get => _collapsedChecks; set { _collapsedChecks = value; _prefs?.Update(p => p with { ChecksCollapsed = value }); } }
    public bool CollapsedStress { get => _collapsedStress; set { _collapsedStress = value; _prefs?.Update(p => p with { StressCollapsed = value }); } }
    public bool IsCollapsed(CheckGroup g) => g == CheckGroup.Checks ? CollapsedChecks : CollapsedStress;
    public void ToggleCollapsed(CheckGroup g) { if (g == CheckGroup.Checks) CollapsedChecks = !CollapsedChecks; else CollapsedStress = !CollapsedStress; Raise(); }
    public void SetAllCollapsed(bool collapsed) { CollapsedChecks = CollapsedStress = collapsed; Raise(); }

    private StressSuiteMode _mode = StressSuiteMode.Short;
    public StressSuiteMode Mode { get => _mode; set { _mode = value; _prefs?.Update(p => p with { StressMode = value.ToString() }); } }
    public string? SelectedModule { get; set; }

    /// <summary>Selects <paramref name="module"/> and expands the group containing it so the row is visible in the left pane.</summary>
    public void FocusModule(string module)
    {
        SelectedModule = module;
        if (ChecksModules.Any(m => string.Equals(m.Name, module, StringComparison.OrdinalIgnoreCase)))
            CollapsedChecks = false;
        else if (StressModules.Any(m => string.Equals(m.Name, module, StringComparison.OrdinalIgnoreCase)))
            CollapsedStress = false;
        Raise();
    }

    public bool IsSelected(string module) { lock (_gate) return _selected.Contains(module); }
    public void SetSelected(string module, bool on) { lock (_gate) { if (on) _selected.Add(module); else _selected.Remove(module); } SaveSelection(); Raise(); }

    private void SaveSelection()
    {
        if (_prefs is null) return;
        List<string> sel; lock (_gate) sel = _selected.ToList();
        _prefs.Update(p => p with { SelectedModules = sel });
    }
    public int SelectedCount(CheckGroup g) { lock (_gate) return Modules(g).Count(m => _selected.Contains(m.Name)); }

    /// <summary>True = all, false = none, null = some (tri-state select-all).</summary>
    public bool? AllSelected(CheckGroup g)
    {
        var n = SelectedCount(g); var total = Modules(g).Count;
        return n == 0 ? false : n == total ? true : null;
    }

    public void SelectAll(CheckGroup g, bool on) { lock (_gate) foreach (var m in Modules(g)) { if (on) _selected.Add(m.Name); else _selected.Remove(m.Name); } SaveSelection(); Raise(); }

    public CheckGroup? RunningGroup { get; private set; }
    public GroupRunProgress? Progress { get; private set; }
    public bool IsBusy => RunningGroup is not null;

    /// <summary>The mode label ("short run"/"extended run") the module's current result ran in, if it came from a stress run.</summary>
    public string? RunLabel(string module) { lock (_gate) return _runLabels.GetValueOrDefault(module); }

    /// <summary>Latest finished, non-cancelled result this session (so a cancelled run never hides the previous result).</summary>
    public (DiagnosticResult Result, string? RunLabel)? LastCompleted(string module) { lock (_gate) return _lastCompleted.TryGetValue(module, out var v) ? v : null; }

    private void OnResult(DiagnosticResult r)
    {
        var kind = CheckRows.KindOf(r);
        lock (_gate)
        {
            if (kind is RowKind.NotRun or RowKind.Running) { if (kind == RowKind.Running) _runLabels.Remove(r.ModuleName); }
            else
            {
                var label = _diag.CurrentSuiteLabel;
                _runLabels[r.ModuleName] = label;
                if (kind != RowKind.Cancelled) _lastCompleted[r.ModuleName] = (r, label);
            }
        }
        Raise();
    }

    /// <summary>Runs the selected modules of a group sequentially. Stress tests use the stress suite (mode, overheat/error stop);
    /// the security audit runs on its own afterwards when ticked. No-op when anything is already running.</summary>
    public async Task RunGroupAsync(CheckGroup g)
    {
        CancellationTokenSource cts;
        List<IDiagnosticModule> selected;
        lock (_gate)
        {
            if (RunningGroup is not null || _diag.IsStressSuiteRunning || (g == CheckGroup.Stress && _diag.IsAnyStressRunning)) return;
            selected = Modules(g).Where(m => _selected.Contains(m.Name)).ToList();
            if (selected.Count == 0) return;
            RunningGroup = g;
            if (g == CheckGroup.Checks) CollapsedChecks = false; else CollapsedStress = false;
            _cts = cts = new CancellationTokenSource();
        }
        Raise();
        try
        {
            if (g == CheckGroup.Checks)
            {
                for (var i = 0; i < selected.Count && !cts.IsCancellationRequested; i++)
                {
                    SetProgress(g, i + 1, selected.Count, selected[i]);
                    try { await _diag.RunAsync(selected[i].Name, null, cts.Token).ConfigureAwait(false); } catch (Exception) { }
                }
            }
            else
            {
                var stress = selected.Where(m => !IsSeparateStep(m)).Select(m => m.Name).ToList();
                var separate = selected.Where(IsSeparateStep).ToList();
                var total = stress.Count + separate.Count;
                if (stress.Count > 0)
                {
                    var p = new InlineProgress(sp =>
                    {
                        if (sp.Finished || sp.Index == 0) return;
                        var mod = _diag.Modules.FirstOrDefault(m => string.Equals(m.Name, sp.Steps[sp.Index - 1].ModuleName, StringComparison.OrdinalIgnoreCase));
                        if (mod is not null) SetProgress(g, sp.Index, total, mod);
                    });
                    try { await _diag.RunStressSuiteAsync(Mode, p, cts.Token, stress, runQuickChecks: false).ConfigureAwait(false); } catch (Exception) { }
                }
                for (var i = 0; i < separate.Count && !cts.IsCancellationRequested; i++)
                {
                    SetProgress(g, stress.Count + i + 1, total, separate[i]);
                    try { await _diag.RunAsync(separate[i].Name, null, cts.Token).ConfigureAwait(false); } catch (Exception) { }
                }
            }
        }
        finally
        {
            lock (_gate) { RunningGroup = null; Progress = null; _cts = null; }
            cts.Dispose();
            Raise();
        }
    }

    /// <summary>Stops the running group (current test is cancelled; remaining ones are not started).</summary>
    public void Stop()
    {
        CancellationTokenSource? c;
        lock (_gate) c = _cts;
        try { c?.Cancel(); } catch (ObjectDisposedException) { }
        try { _diag.CancelStressSuite(); } catch { }
        try { (_diag.Modules.FirstOrDefault(m => m.Name == SecurityAuditModule.ModuleName) as SecurityAuditModule)?.Cancel(); } catch { }
        foreach (var a in _diag.Modules.OfType<Audio.IAudioTestModule>()) { try { a.Cancel(); } catch { } }
        foreach (var w in _diag.Modules.OfType<Webcam.IWebcamTestModule>()) { try { w.Cancel(); } catch { } }
        foreach (var n in _diag.Modules.OfType<Npu.INpuTestModule>()) { try { n.Cancel(); } catch { } }
    }

    /// <summary>"Run just this" is allowed when no group run is active and (for stress tests) no stress test runs.</summary>
    public bool CanRunSingle(IDiagnosticModule m) =>
        RunningGroup is null && !_diag.IsStressSuiteRunning && !_diag.IsRunning(m.Name) && !(m is IStressSuiteModule && _diag.IsAnyStressRunning);

    public Task RunSingleAsync(IDiagnosticModule m) => CanRunSingle(m) ? _diag.RunAsync(m.Name) : Task.CompletedTask;

    private void SetProgress(CheckGroup g, int i, int n, IDiagnosticModule m)
    {
        lock (_gate) { Progress = new GroupRunProgress(g, i, n, m.DisplayName); SelectedModule = m.Name; }
        Raise();
    }

    private void Raise() { try { Changed?.Invoke(); } catch { } }

    private sealed class InlineProgress(Action<StressSuiteProgress> a) : IProgress<StressSuiteProgress>
    {
        public void Report(StressSuiteProgress value) { try { a(value); } catch { } }
    }
}

/// <summary>Banner of the Checks &amp; Tests screen: run progress while a group runs, otherwise the Dashboard summary.</summary>
public static class ChecksBanner
{
    /// <returns>Kind: run / ok / warn / err; Title text.</returns>
    public static (string Kind, string Title) Build(DashboardSummary summary, GroupRunProgress? progress, bool anyResult)
    {
        if (progress is { } p) return ("run", $"Running {p.Index} of {p.Total}: {p.Current}");
        if (summary.Problems.Count > 0) return (summary.HasError ? "err" : "warn", $"{summary.TitleLead}: {string.Join(", ", summary.Problems.Select(x => x.DisplayName))}");
        return anyResult ? ("ok", "Your PC looks healthy") : ("ok", "Not checked yet");
    }
}
