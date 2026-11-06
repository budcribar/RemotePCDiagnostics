using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Security;

namespace RemotePCDiagnostics.Core;

public enum CheckGroup { Checks, Stress }
public enum RowKind { NotRun, Running, Passed, Warning, Critical, Cancelled, CouldNotRun, Skipped, Blocked }

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
            "Cancelled" => RowKind.Cancelled, CouldNotRun.OutcomeText => RowKind.CouldNotRun, "Skipped" => RowKind.Skipped, "Blocked" => RowKind.Blocked,
            _ => RowKind.NotRun,
        },
    };

    private static bool IsCancelled(DiagnosticResult r) => ResultEventLogger.IsCancelled(r) || Cancellation.IsCancelled(r);

    public static string Text(RowKind k) => k switch
    {
        RowKind.Passed => "Passed", RowKind.Warning => "Warning", RowKind.Critical => "Critical", RowKind.Running => "Running…",
        RowKind.Cancelled => "Cancelled", RowKind.CouldNotRun => CouldNotRun.OutcomeText, RowKind.Skipped => "Skipped", RowKind.Blocked => "Blocked",
        _ => "Not run",
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
            (RowKind.Cancelled, "cancelled"), (RowKind.CouldNotRun, "couldn't run"), (RowKind.Skipped, "skipped"), (RowKind.Blocked, "blocked"),
            (RowKind.NotRun, "not run"),
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
    private readonly List<Workflow.WorkflowCheckItem> _checkItems = [];

    public IReadOnlyList<Workflow.WorkflowCheckItem> CheckItems { get { lock (_gate) return _checkItems.ToList(); } }
    public int CompletedChecksCount => CheckItems.Count(c => c.Status is DiagnosticStatus.Ok or DiagnosticStatus.Warning or DiagnosticStatus.Error);
    public int TotalChecksCount => CheckItems.Count;

    public double CheckProgressFraction
    {
        get
        {
            var items = CheckItems;
            if (items.Count == 0) return 0;
            var sum = 0.0;
            foreach (var c in items)
            {
                if (c.Status is DiagnosticStatus.Ok or DiagnosticStatus.Warning or DiagnosticStatus.Error) sum += 1.0;
                else if (c.Status == DiagnosticStatus.Running && c.Total > 0) sum += Math.Clamp(c.Fraction, 0.0, 0.95);
            }
            return Math.Clamp(sum / items.Count, 0.0, 1.0);
        }
    }

    public IReadOnlyList<Workflow.WorkflowCheckItem> LiveCheckItems(ResultStore store)
    {
        lock (_gate)
        {
            if (RunningGroup == CheckGroup.Checks && _checkItems.Count > 0)
                return _checkItems.ToList();
        }
        return ChecksModules.Select(m =>
        {
            var r = store.Get(m.Name);
            var cp = r.Status == DiagnosticStatus.Running ? _diag.GetProgress(m.Name) : null;
            var msg = r.Status switch
            {
                DiagnosticStatus.NotRun => "Waiting…",
                DiagnosticStatus.Running => !string.IsNullOrWhiteSpace(r.Message) ? r.Message : "Running…",
                _ => r.Message
            };
            return new Workflow.WorkflowCheckItem(m.Name, m.DisplayName, r.Status, msg, cp?.Step ?? 0, cp?.Total ?? 0);
        }).ToList();
    }

    private void UpdateCheckItem(string id, Func<Workflow.WorkflowCheckItem, Workflow.WorkflowCheckItem> change)
    {
        lock (_gate)
        {
            var idx = _checkItems.FindIndex(x => string.Equals(x.Id, id, StringComparison.OrdinalIgnoreCase));
            if (idx >= 0) _checkItems[idx] = change(_checkItems[idx]);
        }
    }

    public event Action? Changed;

    private readonly Preferences.PreferencesService? _prefs;

    private readonly ResultStore _store;
    private readonly Optimizations.MemorySuggestionService? _memory;

    public ChecksScreenState(DiagnosticsService diag, ResultStore store, Preferences.PreferencesService? prefs = null, Optimizations.MemorySuggestionService? memory = null)
    {
        _diag = diag;
        _store = store;
        _memory = memory;
        _prefs = prefs;
        var saved = prefs?.Current;
        if (saved?.SelectedModuleIds is { } sel)
            foreach (var m in ChecksModules.Concat(StressModules).Where(m => sel.Contains(m.Id))) _selected.Add(m.Name);
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

    /// <summary>Stress tests page: stress tests in suite order, then the audio, webcam and NPU tests (separate steps that run on their own
    /// after them when selected). The security audit is not here: it has its own page.</summary>
    /// <remarks>Built from the catalog: stress tests in suite order, then on-demand tests by group and order.</remarks>
    public IReadOnlyList<IDiagnosticModule> StressModules
    {
        get
        {
            var order = _diag.StressOrder.ToList();
            var listed = _diag.Modules.Select(m => (Module: m, Descriptor: _diag.Catalog.Get(m.Id))).Where(x => x.Descriptor is { OnStressPage: true }).ToList();
            var stress = listed.Where(x => x.Descriptor!.Kind == ModuleKind.StressTest)
                .OrderBy(x => order.FindIndex(n => string.Equals(n, x.Module.Name, StringComparison.OrdinalIgnoreCase)) is var i and >= 0 ? i : int.MaxValue)
                .ThenBy(x => ModuleGroups.Rank(x.Descriptor!.Group)).ThenBy(x => x.Descriptor!.Order);
            var onDemand = listed.Where(x => x.Descriptor!.Kind == ModuleKind.OnDemand)
                .OrderBy(x => ModuleGroups.Rank(x.Descriptor!.Group)).ThenBy(x => x.Descriptor!.Order);
            return stress.Concat(onDemand).Select(x => x.Module).ToList();
        }
    }

    /// <summary>On-demand tests (security audit, audio, webcam, NPU, SFC/DISM): listed with the stress tests but never part of the stress run,
    /// and not ticked by default.</summary>
    public static bool IsSeparateStep(IDiagnosticModule m) => m is not IStressSuiteModule && !m.IncludeInRunAll;

    public IReadOnlyList<IDiagnosticModule> Modules(CheckGroup g) => g == CheckGroup.Checks ? ChecksModules : StressModules;

    public const string ChecksRoute = "checks", StressRoute = "stress", SecurityAuditRoute = "security-audit";

    /// <summary>Which list a page address shows: "stress" (any case, with or without query/fragment/trailing slash) is Stress tests,
    /// anything else (e.g. "checks") is Checks.</summary>
    public static CheckGroup GroupForPath(string? baseRelativePath) =>
        (baseRelativePath ?? "").Split('?', '#')[0].Trim('/').Equals(StressRoute, StringComparison.OrdinalIgnoreCase) ? CheckGroup.Stress : CheckGroup.Checks;

    /// <summary>Which page shows <paramref name="module"/>: "security-audit", "stress" or "checks" (also for anything else).</summary>
    public string PageFor(string module) =>
        _diag.Catalog.Find(module)?.Page is { } page ? page
        : StressModules.Any(m => string.Equals(m.Name, module, StringComparison.OrdinalIgnoreCase)) ? StressRoute : ChecksRoute;

    /// <summary>The group (page) a module belongs to, or null for the security audit and modules on neither page.</summary>
    public CheckGroup? GroupOf(string module) =>
        ChecksModules.Any(m => string.Equals(m.Name, module, StringComparison.OrdinalIgnoreCase)) ? CheckGroup.Checks
        : StressModules.Any(m => string.Equals(m.Name, module, StringComparison.OrdinalIgnoreCase)) ? CheckGroup.Stress : null;

    private readonly Dictionary<CheckGroup, string> _selectedByGroup = [];

    /// <summary>The selected test on one page (each page remembers its own), or its first test.</summary>
    public IDiagnosticModule? SelectedIn(CheckGroup g)
    {
        var mods = Modules(g);
        string? name; lock (_gate) name = _selectedByGroup.GetValueOrDefault(g);
        return mods.FirstOrDefault(m => string.Equals(m.Name, name, StringComparison.OrdinalIgnoreCase)) ?? mods.FirstOrDefault();
    }

    private bool _collapsedChecks = true, _collapsedStress = true;
    public bool CollapsedChecks { get => _collapsedChecks; set { _collapsedChecks = value; _prefs?.Update(p => p with { ChecksCollapsed = value }); } }
    public bool CollapsedStress { get => _collapsedStress; set { _collapsedStress = value; _prefs?.Update(p => p with { StressCollapsed = value }); } }
    public bool IsCollapsed(CheckGroup g) => g == CheckGroup.Checks ? CollapsedChecks : CollapsedStress;
    public void ToggleCollapsed(CheckGroup g) { if (g == CheckGroup.Checks) CollapsedChecks = !CollapsedChecks; else CollapsedStress = !CollapsedStress; Raise(); }
    public void SetAllCollapsed(bool collapsed) { CollapsedChecks = CollapsedStress = collapsed; Raise(); }

    private StressSuiteMode _mode = StressSuiteMode.Short;
    public StressSuiteMode Mode { get => _mode; set { _mode = value; _prefs?.Update(p => p with { StressMode = value.ToString() }); } }
    private string? _selectedModule;
    public string? SelectedModule
    {
        get => _selectedModule;
        set { _selectedModule = value; if (value is not null && GroupOf(value) is { } g) lock (_gate) _selectedByGroup[g] = value; }
    }

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
        var ids = sel.Select(n => _diag.Catalog.Find(n)?.Id).OfType<Guid>().ToList();
        _prefs.Update(p => p with { SelectedModuleIds = ids });
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
    /// <summary>Outcome line of the last group run (stress suite summary with skipped/stopping tests, or an error that kept a
    /// test from running), shown on the page instead of being swallowed. Null until a run reports something.</summary>
    public string? LastRunNote { get; private set; }
    /// <summary>Last stress suite result from a group run.</summary>
    public StressSuiteResult? LastSuiteResult { get; private set; }

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
    /// the audio, webcam and NPU tests run on their own afterwards when ticked. No-op when anything is already running.</summary>
    public Task RunAllChecksAsync() => RunGroupAsync(CheckGroup.Checks, allModules: true);

    public async Task RunGroupAsync(CheckGroup g, bool allModules = false)
    {
        CancellationTokenSource cts;
        List<IDiagnosticModule> selected;
        lock (_gate)
        {
            if (RunningGroup is not null || _diag.IsStressSuiteRunning || (g == CheckGroup.Stress && _diag.IsAnyStressRunning)) return;
            selected = (allModules ? Modules(g) : Modules(g).Where(m => _selected.Contains(m.Name))).ToList();
            if (selected.Count == 0) return;
            if (g == CheckGroup.Checks)
            {
                _checkItems.Clear();
                foreach (var m in selected) _checkItems.Add(new(m.Name, m.DisplayName, DiagnosticStatus.NotRun, "Waiting…"));
                if (_memory is not null)
                {
                    _checkItems.Add(new("MemoryScan", "Memory, startup & apps", DiagnosticStatus.NotRun, "Waiting…", 0, 5));
                    _checkItems.Add(new("StorageScan", "Storage caches & leftovers", DiagnosticStatus.NotRun, "Waiting…", 0, Storage.StorageCleanupCatalog.All.Count + 3));
                }
            }
            if (selected.Count == 0) return;
            RunningGroup = g;
            if (g == CheckGroup.Checks) CollapsedChecks = false; else CollapsedStress = false;
            _cts = cts = new CancellationTokenSource();
            LastRunNote = null;
        }
        Raise();
        var errors = new List<string>();
        void Failed(IDiagnosticModule m, Exception ex)
        {
            if (ex is OperationCanceledException && cts.IsCancellationRequested) return;
            lock (_gate) errors.Add($"{m.DisplayName} couldn't run: {ex.Message}");
        }
        try
        {
            if (g == CheckGroup.Checks)
            {
                for (var i = 0; i < selected.Count && !cts.IsCancellationRequested; i++)
                {

                    var mod = selected[i];
                    UpdateCheckItem(mod.Name, item => item with { Status = DiagnosticStatus.Running, Message = "Running…" });
                    SetProgress(g, i + 1, selected.Count, mod);
                    var progress = CheckProgressExtensions.Create(cp =>
                    {
                        UpdateCheckItem(mod.Name, item => item with { Status = DiagnosticStatus.Running, Message = cp.Message, Step = cp.Step, Total = cp.Total });
                        Raise();
                    });
                    try
                    {
                        var r = await _diag.RunAsync(mod.Name, progress, cts.Token).ConfigureAwait(false);
                        UpdateCheckItem(mod.Name, item => item with { Status = r.Status, Message = r.Message, Step = item.Total > 0 ? item.Total : 1, Total = item.Total > 0 ? item.Total : 1 });
                    }
                    catch (Exception ex) { Failed(mod, ex); }
                }
                if (selected.Count > 0 && !cts.IsCancellationRequested)
                    await RunMemoryAndStorageScansAsync(cts.Token, errors).ConfigureAwait(false);
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
                    try
                    {
                        var res = await _diag.RunStressSuiteAsync(Mode, p, cts.Token, stress, runQuickChecks: false).ConfigureAwait(false);
                        lock (_gate) { LastSuiteResult = res; errors.Insert(0, res.Message); }
                    }
                    catch (Exception ex) when (!(ex is OperationCanceledException && cts.IsCancellationRequested))
                    {
                        lock (_gate) errors.Insert(0, $"Stress tests couldn't run: {ex.Message}");
                    }
                    catch (OperationCanceledException) { }
                }
                for (var i = 0; i < separate.Count && !cts.IsCancellationRequested; i++)
                {
                    SetProgress(g, stress.Count + i + 1, total, separate[i]);
                    try { await _diag.RunAsync(separate[i].Name, null, cts.Token).ConfigureAwait(false); } catch (Exception ex) { Failed(separate[i], ex); }
                }
            }
        }
        finally
        {
            lock (_gate) { RunningGroup = null; Progress = null; _cts = null; if (g == CheckGroup.Checks) _checkItems.Clear(); LastRunNote = errors.Count == 0 ? null : string.Join(" ", errors); }
            cts.Dispose();
            Raise();
        }
    }

    /// <summary>Stops the running group (current test is cancelled; remaining ones are not started).</summary>
    private async Task RunMemoryAndStorageScansAsync(CancellationToken ct, List<string> errors)
    {
        if (_memory is null || ct.IsCancellationRequested) return;
        try
        {
            UpdateCheckItem("MemoryScan", item => item with { Status = DiagnosticStatus.Running, Message = "Looking for ways to use less memory…", Step = 1, Total = 5 });
            Raise();
            var memProgress = CheckProgressExtensions.Create(cp =>
            {
                UpdateCheckItem("MemoryScan", item => item with { Status = DiagnosticStatus.Running, Message = cp.Message, Step = cp.Step > 0 ? cp.Step : item.Step, Total = cp.Total > 0 ? cp.Total : item.Total });
                Raise();
            });
            if (_memory.Snapshot is null || _memory.ScanError is not null)
                await _memory.ScanAsync(ct, memProgress).ConfigureAwait(false);
            var memCount = _memory.Suggestions.Count;
            var memMsg = memCount == 0 ? "No memory or startup issues found." : $"{memCount} suggestion{(memCount == 1 ? "" : "s")} found.";
            UpdateCheckItem("MemoryScan", item => item with { Status = memCount > 0 ? DiagnosticStatus.Warning : DiagnosticStatus.Ok, Message = memMsg, Step = item.Total, Total = item.Total });
            Raise();

            if (!ct.IsCancellationRequested)
            {
                var storageTotal = Storage.StorageCleanupCatalog.All.Count + 3;
                UpdateCheckItem("StorageScan", item => item with { Status = DiagnosticStatus.Running, Message = "Measuring caches and leftovers that can be deleted…", Step = 1, Total = storageTotal });
                Raise();
                var storageProgress = CheckProgressExtensions.Create(cp =>
                {
                    UpdateCheckItem("StorageScan", item => item with { Status = DiagnosticStatus.Running, Message = cp.Message, Step = cp.Step > 0 ? cp.Step : item.Step, Total = cp.Total > 0 ? cp.Total : item.Total });
                    Raise();
                });
                if (!_memory.StorageScanned || _memory.StorageError is not null)
                    await _memory.ScanStorageAsync(refresh: true, ct, storageProgress).ConfigureAwait(false);
                var stCount = _memory.StorageSuggestions.Count;
                var stMsg = stCount == 0 ? "Nothing large to clean up." : $"{stCount} cleanup item{(stCount == 1 ? "" : "s")} found.";
                UpdateCheckItem("StorageScan", item => item with { Status = stCount > 0 ? DiagnosticStatus.Warning : DiagnosticStatus.Ok, Message = stMsg, Step = item.Total, Total = item.Total });
                Raise();
            }
        }
        catch (Exception ex) when (!(ex is OperationCanceledException && ct.IsCancellationRequested))
        {
            lock (_gate) errors.Add($"Memory/storage scan couldn't run: {ex.Message}");
        }
    }

    public void Stop()
    {
        CancellationTokenSource? c;
        lock (_gate) c = _cts;
        try { c?.Cancel(); } catch (ObjectDisposedException) { }
        try { _diag.CancelStressSuite(); } catch { }
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
        lock (_gate) Progress = new GroupRunProgress(g, i, n, m.DisplayName);
        SelectedModule = m.Name;
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
    /// <param name="anyResult">Whether any test this page is about has a result in this session.</param>
    /// <param name="noResultTitle">Title when nothing has run yet.</param>
    public static (string Kind, string Title) Build(DashboardSummary summary, GroupRunProgress? progress, bool anyResult, string noResultTitle = "Not checked yet")
    {
        if (progress is { } p) return ("run", $"Running {p.Index} of {p.Total}: {p.Current}");
        if (summary.Problems.Count > 0) return (summary.HasError ? "err" : "warn", $"{summary.TitleLead}: {string.Join(", ", summary.Problems.Select(x => x.DisplayName))}");
        return anyResult ? ("ok", "Your PC looks healthy") : ("ok", noResultTitle);
    }
}
