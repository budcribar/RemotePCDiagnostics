using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Benchmarks;
using RemotePCDiagnostics.Core.Checks;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Workflow;

/// <summary>
/// Runs the whole service call with one decision from the tech. State is saved after every step, and the app is started again
/// (elevated, same session) after each restart, so the workflow carries on by itself.
/// </summary>
public sealed class WorkflowService(
    DiagnosticsService diag, ResultStore results, RemediationService remediation, BenchmarkService bench, IWorkflowSystem sys, IWorkflowStore store,
    MemorySuggestionService? memory = null, ISessionContext? session = null, Action<LogLevel, string>? events = null, ILogger? log = null,
    Func<TimeSpan, CancellationToken, Task>? delay = null, IChangeJournal? journal = null, Preferences.PreferencesService? prefs = null)
{
    public const int RestartsInWorkflow = 2;
    /// <summary>Task Scheduler task that starts the app again (elevated) after each restart; removed when the workflow ends.</summary>
    public const string ResumeTaskName = "Remote PC Diagnostics - continue service workflow";
    public static readonly TimeSpan RestartDelay = TimeSpan.FromSeconds(30);

    private readonly object _gate = new();
    /// <summary>7: Windows Search only on small, nearly-full PCs without classic Outlook, and opt-in (unticked); Widgets and Search highlights fixes.
    /// 8: Microsoft Teams startup is opt-in (unticked).</summary>
    /// 14: Windows repair (DISM RestoreHealth, SFC /scannow) offered when the integrity scans found corruption.</summary>
    public const int CurrentReviewRulesVersion = 14;
    private WorkflowState _state = LoadState(store);

    private static WorkflowState LoadState(IWorkflowStore store)
    {
        var saved = store.Load();
        // Old approvals may include recommendations that current rules deliberately suppress.
        // Never invalidate an in-progress workflow: its resume and cleanup state must survive.
        return saved is { Stage: WorkflowStage.Review } && saved.ReviewRulesVersion != CurrentReviewRulesVersion
            ? new WorkflowState() : saved ?? new WorkflowState();
    }
    private CancellationTokenSource? _cts;
    private readonly List<WorkflowCheckItem> _checkItems = [];

    public IReadOnlyList<WorkflowCheckItem> CheckItems { get { lock (_gate) return _checkItems.ToList(); } }
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

    private void UpdateCheckItem(string id, Func<WorkflowCheckItem, WorkflowCheckItem> change)
    {
        lock (_gate)
        {
            var idx = _checkItems.FindIndex(x => x.Id == id);
            if (idx >= 0) _checkItems[idx] = change(_checkItems[idx]);
        }
    }
    private TaskCompletionSource? _resuming;

    public event Action? Changed;
    public WorkflowState State { get { lock (_gate) return _state; } }
    public string? Status { get; private set; }
    /// <summary>0..1 progress of the DISM/SFC repair running right now (null when none runs or it hasn't reported a percent yet).</summary>
    public double? RepairFraction { get; private set; }
    /// <summary>The integrity scan running again after the restart to confirm a repair (null when none runs). It takes minutes and
    /// reports no percent, so the page shows it as its own running step instead of looking stuck on the finished benchmark.</summary>
    public WorkflowRescan? Rescan { get; private set; }
    public TimeSpan? SettleRemaining { get; private set; }
    public TimeSpan? SettleTotal { get; private set; }
    public double? SettleFraction { get; private set; }
    public bool Busy { get; private set; }

    private string Actor => ServiceActor.From(session);
    private void Log(string m) => log.Info("[workflow] " + m);
    private void LogWarn(string m) => log.Warn("[workflow] " + m);
    private void LogError(string m) => log.Error("[workflow] " + m);
    private void LogLine(string m) => log.Line("[workflow] " + m);
    private void Raise() { try { Changed?.Invoke(); } catch (Exception ex) { LogWarn("Changed handler failed: " + ex.Message); } }

    private void Save(Func<WorkflowState, WorkflowState> change)
    {
        WorkflowState s;
        lock (_gate) { s = _state = change(_state); }
        store.Save(s);
        Raise();
    }

    private void Note(string line)
    {
        Status = line;
        LogLine(line);
        Save(s => s with { Log = [.. s.Log.TakeLast(199), $"{DateTimeOffset.Now:g}  {line}"] });
    }

    private Task Delay(TimeSpan t, CancellationToken ct) => (delay ?? Task.Delay)(t, ct);

    // ---- step 1: checks → review ----

    public bool HasCompletedCheckModuleResults =>
        diag.Modules.Where(m => m.IncludeInRunAll).All(m => IsCompletedResult(results.Get(m.Name)));

    private static bool IsCompletedResult(DiagnosticResult r) =>
        r.Status is DiagnosticStatus.Ok or DiagnosticStatus.Warning or DiagnosticStatus.Error && !Cancellation.IsCancelled(r);

    public async Task RunChecksAsync(CancellationToken ct = default, bool forceRerun = false)
    {
        if (Busy || State.IsRunning) return;
        Busy = true;
        // The Windows integrity scans (DISM ScanHealth, SFC verify-only) aren't in Run all, but the workflow needs them to decide on repairs.
        var modules = diag.Modules.Where(m => m.IncludeInRunAll || m is WindowsIntegrityModule).ToList();
        lock (_gate)
        {
            _checkItems.Clear();
            foreach (var m in modules)
                _checkItems.Add(new(m.Name, m.DisplayName, DiagnosticStatus.NotRun, "Waiting…"));
            if (memory is not null)
            {
                _checkItems.Add(new("MemoryScan", "Memory, startup & apps", DiagnosticStatus.NotRun, "Waiting…", 0, 5));
                _checkItems.Add(new("StorageScan", "Storage caches & leftovers", DiagnosticStatus.NotRun, "Waiting…", 0, Storage.StorageCleanupCatalog.All.Count + 3));
            }
        }
        Save(_ => new WorkflowState { Stage = WorkflowStage.Checking, Actor = Actor });
        try
        {
            Note("Running all checks…");
            foreach (var m in modules)
            {
                ct.ThrowIfCancellationRequested();
                // A check turned off on this PC is skipped even when an earlier result is still stored, so the review doesn't keep that result.
                var existing = !forceRerun && !diag.IsTurnedOff(m.Name) ? results.Get(m.Name) : null;
                if (existing is not null && IsCompletedResult(existing))
                {
                    UpdateCheckItem(m.Name, item => item with { Status = existing.Status, Message = existing.Message, Step = 1, Total = 1 });
                    Note($"{m.DisplayName}: {existing.Message} ({CompletedChecksCount} of {TotalChecksCount})");
                    continue;
                }
                UpdateCheckItem(m.Name, item => item with { Status = DiagnosticStatus.Running, Message = "Running…" });
                Status = $"Running checks ({CompletedChecksCount} of {TotalChecksCount} done) · {m.DisplayName}…";
                Raise();
                var progress = CheckProgressExtensions.Create(cp =>
                {
                    UpdateCheckItem(m.Name, item => item with { Status = DiagnosticStatus.Running, Message = cp.Message, Step = cp.Step, Total = cp.Total });
                    Status = cp.HasProgress
                        ? $"Running checks ({CompletedChecksCount} of {TotalChecksCount} done) · {m.DisplayName} ({cp.Step}/{cp.Total}): {cp.Message}"
                        : $"Running checks ({CompletedChecksCount} of {TotalChecksCount} done) · {m.DisplayName}: {cp.Message}";
                    Raise();
                });
                var r = await diag.RunAsync(m.Name, progress, ct).ConfigureAwait(false);
                UpdateCheckItem(m.Name, item => item with { Status = r.Status, Message = r.Message, Step = item.Total > 0 ? item.Total : 1, Total = item.Total > 0 ? item.Total : 1 });
                Note($"{m.DisplayName}: {r.Message} ({CompletedChecksCount} of {TotalChecksCount})");
            }
            IReadOnlyList<MemorySuggestion> suggestions = [];
            if (memory is not null)
            {
                UpdateCheckItem("MemoryScan", item => item with { Status = DiagnosticStatus.Running, Message = "Looking for ways to use less memory…", Step = 1, Total = 5 });
                Note("Looking for ways to use less memory…");
                var memProgress = CheckProgressExtensions.Create(cp =>
                {
                    UpdateCheckItem("MemoryScan", item => item with { Status = DiagnosticStatus.Running, Message = cp.Message, Step = cp.Step > 0 ? cp.Step : item.Step, Total = cp.Total > 0 ? cp.Total : item.Total });
                    Status = cp.HasProgress
                        ? $"Running checks ({CompletedChecksCount} of {TotalChecksCount} done) · Memory, startup & apps ({cp.Step}/{cp.Total}): {cp.Message}"
                        : $"Running checks ({CompletedChecksCount} of {TotalChecksCount} done) · Memory, startup & apps: {cp.Message}";
                    Raise();
                });
                if (forceRerun || memory.Snapshot is null || memory.ScanError is not null)
                    await memory.ScanAsync(ct, memProgress).ConfigureAwait(false);
                var memCount = memory.Suggestions.Count;
                var memMsg = memCount == 0 ? "No memory or startup issues found." : $"{memCount} suggestion{(memCount == 1 ? "" : "s")} found.";
                UpdateCheckItem("MemoryScan", item => item with { Status = memCount > 0 ? DiagnosticStatus.Warning : DiagnosticStatus.Ok, Message = memMsg, Step = item.Total, Total = item.Total });
                Note($"Memory, startup & apps: {memMsg} ({CompletedChecksCount} of {TotalChecksCount})");

                Note("Measuring caches and leftovers that can be deleted…");
                var storageTotal = Storage.StorageCleanupCatalog.All.Count + 3;
                UpdateCheckItem("StorageScan", item => item with { Status = DiagnosticStatus.Running, Message = "Measuring caches and leftovers that can be deleted…", Step = 1, Total = storageTotal });
                var storageProgress = CheckProgressExtensions.Create(cp =>
                {
                    UpdateCheckItem("StorageScan", item => item with { Status = DiagnosticStatus.Running, Message = cp.Message, Step = cp.Step > 0 ? cp.Step : item.Step, Total = cp.Total > 0 ? cp.Total : item.Total });
                    Status = cp.HasProgress
                        ? $"Running checks ({CompletedChecksCount} of {TotalChecksCount} done) · Storage caches & leftovers ({cp.Step}/{cp.Total}): {cp.Message}"
                        : $"Running checks ({CompletedChecksCount} of {TotalChecksCount} done) · Storage caches & leftovers: {cp.Message}";
                    Raise();
                });
                if (forceRerun || !memory.StorageScanned || memory.StorageError is not null)
                    await memory.ScanStorageAsync(refresh: true, ct, storageProgress).ConfigureAwait(false);
                var stCount = memory.StorageSuggestions.Count;
                var stMsg = stCount == 0 ? "Nothing large to clean up." : $"{stCount} cleanup item{(stCount == 1 ? "" : "s")} found.";
                UpdateCheckItem("StorageScan", item => item with { Status = stCount > 0 ? DiagnosticStatus.Warning : DiagnosticStatus.Ok, Message = stMsg, Step = item.Total, Total = item.Total });
                Note($"Storage caches & leftovers: {stMsg} ({CompletedChecksCount} of {TotalChecksCount})");
                suggestions = [.. memory.Suggestions, .. memory.StorageSuggestions];
            }
            var snapshot = results.Snapshot.Values.ToList();
            var fixes = FixCatalog.Build(snapshot, suggestions, remediation, diag.Catalog);
            var notOffered = FixCatalog.NotOffered(snapshot, suggestions, remediation);
            var findings = snapshot.Where(r => r.Status is DiagnosticStatus.Warning or DiagnosticStatus.Error && !Cancellation.IsCancelled(r) && !CheckEnableRules.IsTurnedOff(r))
                .Select(r => $"{diag.Catalog.DisplayName(r.ModuleName)}: {r.Message} (scan {r.Timestamp:O})").ToList();
            var hw = results.Get(ModuleSlugs.Osquery).Payload is HardwareInventory inv ? inv.FriendlySummary() : "";
            Save(s => s with
            {
                Stage = WorkflowStage.Review, ReviewRulesVersion = CurrentReviewRulesVersion, ReviewedUtc = DateTimeOffset.UtcNow,
                // Ticked: what the remote user chose for this fix last time, otherwise its default (everything except opt-in fixes).
                Fixes = fixes, Approved = fixes.Where(f => prefs?.IsTicked(f.Id, f.DefaultOn) ?? f.DefaultOn).Select(f => f.Id).ToList(),
                Findings = findings, NotOffered = notOffered, Recommendations = FixCatalog.Recommendations(suggestions), Machine = session?.MachineName ?? Environment.MachineName, HardwareSummary = hw,
            });
            Note($"Checks finished: {fixes.Count} fix{(fixes.Count == 1 ? "" : "es")} to review.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogWarn("checks failed: " + ex);
            Save(s => s with { Stage = WorkflowStage.Failed, Error = "The checks couldn't finish. Try again." });
        }
        finally { Busy = false; Raise(); }
    }

    public void SetApproved(string id, bool on)
    {
        if (State.Stage != WorkflowStage.Review) return;
        Save(s => s with { Approved = on ? s.Approved.Union([id]).ToList() : s.Approved.Where(x => x != id).ToList() });
        prefs?.RememberFixChoices([(id, on)]);
    }

    public void SetAllApproved(bool on)
    {
        if (State.Stage != WorkflowStage.Review) return;
        Save(s => s with { Approved = on ? s.Fixes.Select(f => f.Id).ToList() : [] });
        prefs?.RememberFixChoices(State.Fixes.Select(f => (f.Id, on)));
    }

    public void SetRecommendedApproved()
    {
        if (State.Stage != WorkflowStage.Review) return;
        Save(s => s with { Approved = s.Fixes.Where(f => f.DefaultOn).Select(f => f.Id).ToList() });
        prefs?.ForgetFixChoices(State.Fixes.Select(f => f.Id).ToList()); // back to the defaults, also for next time
    }

    public RestartSignInStatus RestartSignIn() => sys.GetRestartSignIn();

    /// <summary>Continuing after a restart is set up by the Agent: the app never runs as administrator.</summary>
    public const string NeedsAgentMessage = "Nothing was changed. Turn on Admin Repair Mode so the Agent can set up the restarts, then try again.";

    // ---- step 2: the tech's one click; everything after runs by itself ----

    /// <summary>
    /// Starts the unattended part. Windows signs the PC back in after each restart where it can (shutdown /g); otherwise someone signs in
    /// and the workflow carries on from there. No password is asked for or stored.
    /// </summary>
    public async Task<string?> StartAsync(CancellationToken ct = default)
    {
        if (State.Stage != WorkflowStage.Review) return "Run the checks first.";
        var signsIn = false;
        try { signsIn = sys.GetRestartSignIn().SignsInBySelf; } catch (Exception ex) { Log("restart sign-in status: " + ex.Message); }
        if (!await sys.RegisterResumeAsync(ct).ConfigureAwait(false))
            return "Couldn't set the app to continue after the restart. " + NeedsAgentMessage;
        Save(s => s with
        {
            Stage = WorkflowStage.RestartBefore, StartedUtc = DateTimeOffset.UtcNow, Actor = Actor, Error = null, SignsInAfterRestart = signsIn,
            ResumeTaskCreated = true, ResumeTaskRemoved = null, Restarts = [], RestartAborted = false,
            Outcomes = [], ChangesTracked = journal is not null, ReportPath = null, ReportHtml = null,
        });
        Event(LogLevel.Information, $"Service workflow started\r\nActor: {Actor}\r\nFixes approved: {State.Approved.Count} of {State.Fixes.Count}\r\nWindows signs back in after restarts: {(signsIn ? "yes" : "no, someone signs in")}");
        return await RestartAsync("Restarting so the before benchmark starts from a fresh boot.", ct).ConfigureAwait(false);
    }

    private async Task<string?> RestartAsync(string why, CancellationToken ct)
    {
        Note(why);
        var asked = DateTimeOffset.UtcNow;
        Save(s => s with { RestartRequestedUtc = asked });
        var ok = await sys.RestartAsync(RestartDelay, "Remote PC Diagnostics: restarting to continue the service workflow. Please save your work.", ct).ConfigureAwait(false);
        Save(s => s with { Restarts = [.. s.Restarts, new WorkflowRestart(why, asked, ok)] });
        if (ok) return null;
        await FailAsync("Windows didn't accept the restart.", ct).ConfigureAwait(false);
        return "Windows didn't accept the restart.";
    }

    /// <summary>True when Windows started after the restart was requested (so this is the new boot, not the old one).</summary>
    public bool RestartHappened(DateTimeOffset now) =>
        State.RestartRequestedUtc is { } asked && now - sys.Uptime > asked;

    // ---- after each restart ----

    /// <summary>Called once when the app starts: continues a workflow that was waiting for a restart (or was interrupted mid-step).</summary>
    public async Task ResumeAsync(CancellationToken ct = default)
    {
        var stage = State.Stage;
        if (!State.IsRunning || Busy) return;
        if (stage is WorkflowStage.RestartBefore or WorkflowStage.RestartAfter && !RestartHappened(DateTimeOffset.UtcNow))
        {
            Note("Waiting for the restart (it was cancelled or hasn't happened yet). Use \"Restart now\" to continue.");
            return;
        }
        Busy = true;
        _resuming = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var token = _cts.Token;
        if (stage is WorkflowStage.RestartBefore or WorkflowStage.RestartAfter)
        {
            var booted = DateTimeOffset.UtcNow - sys.Uptime;
            // The restart has happened: leave the restart stage right away (before settling), so the page stops offering "Restart now"
            // and a second press can't restart the PC again while start-up settles.
            var next = stage == WorkflowStage.RestartBefore ? WorkflowStage.BeforeBenchmark : WorkflowStage.AfterBenchmark;
            Save(s => s with { Stage = next, Restarts = s.Restarts.Select((r, i) => i == s.Restarts.Count - 1 && r.BootedUtc is null ? r with { BootedUtc = booted } : r).ToList() });
            stage = next;
        }
        try
        {
            if (stage is WorkflowStage.RestartBefore or WorkflowStage.BeforeBenchmark)
            {
                await SettleAsync(token).ConfigureAwait(false);
                Save(s => s with { Stage = WorkflowStage.BeforeBenchmark });
                Note("Running the before benchmark…");
                bench.Clear();
                // Only the start-up after the workflow's own restart, so before and after are both a restart the app asked for.
                var bootedBefore = State.Restarts.LastOrDefault(r => r.BootedUtc is not null)?.BootedUtc;
                if (await bench.RunAsync(BenchmarkPhase.Before, token, bootedBefore?.AddSeconds(-30)).ConfigureAwait(false) is null) throw new InvalidOperationException("before benchmark didn't start");
                stage = WorkflowStage.Applying;
                Save(s => s with { Stage = WorkflowStage.Applying });
            }
            if (stage is WorkflowStage.Applying)
            {
                await ApplyAsync(token).ConfigureAwait(false);
                Save(s => s with { Stage = WorkflowStage.RestartAfter });
                await RestartAsync("Fixes applied. Restarting so the after benchmark starts from a fresh boot.", token).ConfigureAwait(false);
                return;
            }
            if (stage is WorkflowStage.RestartAfter or WorkflowStage.AfterBenchmark)
            {
                await SettleAsync(token).ConfigureAwait(false);
                Save(s => s with { Stage = WorkflowStage.AfterBenchmark });
                Note("Running the after benchmark…");
                if (await bench.RunAsync(BenchmarkPhase.After, token).ConfigureAwait(false) is null) Log("after benchmark didn't run");
                // After the benchmark (so the scans don't load the PC while it's measured): confirm the repairs on the fresh boot.
                await RescanAfterRepairAsync(token).ConfigureAwait(false);
                stage = WorkflowStage.Reporting;
                Save(s => s with { Stage = WorkflowStage.Reporting });
            }
            if (stage is WorkflowStage.Reporting)
            {
                // Clean up first, so the report can say whether the restart task is really gone.
                await CleanupAsync(token).ConfigureAwait(false);
                Note("Writing the client report…");
                Save(s => s with { Stage = WorkflowStage.Done });
                var path = WriteReport();
                Note(path is null ? "Done. The report is shown here (it couldn't be saved as a file)." : $"Done. Report saved to {path}");
                Event(State.ResumeTaskRemoved != false ? LogLevel.Information : LogLevel.Warning,
                    $"Service workflow finished\r\nActor: {State.Actor}\r\n{bench.Comparison.OverallText}\r\nApplied: {State.Outcomes.Count(o => o.Success && !o.Skipped)} · Failed: {State.Outcomes.Count(o => !o.Success && !o.Skipped)} · Skipped: {State.Outcomes.Count(o => o.Skipped)}\r\n{CleanupText()}\r\nReport: {path ?? "(not saved)"}");
            }
        }
        catch (OperationCanceledException) { Log("resume cancelled"); }
        catch (Exception ex) { LogWarn("resume failed: " + ex); await FailAsync("Something went wrong while continuing the workflow.", CancellationToken.None).ConfigureAwait(false); }
        finally { Busy = false; _cts?.Dispose(); _cts = null; _resuming?.TrySetResult(); Raise(); }
    }

    private async Task SettleAsync(CancellationToken ct)
    {
        var wait = bench.Settings.SettleAfterRestart;
        Note($"Restart complete. Letting Windows finish starting up ({wait.TotalMinutes:0} min)…");
        try
        {
            await BenchmarkService.WaitWithCountdownAsync(wait, Delay, (rem, frac) =>
            {
                SettleRemaining = rem;
                SettleTotal = wait;
                SettleFraction = frac;
                Status = $"Restart complete. Letting Windows finish starting up ({BenchmarkService.FormatCountdown(rem)} left of {wait.TotalMinutes:0} min)…";
                Raise();
            }, ct).ConfigureAwait(false);
        }
        finally
        {
            SettleRemaining = null;
            SettleTotal = null;
            SettleFraction = null;
            Raise();
        }
    }

    private async Task ApplyAsync(CancellationToken ct)
    {
        var approved = State.Fixes.Where(f => State.IsApproved(f.Id)).OrderBy(f => f.Order).ToList();
        IReadOnlyList<MemorySuggestion> fresh = [];
        if (memory is not null && approved.Any(f => f.Source == FixSource.Memory))
        {
            await memory.ScanAsync(ct).ConfigureAwait(false); // suggestions are matched again on the fresh boot
            // Storage cleanups are measured again too; each one re-checks its rules on disk again right before deleting.
            if (approved.Any(f => f.MemoryAction == MemoryActionType.CleanStorage)) await memory.ScanStorageAsync(refresh: true, ct).ConfigureAwait(false);
            fresh = [.. memory.Suggestions, .. memory.StorageSuggestions];
        }
        var outcomes = new List<FixOutcome>();
        for (var i = 0; i < approved.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            var f = approved[i];
            Note($"Applying fix {i + 1} of {approved.Count}: {f.Title}…");
            var journalBefore = JournalIds();
            FixOutcome o;
            try { o = await ApplyOneAsync(f, fresh, ct).ConfigureAwait(false); }
            catch (OperationCanceledException)
            {
                // Stopped mid-fix: record it (and anything it already journaled) so the report doesn't lose a change.
                outcomes.Add(new(f.Id, f.Title, false, "Stopped while this was being applied; it may be partly done.", Changes: NewChanges(journalBefore)));
                Save(s => s with { Outcomes = outcomes.ToList() });
                throw;
            }
            catch (Exception ex) { LogError($"fix {f.Id} failed: {ex}"); o = new(f.Id, f.Title, false, "Windows didn't allow this change."); }
            outcomes.Add(o with { Changes = NewChanges(journalBefore) });
            Save(s => s with { Outcomes = outcomes.ToList() });
        }
        Note($"Applied {outcomes.Count(o => o.Success && !o.Skipped)} of {approved.Count} fixes.");
    }

    private HashSet<Guid> JournalIds()
    {
        try { return journal?.All.Select(c => c.Id).ToHashSet() ?? []; } catch (Exception ex) { Log("journal read: " + ex.Message); return []; }
    }

    /// <summary>Journal entries written since <paramref name="before"/> (by the fix that just ran).</summary>
    private IReadOnlyList<FixChange> NewChanges(HashSet<Guid> before)
    {
        try
        {
            return journal?.All.Where(c => !before.Contains(c.Id)).OrderBy(c => c.TimeUtc)
                .Select(c => new FixChange(c.Id, Undoability.Describe(c), Undoability.Of(c))).ToList() ?? [];
        }
        catch (Exception ex) { Log("journal read: " + ex.Message); return []; }
    }

    private async Task<FixOutcome> ApplyOneAsync(WorkflowFix f, IReadOnlyList<MemorySuggestion> fresh, CancellationToken ct)
    {
        if (f.Source == FixSource.Remediation && f.Remediation is { Kind: RemediationKind.RepairComponentStore or RemediationKind.RepairSystemFiles } rep)
            return await ApplyRepairAsync(f, rep, ct).ConfigureAwait(false);
        if (f.Source == FixSource.Remediation && f.Remediation is { } skip && FixCatalog.SkippedRemediation.Contains(skip.Kind))
            return new(f.Id, f.Title, true, "Skipped: this fix isn't run as part of a workflow. Apply it from its own page if it's still needed.", Skipped: true);
        if (f.Source == FixSource.Remediation && f.Remediation is { } a)
        {
            var r = await remediation.ExecuteAsync(a, ct).ConfigureAwait(false);
            return new(f.Id, f.Title, r.Success, r.Message);
        }
        if (f.Source == FixSource.Memory && memory is not null && f.MemoryAction is { } t)
        {
            var s = fresh.FirstOrDefault(x => x.Id == f.SuggestionId);
            var action = s?.Actions.FirstOrDefault(x => x.Type == t && x.Target == f.MemoryTarget);
            if (s is null || action is null) return new(f.Id, f.Title, true, "Not needed any more after the restart.", Skipped: true);
            var r = await memory.ApplyAsync(s, action, ct).ConfigureAwait(false);
            return new(f.Id, f.Title, r.Success, r.Message, Skipped: r.Skipped);
        }
        return new(f.Id, f.Title, false, "Skipped: this fix couldn't be run here (the part of the app that applies it isn't available).", Skipped: true);
    }

    private async Task<FixOutcome> ApplyRepairAsync(WorkflowFix f, AreaAction a, CancellationToken ct)
    {
        var title = f.Title;
        RepairFraction = null;
        remediation.RepairProgress = new InlineProgress(p =>
        {
            Status = $"{title}: {p}";
            var m = System.Text.RegularExpressions.Regex.Match(p, @"(\d{1,3}(?:\.\d+)?)\s*%");
            if (m.Success && double.TryParse(m.Groups[1].Value, System.Globalization.NumberStyles.AllowDecimalPoint, System.Globalization.CultureInfo.InvariantCulture, out var pct))
                RepairFraction = Math.Clamp(pct / 100.0, 0, 1);
            Raise();
        });
        RemediationResult r;
        try { r = await remediation.ExecuteAsync(a, ct).ConfigureAwait(false); }
        finally { remediation.RepairProgress = null; RepairFraction = null; }
        if (remediation.LastRepair is { } rr && (rr.Id == WindowsRepair.DismId) == (a.Kind == RemediationKind.RepairComponentStore))
        {
            Save(s => s with
            {
                RepairFindings = [.. s.RepairFindings, ToFinding(rr, afterRestart: false)],
                RepairRebootPending = s.RepairRebootPending || rr.RebootRequired,
            });
            if (rr.RebootRequired) Note($"{title}: Windows asked for a restart; the restart after the fixes covers it.");
        }
        return new(f.Id, f.Title, r.Success, r.Message);
    }

    private static RepairFinding ToFinding(RepairResult r, bool afterRestart) =>
        new(r.Id, r.Title, r.Status, r.Summary, r.Evidence, r.Details.Select(d => new RepairDetail(d.Label, d.Value)).ToList(), r.RebootRequired, afterRestart);

    /// <summary>After the restart: scan again (DISM ScanHealth, SFC verify-only) for the repairs that ran, so the report shows the state after.</summary>
    private async Task RescanAfterRepairAsync(CancellationToken ct)
    {
        var ran = State.RepairFindings.Where(x => !x.AfterRestart).Select(x => x.Id).ToHashSet();
        if (ran.Count == 0 || State.RepairFindings.Any(x => x.AfterRestart)) return;
        var scans = diag.Modules.OfType<WindowsIntegrityModule>()
            .Select(m => (Module: m, Id: m is DismScanHealthModule ? WindowsRepair.DismId : WindowsRepair.SfcId))
            .Where(x => ran.Contains(x.Id)).ToList();
        try
        {
            for (var i = 0; i < scans.Count; i++)
                await RescanOneAsync(scans[i].Module, scans[i].Id, i + 1, scans.Count, ct).ConfigureAwait(false);
        }
        finally { Rescan = null; Raise(); }
    }

    private async Task RescanOneAsync(WindowsIntegrityModule m, string id, int number, int count, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        Rescan = new(m.DisplayName, number, count, DateTimeOffset.UtcNow, null);
        Note($"Checking again after the restart ({number} of {count}): {m.DisplayName}. This can take several minutes…");
        var progress = CheckProgressExtensions.Create(cp =>
        {
            if (Rescan is { } now) Rescan = now with { Message = cp.Message };
            Status = $"Checking again after the restart ({number} of {count}): {m.DisplayName}: {cp.Message}";
            Raise();
        });
        DiagnosticResult r;
        try { r = await diag.RunAsync(m.Name, progress, ct).ConfigureAwait(false); }
        catch (Exception ex) when (ex is not OperationCanceledException) { LogWarn("re-scan failed: " + ex.Message); return; }
        var card = (r.Report() as AreaReport)?.Cards.FirstOrDefault();
        var finding = new RepairFinding($"{id}-after", $"{m.DisplayName} after the restart",
            r.Status, r.Message, card?.Meta ?? "", card?.Rows.Select(x => new RepairDetail(x.Values.Count > 0 ? x.Values[0] : "", x.Values.Count > 1 ? x.Values[1] : "")).ToList() ?? [],
            AfterRestart: true);
        Save(s => s with { RepairFindings = [.. s.RepairFindings, finding] });
    }

    private sealed class InlineProgress(Action<string> a) : IProgress<string> { public void Report(string v) { try { a(v); } catch { } } }

    // ---- control ----

    /// <summary>Retries a restart that was cancelled or didn't happen.</summary>
    /// <summary>True only while the workflow is really waiting for a restart (not once it has restarted and is continuing).</summary>
    public bool WaitingForRestart => !Busy && State.Stage is WorkflowStage.RestartBefore or WorkflowStage.RestartAfter && !RestartHappened(DateTimeOffset.UtcNow);

    /// <summary>When the app starts with a workflow in progress, it opens on the Service workflow page.</summary>
    public bool ShouldOpenWorkflowPage => State.IsRunning;

    public Task<string?> RestartNowAsync(CancellationToken ct = default) =>
        WaitingForRestart ? RestartAsync("Restarting now…", ct) : Task.FromResult<string?>("Nothing is waiting for a restart.");

    /// <summary>Stops the workflow: aborts a pending restart and removes the restart task. Fixes already applied stay (use Undo).</summary>
    public async Task CancelAsync()
    {
        var wasRunning = State.IsRunning;
        var restartPending = State.Stage is WorkflowStage.RestartBefore or WorkflowStage.RestartAfter;
        try { _cts?.Cancel(); } catch (ObjectDisposedException) { }
        try { bench.Stop(); } catch { }
        // Let a running step finish recording what it did before the report is written.
        if (_resuming is { } r) try { await r.Task.WaitAsync(TimeSpan.FromSeconds(60)).ConfigureAwait(false); } catch (TimeoutException) { Log("cancel: the running step didn't stop in time"); }
        try { await sys.AbortRestartAsync(CancellationToken.None).ConfigureAwait(false); } catch (Exception ex) { LogWarn("abort restart: " + ex.Message); }
        await CleanupAsync(CancellationToken.None).ConfigureAwait(false);
        Save(s => s with { Stage = WorkflowStage.Cancelled, RestartAborted = s.RestartAborted || restartPending });
        Note("Workflow cancelled. Fixes already applied stay in place (use Undo changes to revert them).");
        var path = wasRunning && State.StartedUtc is not null ? WriteReport() : null;
        Event(LogLevel.Warning, $"Service workflow cancelled\r\nActor: {Actor}\r\nApplied before cancelling: {State.Outcomes.Count(o => o.Success && !o.Skipped)}\r\n{CleanupText()}\r\nReport: {path ?? "(not saved)"}");
    }

    /// <summary>
    /// Reads the saved workflow again: the Agent keeps it, and it may connect after the app started (nothing could be read then).
    /// Only while nothing has happened in this run, so it never replaces a workflow in progress. True when it got a saved workflow.
    /// </summary>
    public bool Reload()
    {
        if (Busy) return false;
        var saved = LoadState(store);
        lock (_gate)
        {
            var untouched = _state is { Stage: WorkflowStage.Idle, StartedUtc: null, ReviewedUtc: null, Fixes.Count: 0, Log.Count: 0 };
            if (!untouched || saved.Stage == WorkflowStage.Idle) return false;
            _state = saved;
        }
        Log($"Saved workflow read after the Agent connected (stage {saved.Stage}).");
        Raise();
        return true;
    }

    /// <summary>Back to the start (keeps nothing of the old run except saved benchmark results).</summary>
    public void Reset()
    {
        if (State.IsRunning || Busy) return;
        Status = null;
        lock (_gate) _checkItems.Clear();
        Save(_ => new WorkflowState());
    }

    /// <summary>
    /// Drops a review that is only parked. The person left the Service workflow page, chose Start over, or a remote caller
    /// dismissed it. An active stage is left as it is. True when a review was cleared and the workflow is Idle.
    /// </summary>
    public bool DismissParkedReview()
    {
        if (Busy || State.Stage != WorkflowStage.Review)
            return false;
        Reset();
        return State.Stage == WorkflowStage.Idle;
    }

    // ---- after the run: one-change Undo / Reinstall and Apply / Remove again, from the report box ----

    /// <summary>Report-box actions are only offered on a finished or stopped run, and one at a time.</summary>
    public bool CanChangeAfterRun => !Busy && State.StartedUtc is not null && State.Stage is WorkflowStage.Done or WorkflowStage.Cancelled or WorkflowStage.Failed;

    /// <summary>
    /// Undoes one change this run made (Undo, or Reinstall for a removed Store app) through <paramref name="undo"/>, whose admin parts run in
    /// the Agent like "Undo all". Marks it undone in the report and saves the report again. Returns the message to show.
    /// </summary>
    public async Task<string> UndoChangeAsync(UndoService undo, Guid journalId, CancellationToken ct = default)
    {
        if (!CanChangeAfterRun) return "Wait until the service workflow has finished.";
        var change = State.Outcomes.SelectMany(o => o.Changes ?? []).FirstOrDefault(c => c.JournalId == journalId);
        if (change is null) return "That change isn't part of this service.";
        if (change.UndoneUtc is not null) return "Already undone.";
        if (change.Undo is not (UndoSupport.Full or UndoSupport.Reinstall)) return "This change is permanent, so it can't be undone.";
        if (journal is { IsLoaded: false }) return "The undo list is kept by the Agent. Turn on Admin Repair Mode, then try again.";
        Busy = true; Raise();
        try
        {
            var r = await undo.UndoChangeAsync(journalId, Actor, ct).ConfigureAwait(false);
            // Not in the journal any more: "Undo all" (or the History page) already put it back.
            if (r is null || r.Success)
            {
                MarkUndone(journalId, DateTimeOffset.UtcNow);
                RewriteReport();
                var message = r?.Message ?? "Already put back by an earlier undo.";
                Note($"Undid \"{change.Text}\": {message}");
                return message;
            }
            Note($"Couldn't undo \"{change.Text}\": {r.Message}");
            return r.Message;
        }
        finally { Busy = false; Raise(); }
    }

    /// <summary>
    /// Runs an undone fix again ("Apply again", or "Remove again" for a reinstalled app), the same way the workflow applied it, and records what
    /// it changed this time so it can be undone again. Saves the report again. Returns the message to show.
    /// </summary>
    public async Task<string> ReapplyFixAsync(string fixId, CancellationToken ct = default)
    {
        if (!CanChangeAfterRun) return "Wait until the service workflow has finished.";
        var outcome = State.Outcomes.FirstOrDefault(o => o.FixId == fixId);
        var fix = State.Fixes.FirstOrDefault(f => f.Id == fixId);
        if (outcome is null || fix is null || !ReportItems.CanReapply(State, outcome)) return "Undo this fix first, then it can be applied again.";
        Busy = true; Raise();
        try
        {
            IReadOnlyList<MemorySuggestion> fresh = [];
            if (fix.Source == FixSource.Memory && memory is not null)
            {
                await memory.ScanAsync(ct).ConfigureAwait(false);
                fresh = [.. memory.Suggestions, .. memory.StorageSuggestions];
            }
            var before = JournalIds();
            FixOutcome o;
            try { o = await ApplyOneAsync(fix, fresh, ct).ConfigureAwait(false); }
            catch (Exception ex) when (ex is not OperationCanceledException) { LogError($"reapply {fixId} failed: {ex}"); o = new(fix.Id, fix.Title, false, "Windows didn't allow this change."); }
            var added = NewChanges(before);
            if (o.Success && !o.Skipped && added.Count > 0)
            {
                Save(s => s with
                {
                    Outcomes = s.Outcomes.Select(x => x.FixId != fixId ? x
                        : x with { Message = o.Message, Changes = [.. (x.Changes ?? []).Where(c => c.UndoneUtc is null), .. added] }).ToList(),
                });
                RewriteReport();
                Note($"Applied \"{fix.Title}\" again: {o.Message}");
                return o.Message;
            }
            var why = o.Success ? (o.Skipped ? o.Message : "Nothing needed changing: it's already set.") : o.Message;
            Note($"Couldn't apply \"{fix.Title}\" again: {why}");
            return why;
        }
        finally { Busy = false; Raise(); }
    }

    private void MarkUndone(Guid journalId, DateTimeOffset when) =>
        Save(s => s with
        {
            Outcomes = s.Outcomes.Select(o => o.Changes is { } ch && ch.Any(c => c.JournalId == journalId)
                ? o with { Changes = ch.Select(c => c.JournalId == journalId ? c with { UndoneUtc = when } : c).ToList() }
                : o).ToList(),
        });

    /// <summary>Saves the report again in the same file, so the file and the page show what's undone now.</summary>
    private void RewriteReport()
    {
        try { SaveAndStoreReport(State.FinishedUtc?.ToLocalTime() ?? DateTimeOffset.Now, State.Branding, preferredPath: State.ReportPath); }
        catch (Exception ex) { LogWarn("report rewrite failed: " + ex.Message); }
    }

    /// <summary>True when <paramref name="baseRelativePath"/> is the Service workflow page (no leading slash, query ignored).</summary>
    public static bool IsWorkflowRoute(string? baseRelativePath)
    {
        var path = (baseRelativePath ?? "").Split('?', '#')[0].Trim().Trim('/');
        return path.Equals("workflow", StringComparison.OrdinalIgnoreCase);
    }

    private async Task FailAsync(string message, CancellationToken ct)
    {
        await CleanupAsync(ct).ConfigureAwait(false);
        Save(s => s with { Stage = WorkflowStage.Failed, Error = message });
        Note(message);
        var path = State.StartedUtc is not null ? WriteReport() : null;
        Event(LogLevel.Warning, $"Service workflow failed\r\n{message}\r\n{CleanupText()}\r\nReport: {path ?? "(not saved)"}");
    }

    /// <summary>Removes the restart task, recording whether it really went (for the report).</summary>
    private async Task CleanupAsync(CancellationToken ct)
    {
        if (State.ResumeTaskRemoved != true) // also when nothing was registered: removing a missing task is harmless
        {
            bool removed;
            try { removed = await sys.RemoveResumeAsync(ct).ConfigureAwait(false); }
            catch (Exception ex) { Log("remove resume task: " + ex.Message); removed = false; }
            Save(s => s with { ResumeTaskRemoved = removed });
            if (!removed) Note($"Couldn't remove the scheduled task \"{ResumeTaskName}\". Delete it in Task Scheduler.");
        }
    }

    private string CleanupText() =>
        State.ResumeTaskRemoved == false ? $"Scheduled task \"{ResumeTaskName}\": COULD NOT BE REMOVED" : "Scheduled task: removed";

    /// <summary>
    /// Builds the client report from the current state, saves it, and keeps the exact HTML in the state so the page shows the same report
    /// as the file. Returns the saved path (null = couldn't be saved).
    /// </summary>
    private string? WriteReport()
    {
        var when = DateTimeOffset.Now;
        var earlier = 0;
        try
        {
            var mine = State.Outcomes.SelectMany(o => o.Changes ?? []).Select(c => c.JournalId).ToHashSet();
            earlier = journal?.All.Count(c => !mine.Contains(c.Id)) ?? 0;
        }
        catch (Exception ex) { Log("journal read: " + ex.Message); }
        var branding = ResolveBranding(State.Branding);
        Save(s => s with { FinishedUtc = when.ToUniversalTime(), EarlierChanges = earlier, Branding = branding });
        return SaveAndStoreReport(when, branding);
    }

    /// <summary>Re-renders and re-saves the current workflow's client report after shop branding or per-report technician notes are edited.</summary>
    public string? RefreshReportBranding(ShopBranding? overrideBranding = null)
    {
        var when = State.FinishedUtc?.ToLocalTime() ?? DateTimeOffset.Now;
        var branding = ResolveBranding(overrideBranding ?? State.Branding);
        Save(s => s with { Branding = branding });
        var path = SaveAndStoreReport(when, branding, preferredPath: State.ReportPath);
        Changed?.Invoke();
        return path;
    }

    /// <summary>Builds and saves a 1-page Buyer Hardware QA Certificate from the latest diagnostic results.</summary>
    public string? SaveHardwareQaCertificate(ShopBranding? overrideBranding = null, PhysicalBenchQaSnapshot? physicalQa = null) =>
        SaveHardwareQaCertificate(out _, out _, overrideBranding, physicalQa);

    /// <summary>Builds and saves a 1-page Buyer Hardware QA Certificate from the latest diagnostic results.</summary>
    public string? SaveHardwareQaCertificate(
        out HardwareQaSnapshot snapshot,
        out string html,
        ShopBranding? overrideBranding = null,
        PhysicalBenchQaSnapshot? physicalQa = null)
    {
        var when = DateTimeOffset.Now;
        var branding = ResolveBranding(overrideBranding);
        var machine = !string.IsNullOrWhiteSpace(session?.MachineName) ? session.MachineName : State.Machine;
        snapshot = HardwareQaCertificate.Capture(results, machine, when, branding, physicalQa: physicalQa);
        html = HardwareQaCertificate.BuildHtml(snapshot);
        string? path = null;
        try
        {
            path = sys.CertificateFile(when, snapshot.CertificateId);
            sys.SaveReport(path, html);
        }
        catch (Exception ex)
        {
            LogWarn("qa certificate save failed: " + ex.Message);
            path = null;
        }
        return path;
    }

    private ShopBranding? ResolveBranding(ShopBranding? reportSpecific)
    {
        var global = prefs?.Current.Branding?.Normalized();
        var specific = reportSpecific?.Normalized();
        if (global is null) return specific?.HasAny == true ? specific : null;
        if (specific is null) return global.HasAny ? global : null;
        var merged = global with
        {
            TechnicianName = specific.TechnicianName ?? global.TechnicianName,
            TechnicianNotes = specific.TechnicianNotes ?? global.TechnicianNotes,
        };
        return merged.HasAny ? merged : null;
    }

    private string? SaveAndStoreReport(DateTimeOffset when, ShopBranding? branding, string? preferredPath = null)
    {
        string? path = preferredPath;
        if (string.IsNullOrWhiteSpace(path))
        {
            try { path = sys.ReportFile(when); } catch (Exception ex) { Log("report path: " + ex.Message); path = null; }
        }
        var html = path is null ? null : ClientReport.Build(State with { ReportPath = path, Branding = branding }, bench.Before, bench.After, bench.Comparison, when, branding);
        if (path is not null)
        {
            try { sys.SaveReport(path, html!); }
            catch (Exception ex) { LogWarn("report save failed: " + ex.Message); path = null; }
        }
        if (path is null) html = ClientReport.Build(State with { ReportPath = null, Branding = branding }, bench.Before, bench.After, bench.Comparison, when, branding);
        Save(s => s with { ReportPath = path, ReportHtml = html, Branding = branding });
        return path;
    }

    private void Event(LogLevel l, string text) { try { events?.Invoke(l, text); } catch { } }
}
