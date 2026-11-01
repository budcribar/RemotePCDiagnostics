using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Benchmarks;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Memory;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Workflow;

/// <summary>Credentials for the temporary automatic sign-in (used once, never saved by this app).</summary>
public sealed record AutoLogonRequest(string User, string Domain, string Password);

/// <summary>
/// Runs the whole service call with one decision from the tech. State is saved after every step, and the app is started again
/// (elevated, same session) after each restart, so the workflow carries on by itself.
/// </summary>
public sealed class WorkflowService(
    DiagnosticsService diag, ResultStore results, RemediationService remediation, BenchmarkService bench, IWorkflowSystem sys, IWorkflowStore store,
    MemorySuggestionService? memory = null, ISessionContext? session = null, Action<LogLevel, string>? events = null, Action<string>? log = null,
    Func<TimeSpan, CancellationToken, Task>? delay = null)
{
    public const int RestartsInWorkflow = 2;
    public static readonly TimeSpan RestartDelay = TimeSpan.FromSeconds(30);

    private readonly object _gate = new();
    /// <summary>4: Windows Search only on small, nearly-full PCs without classic Outlook, and opt-in (unticked).</summary>
    public const int CurrentReviewRulesVersion = 4;
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

    public event Action? Changed;
    public WorkflowState State { get { lock (_gate) return _state; } }
    public string? Status { get; private set; }
    public bool Busy { get; private set; }

    private string Actor => ServiceActor.From(session);
    private void Log(string m) { try { log?.Invoke("[workflow] " + m); } catch { } }
    private void Raise() { try { Changed?.Invoke(); } catch (Exception ex) { Log("Changed handler failed: " + ex.Message); } }

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
        Log(line);
        Save(s => s with { Log = [.. s.Log.TakeLast(199), $"{DateTimeOffset.Now:g}  {line}"] });
    }

    private Task Delay(TimeSpan t, CancellationToken ct) => (delay ?? Task.Delay)(t, ct);

    // ---- step 1: checks → review ----

    public async Task RunChecksAsync(CancellationToken ct = default)
    {
        if (Busy || State.IsRunning) return;
        Busy = true;
        Save(_ => new WorkflowState { Stage = WorkflowStage.Checking, Actor = Actor });
        try
        {
            Note("Running all checks…");
            await diag.RunAllAsync(ct).ConfigureAwait(false);
            IReadOnlyList<MemorySuggestion> suggestions = [];
            if (memory is not null)
            {
                Note("Looking for ways to use less memory…");
                await memory.ScanAsync(ct).ConfigureAwait(false);
                suggestions = memory.Suggestions;
            }
            var snapshot = results.Snapshot.Values.ToList();
            var fixes = FixCatalog.Build(snapshot, suggestions, remediation);
            var findings = snapshot.Where(r => r.Status is DiagnosticStatus.Warning or DiagnosticStatus.Error && !DashboardSummary.IsCancelled(new BannerModule(r.ModuleName, r.ModuleName, false, false, r.Status, r.Message)))
                .Select(r => $"{diag.Modules.FirstOrDefault(m => m.Name == r.ModuleName)?.DisplayName ?? r.ModuleName}: {r.Message}").ToList();
            var hw = results.Get("Osquery").Payload is HardwareInventory inv ? inv.FriendlySummary() : "";
            Save(s => s with
            {
                Stage = WorkflowStage.Review, ReviewRulesVersion = CurrentReviewRulesVersion,
                Fixes = fixes, Approved = fixes.Where(f => f.DefaultOn).Select(f => f.Id).ToList(), // everything starts ticked except opt-in fixes
                Findings = findings, Recommendations = FixCatalog.Recommendations(suggestions), Machine = session?.MachineName ?? Environment.MachineName, HardwareSummary = hw,
            });
            Note($"Checks finished: {fixes.Count} fix{(fixes.Count == 1 ? "" : "es")} to review.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log("checks failed: " + ex);
            Save(s => s with { Stage = WorkflowStage.Failed, Error = "The checks couldn't finish. Try again." });
        }
        finally { Busy = false; Raise(); }
    }

    public void SetApproved(string id, bool on)
    {
        if (State.Stage != WorkflowStage.Review) return;
        Save(s => s with { Approved = on ? s.Approved.Union([id]).ToList() : s.Approved.Where(x => x != id).ToList() });
    }

    public void SetAllApproved(bool on)
    {
        if (State.Stage != WorkflowStage.Review) return;
        Save(s => s with { Approved = on ? s.Fixes.Select(f => f.Id).ToList() : [] });
    }

    public AutoLogonStatus AutoLogonStatus() => sys.GetAutoLogonStatus();

    // ---- step 2: the tech's one click; everything after runs by itself ----

    /// <summary>Starts the unattended part. <paramref name="signIn"/> null = the PC signs in by itself already, or the client will sign in.</summary>
    public async Task<string?> StartAsync(AutoLogonRequest? signIn, CancellationToken ct = default)
    {
        if (State.Stage != WorkflowStage.Review) return "Run the checks first.";
        AutoLogonBackup? backup = null;
        if (signIn is not null)
        {
            if (!sys.ValidateCredentials(signIn.User, signIn.Domain, signIn.Password)) return "That password didn't work for this account. Nothing was changed.";
            backup = sys.EnableAutoLogon(signIn.User, signIn.Domain, signIn.Password, RestartsInWorkflow);
        }
        if (!await sys.RegisterResumeAsync(ct).ConfigureAwait(false))
        {
            if (backup is not null) sys.DisableAutoLogon(backup);
            return "Couldn't set the app to continue after the restart (administrator rights required). Nothing was changed.";
        }
        Save(s => s with { Stage = WorkflowStage.RestartBefore, StartedUtc = DateTimeOffset.UtcNow, Actor = Actor, AutoLogonEnabled = backup is not null, AutoLogonBackup = backup, Error = null });
        Event(LogLevel.Information, $"Service workflow started\r\nActor: {Actor}\r\nFixes approved: {State.Approved.Count} of {State.Fixes.Count}\r\nAutomatic sign-in: {(backup is not null ? "on (2 sign-ins)" : "off")}");
        return await RestartAsync("Restarting so the before benchmark starts from a fresh boot.", ct).ConfigureAwait(false);
    }

    private async Task<string?> RestartAsync(string why, CancellationToken ct)
    {
        Note(why);
        Save(s => s with { RestartRequestedUtc = DateTimeOffset.UtcNow });
        if (await sys.RestartAsync(RestartDelay, "Remote PC Diagnostics: restarting to continue the service workflow. Please save your work.", ct).ConfigureAwait(false)) return null;
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
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var token = _cts.Token;
        try
        {
            if (stage is WorkflowStage.RestartBefore or WorkflowStage.BeforeBenchmark)
            {
                await SettleAsync(token).ConfigureAwait(false);
                Save(s => s with { Stage = WorkflowStage.BeforeBenchmark });
                Note("Running the before benchmark…");
                bench.Clear();
                if (await bench.RunAsync(BenchmarkPhase.Before, token).ConfigureAwait(false) is null) throw new InvalidOperationException("before benchmark didn't start");
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
                await bench.RunAsync(BenchmarkPhase.After, token).ConfigureAwait(false);
                stage = WorkflowStage.Reporting;
                Save(s => s with { Stage = WorkflowStage.Reporting });
            }
            if (stage is WorkflowStage.Reporting)
            {
                Note("Writing the client report…");
                var html = ClientReport.Build(State, bench.Before, bench.After, bench.Comparison, DateTimeOffset.Now);
                string? path = null;
                try { path = sys.SaveReport(html, DateTimeOffset.Now); } catch (Exception ex) { Log("report save failed: " + ex.Message); }
                await CleanupAsync(token).ConfigureAwait(false);
                Save(s => s with { Stage = WorkflowStage.Done, ReportPath = path, FinishedUtc = DateTimeOffset.UtcNow });
                Note(path is null ? "Done. The report is shown here (it couldn't be saved as a file)." : $"Done. Report saved to {path}");
                Event(LogLevel.Information, $"Service workflow finished\r\nActor: {State.Actor}\r\n{bench.Comparison.OverallText}\r\nApplied: {State.Outcomes.Count(o => o.Success)} · Failed: {State.Outcomes.Count(o => !o.Success && !o.Skipped)} · Skipped: {State.Outcomes.Count(o => o.Skipped)}\r\nReport: {path ?? "(not saved)"}");
            }
        }
        catch (OperationCanceledException) { Log("resume cancelled"); }
        catch (Exception ex) { Log("resume failed: " + ex); await FailAsync("Something went wrong while continuing the workflow; automatic sign-in and the restart task were removed.", CancellationToken.None).ConfigureAwait(false); }
        finally { Busy = false; _cts?.Dispose(); _cts = null; Raise(); }
    }

    private async Task SettleAsync(CancellationToken ct)
    {
        var wait = bench.Settings.SettleAfterRestart;
        Note($"Restart complete. Letting Windows finish starting up ({wait.TotalMinutes:0} min)…");
        await Delay(wait, ct).ConfigureAwait(false);
    }

    private async Task ApplyAsync(CancellationToken ct)
    {
        var approved = State.Fixes.Where(f => State.IsApproved(f.Id)).OrderBy(f => f.Order).ToList();
        IReadOnlyList<MemorySuggestion> fresh = [];
        if (memory is not null && approved.Any(f => f.Source == FixSource.Memory))
        {
            await memory.ScanAsync(ct).ConfigureAwait(false); // suggestions are matched again on the fresh boot
            fresh = memory.Suggestions;
        }
        var outcomes = new List<FixOutcome>();
        for (var i = 0; i < approved.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            var f = approved[i];
            Note($"Applying fix {i + 1} of {approved.Count}: {f.Title}…");
            FixOutcome o;
            try { o = await ApplyOneAsync(f, fresh, ct).ConfigureAwait(false); }
            catch (Exception ex) when (ex is not OperationCanceledException) { Log($"fix {f.Id} failed: {ex}"); o = new(f.Id, f.Title, false, "Windows didn't allow this change."); }
            outcomes.Add(o);
            Save(s => s with { Outcomes = outcomes.ToList() });
        }
        Note($"Applied {outcomes.Count(o => o.Success)} of {approved.Count} fixes.");
    }

    private async Task<FixOutcome> ApplyOneAsync(WorkflowFix f, IReadOnlyList<MemorySuggestion> fresh, CancellationToken ct)
    {
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
            return new(f.Id, f.Title, r.Success, r.Message);
        }
        return new(f.Id, f.Title, false, "This fix isn't available.", Skipped: true);
    }

    // ---- control ----

    /// <summary>Retries a restart that was cancelled or didn't happen.</summary>
    public Task<string?> RestartNowAsync(CancellationToken ct = default) =>
        State.Stage is WorkflowStage.RestartBefore or WorkflowStage.RestartAfter ? RestartAsync("Restarting now…", ct) : Task.FromResult<string?>("Nothing is waiting for a restart.");

    /// <summary>Stops the workflow: aborts a pending restart, removes automatic sign-in and the restart task. Fixes already applied stay (use Undo).</summary>
    public async Task CancelAsync()
    {
        try { _cts?.Cancel(); } catch (ObjectDisposedException) { }
        try { bench.Stop(); } catch { }
        await sys.AbortRestartAsync(CancellationToken.None).ConfigureAwait(false);
        await CleanupAsync(CancellationToken.None).ConfigureAwait(false);
        Save(s => s with { Stage = WorkflowStage.Cancelled, FinishedUtc = DateTimeOffset.UtcNow });
        Note("Workflow cancelled. Fixes already applied stay in place (use Undo changes to revert them).");
        Event(LogLevel.Warning, $"Service workflow cancelled\r\nActor: {Actor}");
    }

    /// <summary>Back to the start (keeps nothing of the old run except saved benchmark results).</summary>
    public void Reset()
    {
        if (State.IsRunning || Busy) return;
        Status = null;
        Save(_ => new WorkflowState());
    }

    private async Task FailAsync(string message, CancellationToken ct)
    {
        await CleanupAsync(ct).ConfigureAwait(false);
        Save(s => s with { Stage = WorkflowStage.Failed, Error = message, FinishedUtc = DateTimeOffset.UtcNow });
        Note(message);
        Event(LogLevel.Warning, $"Service workflow failed\r\n{message}");
    }

    private async Task CleanupAsync(CancellationToken ct)
    {
        try { await sys.RemoveResumeAsync(ct).ConfigureAwait(false); } catch (Exception ex) { Log("remove resume task: " + ex.Message); }
        if (State.AutoLogonEnabled)
        {
            try { sys.DisableAutoLogon(State.AutoLogonBackup); Save(s => s with { AutoLogonEnabled = false }); }
            catch (Exception ex) { Log("disable auto sign-in: " + ex.Message); }
        }
    }

    private void Event(LogLevel l, string text) { try { events?.Invoke(l, text); } catch { } }
}
