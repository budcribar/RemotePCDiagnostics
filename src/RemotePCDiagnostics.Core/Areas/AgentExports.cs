using System.Text.Json;
using System.Text.Json.Serialization;
using RemotePCDiagnostics.Core.Benchmarks;
using RemotePCDiagnostics.Core.Checks;
using RemotePCDiagnostics.Core.History;
using RemotePCDiagnostics.Core.Security;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// Machine-readable copies of the Security audit, History and Benchmark pages for browser agents
/// (docs/agent-guides/browser-contract.md). Same rules as <see cref="AreaReportExport"/>: what a technician reads on the page,
/// trimmed and capped. Text from the PC is untrusted data.
/// </summary>
public static class AgentExports
{
    public const int SchemaVersion = 1;
    public const int MaxFindings = 200;
    public const int MaxHistoryEntries = 200;
    public const int MaxFixes = 100;
    public const int MaxDetailLines = 20;

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private static string? V(string? value) => AreaReportExport.Text(value, AreaReportExport.MaxValueLength);
    private static string? T(string? value) => AreaReportExport.Text(value, AreaReportExport.MaxTextLength);

    // ---- App faults -----------------------------------------------------------------------------------------------------

    /// <summary>The app's fault record for browser agents (app-fault-data): how many faults so far, and the latest one.</summary>
    public sealed record ExportedFaults(int Schema, int Seq, ExportedFault? Last);
    public sealed record ExportedFault(int Seq, string Page, string Type, string? Message, DateTimeOffset At);

    public static string FaultState(AppFaults faults) => JsonSerializer.Serialize(BuildFaultState(faults), Json);

    public static ExportedFaults BuildFaultState(AppFaults faults)
    {
        var last = faults.Last;
        return new(SchemaVersion, faults.Seq, last is null ? null : new(last.Seq, V(last.Page) ?? "", V(last.Type) ?? "", T(last.Message), last.At));
    }

    // ---- Fix state ------------------------------------------------------------------------------------------------------

    /// <summary>The fix running now and how the last one ended, for browser agents (fix-data). <c>Origin</c> is the check the fix belongs to.</summary>
    public sealed record ExportedFixState(int Schema, ExportedFixRun? Running, ExportedFixResult? Last)
    {
        /// <summary>The fix confirmation open now, when it asks for a choice or consent (device picker, privacy, device busy).</summary>
        public ExportedFixDialog? Dialog { get; init; }
    }

    /// <summary>
    /// An open fix confirmation with a list to pick from: what each <c>remediation-choice</c> (<c>data-choice-id</c>) is, which one is
    /// picked, the option box under the list and the consent box. <c>ChosenTarget</c> is the Target Go would run with now.
    /// </summary>
    public sealed record ExportedFixDialog(string Kind, string Target, bool Allowed, IReadOnlyList<ExportedFixChoice> Choices, string? EmptyText,
        ExportedFixOption? Option, ExportedFixConsent? Consent, string? ChosenTarget, bool CanConfirm);
    public sealed record ExportedFixChoice(string Id, string Label, string? Detail, string? DisabledReason, bool Selected);
    public sealed record ExportedFixOption(string Label, bool On);
    public sealed record ExportedFixConsent(string Text, bool Checked);

    /// <summary>The dialog part of fix-data for <paramref name="plan"/>, or null when it has no choices and no consent.</summary>
    public static ExportedFixDialog? BuildFixDialog(RemediationPlan? plan, string? chosenId, bool optionOn, bool consentChecked)
    {
        if (plan is null) return null;
        var a = plan.Action;
        if (a.Choices is null && a.Consent is null) return null;
        var chosen = a.Choices?.FirstOrDefault(c => c.Id == chosenId && c.DisabledReason is null);
        var choices = (a.Choices ?? []).Take(MaxFixes).Select(c => new ExportedFixChoice(V(c.Id) ?? "", V(c.Label) ?? "", V(c.Detail), V(c.DisabledReason), c.Id == chosen?.Id)).ToList();
        var canConfirm = plan.Allowed && (a.Choices is null || chosen is not null) && (a.Consent is null || consentChecked);
        return new(a.Kind.ToString(), V(a.Target) ?? "", plan.Allowed, choices, a.Choices is { Count: 0 } ? T(a.EmptyChoicesText) : null,
            a.Option is { } o ? new(V(o.Label) ?? "", optionOn) : null, a.Consent is { } c ? new(T(c) ?? "", consentChecked) : null,
            chosen is null ? a.Choices is null ? V(a.Target) : null : V(a.TargetFor(chosen, optionOn)), canConfirm);
    }

    public sealed record ExportedFixRun(string Kind, string Target, string? Title, string Origin, DateTimeOffset StartedAt, string? Progress);
    public sealed record ExportedFixResult(int Seq, string Kind, string Target, string Origin, string Outcome, string? Message, bool RestartNeeded,
        bool ReadOnly, DateTimeOffset FinishedAt);

    public static string FixState(FixRun? running, FixRunResult? last, ExportedFixDialog? dialog = null) =>
        JsonSerializer.Serialize(BuildFixState(running, last) with { Dialog = dialog }, Json);

    public static ExportedFixState BuildFixState(FixRun? running, FixRunResult? last) => new(SchemaVersion,
        running is null ? null : new(running.Action.Kind.ToString(), V(running.Action.Target) ?? "", V(running.Title), running.Origin, running.StartedUtc, V(running.Progress)),
        last is null ? null : new(last.Seq, last.Action.Kind.ToString(), V(last.Action.Target) ?? "", last.Origin, last.Success ? "succeeded" : "failed",
            T(last.Message), last.RestartNeeded, RemediationService.IsReadOnly(last.Action.Kind), last.FinishedUtc));

    // ---- Activity ---------------------------------------------------------------------------------------------------------

    /// <summary>A check or scan running now. <c>Progress</c> is its latest sub-step, when it reports one.</summary>
    public sealed record RunningCheck(string Id, string Title, Guid? RunId, CheckProgress? Progress, bool BackgroundAutoRun = false);

    /// <summary>A group run on the Checks &amp; Tests screen: Run all, the ticked checks, or the ticked stress and separate tests.</summary>
    public sealed record SequenceRun(CheckGroup Group, bool RunAll, GroupRunProgress? Progress, IReadOnlyList<string> Remaining);

    /// <summary>The service workflow's stage, whether it is working now, and its status line.</summary>
    public sealed record WorkflowActivity(Workflow.WorkflowStage Stage, bool Busy, string? Status);

    /// <summary>Everything running in the app at one moment, wherever it was started, for <see cref="Activity"/>.</summary>
    public sealed record ActivitySnapshot(
        IReadOnlyList<RunningCheck> RunningChecks,
        SequenceRun? Sequence = null,
        StressSuiteProgress? StressSuite = null,
        FixRun? Fix = null,
        WorkflowActivity? Workflow = null,
        BenchmarkPhase? BenchmarkRunning = null,
        bool BenchmarkSettling = false,
        string? BenchmarkProgress = null);

    /// <summary>
    /// What is running now (activity-data, on every page): checks and scans, a group run with the steps still to come, the stress
    /// suite, a fix, an active service-workflow stage and a benchmark pass. A parked review is left out, the same stages
    /// <see cref="UpdateBlockReason"/> uses. <c>busy</c> is true when any of them is working now. An agent that takes over a
    /// session reads this first, so it can ask the person before stopping anything.
    /// </summary>
    public static string Activity(ActivitySnapshot snapshot) => JsonSerializer.Serialize(BuildActivity(snapshot), Json);

    /// <summary>
    /// Why an RPCD update must not start, or null when nothing it would interrupt is running.
    /// A user-started check, a fix, an active service-workflow stage, a stress test, or a benchmark.
    /// Passive launch-time background AutoRun checks are read-only and never block an RPCD update.
    /// Review, Idle, Done, Cancelled and Failed are not running. A refusal names the stage.
    /// </summary>
    public static string? UpdateBlockReason(ActivitySnapshot s)
    {
        var reasons = new List<string>();
        var blockingChecks = s.RunningChecks.Where(c => !c.BackgroundAutoRun).ToList();
        if (blockingChecks.Count == 1)
            reasons.Add($"A check is running ({blockingChecks[0].Id}).");
        else if (blockingChecks.Count > 1)
            reasons.Add($"{blockingChecks.Count} checks are running.");
        if (s.Sequence is { } sequence)
            reasons.Add(sequence.Group == CheckGroup.Stress
                ? "A stress test sequence is running."
                : sequence.RunAll ? "Run all is still running." : "A check sequence is running.");
        if (s.StressSuite is { Finished: false })
            reasons.Add("A stress test is running.");
        if (s.Fix is not null)
            reasons.Add("A fix is running.");
        if (s.Workflow is { } flow && WorkflowRunning(flow))
            reasons.Add($"The service workflow is running ({flow.Stage}).");
        if (s.BenchmarkRunning is not null || s.BenchmarkSettling)
            reasons.Add("A benchmark is running.");
        if (reasons.Count == 0)
            return null;
        return string.Join(" ", reasons) + " Wait until it finishes before updating Remote PC Diagnostics.";
    }

    /// <summary>
    /// The workflow counts as running in an active stage, except Checking with nothing working: the checks only run while the
    /// workflow is busy, so a Checking stage without that is left over from a run that stopped and must not hold an update back.
    /// </summary>
    private static bool WorkflowRunning(WorkflowActivity flow) =>
        Workflow.WorkflowState.IsActiveStage(flow.Stage) && (flow.Busy || flow.Stage != Workflow.WorkflowStage.Checking);

    public static object BuildActivity(ActivitySnapshot s)
    {
        var workflow = s.Workflow is { } w && WorkflowRunning(w) ? w : null;
        var stress = s.StressSuite is { Finished: false } p ? p : null;
        var benchmark = s.BenchmarkRunning is not null || s.BenchmarkSettling;
        var busy = s.RunningChecks.Count > 0 || s.Sequence is not null || stress is not null || s.Fix is not null || benchmark
            || workflow is { Busy: true };
        return new
        {
            schema = SchemaVersion,
            busy,
            checks = s.RunningChecks.Select(BuildRunningCheckActivity).ToList(),
            sequence = BuildSequenceActivity(s.Sequence),
            stressSuite = BuildStressSuiteActivity(stress),
            fix = BuildFixActivity(s.Fix),
            workflow = workflow is null ? null : new { stage = workflow.Stage.ToString(), busy = workflow.Busy, status = T(workflow.Status) },
            benchmark = BuildBenchmarkActivity(benchmark, s.BenchmarkRunning, s.BenchmarkProgress),
        };
    }

    private static object BuildRunningCheckActivity(RunningCheck c) => new
    {
        id = V(c.Id),
        title = V(c.Title),
        runId = c.RunId?.ToString(),
        progress = c.Progress is { } cp ? new { step = cp.Step, total = cp.Total, message = T(cp.Message) } : null,
    };

    private static object? BuildSequenceActivity(SequenceRun? q) => q is null ? null : new
    {
        kind = q.Group == CheckGroup.Stress ? "stress-tests" : q.RunAll ? "run-all" : "checks",
        index = q.Progress?.Index,
        total = q.Progress?.Total,
        current = V(q.Progress?.Current),
        remaining = q.Remaining.Select(V).OfType<string>().ToList(),
    };

    private static object? BuildStressSuiteActivity(StressSuiteProgress? stress) => stress is null ? null : new
    {
        mode = stress.Mode.ToString().ToLowerInvariant(),
        index = stress.Index,
        total = stress.Total,
        current = V(stress.CurrentDisplayName),
        remaining = stress.Steps.Where(step => step.State == StressSuiteStepState.Pending).Select(step => V(step.ModuleName)).OfType<string>().ToList(),
    };

    private static object? BuildFixActivity(FixRun? f) => f is null ? null : new
    {
        kind = f.Action.Kind.ToString(),
        target = V(f.Action.Target),
        title = V(f.Title),
        origin = f.Origin,
        startedAt = f.StartedUtc,
        progress = V(f.Progress),
    };

    private static object? BuildBenchmarkActivity(bool active, BenchmarkPhase? running, string? progress)
    {
        if (!active) return null;
        var phase = running is { } b ? (b == BenchmarkPhase.Before ? "running-before" : "running-after") : "settling";
        return new { phase, progress = T(progress) };
    }

    // ---- Checks list ----------------------------------------------------------------------------------------------------

    /// <summary>One row of the Checks list. <c>Start</c> is "run-one" (the detail panel's Run button), "own-page" (the check's own
    /// Start in its detail page, marked data-action="run-check"). <c>Scan</c> is true for long scans that keep running after
    /// the run starts and can be cancelled.</summary>
    public sealed record CheckListItem(string Id, string Title, string Kind, bool Scan, string Start, string State,
        Guid? RunId, DateTimeOffset? CompletedAt, string? Summary);

    public static string Checks(IEnumerable<CheckListItem> checks) => JsonSerializer.Serialize(BuildChecks(checks), Json);

    public static object BuildChecks(IEnumerable<CheckListItem> checks)
    {
        var list = checks.ToList();
        return new
        {
            schema = SchemaVersion,
            checkCount = list.Count,
            checks = list.Select(c => new
            {
                id = V(c.Id),
                title = V(c.Title),
                kind = c.Kind,
                scan = c.Scan,
                start = c.Start,
                state = c.State,
                runId = c.RunId?.ToString(),
                completedAt = c.CompletedAt?.ToString("O"),
                summary = T(c.Summary),
            }).ToList(),
        };
    }

    // ---- Memory suggestions and storage cleanup (Resource hogs and Drive health pages) --------------------------------------

    public const int MaxSuggestions = 60;

    private static string UndoKey(Changes.UndoSupport u) => u switch
    {
        Changes.UndoSupport.Full => "full",
        Changes.UndoSupport.NothingToUndo => "nothing",
        Changes.UndoSupport.Reinstall => "reinstall",
        _ => "none",
    };

    private static object? SuggestionResultExport(Optimizations.SuggestionResult? r) => r is null ? null : new
    {
        suggestionId = V(r.SuggestionId),
        succeeded = r.Success,
        skipped = r.Skipped ? true : (bool?)null,
        message = T(r.Message),
        action = r.Action?.ToString(),
        undone = r.Undone ? true : (bool?)null,
        canForceClose = r.CanForceClose ? true : (bool?)null,
        at = new DateTimeOffset(r.When.ToUniversalTime(), TimeSpan.Zero).ToString("O"),
    };

    private static object SuggestionExport(Optimizations.MemorySuggestionService svc, Optimizations.MemorySuggestion s) => new
    {
        id = V(s.Id),
        title = V(s.Title),
        why = T(s.Why),
        note = T(s.Note),
        category = V(s.Category),
        kind = s.Kind.ToString().ToLowerInvariant(),
        risk = s.Risk.ToString().ToLowerInvariant(),
        savingBytes = s.SavingBytes,
        defaultOn = s.DefaultOn,
        actions = s.Actions.Select(a => new
        {
            type = a.Type.ToString(),
            label = V(a.Label),
            confirm = a.Confirm is not null ? true : (bool?)null,
            undo = UndoKey(s.Undo ?? Changes.Undoability.Of(a.Type)),
        }).ToList(),
        canUndo = svc.UndoFor(s.Id) is not null ? true : (bool?)null,
        result = SuggestionResultExport(svc.ResultFor(s.Id)),
    };

    /// <summary>
    /// The Ways to use less memory panel for browser agents (mem-suggest-data). Each action is the panel's
    /// <c>[data-action=mem-act][data-suggestion-id][data-action-type]</c> button; one with confirm true then needs mem-confirm-yes. last is
    /// the newest result, also when its card is gone after the change.
    /// </summary>
    public static string MemorySuggestions(Optimizations.MemorySuggestionService svc) => JsonSerializer.Serialize(new
    {
        schema = SchemaVersion,
        scanned = svc.Snapshot is not null,
        scanning = svc.Scanning,
        busy = V(svc.Busy),
        error = T(svc.ScanError),
        freedBytes = svc.TotalFreedBytes,
        last = SuggestionResultExport(svc.Recent.FirstOrDefault(r => Storage.StorageCleanupCatalog.Find(r.SuggestionId) is null)),
        suggestions = svc.Suggestions.Take(MaxSuggestions).Select(s => SuggestionExport(svc, s)).ToList(),
    }, Json);

    /// <summary>
    /// The Caches and leftovers panel for browser agents (storage-cleanup-data): nothing is listed until storage-scan has measured.
    /// Each delete is <c>[data-action=storage-delete][data-suggestion-id]</c>, then storage-confirm-yes. Deleting can't be undone.
    /// </summary>
    public static string StorageCleanup(Optimizations.MemorySuggestionService svc) => JsonSerializer.Serialize(new
    {
        schema = SchemaVersion,
        scanned = svc.StorageScanned,
        scanning = svc.ScanningStorage,
        busy = V(svc.Busy),
        error = T(svc.StorageError),
        freedBytes = svc.StorageFreedBytes,
        last = SuggestionResultExport(svc.Recent.FirstOrDefault(r => Storage.StorageCleanupCatalog.Find(r.SuggestionId) is not null)),
        suggestions = svc.StorageSuggestions.Take(MaxSuggestions).Select(s => new
        {
            id = V(s.Id),
            title = V(s.Title),
            why = T(s.Why),
            sizeBytes = svc.StorageItems.FirstOrDefault(i => i.Id == s.Id)?.SizeBytes,
            defaultOn = s.DefaultOn,
            undo = "none",
            result = SuggestionResultExport(svc.ResultFor(s.Id)),
        }).ToList(),
    }, Json);

    // ---- Undo changes (History and Benchmark pages) -----------------------------------------------------------------------

    /// <summary>
    /// The Undo changes panel for browser agents (undo-data): what can be put back (each with its undo-one-{id} button), what is
    /// permanent, and the last undo's result. resultSeq goes up with every finished undo.
    /// </summary>
    public static string Undo(bool loaded, IReadOnlyList<Changes.ChangeRecord> pending, IReadOnlyList<Changes.ChangeRecord> permanent, bool busy,
        int resultSeq, Changes.UndoAllResult? all, Changes.UndoItemResult? one) =>
        JsonSerializer.Serialize(BuildUndo(loaded, pending, permanent, busy, resultSeq, all, one), Json);

    public static object BuildUndo(bool loaded, IReadOnlyList<Changes.ChangeRecord> pending, IReadOnlyList<Changes.ChangeRecord> permanent, bool busy,
        int resultSeq, Changes.UndoAllResult? all, Changes.UndoItemResult? one) => new
    {
        schema = SchemaVersion,
        loaded,
        busy,
        pending = pending.Select(Change).ToList(),
        permanent = permanent.Select(Change).ToList(),
        resultSeq,
        lastResult = all is not null
            ? new
            {
                kind = "all",
                summary = T(all.Summary),
                succeeded = all.Succeeded,
                failed = all.Failed,
                skipped = all.Skipped,
                needsRestart = all.NeedsRestart,
                items = all.Items.Select(Item).ToList(),
            }
            : one is not null
                ? new
                {
                    kind = "one",
                    summary = T(one.Message),
                    succeeded = one.Success ? 1 : 0,
                    failed = !one.Success && !one.Skipped ? 1 : 0,
                    skipped = one.Skipped ? 1 : 0,
                    needsRestart = one.Success && one.Change.NeedsRestart,
                    items = new[] { Item(one) }.ToList(),
                }
                : null,
    };

    private static object Change(Changes.ChangeRecord c) => new
    {
        id = c.Id.ToString(),
        label = T(c.Label),
        kind = c.Kind.ToString(),
        at = c.TimeUtc.ToString("O"),
        actor = V(c.Actor),
        needsRestart = c.NeedsRestart,
    };

    private static object Item(Changes.UndoItemResult i) => new
    {
        id = i.Change.Id.ToString(),
        label = T(i.Change.Label),
        outcome = i.Success ? "undone" : i.Skipped ? "permanent" : "failed",
        message = T(i.Message),
    };

    // ---- Which checks are turned on -------------------------------------------------------------------------------------

    /// <summary>
    /// The Checks page's enablement for browser agents (checks-report-data): every diagnostic check, hidden hardware included,
    /// the profiles each check belongs to, and the profile catalog with which profiles are picked (Settings.Profiles).
    /// </summary>
    public static string CheckEnablement(IReadOnlyList<CheckChoice> checks, IReadOnlyCollection<string>? activeProfiles = null) =>
        JsonSerializer.Serialize(BuildCheckEnablement(checks, activeProfiles), Json);

    public static object BuildCheckEnablement(IEnumerable<CheckChoice> checks, IReadOnlyCollection<string>? activeProfiles = null)
    {
        var active = new HashSet<string>(activeProfiles ?? [], StringComparer.OrdinalIgnoreCase);
        return new
        {
            schema = SchemaVersion,
            checks = checks.Select(c => new
            {
                id = V(c.Id),
                title = V(c.Title),
                category = V(c.Category),
                available = c.Available,
                enabled = c.Enabled,
                reason = T(c.Reason),
                profiles = CheckProfiles.All
                    .Where(p => p.CheckIds.Contains(c.Id, StringComparer.OrdinalIgnoreCase))
                    .Select(p => p.Id).ToList(),
            }).ToList(),
            profiles = CheckProfiles.All.Select(p => new
            {
                id = p.Id,
                name = p.DisplayName,
                summary = p.Summary,
                checks = p.CheckIds,
                active = active.Contains(p.Id),
            }).ToList(),
        };
    }

    // ---- Security audit -------------------------------------------------------------------------------------------------

    public static string Audit(SecurityAuditReport report) => JsonSerializer.Serialize(BuildAudit(report), Json);

    /// <summary>Counts as the page shows them, and every shown finding that did not pass, worst first.</summary>
    public static object BuildAudit(SecurityAuditReport report)
    {
        static int Rank(AuditFinding f) => f.Outcome switch { AuditOutcome.Failed => 0, AuditOutcome.Warning => 1, AuditOutcome.NotChecked => 2, _ => 3 };
        var attention = report.Shown.Where(f => f.Outcome != AuditOutcome.Passed)
            .OrderBy(Rank).ThenBy(f => f.Id, StringComparer.OrdinalIgnoreCase).ToList();
        return new
        {
            schema = SchemaVersion,
            status = report.Status.ToString().ToLowerInvariant(),
            notice = T(report.Notice),
            homePc = report.HomePc,
            hiddenEnterpriseSettings = report.Hidden,
            passed = report.Passed,
            warnings = report.Warnings,
            failed = report.Failed,
            notChecked = report.NotChecked,
            highRisk = report.HighRisk,
            attentionCount = attention.Count,
            findings = attention.Take(MaxFindings).Select(f => new
            {
                id = V(f.Id),
                category = V(f.Category),
                name = V(f.Name),
                severity = V(f.Severity),
                outcome = f.Outcome.ToString().ToLowerInvariant(),
                current = V(f.CurrentValue),
                recommended = V(f.RecommendedValue),
            }).ToList(),
        };
    }

    // ---- History --------------------------------------------------------------------------------------------------------

    public static string History(IReadOnlyList<HistoryEntry> entries, IReadOnlyList<FixHistoryItem> fixes, string range, bool available,
        string testFilter = "", string outcomeFilter = "") =>
        JsonSerializer.Serialize(BuildHistory(entries, fixes, range, available, testFilter, outcomeFilter), Json);

    /// <summary>
    /// The results and fixes the page lists for its current filters, newest first, and the filters themselves: the range, the
    /// test (a check ID) and the result, the last two empty when the page lists all of them. An agent that changes a filter
    /// waits for the copy to name the new value.
    /// </summary>
    public static object BuildHistory(IReadOnlyList<HistoryEntry> entries, IReadOnlyList<FixHistoryItem> fixes, string range, bool available,
        string testFilter = "", string outcomeFilter = "") => new
    {
        schema = SchemaVersion,
        range,
        testFilter = V(testFilter) ?? "",
        outcomeFilter = V(outcomeFilter) ?? "",
        available,
        entryCount = entries.Count,
        fixCount = fixes.Count,
        entries = entries.OrderByDescending(e => e.TimeUtc).Take(MaxHistoryEntries).Select(e => new
        {
            completedAt = e.TimeUtc.ToString("O"),
            checkId = V(e.Module),
            test = V(e.Test),
            instance = V(e.Instance),
            outcome = V(e.Outcome),
            summary = T(e.Summary),
            durationSeconds = e.DurationSeconds,
            suite = V(e.Suite),
            measurements = HistoryPresentation.Measurements(e).Take(MaxDetailLines)
                .Select(m => new { name = V(m.Name), value = V(m.Value) }).ToList(),
            details = HistoryPresentation.Details(e).Take(MaxDetailLines).Select(T).OfType<string>().ToList(),
            // The numbers the check tracks over time (contract 3); left out when the result has none.
            keyMetrics = HistoryTrends.Metrics(e) is { Count: > 0 } km
                ? km.Select(k => new { id = V(k.Id), label = V(k.Label), value = k.Value, unit = V(k.Unit), text = KeyMetricText.Value(k.Value, k.Unit) }).ToList()
                : null,
        }).ToList(),
        fixes = fixes.OrderByDescending(f => f.TimeUtc).Take(MaxFixes).Select(f => new
        {
            at = f.TimeUtc.ToString("O"),
            category = V(f.Category),
            actor = V(f.Actor),
            success = f.Success,
            summary = T(f.Summary),
            impact = V(f.ImpactBadge),
        }).ToList(),
    };

    // ---- Benchmark ------------------------------------------------------------------------------------------------------

    public static string Benchmark(BenchmarkService bench) => JsonSerializer.Serialize(BuildBenchmark(
        bench.Settings, bench.Before, bench.After, bench.Comparison, bench.Running, bench.Settling is not null,
        bench.Progress, bench.BeforePendingRestart, bench.AfterPendingRestart, bench.Message,
        bench.DetectedToolchains, bench.DevDrivePrecheck, bench.LastAntivirusComparison, bench.LastDevDriveComparison,
        bench.Blocked, bench.StartChoices(), bench.TestChoices()), Json);

    /// <summary>The page's state: settings, which kinds this PC can enable, what is running or waiting for a restart, each pass, and the comparison.</summary>
    public static object BuildBenchmark(BenchmarkSettings settings, BenchmarkRun? before, BenchmarkRun? after, BenchmarkComparison comparison,
        BenchmarkPhase? running, bool settling, string? progress, bool beforePendingRestart, bool afterPendingRestart, string? message,
        IReadOnlyList<DetectedToolchain>? detectedToolchains = null, DevDrivePrecheckResult? devDrivePrecheck = null,
        DeveloperBuildResult? lastAvComparison = null, DevDriveComparisonResult? lastDevDriveComparison = null,
        BenchmarkBlock? blocked = null, IReadOnlyList<BenchmarkStartChoice>? starts = null,
        IReadOnlyList<BenchmarkTestChoice>? tests = null) => new
    {
        schema = SchemaVersion,
        phase = ResolveBenchmarkPhase(running, settling, beforePendingRestart, afterPendingRestart, before, after),
        progress = T(progress),
        message = T(message),
        settings = new
        {
            enabled = settings.Enabled.Select(k => k.ToString()).ToList(),
            restartBeforeAfter = settings.RestartBeforeAfter,
            // Runs per test (bench-runs); runChoices are the values the select offers.
            runs = settings.Runs,
            runChoices = BenchmarkSettings.RunChoices,
        },
        // Every kind. available false means the PC lacks the hardware or software: there is no control to turn it on.
        tests = tests?.Select(t => new
        {
            id = t.Id,
            available = t.Available,
            enabled = t.Enabled,
            control = t.Control,
            reason = T(t.Reason),
        }).ToList(),
        // How each pass can be started, and the last refusal. A refusal names the blocking setting and does not change restartBeforeAfter.
        starts = starts?.Select(s => new
        {
            pass = s.Pass,
            restart = s.Restart,
            control = s.Control,
            available = s.Available,
            setting = s.Setting,
            reason = T(s.Reason),
        }).ToList(),
        blocked = blocked is null ? null : new { setting = blocked.Setting, reason = T(blocked.Reason) },
        before = Pass(before),
        after = Pass(after),
        overallPercent = before is not null && after is not null ? comparison.OverallPercent : null,
        overall = before is not null && after is not null ? T(comparison.OverallText) : null,
        warnings = comparison.Warnings.Select(T).OfType<string>().ToList(),
        deltas = BuildBenchmarkDeltas(before, after, comparison),
        developer = BuildDeveloperBenchmarkSection(detectedToolchains, devDrivePrecheck, lastAvComparison, lastDevDriveComparison),
    };

    private static string ResolveBenchmarkPhase(
        BenchmarkPhase? running, bool settling, bool beforePendingRestart, bool afterPendingRestart, BenchmarkRun? before, BenchmarkRun? after)
    {
        if (running is { } p) return p == BenchmarkPhase.Before ? "running-before" : "running-after";
        if (settling) return "settling";
        if (beforePendingRestart) return "restart-pending-before";
        if (afterPendingRestart) return "restart-pending-after";
        if (before is null) return "no-baseline";
        return after is null ? "baseline-ready" : "compared";
    }

    private static object? BuildBenchmarkDeltas(BenchmarkRun? before, BenchmarkRun? after, BenchmarkComparison comparison) =>
        before is not null && after is not null
            ? comparison.Deltas.Select(d => new
            {
                kind = d.Info.Kind.ToString(),
                title = d.Info.Title,
                unit = d.Info.Unit,
                lowerIsBetter = d.Info.LowerIsBetter,
                before = d.Before,
                after = d.After,
                verdict = d.Verdict.ToString().ToLowerInvariant(),
                improvementPercent = d.ImprovementPercent,
                change = T(d.ChangeSummary),
                note = T(d.Note),
            }).ToList()
            : null;

    private static object? BuildDeveloperBenchmarkSection(
        IReadOnlyList<DetectedToolchain>? detectedToolchains,
        DevDrivePrecheckResult? devDrivePrecheck,
        DeveloperBuildResult? lastAvComparison,
        DevDriveComparisonResult? lastDevDriveComparison)
    {
        if (detectedToolchains is not { Count: > 0 } && lastAvComparison is null && lastDevDriveComparison is null)
            return null;

        return new
        {
            busyWarning = DeveloperScoring.BusyPcWarning,
            toolchains = (detectedToolchains ?? []).Select(t => new { language = t.Language.ToString(), name = V(t.DisplayName), version = V(t.Version) }).ToList(),
            csharpUnavailableReason = T(CSharpUnavailableReason(detectedToolchains)),
            antivirusComparison = BuildAvComparison(lastAvComparison),
            devDrivePrecheck = devDrivePrecheck is null ? null : new
            {
                eligible = devDrivePrecheck.Eligible,
                reason = T(devDrivePrecheck.Reason),
                requiresExplicitApproval = true,
            },
            devDriveComparison = BuildDevDriveComparison(lastDevDriveComparison),
        };
    }

    private static object? BuildAvComparison(DeveloperBuildResult? lastAvComparison) =>
        lastAvComparison is null ? null : new
        {
            language = lastAvComparison.Language.ToString(),
            pinId = V(lastAvComparison.PinId),
            coldMedianSeconds = lastAvComparison.ColdMedianSeconds,
            warmMedianSeconds = lastAvComparison.WarmMedianSeconds,
            warmExcludedMedianSeconds = lastAvComparison.WarmExcludedMedianSeconds,
            restoreSeconds = lastAvComparison.RestoreSeconds,
            antivirusCostSeconds = lastAvComparison.AntivirusCostSeconds,
            antivirusCostPercent = lastAvComparison.AntivirusCostPercent,
            band = lastAvComparison.Band.ToString(),
            note = T(lastAvComparison.Note),
            toolExitCode = lastAvComparison.ToolExitCode,
        };

    private static object? BuildDevDriveComparison(DevDriveComparisonResult? lastDevDriveComparison) =>
        lastDevDriveComparison is null ? null : new
        {
            succeeded = lastDevDriveComparison.Succeeded,
            order = V(lastDevDriveComparison.Order),
            ntfsColdMedianSeconds = lastDevDriveComparison.NtfsColdMedianSeconds,
            ntfsWarmMedianSeconds = lastDevDriveComparison.NtfsWarmMedianSeconds,
            devDriveColdMedianSeconds = lastDevDriveComparison.DevDriveColdMedianSeconds,
            devDriveWarmMedianSeconds = lastDevDriveComparison.DevDriveWarmMedianSeconds,
            coldPercentFaster = lastDevDriveComparison.ColdPercentFaster,
            warmPercentFaster = lastDevDriveComparison.WarmPercentFaster,
            defenderPerformanceModeActive = lastDevDriveComparison.DefenderPerformanceModeActive,
            note = T(lastDevDriveComparison.Note),
        };

    private static string? CSharpUnavailableReason(IReadOnlyList<DetectedToolchain>? toolchains)
    {
        var csharp = toolchains?.FirstOrDefault(t => t.Language == DeveloperLanguage.CSharp);
        return csharp is null ? null : DeveloperCSharpPin.UnsupportedSdkReason(csharp.Version, csharp.MajorVersion);
    }

    private static object? Pass(BenchmarkRun? run) => run is null ? null : new
    {
        at = run.TimeUtc.ToString("O"),
        completed = run.Completed,
        onBattery = run.Conditions.OnBattery,
        cpuTemperatureCelsius = run.Conditions.CpuTemperatureC,
        powerPlan = V(run.Conditions.PowerPlan),
        powerMode = V(run.Conditions.PowerMode),
        performanceLimitPercent = run.Conditions.PerformanceLimitPercent,
        performanceLimitPowerSource = V(run.Conditions.PerformanceLimitPowerSource),
        acMaxProcessorStatePercent = run.Conditions.AcMaxProcessorStatePercent,
        dischargingOnAc = run.Conditions.DischargingOnAc,
        measurements = run.Measurements.Select(m =>
        {
            var info = Benchmarks.Benchmarks.All.FirstOrDefault(i => i.Kind == m.Kind);
            return new
            {
                kind = m.Kind.ToString(),
                unit = info?.Unit,
                median = m.Median,
                samples = m.Samples.Count,
                spread = m.Spread,
                note = T(m.Note),
                detail = T(m.Detail),
                developerBuild = m.DeveloperBuild is null ? null : new
                {
                    language = m.DeveloperBuild.Language.ToString(),
                    pinId = V(m.DeveloperBuild.PinId),
                    coldMedianSeconds = m.DeveloperBuild.ColdMedianSeconds,
                    warmMedianSeconds = m.DeveloperBuild.WarmMedianSeconds,
                    restoreSeconds = m.DeveloperBuild.RestoreSeconds,
                    score = m.DeveloperBuild.Score,
                    band = m.DeveloperBuild.Band.ToString(),
                    note = T(m.DeveloperBuild.Note),
                    toolExitCode = m.DeveloperBuild.ToolExitCode,
                },
            };
        }).ToList(),
    };
}
