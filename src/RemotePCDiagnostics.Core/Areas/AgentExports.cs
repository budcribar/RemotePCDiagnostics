using System.Text.Json;
using System.Text.Json.Serialization;
using RemotePCDiagnostics.Core.Benchmarks;
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
    public sealed record ExportedFixState(int Schema, ExportedFixRun? Running, ExportedFixResult? Last);
    public sealed record ExportedFixRun(string Kind, string Target, string? Title, string Origin, DateTimeOffset StartedAt, string? Progress);
    public sealed record ExportedFixResult(int Seq, string Kind, string Target, string Origin, string Outcome, string? Message, bool RestartNeeded,
        bool ReadOnly, DateTimeOffset FinishedAt);

    public static string FixState(FixRun? running, FixRunResult? last) => JsonSerializer.Serialize(BuildFixState(running, last), Json);

    public static ExportedFixState BuildFixState(FixRun? running, FixRunResult? last) => new(SchemaVersion,
        running is null ? null : new(running.Action.Kind.ToString(), V(running.Action.Target) ?? "", V(running.Title), running.Origin, running.StartedUtc, V(running.Progress)),
        last is null ? null : new(last.Seq, last.Action.Kind.ToString(), V(last.Action.Target) ?? "", last.Origin, last.Success ? "succeeded" : "failed",
            T(last.Message), last.RestartNeeded, RemediationService.IsReadOnly(last.Action.Kind), last.FinishedUtc));

    // ---- Activity ---------------------------------------------------------------------------------------------------------

    /// <summary>A check or scan running now. <c>Progress</c> is its latest sub-step, when it reports one.</summary>
    public sealed record RunningCheck(string Id, string Title, Guid? RunId, CheckProgress? Progress);

    /// <summary>A group run on the Checks &amp; Tests screen: Run all, the ticked checks, or the ticked stress and separate tests.</summary>
    public sealed record SequenceRun(CheckGroup Group, bool RunAll, GroupRunProgress? Progress, IReadOnlyList<string> Remaining);

    /// <summary>The service workflow's stage, whether it is working now, and its status line.</summary>
    public sealed record WorkflowActivity(Workflow.WorkflowStage Stage, bool Busy, string? Status);

    /// <summary>Everything running in the app at one moment, wherever it was started, for <see cref="Activity"/>.</summary>
    /// <summary>Who has control, who should keep it, and why that last changed. Readable on every page, including while view-only.</summary>
    public sealed record ControlMark(string Actual, string KeptWith, string Reason, DateTimeOffset? MovedAt);

    /// <summary>A check that already finished. Not a running check: view-only mirrors can read it without opening the check.</summary>
    public sealed record FinishedCheck(string Id, string Status, string? Summary, Guid? RunId, DateTimeOffset At);

    public sealed record ActivitySnapshot(
        IReadOnlyList<RunningCheck> Checks,
        SequenceRun? Sequence = null,
        StressSuiteProgress? StressSuite = null,
        FixRun? Fix = null,
        WorkflowActivity? Workflow = null,
        BenchmarkPhase? BenchmarkRunning = null,
        bool BenchmarkSettling = false,
        string? BenchmarkProgress = null,
        ControlMark? Control = null,
        IReadOnlyList<FinishedCheck>? Finished = null);

    /// <summary>Finished checks only, newest first, capped. A running or not-yet-run check is left out.</summary>
    public static IReadOnlyList<FinishedCheck> FinishedFrom(IEnumerable<DiagnosticResult> results) =>
        results
            .Where(r => r.Status is DiagnosticStatus.Ok or DiagnosticStatus.Warning or DiagnosticStatus.Error)
            .OrderByDescending(r => r.Timestamp)
            .Take(40)
            .Select(r => new FinishedCheck(
                r.ModuleName,
                r.Cancelled ? "cancelled" : r.Status.ToString().ToLowerInvariant(),
                T(r.Message),
                r.RunId,
                r.Timestamp))
            .ToList();

    /// <summary>
    /// What is running now (activity-data, on every page): checks and scans, a group run with the steps still to come, the stress
    /// suite, a fix, the service workflow and a benchmark pass. <c>busy</c> is true when any of them is. An agent that takes over a
    /// session reads this first, so it can ask the person before stopping anything. <c>control</c> says who holds the session and
    /// why it last moved. <c>finished</c> is checks that already produced a result, so a view-only mirror can read them without
    /// clicking.
    /// </summary>
    public static string Activity(ActivitySnapshot snapshot) => JsonSerializer.Serialize(BuildActivity(snapshot), Json);

    private static readonly HashSet<Workflow.WorkflowStage> IdleStages =
        [Workflow.WorkflowStage.Idle, Workflow.WorkflowStage.Done, Workflow.WorkflowStage.Cancelled, Workflow.WorkflowStage.Failed];

    public static object BuildActivity(ActivitySnapshot s)
    {
        var workflow = s.Workflow is { } w && !IdleStages.Contains(w.Stage) ? w : null;
        var stress = s.StressSuite is { Finished: false } p ? p : null;
        var benchmark = s.BenchmarkRunning is not null || s.BenchmarkSettling;
        var busy = s.Checks.Count > 0 || s.Sequence is not null || stress is not null || s.Fix is not null || benchmark
            || workflow is { Busy: true };
        return new
        {
            schema = SchemaVersion,
            busy,
            checks = s.Checks.Select(c => new
            {
                id = V(c.Id),
                title = V(c.Title),
                runId = c.RunId?.ToString(),
                progress = c.Progress is { } cp ? new { step = cp.Step, total = cp.Total, message = T(cp.Message) } : null,
            }).ToList(),
            sequence = s.Sequence is { } q ? new
            {
                kind = q.Group == CheckGroup.Stress ? "stress-tests" : q.RunAll ? "run-all" : "checks",
                index = q.Progress?.Index,
                total = q.Progress?.Total,
                current = V(q.Progress?.Current),
                remaining = q.Remaining.Select(V).OfType<string>().ToList(),
            } : null,
            stressSuite = stress is null ? null : new
            {
                mode = stress.Mode.ToString().ToLowerInvariant(),
                index = stress.Index,
                total = stress.Total,
                current = V(stress.CurrentDisplayName),
                remaining = stress.Steps.Where(step => step.State == StressSuiteStepState.Pending).Select(step => V(step.ModuleName)).OfType<string>().ToList(),
            },
            fix = s.Fix is { } f ? new
            {
                kind = f.Action.Kind.ToString(),
                target = V(f.Action.Target),
                title = V(f.Title),
                origin = f.Origin,
                startedAt = f.StartedUtc,
                progress = V(f.Progress),
            } : null,
            workflow = workflow is null ? null : new { stage = workflow.Stage.ToString(), busy = workflow.Busy, status = T(workflow.Status) },
            benchmark = benchmark ? new
            {
                phase = s.BenchmarkRunning is { } b ? (b == BenchmarkPhase.Before ? "running-before" : "running-after") : "settling",
                progress = T(s.BenchmarkProgress),
            } : null,
            control = s.Control is { } control ? new
            {
                actual = control.Actual,
                keptWith = control.KeptWith,
                reason = control.Reason,
                movedAt = control.MovedAt?.ToString("O"),
            } : null,
            finished = s.Finished is { Count: > 0 } finished
                ? finished.Select(f => new
                {
                    id = V(f.Id),
                    status = f.Status,
                    summary = f.Summary,
                    runId = f.RunId?.ToString(),
                    at = f.At.ToString("O"),
                }).ToList()
                : null,
        };
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
        bench.DetectedToolchains, bench.DevDrivePrecheck, bench.LastAntivirusComparison, bench.LastDevDriveComparison), Json);

    /// <summary>The page's state: settings, what is running or waiting for a restart, each pass, and the comparison.</summary>
    public static object BuildBenchmark(BenchmarkSettings settings, BenchmarkRun? before, BenchmarkRun? after, BenchmarkComparison comparison,
        BenchmarkPhase? running, bool settling, string? progress, bool beforePendingRestart, bool afterPendingRestart, string? message,
        IReadOnlyList<DetectedToolchain>? detectedToolchains = null, DevDrivePrecheckResult? devDrivePrecheck = null,
        DeveloperBuildResult? lastAvComparison = null, DevDriveComparisonResult? lastDevDriveComparison = null) => new
    {
        schema = SchemaVersion,
        phase = running is { } p ? (p == BenchmarkPhase.Before ? "running-before" : "running-after")
            : settling ? "settling"
            : beforePendingRestart ? "restart-pending-before"
            : afterPendingRestart ? "restart-pending-after"
            : before is null ? "no-baseline"
            : after is null ? "baseline-ready"
            : "compared",
        progress = T(progress),
        message = T(message),
        settings = new
        {
            enabled = settings.Enabled.Select(k => k.ToString()).ToList(),
            restartBeforeAfter = settings.RestartBeforeAfter,
        },
        before = Pass(before),
        after = Pass(after),
        overallPercent = before is not null && after is not null ? comparison.OverallPercent : null,
        overall = before is not null && after is not null ? T(comparison.OverallText) : null,
        warnings = comparison.Warnings.Select(T).OfType<string>().ToList(),
        deltas = before is not null && after is not null
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
            : null,
        developer = detectedToolchains is { Count: > 0 } || lastAvComparison is not null || lastDevDriveComparison is not null
            ? new
            {
                busyWarning = DeveloperScoring.BusyPcWarning,
                toolchains = (detectedToolchains ?? []).Select(t => new { language = t.Language.ToString(), name = V(t.DisplayName), version = V(t.Version) }).ToList(),
                antivirusComparison = lastAvComparison is null ? null : new
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
                },
                devDrivePrecheck = devDrivePrecheck is null ? null : new
                {
                    eligible = devDrivePrecheck.Eligible,
                    reason = T(devDrivePrecheck.Reason),
                    requiresExplicitApproval = true,
                },
                devDriveComparison = lastDevDriveComparison is null ? null : new
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
                },
            }
            : null,
    };

    private static object? Pass(BenchmarkRun? run) => run is null ? null : new
    {
        at = run.TimeUtc.ToString("O"),
        completed = run.Completed,
        onBattery = run.Conditions.OnBattery,
        cpuTemperatureCelsius = run.Conditions.CpuTemperatureC,
        powerPlan = V(run.Conditions.PowerPlan),
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
                },
            };
        }).ToList(),
    };
}
