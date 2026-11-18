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

    public static string History(IReadOnlyList<HistoryEntry> entries, IReadOnlyList<FixHistoryItem> fixes, string range, bool available) =>
        JsonSerializer.Serialize(BuildHistory(entries, fixes, range, available), Json);

    /// <summary>The results and fixes the page lists for its current filters, newest first.</summary>
    public static object BuildHistory(IReadOnlyList<HistoryEntry> entries, IReadOnlyList<FixHistoryItem> fixes, string range, bool available) => new
    {
        schema = SchemaVersion,
        range,
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
        bench.Progress, bench.BeforePendingRestart, bench.AfterPendingRestart, bench.Message), Json);

    /// <summary>The page's state: settings, what is running or waiting for a restart, each pass, and the comparison.</summary>
    public static object BuildBenchmark(BenchmarkSettings settings, BenchmarkRun? before, BenchmarkRun? after, BenchmarkComparison comparison,
        BenchmarkPhase? running, bool settling, string? progress, bool beforePendingRestart, bool afterPendingRestart, string? message) => new
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
            };
        }).ToList(),
    };
}
