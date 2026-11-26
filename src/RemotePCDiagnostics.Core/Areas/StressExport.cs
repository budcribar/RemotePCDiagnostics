using System.Text.Json;
using System.Text.Json.Serialization;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// Machine-readable state of the Stress tests page for browser agents (docs/agent-guides/browser-contract.md, stress-data):
/// the selected length, whether a run is going and how far it is, and each stress test's latest result with its run ID.
/// </summary>
public static class StressExport
{
    public const int SchemaVersion = 1;

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>One stress test as the page shows it.</summary>
    public sealed record Test(string CheckId, string Name, bool Selected, DiagnosticResult Result, string? RunLabel);

    public static string ToJson(StressSuiteMode mode, bool running, StressSuiteProgress? progress, StressSuiteResult? last,
        string? lastRunNote, IReadOnlyList<Test> tests) =>
        JsonSerializer.Serialize(Build(mode, running, progress, last, lastRunNote, tests), Json);

    public static object Build(StressSuiteMode mode, bool running, StressSuiteProgress? progress, StressSuiteResult? last,
        string? lastRunNote, IReadOnlyList<Test> tests) => new
    {
        schema = SchemaVersion,
        mode = mode == StressSuiteMode.Extended ? "extended" : "short",
        minutesPerTest = StressSuiteDurations.PerTest(mode).TotalMinutes,
        running,
        progress = BuildProgress(running, progress),
        lastSuite = BuildLastSuite(last),
        note = AreaReportExport.Text(lastRunNote, AreaReportExport.MaxTextLength),
        selectedCheckIds = tests.Where(t => t.Selected).Select(t => t.CheckId).ToList(),
        tests = tests.Select(BuildTestItem).ToList(),
    };

    private static object? BuildProgress(bool running, StressSuiteProgress? progress) =>
        running && progress is { Finished: false } p
            ? new
            {
                index = p.Index,
                total = p.Total,
                current = AreaReportExport.Text(p.CurrentDisplayName, AreaReportExport.MaxValueLength),
                headline = AreaReportExport.Text(p.Headline, AreaReportExport.MaxTextLength),
                steps = Steps(p.Steps),
            }
            : null;

    private static object? BuildLastSuite(StressSuiteResult? last) =>
        last is null ? null : new
        {
            mode = last.Mode == StressSuiteMode.Extended ? "extended" : "short",
            outcome = last.Outcome switch
            {
                StressSuiteOutcome.Completed => "completed",
                StressSuiteOutcome.StoppedOnProblem => "stopped-on-problem",
                _ => "cancelled",
            },
            message = AreaReportExport.Text(last.Message, AreaReportExport.MaxTextLength),
            steps = Steps(last.Steps),
        };

    private static object BuildTestItem(Test t)
    {
        var r = t.Result;
        var kind = CheckRows.KindOf(r);
        var finished = kind is not (RowKind.NotRun or RowKind.Running);
        var report = r.Report() as IStressReport;
        return new
        {
            checkId = t.CheckId,
            name = AreaReportExport.Text(t.Name, AreaReportExport.MaxValueLength),
            selected = t.Selected,
            state = kind.ToString().ToLowerInvariant(),
            runId = r.RunId,
            completedAt = finished ? r.Timestamp.ToString("O") : null,
            runLabel = finished ? AreaReportExport.Text(t.RunLabel, AreaReportExport.MaxValueLength) : null,
            message = AreaReportExport.Text(r.Message, AreaReportExport.MaxTextLength),
            headline = finished ? AreaReportExport.Text(report?.Headline, AreaReportExport.MaxTextLength) : null,
            overheated = finished && report is { IsOverheated: true } ? true : (bool?)null,
            stoppedByUser = finished && (r.Cancelled || report is { IsStoppedByUser: true }) ? true : (bool?)null,
            couldNotRun = finished && report is { IsCouldNotRun: true } ? true : (bool?)null,
            unavailable = finished && report is { IsUnavailable: true } ? true : (bool?)null,
        };
    }

    private static object Steps(IReadOnlyList<StressSuiteStep> steps) => steps.Select(s => new
    {
        checkId = s.ModuleName,
        name = AreaReportExport.Text(s.DisplayName, AreaReportExport.MaxValueLength),
        state = s.State.ToString().ToLowerInvariant(),
        message = AreaReportExport.Text(s.Message, AreaReportExport.MaxTextLength),
    }).ToList();
}
