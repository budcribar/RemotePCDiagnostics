using System.Text.Json;
using System.Text.Json.Serialization;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// Machine-readable state of the Service workflow page for browser agents (workflow-data): the stage, live progress, the fixes to
/// review with their stable IDs and whether each is ticked, their outcomes, and whether the run can start. Never holds sign-in
/// details: only whether the PC signs in by itself and whether an account and password have been typed.
/// </summary>
public static class WorkflowExport
{
    public const int SchemaVersion = 2;
    public const int MaxFixes = 200;
    public const int MaxLines = 50;

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>Sign-in readiness on the review screen; no names or passwords.</summary>
    /// <summary>Whether Windows signs back in by itself after the restarts (<paramref name="RestartSignOn"/> null = can't tell). No password is involved.</summary>
    public sealed record SignIn(bool Automatic, bool? RestartSignOn, bool CanStart);

    private static string? V(string? v) => AreaReportExport.Text(v, AreaReportExport.MaxValueLength);
    private static string? T(string? v) => AreaReportExport.Text(v, AreaReportExport.MaxTextLength);

    public static string ToJson(WorkflowState s, bool busy, bool waitingForRestart, string? status, string? message,
        IReadOnlyList<WorkflowCheckItem> checks, IReadOnlyCollection<string> openAreas, SignIn signIn, bool canChange = false, string? changeMessage = null) =>
        JsonSerializer.Serialize(Build(s, busy, waitingForRestart, status, message, checks, openAreas, signIn, canChange, changeMessage), Json);

    /// <summary>
    /// The client report's changes, one per line of the report box, with the actions its buttons offer: <c>undo</c> or
    /// <c>reinstall</c> (the wf-change-undo button) and <c>reapply</c> (wf-change-reapply, once per fix: it runs the whole fix again).
    /// <c>changeId</c> is the button's data-change-id.
    /// </summary>
    private static bool Finished(WorkflowState s) => s.Stage is WorkflowStage.Done or WorkflowStage.Cancelled or WorkflowStage.Failed;

    public static IReadOnlyList<object> Changes(WorkflowState s)
    {
        var reapplyOffered = new HashSet<string>(StringComparer.Ordinal);
        var list = new List<object>();
        foreach (var item in s.Outcomes.SelectMany(o => ReportItems.For(s, o)).Take(MaxFixes))
        {
            var actions = new List<string>();
            if (item.CanUndo) actions.Add(item.Tag == ReportTag.Reinstallable ? "reinstall" : "undo");
            else if (item.CanReapply && reapplyOffered.Add(item.FixId)) actions.Add("reapply");
            list.Add(new
            {
                changeId = item.JournalId?.ToString("N") ?? item.FixId,
                fixId = item.FixId,
                fixTitle = V(item.FixTitle),
                text = T(item.Text),
                tag = item.Tag.ToString(),
                label = ReportItems.Label(item.Tag, item.WasReinstall),
                undoneAt = item.UndoneUtc?.ToString("O"),
                actions,
            });
        }
        return list;
    }

    public static object Build(WorkflowState s, bool busy, bool waitingForRestart, string? status, string? message,
        IReadOnlyList<WorkflowCheckItem> checks, IReadOnlyCollection<string> openAreas, SignIn signIn, bool canChange = false, string? changeMessage = null) => new
    {
        schema = SchemaVersion,
        stage = s.Stage.ToString(),
        running = s.IsRunning,
        busy,
        waitingForRestart,
        status = T(status),
        message = T(message),
        error = T(s.Error),
        startedAt = s.StartedUtc?.ToString("O"),
        reviewedAt = s.ReviewedUtc?.ToString("O"),
        finishedAt = s.FinishedUtc?.ToString("O"),
        restartRequestedAt = s.RestartRequestedUtc?.ToString("O"),
        restarts = s.Restarts.Count,
        checks = s.Stage == WorkflowStage.Checking ? BuildCheckItems(checks) : null,
        findings = s.Findings.Take(MaxLines).Select(T).OfType<string>().ToList(),
        recommendations = s.Recommendations.Take(MaxLines).Select(T).OfType<string>().ToList(),
        notOffered = s.NotOffered.Take(MaxLines).Select(T).OfType<string>().ToList(),
        approvedCount = s.Fixes.Count(f => s.IsApproved(f.Id)),
        fixes = BuildFixItems(s, openAreas),
        outcomes = BuildOutcomeItems(s),
        repairs = BuildRepairItems(s),
        signIn = s.Stage == WorkflowStage.Review
            ? new { automatic = signIn.Automatic, restartSignOn = signIn.RestartSignOn, canStart = signIn.CanStart }
            : null,
        reportSaved = s.ReportPath is not null ? true : (bool?)null,
        changes = Finished(s) ? Changes(s) : null,
        canChange = Finished(s) ? canChange : (bool?)null,
        changeMessage = T(changeMessage),
    };

    private static object BuildCheckItems(IReadOnlyList<WorkflowCheckItem> checks) =>
        checks.Select(c => new
        {
            id = V(c.Id),
            title = V(c.Title),
            status = c.Status.ToString().ToLowerInvariant(),
            message = T(c.Message),
            step = c.HasProgress ? c.Step : (int?)null,
            total = c.HasProgress ? c.Total : (int?)null,
        }).ToList();

    private static object BuildFixItems(WorkflowState s, IReadOnlyCollection<string> openAreas) =>
        s.Fixes.Take(MaxFixes).Select(f => new
        {
            id = f.Id,
            title = V(f.Title),
            why = T(f.Why),
            area = V(f.Area),
            areaKey = f.GroupKey,
            areaOpen = openAreas.Contains(f.GroupKey),
            risk = f.Risk.ToString().ToLowerInvariant(),
            slow = f.Slow ? true : (bool?)null,
            defaultOn = f.DefaultOn,
            needsAdmin = f.NeedsAdmin ? true : (bool?)null,
            undo = f.Undo.ToString().ToLowerInvariant(),
            approved = s.IsApproved(f.Id),
        }).ToList();

    private static object BuildOutcomeItems(WorkflowState s) =>
        s.Outcomes.Take(MaxFixes).Select(o => new
        {
            fixId = o.FixId,
            title = V(o.Title),
            outcome = o.Skipped ? "skipped" : o.Success ? "succeeded" : "failed",
            message = T(o.Message),
        }).ToList();

    private static object BuildRepairItems(WorkflowState s) =>
        s.RepairFindings.Take(MaxLines).Select(r => new
        {
            id = V(r.Id),
            title = V(r.Title),
            level = r.Level.ToString().ToLowerInvariant(),
            summary = T(r.Summary),
            rebootRequired = r.RebootRequired ? true : (bool?)null,
            afterRestart = r.AfterRestart ? true : (bool?)null,
        }).ToList();
}
