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
    public const int SchemaVersion = 1;
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
        IReadOnlyList<WorkflowCheckItem> checks, IReadOnlyCollection<string> openAreas, SignIn signIn) =>
        JsonSerializer.Serialize(Build(s, busy, waitingForRestart, status, message, checks, openAreas, signIn), Json);

    public static object Build(WorkflowState s, bool busy, bool waitingForRestart, string? status, string? message,
        IReadOnlyList<WorkflowCheckItem> checks, IReadOnlyCollection<string> openAreas, SignIn signIn) => new
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
        checks = s.Stage == WorkflowStage.Checking
            ? checks.Select(c => new
            {
                id = V(c.Id),
                title = V(c.Title),
                status = c.Status.ToString().ToLowerInvariant(),
                message = T(c.Message),
                step = c.HasProgress ? c.Step : (int?)null,
                total = c.HasProgress ? c.Total : (int?)null,
            }).ToList()
            : null,
        findings = s.Findings.Take(MaxLines).Select(T).OfType<string>().ToList(),
        recommendations = s.Recommendations.Take(MaxLines).Select(T).OfType<string>().ToList(),
        notOffered = s.NotOffered.Take(MaxLines).Select(T).OfType<string>().ToList(),
        approvedCount = s.Fixes.Count(f => s.IsApproved(f.Id)),
        fixes = s.Fixes.Take(MaxFixes).Select(f => new
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
        }).ToList(),
        outcomes = s.Outcomes.Take(MaxFixes).Select(o => new
        {
            fixId = o.FixId,
            title = V(o.Title),
            outcome = o.Skipped ? "skipped" : o.Success ? "succeeded" : "failed",
            message = T(o.Message),
        }).ToList(),
        repairs = s.RepairFindings.Take(MaxLines).Select(r => new
        {
            id = V(r.Id),
            title = V(r.Title),
            level = r.Level.ToString().ToLowerInvariant(),
            summary = T(r.Summary),
            rebootRequired = r.RebootRequired ? true : (bool?)null,
            afterRestart = r.AfterRestart ? true : (bool?)null,
        }).ToList(),
        signIn = s.Stage == WorkflowStage.Review
            ? new { automatic = signIn.Automatic, restartSignOn = signIn.RestartSignOn, canStart = signIn.CanStart }
            : null,
        reportSaved = s.ReportPath is not null ? true : (bool?)null,
    };
}
