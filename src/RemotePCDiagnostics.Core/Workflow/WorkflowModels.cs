using System.Text.Json;
using System.Text.Json.Serialization;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Memory;

namespace RemotePCDiagnostics.Core.Workflow;

/// <summary>
/// One service call, end to end: checks → tech review (the only input) → restart → before benchmark → apply approved fixes
/// → restart → after benchmark → client report.
/// </summary>
public enum WorkflowStage { Idle, Checking, Review, RestartBefore, BeforeBenchmark, Applying, RestartAfter, AfterBenchmark, Reporting, Done, Cancelled, Failed }

public enum FixSource { Remediation, Memory }

/// <summary>Live status of one check or scan while <see cref="WorkflowStage.Checking"/> is running.</summary>
public sealed record WorkflowCheckItem(
    string Id, string Title, DiagnosticStatus Status, string Message, int Step = 0, int Total = 0)
{
    public bool HasProgress => Total > 1;
    public double Fraction => Total > 0
        ? Math.Clamp((double)Step / Total, 0.0, 1.0)
        : Status is DiagnosticStatus.Ok or DiagnosticStatus.Warning or DiagnosticStatus.Error ? 1.0 : 0.0;
}

/// <summary>A fix the tech can approve. Remediation fixes replay their <see cref="AreaAction"/>; memory fixes are matched again after the restart.</summary>
/// <param name="DefaultOn">Ticked when the review opens. False = opt-in (e.g. Windows Search): listed unticked; the tech ticks it by hand.</param>
public sealed record WorkflowFix(
    string Id, string Title, string Why, string Area, SuggestionRisk Risk, FixSource Source, int Order,
    AreaAction? Remediation = null, string? SuggestionId = null, MemoryActionType? MemoryAction = null, string? MemoryTarget = null,
    bool NeedsAdmin = false, bool Slow = false, Changes.UndoSupport Undo = Changes.UndoSupport.Full, bool DefaultOn = true,
    string? UndoChip = null, string? AreaKey = null)
{
    /// <summary>Stable key for the area (grouping, remembered open areas). Always the untranslated name from the code, even if
    /// <see cref="Area"/> is ever shown translated.</summary>
    public string GroupKey => AreaKey ?? Area;
}

/// <param name="Changes">What the fix recorded in the undo journal while it ran (one line per setting, with its old value where known).</param>
public sealed record FixOutcome(string FixId, string Title, bool Success, string Message, bool Skipped = false, IReadOnlyList<FixChange>? Changes = null);

/// <summary>A Windows repair result (DISM RestoreHealth / SFC /scannow, or the re-scan after the restart) for the report,
/// in the check-finding shape: id, title, level, summary, evidence line and a detail table.</summary>
public sealed record RepairFinding(string Id, string Title, DiagnosticStatus Level, string Summary, string Evidence,
    IReadOnlyList<RepairDetail> Details, bool RebootRequired = false, bool AfterRestart = false);

public sealed record RepairDetail(string Label, string Value);

/// <summary>One undo-journal entry written while a fix ran, so the report can say exactly what changed and whether undo puts it back.</summary>
public sealed record FixChange(Guid JournalId, string Text, Changes.UndoSupport Undo);

/// <summary>A restart the workflow asked Windows for. <paramref name="BootedUtc"/> is filled in once the app is running again on the new boot.</summary>
public sealed record WorkflowRestart(string Why, DateTimeOffset RequestedUtc, bool Accepted, DateTimeOffset? BootedUtc = null);

/// <summary>Winlogon values before the workflow turned on automatic sign-in (restored at the end). Never contains a password.</summary>
public sealed record AutoLogonBackup(string? AutoAdminLogon, string? DefaultUserName, string? DefaultDomainName, string? AutoLogonCount, int? PasswordLessBuildVersion = null);

/// <summary>Whether this PC can sign in automatically for the workflow's restarts.</summary>
public sealed record AutoLogonStatus(string UserName, string Domain, bool AlreadyAutomatic, bool BlockedByWindowsHello, string? Note = null,
    string? MicrosoftAccountEmail = null)
{
    public bool CanUse => !AlreadyAutomatic;

    /// <summary>What the sign-in box starts with: the Microsoft account email when the signed-in account is one, else the local user name.</summary>
    public string PrefillUser => MicrosoftAccountEmail is { } e && e.Contains('@') ? e.Trim() : UserName;
}

/// <summary>Everything the workflow keeps across restarts (%ProgramData%\RemotePCDiagnostics\state\workflow.json, which only administrators can change). No passwords.</summary>
public sealed record WorkflowState
{
    /// <summary>Recommendation rules used to produce this review; zero denotes a legacy saved review.</summary>
    public int ReviewRulesVersion { get; init; }
    public WorkflowStage Stage { get; init; } = WorkflowStage.Idle;
    public IReadOnlyList<WorkflowFix> Fixes { get; init; } = [];
    public IReadOnlyList<string> Approved { get; init; } = [];
    public IReadOnlyList<FixOutcome> Outcomes { get; init; } = [];
    public IReadOnlyList<string> Findings { get; init; } = [];
    public IReadOnlyList<string> Recommendations { get; init; } = [];
    public string Machine { get; init; } = "";
    public string HardwareSummary { get; init; } = "";
    public string? Actor { get; init; }
    public DateTimeOffset? StartedUtc { get; init; }
    /// <summary>When the saved review snapshot was assembled, before technician approval.</summary>
    public DateTimeOffset? ReviewedUtc { get; init; }
    public DateTimeOffset? FinishedUtc { get; init; }
    /// <summary>When the last restart was requested; used to tell whether the PC really restarted.</summary>
    public DateTimeOffset? RestartRequestedUtc { get; init; }
    public bool AutoLogonEnabled { get; init; }
    public AutoLogonBackup? AutoLogonBackup { get; init; }
    /// <summary>The workflow turned automatic sign-in on (for <see cref="AutoLogonUser"/>), whether or not it's off again.</summary>
    public bool AutoLogonUsed { get; init; }
    public string? AutoLogonUser { get; init; }
    /// <summary>The PC already signed in by itself before the workflow (nothing was changed).</summary>
    public bool AutoLogonAlreadyOn { get; init; }
    public DateTimeOffset? AutoLogonRestoredUtc { get; init; }
    /// <summary>Set when turning automatic sign-in off again failed: the PC may still sign in without a password.</summary>
    public string? AutoLogonRestoreError { get; init; }
    /// <summary>The "continue after sign-in" scheduled task was created; <see cref="ResumeTaskRemoved"/> = whether it's gone again (null = not tried yet).</summary>
    public bool ResumeTaskCreated { get; init; }
    public bool? ResumeTaskRemoved { get; init; }
    public IReadOnlyList<WorkflowRestart> Restarts { get; init; } = [];
    /// <summary>A pending restart was called off when the workflow was cancelled.</summary>
    public bool RestartAborted { get; init; }
    /// <summary>Fixes the checks found that the workflow doesn't offer, with the reason.</summary>
    public IReadOnlyList<string> NotOffered { get; init; } = [];
    /// <summary>Whether this run had an undo journal to read (so "no journal entries" really means nothing lasting changed).</summary>
    public bool ChangesTracked { get; init; }
    /// <summary>Undo-journal entries from before this run that "Undo all" would also put back.</summary>
    public int EarlierChanges { get; init; }
    public string? ReportPath { get; init; }
    /// <summary>The report exactly as saved, so the page shows the same thing as the file.</summary>
    public string? ReportHtml { get; init; }
    public string? Error { get; init; }
    public IReadOnlyList<string> Log { get; init; } = [];
    /// <summary>DISM/SFC repair results and the integrity re-scans after the restart.</summary>
    public IReadOnlyList<RepairFinding> RepairFindings { get; init; } = [];
    /// <summary>A repair asked for a restart (exit code 3010 or "restart" in its output); the workflow's restart after the fixes covers it.</summary>
    public bool RepairRebootPending { get; init; }

    public bool IsApproved(string id) => Approved.Contains(id);
    public bool IsRunning => Stage is WorkflowStage.RestartBefore or WorkflowStage.BeforeBenchmark or WorkflowStage.Applying
        or WorkflowStage.RestartAfter or WorkflowStage.AfterBenchmark or WorkflowStage.Reporting;

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
    public string ToJson() => JsonSerializer.Serialize(this, Json);
    public static WorkflowState? FromJson(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try { return JsonSerializer.Deserialize<WorkflowState>(json, Json); } catch (JsonException) { return null; }
    }
}

public interface IWorkflowStore
{
    WorkflowState? Load();
    void Save(WorkflowState state);
}

public sealed class FileWorkflowStore(string path, ILogger? log = null) : IWorkflowStore
{
    public static string DefaultPath() =>
        ProtectedState.PathFor(ProtectedState.WorkflowFile);

    public WorkflowState? Load()
    {
        try { return File.Exists(path) ? WorkflowState.FromJson(File.ReadAllText(path)) : null; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { log.Warn($"Workflow state read failed: {ex.Message}"); return null; }
    }

    public void Save(WorkflowState state)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            var tmp = path + ".tmp";
            File.WriteAllText(tmp, state.ToJson());
            File.Move(tmp, path, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { log.Warn($"Workflow state write failed: {ex.Message}"); }
    }
}

/// <summary>Windows pieces the workflow needs (Host implementation; fakes in tests).</summary>
public interface IWorkflowSystem
{
    /// <summary>Start this app elevated at the next sign-in (Task Scheduler, highest privileges), reconnecting to the same session.</summary>
    Task<bool> RegisterResumeAsync(CancellationToken ct);
    /// <summary>Removes the task again; false when it's still there afterwards.</summary>
    Task<bool> RemoveResumeAsync(CancellationToken ct);
    Task<bool> RestartAsync(TimeSpan delay, string message, CancellationToken ct);
    Task AbortRestartAsync(CancellationToken ct);
    /// <summary>Time since Windows started.</summary>
    TimeSpan Uptime { get; }
    AutoLogonStatus GetAutoLogonStatus();
    bool ValidateCredentials(string user, string domain, string password);
    /// <summary>Turns on automatic sign-in for <paramref name="logons"/> sign-ins (password kept as an LSA secret). Returns the previous settings.</summary>
    AutoLogonBackup EnableAutoLogon(string user, string domain, string password, int logons);
    /// <summary>Turns automatic sign-in off again, removes the stored password and restores the previous settings.</summary>
    void DisableAutoLogon(AutoLogonBackup? backup);
    /// <summary>Where the client report for <paramref name="when"/> is saved (full path).</summary>
    string ReportFile(DateTimeOffset when);
    /// <summary>Saves the client report to <paramref name="path"/> (from <see cref="ReportFile"/>).</summary>
    void SaveReport(string path, string html);
}
