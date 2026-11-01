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

/// <summary>A fix the tech can approve. Remediation fixes replay their <see cref="AreaAction"/>; memory fixes are matched again after the restart.</summary>
public sealed record WorkflowFix(
    string Id, string Title, string Why, string Area, SuggestionRisk Risk, FixSource Source, int Order,
    AreaAction? Remediation = null, string? SuggestionId = null, MemoryActionType? MemoryAction = null, string? MemoryTarget = null,
    bool NeedsAdmin = false, bool Slow = false, Changes.UndoSupport Undo = Changes.UndoSupport.Full);

public sealed record FixOutcome(string FixId, string Title, bool Success, string Message, bool Skipped = false);

/// <summary>Winlogon values before the workflow turned on automatic sign-in (restored at the end). Never contains a password.</summary>
public sealed record AutoLogonBackup(string? AutoAdminLogon, string? DefaultUserName, string? DefaultDomainName, string? AutoLogonCount);

/// <summary>Whether this PC can sign in automatically for the workflow's restarts.</summary>
public sealed record AutoLogonStatus(string UserName, string Domain, bool AlreadyAutomatic, bool BlockedByWindowsHello, string? Note = null)
{
    public bool CanUse => !AlreadyAutomatic && !BlockedByWindowsHello;
}

/// <summary>Everything the workflow keeps across restarts (%LOCALAPPDATA%\RemotePCDiagnostics\workflow.json). No passwords.</summary>
public sealed record WorkflowState
{
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
    public DateTimeOffset? FinishedUtc { get; init; }
    /// <summary>When the last restart was requested; used to tell whether the PC really restarted.</summary>
    public DateTimeOffset? RestartRequestedUtc { get; init; }
    public bool AutoLogonEnabled { get; init; }
    public AutoLogonBackup? AutoLogonBackup { get; init; }
    public string? ReportPath { get; init; }
    public string? Error { get; init; }
    public IReadOnlyList<string> Log { get; init; } = [];

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

public sealed class FileWorkflowStore(string path, Action<string>? log = null) : IWorkflowStore
{
    public static string DefaultPath() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RemotePCDiagnostics", "workflow.json");

    public WorkflowState? Load()
    {
        try { return File.Exists(path) ? WorkflowState.FromJson(File.ReadAllText(path)) : null; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { log?.Invoke($"Workflow state read failed: {ex.Message}"); return null; }
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
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { log?.Invoke($"Workflow state write failed: {ex.Message}"); }
    }
}

/// <summary>Windows pieces the workflow needs (Host implementation; fakes in tests).</summary>
public interface IWorkflowSystem
{
    /// <summary>Start this app elevated at the next sign-in (Task Scheduler, highest privileges), reconnecting to the same session.</summary>
    Task<bool> RegisterResumeAsync(CancellationToken ct);
    Task RemoveResumeAsync(CancellationToken ct);
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
    /// <summary>Saves the client report; returns the full path.</summary>
    string SaveReport(string html, DateTimeOffset when);
}
