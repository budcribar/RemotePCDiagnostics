namespace RemotePCDiagnostics.Core;

/// <summary>
/// Where the files the elevated app acts on live: the undo journal, the service workflow, the reboot resume state and benchmarks.
/// They are in %ProgramData%\RemotePCDiagnostics\state, which only Administrators and SYSTEM can change (Host secures the folder at
/// startup). They used to be in %LOCALAPPDATA%\RemotePCDiagnostics, which any program the user runs can rewrite without a UAC prompt,
/// so a forged undo entry or workflow approval would have been carried out with administrator rights.
/// </summary>
public static class ProtectedState
{
    public const string ChangesFile = "changes.json", WorkflowFile = "workflow.json", PendingRebootFile = "pending-reboot.json", BenchmarksFile = "benchmarks.json";

    /// <summary>Every file that moved from %LOCALAPPDATA%\RemotePCDiagnostics to the state folder.</summary>
    public static readonly IReadOnlyList<string> FileNames = [ChangesFile, WorkflowFile, PendingRebootFile, BenchmarksFile];

    /// <summary>%ProgramData%\RemotePCDiagnostics: everyone can read it, only Administrators and SYSTEM can change it.</summary>
    public static string AppDataFolder() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "RemotePCDiagnostics");

    /// <summary>%ProgramData%\RemotePCDiagnostics\state: only Administrators and SYSTEM can open it.</summary>
    public static string Folder() => Path.Combine(AppDataFolder(), "state");

    public static string PathFor(string fileName) => Path.Combine(Folder(), fileName);

    /// <summary>%LOCALAPPDATA%\RemotePCDiagnostics, where these files were before.</summary>
    public static string LegacyFolder() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RemotePCDiagnostics");
}

/// <summary>
/// What the Agent accepts from the app for the state folder (the app isn't elevated, so it can't open the folder itself): the undo
/// journal's records, and the workflow and benchmark state by fixed file name. Everything is checked before it's saved.
/// </summary>
public static class ProtectedStateFiles
{
    /// <summary>The state files the app reads and saves through the Agent. The undo journal has its own requests.</summary>
    public static readonly IReadOnlyList<string> AgentManaged = [ProtectedState.WorkflowFile, ProtectedState.BenchmarksFile];

    /// <summary>A browser's whole Local State file is the largest "before" value a change keeps.</summary>
    public const int MaxPreviousChars = 4 * 1024 * 1024;
    private const int MaxTextChars = 16 * 1024;

    public static bool IsAgentManaged(string? name) =>
        name is not null && AgentManaged.Contains(name, StringComparer.Ordinal);

    /// <summary>Why the Agent won't save this state file's JSON, or null when it's fine.</summary>
    public static string? InvalidState(string name, string json) => name switch
    {
        ProtectedState.WorkflowFile => Workflow.WorkflowState.FromJson(json) is null ? "That isn't a saved workflow." : null,
        ProtectedState.BenchmarksFile => Benchmarks.BenchmarkState.FromJson(json) is null ? "That isn't saved benchmark state." : null,
        _ => $"'{name}' isn't a state file the Agent keeps.",
    };

    /// <summary>Why the Agent won't record this change in the undo journal, or null when it's fine.</summary>
    public static string? InvalidChange(Changes.ChangeRecord? c)
    {
        if (c is null) return "Which change to record wasn't given.";
        if (c.Id == Guid.Empty) return "The change has no id.";
        if (!Enum.IsDefined(c.Kind)) return "The change is of a kind this Agent doesn't know.";
        if (c.Target is null || c.Target.Length > MaxTextChars) return "The change's target is missing or too long.";
        if (c.Label is null || c.Label.Length > MaxTextChars || c.Actor is null || c.Actor.Length > MaxTextChars) return "The change's label or actor is missing or too long.";
        if (c.Previous?.Length > MaxPreviousChars || c.PreviousExtra?.Length > MaxTextChars || c.CreatedKey?.Length > MaxTextChars) return "The change's recorded values are too long.";
        return null;
    }
}
