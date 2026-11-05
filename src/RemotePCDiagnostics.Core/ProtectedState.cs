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
