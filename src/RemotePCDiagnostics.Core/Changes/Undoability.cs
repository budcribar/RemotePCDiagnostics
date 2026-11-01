using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Memory;

namespace RemotePCDiagnostics.Core.Changes;

/// <summary>What "Undo all" can do for a fix.</summary>
public enum UndoSupport
{
    /// <summary>The previous setting is journaled and put back exactly.</summary>
    Full,
    /// <summary>Leaves no lasting change (flush DNS, re-trim, rescan devices), so there's nothing to put back.</summary>
    NothingToUndo,
    /// <summary>Deleted files can't come back; undo recreates placeholder files of the same total size (for testing the benchmarks).</summary>
    PlaceholdersOnly,
    /// <summary>Permanent: installed updates, removed apps, uninstalled programs. Journaled so "Undo all" reports it as skipped.</summary>
    None,
}

public static class Undoability
{
    public static UndoSupport Of(RemediationKind k) => k switch
    {
        RemediationKind.SetBalancedPowerPlan or RemediationKind.DisableFastStartup or RemediationKind.DisableSystemProxy
            or RemediationKind.SetPublicDns or RemediationKind.ResetDhcpDns => UndoSupport.Full,
        RemediationKind.CleanTempFiles => UndoSupport.PlaceholdersOnly,
        RemediationKind.CheckAndInstallDriverUpdates or RemediationKind.CheckAndInstallWindowsUpdates or RemediationKind.EnableDevice => UndoSupport.None,
        _ => UndoSupport.NothingToUndo,
    };

    /// <summary>Memory actions that change a setting journal its previous value; the rest leave nothing lasting.</summary>
    public static UndoSupport Of(MemoryActionType t) => t switch
    {
        MemoryActionType.DisableStartup or MemoryActionType.EnableBrowserMemorySaver or MemoryActionType.SetServiceManual
            or MemoryActionType.SetServiceDisabled or MemoryActionType.StopService
            or MemoryActionType.DisableTransparency or MemoryActionType.AutoManagePageFile or MemoryActionType.DisableFastStartup => UndoSupport.Full,
        _ => UndoSupport.NothingToUndo, // closing apps, ending build servers, restarting, opening Settings
    };

    /// <summary>Short chip text for the fix list; null when undo puts it back exactly (or there's nothing to put back).</summary>
    public static string? Chip(UndoSupport u) => u switch
    {
        UndoSupport.None => "can't be undone",
        UndoSupport.PlaceholdersOnly => "undo leaves placeholder files",
        _ => null,
    };

    /// <summary>Journal record for a permanent change, so "Undo all" lists it as skipped instead of silently ignoring it.</summary>
    public static ChangeRecord Permanent(string target, string label, string actor) =>
        ChangeRecord.New(ChangeKind.NotUndoable, target, null, label, actor);
}
