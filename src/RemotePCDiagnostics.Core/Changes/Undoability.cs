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
    /// <summary>Legacy serialized value retained for compatibility; treated as permanent.</summary>
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
        RemediationKind.CleanTempFiles => UndoSupport.None,
        RemediationKind.CheckAndInstallDriverUpdates or RemediationKind.CheckAndInstallWindowsUpdates or RemediationKind.EnableDevice => UndoSupport.None,
        _ => UndoSupport.NothingToUndo,
    };

    /// <summary>Memory actions that change a setting journal its previous value; the rest leave nothing lasting.</summary>
    public static UndoSupport Of(MemoryActionType t) => t switch
    {
        MemoryActionType.DisableStartup or MemoryActionType.EnableBrowserMemorySaver or MemoryActionType.SetServiceManual
            or MemoryActionType.SetServiceDisabled or MemoryActionType.StopService or MemoryActionType.AddDefenderExclusions
            or MemoryActionType.DisableTransparency or MemoryActionType.AutoManagePageFile or MemoryActionType.DisableFastStartup
            or MemoryActionType.DisableWidgets or MemoryActionType.DisableSearchHighlights or MemoryActionType.ReduceHibernateFile
            or MemoryActionType.SkipOfficeStartScreen => UndoSupport.Full,
        MemoryActionType.CleanStorage => UndoSupport.None, // deleted caches don't come back
        _ => UndoSupport.NothingToUndo, // closing apps, ending build servers, restarting, opening Settings
    };

    /// <summary>Short chip text for the fix list; null when undo puts it back exactly (or there's nothing to put back).</summary>
    public static string? Chip(UndoSupport u) => u switch
    {
        UndoSupport.None => "can't be undone",
        UndoSupport.PlaceholdersOnly => "can't be undone",
        _ => null,
    };

    /// <summary>What undo does for one journaled change (for the client report).</summary>
    public static UndoSupport Of(ChangeRecord c) => c.Kind switch
    {
        ChangeKind.NotUndoable => UndoSupport.None,
        ChangeKind.TempFiles => UndoSupport.None, // deleted files can't come back
        _ => UndoSupport.Full,
    };

    /// <summary>The journal label plus, where the journal keeps it in readable form, what the setting was before ("DNS … (was automatic)").</summary>
    public static string Describe(ChangeRecord c)
    {
        var was = c.Kind switch
        {
            ChangeKind.PowerPlan => PlanName(c.Previous),
            ChangeKind.AdapterDns => string.IsNullOrWhiteSpace(c.Previous) ? "automatic" : string.Join(", ", c.Previous.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)),
            ChangeKind.ServiceStartType => c.Previous,
            ChangeKind.ServiceRunning => c.Previous?.ToLowerInvariant(),
            ChangeKind.FastStartup or ChangeKind.SystemProxy or ChangeKind.Transparency => c.Previous == "0" ? "off" : "on",
            ChangeKind.PageFile => "a custom size",
            _ => null,
        };
        return string.IsNullOrWhiteSpace(was) || c.Label.Contains("(was ", StringComparison.Ordinal) ? c.Label : $"{c.Label} (was {was})";
    }

    private static string PlanName(string? guid) => guid?.ToLowerInvariant() switch
    {
        null or "" => "",
        "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" => "High performance",
        "a1841308-3bce-4d0d-9ff0-5c3e3b8f1b4b" => "Power saver",
        "e9a42b02-d5df-448d-aa00-03f14749eb61" => "Ultimate Performance",
        "381b4222-f694-41f0-9685-ff5bb260df2e" => "Balanced",
        _ => "a custom power plan",
    };

    /// <summary>Journal record for a permanent change, so "Undo all" lists it as skipped instead of silently ignoring it.</summary>
    public static ChangeRecord Permanent(string target, string label, string actor) =>
        ChangeRecord.New(ChangeKind.NotUndoable, target, null, label, actor);
}
