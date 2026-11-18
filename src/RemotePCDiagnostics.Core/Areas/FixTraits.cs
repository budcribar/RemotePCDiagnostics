namespace RemotePCDiagnostics.Core.Areas;

/// <summary>What to expect of each one-click fix, for the page and for agents choosing which single fix to run.</summary>
public static class FixTraits
{
    /// <summary>Can run for many minutes.</summary>
    public static bool Slow(RemediationKind k) => k is RemediationKind.CheckAndInstallDriverUpdates or RemediationKind.CheckAndInstallWindowsUpdates
        or RemediationKind.InstallUpdate or RemediationKind.AnalyzeComponentStore or RemediationKind.CleanUpComponentStore
        or RemediationKind.RepairComponentStore or RemediationKind.RepairComponentStoreFromImage or RemediationKind.RepairSystemFiles
        or RemediationKind.OptimizeSsd;

    /// <summary>Windows may ask for a restart to finish it.</summary>
    public static bool MayNeedRestart(RemediationKind k) => k is RemediationKind.CheckAndInstallDriverUpdates or RemediationKind.CheckAndInstallWindowsUpdates
        or RemediationKind.InstallUpdate or RemediationKind.CleanUpComponentStore or RemediationKind.RepairComponentStore
        or RemediationKind.RepairComponentStoreFromImage or RemediationKind.RepairSystemFiles;

    public static string Risk(RemediationKind k) => Workflow.FixCatalog.RiskOf(k).ToString().ToLowerInvariant();

    public static string Undo(RemediationKind k) => Changes.Undoability.Of(k) switch
    {
        Changes.UndoSupport.Full => "full",
        Changes.UndoSupport.NothingToUndo => "nothing",
        _ => "none",
    };
}
