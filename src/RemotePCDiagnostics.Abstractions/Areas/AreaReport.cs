namespace RemotePCDiagnostics.Core.Areas;

/// <summary>Status dot for a card or a drawer row.</summary>
public enum AreaLevel { Neutral, Ok, Warning, Error }

/// <summary>Supported one-click automated remediations across diagnostic area modules.</summary>
public enum RemediationKind
{
    // 1. Drivers & Windows Updates
    CheckAndInstallDriverUpdates,
    CheckAndInstallWindowsUpdates,
    RestartDevice,
    EnableDevice,
    ScanHardwareChanges,

    // 2. Performance, Power Plan & Uptime
    SetBalancedPowerPlan,
    DisableFastStartup,
    ScheduleCleanRestart,
    CancelScheduledRestart,
    EndProcessGroup,

    // 3. Network & Connectivity Fixes
    DisableSystemProxy,
    FlushDnsAndRenewIp,
    SetPublicDns,
    ResetDhcpDns,

    // 4. Storage & Disk Space Cleanup
    CleanTempFiles,
    OptimizeSsd,

    // 5. Windows repair (offered when DISM ScanHealth / SFC verify-only found corruption)
    RepairComponentStore,
    RepairSystemFiles,

    // 6. Security settings (Security essentials): Target = a SecurityFixes key ("pua", "asr", "llmnr", ...)
    ApplySecuritySetting,

    // 7. Single steps, each run alone. New members go at the end so numbers already written stay the same.
    /// <summary>Read-only: reports the component store's size and whether a cleanup is recommended.</summary>
    AnalyzeComponentStore,
    /// <summary>Removes superseded component versions (DISM StartComponentCleanup).</summary>
    CleanUpComponentStore,
    /// <summary>DISM RestoreHealth from a Windows image instead of Windows Update. Target = the path of install.wim / install.esd.</summary>
    RepairComponentStoreFromImage,
    /// <summary>Installs one pending Windows or driver update. Target = the update's Windows Update ID.</summary>
    InstallUpdate,
}

/// <summary>A one-click remediation button attached to an <see cref="AreaCard"/> or <see cref="AreaRow"/>.</summary>
public sealed record AreaAction(RemediationKind Kind, string ButtonText, string Target = "", string TargetLabel = "", string? CurrentSetting = null);

/// <summary>A button on an <see cref="AreaCard"/> that runs another check (a stress test, say) as the suggested next step. Unlike an
/// <see cref="AreaAction"/> it changes nothing on the PC; it is run like Run just this.</summary>
public sealed record AreaCheckLink(string CheckId, string ButtonText);

/// <summary>One drawer table row; <see cref="Values"/> line up with <see cref="AreaCard.Columns"/>. All text is end-user friendly.</summary>
public sealed record AreaRow(
    AreaLevel Level,
    IReadOnlyList<string> Values,
    IReadOnlyList<string?>? SortKeys = null,
    string? Key = null,
    IReadOnlyList<AreaAction>? Actions = null,
    string? Detail = null, string? DumpPath = null, string? GetHelpUri = null, string? EventCopyText = null, IReadOnlyList<string>? ReviewKeys = null, IReadOnlyList<HangOccurrence>? HangOccurrences = null,
    string? FilePath = null);
/// <remarks><see cref="AreaRow.Key"/> is an optional stable id (e.g. the service name) used for row actions.
/// <see cref="AreaRow.Detail"/> is optional longer text (full message, occurrences) shown when the row is expanded.</remarks>

/// <summary>A summary card plus its drill-down drawer content. Text here is shown to the user; technical detail goes to the log.</summary>
public sealed record AreaCard(
    string Id, string Title, AreaLevel Level, string Headline, string Meta,
    IReadOnlyList<string> Columns, IReadOnlyList<AreaRow> Rows,
    string? ErrorText = null, string? EmptyText = null, string? Note = null,
    IReadOnlyList<AreaAction>? Actions = null, bool PreserveRowOrder = false)
{
    public int? EventCount { get; init; }
    public int? WindowDays { get; init; }
    public int? RecentEventCount { get; init; }
    public int? RecentWindowDays { get; init; }

    /// <summary>The check the card suggests running next, shown as a button on the card.</summary>
    public AreaCheckLink? RunCheck { get; init; }

    /// <summary>For a card about storage volumes: their capacity, free and used space in bytes, added up. The page publishes them
    /// for browser agents as numbers, so nothing has to be read back out of the formatted text.</summary>
    public long? TotalBytes { get; init; }
    public long? FreeBytes { get; init; }
    public long? UsedBytes { get; init; }

    public static AreaCard Failed(string id, string title, string errorText) =>
        new(id, title, AreaLevel.Error, "", "", [], [], ErrorText: errorText);
}

/// <summary>Payload of an area module: the cards, a one-line summary for the Dashboard, and the overall status.</summary>
public sealed record AreaReport(IReadOnlyList<AreaCard> Cards, string Summary, DiagnosticStatus Status, string? Notice = null, IReadOnlyList<AreaCard>? ReviewedCards = null, bool Cancelled = false)
    : IRunEnd
{
    /// <summary>
    /// Set when the check never reached a verdict (the tool was blocked, didn't start, or ended without a recognizable result): History
    /// and the Checks screen show "Couldn't run" with this reason instead of Critical. <see cref="Status"/> stays Error so nothing treats
    /// the run as passed.
    /// </summary>
    public string? CouldNotRunReason { get; init; }

    [System.Text.Json.Serialization.JsonIgnore]
    public RunEnd RunEnd => Cancelled ? RunEnd.Cancelled : CouldNotRunReason is not null ? RunEnd.CouldNotRun : RunEnd.Finished;

    public static AreaReport Failed(string message) => new([], message, DiagnosticStatus.Error);

    /// <summary>A scan stopped with <c>ICancellableScan.Cancel</c> before it finished: Cancelled, so History and the Checks screen don't
    /// count it as a failure.</summary>
    public static AreaReport ScanCancelled() => new([], "Scan cancelled before it finished", DiagnosticStatus.Warning, Cancelled: true);

    public static DiagnosticStatus Worst(IEnumerable<AreaLevel> levels) =>
        levels.DefaultIfEmpty(AreaLevel.Ok).Max() switch
        {
            AreaLevel.Error => DiagnosticStatus.Error,
            AreaLevel.Warning => DiagnosticStatus.Warning,
            _ => DiagnosticStatus.Ok,
        };
}
