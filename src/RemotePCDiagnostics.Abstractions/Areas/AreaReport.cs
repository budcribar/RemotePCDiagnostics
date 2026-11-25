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
    /// <summary>Stops one device from waking the PC (<c>powercfg /devicedisablewake</c>). Target = the device's name exactly as
    /// <c>powercfg /devicequery wake_armed</c> lists it; it must still be on that list when the fix runs. Undo arms it again.</summary>
    DisableDeviceWake,
    /// <summary>Downloads, verifies, and stages the latest vendor BIOS/UEFI firmware update via <c>IBiosUpdateService</c>. Target = target BIOS version.</summary>
    InstallBiosUpdate,
    /// <summary>Moves extra copies in one or more duplicate file sets to the Recycle Bin after re-verifying SHA-256 hashes against the kept copy. Target = JSON array of <c>DuplicateDeletionSet</c>.</summary>
    DeleteDuplicateFiles,
    /// <summary>Stops a scheduled task from waking the PC by turning off its WakeToRun setting. Target = full Task Scheduler path (e.g. <c>\Hewlett-Packard\HP Diagnostics\SmartCheckTest</c>). Undo turns WakeToRun back on.</summary>
    DisableWakeTimer,
    /// <summary>Opens a Windows Settings or Windows Security page (<c>ms-settings:</c> or <c>windowsdefender:</c>) for settings Windows won't let apps change directly (such as Tamper Protection). Target = settings URI.</summary>
    OpenSettings,
    /// <summary>Turns on Windows Storage Sense (<c>HKCU\...\StoragePolicy\01 = 1</c>) while preserving existing cadence and cleanup choices.</summary>
    EnableStorageSense,
    /// <summary>Resets configured AC Maximum processor state (<c>PROCTHROTTLEMAX</c>) on the active power scheme back to 100%.</summary>
    ResetMaxProcessorState,
    /// <summary>Points an allowlisted developer package cache user environment variable (<c>NUGET_PACKAGES</c>, <c>npm_config_cache</c>, <c>PIP_CACHE_DIR</c>, <c>VCPKG_DEFAULT_BINARY_CACHE</c>) to a Dev Drive folder.</summary>
    MovePackageCacheToDevDrive,
    /// <summary>Creates and mounts a persistent dynamically expanding ReFS Dev Drive VHDX (~50 GB) via the Agent. Undo detaches and deletes it.</summary>
    CreatePersistentDevDrive,
    /// <summary>Installs an allowlisted .NET SDK side-by-side via winget (<c>Microsoft.DotNet.SDK.10</c> or <c>Microsoft.DotNet.SDK.11</c>).</summary>
    InstallDotNetSdk,

    // 8. Sound (Core Audio in the signed-in user's session; IPolicyConfig for the default device, the endpoint switch, format and enhancements)
    /// <summary>Unmutes an audio endpoint. Target = the endpoint id. Undo mutes it again.</summary>
    UnmuteAudioEndpoint,
    /// <summary>Raises a quiet endpoint (outputs to 50%, microphones to 80%). Target = the endpoint id. Undo puts the old level back.</summary>
    RaiseAudioVolume,
    /// <summary>A dialog fix (device picker). Target before the choice = "output" or "input"; after = the endpoint id, plus "|calls" when it
    /// becomes the default for calls too. Undo makes the previous defaults the defaults again.</summary>
    SetDefaultAudioEndpoint,
    /// <summary>Turns a disabled endpoint back on (the Sound control panel's Enable). Target = the endpoint id. Undo disables it again.</summary>
    EnableAudioEndpoint,
    /// <summary>Puts the shared-mode format back to the driver's default. Target = the endpoint id. Undo puts the old format back.</summary>
    ResetAudioFormat,
    /// <summary>Turns audio enhancements off ("{id}|off") or on ("{id}|on"). Undo puts the switch back.</summary>
    ToggleAudioEnhancements,
    /// <summary>Unmutes one app in the Volume mixer. Target = "{endpointId}|{process name}". Undo mutes it again while it still runs.</summary>
    UnmuteAudioSession,
    /// <summary>A consent dialog: turns on the Windows privacy switches that block the microphone or camera. Target = "microphone" or
    /// "webcam". The per-account switches change in the app; the device-wide one through the Agent, only when it's the one that's off.</summary>
    AllowCapturePrivacy,
    /// <summary>A dialog fix (device busy): closes the app holding an audio device. Target before the choice = the endpoint id; after =
    /// "{endpointId}|{process name}". Runs the End task path (protected processes refused, the Agent for an elevated app). Not undoable.</summary>
    CloseAudioHolder,
    /// <summary>Starts Windows Audio Endpoint Builder, then Windows Audio, through the Agent (the services card). Target = "". Leaves nothing to undo.</summary>
    StartAudioServices,
    /// <summary>Restarts Windows Audio through the Agent when it stopped answering; if the sound devices still don't answer, restarts the
    /// Endpoint Builder too (which takes Windows Audio with it) and starts both. Target = "". Leaves nothing to undo.</summary>
    RestartAudioServices,
    /// <summary>Sets whichever of the two Windows Audio services is disabled back to Automatic (journaled), then starts them. Target = "".
    /// Undo puts the start type back.</summary>
    SetAudioServicesAutomatic,
}

/// <summary>A one-click remediation button attached to an <see cref="AreaCard"/> or <see cref="AreaRow"/>.</summary>
public sealed record AreaAction(RemediationKind Kind, string ButtonText, string Target = "", string TargetLabel = "", string? CurrentSetting = null)
{
    /// <summary>
    /// A fix that needs a choice (which device, which app): its confirmation lists these and Go waits until one is picked (or one is
    /// <see cref="AreaChoice.Selected"/>). The picked choice's <see cref="AreaChoice.Id"/> becomes the fix's Target. Null = no choice.
    /// </summary>
    public IReadOnlyList<AreaChoice>? Choices { get; init; }
    /// <summary>A checkbox under the choices ("Also use for calls"); ticked adds its <see cref="AreaChoiceOption.Suffix"/> to the Target.</summary>
    public AreaChoiceOption? Option { get; init; }
    /// <summary>A box the person must tick before Go is enabled (what they agree to). Null = no consent needed.</summary>
    public string? Consent { get; init; }
    /// <summary>What the dialog says when <see cref="Choices"/> is empty (nothing to pick).</summary>
    public string? EmptyChoicesText { get; init; }

    /// <summary>The Target once <paramref name="choice"/> is picked and the option is ticked or not.</summary>
    public string TargetFor(AreaChoice choice, bool optionTicked) => choice.Id + (optionTicked && Option is { } o ? o.Suffix : "");
}

/// <summary>One row of a fix dialog's list. <see cref="DisabledReason"/> set = shown greyed out with the reason, not selectable.</summary>
public sealed record AreaChoice(string Id, string Label, string? Detail = null, string? DisabledReason = null, bool Selected = false);

/// <summary>The checkbox under a fix dialog's list. <see cref="Suffix"/> is added to the chosen Target when it's ticked.</summary>
public sealed record AreaChoiceOption(string Label, string Suffix, bool DefaultOn = true);

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
    string? FilePath = null, IReadOnlyList<HangOccurrence>? EvidenceOccurrences = null);
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
    : IRunEnd, IKeyMetrics
{
    /// <summary>The numbers this check tracks over time (see <see cref="KeyMetric"/>); null when it tracks none or couldn't read them.</summary>
    public IReadOnlyList<KeyMetric>? KeyMetrics { get; init; }

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
