namespace RemotePCDiagnostics.Core.Bios;

/// <summary>Firmware startup mode reported by the operating system.</summary>
public enum BiosFirmwareMode
{
    Unknown = 0,
    Uefi = 1,
    Legacy = 2,
}

/// <summary>Outcome of checking a vendor catalog or update backend for a newer BIOS version.</summary>
public enum BiosCheckStatus
{
    UpToDate = 0,
    UpdateAvailable = 1,
    UnsupportedHardware = 2,
    ProviderUnavailable = 3,
    Offline = 4,
    Failed = 5,
}

/// <summary>Urgency / classification reported by the vendor for a BIOS release.</summary>
public enum BiosUpdateSeverity
{
    Unknown = 0,
    Optional = 1,
    Recommended = 2,
    Critical = 3,
}

/// <summary>Lifecycle stages reported during a BIOS update installation.</summary>
public enum BiosInstallStage
{
    CheckingPrerequisites = 0,
    Downloading = 1,
    Verifying = 2,
    SuspendingBitLocker = 3,
    Staging = 4,
    Installing = 5,
    RebootRequired = 6,
    Completed = 7,
    Failed = 8,
}

/// <summary>Terminal outcome of <see cref="IBiosUpdateProvider.InstallAsync"/> and <see cref="IBiosUpdateService.InstallUpdateAsync"/>.</summary>
public enum BiosInstallStatus
{
    StagedForReboot = 0,
    Completed = 1,
    AlreadyUpToDate = 2,
    BlockedByPrerequisites = 3,
    Unsupported = 4,
    Refused = 5,
    Failed = 6,
}

/// <summary>
/// Vendor-independent SMBIOS / firmware identity probed once from the PC and supplied to every <see cref="IBiosUpdateProvider"/>.
/// </summary>
public sealed record BiosSystemIdentity(
    string Manufacturer,
    string Model,
    string SystemSku,
    string BoardManufacturer,
    string BoardProduct,
    string BoardVersion,
    string SerialNumber,
    string OsVersion,
    string Architecture,
    BiosCurrentInfo CurrentBios)
{
    public static BiosSystemIdentity Empty { get; } = new(
        Manufacturer: "",
        Model: "",
        SystemSku: "",
        BoardManufacturer: "",
        BoardProduct: "",
        BoardVersion: "",
        SerialNumber: "",
        OsVersion: "",
        Architecture: "",
        CurrentBios: BiosCurrentInfo.Empty);
}

/// <summary>Currently installed BIOS/UEFI firmware details.</summary>
public sealed record BiosCurrentInfo(
    string Vendor,
    string Version,
    DateOnly? ReleaseDate = null,
    string ReleaseDateRaw = "",
    string SmbiosRevision = "",
    BiosFirmwareMode FirmwareMode = BiosFirmwareMode.Unknown,
    string Family = "",
    string ProviderId = "",
    IReadOnlyDictionary<string, string>? Metadata = null)
{
    public static BiosCurrentInfo Empty { get; } = new("", "");

    public bool HasVersion => !string.IsNullOrWhiteSpace(Version);
}

/// <summary>Declares what operations a vendor BIOS update provider supports.</summary>
public sealed record BiosProviderCapabilities(
    bool CanCheckLatest = true,
    bool CanInstall = false,
    bool SupportsSilentInstall = false,
    bool RequiresReboot = true,
    bool RequiresElevation = true,
    bool RequiresInternet = true);

/// <summary>Result of querying a vendor provider for the latest BIOS available for this PC.</summary>
public sealed record BiosLatestInfo(
    BiosCheckStatus Status,
    string ProviderId,
    string? LatestVersion = null,
    DateOnly? ReleaseDate = null,
    BiosUpdateSeverity Severity = BiosUpdateSeverity.Unknown,
    string? PackageId = null,
    string? ReleaseSummary = null,
    string? ReleaseNotesUrl = null,
    string? DownloadUrl = null,
    string? Sha256 = null,
    long? SizeBytes = null,
    bool RequiresReboot = true,
    string? Message = null,
    IReadOnlyDictionary<string, string>? Metadata = null)
{
    public static BiosLatestInfo UpToDate(
        string providerId,
        string? latestVersion,
        DateOnly? releaseDate = null,
        string? message = null,
        IReadOnlyDictionary<string, string>? metadata = null) =>
        new(BiosCheckStatus.UpToDate, providerId, latestVersion, releaseDate, Message: message ?? "BIOS is up to date.", Metadata: metadata);

    public static BiosLatestInfo UpdateAvailable(
        string providerId,
        string latestVersion,
        DateOnly? releaseDate = null,
        BiosUpdateSeverity severity = BiosUpdateSeverity.Recommended,
        string? packageId = null,
        string? releaseSummary = null,
        string? releaseNotesUrl = null,
        string? downloadUrl = null,
        string? sha256 = null,
        long? sizeBytes = null,
        bool requiresReboot = true,
        string? message = null,
        IReadOnlyDictionary<string, string>? metadata = null) =>
        new(BiosCheckStatus.UpdateAvailable, providerId, latestVersion, releaseDate, severity, packageId,
            releaseSummary, releaseNotesUrl, downloadUrl, sha256, sizeBytes, requiresReboot,
            message ?? $"BIOS update {latestVersion} is available.", metadata);

    public static BiosLatestInfo Unsupported(string providerId, string message) =>
        new(BiosCheckStatus.UnsupportedHardware, providerId, Message: message);

    public static BiosLatestInfo Unavailable(string providerId, string message) =>
        new(BiosCheckStatus.ProviderUnavailable, providerId, Message: message);

    public static BiosLatestInfo Offline(string providerId, string message = "Internet access is required to check for BIOS updates.") =>
        new(BiosCheckStatus.Offline, providerId, Message: message);

    public static BiosLatestInfo Failed(string providerId, string message) =>
        new(BiosCheckStatus.Failed, providerId, Message: message);
}

/// <summary>Inputs to <see cref="IBiosUpdateService.InstallUpdateAsync"/> and <see cref="IBiosUpdateProvider.InstallAsync"/>.</summary>
public sealed record BiosInstallRequest(
    BiosSystemIdentity System,
    BiosCurrentInfo Current,
    BiosLatestInfo Target,
    bool Approved,
    string ApprovedBy = "",
    bool SuspendBitLocker = true,
    bool AllowReboot = false,
    bool VerifyHash = true,
    string? StagingDirectory = null);

/// <summary>Progress snapshot reported while downloading, verifying, or staging a BIOS update.</summary>
public sealed record BiosInstallProgress(
    BiosInstallStage Stage,
    int Percent,
    string Detail);

/// <summary>Outcome of attempting to install or stage a BIOS update.</summary>
public sealed record BiosInstallResult(
    bool Succeeded,
    BiosInstallStatus Status,
    bool RequiresReboot = false,
    bool BitLockerSuspended = false,
    string? PreviousVersion = null,
    string? TargetVersion = null,
    string Message = "",
    int? ExitCode = null,
    string? LogTail = null)
{
    public static BiosInstallResult StagedForReboot(
        string? previousVersion,
        string? targetVersion,
        bool bitLockerSuspended = false,
        string? message = null,
        int? exitCode = 0,
        string? logTail = null) =>
        new(true, BiosInstallStatus.StagedForReboot, RequiresReboot: true, BitLockerSuspended: bitLockerSuspended,
            PreviousVersion: previousVersion, TargetVersion: targetVersion,
            Message: message ?? $"BIOS {targetVersion} is staged and will be applied on the next restart.",
            ExitCode: exitCode, LogTail: logTail);

    public static BiosInstallResult Refused(string message, string? previousVersion = null, string? targetVersion = null) =>
        new(false, BiosInstallStatus.Refused, PreviousVersion: previousVersion, TargetVersion: targetVersion, Message: message);

    public static BiosInstallResult Blocked(string message, string? previousVersion = null, string? targetVersion = null) =>
        new(false, BiosInstallStatus.BlockedByPrerequisites, PreviousVersion: previousVersion, TargetVersion: targetVersion, Message: message);

    public static BiosInstallResult Unsupported(string message, string? previousVersion = null, string? targetVersion = null) =>
        new(false, BiosInstallStatus.Unsupported, PreviousVersion: previousVersion, TargetVersion: targetVersion, Message: message);

    public static BiosInstallResult Failed(string message, string? previousVersion = null, string? targetVersion = null, int? exitCode = null, string? logTail = null) =>
        new(false, BiosInstallStatus.Failed, PreviousVersion: previousVersion, TargetVersion: targetVersion, Message: message, ExitCode: exitCode, LogTail: logTail);
}

/// <summary>Point-in-time power, encryption, elevation, and reboot state checked before flashing firmware.</summary>
public sealed record BiosSafetySnapshot(
    bool? OnAcPower,
    bool? HasBattery,
    int? BatteryPercent,
    bool? BitLockerActive,
    bool? BitLockerSuspended,
    bool HasElevation,
    bool? PendingReboot);

/// <summary>Pre-flash safety gate evaluation.</summary>
public sealed record BiosSafetyCheckResult(
    bool Passed,
    IReadOnlyList<string> BlockingReasons,
    IReadOnlyList<string> Warnings);

/// <summary>End-to-end result returned by <see cref="IBiosUpdateService.CheckForUpdateAsync"/>.</summary>
public sealed record BiosUpdateCheckOutcome(
    BiosSystemIdentity System,
    BiosCurrentInfo Current,
    BiosLatestInfo Latest,
    string? ProviderId,
    string? ProviderDisplayName);
