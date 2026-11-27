using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Session;
using static RemotePCDiagnostics.Core.Bios.BiosProviderCommon;

namespace RemotePCDiagnostics.Core.Bios;

/// <summary>
/// Generic UEFI firmware capsule fallback provider (<c>VendorId = "windows-update"</c>, <c>Priority = 10</c>).
/// Uses 100% pure-C# Windows Update Agent COM (<c>Microsoft.Update.Session</c>) via
/// <see cref="IBiosWindowsUpdateClient"/> to discover and install pending UEFI <c>System Firmware</c>
/// driver capsules, suspending BitLocker for one reboot when requested and routing privileged
/// installs through <see cref="IElevatedCommandBridge"/> when running un-elevated.
/// </summary>
public sealed partial class WindowsUpdateBiosProvider : IBiosUpdateProvider
{
    public const string ProviderVendorId = "windows-update";

    private static readonly TimeSpan DefaultInstallTimeout = TimeSpan.FromMinutes(10);

    private static readonly HashSet<string> NonFirmwareDriverClasses = new(StringComparer.OrdinalIgnoreCase)
    {
        "media",
        "display",
        "net",
        "audioendpoint",
        "bluetooth",
        "camera",
        "hidclass",
        "keyboard",
        "mouse",
        "printer",
        "diskdrive",
        "scsiadapter",
        "usb",
        "usbdevice",
        "ports",
        "battery",
        "monitor",
        "sensor",
        "biometric",
        "smartcardreader",
        "softwarecomponent",
        "extension",
    };

    private static readonly string[] ExcludedSubstrings =
    [
        "management engine",
        "management engine interface",
        "csme",
        "bios setup",
        "setup utility",
        "configuration utility",
        "update utility",
        "utility",
        "diagnostic",
        "diagnostics",
        "toolkit",
        "application",
        "usb",
        "hub",
        "thunderbolt",
        "dock",
        "nvme",
        "storage",
        "audio",
        "sound",
        "realtek",
        "graphics",
        "display",
        "video",
        "monitor",
        "geforce",
        "radeon",
        "network",
        "ethernet",
        "wi-fi",
        "wifi",
        "wlan",
        "bluetooth",
        "wwan",
        "cellular",
        "camera",
        "webcam",
        "touchpad",
        "trackpad",
        "touchscreen",
        "keyboard",
        "mouse",
        "printer",
        "scanner",
        "fingerprint",
        "biometric",
        "smartcard",
        "battery",
        "power delivery",
        "retimer",
        "embedded controller",
        "ec firmware",
        "pd firmware",
        "chipset",
        "cumulative update",
        "security intelligence",
        "windows defender",
        "malicious software removal",
        ".net framework",
        "feature update",
        "servicing stack",
        "quality update",
        "microsoft edge",
        "silverlight",
    ];

    // Offline / service-unreachable Windows Update COM HRESULTs.
    private static readonly HashSet<int> OfflineWuaHResults =
    [
        unchecked((int)0x8024402C), // WU_E_PT_WINHTTP_NAME_NOT_RESOLVED
        unchecked((int)0x8024402F), // WU_E_PT_ECP_SUCCEEDED_WITH_ERRORS / connection error
        unchecked((int)0x80244022), // WU_E_PT_HTTP_STATUS_SERVICE_UNAVAIL
        unchecked((int)0x80072EE7), // ERROR_WINHTTP_NAME_NOT_RESOLVED
        unchecked((int)0x80072EFD), // ERROR_WINHTTP_CANNOT_CONNECT
        unchecked((int)0x80072EFE), // ERROR_WINHTTP_CONNECTION_ERROR
        unchecked((int)0x80072EE2), // ERROR_WINHTTP_TIMEOUT
        unchecked((int)0x8024401C), // WU_E_PT_HTTP_STATUS_REQUEST_TIMEOUT
    ];

    [GeneratedRegex(@"\b(?:amt|me|mei|lan|nic|gpu|ssd|hdd|tool)\b", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex ExcludedShortTokensRegex();

    [GeneratedRegex(@"\b(?:system\s+firmware|uefi|bios|firmware)\b", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex FirmwarePositiveRegex();

    [GeneratedRegex(@"(?:\s-\s+|\b(?:version|ver\.?|rev\.?)\s*[:\-]?\s*)([A-Za-z]?[0-9]+(?:\.[0-9]+){1,3})\b", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex TitleVersionRegex();

    [GeneratedRegex(@"^(?:UEFI\s+Version|BIOS\s+Version|Firmware\s+Version|Version|Ver\.?|Rev\.?|UEFI|BIOS|v(?=\d|\s|[:\-]))\s*[:\-]?\s*", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex LeadingVersionPrefixRegex();


    private readonly IBiosWindowsUpdateClient _wuaClient;
    private readonly Func<DateTimeOffset> _now;

    /// <summary>Windows Update's local cache is trusted when its last finished scan is at most this old; older, the check searches online.</summary>
    public static readonly TimeSpan MaxCacheAge = TimeSpan.FromDays(7);

    /// <summary>
    /// Searches the local cache when Windows Update scanned recently, otherwise the update service. When the online search fails or
    /// times out, falls back to the cache and returns when that cache was last refreshed (null when the result is current).
    /// </summary>
    private async Task<(IReadOnlyList<BiosWuaFirmwareUpdate>? Updates, DateTimeOffset? CacheOnlyAsOf)> SearchFreshEnoughAsync(string? serial, CancellationToken ct)
    {
        DateTimeOffset? lastScan = null;
        try { lastScan = await _wuaClient.GetLastSuccessfulScanUtcAsync(ct).ConfigureAwait(false); }
        catch (Exception ex) when (ex is not OperationCanceledException) { LogWarn($"Couldn't read when Windows Update last scanned: {ex.Message}", serial); }

        if (lastScan is { } t && _now() - t <= MaxCacheAge)
            return (await _wuaClient.SearchPendingFirmwareUpdatesAsync(online: false, ct).ConfigureAwait(false), null);

        try
        {
            return (await _wuaClient.SearchPendingFirmwareUpdatesAsync(online: true, ct).ConfigureAwait(false), null);
        }
        // No Windows Update on this host at all: an offline search would fail the same way.
        catch (Exception ex) when (ex is not PlatformNotSupportedException && (ex is not OperationCanceledException || !ct.IsCancellationRequested))
        {
            LogWarn($"Online Windows Update search failed ({ex.Message}); using the local cache from {lastScan?.ToString("u", CultureInfo.InvariantCulture) ?? "an unknown time"}.", serial);
            return (await _wuaClient.SearchPendingFirmwareUpdatesAsync(online: false, ct).ConfigureAwait(false), lastScan ?? DateTimeOffset.MinValue);
        }
    }

    /// <summary>Set on the result when only an old local cache could be searched, so a vendor provider falling back here still shows why.</summary>
    internal const string StaleCacheMetadataKey = "windowsUpdateCacheStale";

    internal static string StaleCacheMessage(DateTimeOffset lastScan, DateTimeOffset now)
    {
        var when = lastScan == DateTimeOffset.MinValue
            ? "Windows Update hasn't reported a finished scan"
            : $"Windows Update last checked for updates {Math.Max(0, (int)(now - lastScan).TotalDays)} days ago";
        return $"{when}, and an online check couldn't finish, so this PC may be missing a firmware update. Run Windows Update, then check again.";
    }
    private readonly SystemCommandRunner? _commands;
    private readonly IElevatedCommandBridge? _elevatedBridge;
    private readonly Func<bool>? _isProcessElevated;
    private readonly ILogger? _log;

    /// <summary>
    /// Creates a Windows Update UEFI firmware provider. All parameters are optional so MS.DI
    /// resolves this single constructor cleanly with zero extra service registrations.
    /// </summary>
    public WindowsUpdateBiosProvider(
        IBiosWindowsUpdateClient? wuaClient = null,
        SystemCommandRunner? commands = null,
        IElevatedCommandBridge? elevatedBridge = null,
        Func<bool>? isProcessElevated = null,
        ILogger? log = null,
        Func<DateTimeOffset>? now = null)
    {
        _wuaClient = wuaClient ?? new WindowsUpdateAgentBiosClient(log);
        _now = now ?? (() => DateTimeOffset.UtcNow);
        _commands = commands;
        _elevatedBridge = elevatedBridge;
        _isProcessElevated = isProcessElevated;
        _log = log;
    }

    public string VendorId => ProviderVendorId;
    public string DisplayName => "Windows Update";
    public int Priority => 10;

    public BiosProviderCapabilities Capabilities { get; } = new(
        CanCheckLatest: true,
        CanInstall: true,
        SupportsSilentInstall: true,
        RequiresReboot: true,
        RequiresElevation: true,
        RequiresInternet: true);

    public bool CanHandle(BiosSystemIdentity system) =>
        system is not null && system.CurrentBios?.FirmwareMode == BiosFirmwareMode.Uefi;

    public Task<BiosCurrentInfo> GetCurrentVersionAsync(BiosSystemIdentity system, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(system);
        ct.ThrowIfCancellationRequested();

        var current = system.CurrentBios ?? BiosCurrentInfo.Empty;
        var serial = system.SerialNumber;
        var safeVendor = RedactText(current.Vendor, serial);
        var safeVersion = RedactText(current.Version, serial);
        var safeReleaseDateRaw = RedactText(current.ReleaseDateRaw, serial);
        var safeSmbiosRevision = RedactText(current.SmbiosRevision, serial);
        var safeFamily = RedactText(current.Family, serial);

        IReadOnlyDictionary<string, string>? safeMetadata = current.Metadata;
        if (current.Metadata is not null && current.Metadata.Count > 0 && !string.IsNullOrWhiteSpace(serial))
        {
            var dict = new Dictionary<string, string>(current.Metadata.Count, StringComparer.OrdinalIgnoreCase);
            foreach (var kv in current.Metadata)
                dict[kv.Key] = RedactText(kv.Value, serial);
            safeMetadata = dict;
        }

        return Task.FromResult(current with
        {
            Vendor = safeVendor,
            Version = safeVersion,
            ReleaseDateRaw = safeReleaseDateRaw,
            SmbiosRevision = safeSmbiosRevision,
            Family = safeFamily,
            ProviderId = VendorId,
            Metadata = safeMetadata,
        });
    }

    public async Task<BiosLatestInfo> GetLatestVersionAsync(
        BiosSystemIdentity system,
        BiosCurrentInfo current,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(system);
        ct.ThrowIfCancellationRequested();
        current ??= system.CurrentBios ?? BiosCurrentInfo.Empty;

        var serial = system.SerialNumber;

        if (system.CurrentBios?.FirmwareMode != BiosFirmwareMode.Uefi)
        {
            return RedactLatestInfo(
                BiosLatestInfo.Unsupported(
                    VendorId,
                    "Windows Update firmware updates are only supported on UEFI systems."),
                serial);
        }

        try
        {
            var (updates, cacheOnlyAsOf) = await SearchFreshEnoughAsync(serial, ct).ConfigureAwait(false);
            var parsedCurrent = ParseWuaVersion(current.Version);

            var candidates = new List<WuaCandidate>();

            if (updates is not null)
            {
                foreach (var update in updates)
                {
                    if (!IsSystemFirmwareUpdate(update))
                        continue;

                    if (!TryParseStrictUpdateId(update.UpdateId, out var id))
                        continue;

                    var effectiveVersion = NormalizeVersion(update.Version) ?? TryExtractVersionFromTitle(update.Title);
                    var parsedVersion = ParseWuaVersion(effectiveVersion);
                    var isNewer = IsCandidateNewerThanCurrent(parsedVersion, update.ReleaseDate, parsedCurrent, current);

                    candidates.Add(new WuaCandidate(
                        Update: update,
                        Id: id,
                        CanonicalId: id.ToString("D"),
                        EffectiveVersion: effectiveVersion,
                        ParsedVersion: parsedVersion,
                        IsNewer: isNewer));
                }
            }

            // An old cache with nothing newer in it says nothing about today: don't call the PC up to date.
            if (cacheOnlyAsOf is { } asOf && !candidates.Any(c => c.IsNewer))
            {
                return RedactLatestInfo(
                    BiosLatestInfo.Unavailable(VendorId, StaleCacheMessage(asOf, _now())) with
                    {
                        Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { [StaleCacheMetadataKey] = "true" },
                    },
                    serial);
            }

            if (candidates.Count == 0)
            {
                return RedactLatestInfo(
                    BiosLatestInfo.UpToDate(
                        providerId: VendorId,
                        latestVersion: current.HasVersion ? current.Version : null,
                        releaseDate: current.ReleaseDate,
                        message: "No pending UEFI firmware updates were found via Windows Update."),
                    serial);
            }

            var ordered = OrderCandidates(candidates);
            var winner = ordered[0];
            var u = winner.Update;

            var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["source"] = "windows-update-agent",
                ["updateId"] = winner.CanonicalId,
            };

            if (!string.IsNullOrWhiteSpace(u.DriverClass))
                metadata["driverClass"] = u.DriverClass.Trim();
            if (!string.IsNullOrWhiteSpace(u.DriverModel))
                metadata["driverModel"] = u.DriverModel.Trim();

            if (winner.IsNewer)
            {
                var latestVersion = winner.EffectiveVersion
                    ?? u.ReleaseDate?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)
                    ?? u.Title.Trim();

                var severity = u.Severity == BiosUpdateSeverity.Unknown
                    ? BiosUpdateSeverity.Recommended
                    : u.Severity;

                return RedactLatestInfo(
                    BiosLatestInfo.UpdateAvailable(
                        providerId: VendorId,
                        latestVersion: latestVersion,
                        releaseDate: u.ReleaseDate,
                        severity: severity,
                        packageId: winner.CanonicalId,
                        releaseSummary: u.Title.Trim(),
                        downloadUrl: null,
                        sha256: null,
                        sizeBytes: u.SizeBytes is > 0 ? u.SizeBytes : null,
                        requiresReboot: u.RebootRequired,
                        metadata: metadata),
                    serial);
            }

            return RedactLatestInfo(
                BiosLatestInfo.UpToDate(
                    providerId: VendorId,
                    latestVersion: winner.EffectiveVersion ?? (current.HasVersion ? current.Version : null),
                    releaseDate: u.ReleaseDate ?? current.ReleaseDate,
                    message: "UEFI firmware is already up to date.",
                    metadata: metadata),
                serial);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (PlatformNotSupportedException ex)
        {
            LogWarn($"Windows Update Agent unavailable on current platform: {ex.Message}", serial);
            return RedactLatestInfo(
                BiosLatestInfo.Unavailable(VendorId, ex.Message),
                serial);
        }
        catch (COMException comEx)
        {
            var described = AgentWindowsUpdate.Describe(comEx);
            LogWarn($"Windows Update Agent COM error: {described}", serial);
            if (IsOfflineWuaHResult(comEx.HResult))
            {
                return RedactLatestInfo(
                    BiosLatestInfo.Offline(VendorId, $"Windows Update could not reach the update service: {described}"),
                    serial);
            }

            return RedactLatestInfo(
                BiosLatestInfo.Unavailable(VendorId, $"Windows Update Agent search failed: {described}"),
                serial);
        }
        catch (Exception ex) when (ex is TimeoutException or OperationCanceledException)
        {
            LogWarn("Windows Update Agent search timed out.", serial);
            return RedactLatestInfo(
                BiosLatestInfo.Offline(VendorId, "Windows Update Agent search timed out."),
                serial);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or InvalidOperationException)
        {
            LogWarn($"Windows Update Agent unavailable: {ex.Message}", serial);
            return RedactLatestInfo(
                BiosLatestInfo.Unavailable(VendorId, $"Windows Update Agent is unavailable: {ex.Message}"),
                serial);
        }
        catch (Exception ex)
        {
            LogWarn($"Windows Update firmware check failed: {ex.Message}", serial);
            return RedactLatestInfo(
                BiosLatestInfo.Failed(VendorId, $"Windows Update firmware check failed: {ex.Message}"),
                serial);
        }
    }

    public async Task<BiosInstallResult> InstallAsync(
        BiosInstallRequest request,
        IProgress<BiosInstallProgress>? progress = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ct.ThrowIfCancellationRequested();

        var (serial, prev, target, redactingLog, redactingProgress) =
            CreateRedactedInstallContext(request, _log, progress);

        // 1. Strict canonical 36-char "D" GUID validation FIRST (0 BitLocker / 0 WUA / 0 bridge calls on failure).
        if (request.Target is null || !TryParseStrictUpdateId(request.Target.PackageId, out var updateId))
        {
            const string msg = "Windows Update BIOS target requires a valid non-empty canonical GUID PackageId.";
            redactingProgress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, msg));
            return BiosInstallResult.Failed(msg, prev, target);
        }

        // 2. Resolve effective elevation & bridge; fail closed BEFORE touching BitLocker or local WUA.
        var effectiveBridge = _elevatedBridge ?? _commands?.ElevatedBridge;
        var elevated = _isProcessElevated is not null
            ? _isProcessElevated()
            : (_commands is not null ? _commands.IsProcessElevated : ElevationService.DetectProcessElevated());

        if (!elevated && effectiveBridge is not { IsConnected: true })
        {
            var msg = $"Administrator rights (or the elevated Agent service) are required to install UEFI firmware updates via Windows Update. {ElevationService.AdminRepairHint}";
            LogWarn(msg, serial);
            redactingProgress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, msg));
            return BiosInstallResult.Failed(msg, prev, target, exitCode: SystemCommandRunner.AgentFailedExitCode);
        }

        // 3. Suspend BitLocker for 1 reboot if requested (fail closed on ElevationRequired).
        var bitLocker = await BiosBitLockerSuspender.SuspendForOneRebootWithResultAsync(
            request,
            _commands,
            redactingProgress,
            redactingLog,
            ct,
            bridge: effectiveBridge,
            isProcessElevated: () => elevated).ConfigureAwait(false);

        if (bitLocker.BlocksInstall)
        {
            var rawMsg = bitLocker.Message
                ?? $"Administrator rights (or the elevated Agent service) are required to suspend BitLocker. {ElevationService.AdminRepairHint}";
            var msg = RedactText(rawMsg, serial);
            redactingProgress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, msg));
            return BiosInstallResult.Failed(msg, prev, target, exitCode: SystemCommandRunner.AgentFailedExitCode);
        }

        // 4. Execute WUA firmware install locally (when elevated) or via Agent bridge (when un-elevated).
        var displayTarget = target ?? updateId.ToString("D");
        redactingProgress?.Report(new BiosInstallProgress(
            BiosInstallStage.Installing,
            0,
            RedactText($"Installing UEFI firmware update {displayTarget} via Windows Update...", serial)));

        BiosWuaInstallOutcome? outcome;
        if (elevated)
        {
            try
            {
                outcome = await _wuaClient.InstallUpdateAsync(updateId, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                var msg = RedactText($"Windows Update firmware installation failed: {AgentWindowsUpdate.Describe(ex)}", serial);
                LogWarn(msg, serial);
                redactingProgress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, msg));
                return new BiosInstallResult(
                    Succeeded: false,
                    Status: BiosInstallStatus.Failed,
                    RequiresReboot: false,
                    BitLockerSuspended: bitLocker.Suspended,
                    PreviousVersion: prev,
                    TargetVersion: target,
                    Message: msg,
                    ExitCode: AgentWindowsUpdate.FailedCode);
            }
        }
        else
        {
            try
            {
                outcome = await effectiveBridge!.InstallBiosWindowsUpdateAsync(updateId, DefaultInstallTimeout, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex) when (ex is AdminRequiredException or NotSupportedException)
            {
                // NEVER fall back locally when un-elevated!
                var sanitized = RedactText(ex.Message, serial);
                LogWarn($"Elevated Agent rejected Windows Update firmware install: {sanitized}", serial);
                redactingProgress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, sanitized));
                return new BiosInstallResult(
                    Succeeded: false,
                    Status: BiosInstallStatus.Failed,
                    RequiresReboot: false,
                    BitLockerSuspended: bitLocker.Suspended,
                    PreviousVersion: prev,
                    TargetVersion: target,
                    Message: sanitized,
                    ExitCode: SystemCommandRunner.AgentFailedExitCode);
            }
            catch (Exception ex)
            {
                var msg = RedactText(
                    $"Elevated Agent Windows Update firmware installation failed: {ex.Message} {ElevationService.AdminRepairHint}",
                    serial);
                LogWarn(msg, serial);
                redactingProgress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, msg));
                return new BiosInstallResult(
                    Succeeded: false,
                    Status: BiosInstallStatus.Failed,
                    RequiresReboot: false,
                    BitLockerSuspended: bitLocker.Suspended,
                    PreviousVersion: prev,
                    TargetVersion: target,
                    Message: msg,
                    ExitCode: SystemCommandRunner.AgentFailedExitCode);
            }
        }

        // 5. Map BiosWuaInstallOutcome cleanly while ALWAYS preserving bitLocker.Suspended.
        if (outcome is null)
        {
            const string nullMsg = "Windows Update returned no installation outcome.";
            redactingProgress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, nullMsg));
            return new BiosInstallResult(
                Succeeded: false,
                Status: BiosInstallStatus.Failed,
                RequiresReboot: false,
                BitLockerSuspended: bitLocker.Suspended,
                PreviousVersion: prev,
                TargetVersion: target,
                Message: nullMsg,
                ExitCode: AgentWindowsUpdate.FailedCode);
        }

        var sanitizedOutcomeMsg = RedactText(outcome.Message ?? "", serial);

        if (outcome.Succeeded && outcome.RebootRequired)
        {
            var msg = string.IsNullOrWhiteSpace(sanitizedOutcomeMsg)
                ? $"BIOS {displayTarget} is staged and will be applied on the next restart."
                : sanitizedOutcomeMsg;
            redactingProgress?.Report(new BiosInstallProgress(BiosInstallStage.RebootRequired, 100, msg));
            return BiosInstallResult.StagedForReboot(prev, target, bitLocker.Suspended, msg, outcome.ResultCode);
        }

        if (outcome.Succeeded)
        {
            var msg = string.IsNullOrWhiteSpace(sanitizedOutcomeMsg)
                ? $"BIOS {displayTarget} installation completed."
                : sanitizedOutcomeMsg;
            redactingProgress?.Report(new BiosInstallProgress(BiosInstallStage.Completed, 100, msg));
            return new BiosInstallResult(
                Succeeded: true,
                Status: BiosInstallStatus.Completed,
                RequiresReboot: false,
                BitLockerSuspended: bitLocker.Suspended,
                PreviousVersion: prev,
                TargetVersion: target,
                Message: msg,
                ExitCode: outcome.ResultCode);
        }

        var failMsg = string.IsNullOrWhiteSpace(sanitizedOutcomeMsg)
            ? $"Windows Update firmware installation failed (result code {outcome.ResultCode})."
            : sanitizedOutcomeMsg;
        redactingProgress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, failMsg));
        return new BiosInstallResult(
            Succeeded: false,
            Status: BiosInstallStatus.Failed,
            RequiresReboot: false,
            BitLockerSuspended: bitLocker.Suspended,
            PreviousVersion: prev,
            TargetVersion: target,
            Message: failMsg,
            ExitCode: outcome.ResultCode);
    }

    // -------------------------------------------------------------------------
    // Strict GUID validation & System Firmware filter
    // -------------------------------------------------------------------------

    internal static bool TryParseStrictUpdateId(string? raw, out Guid updateId)
    {
        updateId = Guid.Empty;
        if (string.IsNullOrEmpty(raw) || raw.Length != 36)
            return false;

        return Guid.TryParseExact(raw, "D", out updateId) && updateId != Guid.Empty;
    }

    internal static bool IsSystemFirmwareUpdate(BiosWuaFirmwareUpdate? update)
    {
        if (update is null || string.IsNullOrWhiteSpace(update.Title))
            return false;

        if (!TryParseStrictUpdateId(update.UpdateId, out _))
            return false;

        var driverClass = update.DriverClass?.Trim() ?? "";
        if (driverClass.Length > 0 && NonFirmwareDriverClasses.Contains(driverClass))
            return false;

        var driverModel = update.DriverModel?.Trim() ?? "";
        var categoriesJoined = update.Categories is { Count: > 0 }
            ? string.Join(" ", update.Categories.Where(static c => !string.IsNullOrWhiteSpace(c)))
            : "";

        var combined = $"{update.Title} {driverModel} {driverClass} {categoriesJoined}";

        // Step A — Negative exclusions (non-BIOS drivers, peripheral firmware, Intel ME/CSME/AMT, OS updates).
        foreach (var excluded in ExcludedSubstrings)
        {
            if (combined.Contains(excluded, StringComparison.OrdinalIgnoreCase))
                return false;
        }

        if (ExcludedShortTokensRegex().IsMatch(combined))
            return false;

        // Step B — Positive system-firmware match (DriverClass="System" alone is NOT sufficient).
        if (driverClass.Length > 0 && FirmwarePositiveRegex().IsMatch(driverClass))
            return true;

        if (categoriesJoined.Length > 0 && FirmwarePositiveRegex().IsMatch(categoriesJoined))
            return true;

        if (driverModel.Length > 0 && FirmwarePositiveRegex().IsMatch(driverModel))
            return true;

        return FirmwarePositiveRegex().IsMatch(update.Title);
    }

    private static bool IsOfflineWuaHResult(int hresult) => OfflineWuaHResults.Contains(hresult);

    // -------------------------------------------------------------------------
    // Version parsing, comparison & Strict Weak Ordering (SWO)
    // -------------------------------------------------------------------------

    internal static string? TryExtractVersionFromTitle(string? title)
    {
        if (string.IsNullOrWhiteSpace(title))
            return null;

        var matches = TitleVersionRegex().Matches(title);
        if (matches.Count == 0)
            return null;

        var extracted = matches[^1].Groups[1].Value.Trim();
        return extracted.Length > 0 ? extracted : null;
    }

    private static string? NormalizeVersion(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        var cleaned = raw.Trim();
        for (var i = 0; i < 3; i++)
        {
            var stripped = LeadingVersionPrefixRegex().Replace(cleaned, "").Trim();
            if (string.Equals(stripped, cleaned, StringComparison.Ordinal))
                break;
            cleaned = stripped;
        }

        return cleaned.Length > 0 ? cleaned : null;
    }

    internal static WuaParsedVersion ParseWuaVersion(string? raw)
    {
        var cleaned = NormalizeVersion(raw);
        if (string.IsNullOrEmpty(cleaned))
            return new("", VersionClass.Empty, "0:", [], "");

        if (IsDottedNumeric(cleaned) && TryParseDottedInt64(cleaned, out var numSegs))
            return new(cleaned, VersionClass.Numeric, "1:NUM", numSegs, cleaned);

        var prefixMatch = PrefixNumericRegex().Match(cleaned);
        if (prefixMatch.Success && TryParseDottedInt64(prefixMatch.Groups[2].Value, out var pfxSegs))
            return new(cleaned, VersionClass.PrefixNumeric, "2:PFX:" + prefixMatch.Groups[1].Value, pfxSegs, cleaned);

        if (TryExtractSkeletonVersion(cleaned, classPrefix: 3, out var skelKey, out var runs))
            return new(cleaned, VersionClass.Skeleton, skelKey, runs, cleaned);

        return new(cleaned, VersionClass.Literal, "4:LIT:" + cleaned, [], cleaned);
    }

    private static bool IsCandidateNewerThanCurrent(
        WuaParsedVersion candParsed,
        DateOnly? candDate,
        WuaParsedVersion currentParsed,
        BiosCurrentInfo current)
    {
        // Case 1: Comparable versions (same SWO class or BiosVersionComparer comparable).
        if (candParsed.Class != VersionClass.Empty && currentParsed.Class != VersionClass.Empty)
        {
            int? cmp = null;
            if (StringComparer.OrdinalIgnoreCase.Equals(candParsed.ClassKey, currentParsed.ClassKey))
                cmp = CompareWithinClass(currentParsed, candParsed);
            else
                cmp = BiosVersionComparer.Compare(currentParsed.NormalizedVersion, candParsed.NormalizedVersion);

            if (cmp.HasValue)
                return cmp.Value < 0;
        }

        // Case 2: Both release dates present when version is missing or incomparable.
        if (candDate.HasValue && current.ReleaseDate.HasValue)
            return candDate.Value > current.ReleaseDate.Value;

        // Case 3: Pending IsInstalled=0 WUA capsule with no version/date proof of being equal or older.
        return true;
    }

    internal static List<WuaCandidate> OrderCandidates(IReadOnlyList<WuaCandidate> candidates) =>
        BiosProviderCommon.OrderCandidates(
            candidates,
            getPrefRank: static c => c.IsNewer ? 0 : 1,
            getClassKey: static c => c.ParsedVersion.ClassKey,
            getReleaseDate: static c => c.Update.ReleaseDate,
            compareWithinClass: static (a, b) => CompareWithinClass(a.ParsedVersion, b.ParsedVersion),
            compareTieBreakers: static (a, b) =>
            {
                var dateCmp = CompareNullableDateDescending(a.Update.ReleaseDate, b.Update.ReleaseDate);
                if (dateCmp != 0)
                    return dateCmp;

                var sevCmp = b.Update.Severity.CompareTo(a.Update.Severity);
                if (sevCmp != 0)
                    return sevCmp;

                var titleCmp = StringComparer.OrdinalIgnoreCase.Compare(a.Update.Title, b.Update.Title);
                if (titleCmp != 0)
                    return titleCmp;

                titleCmp = StringComparer.Ordinal.Compare(a.Update.Title, b.Update.Title);
                if (titleCmp != 0)
                    return titleCmp;

                var idCmp = StringComparer.OrdinalIgnoreCase.Compare(a.CanonicalId, b.CanonicalId);
                if (idCmp != 0)
                    return idCmp;

                idCmp = StringComparer.Ordinal.Compare(a.CanonicalId, b.CanonicalId);
                if (idCmp != 0)
                    return idCmp;

                var rawIdCmp = StringComparer.Ordinal.Compare(a.Update.UpdateId ?? "", b.Update.UpdateId ?? "");
                if (rawIdCmp != 0)
                    return rawIdCmp;

                var rawVerCmp = StringComparer.Ordinal.Compare(a.Update.Version ?? "", b.Update.Version ?? "");
                if (rawVerCmp != 0)
                    return rawVerCmp;

                var sizeCmp = CompareNullableLongDescending(a.Update.SizeBytes, b.Update.SizeBytes);
                if (sizeCmp != 0)
                    return sizeCmp;

                var rebootCmp = b.Update.RebootRequired.CompareTo(a.Update.RebootRequired);
                if (rebootCmp != 0)
                    return rebootCmp;

                var classMetaCmp = StringComparer.Ordinal.Compare(a.Update.DriverClass ?? "", b.Update.DriverClass ?? "");
                if (classMetaCmp != 0)
                    return classMetaCmp;

                var modelMetaCmp = StringComparer.Ordinal.Compare(a.Update.DriverModel ?? "", b.Update.DriverModel ?? "");
                if (modelMetaCmp != 0)
                    return modelMetaCmp;

                var aCats = a.Update.Categories is { Count: > 0 } ? string.Join("\u001F", a.Update.Categories) : "";
                var bCats = b.Update.Categories is { Count: > 0 } ? string.Join("\u001F", b.Update.Categories) : "";
                return StringComparer.Ordinal.Compare(aCats, bCats);
            },
            comparePrefRankFirst: true,
            prefRankDescending: false);

    private static int CompareWithinClass(WuaParsedVersion a, WuaParsedVersion b)
    {
        return a.Class switch
        {
            VersionClass.Numeric => CompareNumericSegmentArrays(a.Segments, b.Segments),
            VersionClass.PrefixNumeric => CompareNumericSegmentArrays(a.Segments, b.Segments),
            VersionClass.Skeleton => CompareFixedLengthArrays(a.Segments, b.Segments),
            VersionClass.Literal => StringComparer.OrdinalIgnoreCase.Compare(a.RawNormalized, b.RawNormalized),
            _ => 0,
        };
    }

    private void LogWarn(string message, string? serialNumber) =>
        _log?.Warn(RedactText(message, serialNumber));

    internal enum VersionClass
    {
        Empty,
        Numeric,
        PrefixNumeric,
        Skeleton,
        Literal,
    }

    internal sealed record WuaParsedVersion(
        string NormalizedVersion,
        VersionClass Class,
        string ClassKey,
        long[] Segments,
        string RawNormalized);

    internal sealed record WuaCandidate(
        BiosWuaFirmwareUpdate Update,
        Guid Id,
        string CanonicalId,
        string? EffectiveVersion,
        WuaParsedVersion ParsedVersion,
        bool IsNewer);

}

/// <summary>
/// Pure-C# Windows Update Agent COM (<c>Microsoft.Update.Session</c>) implementation of
/// <see cref="IBiosWindowsUpdateClient"/>. Zero PowerShell or shell scripts; safely guarded with
/// <see cref="OperatingSystem.IsWindows"/> / <see cref="SupportedOSPlatformAttribute"/> for cross-platform builds.
/// </summary>
internal sealed class WindowsUpdateAgentBiosClient : IBiosWindowsUpdateClient
{
    private static readonly TimeSpan DefaultSearchTimeout = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan OnlineSearchTimeout = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan DefaultInstallTimeout = TimeSpan.FromMinutes(10);

    private readonly ILogger? _log;

    public WindowsUpdateAgentBiosClient(ILogger? log = null)
    {
        _log = log;
    }

    public Task<IReadOnlyList<BiosWuaFirmwareUpdate>> SearchPendingFirmwareUpdatesAsync(CancellationToken ct = default) =>
        SearchPendingFirmwareUpdatesAsync(online: false, ct);

    public async Task<IReadOnlyList<BiosWuaFirmwareUpdate>> SearchPendingFirmwareUpdatesAsync(bool online, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Windows Update Agent is only available on Windows.");

        return await AgentWindowsUpdate.RunSerializedSearchAsync(() => SearchPendingFirmwareUpdatesWindows(online), online ? OnlineSearchTimeout : DefaultSearchTimeout, ct)
            .ConfigureAwait(false);
    }

    public Task<DateTimeOffset?> GetLastSuccessfulScanUtcAsync(CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsWindows())
            return Task.FromResult<DateTimeOffset?>(null);
        return Task.Run(ReadLastSuccessfulScanUtcWindows, CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(15), ct);
    }

    /// <summary><c>Microsoft.Update.AutoUpdate.Results.LastSearchSuccessDate</c> (UTC); readable by a standard user. Null when unknown.</summary>
    [SupportedOSPlatform("windows")]
    private DateTimeOffset? ReadLastSuccessfulScanUtcWindows()
    {
        object? auObj = null;
        object? resultsObj = null;
        try
        {
            var auType = Type.GetTypeFromProgID("Microsoft.Update.AutoUpdate", throwOnError: false);
            if (auType is null) return null;
            auObj = Activator.CreateInstance(auType);
            if (auObj is null) return null;
            dynamic au = auObj;
            resultsObj = au.Results;
            dynamic results = resultsObj!;
            object? value = results.LastSearchSuccessDate;
            if (value is not DateTime dt || dt.Year < 2000) return null;
            return new DateTimeOffset(DateTime.SpecifyKind(dt, DateTimeKind.Utc));
        }
        catch (Exception ex) when (ex is COMException or InvalidCastException or Microsoft.CSharp.RuntimeBinder.RuntimeBinderException)
        {
            _log?.Warn($"[bios:windowsupdate] Couldn't read the last Windows Update scan time: {ex.Message}");
            return null;
        }
        finally
        {
            SafeReleaseCom(resultsObj);
            SafeReleaseCom(auObj);
        }
    }

    public async Task<BiosWuaInstallOutcome> InstallUpdateAsync(Guid updateId, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();

        if (updateId == Guid.Empty)
            return new BiosWuaInstallOutcome(false, -1, false, "A valid non-empty Windows Update ID is required.");

        if (!OperatingSystem.IsWindows())
        {
            return new BiosWuaInstallOutcome(
                false,
                AgentWindowsUpdate.FailedCode,
                false,
                "Windows Update Agent is only available on Windows.");
        }

        return await RunInstallUpdateWindowsAsync(updateId, ct).ConfigureAwait(false);
    }

    [SupportedOSPlatform("windows")]
    private Task<BiosWuaInstallOutcome> RunInstallUpdateWindowsAsync(Guid updateId, CancellationToken ct) =>
        Task.Run(() => InstallUpdateWindows(updateId), CancellationToken.None)
            .WaitAsync(DefaultInstallTimeout, ct);

    [SupportedOSPlatform("windows")]
    private IReadOnlyList<BiosWuaFirmwareUpdate> SearchPendingFirmwareUpdatesWindows(bool online)
    {
        object? sessionObj = null;
        object? searcherObj = null;
        object? searchResultObj = null;
        object? updatesObj = null;

        try
        {
            var sessionType = Type.GetTypeFromProgID("Microsoft.Update.Session", throwOnError: true)!;
            sessionObj = Activator.CreateInstance(sessionType)!;
            dynamic session = sessionObj;
            try
            {
                session.ClientApplicationID = "Remote PC Diagnostics";
            }
            catch (COMException)
            {
                // Best-effort client application ID tagging.
            }

            searcherObj = session.CreateUpdateSearcher();
            dynamic searcher = searcherObj;
            try
            {
                // Offline: Windows Update's local catalog cache (same as PendingUpdates), quick and never stalls on the update service.
                // Online: only when that cache is old (see WindowsUpdateBiosProvider.MaxCacheAge).
                searcher.Online = online;
            }
            catch (COMException)
            {
                // Best effort: the searcher's own default is used.
            }
            searchResultObj = searcher.Search(AgentWindowsUpdate.Criteria(driversOnly: true));
            dynamic searchResult = searchResultObj;
            updatesObj = searchResult.Updates;
            dynamic updates = updatesObj;

            var count = (int)updates.Count;
            var results = new List<BiosWuaFirmwareUpdate>(count);

            for (var i = 0; i < count; i++)
            {
                object? updateObj = null;
                object? identityObj = null;
                object? categoriesObj = null;

                try
                {
                    updateObj = updates.Item(i);
                    dynamic update = updateObj;

                    identityObj = update.Identity;
                    dynamic? identity = identityObj;
                    var updateId = identity is not null ? ((string?)identity.UpdateID ?? "") : "";
                    var title = (string?)update.Title ?? "";
                    var driverClass = TryReadComString(() => (string?)update.DriverClass);
                    var driverModel = TryReadComString(() => (string?)update.DriverModel);
                    var releaseDate = TryReadComDate(() => (object?)update.DriverVerDate)
                                      ?? TryReadComDate(() => (object?)update.LastDeploymentChangeTime);
                    var sizeBytes = TryReadComLong(() => Convert.ToInt64(update.MaxDownloadSize, CultureInfo.InvariantCulture));
                    var rebootRequired = TryReadComBool(() => (bool)update.RebootRequired) ?? true;
                    var severity = ParseMsrcSeverity(TryReadComString(() => (string?)update.MsrcSeverity));
                    var version = WindowsUpdateBiosProvider.TryExtractVersionFromTitle(title);

                    var categories = new List<string>();
                    try
                    {
                        categoriesObj = update.Categories;
                        if (categoriesObj is not null)
                        {
                            dynamic catColl = categoriesObj;
                            var catCount = (int)catColl.Count;
                            for (var j = 0; j < catCount; j++)
                            {
                                object? catObj = null;
                                try
                                {
                                    catObj = catColl.Item(j);
                                    dynamic cat = catObj;
                                    var catName = (string?)cat.Name;
                                    if (!string.IsNullOrWhiteSpace(catName))
                                        categories.Add(catName.Trim());
                                }
                                finally
                                {
                                    SafeReleaseCom(catObj);
                                }
                            }
                        }
                    }
                    catch (COMException)
                    {
                        // Categories are optional metadata.
                    }

                    results.Add(new BiosWuaFirmwareUpdate(
                        UpdateId: updateId,
                        Title: title,
                        Version: version,
                        ReleaseDate: releaseDate,
                        SizeBytes: sizeBytes is > 0 ? sizeBytes : null,
                        Severity: severity,
                        RebootRequired: rebootRequired,
                        DriverClass: driverClass,
                        DriverModel: driverModel,
                        Categories: categories.Count > 0 ? categories : null));
                }
                finally
                {
                    SafeReleaseCom(categoriesObj);
                    SafeReleaseCom(identityObj);
                    SafeReleaseCom(updateObj);
                }
            }

            return results;
        }
        finally
        {
            SafeReleaseCom(updatesObj);
            SafeReleaseCom(searchResultObj);
            SafeReleaseCom(searcherObj);
            SafeReleaseCom(sessionObj);
        }
    }

    [SupportedOSPlatform("windows")]
    private BiosWuaInstallOutcome InstallUpdateWindows(Guid updateId)
    {
        using var api = new WuaComApi();
        var r = AgentWindowsUpdate.InstallOneDetailed(api, updateId);

        if (!string.IsNullOrEmpty(r.Error))
        {
            _log?.Warn($"Windows Update firmware install error for {updateId:D}: {r.Error}");
            return new BiosWuaInstallOutcome(
                Succeeded: false,
                ResultCode: r.ResultCode > 0 ? r.ResultCode : AgentWindowsUpdate.FailedCode,
                RebootRequired: false,
                Message: r.Error);
        }

        if (!r.Found)
        {
            return new BiosWuaInstallOutcome(
                Succeeded: false,
                ResultCode: -1,
                RebootRequired: false,
                Message: $"Windows Update no longer offers update {updateId:D}.");
        }

        if (r.ResultCode == -1)
        {
            return new BiosWuaInstallOutcome(
                Succeeded: false,
                ResultCode: r.DownloadResult,
                RebootRequired: false,
                Message: $"Windows Update download failed for {r.Title} (result code {r.DownloadResult}).");
        }

        if (r.Installed)
        {
            var msg = r.RebootRequired
                ? $"Installed {r.Title}. Reboot required."
                : $"Installed {r.Title}.";
            return new BiosWuaInstallOutcome(
                Succeeded: true,
                ResultCode: r.ResultCode,
                RebootRequired: r.RebootRequired,
                Message: msg);
        }

        return new BiosWuaInstallOutcome(
            Succeeded: false,
            ResultCode: r.ResultCode,
            RebootRequired: r.RebootRequired,
            Message: $"Windows Update install failed for {r.Title} (result={r.ResultCode}, hresult=0x{unchecked((uint)r.HResult):X8}).");
    }

    private static string? TryReadComString(Func<string?> getter)
    {
        try
        {
            var val = getter();
            return string.IsNullOrWhiteSpace(val) ? null : val.Trim();
        }
        catch
        {
            return null;
        }
    }

    private static DateOnly? TryReadComDate(Func<object?> getter)
    {
        try
        {
            var val = getter();
            if (val is DateTime dt && dt.Year >= 1990)
                return DateOnly.FromDateTime(dt);
            if (val is DateTimeOffset dto && dto.Year >= 1990)
                return DateOnly.FromDateTime(dto.UtcDateTime);
            return null;
        }
        catch
        {
            return null;
        }
    }

    private static long? TryReadComLong(Func<long> getter)
    {
        try
        {
            var val = getter();
            return val > 0 ? val : null;
        }
        catch
        {
            return null;
        }
    }

    private static bool? TryReadComBool(Func<bool> getter)
    {
        try
        {
            return getter();
        }
        catch
        {
            return null;
        }
    }

    private static BiosUpdateSeverity ParseMsrcSeverity(string? severity)
    {
        if (string.IsNullOrWhiteSpace(severity))
            return BiosUpdateSeverity.Recommended;

        var s = severity.Trim();
        if (s.Equals("Critical", StringComparison.OrdinalIgnoreCase))
            return BiosUpdateSeverity.Critical;
        if (s.Equals("Important", StringComparison.OrdinalIgnoreCase))
            return BiosUpdateSeverity.Recommended;
        if (s.Equals("Moderate", StringComparison.OrdinalIgnoreCase)
            || s.Equals("Low", StringComparison.OrdinalIgnoreCase))
            return BiosUpdateSeverity.Optional;

        return BiosUpdateSeverity.Recommended;
    }

    [SupportedOSPlatform("windows")]
    private static void SafeReleaseCom(object? comObj)
    {
        if (comObj is null)
            return;

        try
        {
            if (Marshal.IsComObject(comObj))
                Marshal.FinalReleaseComObject(comObj);
        }
        catch
        {
            // Best-effort COM RCW cleanup.
        }
    }
}
