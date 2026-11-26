using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Session;
using static RemotePCDiagnostics.Core.Bios.BiosProviderCommon;
using static RemotePCDiagnostics.Core.Bios.BiosProviderHttp;

namespace RemotePCDiagnostics.Core.Bios;

/// <summary>
/// Built-in Microsoft Surface UEFI/BIOS update provider (<c>VendorId = "microsoft"</c>).
/// Queries Microsoft Surface firmware/driver MSI metadata over HTTPS (100% pure C#, JSON and XML),
/// verifies integrity (SHA-256 / Authenticode), suspends BitLocker for one reboot when requested,
/// and stages updates silently via <c>msiexec.exe</c> (routing through <see cref="IElevatedCommandBridge"/>
/// when running un-elevated). Explicitly excludes Hyper-V virtual machines.
/// </summary>
public sealed partial class MicrosoftSurfaceBiosUpdateProvider : IBiosUpdateProvider
{
    public const string ProviderVendorId = "microsoft";
    public const string DefaultCatalogUrlTemplate =
        "https://www.microsoft.com/surface/api/firmware?model={model}&os={os}";

    public static readonly IReadOnlyList<string> AllowedHostSuffixes = ["microsoft.com"];

    public const long MaxCatalogBytes = 8L * 1024 * 1024;

    private static readonly TimeSpan DefaultInstallerTimeout = TimeSpan.FromMinutes(10);
    private static readonly HashSet<int> RebootSuccessExitCodes = [0, 3010];

    private static readonly string[] AlwaysRejectKeywords =
    [
        "recovery image",
        "diagnostic toolkit",
        "surface diagnostic",
        "surface app",
        "data eraser",
        "it toolkit",
        "deployment tool",
        "surface dock",
        "dock firmware",
        "dock updater",
        "type cover",
        "surface pen",
        "surface mouse",
        "surface headphones",
        "surface earbuds",
        "user guide",
        "manual",
    ];

    private static readonly string[] PeripheralKeywords =
    [
        "dock",
        "audio",
        "camera",
        "webcam",
        "bluetooth",
        "wlan",
        "wi-fi",
        "wifi",
        "lte modem",
        "lte driver",
        "lte firmware",
        "modem",
        "keyboard",
        "type cover",
        "pen",
        "mouse",
        "headphones",
        "earbuds",
        "monitor",
        "display",
        "usb hub",
        "adapter",
        "charger",
        "power supply",
    ];

    private static readonly HashSet<string> XmlReleaseElementNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Release",
        "Package",
        "Update",
        "UpdateInfo",
        "Firmware",
        "Msi",
        "Entry",
        "Item",
        "Download",
    };

    [GeneratedRegex(@"^(?:Microsoft\s+Surface\s+UEFI|Surface\s+UEFI|UEFI\s+Version|BIOS\s+Version|Firmware\s+Version|Version|Ver\.?|Rev\.?|UEFI|BIOS|v(?=\d|\s|[:\-]))\s*[:\-]?\s*", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex LeadingVersionPrefixRegex();

    [GeneratedRegex(@"^([0-9]+(?:\.[0-9]+){1,3})(?:\s*\([^)]*\))?$", RegexOptions.CultureInvariant)]
    private static partial Regex DottedWithOptionalNoteRegex();

    [GeneratedRegex(@"\b(?:beta|alpha|pre-?release|insider|preview|engineering\s+sample|test\s+(?:bios|firmware|uefi))\b", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex SurfaceBetaTokenRegex();

    [GeneratedRegex(@"\{(?:os|osVersion)\}", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex OsPlaceholderRegex();

    private readonly HttpClient _httpClient;
    private readonly SystemCommandRunner? _commands;
    private readonly IBiosSignatureVerifier _signatureVerifier;
    private readonly IElevatedCommandBridge? _elevatedBridge;
    private readonly Func<bool>? _isProcessElevated;
    private readonly ILogger? _log;
    private readonly string _catalogUrlTemplate;

    /// <summary>
    /// Creates a Microsoft Surface BIOS/UEFI update provider. All parameters are optional so MS.DI
    /// resolves this single constructor cleanly with zero extra service registrations.
    /// </summary>
    public MicrosoftSurfaceBiosUpdateProvider(
        HttpClient? httpClient = null,
        SystemCommandRunner? commands = null,
        IBiosSignatureVerifier? signatureVerifier = null,
        IElevatedCommandBridge? elevatedBridge = null,
        Func<bool>? isProcessElevated = null,
        ILogger? log = null,
        string? catalogUrlTemplate = null)
    {
        _httpClient = httpClient ?? BiosProviderHttp.SharedClient;
        _commands = commands;
        _signatureVerifier = signatureVerifier ?? WinVerifyTrustSignatureVerifier.Instance;
        _elevatedBridge = elevatedBridge;
        _isProcessElevated = isProcessElevated;
        _log = log;
        _catalogUrlTemplate = string.IsNullOrWhiteSpace(catalogUrlTemplate)
            ? DefaultCatalogUrlTemplate
            : catalogUrlTemplate.Trim();
    }

    /// <summary>Creates a provider backed by a custom <see cref="HttpMessageHandler"/> (e.g., for offline tests).</summary>
    public static MicrosoftSurfaceBiosUpdateProvider CreateWithHandler(
        HttpMessageHandler httpHandler,
        SystemCommandRunner? commands = null,
        IBiosSignatureVerifier? signatureVerifier = null,
        IElevatedCommandBridge? elevatedBridge = null,
        Func<bool>? isProcessElevated = null,
        ILogger? log = null,
        string? catalogUrlTemplate = null) =>
        new(
            BiosProviderHttp.CreateClient(httpHandler),
            commands,
            signatureVerifier,
            elevatedBridge,
            isProcessElevated,
            log,
            catalogUrlTemplate);

    public string VendorId => ProviderVendorId;
    public string DisplayName => "Microsoft Surface";
    public int Priority => 100;

    public BiosProviderCapabilities Capabilities { get; } = new(
        CanCheckLatest: true,
        CanInstall: true,
        SupportsSilentInstall: true,
        RequiresReboot: true,
        RequiresElevation: true,
        RequiresInternet: true);

    public bool CanHandle(BiosSystemIdentity system) =>
        system is not null && BiosVendorIdentity.IsMicrosoftSurface(system);

    public Task<BiosCurrentInfo> GetCurrentVersionAsync(BiosSystemIdentity system, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(system);
        ct.ThrowIfCancellationRequested();

        var current = system.CurrentBios ?? BiosCurrentInfo.Empty;
        var parsed = ParseSurfaceVersion(current.Version);
        var metadata = current.Metadata is not null
            ? new Dictionary<string, string>(current.Metadata, StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (!string.IsNullOrWhiteSpace(current.Version))
        {
            var rawTrimmed = current.Version.Trim();
            if (!string.Equals(rawTrimmed, parsed.NormalizedVersion, StringComparison.Ordinal))
                metadata["rawVersion"] = rawTrimmed;
        }

        if (TryResolveModelIdentifier(system, out var modelToken, out _))
            metadata["model"] = modelToken;

        if (!string.IsNullOrWhiteSpace(system.OsVersion))
            metadata["os"] = BiosVendorIdentity.IsWindows11(system.OsVersion) ? "win11" : "win10";

        var serial = system.SerialNumber;
        var safeVendor = RedactText(current.Vendor, serial);
        var safeVersion = RedactText(parsed.NormalizedVersion, serial);
        var safeReleaseDateRaw = RedactText(current.ReleaseDateRaw, serial);
        var safeSmbiosRevision = RedactText(current.SmbiosRevision, serial);
        var safeFamily = RedactText(current.Family, serial);
        var safeMetadata = RedactMetadata(metadata, serial);

        return Task.FromResult(current with
        {
            Vendor = safeVendor,
            Version = safeVersion,
            ReleaseDateRaw = safeReleaseDateRaw,
            SmbiosRevision = safeSmbiosRevision,
            Family = safeFamily,
            ProviderId = VendorId,
            Metadata = safeMetadata.Count > 0 ? safeMetadata : null,
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

        if (ContainsVirtualMachine(system.Model) || ContainsVirtualMachine(system.BoardProduct))
        {
            return RedactLatestInfo(
                BiosLatestInfo.Unsupported(
                    VendorId,
                    "Hyper-V virtual machines are not supported by the Microsoft Surface firmware provider."),
                serial);
        }

        if (!TryResolveModelIdentifier(system, out var modelToken, out var reason))
        {
            return RedactLatestInfo(
                BiosLatestInfo.Unsupported(
                    VendorId,
                    $"Unable to determine a valid Microsoft Surface model identifier: {reason}"),
                serial);
        }

        var isWin11 = BiosVendorIdentity.IsWindows11(system.OsVersion);
        var hasExplicitOs = !string.IsNullOrWhiteSpace(system.OsVersion);
        var osToken = isWin11 ? "win11" : "win10";

        var requestUrl = BuildCatalogUrl(_catalogUrlTemplate, modelToken, osToken);
        if (!TryValidateVendorUrl(requestUrl, AllowedHostSuffixes, out _))
        {
            LogWarn("Rejected disallowed Microsoft Surface catalog URL before request.", serial);
            return RedactLatestInfo(
                BiosLatestInfo.Failed(
                    VendorId,
                    "Microsoft Surface catalog URL failed HTTPS/domain allowlist validation."),
                serial);
        }

        try
        {
            using var response = await GetCatalogWithSafeRedirectsAsync(requestUrl, ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return RedactLatestInfo(
                    BiosProviderHttp.ClassifyHttpStatus(VendorId, DisplayName, response.StatusCode, $"model '{modelToken}'"),
                    serial);
            }

            var (payload, offset, length) = await ReadBoundedBytesAsync(response.Content, MaxCatalogBytes, ct).ConfigureAwait(false);
            var firstNonWs = FindFirstNonWhitespaceByte(payload, offset, length);
            if (firstNonWs < 0)
                throw new InvalidDataException("Microsoft Surface catalog response body is empty or whitespace.");

            var candidates = new List<SurfaceCatalogCandidate>();
            var untrusted = new List<SurfaceCatalogCandidate>();
            var sawAnyFirmwareEntry = false;
            var sawOnlyBeta = false;

            if (payload[firstNonWs] == (byte)'<')
            {
                var xmlText = Encoding.UTF8.GetString(payload, offset, length);
                var doc = BiosArchiveAndXml.ParseXmlSafe(xmlText);
                ExtractCandidatesFromXml(
                    doc,
                    modelToken,
                    isWin11,
                    hasExplicitOs,
                    system.Architecture,
                    serial,
                    candidates,
                    untrusted,
                    ref sawAnyFirmwareEntry,
                    ref sawOnlyBeta);
            }
            else if (payload[firstNonWs] is (byte)'{' or (byte)'[')
            {
                using var doc = JsonDocument.Parse(
                    new ReadOnlyMemory<byte>(payload, offset, length),
                    new JsonDocumentOptions
                    {
                        MaxDepth = 64,
                        CommentHandling = JsonCommentHandling.Disallow,
                        AllowTrailingCommas = false,
                    });
                ExtractCandidatesFromJson(
                    doc.RootElement,
                    modelToken,
                    isWin11,
                    hasExplicitOs,
                    system.Architecture,
                    serial,
                    candidates,
                    untrusted,
                    ref sawAnyFirmwareEntry,
                    ref sawOnlyBeta);
            }
            else
            {
                throw new InvalidDataException("Microsoft Surface catalog response was neither valid JSON nor XML.");
            }

            if (candidates.Count == 0)
            {
                if (untrusted.Count > 0)
                {
                    return RedactLatestInfo(
                        BiosLatestInfo.Failed(
                            VendorId,
                            $"Microsoft Surface firmware catalog for '{modelToken}' contained only untrusted or non-MSI download URLs."),
                        serial);
                }

                if (sawOnlyBeta && !sawAnyFirmwareEntry)
                {
                    return RedactLatestInfo(
                        BiosLatestInfo.Unsupported(
                            VendorId,
                            $"Only beta or pre-release Surface firmware entries were found for '{modelToken}'."),
                        serial);
                }

                return RedactLatestInfo(
                    BiosLatestInfo.Unsupported(
                        VendorId,
                        $"No Microsoft Surface firmware MSI release was found in the catalog for '{modelToken}'."),
                    serial);
            }

            var ordered = OrderCandidates(candidates);
            var best = ordered[0];

            var parsedCurrent = ParseSurfaceVersion(current.Version);
            var isNewer = IsCandidateNewer(parsedCurrent, current.ReleaseDate, best.ParsedVersion, best.ReleaseDate);

            // Fail closed if an untrusted candidate would outrank (or hide an update beyond) our best trusted candidate.
            if (untrusted.Count > 0)
            {
                foreach (var bad in untrusted)
                {
                    // Stale lower-preference OS fallback (e.g., Win10 untrusted entry on Win11)
                    // must not poison a healthy exact-OS release.
                    if (bad.OsPrefRank > best.OsPrefRank)
                        continue;

                    var untrustedOutranks = bad.OsPrefRank < best.OsPrefRank
                        || IsCandidateNewer(best.ParsedVersion, best.ReleaseDate, bad.ParsedVersion, bad.ReleaseDate);
                    if (!untrustedOutranks && !isNewer)
                    {
                        var cmpSame = CompareComparableVersions(bad.ParsedVersion, best.ParsedVersion);
                        if (cmpSame is null || cmpSame.Value >= 0)
                            untrustedOutranks = true;
                    }

                    if (untrustedOutranks)
                    {
                        LogWarn($"Rejected Surface catalog because a newer/competing release had an untrusted or non-MSI download URL for model '{modelToken}'.", serial);
                        return RedactLatestInfo(
                            BiosLatestInfo.Failed(
                                VendorId,
                                $"Microsoft Surface firmware catalog for '{modelToken}' contained an untrusted or non-MSI download URL for a competing release."),
                            serial);
                    }
                }
            }

            var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["model"] = modelToken,
                ["os"] = osToken,
                ["installMode"] = BiosAgentInstallModes.MicrosoftSurfaceMsi,
            };

            if (!string.IsNullOrWhiteSpace(best.DownloadUrl))
                metadata["msiFileName"] = BiosVendorIdentity.SanitizeFileName(best.DownloadUrl, "surface-firmware-update.msi");

            if (!isNewer)
            {
                return RedactLatestInfo(
                    BiosLatestInfo.UpToDate(
                        providerId: VendorId,
                        latestVersion: best.DisplayVersion,
                        releaseDate: best.ReleaseDate,
                        metadata: metadata),
                    serial);
            }

            return RedactLatestInfo(
                BiosLatestInfo.UpdateAvailable(
                    providerId: VendorId,
                    latestVersion: best.DisplayVersion,
                    releaseDate: best.ReleaseDate,
                    severity: best.Severity,
                    packageId: best.PackageId,
                    releaseSummary: best.ReleaseSummary,
                    releaseNotesUrl: best.ReleaseNotesUrl,
                    downloadUrl: best.DownloadUrl,
                    sha256: best.Sha256,
                    sizeBytes: best.SizeBytes,
                    requiresReboot: true,
                    metadata: metadata),
                serial);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            LogWarn($"Microsoft Surface BIOS catalog lookup failed: {ex.Message}", serial);
            return RedactLatestInfo(
                BiosProviderHttp.ClassifyHttpFailure(VendorId, DisplayName, ex, ct),
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

        var serial = request.System?.SerialNumber;
        var prev = request.Current?.Version is not null ? RedactText(request.Current.Version, serial) : null;
        var target = request.Target?.LatestVersion is not null ? RedactText(request.Target.LatestVersion, serial) : null;
        var redactingLog = _log is not null && !string.IsNullOrWhiteSpace(serial)
            ? new RedactingLogger(_log, serial)
            : _log;
        var redactingProgress = progress is not null && !string.IsNullOrWhiteSpace(serial)
            ? new RedactingProgress(progress, serial)
            : progress;

        if (request.Target is null || string.IsNullOrWhiteSpace(request.Target.DownloadUrl))
        {
            const string msg = "Microsoft Surface firmware update target does not specify a download URL.";
            redactingProgress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, msg));
            return BiosInstallResult.Failed(msg, prev, target);
        }

        if (!TryValidateVendorUrl(request.Target.DownloadUrl, AllowedHostSuffixes, out var downloadUri))
        {
            const string msg = "Microsoft Surface firmware download URL failed HTTPS/microsoft.com allowlist or path validation.";
            LogWarn(msg, serial);
            redactingProgress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, msg));
            return BiosInstallResult.Failed(msg, prev, target);
        }

        var urlExt = Path.GetExtension(downloadUri.AbsolutePath);
        if (!string.IsNullOrEmpty(urlExt) && !urlExt.Equals(".msi", StringComparison.OrdinalIgnoreCase))
        {
            const string msg = "Microsoft Surface firmware installer must be an .msi package.";
            LogWarn(msg, serial);
            redactingProgress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, msg));
            return BiosInstallResult.Failed(msg, prev, target);
        }

        string? autoStagingDir = null;
        var effectiveRequest = request;
        if (string.IsNullOrWhiteSpace(request.StagingDirectory))
        {
            autoStagingDir = Path.Combine(Path.GetTempPath(), $"rpd-bios-surface-{Guid.NewGuid():N}");
            effectiveRequest = request with { StagingDirectory = autoStagingDir };
        }
        else if (!ValidateStagingDirectorySafe(request.StagingDirectory, out var stagingErr))
        {
            var safeStagingErr = RedactText(stagingErr, serial);
            LogWarn(safeStagingErr, serial);
            redactingProgress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, safeStagingErr));
            return BiosInstallResult.Failed(safeStagingErr, prev, target);
        }

        var defaultFileName = BuildDefaultPackageFileName(request.Target.PackageId);
        var safeFileName = BuildSafePackageFileName(request.Target.DownloadUrl, defaultFileName, ".msi");
        var resolvedStagingDir = effectiveRequest.StagingDirectory!;
        var targetFilePath = Path.Combine(resolvedStagingDir, safeFileName);
        var targetPartPath = targetFilePath + ".part";
        if (IsSymlinkOrReparsePoint(targetFilePath)
            || IsSymlinkOrReparsePoint(targetPartPath)
            || Directory.Exists(targetFilePath))
        {
            const string symErr = "Target package staging file or .part path is a symbolic link, reparse point, or existing directory.";
            LogWarn(symErr, serial);
            redactingProgress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, symErr));
            return BiosInstallResult.Failed(symErr, prev, target);
        }

        try
        {
            var verified = await DownloadAndVerifySurfacePackageAsync(
                effectiveRequest,
                resolvedStagingDir,
                safeFileName,
                redactingProgress,
                redactingLog,
                ct).ConfigureAwait(false);

            if (!verified.Succeeded || string.IsNullOrWhiteSpace(verified.FilePath))
            {
                var err = RedactText(
                    verified.ErrorMessage ?? "Microsoft Surface firmware package download or verification failed.",
                    serial);
                redactingProgress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, err));
                return BiosInstallResult.Failed(err, prev, target);
            }

            if (!TryEnsureMsiExtension(verified.FilePath, out var packagePath, out var extError))
            {
                TryDeleteFile(verified.FilePath);
                var safeExtErr = RedactText(extError, serial);
                redactingProgress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, safeExtErr));
                return BiosInstallResult.Failed(safeExtErr, prev, target);
            }

            // Compute & normalize expectedSha256 BEFORE suspending BitLocker.
            var expectedSha256 = !string.IsNullOrWhiteSpace(verified.ActualSha256)
                ? verified.ActualSha256.Trim().ToLowerInvariant()
                : (await BiosPackageVerifier.ComputeSha256HexAsync(packagePath, ct).ConfigureAwait(false)).Trim().ToLowerInvariant();

            var bitLocker = await BiosBitLockerSuspender.SuspendForOneRebootWithResultAsync(
                effectiveRequest,
                _commands,
                redactingProgress,
                redactingLog,
                ct,
                bridge: _elevatedBridge,
                isProcessElevated: _isProcessElevated).ConfigureAwait(false);

            if (bitLocker.BlocksInstall)
            {
                var msg = RedactText(
                    bitLocker.Message
                    ?? $"Administrator rights (or the elevated Agent service) are required to suspend BitLocker. {ElevationService.AdminRepairHint}",
                    serial);
                redactingProgress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, msg));
                return BiosInstallResult.Failed(msg, prev, target, exitCode: SystemCommandRunner.AgentFailedExitCode);
            }

            var executablePath = SystemCommandRunner.SystemTool("msiexec.exe");
            var arguments = BiosAgentInstallModes.BuildArguments(
                BiosAgentInstallModes.MicrosoftSurfaceMsi,
                request.AllowReboot,
                packagePath);

            var agentRequest = new BiosAgentInstallRequest(
                VendorId: VendorId,
                InstallMode: BiosAgentInstallModes.MicrosoftSurfaceMsi,
                PackagePath: packagePath,
                ExpectedSha256: expectedSha256,
                AllowReboot: request.AllowReboot,
                InfRelativePath: null,
                TimeoutMs: (int)DefaultInstallerTimeout.TotalMilliseconds);

            var runnerRequest = effectiveRequest with
            {
                Current = (effectiveRequest.Current ?? BiosCurrentInfo.Empty) with { Version = prev ?? "" },
                Target = effectiveRequest.Target with { LatestVersion = target },
            };

            redactingProgress?.Report(new BiosInstallProgress(
                BiosInstallStage.Staging,
                0,
                "Staging Microsoft Surface firmware update…"));
            redactingProgress?.Report(new BiosInstallProgress(
                BiosInstallStage.Installing,
                50,
                "Running Microsoft Surface firmware MSI installer..."));

            var result = await BiosInstallerRunner.RunInstallerAsync(
                commands: _commands,
                executablePath: executablePath,
                arguments: arguments,
                request: runnerRequest,
                bitLockerSuspended: bitLocker.Suspended,
                rebootSuccessExitCodes: RebootSuccessExitCodes,
                completedSuccessExitCodes: null,
                timeout: DefaultInstallerTimeout,
                log: redactingLog,
                ct: ct,
                workingDirectory: Path.GetDirectoryName(packagePath),
                agentRequest: agentRequest,
                bridge: _elevatedBridge,
                isProcessElevated: _isProcessElevated).ConfigureAwait(false);

            result = RedactInstallResult(result, serial);

            if (result.Succeeded && result.RequiresReboot)
                redactingProgress?.Report(new BiosInstallProgress(BiosInstallStage.RebootRequired, 100, result.Message));
            else if (result.Succeeded)
                redactingProgress?.Report(new BiosInstallProgress(BiosInstallStage.Completed, 100, result.Message));
            else
                redactingProgress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, result.Message));

            return result;
        }
        finally
        {
            if (autoStagingDir is not null)
                TryDeleteDirectoryRecursive(autoStagingDir);
        }
    }

    // -------------------------------------------------------------------------
    // JSON & XML catalog extraction
    // -------------------------------------------------------------------------

    private void ExtractCandidatesFromJson(
        JsonElement root,
        string modelToken,
        bool isWin11,
        bool hasExplicitOs,
        string? systemArch,
        string? serialNumber,
        List<SurfaceCatalogCandidate> candidates,
        List<SurfaceCatalogCandidate> untrusted,
        ref bool sawAnyFirmwareEntry,
        ref bool sawOnlyBeta)
    {
        var items = new List<JsonElement>();
        CollectJsonReleaseObjects(root, items, depth: 0);

        foreach (var item in items)
        {
            if (item.ValueKind != JsonValueKind.Object)
                continue;

            var category = GetStringOrNumber(item, "category", "type", "packageType", "group");
            var title = GetStringOrNumber(item, "title", "name", "displayName", "packageName");
            var description = GetStringOrNumber(item, "description", "releaseSummary", "summary", "notes", "releaseNotes");

            if (!IsSurfaceFirmwareEntry(category, title, description))
                continue;

            if (!MatchesModelJson(item, modelToken))
                continue;

            if (!MatchesArchitecture(GetStringOrNumber(item, "architecture", "arch", "platform"), systemArch))
                continue;

            var osText = GetStringOrNumber(item, "os", "osVersion", "targetOs", "windowsVersion", "operatingSystem");
            if (!TryEvaluateOsPreference(osText, isWin11, hasExplicitOs, out var osPrefRank))
                continue;

            var rawVersion = GetStringOrNumber(
                item,
                "uefiVersion",
                "firmwareVersion",
                "biosVersion",
                "version",
                "msiVersion",
                "packageVersion");

            var isBeta = GetNullableBool(item, "isBeta", "beta", "isPreRelease", "preRelease");
            var isRelease = GetNullableBool(item, "isRelease", "stable");

            if (IsBetaRelease(rawVersion, title, description, isRelease, isBeta))
            {
                sawOnlyBeta = true;
                continue;
            }

            if (string.IsNullOrWhiteSpace(rawVersion))
                continue;

            sawAnyFirmwareEntry = true;

            var parsedVersion = ParseSurfaceVersion(rawVersion);
            if (parsedVersion.Class == VersionClass.Empty)
                continue;

            var urlState = TryExtractMsiDownloadUrlFromJson(item, out var downloadUrl);
            var releaseDate = TryParseReleaseDate(GetStringOrNumber(item, "releaseDate", "date", "publishedDate", "publishDate", "updated"));
            var sizeBytes = TryParseSizeBytes(item, "sizeBytes", "fileSize", "size", "downloadSize");
            var packageId = GetStringOrNumber(item, "packageId", "id", "downloadId", "kb", "releaseId", "msiName");
            var rawSha256 = GetStringOrNumber(item, "sha256", "sha256Hash", "checksum", "hash", "digest");
            var sha256 = TryNormalizeSha256(rawSha256);
            var rawSeverity = GetStringOrNumber(item, "severity", "criticality", "urgency", "priority");
            var isCritical = GetNullableBool(item, "isCritical", "critical", "security");
            var severity = ParseSeverity(rawSeverity, isCritical, title, description);
            var summary = CleanReleaseSummary(title, description);

            var rawNotesUrl = GetStringOrNumber(item, "releaseNotesUrl", "detailsUrl", "infoUrl", "kbUrl", "moreInfoUrl");
            string? notesUrl = null;
            if (!string.IsNullOrWhiteSpace(rawNotesUrl)
                && TryValidateVendorUrl(rawNotesUrl, AllowedHostSuffixes, out var parsedNotesUri))
            {
                notesUrl = parsedNotesUri.AbsoluteUri;
            }

            var candidate = new SurfaceCatalogCandidate(
                DisplayVersion: parsedVersion.DisplayVersion,
                ParsedVersion: parsedVersion,
                OsPrefRank: osPrefRank,
                ReleaseDate: releaseDate,
                Severity: severity,
                PackageId: packageId,
                ReleaseSummary: summary,
                ReleaseNotesUrl: notesUrl,
                DownloadUrl: downloadUrl,
                Sha256: sha256,
                SizeBytes: sizeBytes);

            if (urlState == UrlExtractionState.Valid)
            {
                candidates.Add(candidate);
            }
            else if (urlState == UrlExtractionState.Untrusted)
            {
                LogWarn($"Ignoring Microsoft Surface catalog entry '{parsedVersion.DisplayVersion}' with untrusted or non-MSI download URL.", serialNumber);
                untrusted.Add(candidate);
            }
        }
    }

    private static void CollectJsonReleaseObjects(JsonElement element, List<JsonElement> output, int depth)
    {
        if (depth > 8)
            return;

        if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.Object)
                    output.Add(item);
            }

            return;
        }

        if (element.ValueKind != JsonValueKind.Object)
            return;

        string[] multiReleaseKeys =
        [
            "releases", "packages", "updates", "items",
            "firmware", "downloads", "results", "data", "value",
        ];

        var foundCollection = false;
        foreach (var key in multiReleaseKeys)
        {
            if (TryGetPropertyIgnoreCase(element, out var child, key))
            {
                if (child.ValueKind == JsonValueKind.Array)
                {
                    foundCollection = true;
                    foreach (var item in child.EnumerateArray())
                    {
                        if (item.ValueKind == JsonValueKind.Object)
                            output.Add(item);
                    }
                }
                else if (child.ValueKind == JsonValueKind.Object)
                {
                    foundCollection = true;
                    CollectJsonReleaseObjects(child, output, depth + 1);
                }
            }
        }

        if (foundCollection)
            return;

        // Single release object at root (which may contain a nested "files" array for download URLs).
        if (TryGetPropertyIgnoreCase(element, out _, "uefiVersion", "firmwareVersion", "biosVersion", "version", "msiVersion", "packageVersion"))
        {
            output.Add(element);
            return;
        }

        if (TryGetPropertyIgnoreCase(element, out var filesChild, "files"))
        {
            if (filesChild.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in filesChild.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.Object)
                        output.Add(item);
                }

                return;
            }
            else if (filesChild.ValueKind == JsonValueKind.Object)
            {
                CollectJsonReleaseObjects(filesChild, output, depth + 1);
                if (output.Count > 0)
                    return;
            }
        }

        string[] wrapperKeys = ["result", "surface", "catalog", "product", "response"];
        foreach (var key in wrapperKeys)
        {
            if (TryGetPropertyIgnoreCase(element, out var child, key)
                && (child.ValueKind == JsonValueKind.Object || child.ValueKind == JsonValueKind.Array))
            {
                CollectJsonReleaseObjects(child, output, depth + 1);
                if (output.Count > 0)
                    return;
            }
        }
    }

    private UrlExtractionState TryExtractMsiDownloadUrlFromJson(JsonElement item, out string? validatedUrl)
    {
        validatedUrl = null;
        string[] explicitDownloadKeys = ["downloadUrl", "msiUrl", "packageUrl", "fileUrl", "downloadLink"];
        string[] fallbackUrlKeys = ["url", "link"];

        var sawUntrusted = false;
        foreach (var key in explicitDownloadKeys)
        {
            if (!TryGetPropertyIgnoreCase(item, out var prop, key))
                continue;

            var propState = TryExtractMsiUrlFromJsonProperty(prop, out var valid);
            if (propState == UrlExtractionState.Valid)
            {
                validatedUrl = valid;
                return UrlExtractionState.Valid;
            }

            if (propState == UrlExtractionState.Untrusted)
            {
                // Fail closed when an explicit download URL property is poisoned/untrusted
                // rather than silently falling back to a secondary "url" property.
                return UrlExtractionState.Untrusted;
            }
        }

        foreach (var key in fallbackUrlKeys)
        {
            if (!TryGetPropertyIgnoreCase(item, out var prop, key))
                continue;

            var propState = TryExtractMsiUrlFromJsonProperty(prop, out var valid);
            if (propState == UrlExtractionState.Valid)
            {
                validatedUrl = valid;
                return UrlExtractionState.Valid;
            }

            if (propState == UrlExtractionState.Untrusted)
                sawUntrusted = true;
        }

        if (TryGetPropertyIgnoreCase(item, out var filesEl, "files") && filesEl.ValueKind == JsonValueKind.Array)
        {
            foreach (var file in filesEl.EnumerateArray())
            {
                if (file.ValueKind != JsonValueKind.Object)
                    continue;

                var state = TryExtractMsiDownloadUrlFromJson(file, out var fileUrl);
                if (state == UrlExtractionState.Valid)
                {
                    validatedUrl = fileUrl;
                    return UrlExtractionState.Valid;
                }

                if (state == UrlExtractionState.Untrusted)
                    sawUntrusted = true;
            }
        }

        return sawUntrusted ? UrlExtractionState.Untrusted : UrlExtractionState.Absent;
    }

    private static UrlExtractionState TryExtractMsiUrlFromJsonProperty(JsonElement prop, out string? validatedUrl)
    {
        validatedUrl = null;
        if (prop.ValueKind == JsonValueKind.String)
        {
            var raw = prop.GetString()?.Trim();
            if (string.IsNullOrEmpty(raw))
                return UrlExtractionState.Absent;

            if (TryValidateMsiDownloadUrl(raw, out var valid))
            {
                validatedUrl = valid;
                return UrlExtractionState.Valid;
            }

            return UrlExtractionState.Untrusted;
        }

        if (prop.ValueKind == JsonValueKind.Object)
        {
            if (TryGetPropertyIgnoreCase(prop, out var nested, "url", "href", "downloadUrl", "msiUrl"))
            {
                if (nested.ValueKind == JsonValueKind.String)
                {
                    var raw = nested.GetString()?.Trim();
                    if (string.IsNullOrEmpty(raw))
                        return UrlExtractionState.Absent;

                    if (TryValidateMsiDownloadUrl(raw, out var valid))
                    {
                        validatedUrl = valid;
                        return UrlExtractionState.Valid;
                    }

                    return UrlExtractionState.Untrusted;
                }

                return UrlExtractionState.Untrusted;
            }

            return UrlExtractionState.Untrusted;
        }

        // Wrong JSON value kind on a non-null download URL field -> fail closed as untrusted.
        return UrlExtractionState.Untrusted;
    }

    private void ExtractCandidatesFromXml(
        XDocument doc,
        string modelToken,
        bool isWin11,
        bool hasExplicitOs,
        string? systemArch,
        string? serialNumber,
        List<SurfaceCatalogCandidate> candidates,
        List<SurfaceCatalogCandidate> untrusted,
        ref bool sawAnyFirmwareEntry,
        ref bool sawOnlyBeta)
    {
        if (doc.Root is null)
            return;

        var elements = doc.Root
            .DescendantsAndSelf()
            .Where(e => XmlReleaseElementNames.Contains(e.Name.LocalName))
            .ToList();

        foreach (var el in elements)
        {
            var rawVersion = GetXmlField(el, "uefiVersion", "firmwareVersion", "biosVersion", "version", "msiVersion", "packageVersion");
            if (string.IsNullOrWhiteSpace(rawVersion))
                continue;

            var category = GetXmlField(el, "category", "type", "packageType", "group");
            var title = GetXmlField(el, "title", "name", "displayName", "packageName");
            var description = GetXmlField(el, "description", "releaseSummary", "summary", "notes", "releaseNotes");

            if (!IsSurfaceFirmwareEntry(category, title, description))
                continue;

            if (!MatchesModelXml(el, modelToken))
                continue;

            if (!MatchesArchitecture(GetXmlField(el, "architecture", "arch", "platform"), systemArch))
                continue;

            var osText = GetXmlField(el, "os", "osVersion", "targetOs", "windowsVersion", "operatingSystem");
            if (!TryEvaluateOsPreference(osText, isWin11, hasExplicitOs, out var osPrefRank))
                continue;

            var isBeta = ParseNullableBoolString(GetXmlField(el, "isBeta", "beta", "isPreRelease", "preRelease"));
            var isRelease = ParseNullableBoolString(GetXmlField(el, "isRelease", "stable"));

            if (IsBetaRelease(rawVersion, title, description, isRelease, isBeta))
            {
                sawOnlyBeta = true;
                continue;
            }

            sawAnyFirmwareEntry = true;

            var parsedVersion = ParseSurfaceVersion(rawVersion);
            if (parsedVersion.Class == VersionClass.Empty)
                continue;

            var rawUrl = GetXmlField(el, "downloadUrl", "msiUrl", "packageUrl", "url", "fileUrl", "downloadLink", "link");
            var urlState = UrlExtractionState.Absent;
            string? downloadUrl = null;
            if (!string.IsNullOrWhiteSpace(rawUrl))
            {
                if (TryValidateMsiDownloadUrl(rawUrl, out var validUrl))
                {
                    downloadUrl = validUrl;
                    urlState = UrlExtractionState.Valid;
                }
                else
                {
                    urlState = UrlExtractionState.Untrusted;
                }
            }

            var releaseDate = TryParseReleaseDate(GetXmlField(el, "releaseDate", "date", "publishedDate", "publishDate", "updated"));
            var sizeBytes = TryParseSizeString(GetXmlField(el, "sizeBytes", "fileSize", "size", "downloadSize"));
            var packageId = GetXmlField(el, "packageId", "id", "downloadId", "kb", "releaseId", "msiName");
            var sha256 = TryNormalizeSha256(GetXmlField(el, "sha256", "sha256Hash", "checksum", "hash", "digest"));
            var rawSeverity = GetXmlField(el, "severity", "criticality", "urgency", "priority");
            var isCritical = ParseNullableBoolString(GetXmlField(el, "isCritical", "critical", "security"));
            var severity = ParseSeverity(rawSeverity, isCritical, title, description);
            var summary = CleanReleaseSummary(title, description);

            var rawNotesUrl = GetXmlField(el, "releaseNotesUrl", "detailsUrl", "infoUrl", "kbUrl", "moreInfoUrl");
            string? notesUrl = null;
            if (!string.IsNullOrWhiteSpace(rawNotesUrl)
                && TryValidateVendorUrl(rawNotesUrl, AllowedHostSuffixes, out var parsedNotesUri))
            {
                notesUrl = parsedNotesUri.AbsoluteUri;
            }

            var candidate = new SurfaceCatalogCandidate(
                DisplayVersion: parsedVersion.DisplayVersion,
                ParsedVersion: parsedVersion,
                OsPrefRank: osPrefRank,
                ReleaseDate: releaseDate,
                Severity: severity,
                PackageId: packageId,
                ReleaseSummary: summary,
                ReleaseNotesUrl: notesUrl,
                DownloadUrl: downloadUrl,
                Sha256: sha256,
                SizeBytes: sizeBytes);

            if (urlState == UrlExtractionState.Valid)
            {
                candidates.Add(candidate);
            }
            else if (urlState == UrlExtractionState.Untrusted)
            {
                LogWarn($"Ignoring Microsoft Surface XML catalog entry '{parsedVersion.DisplayVersion}' with untrusted or non-MSI download URL.", serialNumber);
                untrusted.Add(candidate);
            }
        }
    }

    private static string? GetXmlField(XElement el, params string[] names)
    {
        foreach (var name in names)
        {
            var child = el.Elements().FirstOrDefault(e => string.Equals(e.Name.LocalName, name, StringComparison.OrdinalIgnoreCase));
            if (child is not null && !string.IsNullOrWhiteSpace(child.Value))
                return child.Value.Trim();

            var attr = el.Attributes().FirstOrDefault(a => string.Equals(a.Name.LocalName, name, StringComparison.OrdinalIgnoreCase));
            if (attr is not null && !string.IsNullOrWhiteSpace(attr.Value))
                return attr.Value.Trim();
        }

        return null;
    }

    private static bool TryValidateMsiDownloadUrl(string rawUrl, out string validatedUrl)
    {
        validatedUrl = "";
        if (!TryValidateVendorUrl(rawUrl, AllowedHostSuffixes, out var uri))
            return false;

        if (!uri.AbsolutePath.EndsWith(".msi", StringComparison.OrdinalIgnoreCase))
            return false;

        validatedUrl = uri.AbsoluteUri;
        return true;
    }

    // -------------------------------------------------------------------------
    // Surface-aware filtering (model / OS / architecture / category)
    // -------------------------------------------------------------------------

    private static bool IsSurfaceFirmwareEntry(string? category, string? title, string? description)
    {
        var combined = $"{category} {title}".Trim();

        // Always-reject keywords apply across category, title, AND description before accepting explicitlyFirmware.
        if (combined.Length > 0 && ContainsAnyKeyword(combined, AlwaysRejectKeywords))
            return false;

        if (!string.IsNullOrWhiteSpace(description) && ContainsAnyKeyword(description, AlwaysRejectKeywords))
            return false;

        // Reject peripheral categories/titles (e.g. Pen, Dock, Audio, Camera, Bluetooth, Wi-Fi, USB Hub)
        // before accepting explicitlyFirmware so peripheral firmware packages are never selected.
        if (!string.IsNullOrWhiteSpace(category) && ContainsAnyKeyword(category, PeripheralKeywords))
            return false;

        if (!string.IsNullOrWhiteSpace(title) && ContainsAnyKeyword(title, PeripheralKeywords))
            return false;

        if (combined.Length == 0)
            return true;

        // Real Microsoft Surface firmware MSIs are officially titled "Surface ... Drivers and Firmware".
        var explicitlyFirmware =
            combined.Contains("firmware", StringComparison.OrdinalIgnoreCase)
            || combined.Contains("uefi", StringComparison.OrdinalIgnoreCase)
            || combined.Contains("bios", StringComparison.OrdinalIgnoreCase)
            || combined.Contains("drivers and firmware", StringComparison.OrdinalIgnoreCase);

        if (explicitlyFirmware)
            return true;

        if (!string.IsNullOrWhiteSpace(category))
        {
            if (MatchesKeywordPhrase(category, "driver")
                || MatchesKeywordPhrase(category, "drivers")
                || MatchesKeywordPhrase(category, "tool")
                || MatchesKeywordPhrase(category, "toolkit")
                || MatchesKeywordPhrase(category, "utility")
                || MatchesKeywordPhrase(category, "application"))
            {
                return false;
            }
        }

        return true;
    }

    private static bool MatchesModelJson(JsonElement item, string modelToken)
    {
        string[] keys = ["model", "models", "product", "products", "device", "devices", "surfaceModel"];
        var foundModelField = false;
        var normalizedTarget = NormalizeModelForMatch(modelToken);

        foreach (var key in keys)
        {
            if (!TryGetPropertyIgnoreCase(item, out var el, key))
                continue;

            if (el.ValueKind == JsonValueKind.String)
            {
                var val = el.GetString()?.Trim();
                if (string.IsNullOrEmpty(val))
                    continue;

                foundModelField = true;
                if (ModelsMatch(normalizedTarget, val))
                    return true;
            }
            else if (el.ValueKind == JsonValueKind.Array)
            {
                foreach (var entry in el.EnumerateArray())
                {
                    if (entry.ValueKind != JsonValueKind.String)
                        continue;

                    var val = entry.GetString()?.Trim();
                    if (string.IsNullOrEmpty(val))
                        continue;

                    foundModelField = true;
                    if (ModelsMatch(normalizedTarget, val))
                        return true;
                }
            }
        }

        return !foundModelField;
    }

    private static bool MatchesModelXml(XElement el, string modelToken)
    {
        string[] names = ["model", "models", "product", "products", "device", "surfaceModel"];
        var normalizedTarget = NormalizeModelForMatch(modelToken);
        var foundModelField = false;

        foreach (var name in names)
        {
            foreach (var child in el.Elements().Where(e => string.Equals(e.Name.LocalName, name, StringComparison.OrdinalIgnoreCase)))
            {
                if (child.HasElements)
                {
                    foreach (var sub in child.Elements())
                    {
                        var val = sub.Value?.Trim();
                        if (string.IsNullOrEmpty(val))
                            continue;

                        foundModelField = true;
                        if (ModelsMatch(normalizedTarget, val))
                            return true;
                    }
                }
                else
                {
                    var val = child.Value?.Trim();
                    if (string.IsNullOrEmpty(val))
                        continue;

                    foundModelField = true;
                    if (ModelsMatch(normalizedTarget, val))
                        return true;
                }
            }

            var attr = el.Attributes().FirstOrDefault(a => string.Equals(a.Name.LocalName, name, StringComparison.OrdinalIgnoreCase));
            if (attr is not null && !string.IsNullOrWhiteSpace(attr.Value))
            {
                foundModelField = true;
                if (ModelsMatch(normalizedTarget, attr.Value))
                    return true;
            }
        }

        return !foundModelField;
    }

    private static bool ModelsMatch(string normalizedTarget, string rawEntryModel)
    {
        var normalizedEntry = NormalizeModelForMatch(rawEntryModel);
        if (normalizedEntry.Length == 0)
            return false;

        return string.Equals(normalizedTarget, normalizedEntry, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeModelForMatch(string raw)
    {
        var sb = new StringBuilder(raw.Length);
        var prevSpace = true;
        foreach (var c in raw)
        {
            if (char.IsLetterOrDigit(c))
            {
                sb.Append(char.ToLowerInvariant(c));
                prevSpace = false;
            }
            else if (!prevSpace)
            {
                sb.Append(' ');
                prevSpace = true;
            }
        }

        return sb.ToString().Trim();
    }

    private static bool TryEvaluateOsPreference(string? osText, bool isWin11, bool hasExplicitOs, out int osPrefRank)
    {
        osPrefRank = 1;
        if (string.IsNullOrWhiteSpace(osText))
            return true;

        var s = osText.Trim();
        var mentionsWin11 = s.Contains("win11", StringComparison.OrdinalIgnoreCase)
                            || s.Contains("windows 11", StringComparison.OrdinalIgnoreCase)
                            || s.Contains("windows11", StringComparison.OrdinalIgnoreCase)
                            || BiosVendorIdentity.IsWindows11(s);
        var mentionsWin10 = s.Contains("win10", StringComparison.OrdinalIgnoreCase)
                            || s.Contains("windows 10", StringComparison.OrdinalIgnoreCase)
                            || s.Contains("windows10", StringComparison.OrdinalIgnoreCase);

        if (mentionsWin11 && mentionsWin10)
        {
            osPrefRank = 1;
            return true;
        }

        if (mentionsWin11)
        {
            if (!isWin11 && hasExplicitOs)
                return false; // Skip Win11-only MSI on an explicit Win10 system.

            osPrefRank = isWin11 ? 0 : 1;
            return true;
        }

        if (mentionsWin10)
        {
            osPrefRank = isWin11 ? 2 : 0;
            return true;
        }

        osPrefRank = 1;
        return true;
    }

    private static bool MatchesArchitecture(string? entryArch, string? systemArch)
    {
        if (string.IsNullOrWhiteSpace(entryArch) || string.IsNullOrWhiteSpace(systemArch))
            return true;

        var normEntry = NormalizeArch(entryArch);
        var normSystem = NormalizeArch(systemArch);
        if (normEntry.Length == 0 || normSystem.Length == 0)
            return true;

        return string.Equals(normEntry, normSystem, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeArch(string raw)
    {
        var t = raw.Trim().ToLowerInvariant();
        if (t is "x64" or "amd64" or "x86_64" or "x86-64" or "intel64" or "64-bit" or "64bit")
            return "x64";
        if (t is "arm64" or "aarch64" or "arm64ec")
            return "arm64";
        if (t is "x86" or "i386" or "i686" or "32-bit" or "32bit")
            return "x86";
        return "";
    }

    // -------------------------------------------------------------------------
    // Version parsing, comparison & Strict Weak Ordering (SWO)
    // -------------------------------------------------------------------------

    internal static SurfaceParsedVersion ParseSurfaceVersion(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return new("", "", VersionClass.Empty, "0:", [], "");

        var cleaned = raw.Trim();
        for (var i = 0; i < 3; i++)
        {
            var stripped = LeadingVersionPrefixRegex().Replace(cleaned, "").Trim();
            if (string.Equals(stripped, cleaned, StringComparison.Ordinal))
                break;
            cleaned = stripped;
        }

        var noteMatch = DottedWithOptionalNoteRegex().Match(cleaned);
        if (noteMatch.Success)
            cleaned = noteMatch.Groups[1].Value;

        var (cls, classKey, segments) = ClassifyGenericVersion(cleaned);
        return new SurfaceParsedVersion(
            NormalizedVersion: cleaned,
            DisplayVersion: cleaned,
            Class: cls,
            ClassKey: classKey,
            Segments: segments,
            RawNormalized: cleaned);
    }

    private static int? CompareComparableVersions(SurfaceParsedVersion a, SurfaceParsedVersion b)
    {
        if (a.Class == VersionClass.Empty || b.Class == VersionClass.Empty)
            return null;

        if (!StringComparer.OrdinalIgnoreCase.Equals(a.ClassKey, b.ClassKey))
            return null;

        return CompareWithinClass(a, b);
    }

    private static int CompareWithinClass(SurfaceParsedVersion a, SurfaceParsedVersion b)
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

    private static bool IsCandidateNewer(
        SurfaceParsedVersion current,
        DateOnly? currentDate,
        SurfaceParsedVersion candidate,
        DateOnly? candidateDate)
    {
        var cmp = CompareComparableVersions(current, candidate);
        if (cmp.HasValue)
            return cmp.Value < 0;

        if (candidateDate.HasValue && currentDate.HasValue)
            return candidateDate.Value > currentDate.Value;

        if (current.Class == VersionClass.Empty && candidate.Class != VersionClass.Empty)
            return true;

        return false;
    }

    internal static List<SurfaceCatalogCandidate> OrderCandidates(IReadOnlyList<SurfaceCatalogCandidate> candidates) =>
        BiosProviderCommon.OrderCandidates(
            candidates,
            getPrefRank: static c => c.OsPrefRank,
            getClassKey: static c => c.ParsedVersion.ClassKey,
            getReleaseDate: static c => c.ReleaseDate,
            compareWithinClass: static (a, b) => CompareWithinClass(a.ParsedVersion, b.ParsedVersion),
            compareTieBreakers: static (a, b) => CompareCandidateTieBreakers(
                a.ReleaseDate, b.ReleaseDate,
                a.DisplayVersion, b.DisplayVersion,
                a.DownloadUrl, b.DownloadUrl,
                a.PackageId, b.PackageId,
                a.Sha256, b.Sha256,
                a.ReleaseNotesUrl, b.ReleaseNotesUrl,
                a.ReleaseSummary, b.ReleaseSummary,
                a.SizeBytes, b.SizeBytes,
                a.Severity, b.Severity),
            comparePrefRankFirst: true,
            prefRankDescending: false);

    private static (VersionClass Class, string ClassKey, long[] Segments) ClassifyGenericVersion(string normalized)
    {
        if (string.IsNullOrWhiteSpace(normalized))
            return (VersionClass.Empty, "0:", []);

        if (IsDottedNumeric(normalized) && TryParseDottedInt64(normalized, out var numSegs))
            return (VersionClass.Numeric, "1:NUM", numSegs);

        var prefixMatch = PrefixNumericRegex().Match(normalized);
        if (prefixMatch.Success && TryParseDottedInt64(prefixMatch.Groups[2].Value, out var pfxSegs))
            return (VersionClass.PrefixNumeric, "2:PFX:" + prefixMatch.Groups[1].Value, pfxSegs);

        var digitMatches = DigitRunsRegex().Matches(normalized);
        if (digitMatches.Count > 0)
        {
            var runs = new long[digitMatches.Count];
            var allFit = true;
            for (var i = 0; i < digitMatches.Count; i++)
            {
                if (!long.TryParse(digitMatches[i].Value, NumberStyles.None, CultureInfo.InvariantCulture, out runs[i]))
                {
                    allFit = false;
                    break;
                }
            }

            if (allFit)
            {
                var skeleton = BuildBijectiveSkeleton(normalized);
                return (VersionClass.Skeleton, $"3:SKEL:{runs.Length}:{skeleton}", runs);
            }
        }

        return (VersionClass.Literal, "4:LIT:" + normalized, []);
    }

    private static bool ContainsVirtualMachine(string? text) =>
        !string.IsNullOrWhiteSpace(text)
        && text.Contains("Virtual Machine", StringComparison.OrdinalIgnoreCase);

    private static string BuildCatalogUrl(string template, string modelToken, string osToken)
    {
        var escapedOs = Uri.EscapeDataString(osToken);
        var url = OsPlaceholderRegex().Replace(template, escapedOs);
        return BiosProviderCommon.BuildCatalogUrl(url, modelToken);
    }

    private Task<HttpResponseMessage> GetCatalogWithSafeRedirectsAsync(string initialUrl, CancellationToken ct) =>
        GetVendorUrlWithSafeRedirectsAsync(
            _httpClient,
            initialUrl,
            AllowedHostSuffixes,
            DisplayName,
            acceptHeader: "application/json, application/xml, text/xml;q=0.9",
            ct);

    private static async Task<(byte[] Buffer, int Offset, int Length)> ReadBoundedBytesAsync(
        HttpContent content,
        long maxBytes,
        CancellationToken ct)
    {
        var bytes = await BiosProviderHttp.ReadBoundedBytesAsync(
            content, maxBytes, "Microsoft Surface catalog response", ct).ConfigureAwait(false);
        if (bytes.Length == 0)
            throw new InvalidDataException("Microsoft Surface catalog response body is empty.");

        var offset = 0;
        var length = bytes.Length;
        if (length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
        {
            offset = 3;
            length -= 3;
        }

        return (bytes, offset, length);
    }

    private Task<BiosVerifiedPackageResult> DownloadAndVerifySurfacePackageAsync(
        BiosInstallRequest request,
        string stagingDir,
        string fileName,
        IProgress<BiosInstallProgress>? progress,
        ILogger? log,
        CancellationToken ct,
        long maxBytes = DefaultMaxDownloadBytes) =>
        DownloadAndVerifyVendorPackageAsync(
            VendorId,
            _signatureVerifier,
            GetPackageWithSafeRedirectsAsync,
            request,
            stagingDir,
            fileName,
            progress,
            log,
            ct,
            maxBytes);

    private Task<HttpResponseMessage> GetPackageWithSafeRedirectsAsync(string initialUrl, CancellationToken ct) =>
        GetVendorUrlWithSafeRedirectsAsync(
            _httpClient,
            initialUrl,
            AllowedHostSuffixes,
            DisplayName,
            acceptHeader: null,
            ct,
            disallowedUrlMessage: "Disallowed Microsoft Surface package URL.",
            validateUri: static (uri, isRedirect) =>
            {
                var ext = Path.GetExtension(uri.AbsolutePath);
                if (!string.IsNullOrEmpty(ext) && !ext.Equals(".msi", StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException(isRedirect
                        ? "Rejected redirect target: Microsoft Surface firmware installer must be an .msi package."
                        : "Microsoft Surface firmware installer must be an .msi package.");
                }
            });

    private static bool IsSymlinkOrReparsePoint(string path) => IsSymlinkOrReparsePath(path);

    private static bool IsBetaRelease(string? version, string? title, string? description, bool? isReleaseFlag, bool? isBetaFlag) =>
        BiosProviderCommon.IsBetaRelease(version, title, description, isReleaseFlag, isBetaFlag, SurfaceBetaTokenRegex());

    private static string BuildDefaultPackageFileName(string? packageId)
    {
        if (!string.IsNullOrWhiteSpace(packageId))
        {
            var sanitized = BiosVendorIdentity.SanitizeFileName(packageId, "surface-firmware-update");
            if (!sanitized.EndsWith(".msi", StringComparison.OrdinalIgnoreCase))
            {
                var ext = Path.GetExtension(sanitized);
                if (string.IsNullOrEmpty(ext))
                    sanitized += ".msi";
                else
                    sanitized = "surface-firmware-update.msi";
            }

            return sanitized;
        }

        return "surface-firmware-update.msi";
    }

    private static bool TryEnsureMsiExtension(string filePath, out string msiPath, out string error)
    {
        msiPath = "";
        error = "";

        if (string.IsNullOrWhiteSpace(filePath))
        {
            error = "Downloaded Microsoft Surface package path is empty.";
            return false;
        }

        var ext = Path.GetExtension(filePath);
        if (ext.Equals(".msi", StringComparison.OrdinalIgnoreCase))
        {
            msiPath = filePath;
            return true;
        }

        if (string.IsNullOrEmpty(ext))
        {
            var candidate = filePath + ".msi";
            if (IsSymlinkOrReparsePath(candidate) || Directory.Exists(candidate))
            {
                error = $"Target Microsoft Surface package path '{Path.GetFileName(candidate)}' conflicts with an unsafe link or existing directory.";
                return false;
            }

            try
            {
                File.Move(filePath, candidate, overwrite: true);
                msiPath = candidate;
                return true;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                error = $"Failed to stage Microsoft Surface MSI package with .msi extension: {ex.Message}";
                return false;
            }
        }

        error = $"Microsoft Surface firmware installer must have a .msi extension (got '{ext}').";
        return false;
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

    internal sealed record SurfaceParsedVersion(
        string NormalizedVersion,
        string DisplayVersion,
        VersionClass Class,
        string ClassKey,
        long[] Segments,
        string RawNormalized);

    internal sealed record SurfaceCatalogCandidate(
        string DisplayVersion,
        SurfaceParsedVersion ParsedVersion,
        int OsPrefRank,
        DateOnly? ReleaseDate,
        BiosUpdateSeverity Severity,
        string? PackageId,
        string? ReleaseSummary,
        string? ReleaseNotesUrl,
        string? DownloadUrl,
        string? Sha256,
        long? SizeBytes);
}
