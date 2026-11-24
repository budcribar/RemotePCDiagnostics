using System.Buffers;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Session;

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
    private const int MaxInitialStreamCapacity = 256 * 1024;
    private const int ReadBufferSize = 81920;
    private const int MaxSummaryLength = 1000;

    private static readonly TimeSpan DefaultInstallerTimeout = TimeSpan.FromMinutes(10);
    private static readonly HashSet<int> RebootSuccessExitCodes = [0, 3010];
    private static readonly IEqualityComparer<(int OsPrefRank, string ClassKey)> BucketKeyComparer = new BucketKeyEqualityComparer();

    private static readonly HashSet<string> PlaceholderTokens = new(StringComparer.OrdinalIgnoreCase)
    {
        "To Be Filled By O.E.M.",
        "To Be Filled By OEM",
        "To Be Filled By O.E.M",
        "System Product Name",
        "Default string",
        "Default",
        "All Series",
        "Not Applicable",
        "Not Specified",
        "Not Available",
        "Not Present",
        "Not Set",
        "None",
        "Null",
        "N/A",
        "NA",
        "Unknown",
        "Undefined",
        "TBD",
        "Empty",
        "SKU",
        "SKU Number",
        "OEM",
        "Standard",
        "Generic",
        "Type1ProductConfigId",
        "System Version",
        "System Manufacturer",
        "System Serial Number",
        "Chassis Version",
        "Base Board Product Name",
        "BaseBoard Product Name",
        "Board Product",
        "0",
        "0000",
        "XXXX",
    };

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

    [GeneratedRegex(@"\A[0-9A-Fa-f]{64}\z", RegexOptions.CultureInvariant)]
    private static partial Regex Sha256Regex();

    [GeneratedRegex(@"^(?:Microsoft\s+Surface\s+UEFI|Surface\s+UEFI|UEFI\s+Version|BIOS\s+Version|Firmware\s+Version|Version|Ver\.?|Rev\.?|UEFI|BIOS|v(?=\d|\s|[:\-]))\s*[:\-]?\s*", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex LeadingVersionPrefixRegex();

    [GeneratedRegex(@"^([0-9]+(?:\.[0-9]+){1,3})(?:\s*\([^)]*\))?$", RegexOptions.CultureInvariant)]
    private static partial Regex DottedWithOptionalNoteRegex();

    [GeneratedRegex(@"\b(?:beta|alpha|pre-?release|insider|preview|engineering\s+sample|test\s+(?:bios|firmware|uefi))\b", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex BetaTokenRegex();

    [GeneratedRegex(@"\A[1-9]\d{0,2}(?:,\d{3})+\z", RegexOptions.CultureInvariant)]
    private static partial Regex ThousandsGroupedIntRegex();

    [GeneratedRegex(@"^\s*([1-9][0-9]{0,2}(?:,[0-9]{3})+(?:\.[0-9]+)?|[0-9]+(?:[.,][0-9]+)?)\s*(bytes?|b|kbytes?|kb|kib|mbytes?|mb|mib|gbytes?|gb|gib)\s*$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex HumanSizeRegex();

    [GeneratedRegex(@"<br\s*/?>", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex HtmlBreakRegex();

    [GeneratedRegex(@"<[^>]+>", RegexOptions.CultureInvariant)]
    private static partial Regex HtmlTagRegex();

    [GeneratedRegex(@"\s+", RegexOptions.CultureInvariant)]
    private static partial Regex WhitespaceRegex();

    [GeneratedRegex(@"^([A-Za-z]+)[\.\-\s_]*(\d+(?:\.\d+)*)$", RegexOptions.CultureInvariant)]
    private static partial Regex PrefixNumericRegex();

    [GeneratedRegex(@"\d+", RegexOptions.CultureInvariant)]
    private static partial Regex DigitRunsRegex();

    [GeneratedRegex(@"\{(?:model|product|board)\}", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex ModelPlaceholderRegex();

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
                $"Staging Microsoft Surface firmware update {target ?? "package"}..."));
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

    internal static List<SurfaceCatalogCandidate> OrderCandidates(IReadOnlyList<SurfaceCatalogCandidate> candidates)
    {
        var bucketMaxDates = new Dictionary<(int OsPrefRank, string ClassKey), DateOnly?>(BucketKeyComparer);

        foreach (var candidate in candidates)
        {
            var bucketKey = (candidate.OsPrefRank, candidate.ParsedVersion.ClassKey);
            if (!bucketMaxDates.TryGetValue(bucketKey, out var existingMax)
                || (candidate.ReleaseDate.HasValue && (!existingMax.HasValue || candidate.ReleaseDate.Value > existingMax.Value)))
            {
                bucketMaxDates[bucketKey] = candidate.ReleaseDate;
            }
        }

        var ordered = new List<SurfaceCatalogCandidate>(candidates);
        ordered.Sort((a, b) =>
        {
            var osCmp = a.OsPrefRank.CompareTo(b.OsPrefRank);
            if (osCmp != 0)
                return osCmp;

            var bucketDateCmp = CompareNullableDateDescending(
                bucketMaxDates[(a.OsPrefRank, a.ParsedVersion.ClassKey)],
                bucketMaxDates[(b.OsPrefRank, b.ParsedVersion.ClassKey)]);
            if (bucketDateCmp != 0)
                return bucketDateCmp;

            var classCmp = StringComparer.OrdinalIgnoreCase.Compare(a.ParsedVersion.ClassKey, b.ParsedVersion.ClassKey);
            if (classCmp != 0)
                return classCmp;

            var verCmp = CompareWithinClass(b.ParsedVersion, a.ParsedVersion);
            if (verCmp != 0)
                return verCmp;

            var dateCmp = CompareNullableDateDescending(a.ReleaseDate, b.ReleaseDate);
            if (dateCmp != 0)
                return dateCmp;

            var rawCmp = StringComparer.OrdinalIgnoreCase.Compare(a.DisplayVersion, b.DisplayVersion);
            if (rawCmp != 0)
                return rawCmp;

            rawCmp = StringComparer.Ordinal.Compare(a.DisplayVersion, b.DisplayVersion);
            if (rawCmp != 0)
                return rawCmp;

            var aHasUrl = !string.IsNullOrEmpty(a.DownloadUrl);
            var bHasUrl = !string.IsNullOrEmpty(b.DownloadUrl);
            if (aHasUrl != bHasUrl)
                return bHasUrl.CompareTo(aHasUrl);

            var urlCmp = StringComparer.OrdinalIgnoreCase.Compare(a.DownloadUrl ?? "", b.DownloadUrl ?? "");
            if (urlCmp != 0)
                return urlCmp;

            urlCmp = StringComparer.Ordinal.Compare(a.DownloadUrl ?? "", b.DownloadUrl ?? "");
            if (urlCmp != 0)
                return urlCmp;

            var pkgCmp = StringComparer.OrdinalIgnoreCase.Compare(a.PackageId ?? "", b.PackageId ?? "");
            if (pkgCmp != 0)
                return pkgCmp;

            pkgCmp = StringComparer.Ordinal.Compare(a.PackageId ?? "", b.PackageId ?? "");
            if (pkgCmp != 0)
                return pkgCmp;

            var shaCmp = StringComparer.OrdinalIgnoreCase.Compare(a.Sha256 ?? "", b.Sha256 ?? "");
            if (shaCmp != 0)
                return shaCmp;

            shaCmp = StringComparer.Ordinal.Compare(a.Sha256 ?? "", b.Sha256 ?? "");
            if (shaCmp != 0)
                return shaCmp;

            var notesCmp = StringComparer.OrdinalIgnoreCase.Compare(a.ReleaseNotesUrl ?? "", b.ReleaseNotesUrl ?? "");
            if (notesCmp != 0)
                return notesCmp;

            notesCmp = StringComparer.Ordinal.Compare(a.ReleaseNotesUrl ?? "", b.ReleaseNotesUrl ?? "");
            if (notesCmp != 0)
                return notesCmp;

            var summaryCmp = StringComparer.Ordinal.Compare(a.ReleaseSummary ?? "", b.ReleaseSummary ?? "");
            if (summaryCmp != 0)
                return summaryCmp;

            var sizeCmp = CompareNullableLongDescending(a.SizeBytes, b.SizeBytes);
            if (sizeCmp != 0)
                return sizeCmp;

            return b.Severity.CompareTo(a.Severity);
        });

        return ordered;
    }

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

    private static string BuildBijectiveSkeleton(string value)
    {
        var sb = new StringBuilder(value.Length + 8);
        var inDigits = false;
        foreach (var c in value)
        {
            if (char.IsAsciiDigit(c))
            {
                if (!inDigits)
                {
                    sb.Append('#');
                    inDigits = true;
                }
            }
            else
            {
                inDigits = false;
                if (c == '\\')
                    sb.Append(@"\\");
                else if (c == '#')
                    sb.Append(@"\#");
                else
                    sb.Append(c);
            }
        }

        return sb.ToString();
    }

    private static bool IsDottedNumeric(string value)
    {
        var parts = value.Split('.');
        return parts.Length > 0 && parts.All(p => p.Length > 0 && p.All(char.IsAsciiDigit));
    }

    private static bool TryParseDottedInt64(string dotted, out long[] segments)
    {
        var parts = dotted.Split('.');
        segments = new long[parts.Length];
        for (var i = 0; i < parts.Length; i++)
        {
            if (!long.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out segments[i]))
            {
                segments = [];
                return false;
            }
        }

        return true;
    }

    private static int CompareNumericSegmentArrays(long[] a, long[] b)
    {
        var len = Math.Max(a.Length, b.Length);
        for (var i = 0; i < len; i++)
        {
            var av = i < a.Length ? a[i] : 0L;
            var bv = i < b.Length ? b[i] : 0L;
            if (av != bv)
                return av.CompareTo(bv);
        }

        return 0;
    }

    private static int CompareFixedLengthArrays(long[] a, long[] b)
    {
        var len = Math.Min(a.Length, b.Length);
        for (var i = 0; i < len; i++)
        {
            if (a[i] != b[i])
                return a[i].CompareTo(b[i]);
        }

        return a.Length.CompareTo(b.Length);
    }

    private static int CompareNullableDateDescending(DateOnly? a, DateOnly? b)
    {
        if (a.HasValue && b.HasValue)
            return b.Value.CompareTo(a.Value);
        if (b.HasValue)
            return 1;
        if (a.HasValue)
            return -1;
        return 0;
    }

    private static int CompareNullableLongDescending(long? a, long? b)
    {
        if (a.HasValue && b.HasValue)
            return b.Value.CompareTo(a.Value);
        if (b.HasValue)
            return 1;
        if (a.HasValue)
            return -1;
        return 0;
    }

    // -------------------------------------------------------------------------
    // SMBIOS token validation & URL / redirect security
    // -------------------------------------------------------------------------

    private static bool ContainsVirtualMachine(string? text) =>
        !string.IsNullOrWhiteSpace(text)
        && text.Contains("Virtual Machine", StringComparison.OrdinalIgnoreCase);

    private static bool TryResolveModelIdentifier(BiosSystemIdentity system, out string resolved, out string reason)
    {
        resolved = "";
        reason = "";

        var modelStatus = ClassifyModelToken(system.Model, out var modelToken);
        var boardStatus = ClassifyModelToken(system.BoardProduct, out var boardToken);

        if (modelStatus == SmbiosTokenStatus.InvalidUnsafe)
        {
            reason = "SMBIOS Model contains disallowed characters.";
            return false;
        }

        if (boardStatus == SmbiosTokenStatus.InvalidUnsafe)
        {
            reason = "SMBIOS BoardProduct contains disallowed characters.";
            return false;
        }

        if (modelStatus == SmbiosTokenStatus.Valid)
        {
            resolved = modelToken;
            return true;
        }

        if (boardStatus == SmbiosTokenStatus.Valid)
        {
            resolved = boardToken;
            return true;
        }

        reason = "SMBIOS Model and BoardProduct are empty or OEM placeholders.";
        return false;
    }

    private static SmbiosTokenStatus ClassifyModelToken(string? raw, out string token)
    {
        token = "";
        if (string.IsNullOrWhiteSpace(raw))
            return SmbiosTokenStatus.EmptyOrPlaceholder;

        var trimmed = raw.Trim();
        if (PlaceholderTokens.Contains(trimmed))
            return SmbiosTokenStatus.EmptyOrPlaceholder;

        if (trimmed.Contains("..", StringComparison.Ordinal))
            return SmbiosTokenStatus.InvalidUnsafe;

        if (!HasAnyAsciiLetterOrDigit(trimmed))
        {
            foreach (var c in trimmed)
            {
                if (c is not (' ' or '-' or '_' or '.' or '/'))
                    return SmbiosTokenStatus.InvalidUnsafe;
            }

            return SmbiosTokenStatus.EmptyOrPlaceholder;
        }

        if (!BiosVendorIdentity.TrySanitizeModelToken(trimmed, out var sanitized))
            return SmbiosTokenStatus.InvalidUnsafe;

        if (sanitized.Contains("to be filled", StringComparison.OrdinalIgnoreCase))
            return SmbiosTokenStatus.EmptyOrPlaceholder;

        token = sanitized;
        return SmbiosTokenStatus.Valid;
    }

    private static bool HasAnyAsciiLetterOrDigit(string value)
    {
        foreach (var c in value)
        {
            if (char.IsAsciiLetterOrDigit(c))
                return true;
        }

        return false;
    }

    private static string BuildCatalogUrl(string template, string modelToken, string osToken)
    {
        var escapedModel = Uri.EscapeDataString(modelToken);
        var escapedOs = Uri.EscapeDataString(osToken);

        var url = OsPlaceholderRegex().Replace(template, escapedOs);
        if (ModelPlaceholderRegex().IsMatch(url))
            return ModelPlaceholderRegex().Replace(url, escapedModel);

        var fragIdx = url.IndexOf('#');
        var basePart = fragIdx >= 0 ? url[..fragIdx] : url;
        var sep = basePart.Contains('?', StringComparison.Ordinal) ? "&" : "?";
        return $"{basePart}{sep}model={escapedModel}";
    }

    private async Task<HttpResponseMessage> GetCatalogWithSafeRedirectsAsync(string initialUrl, CancellationToken ct)
    {
        if (!TryValidateVendorUrl(initialUrl, AllowedHostSuffixes, out var current))
            throw new InvalidOperationException("Disallowed Microsoft Surface catalog URL.");

        var visited = new HashSet<string>(StringComparer.Ordinal) { current.AbsoluteUri };
        const int maxRedirects = BiosProviderHttp.DefaultMaxRedirects;

        for (var hop = 0; hop <= maxRedirects; hop++)
        {
            ct.ThrowIfCancellationRequested();

            using var request = new HttpRequestMessage(HttpMethod.Get, current);
            request.Headers.Accept.ParseAdd("application/json, application/xml;q=0.9, text/xml;q=0.8");

            var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            if ((int)response.StatusCode is not (301 or 302 or 303 or 307 or 308))
            {
                if (response.RequestMessage?.RequestUri is { } finalUri
                    && (!finalUri.IsAbsoluteUri
                        || !TryValidateVendorUrl(finalUri.AbsoluteUri, AllowedHostSuffixes, out _)
                        || (!string.IsNullOrWhiteSpace(finalUri.OriginalString)
                            && !TryValidateVendorUrl(finalUri.OriginalString, AllowedHostSuffixes, out _))))
                {
                    response.Dispose();
                    throw new InvalidOperationException("Rejected redirect target: final response URL failed vendor HTTPS/domain/path validation.");
                }

                return response;
            }

            string? rawNonValidated = null;
            if (response.Headers.NonValidated.TryGetValues("Location", out var rawLocs))
            {
                var count = 0;
                foreach (var val in rawLocs)
                {
                    count++;
                    if (count > 1)
                    {
                        response.Dispose();
                        throw new InvalidOperationException("Rejected ambiguous redirect with multiple Location headers.");
                    }

                    rawNonValidated = val;
                }
            }

            var locationUri = response.Headers.Location;
            response.Dispose();

            if (hop == maxRedirects)
                throw new InvalidOperationException($"Exceeded maximum redirect limit ({maxRedirects}).");

            if (!TryResolveSafeRedirectTarget(current, rawNonValidated, locationUri, out var nextUri))
                throw new InvalidOperationException("Rejected redirect target: failed vendor HTTPS/domain/path validation.");

            if (!visited.Add(nextUri.AbsoluteUri))
                throw new InvalidOperationException("Redirect loop detected.");

            current = nextUri;
        }

        throw new InvalidOperationException($"Exceeded maximum redirect limit ({maxRedirects}).");
    }

    private static bool TryResolveSafeRedirectTarget(Uri current, string? rawLocation, Uri? locationUri, out Uri nextUri)
    {
        nextUri = null!;
        var originalFromUri = locationUri?.OriginalString?.Trim();
        var raw = !string.IsNullOrWhiteSpace(originalFromUri)
            ? originalFromUri
            : rawLocation?.Trim();
        if (string.IsNullOrWhiteSpace(raw) || raw.Length > 4096)
            return false;

        if (!string.IsNullOrWhiteSpace(rawLocation))
        {
            var rawTrimmed = rawLocation.Trim();
            if (!IsSafeRawRedirectLocation(rawTrimmed))
                return false;
        }

        if (!IsSafeRawRedirectLocation(raw))
            return false;

        Uri? resolved;
        if (raw.StartsWith('/'))
        {
            if (!Uri.TryCreate(raw, UriKind.Relative, out var rel) || !Uri.TryCreate(current, rel, out resolved))
                return false;
        }
        else if (locationUri is { IsAbsoluteUri: true })
        {
            resolved = locationUri;
        }
        else if (Uri.TryCreate(raw, UriKind.Absolute, out var absUri))
        {
            resolved = absUri;
        }
        else if (Uri.TryCreate(raw, UriKind.Relative, out var relUri))
        {
            if (!Uri.TryCreate(current, relUri, out resolved))
                return false;
        }
        else
        {
            return false;
        }

        if (resolved is null)
            return false;

        return TryValidateVendorUrl(resolved.AbsoluteUri, AllowedHostSuffixes, out nextUri);
    }

    private static bool IsSafeRawRedirectLocation(string candidate)
    {
        if (candidate.Length == 0 || candidate.Length > 4096)
            return false;

        foreach (var c in candidate)
        {
            if (char.IsControl(c) || char.IsWhiteSpace(c) || c == '\\')
                return false;
        }

        if (candidate.StartsWith("//", StringComparison.Ordinal))
            return false;

        var firstDelim = candidate.IndexOfAny(['/', '?', '#']);
        var firstSegment = firstDelim >= 0 ? candidate[..firstDelim] : candidate;
        if (firstSegment.Contains(':', StringComparison.Ordinal)
            && !candidate.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return !HasUnsafeRedirectLocationPath(candidate);
    }

    private static bool HasUnsafeRedirectLocationPath(string rawLocation)
    {
        var queryOrFragIdx = rawLocation.IndexOfAny(['?', '#']);
        var beforeQuery = queryOrFragIdx >= 0 ? rawLocation[..queryOrFragIdx] : rawLocation;
        if (beforeQuery.IndexOf("://", StringComparison.Ordinal) >= 0)
            return HasUnsafePathSegments(rawLocation);

        var pathPart = beforeQuery.TrimStart('/');
        if (pathPart.Length == 0)
            return false;

        foreach (var seg in pathPart.Split('/'))
        {
            if (seg.Length == 0)
                continue;

            if (IsUnsafePathSegment(seg))
                return true;
        }

        return false;
    }

    private static bool TryValidateVendorUrl(string? rawUrl, IReadOnlyList<string> allowedHostSuffixes, out Uri uri)
    {
        uri = null!;
        if (string.IsNullOrWhiteSpace(rawUrl))
            return false;

        var trimmed = rawUrl.Trim();
        if (trimmed.StartsWith("//", StringComparison.Ordinal))
            return false;

        if (!BiosProviderHttp.TryValidateHttpsUrl(trimmed, allowedHostSuffixes, out var parsed, out _))
            return false;

        if (HasUnsafePathSegments(trimmed))
            return false;

        uri = parsed;
        return true;
    }

    private static bool HasUnsafePathSegments(string url)
    {
        var schemeSep = url.IndexOf("://", StringComparison.Ordinal);
        if (schemeSep < 0)
            return true;

        var afterScheme = url[(schemeSep + 3)..];
        var slashIdx = afterScheme.IndexOf('/');
        if (slashIdx < 0)
            return false;

        var pathPart = afterScheme[(slashIdx + 1)..];
        var queryOrFragIdx = pathPart.IndexOfAny(['?', '#']);
        if (queryOrFragIdx >= 0)
            pathPart = pathPart[..queryOrFragIdx];

        if (pathPart.Length == 0)
            return false;

        foreach (var seg in pathPart.Split('/'))
        {
            if (seg.Length == 0)
                continue;

            if (IsUnsafePathSegment(seg))
                return true;
        }

        return false;
    }

    private static bool IsUnsafePathSegment(string segment)
    {
        var current = segment;
        for (var round = 0; round < 5; round++)
        {
            if (current is "." or ".." || current.Trim() is "." or "..")
                return true;

            if (current.Contains("%2e", StringComparison.OrdinalIgnoreCase)
                || current.Contains("%2f", StringComparison.OrdinalIgnoreCase)
                || current.Contains("%5c", StringComparison.OrdinalIgnoreCase)
                || current.Contains("%00", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            for (var i = 0; i < current.Length; i++)
            {
                var c = current[i];
                if (char.IsControl(c) || c is '/' or '\\' or '?' or '#' or '@')
                    return true;

                if (c == '%')
                {
                    if (i + 2 >= current.Length
                        || !Uri.IsHexDigit(current[i + 1])
                        || !Uri.IsHexDigit(current[i + 2]))
                    {
                        return true;
                    }
                }
            }

            if (!current.Contains('%', StringComparison.Ordinal))
                return false;

            string decoded;
            try
            {
                decoded = Uri.UnescapeDataString(current);
            }
            catch
            {
                return true;
            }

            if (string.Equals(decoded, current, StringComparison.Ordinal))
                return false;

            current = decoded;
        }

        return true;
    }

    private static async Task<(byte[] Buffer, int Offset, int Length)> ReadBoundedBytesAsync(
        HttpContent content,
        long maxBytes,
        CancellationToken ct)
    {
        var contentLength = content.Headers.ContentLength;
        if (contentLength.HasValue && contentLength.Value > maxBytes)
            throw new InvalidDataException($"Microsoft Surface catalog response ({contentLength.Value} bytes) exceeds maximum allowed limit ({maxBytes} bytes).");

        var initialCap = contentLength is > 0
            ? (int)Math.Min(contentLength.Value, MaxInitialStreamCapacity)
            : 4096;

        using var ms = new MemoryStream(initialCap);
        await using var stream = await content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        var buffer = ArrayPool<byte>.Shared.Rent(ReadBufferSize);
        long totalRead = 0;

        try
        {
            while (true)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), ct).ConfigureAwait(false);
                if (read == 0)
                    break;

                totalRead += read;
                if (totalRead > maxBytes)
                    throw new InvalidDataException($"Microsoft Surface catalog response exceeded maximum allowed size ({maxBytes} bytes).");

                ms.Write(buffer, 0, read);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        if (totalRead == 0)
            throw new InvalidDataException("Microsoft Surface catalog response body is empty.");

        var bytes = ms.ToArray();
        var offset = 0;
        var length = bytes.Length;

        if (length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
        {
            offset = 3;
            length -= 3;
        }

        return (bytes, offset, length);
    }

    private static int FindFirstNonWhitespaceByte(byte[] bytes, int offset, int length)
    {
        var end = offset + length;
        for (var i = offset; i < end; i++)
        {
            if (bytes[i] is not ((byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n'))
                return i;
        }

        return -1;
    }

    // -------------------------------------------------------------------------
    // Install staging, hardened package download & symlink safety helpers
    // -------------------------------------------------------------------------

    private async Task<BiosVerifiedPackageResult> DownloadAndVerifySurfacePackageAsync(
        BiosInstallRequest request,
        string stagingDir,
        string fileName,
        IProgress<BiosInstallProgress>? progress,
        ILogger? log,
        CancellationToken ct,
        long maxBytes = BiosProviderHttp.DefaultMaxDownloadBytes)
    {
        var downloadUrl = request.Target.DownloadUrl!;
        var finalPath = Path.Combine(stagingDir, fileName);
        var partPath = $"{finalPath}.{Guid.NewGuid():N}.part";
        var createdPart = false;
        var moved = false;
        var keepFile = false;

        try
        {
            if (IsSymlinkOrReparsePoint(stagingDir)
                || HasSymlinkOrReparseAncestor(stagingDir)
                || File.Exists(stagingDir)
                || IsSymlinkOrReparsePoint(finalPath)
                || Directory.Exists(finalPath)
                || IsSymlinkOrReparsePoint(partPath))
            {
                const string symMsg = "Staging directory or target package file is a symbolic link, reparse point, or conflicting directory.";
                log?.Warn($"[{VendorId}] {symMsg}");
                return BiosVerifiedPackageResult.Fail(symMsg);
            }

            Directory.CreateDirectory(stagingDir);

            if (IsSymlinkOrReparsePoint(stagingDir)
                || HasSymlinkOrReparseAncestor(stagingDir)
                || IsSymlinkOrReparsePoint(finalPath)
                || Directory.Exists(finalPath)
                || IsSymlinkOrReparsePoint(partPath))
            {
                const string symMsg = "Staging directory or target package file became a symbolic link, reparse point, or conflicting directory.";
                log?.Warn($"[{VendorId}] {symMsg}");
                return BiosVerifiedPackageResult.Fail(symMsg);
            }

            progress?.Report(new BiosInstallProgress(BiosInstallStage.Downloading, 0, $"Downloading {fileName}..."));

            using var response = await GetPackageWithSafeRedirectsAsync(downloadUrl, ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                var err = $"Download failed with HTTP {(int)response.StatusCode} ({response.StatusCode}).";
                log?.Warn($"[{VendorId}] BIOS package download failed: {err}");
                return BiosVerifiedPackageResult.Fail(err);
            }

            var contentLength = response.Content.Headers.ContentLength;
            if (contentLength is > 0 && contentLength.Value > maxBytes)
            {
                var err = $"Package size ({contentLength.Value} bytes) exceeds maximum allowed limit ({maxBytes} bytes).";
                log?.Warn($"[{VendorId}] BIOS package download failed: {err}");
                return BiosVerifiedPackageResult.Fail(err);
            }

            if (IsSymlinkOrReparsePoint(stagingDir)
                || HasSymlinkOrReparseAncestor(stagingDir)
                || IsSymlinkOrReparsePoint(finalPath)
                || Directory.Exists(finalPath)
                || IsSymlinkOrReparsePoint(partPath))
            {
                const string symMsg = "Target package file or .part path is a symbolic link, reparse point, or conflicting directory.";
                log?.Warn($"[{VendorId}] {symMsg}");
                return BiosVerifiedPackageResult.Fail(symMsg);
            }

            long downloaded = 0;
            var lastPercent = 0;

            await using (var source = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false))
            await using (var dest = new FileStream(partPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, ReadBufferSize, useAsync: true))
            {
                createdPart = true;
                var buffer = ArrayPool<byte>.Shared.Rent(ReadBufferSize);
                try
                {
                    while (true)
                    {
                        var read = await source.ReadAsync(buffer.AsMemory(0, buffer.Length), ct).ConfigureAwait(false);
                        if (read == 0)
                            break;

                        downloaded += read;
                        if (downloaded > maxBytes)
                        {
                            var err = $"Downloaded package exceeded maximum allowed size ({maxBytes} bytes).";
                            log?.Warn($"[{VendorId}] BIOS package download failed: {err}");
                            return BiosVerifiedPackageResult.Fail(err);
                        }

                        await dest.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);

                        if (contentLength is > 0)
                        {
                            var percent = (int)Math.Clamp(downloaded * 100L / contentLength.Value, 0L, 100L);
                            if (percent > lastPercent)
                            {
                                lastPercent = percent;
                                progress?.Report(new BiosInstallProgress(BiosInstallStage.Downloading, percent, $"Downloading {fileName} ({percent}%)..."));
                            }
                        }
                    }

                    await dest.FlushAsync(ct).ConfigureAwait(false);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(buffer);
                }
            }

            if (downloaded == 0)
            {
                const string emptyErr = "Downloaded package is empty (0 bytes).";
                log?.Warn($"[{VendorId}] BIOS package download failed: {emptyErr}");
                return BiosVerifiedPackageResult.Fail(emptyErr);
            }

            if (IsSymlinkOrReparsePoint(stagingDir)
                || HasSymlinkOrReparseAncestor(stagingDir)
                || IsSymlinkOrReparsePoint(finalPath)
                || Directory.Exists(finalPath)
                || IsSymlinkOrReparsePoint(partPath))
            {
                const string symMsg = "Target package file or .part path became a symbolic link, reparse point, or conflicting directory.";
                log?.Warn($"[{VendorId}] {symMsg}");
                return BiosVerifiedPackageResult.Fail(symMsg);
            }

            if (lastPercent < 100)
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Downloading, 100, $"Downloaded {fileName}."));

            moved = await BiosProviderHttp.MoveIntoPlaceOrReuseIdenticalAsync(partPath, finalPath, ct).ConfigureAwait(false);

            if (request.VerifyHash && !string.IsNullOrWhiteSpace(request.Target.Sha256))
            {
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Verifying, 0, "Verifying package SHA-256 digest..."));

                var (valid, actual) = await BiosPackageVerifier.VerifyFileSha256Async(
                    finalPath,
                    request.Target.Sha256,
                    ct).ConfigureAwait(false);

                if (!valid)
                {
                    log?.Warn($"[{VendorId}] BIOS package SHA-256 mismatch (actual={actual}). Deleting unverified file.");
                    return BiosVerifiedPackageResult.Fail("Downloaded BIOS package failed SHA-256 verification.", actual);
                }

                keepFile = true;
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Verifying, 100, "Package SHA-256 verified."));
                return BiosVerifiedPackageResult.Ok(
                    finalPath,
                    downloaded,
                    actualSha256: actual,
                    verifiedBySha256: true);
            }

            // Even when VerifyHash is false or the catalog omitted a SHA-256 digest,
            // never allow an unverified package through — always require a pinned Authenticode signature.
            progress?.Report(new BiosInstallProgress(BiosInstallStage.Verifying, 0, "Verifying package Authenticode signature..."));

            var allowedSigners = BiosAgentInstallModes.AllowedSignerOrganizationsForVendor(VendorId);
            var signed = allowedSigners.Count > 0
                && await _signatureVerifier.VerifyAuthenticodeAsync(finalPath, allowedSigners, ct).ConfigureAwait(false);
            if (!signed)
            {
                log?.Warn($"[{VendorId}] BIOS package failed Authenticode signature verification. Deleting unverified file.");
                return BiosVerifiedPackageResult.Fail("Downloaded BIOS package failed Authenticode signature verification.");
            }

            keepFile = true;
            progress?.Report(new BiosInstallProgress(BiosInstallStage.Verifying, 100, "Package Authenticode signature verified."));
            return BiosVerifiedPackageResult.Ok(
                finalPath,
                downloaded,
                verifiedByAuthenticode: true);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            const string err = "Package download timed out.";
            log?.Warn($"[{VendorId}] BIOS package download failed: {err}");
            return BiosVerifiedPackageResult.Fail(err);
        }
        catch (InvalidOperationException ex)
        {
            log?.Warn($"[{VendorId}] BIOS package download failed: {ex.Message}");
            return BiosVerifiedPackageResult.Fail(ex.Message);
        }
        catch (HttpRequestException ex)
        {
            var err = $"Network error while downloading package: {ex.Message}";
            log?.Warn($"[{VendorId}] BIOS package download failed: {err}");
            return BiosVerifiedPackageResult.Fail(err);
        }
        catch (SocketException ex)
        {
            var err = $"Socket error while downloading package: {ex.Message}";
            log?.Warn($"[{VendorId}] BIOS package download failed: {err}");
            return BiosVerifiedPackageResult.Fail(err);
        }
        catch (IOException ex)
        {
            var err = $"I/O error while downloading package: {ex.Message}";
            log?.Warn($"[{VendorId}] BIOS package download failed: {err}");
            return BiosVerifiedPackageResult.Fail(err);
        }
        finally
        {
            if (createdPart && !moved)
                TryDeleteFile(partPath);
            if (moved && !keepFile)
                TryDeleteFile(finalPath);
        }
    }

    private async Task<HttpResponseMessage> GetPackageWithSafeRedirectsAsync(string initialUrl, CancellationToken ct)
    {
        if (!TryValidateVendorUrl(initialUrl, AllowedHostSuffixes, out var current))
            throw new InvalidOperationException("Disallowed Microsoft Surface package URL.");

        var initialExt = Path.GetExtension(current.AbsolutePath);
        if (!string.IsNullOrEmpty(initialExt) && !initialExt.Equals(".msi", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Microsoft Surface firmware installer must be an .msi package.");

        var visited = new HashSet<string>(StringComparer.Ordinal) { current.AbsoluteUri };
        const int maxRedirects = BiosProviderHttp.DefaultMaxRedirects;

        for (var hop = 0; hop <= maxRedirects; hop++)
        {
            ct.ThrowIfCancellationRequested();

            using var request = new HttpRequestMessage(HttpMethod.Get, current);
            var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            if ((int)response.StatusCode is not (301 or 302 or 303 or 307 or 308))
            {
                var effectiveUri = current;
                if (response.RequestMessage?.RequestUri is { } finalUri)
                {
                    if (!finalUri.IsAbsoluteUri
                        || !TryValidateVendorUrl(finalUri.AbsoluteUri, AllowedHostSuffixes, out var validatedFinal)
                        || (!string.IsNullOrWhiteSpace(finalUri.OriginalString)
                            && !TryValidateVendorUrl(finalUri.OriginalString, AllowedHostSuffixes, out _)))
                    {
                        response.Dispose();
                        throw new InvalidOperationException("Rejected redirect target: final response URL failed vendor HTTPS/domain/path validation.");
                    }

                    effectiveUri = validatedFinal;
                }

                var finalExt = Path.GetExtension(effectiveUri.AbsolutePath);
                if (!string.IsNullOrEmpty(finalExt) && !finalExt.Equals(".msi", StringComparison.OrdinalIgnoreCase))
                {
                    response.Dispose();
                    throw new InvalidOperationException("Rejected redirect target: Microsoft Surface firmware installer must be an .msi package.");
                }

                return response;
            }

            string? rawNonValidated = null;
            if (response.Headers.NonValidated.TryGetValues("Location", out var rawLocs))
            {
                var count = 0;
                foreach (var val in rawLocs)
                {
                    count++;
                    if (count > 1)
                    {
                        response.Dispose();
                        throw new InvalidOperationException("Rejected ambiguous redirect with multiple Location headers.");
                    }

                    rawNonValidated = val;
                }
            }

            var locationUri = response.Headers.Location;
            response.Dispose();

            if (hop == maxRedirects)
                throw new InvalidOperationException($"Exceeded maximum redirect limit ({maxRedirects}).");

            if (!TryResolveSafeRedirectTarget(current, rawNonValidated, locationUri, out var nextUri))
                throw new InvalidOperationException("Rejected redirect target: failed vendor HTTPS/domain/path validation.");

            var hopExt = Path.GetExtension(nextUri.AbsolutePath);
            if (!string.IsNullOrEmpty(hopExt) && !hopExt.Equals(".msi", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Rejected redirect target: Microsoft Surface firmware installer must be an .msi package.");

            if (!visited.Add(nextUri.AbsoluteUri))
                throw new InvalidOperationException("Redirect loop detected.");

            current = nextUri;
        }

        throw new InvalidOperationException($"Exceeded maximum redirect limit ({maxRedirects}).");
    }

    private static string BuildSafePackageFileName(string url, string defaultFileName, string requiredExtension)
    {
        var candidate = BiosVendorIdentity.SanitizeFileName(url, defaultFileName);
        if (candidate.EndsWith(requiredExtension, StringComparison.OrdinalIgnoreCase)
            && candidate.Length > requiredExtension.Length)
        {
            return candidate;
        }

        var maxStemLen = 128 - requiredExtension.Length;
        var stem = candidate.Length > maxStemLen ? candidate[..maxStemLen] : candidate;
        stem = stem.TrimEnd(' ', '.');
        if (string.IsNullOrWhiteSpace(stem) || stem is "." or "..")
            return defaultFileName;

        var combined = stem + requiredExtension;
        var validated = BiosVendorIdentity.SanitizeFileName(combined, defaultFileName);
        return validated.EndsWith(requiredExtension, StringComparison.OrdinalIgnoreCase)
            ? validated
            : defaultFileName;
    }

    private static bool ValidateStagingDirectorySafe(string stagingDir, out string error)
    {
        error = "";
        try
        {
            var fullStaging = Path.TrimEndingDirectorySeparator(Path.GetFullPath(stagingDir));
            if (string.IsNullOrWhiteSpace(fullStaging))
            {
                error = "Staging directory path is invalid.";
                return false;
            }

            if (IsSymlinkOrReparsePoint(fullStaging))
            {
                error = "Staging directory is a symbolic link or reparse point.";
                return false;
            }

            if (HasSymlinkOrReparseAncestor(fullStaging))
            {
                error = "Staging directory has a symbolic link or reparse point ancestor.";
                return false;
            }

            if (File.Exists(fullStaging))
            {
                error = "Staging directory path collides with an existing file.";
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            error = $"Staging directory path is invalid: {ex.Message}";
            return false;
        }
    }

    private static bool IsSymlinkOrReparsePoint(string path)
    {
        try
        {
            var normalized = Path.TrimEndingDirectorySeparator(path);
            if (string.IsNullOrEmpty(normalized))
                return false;

            var fi = new FileInfo(normalized);
            if (fi.LinkTarget is not null)
                return true;

            var di = new DirectoryInfo(normalized);
            if (di.LinkTarget is not null)
                return true;

            if (fi.Exists)
                return (fi.Attributes & FileAttributes.ReparsePoint) != 0;

            if (di.Exists)
                return (di.Attributes & FileAttributes.ReparsePoint) != 0;

            return false;
        }
        catch
        {
            return true; // Fail closed if attributes cannot be inspected.
        }
    }

    private static bool HasSymlinkOrReparseAncestor(string path)
    {
        try
        {
            var startPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
            for (var current = new DirectoryInfo(startPath); current is not null; current = current.Parent)
            {
                if (current.LinkTarget is not null)
                    return true;

                if (!current.Exists)
                    continue;

                if ((current.Attributes & FileAttributes.ReparsePoint) != 0)
                    return true;
            }

            return false;
        }
        catch
        {
            return true; // Fail closed.
        }
    }

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
            if (IsSymlinkOrReparsePoint(candidate) || Directory.Exists(candidate))
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

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
                File.Delete(path);
        }
        catch
        {
            // Best-effort cleanup.
        }
    }

    private static void TryDeleteDirectoryRecursive(string dir)
    {
        try
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, recursive: true);
        }
        catch
        {
            // Best-effort cleanup.
        }
    }

    // -------------------------------------------------------------------------
    // Parsing, keyword & metadata helpers
    // -------------------------------------------------------------------------

    private static bool ContainsAnyKeyword(string text, string[] keywords)
    {
        foreach (var keyword in keywords)
        {
            if (MatchesKeywordPhrase(text, keyword))
                return true;
        }

        return false;
    }

    private static bool MatchesKeywordPhrase(string text, string phrase)
    {
        var start = 0;
        while (start <= text.Length - phrase.Length)
        {
            var idx = text.IndexOf(phrase, start, StringComparison.OrdinalIgnoreCase);
            if (idx < 0)
                return false;

            var leftOk = idx == 0 || !char.IsLetterOrDigit(text[idx - 1]);
            var rightIdx = idx + phrase.Length;
            var rightOk = rightIdx == text.Length || !char.IsLetterOrDigit(text[rightIdx]);
            if (leftOk && rightOk)
                return true;

            start = idx + 1;
        }

        return false;
    }

    private static bool IsBetaRelease(string? version, string? title, string? description, bool? isReleaseFlag, bool? isBetaFlag)
    {
        if (isBetaFlag == true || isReleaseFlag == false)
            return true;

        if (!string.IsNullOrWhiteSpace(version) && BetaTokenRegex().IsMatch(version))
            return true;

        if (!string.IsNullOrWhiteSpace(title) && BetaTokenRegex().IsMatch(title))
            return true;

        if (!string.IsNullOrWhiteSpace(description))
        {
            var trimmed = description.Trim();
            if (trimmed.StartsWith("beta", StringComparison.OrdinalIgnoreCase)
                || trimmed.Contains("beta version", StringComparison.OrdinalIgnoreCase)
                || trimmed.Contains("beta firmware", StringComparison.OrdinalIgnoreCase)
                || trimmed.Contains("beta release", StringComparison.OrdinalIgnoreCase)
                || trimmed.Contains("insider preview", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool TryGetPropertyIgnoreCase(JsonElement obj, out JsonElement value, params string[] names)
    {
        if (obj.ValueKind == JsonValueKind.Object)
        {
            foreach (var name in names)
            {
                foreach (var prop in obj.EnumerateObject())
                {
                    if (string.Equals(prop.Name, name, StringComparison.OrdinalIgnoreCase)
                        && prop.Value.ValueKind != JsonValueKind.Null)
                    {
                        value = prop.Value;
                        return true;
                    }
                }
            }
        }

        value = default;
        return false;
    }

    private static string? GetStringOrNumber(JsonElement obj, params string[] names)
    {
        if (!TryGetPropertyIgnoreCase(obj, out var el, names))
            return null;

        return el.ValueKind switch
        {
            JsonValueKind.String => string.IsNullOrWhiteSpace(el.GetString()) ? null : el.GetString()!.Trim(),
            JsonValueKind.Number => el.GetRawText(),
            _ => null,
        };
    }

    private static bool? GetNullableBool(JsonElement obj, params string[] names)
    {
        if (!TryGetPropertyIgnoreCase(obj, out var el, names))
            return null;

        if (el.ValueKind == JsonValueKind.True)
            return true;
        if (el.ValueKind == JsonValueKind.False)
            return false;
        if (el.ValueKind == JsonValueKind.Number && el.TryGetInt64(out var n))
            return n != 0;
        if (el.ValueKind == JsonValueKind.String)
            return ParseNullableBoolString(el.GetString());

        return null;
    }

    private static bool? ParseNullableBoolString(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        var s = raw.Trim();
        if (string.Equals(s, "true", StringComparison.OrdinalIgnoreCase)
            || string.Equals(s, "1", StringComparison.Ordinal)
            || string.Equals(s, "yes", StringComparison.OrdinalIgnoreCase))
            return true;

        if (string.Equals(s, "false", StringComparison.OrdinalIgnoreCase)
            || string.Equals(s, "0", StringComparison.Ordinal)
            || string.Equals(s, "no", StringComparison.OrdinalIgnoreCase))
            return false;

        return null;
    }

    private static long? TryParseSizeBytes(JsonElement obj, params string[] names)
    {
        if (!TryGetPropertyIgnoreCase(obj, out var el, names))
            return null;

        const long maxPlausibleBytes = 10L * 1024 * 1024 * 1024;
        if (el.ValueKind == JsonValueKind.Number && el.TryGetInt64(out var direct) && direct is > 0 and <= maxPlausibleBytes)
            return direct;

        if (el.ValueKind != JsonValueKind.String)
            return null;

        return TryParseSizeString(el.GetString());
    }

    private static long? TryParseSizeString(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        const long maxPlausibleBytes = 10L * 1024 * 1024 * 1024;
        var trimmed = raw.Trim();

        if (long.TryParse(trimmed, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed)
            && parsed is > 0 and <= maxPlausibleBytes)
        {
            return parsed;
        }

        if (ThousandsGroupedIntRegex().IsMatch(trimmed))
        {
            var ungrouped = trimmed.Replace(",", "", StringComparison.Ordinal);
            if (long.TryParse(ungrouped, NumberStyles.None, CultureInfo.InvariantCulture, out var groupedParsed)
                && groupedParsed is > 0 and <= maxPlausibleBytes)
            {
                return groupedParsed;
            }
        }

        var match = HumanSizeRegex().Match(trimmed);
        if (!match.Success)
            return null;

        var numToken = match.Groups[1].Value;
        string normalizedNumber;
        var hasComma = numToken.Contains(',', StringComparison.Ordinal);
        var hasDot = numToken.Contains('.', StringComparison.Ordinal);
        if (hasComma && hasDot)
        {
            normalizedNumber = numToken.Replace(",", "", StringComparison.Ordinal);
        }
        else if (hasComma)
        {
            if (ThousandsGroupedIntRegex().IsMatch(numToken))
                normalizedNumber = numToken.Replace(",", "", StringComparison.Ordinal);
            else if (numToken.IndexOf(',') == numToken.LastIndexOf(','))
                normalizedNumber = numToken.Replace(',', '.');
            else
                return null;
        }
        else
        {
            normalizedNumber = numToken;
        }

        if (!double.TryParse(normalizedNumber, NumberStyles.Float, CultureInfo.InvariantCulture, out var amount)
            || double.IsNaN(amount) || double.IsInfinity(amount) || amount <= 0)
        {
            return null;
        }

        var unit = match.Groups[2].Value.ToLowerInvariant();
        var multiplier = unit switch
        {
            "b" or "byte" or "bytes" => 1.0,
            "kb" or "kib" or "kbyte" or "kbytes" => 1024.0,
            "mb" or "mib" or "mbyte" or "mbytes" => 1024.0 * 1024.0,
            "gb" or "gib" or "gbyte" or "gbytes" => 1024.0 * 1024.0 * 1024.0,
            _ => 0.0,
        };

        var bytes = amount * multiplier;
        if (bytes < 1.0 || bytes > maxPlausibleBytes)
            return null;

        return (long)Math.Round(bytes, MidpointRounding.AwayFromZero);
    }

    private static string? TryNormalizeSha256(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        var trimmed = raw.Trim();
        return Sha256Regex().IsMatch(trimmed) ? trimmed.ToLowerInvariant() : null;
    }

    private static DateOnly? TryParseReleaseDate(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        var trimmed = raw.Trim();
        var direct = BiosVersionComparer.TryParseReleaseDate(trimmed);
        if (direct.HasValue)
            return direct;

        string[] extraFormats = ["yyyy.MM.dd", "yyyy-MM-dd HH:mm:ss", "yyyy/MM/dd HH:mm:ss"];
        if (DateTimeOffset.TryParseExact(trimmed, extraFormats, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var exactDto))
            return DateOnly.FromDateTime(exactDto.UtcDateTime);

        if (DateTimeOffset.TryParse(trimmed, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var dto))
            return DateOnly.FromDateTime(dto.UtcDateTime);

        return null;
    }

    private static BiosUpdateSeverity ParseSeverity(string? rawSeverity, bool? isCritical, string? title, string? description)
    {
        if (isCritical == true)
            return BiosUpdateSeverity.Critical;

        if (!string.IsNullOrWhiteSpace(rawSeverity))
        {
            var s = rawSeverity.Trim();
            if (s.Contains("critical", StringComparison.OrdinalIgnoreCase)
                || s.Contains("urgent", StringComparison.OrdinalIgnoreCase)
                || s.Contains("security", StringComparison.OrdinalIgnoreCase)
                || string.Equals(s, "1", StringComparison.Ordinal))
                return BiosUpdateSeverity.Critical;

            if (s.Contains("optional", StringComparison.OrdinalIgnoreCase)
                || s.Contains("routine", StringComparison.OrdinalIgnoreCase)
                || s.Contains("low", StringComparison.OrdinalIgnoreCase)
                || string.Equals(s, "3", StringComparison.Ordinal))
                return BiosUpdateSeverity.Optional;

            if (s.Contains("recommended", StringComparison.OrdinalIgnoreCase)
                || s.Contains("important", StringComparison.OrdinalIgnoreCase)
                || string.Equals(s, "2", StringComparison.Ordinal))
                return BiosUpdateSeverity.Recommended;
        }

        var combined = $"{title} {description}";
        if (combined.Contains("CVE-", StringComparison.OrdinalIgnoreCase)
            || combined.Contains("security vulnerability", StringComparison.OrdinalIgnoreCase))
        {
            return BiosUpdateSeverity.Critical;
        }

        return BiosUpdateSeverity.Recommended;
    }

    private static string? CleanReleaseSummary(string? title, string? description)
    {
        var raw = !string.IsNullOrWhiteSpace(description) ? description : title;
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        var text = HtmlBreakRegex().Replace(raw, "; ");
        text = HtmlTagRegex().Replace(text, " ");
        text = WebUtility.HtmlDecode(text);
        text = WhitespaceRegex().Replace(text, " ").Trim();

        if (text.Length == 0)
            return null;

        return text.Length <= MaxSummaryLength ? text : text[..MaxSummaryLength].TrimEnd();
    }

    // -------------------------------------------------------------------------
    // SerialNumber redaction (logs, models, URLs, install results)
    // -------------------------------------------------------------------------

    private void LogWarn(string message, string? serialNumber) =>
        _log?.Warn(RedactText(message, serialNumber));

    private static BiosInstallResult RedactInstallResult(BiosInstallResult result, string? serialNumber)
    {
        var secret = serialNumber?.Trim();
        if (string.IsNullOrEmpty(secret) || secret.Length < 3)
            return result;

        var safePrev = result.PreviousVersion is not null ? RedactText(result.PreviousVersion, secret) : null;
        var safeTarget = result.TargetVersion is not null ? RedactText(result.TargetVersion, secret) : null;
        var safeMsg = RedactText(result.Message, secret);
        var safeLogTail = result.LogTail is not null ? RedactText(result.LogTail, secret) : null;

        if (ReferenceEquals(safePrev, result.PreviousVersion)
            && ReferenceEquals(safeTarget, result.TargetVersion)
            && ReferenceEquals(safeMsg, result.Message)
            && ReferenceEquals(safeLogTail, result.LogTail))
        {
            return result;
        }

        return result with
        {
            PreviousVersion = safePrev,
            TargetVersion = safeTarget,
            Message = safeMsg,
            LogTail = safeLogTail,
        };
    }

    private static BiosLatestInfo RedactLatestInfo(BiosLatestInfo info, string? serialNumber)
    {
        var secret = serialNumber?.Trim();
        if (string.IsNullOrEmpty(secret) || secret.Length < 3)
            return info;

        var safeLatestVersion = info.LatestVersion is not null
            ? RedactText(info.LatestVersion, secret)
            : null;
        var safeMessage = info.Message is not null
            ? RedactText(info.Message, secret)
            : null;
        var safeSummary = info.ReleaseSummary is not null
            ? RedactText(info.ReleaseSummary, secret)
            : null;
        var safePackageId = info.PackageId is not null
            ? RedactText(info.PackageId, secret)
            : null;

        var safeDownloadUrl = ContainsSerialInUrl(info.DownloadUrl, secret)
            ? null
            : info.DownloadUrl;
        var safeReleaseNotesUrl = ContainsSerialInUrl(info.ReleaseNotesUrl, secret)
            ? null
            : info.ReleaseNotesUrl;

        IReadOnlyDictionary<string, string>? safeMeta = info.Metadata;
        var metaChanged = false;
        if (info.Metadata is not null && info.Metadata.Count > 0)
        {
            var dict = new Dictionary<string, string>(info.Metadata.Count, StringComparer.OrdinalIgnoreCase);
            foreach (var kv in info.Metadata)
            {
                var redactedVal = RedactText(kv.Value, secret);
                if (!ReferenceEquals(redactedVal, kv.Value))
                    metaChanged = true;
                dict[kv.Key] = redactedVal;
            }

            if (metaChanged)
                safeMeta = dict;
        }

        if (ReferenceEquals(safeLatestVersion, info.LatestVersion)
            && ReferenceEquals(safeMessage, info.Message)
            && ReferenceEquals(safeSummary, info.ReleaseSummary)
            && ReferenceEquals(safePackageId, info.PackageId)
            && ReferenceEquals(safeDownloadUrl, info.DownloadUrl)
            && ReferenceEquals(safeReleaseNotesUrl, info.ReleaseNotesUrl)
            && !metaChanged)
        {
            return info;
        }

        return info with
        {
            LatestVersion = safeLatestVersion,
            Message = safeMessage,
            ReleaseSummary = safeSummary,
            PackageId = safePackageId,
            DownloadUrl = safeDownloadUrl,
            ReleaseNotesUrl = safeReleaseNotesUrl,
            Metadata = safeMeta,
        };
    }

    private static Dictionary<string, string> RedactMetadata(Dictionary<string, string> metadata, string? serialNumber)
    {
        if (string.IsNullOrWhiteSpace(serialNumber) || metadata.Count == 0)
            return metadata;

        var result = new Dictionary<string, string>(metadata.Count, StringComparer.OrdinalIgnoreCase);
        foreach (var kv in metadata)
            result[kv.Key] = RedactText(kv.Value, serialNumber);
        return result;
    }

    private static string RedactText(string value, string? serialNumber)
    {
        if (string.IsNullOrEmpty(value))
            return value;

        var secret = serialNumber?.Trim();
        if (string.IsNullOrEmpty(secret) || secret.Length < 3)
            return value;

        var result = BiosInstallerRunner.RedactSerialNumber(value, secret);

        var escaped = Uri.EscapeDataString(secret);
        if (!string.Equals(escaped, secret, StringComparison.OrdinalIgnoreCase))
            result = result.Replace(escaped, "[REDACTED]", StringComparison.OrdinalIgnoreCase);

        var formEncoded = escaped.Replace("%20", "+", StringComparison.Ordinal);
        if (!string.Equals(formEncoded, escaped, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(formEncoded, secret, StringComparison.OrdinalIgnoreCase))
        {
            result = result.Replace(formEncoded, "[REDACTED]", StringComparison.OrdinalIgnoreCase);
        }

        var spaceEncoded = secret.Replace(" ", "%20", StringComparison.Ordinal);
        if (!string.Equals(spaceEncoded, secret, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(spaceEncoded, escaped, StringComparison.OrdinalIgnoreCase))
        {
            result = result.Replace(spaceEncoded, "[REDACTED]", StringComparison.OrdinalIgnoreCase);
        }

        var spacePlusEncoded = secret.Replace(" ", "+", StringComparison.Ordinal);
        if (!string.Equals(spacePlusEncoded, secret, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(spacePlusEncoded, formEncoded, StringComparison.OrdinalIgnoreCase))
        {
            result = result.Replace(spacePlusEncoded, "[REDACTED]", StringComparison.OrdinalIgnoreCase);
        }

        return result;
    }

    private static bool ContainsSerialInUrl(string? url, string secret)
    {
        if (string.IsNullOrEmpty(url))
            return false;

        if (url.Contains(secret, StringComparison.OrdinalIgnoreCase))
            return true;

        var escaped = Uri.EscapeDataString(secret);
        if (!string.Equals(escaped, secret, StringComparison.OrdinalIgnoreCase)
            && url.Contains(escaped, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var formEncoded = escaped.Replace("%20", "+", StringComparison.Ordinal);
        if (!string.Equals(formEncoded, escaped, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(formEncoded, secret, StringComparison.OrdinalIgnoreCase)
            && url.Contains(formEncoded, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var spaceEncoded = secret.Replace(" ", "%20", StringComparison.Ordinal);
        if (!string.Equals(spaceEncoded, secret, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(spaceEncoded, escaped, StringComparison.OrdinalIgnoreCase)
            && url.Contains(spaceEncoded, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var spacePlusEncoded = secret.Replace(" ", "+", StringComparison.Ordinal);
        if (!string.Equals(spacePlusEncoded, secret, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(spacePlusEncoded, formEncoded, StringComparison.OrdinalIgnoreCase)
            && url.Contains(spacePlusEncoded, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var candidate = url;
        for (var round = 0; round < 2; round++)
        {
            string decoded;
            try
            {
                decoded = Uri.UnescapeDataString(candidate);
            }
            catch (UriFormatException)
            {
                break;
            }

            if (decoded.Contains(secret, StringComparison.OrdinalIgnoreCase))
                return true;

            if (decoded.Contains('+', StringComparison.Ordinal))
            {
                var decodedWithSpaces = decoded.Replace('+', ' ');
                if (decodedWithSpaces.Contains(secret, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            if (string.Equals(decoded, candidate, StringComparison.Ordinal))
                break;

            candidate = decoded;
        }

        if (url.Contains('+', StringComparison.Ordinal))
        {
            var rawWithSpaces = url.Replace('+', ' ');
            if (rawWithSpaces.Contains(secret, StringComparison.OrdinalIgnoreCase))
                return true;

            try
            {
                var decodedRaw = Uri.UnescapeDataString(rawWithSpaces);
                if (decodedRaw.Contains(secret, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            catch (UriFormatException)
            {
                // Ignore malformed percent-encoding sequences.
            }
        }

        return false;
    }

    // -------------------------------------------------------------------------
    // Internal types
    // -------------------------------------------------------------------------

    private sealed class RedactingLogger(ILogger inner, string? serialNumber) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => inner.BeginScope(state);

        public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => inner.IsEnabled(logLevel);

        public void Log<TState>(
            Microsoft.Extensions.Logging.LogLevel logLevel,
            Microsoft.Extensions.Logging.EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            ArgumentNullException.ThrowIfNull(formatter);
            var formatted = RedactText(formatter(state, exception), serialNumber);
            inner.Log(logLevel, eventId, formatted, exception: null, static (msg, _) => msg);
        }
    }

    private sealed class RedactingProgress(IProgress<BiosInstallProgress> inner, string? serialNumber) : IProgress<BiosInstallProgress>
    {
        public void Report(BiosInstallProgress value)
        {
            if (value is null)
                return;

            var safeDetail = RedactText(value.Detail ?? "", serialNumber);
            inner.Report(ReferenceEquals(safeDetail, value.Detail) ? value : value with { Detail = safeDetail });
        }
    }

    private enum SmbiosTokenStatus
    {
        EmptyOrPlaceholder,
        Valid,
        InvalidUnsafe,
    }

    private enum UrlExtractionState
    {
        Absent,
        Valid,
        Untrusted,
    }

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

    private sealed class BucketKeyEqualityComparer : IEqualityComparer<(int OsPrefRank, string ClassKey)>
    {
        public bool Equals((int OsPrefRank, string ClassKey) x, (int OsPrefRank, string ClassKey) y) =>
            x.OsPrefRank == y.OsPrefRank
            && StringComparer.OrdinalIgnoreCase.Equals(x.ClassKey, y.ClassKey);

        public int GetHashCode((int OsPrefRank, string ClassKey) obj) =>
            HashCode.Combine(obj.OsPrefRank, StringComparer.OrdinalIgnoreCase.GetHashCode(obj.ClassKey));
    }
}
