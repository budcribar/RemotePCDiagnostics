using System.Buffers;
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
/// Built-in Framework Laptop/Desktop UEFI/BIOS update provider (<c>VendorId = "framework"</c>).
/// Queries LVFS AppStream (<c>fwupd.org</c> <c>.xml.gz</c>/XML) or Framework (<c>frame.work</c> JSON/XML)
/// metadata over HTTPS in 100% pure C#, verifies package integrity (SHA-256 / Authenticode),
/// suspends BitLocker for one reboot when requested, and stages silent <c>.exe</c> updaters or
/// <c>.cab</c> UEFI firmware capsules via <c>pnputil.exe</c> (routing through <see cref="IElevatedCommandBridge"/>
/// when running un-elevated).
/// </summary>
public sealed partial class FrameworkBiosUpdateProvider : IBiosUpdateProvider
{
    public const string ProviderVendorId = "framework";
    public const string DefaultCatalogUrl = "https://cdn.fwupd.org/downloads/firmware.xml.gz";
    public static readonly IReadOnlyList<string> AllowedHostSuffixes = ["fwupd.org", "frame.work"];

    public const long MaxCatalogCompressedBytes = 32L * 1024 * 1024;
    public const long MaxCatalogDecompressedBytes = 64L * 1024 * 1024;
    public const long MaxCabExtractBytes = 128L * 1024 * 1024;

    private const int MaxInitialStreamCapacity = 256 * 1024;
    private const int ReadBufferSize = 81920;
    private const int MaxArchivePathLength = 512;

    private static readonly TimeSpan DefaultInstallerTimeout = TimeSpan.FromMinutes(10);
    private static readonly HashSet<int> RebootSuccessExitCodes = [0, 3010];

    // Matches AgentBiosOperations.ForbiddenPathChars exactly.
    private static readonly char[] ForbiddenArchivePathChars =
        ['&', '|', ';', '>', '<', '`', '$', '%', '"', '\'', '^', '!', '*', '?'];

    private static readonly string[] NonBiosPeripheralKeywords =
    [
        "fingerprint",
        "retimer",
        "pd controller",
        "power delivery",
        "touchpad",
        "trackpad",
        "keyboard",
        "input module",
        "webcam",
        "camera",
        "audio",
        "ssd",
        "nvme",
        "wi-fi",
        "wifi",
        "wlan",
        "bluetooth",
        "dock",
        "expansion card",
        "display",
        "monitor",
        "ethernet",
        "mouse",
        "charger",
        "power adapter",
        "gpu module",
        "dgpu",
        "graphics module",
        "led matrix",
        "numpad",
        "macropad",
    ];

    private static readonly HashSet<string> StopWords = new(StringComparer.OrdinalIgnoreCase)
    {
        "framework",
        "the",
        "and",
        "for",
        "with",
        "edition",
        "series",
        "processor",
        "cpu",
        "mainboard",
        "system",
        "bios",
        "uefi",
        "firmware",
        "update",
        "gen",
    };

    [GeneratedRegex(@"^(?:Framework\s+)?(?:BIOS\s+Version|UEFI\s+Version|Firmware\s+Version|Version|Ver\.?|Rev\.?|BIOS|UEFI|v(?=\d|\s|[:\-]))\s*[:\-]?\s*", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex LeadingVersionPrefixRegex();

    [GeneratedRegex(@"^(\d+(?:\.\d+)*)([A-Za-z])?$", RegexOptions.CultureInvariant)]
    private static partial Regex FrameworkDottedVersionRegex();

    [GeneratedRegex(@"\b(?:beta|alpha|pre-?release|testing|development|dev-?build|rc\d*|engineering\s+sample|test\s+(?:bios|firmware))\b", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex FrameworkBetaTokenRegex();

    [GeneratedRegex(@"\blaptop\s*(12|13|16)\b", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex LaptopSizeRegex();

    [GeneratedRegex(@"\b(11|12|13)th\b", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex IntelGenRegex();

    [GeneratedRegex(@"\b(7040|ai\s*300)\b", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex AmdPlatformRegex();

    private readonly HttpClient _httpClient;
    private readonly SystemCommandRunner? _commands;
    private readonly IBiosSignatureVerifier _signatureVerifier;
    private readonly IElevatedCommandBridge? _elevatedBridge;
    private readonly Func<bool>? _isProcessElevated;
    private readonly ILogger? _log;
    private readonly string _catalogUrl;

    /// <summary>
    /// Creates a Framework BIOS/UEFI update provider. All parameters are optional so MS.DI
    /// resolves this single constructor cleanly with zero extra service registrations.
    /// </summary>
    public FrameworkBiosUpdateProvider(
        HttpClient? httpClient = null,
        SystemCommandRunner? commands = null,
        IBiosSignatureVerifier? signatureVerifier = null,
        IElevatedCommandBridge? elevatedBridge = null,
        Func<bool>? isProcessElevated = null,
        ILogger? log = null,
        string? catalogUrl = null)
    {
        _httpClient = httpClient ?? BiosProviderHttp.SharedClient;
        _commands = commands;
        _signatureVerifier = signatureVerifier ?? WinVerifyTrustSignatureVerifier.Instance;
        _elevatedBridge = elevatedBridge;
        _isProcessElevated = isProcessElevated;
        _log = log;
        _catalogUrl = string.IsNullOrWhiteSpace(catalogUrl)
            ? DefaultCatalogUrl
            : catalogUrl.Trim();
    }

    /// <summary>Creates a provider backed by a custom <see cref="HttpMessageHandler"/> (e.g., for offline tests).</summary>
    public static FrameworkBiosUpdateProvider CreateWithHandler(
        HttpMessageHandler httpHandler,
        SystemCommandRunner? commands = null,
        IBiosSignatureVerifier? signatureVerifier = null,
        IElevatedCommandBridge? elevatedBridge = null,
        Func<bool>? isProcessElevated = null,
        ILogger? log = null,
        string? catalogUrl = null) =>
        new(
            BiosProviderHttp.CreateClient(httpHandler),
            commands,
            signatureVerifier,
            elevatedBridge,
            isProcessElevated,
            log,
            catalogUrl);

    public string VendorId => ProviderVendorId;
    public string DisplayName => "Framework";
    public int Priority => 100;

    public BiosProviderCapabilities Capabilities { get; } = new(
        CanCheckLatest: true,
        CanInstall: true,
        SupportsSilentInstall: true,
        RequiresReboot: true,
        RequiresElevation: true,
        RequiresInternet: true);

    public bool CanHandle(BiosSystemIdentity system) =>
        system is not null && BiosVendorIdentity.IsFramework(system);

    public Task<BiosCurrentInfo> GetCurrentVersionAsync(BiosSystemIdentity system, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(system);
        ct.ThrowIfCancellationRequested();

        var current = system.CurrentBios ?? BiosCurrentInfo.Empty;
        var parsed = ParseFrameworkVersion(current.Version);
        var metadata = current.Metadata is not null
            ? new Dictionary<string, string>(current.Metadata, StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (!string.IsNullOrWhiteSpace(current.Version))
        {
            var rawTrimmed = current.Version.Trim();
            if (!string.Equals(rawTrimmed, parsed.NormalizedVersion, StringComparison.Ordinal))
                metadata["rawVersion"] = rawTrimmed;
        }

        if (TryResolveFrameworkIdentity(system, out var identity, out _))
        {
            if (!string.IsNullOrEmpty(identity.ModelToken))
                metadata["model"] = identity.ModelToken;
            if (!string.IsNullOrEmpty(identity.BoardToken))
                metadata["boardProduct"] = identity.BoardToken;
        }

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

        if (!TryResolveFrameworkIdentity(system, out var identity, out var reason))
        {
            return RedactLatestInfo(
                BiosLatestInfo.Unsupported(
                    VendorId,
                    $"Unable to determine a valid Framework hardware identifier: {reason}"),
                serial);
        }

        var isParameterizedEndpoint = EndpointPlaceholderRegex().IsMatch(_catalogUrl);
        var requestUrl = BuildCatalogUrl(_catalogUrl, identity.PrimaryToken);
        if (!TryValidateVendorUrl(requestUrl, AllowedHostSuffixes, out _))
        {
            LogWarn("Rejected disallowed Framework catalog URL before request.", serial);
            return RedactLatestInfo(
                BiosLatestInfo.Failed(
                    VendorId,
                    "Framework catalog URL failed HTTPS/domain allowlist validation."),
                serial);
        }

        try
        {
            using var response = await GetCatalogWithSafeRedirectsAsync(requestUrl, ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return RedactLatestInfo(
                    BiosProviderHttp.ClassifyHttpStatus(VendorId, DisplayName, response.StatusCode, $"model '{identity.PrimaryToken}'"),
                    serial);
            }

            var rawBytes = await ReadBoundedBytesAsync(
                response.Content,
                MaxCatalogCompressedBytes,
                MaxCatalogDecompressedBytes,
                ct).ConfigureAwait(false);

            byte[] payloadBytes;
            if (rawBytes.Length >= 2 && rawBytes[0] == 0x1F && rawBytes[1] == 0x8B)
            {
                if (rawBytes.Length > MaxCatalogCompressedBytes)
                {
                    throw new InvalidDataException(
                        $"Framework compressed catalog ({rawBytes.Length} bytes) exceeds maximum allowed limit ({MaxCatalogCompressedBytes} bytes).");
                }

                using var gzInput = new MemoryStream(rawBytes, writable: false);
                payloadBytes = await BiosArchiveAndXml.DecompressGzipBoundedAsync(gzInput, MaxCatalogDecompressedBytes, ct).ConfigureAwait(false);
            }
            else
            {
                payloadBytes = rawBytes;
            }

            var (offset, length) = StripUtf8Bom(payloadBytes);
            var firstNonWs = FindFirstNonWhitespaceByte(payloadBytes, offset, length);
            if (firstNonWs < 0)
                throw new InvalidDataException("Framework catalog response body is empty or whitespace.");

            var candidates = new List<FrameworkCatalogCandidate>();
            var untrusted = new List<FrameworkCatalogCandidate>();
            var sawOnlyBeta = false;
            var sawAnyRelease = false;

            if (payloadBytes[firstNonWs] == (byte)'<')
            {
                using var xmlStream = new MemoryStream(payloadBytes, offset, length, writable: false);
                var doc = BiosArchiveAndXml.ParseXmlSafe(xmlStream, MaxCatalogDecompressedBytes);
                ExtractCandidatesFromXml(
                    doc,
                    identity,
                    isParameterizedEndpoint,
                    serial,
                    candidates,
                    untrusted,
                    ref sawAnyRelease,
                    ref sawOnlyBeta);
            }
            else if (payloadBytes[firstNonWs] is (byte)'{' or (byte)'[')
            {
                using var doc = JsonDocument.Parse(
                    new ReadOnlyMemory<byte>(payloadBytes, offset, length),
                    new JsonDocumentOptions
                    {
                        MaxDepth = 64,
                        CommentHandling = JsonCommentHandling.Disallow,
                        AllowTrailingCommas = false,
                    });
                ExtractCandidatesFromJson(
                    doc.RootElement,
                    identity,
                    isParameterizedEndpoint,
                    serial,
                    candidates,
                    untrusted,
                    ref sawAnyRelease,
                    ref sawOnlyBeta);
            }
            else
            {
                throw new InvalidDataException("Framework catalog response was neither valid XML nor JSON.");
            }

            if (candidates.Count == 0)
            {
                if (untrusted.Count > 0)
                {
                    return RedactLatestInfo(
                        BiosLatestInfo.Failed(
                            VendorId,
                            $"Framework firmware catalog for '{identity.PrimaryToken}' contained only untrusted or unsupported download URLs."),
                        serial);
                }

                if (sawOnlyBeta && !sawAnyRelease)
                {
                    return RedactLatestInfo(
                        BiosLatestInfo.Unsupported(
                            VendorId,
                            $"Only beta or development Framework firmware entries were found for '{identity.PrimaryToken}'."),
                        serial);
                }

                return RedactLatestInfo(
                    BiosLatestInfo.Unsupported(
                        VendorId,
                        $"No matching Framework BIOS/UEFI firmware release was found for '{identity.PrimaryToken}'."),
                    serial);
            }

            var ordered = OrderCandidates(candidates);
            var best = ordered[0];

            var parsedCurrent = ParseFrameworkVersion(current.Version);
            var isNewer = IsCandidateNewer(parsedCurrent, current.ReleaseDate, best.ParsedVersion, best.ReleaseDate);

            if (untrusted.Count > 0)
            {
                foreach (var bad in untrusted)
                {
                    if (bad.MatchRank < best.MatchRank)
                        continue;

                    var untrustedOutranks = bad.MatchRank > best.MatchRank
                        || IsCandidateNewer(best.ParsedVersion, best.ReleaseDate, bad.ParsedVersion, bad.ReleaseDate);
                    if (!untrustedOutranks && !isNewer)
                    {
                        var cmpSame = CompareComparableVersions(bad.ParsedVersion, best.ParsedVersion);
                        if (cmpSame is null || cmpSame.Value >= 0)
                            untrustedOutranks = true;
                    }

                    if (untrustedOutranks)
                    {
                        LogWarn($"Rejected Framework catalog because a newer/competing release had an untrusted download URL for '{identity.PrimaryToken}'.", serial);
                        return RedactLatestInfo(
                            BiosLatestInfo.Failed(
                                VendorId,
                                $"Framework firmware catalog for '{identity.PrimaryToken}' contained an untrusted download URL for a competing release."),
                            serial);
                    }
                }
            }

            var isCab = best.DownloadUrl!.EndsWith(".cab", StringComparison.OrdinalIgnoreCase)
                        || (Uri.TryCreate(best.DownloadUrl, UriKind.Absolute, out var bestUri)
                            && bestUri.AbsolutePath.EndsWith(".cab", StringComparison.OrdinalIgnoreCase));

            var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["model"] = identity.PrimaryToken,
                ["installMode"] = isCab ? BiosAgentInstallModes.FrameworkCabCapsule : BiosAgentInstallModes.FrameworkBiosExe,
                ["packageFormat"] = isCab ? "cab" : "exe",
                ["source"] = best.Source,
            };

            if (!string.IsNullOrEmpty(identity.BoardToken))
                metadata["boardProduct"] = identity.BoardToken;

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
            LogWarn($"Framework BIOS catalog lookup failed: {ex.Message}", serial);
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
            const string msg = "Framework BIOS update target does not specify a download URL.";
            redactingProgress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, msg));
            return BiosInstallResult.Failed(msg, prev, target);
        }

        if (!TryValidateVendorUrl(request.Target.DownloadUrl, AllowedHostSuffixes, out var downloadUri))
        {
            const string msg = "Framework BIOS download URL failed HTTPS/domain allowlist (fwupd.org / frame.work) or path validation.";
            LogWarn(msg, serial);
            redactingProgress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, msg));
            return BiosInstallResult.Failed(msg, prev, target);
        }

        var urlExt = Path.GetExtension(downloadUri.AbsolutePath);
        bool isCab;
        string defaultFileName;
        string expectedExt;
        if (urlExt.Equals(".cab", StringComparison.OrdinalIgnoreCase))
        {
            isCab = true;
            expectedExt = ".cab";
            defaultFileName = "framework-bios-capsule.cab";
        }
        else if (urlExt.Equals(".exe", StringComparison.OrdinalIgnoreCase))
        {
            isCab = false;
            expectedExt = ".exe";
            defaultFileName = "framework-bios-update.exe";
        }
        else
        {
            const string msg = "Framework BIOS installer package must be a .cab firmware capsule or .exe updater.";
            LogWarn(msg, serial);
            redactingProgress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, msg));
            return BiosInstallResult.Failed(msg, prev, target);
        }

        string? autoStagingDir = null;
        string? cabExtractDir = null;
        var effectiveRequest = request;
        if (string.IsNullOrWhiteSpace(request.StagingDirectory))
        {
            autoStagingDir = Path.Combine(Path.GetTempPath(), $"rpd-bios-framework-{Guid.NewGuid():N}");
            effectiveRequest = request with { StagingDirectory = autoStagingDir };
        }
        else if (!ValidateStagingDirectorySafe(request.StagingDirectory, out var stagingErr))
        {
            var safeStagingErr = RedactText(stagingErr, serial);
            LogWarn(safeStagingErr, serial);
            redactingProgress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, safeStagingErr));
            return BiosInstallResult.Failed(safeStagingErr, prev, target);
        }

        var safeFileName = BuildSafePackageFileName(request.Target.DownloadUrl, defaultFileName, expectedExt);
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
            var verified = await DownloadAndVerifyFrameworkPackageAsync(
                effectiveRequest,
                resolvedStagingDir,
                safeFileName,
                expectedExt,
                redactingProgress,
                redactingLog,
                ct).ConfigureAwait(false);

            if (!verified.Succeeded || string.IsNullOrWhiteSpace(verified.FilePath))
            {
                var err = RedactText(
                    verified.ErrorMessage ?? "Framework BIOS package download or verification failed.",
                    serial);
                redactingProgress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, err));
                return BiosInstallResult.Failed(err, prev, target);
            }

            var packagePath = verified.FilePath;
            if (!Path.GetExtension(packagePath).Equals(expectedExt, StringComparison.OrdinalIgnoreCase))
            {
                TryDeleteFile(packagePath);
                var extErr = $"Downloaded Framework BIOS package did not have the expected '{expectedExt}' extension.";
                redactingProgress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, extErr));
                return BiosInstallResult.Failed(extErr, prev, target);
            }

            var expectedSha256 = !string.IsNullOrWhiteSpace(verified.ActualSha256)
                ? verified.ActualSha256.Trim().ToLowerInvariant()
                : (await BiosPackageVerifier.ComputeSha256HexAsync(packagePath, ct).ConfigureAwait(false)).Trim().ToLowerInvariant();

            IReadOnlyDictionary<string, byte[]>? validatedCabEntries = null;
            string? infRelativePath = null;

            if (isCab)
            {
                // Pre-validate the CAB archive BEFORE suspending BitLocker so corrupt/unsafe/INF-less
                // capsules never touch BitLocker, pnputil.exe, or the Agent, and always delete rejected CABs!
                var fileInfo = new FileInfo(packagePath);
                if (!fileInfo.Exists || fileInfo.Length == 0 || fileInfo.Length > MaxCabExtractBytes)
                {
                    TryDeleteFile(packagePath);
                    var sizeErr = $"Framework CAB capsule size is invalid or exceeds maximum allowed limit ({MaxCabExtractBytes} bytes).";
                    redactingProgress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, sizeErr));
                    return BiosInstallResult.Failed(sizeErr, prev, target);
                }

                var cabBytes = await File.ReadAllBytesAsync(packagePath, ct).ConfigureAwait(false);
                if (!BiosArchiveAndXml.TryExtractCabEntries(cabBytes, out var entries, MaxCabExtractBytes) || entries.Count == 0)
                {
                    TryDeleteFile(packagePath);
                    const string cabErr = "Framework CAB capsule could not be read or failed archive safety validation.";
                    LogWarn(cabErr, serial);
                    redactingProgress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, cabErr));
                    return BiosInstallResult.Failed(cabErr, prev, target);
                }

                if (!TryValidateCabEntriesAndSelectInf(entries, out var selectedInf, out var validationError))
                {
                    TryDeleteFile(packagePath);
                    var safeCabErr = RedactText(validationError, serial);
                    LogWarn(safeCabErr, serial);
                    redactingProgress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, safeCabErr));
                    return BiosInstallResult.Failed(safeCabErr, prev, target);
                }

                validatedCabEntries = entries;
                infRelativePath = selectedInf;
            }

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

            var elevated = _isProcessElevated is not null
                ? _isProcessElevated()
                : (_commands is not null ? _commands.IsProcessElevated : ElevationService.DetectProcessElevated());

            var runnerRequest = effectiveRequest with
            {
                Current = (effectiveRequest.Current ?? BiosCurrentInfo.Empty) with { Version = prev ?? "" },
                Target = effectiveRequest.Target with { LatestVersion = target },
            };

            BiosInstallResult result;

            if (isCab)
            {
                var agentRequest = new BiosAgentInstallRequest(
                    VendorId: VendorId,
                    InstallMode: BiosAgentInstallModes.FrameworkCabCapsule,
                    PackagePath: packagePath,
                    ExpectedSha256: expectedSha256,
                    AllowReboot: request.AllowReboot,
                    InfRelativePath: infRelativePath,
                    TimeoutMs: (int)DefaultInstallerTimeout.TotalMilliseconds);

                IReadOnlyList<string> arguments;
                string? workingDir;

                redactingProgress?.Report(new BiosInstallProgress(
                    BiosInstallStage.Staging,
                    0,
                    "Staging Framework UEFI firmware capsule…"));

                if (elevated)
                {
                    cabExtractDir = Path.Combine(effectiveRequest.StagingDirectory!, $"cab-extract-{Guid.NewGuid():N}");
                    if (!TryMaterializeCabEntriesSafe(
                            effectiveRequest.StagingDirectory!,
                            cabExtractDir,
                            validatedCabEntries!,
                            infRelativePath!,
                            out var extractedInfPath,
                            out var extractError))
                    {
                        var safeErr = RedactText(extractError, serial);
                        LogWarn(safeErr, serial);
                        redactingProgress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, safeErr));
                        return new BiosInstallResult(
                            Succeeded: false,
                            Status: BiosInstallStatus.Failed,
                            RequiresReboot: false,
                            BitLockerSuspended: bitLocker.Suspended,
                            PreviousVersion: prev,
                            TargetVersion: target,
                            Message: safeErr);
                    }

                    arguments = BiosAgentInstallModes.BuildArguments(
                        BiosAgentInstallModes.FrameworkCabCapsule,
                        request.AllowReboot,
                        extractedInfPath);
                    workingDir = cabExtractDir;
                }
                else
                {
                    // Do NOT write extracted CAB files on Host when un-elevated; Agent extracts into admin-only staging.
                    arguments = BiosAgentInstallModes.BuildArguments(
                        BiosAgentInstallModes.FrameworkCabCapsule,
                        request.AllowReboot,
                        infRelativePath);
                    workingDir = null;
                }

                redactingProgress?.Report(new BiosInstallProgress(
                    BiosInstallStage.Installing,
                    50,
                    "Installing Framework UEFI firmware capsule via pnputil.exe..."));

                result = await BiosInstallerRunner.RunInstallerAsync(
                    commands: _commands,
                    executablePath: SystemCommandRunner.SystemTool("pnputil.exe"),
                    arguments: arguments,
                    request: runnerRequest,
                    bitLockerSuspended: bitLocker.Suspended,
                    rebootSuccessExitCodes: RebootSuccessExitCodes,
                    completedSuccessExitCodes: null,
                    timeout: DefaultInstallerTimeout,
                    log: redactingLog,
                    ct: ct,
                    workingDirectory: workingDir,
                    agentRequest: agentRequest,
                    bridge: _elevatedBridge,
                    isProcessElevated: _isProcessElevated).ConfigureAwait(false);
            }
            else
            {
                var arguments = BiosAgentInstallModes.BuildArguments(
                    BiosAgentInstallModes.FrameworkBiosExe,
                    request.AllowReboot);

                var agentRequest = new BiosAgentInstallRequest(
                    VendorId: VendorId,
                    InstallMode: BiosAgentInstallModes.FrameworkBiosExe,
                    PackagePath: packagePath,
                    ExpectedSha256: expectedSha256,
                    AllowReboot: request.AllowReboot,
                    InfRelativePath: null,
                    TimeoutMs: (int)DefaultInstallerTimeout.TotalMilliseconds);

                redactingProgress?.Report(new BiosInstallProgress(
                    BiosInstallStage.Staging,
                    0,
                    "Staging Framework BIOS update…"));
                redactingProgress?.Report(new BiosInstallProgress(
                    BiosInstallStage.Installing,
                    50,
                    "Running Framework silent BIOS installer..."));

                result = await BiosInstallerRunner.RunInstallerAsync(
                    commands: _commands,
                    executablePath: packagePath,
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
            }

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
            if (cabExtractDir is not null)
                TryDeleteDirectoryRecursive(cabExtractDir);
            if (autoStagingDir is not null)
                TryDeleteDirectoryRecursive(autoStagingDir);
        }
    }

    // -------------------------------------------------------------------------
    // LVFS AppStream XML & frame.work XML/JSON parsing
    // -------------------------------------------------------------------------

    private void ExtractCandidatesFromXml(
        XDocument doc,
        FrameworkHardwareIdentity identity,
        bool isParameterizedEndpoint,
        string? serialNumber,
        List<FrameworkCatalogCandidate> candidates,
        List<FrameworkCatalogCandidate> untrusted,
        ref bool sawAnyRelease,
        ref bool sawOnlyBeta)
    {
        if (doc.Root is null)
            return;

        var components = doc.Root
            .DescendantsAndSelf()
            .Where(e => string.Equals(e.Name.LocalName, "component", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (components.Count > 0)
        {
            foreach (var comp in components)
            {
                var compType = comp.Attribute("type")?.Value?.Trim();
                if (!string.IsNullOrEmpty(compType)
                    && !compType.Equals("firmware", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var compId = GetChildText(comp, "id");
                var compName = GetChildText(comp, "name");
                var compSummary = GetChildText(comp, "summary");
                var developerName = GetChildText(comp, "developer_name")
                                    ?? comp.Elements()
                                        .FirstOrDefault(e => string.Equals(e.Name.LocalName, "developer", StringComparison.OrdinalIgnoreCase))
                                        ?.Elements()
                                        .FirstOrDefault(e => string.Equals(e.Name.LocalName, "name", StringComparison.OrdinalIgnoreCase))
                                        ?.Value?.Trim();

                if (!IsFrameworkComponent(developerName, compId, compName, compSummary, comp))
                    continue;

                var categories = comp.Elements()
                    .Where(e => string.Equals(e.Name.LocalName, "categories", StringComparison.OrdinalIgnoreCase))
                    .SelectMany(c => c.Elements())
                    .Select(e => e.Value?.Trim() ?? "")
                    .Where(s => s.Length > 0)
                    .ToList();

                if (IsPeripheralComponent(compId, compName, compSummary, categories))
                    continue;

                var componentTexts = CollectComponentMatchTexts(comp, compId, compName, compSummary);
                var matchRank = ComputeModelMatchRank(identity, componentTexts, allowOmittedMatch: false);
                if (matchRank <= 0)
                    continue;

                var compNotesUrl = ExtractComponentDetailsUrl(comp);

                var releaseElements = comp.Elements()
                    .Where(e => string.Equals(e.Name.LocalName, "releases", StringComparison.OrdinalIgnoreCase))
                    .SelectMany(r => r.Elements())
                    .Where(e => string.Equals(e.Name.LocalName, "release", StringComparison.OrdinalIgnoreCase))
                    .ToList();

                foreach (var rel in releaseElements)
                {
                    ParseLvfsReleaseElement(
                        rel,
                        compId,
                        compName,
                        compSummary,
                        compNotesUrl,
                        matchRank,
                        serialNumber,
                        candidates,
                        untrusted,
                        ref sawAnyRelease,
                        ref sawOnlyBeta);
                }
            }

            return;
        }

        // Fallback: simple frame.work XML (<Releases>/<Release>, <Packages>/<Package>, <Firmware>/<Update>)
        var simpleReleases = doc.Root
            .DescendantsAndSelf()
            .Where(e => e.Name.LocalName.Equals("release", StringComparison.OrdinalIgnoreCase)
                        || e.Name.LocalName.Equals("package", StringComparison.OrdinalIgnoreCase)
                        || e.Name.LocalName.Equals("update", StringComparison.OrdinalIgnoreCase)
                        || e.Name.LocalName.Equals("firmware", StringComparison.OrdinalIgnoreCase))
            .ToList();

        foreach (var rel in simpleReleases)
        {
            var rawVersion = GetXmlField(rel, "version", "biosVersion", "firmwareVersion");
            if (string.IsNullOrWhiteSpace(rawVersion))
                continue;

            var title = GetXmlField(rel, "title", "name");
            var description = GetXmlField(rel, "description", "summary", "notes");
            var category = GetXmlField(rel, "category", "type");
            if (IsPeripheralComponent(null, title, $"{category} {description}", []))
                continue;

            var modelField = GetXmlField(rel, "model", "product", "board", "boardProduct", "sku");
            var texts = new List<string>();
            if (!string.IsNullOrWhiteSpace(modelField))
                texts.Add(modelField);
            if (!string.IsNullOrWhiteSpace(title))
                texts.Add(title);

            var matchRank = ComputeModelMatchRank(
                identity,
                texts,
                allowOmittedMatch: isParameterizedEndpoint && string.IsNullOrWhiteSpace(modelField));
            if (matchRank <= 0)
                continue;

            var isBeta = ParseNullableBoolString(GetXmlField(rel, "isBeta", "beta", "preRelease"));
            var isRelease = ParseNullableBoolString(GetXmlField(rel, "isRelease", "stable"));
            if (IsBetaRelease(rawVersion, title, description, isRelease, isBeta, null, null))
            {
                sawOnlyBeta = true;
                continue;
            }

            sawAnyRelease = true;
            var parsedVersion = ParseFrameworkVersion(rawVersion);
            if (parsedVersion.Class == VersionClass.Empty)
                continue;

            var rawUrl = GetXmlField(rel, "downloadUrl", "url", "location", "packageUrl", "fileUrl");
            var urlState = UrlExtractionState.Absent;
            string? validatedUrl = null;
            if (!string.IsNullOrWhiteSpace(rawUrl))
            {
                if (TryValidateFrameworkPackageUrl(rawUrl, out var valid))
                {
                    validatedUrl = valid;
                    urlState = UrlExtractionState.Valid;
                }
                else
                {
                    urlState = UrlExtractionState.Untrusted;
                }
            }

            var releaseDate = TryParseReleaseDate(GetXmlField(rel, "releaseDate", "date", "publishedDate"))
                              ?? TryParseUnixTimestamp(GetXmlField(rel, "timestamp"));
            var sha256 = TryNormalizeSha256(GetXmlField(rel, "sha256", "checksum", "hash"));
            var sizeBytes = TryParseSizeString(GetXmlField(rel, "sizeBytes", "size", "fileSize"));
            var packageId = GetXmlField(rel, "packageId", "id", "releaseId");
            var severity = ParseSeverity(GetXmlField(rel, "urgency", "severity"), ParseNullableBoolString(GetXmlField(rel, "isCritical", "critical")), title, description);
            var summary = CleanReleaseSummary(title, description);

            var rawNotes = GetXmlField(rel, "releaseNotesUrl", "detailsUrl", "infoUrl");
            string? notesUrl = null;
            if (!string.IsNullOrWhiteSpace(rawNotes) && TryValidateVendorUrl(rawNotes, AllowedHostSuffixes, out var parsedNotes))
                notesUrl = parsedNotes.AbsoluteUri;

            var candidate = new FrameworkCatalogCandidate(
                DisplayVersion: parsedVersion.DisplayVersion,
                ParsedVersion: parsedVersion,
                MatchRank: matchRank,
                ReleaseDate: releaseDate,
                Severity: severity,
                PackageId: packageId,
                ReleaseSummary: summary,
                ReleaseNotesUrl: notesUrl,
                DownloadUrl: validatedUrl,
                Sha256: sha256,
                SizeBytes: sizeBytes,
                Source: "framework-xml");

            if (urlState == UrlExtractionState.Valid)
                candidates.Add(candidate);
            else if (urlState == UrlExtractionState.Untrusted)
            {
                LogWarn($"Ignoring Framework XML entry '{parsedVersion.DisplayVersion}' with untrusted download URL.", serialNumber);
                untrusted.Add(candidate);
            }
        }
    }

    private void ParseLvfsReleaseElement(
        XElement rel,
        string? compId,
        string? compName,
        string? compSummary,
        string? compNotesUrl,
        int matchRank,
        string? serialNumber,
        List<FrameworkCatalogCandidate> candidates,
        List<FrameworkCatalogCandidate> untrusted,
        ref bool sawAnyRelease,
        ref bool sawOnlyBeta)
    {
        var rawVersion = rel.Attribute("version")?.Value?.Trim() ?? GetChildText(rel, "version");
        if (string.IsNullOrWhiteSpace(rawVersion))
            return;

        var relType = rel.Attribute("type")?.Value?.Trim();
        var relBranch = rel.Attribute("branch")?.Value?.Trim();
        var relDesc = ExtractXmlDescriptionText(rel);

        if (IsBetaRelease(rawVersion, compName, relDesc, isReleaseFlag: null, isBetaFlag: null, relType: relType, relBranch: relBranch))
        {
            sawOnlyBeta = true;
            return;
        }

        sawAnyRelease = true;
        var parsedVersion = ParseFrameworkVersion(rawVersion);
        if (parsedVersion.Class == VersionClass.Empty)
            return;

        var releaseDate = TryParseReleaseDate(rel.Attribute("date")?.Value)
                          ?? TryParseUnixTimestamp(rel.Attribute("timestamp")?.Value);
        var urgency = rel.Attribute("urgency")?.Value?.Trim();
        var severity = ParseSeverity(urgency, null, compName, relDesc);

        string? releaseNotesUrl = compNotesUrl;
        foreach (var urlEl in rel.Elements().Where(e => string.Equals(e.Name.LocalName, "url", StringComparison.OrdinalIgnoreCase)))
        {
            var urlType = urlEl.Attribute("type")?.Value?.Trim();
            if (string.IsNullOrEmpty(urlType)
                || urlType.Equals("details", StringComparison.OrdinalIgnoreCase)
                || urlType.Equals("homepage", StringComparison.OrdinalIgnoreCase))
            {
                var candidateUrl = urlEl.Value?.Trim();
                if (!string.IsNullOrWhiteSpace(candidateUrl)
                    && TryValidateVendorUrl(candidateUrl, AllowedHostSuffixes, out var validNotes))
                {
                    releaseNotesUrl = validNotes.AbsoluteUri;
                    break;
                }
            }
        }

        // Extract artifact URL, container SHA-256 (NEVER target="content"), and download size.
        var (urlState, downloadUrl, sha256, sizeBytes) = ExtractLvfsReleaseArtifact(rel);

        var packageId = !string.IsNullOrWhiteSpace(compId)
            ? $"{compId}:{parsedVersion.DisplayVersion}"
            : parsedVersion.DisplayVersion;

        var summary = CleanReleaseSummary(compName ?? compSummary, relDesc);

        var candidate = new FrameworkCatalogCandidate(
            DisplayVersion: parsedVersion.DisplayVersion,
            ParsedVersion: parsedVersion,
            MatchRank: matchRank,
            ReleaseDate: releaseDate,
            Severity: severity,
            PackageId: packageId,
            ReleaseSummary: summary,
            ReleaseNotesUrl: releaseNotesUrl,
            DownloadUrl: downloadUrl,
            Sha256: sha256,
            SizeBytes: sizeBytes,
            Source: "lvfs");

        if (urlState == UrlExtractionState.Valid)
        {
            candidates.Add(candidate);
        }
        else if (urlState == UrlExtractionState.Untrusted)
        {
            LogWarn($"Ignoring LVFS release '{parsedVersion.DisplayVersion}' with untrusted or unsupported download URL.", serialNumber);
            untrusted.Add(candidate);
        }
    }

    private static (UrlExtractionState State, string? Url, string? Sha256, long? SizeBytes) ExtractLvfsReleaseArtifact(XElement rel)
    {
        var sawUntrusted = false;

        // AppStream 1.0: <artifacts><artifact type="binary">...
        var artifacts = rel.Elements()
            .Where(e => string.Equals(e.Name.LocalName, "artifacts", StringComparison.OrdinalIgnoreCase))
            .SelectMany(a => a.Elements())
            .Where(e => string.Equals(e.Name.LocalName, "artifact", StringComparison.OrdinalIgnoreCase))
            .ToList();

        // Order binary/untyped artifacts before any other artifact types (e.g., source).
        var orderedArtifacts = artifacts
            .Where(a =>
            {
                var t = a.Attribute("type")?.Value?.Trim();
                return string.IsNullOrEmpty(t) || t.Equals("binary", StringComparison.OrdinalIgnoreCase);
            })
            .ToList();

        foreach (var artifact in orderedArtifacts)
        {
            var locElements = artifact.Elements()
                .Where(e => string.Equals(e.Name.LocalName, "location", StringComparison.OrdinalIgnoreCase))
                .ToList();

            string? validUrl = null;
            foreach (var loc in locElements)
            {
                var raw = loc.Value?.Trim();
                if (string.IsNullOrEmpty(raw))
                    continue;

                if (TryValidateFrameworkPackageUrl(raw, out var okUrl))
                {
                    validUrl = okUrl;
                    break;
                }

                sawUntrusted = true;
            }

            if (validUrl is not null)
            {
                var sha = ExtractContainerSha256(artifact) ?? ExtractContainerSha256(rel);
                var size = ExtractDownloadSize(artifact) ?? ExtractDownloadSize(rel);
                return (UrlExtractionState.Valid, validUrl, sha, size);
            }
        }

        // AppStream 0.x: direct <location> child of <release>
        var directLocs = rel.Elements()
            .Where(e => string.Equals(e.Name.LocalName, "location", StringComparison.OrdinalIgnoreCase))
            .ToList();

        foreach (var loc in directLocs)
        {
            var raw = loc.Value?.Trim();
            if (string.IsNullOrEmpty(raw))
                continue;

            if (TryValidateFrameworkPackageUrl(raw, out var okUrl))
            {
                var sha = ExtractContainerSha256(rel);
                var size = ExtractDownloadSize(rel);
                return (UrlExtractionState.Valid, okUrl, sha, size);
            }

            sawUntrusted = true;
        }

        return (sawUntrusted ? UrlExtractionState.Untrusted : UrlExtractionState.Absent, null, null, null);
    }

    /// <summary>
    /// Extracts a SHA-256 checksum for the outer container (<c>.cab</c>/<c>.exe</c>) ONLY.
    /// Explicitly prefers <c>target="container"</c>, accepts omitted <c>target</c>,
    /// and NEVER accepts <c>target="content"</c> (which is the inner <c>firmware.bin</c> hash).
    /// </summary>
    private static string? ExtractContainerSha256(XElement parent)
    {
        string? fallbackNoTarget = null;
        foreach (var cs in parent.Elements().Where(e => string.Equals(e.Name.LocalName, "checksum", StringComparison.OrdinalIgnoreCase)))
        {
            var typeAttr = cs.Attribute("type")?.Value?.Trim();
            if (!string.Equals(typeAttr, "sha256", StringComparison.OrdinalIgnoreCase))
                continue;

            var targetAttr = cs.Attribute("target")?.Value?.Trim();
            if (string.Equals(targetAttr, "content", StringComparison.OrdinalIgnoreCase))
                continue; // NEVER use inner payload hash as container hash!

            var normalized = TryNormalizeSha256(cs.Value);
            if (normalized is null)
                continue;

            if (string.Equals(targetAttr, "container", StringComparison.OrdinalIgnoreCase))
                return normalized;

            if (string.IsNullOrEmpty(targetAttr) && fallbackNoTarget is null)
                fallbackNoTarget = normalized;
        }

        return fallbackNoTarget;
    }

    private static long? ExtractDownloadSize(XElement parent)
    {
        foreach (var sz in parent.Elements().Where(e => string.Equals(e.Name.LocalName, "size", StringComparison.OrdinalIgnoreCase)))
        {
            var typeAttr = sz.Attribute("type")?.Value?.Trim();
            if (string.Equals(typeAttr, "installed", StringComparison.OrdinalIgnoreCase))
                continue;

            if (string.IsNullOrEmpty(typeAttr) || string.Equals(typeAttr, "download", StringComparison.OrdinalIgnoreCase))
            {
                var parsed = TryParseSizeString(sz.Value);
                if (parsed.HasValue)
                    return parsed;
            }
        }

        return null;
    }

    private static string? ExtractXmlDescriptionText(XElement rel)
    {
        var desc = rel.Elements().FirstOrDefault(e => string.Equals(e.Name.LocalName, "description", StringComparison.OrdinalIgnoreCase));
        if (desc is null)
            return null;

        var parts = desc.DescendantNodes()
            .OfType<XText>()
            .Select(t => t.Value.Trim())
            .Where(s => s.Length > 0)
            .ToList();

        return parts.Count > 0 ? string.Join(" ", parts) : null;
    }

    private static string? ExtractComponentDetailsUrl(XElement comp)
    {
        foreach (var urlEl in comp.Elements().Where(e => string.Equals(e.Name.LocalName, "url", StringComparison.OrdinalIgnoreCase)))
        {
            var urlType = urlEl.Attribute("type")?.Value?.Trim();
            if (string.Equals(urlType, "details", StringComparison.OrdinalIgnoreCase)
                || string.Equals(urlType, "homepage", StringComparison.OrdinalIgnoreCase)
                || string.IsNullOrEmpty(urlType))
            {
                var raw = urlEl.Value?.Trim();
                if (!string.IsNullOrWhiteSpace(raw)
                    && TryValidateVendorUrl(raw, AllowedHostSuffixes, out var valid))
                {
                    return valid.AbsoluteUri;
                }
            }
        }

        return null;
    }

    private void ExtractCandidatesFromJson(
        JsonElement root,
        FrameworkHardwareIdentity identity,
        bool isParameterizedEndpoint,
        string? serialNumber,
        List<FrameworkCatalogCandidate> candidates,
        List<FrameworkCatalogCandidate> untrusted,
        ref bool sawAnyRelease,
        ref bool sawOnlyBeta)
    {
        var items = new List<JsonElement>();
        CollectJsonReleaseObjects(root, items, depth: 0);

        foreach (var item in items)
        {
            if (item.ValueKind != JsonValueKind.Object)
                continue;

            var vendor = GetStringOrNumber(item, "vendor", "developer", "manufacturer");
            if (!string.IsNullOrWhiteSpace(vendor)
                && !BiosVendorIdentity.MatchesVendorToken(vendor, "Framework"))
            {
                continue;
            }

            var category = GetStringOrNumber(item, "category", "type", "componentType");
            var title = GetStringOrNumber(item, "title", "name", "displayName", "componentName");
            var description = GetStringOrNumber(item, "description", "releaseSummary", "summary", "notes", "releaseNotes");

            if (IsPeripheralComponent(GetStringOrNumber(item, "componentId"), title, $"{category} {description}", []))
                continue;

            var modelTexts = CollectJsonModelTexts(item, title);
            var hasExplicitModelField = modelTexts.HasExplicitModelField;
            var matchRank = ComputeModelMatchRank(
                identity,
                modelTexts.Texts,
                allowOmittedMatch: isParameterizedEndpoint && !hasExplicitModelField);
            if (matchRank <= 0)
                continue;

            var rawVersion = GetStringOrNumber(item, "biosVersion", "firmwareVersion", "uefiVersion", "version");
            var isBeta = GetNullableBool(item, "isBeta", "beta", "isPreRelease", "preRelease");
            var isRelease = GetNullableBool(item, "isRelease", "stable");
            var relType = GetStringOrNumber(item, "releaseType", "channel", "branch");

            if (IsBetaRelease(rawVersion, title, description, isRelease, isBeta, relType, relType))
            {
                sawOnlyBeta = true;
                continue;
            }

            if (string.IsNullOrWhiteSpace(rawVersion))
                continue;

            sawAnyRelease = true;
            var parsedVersion = ParseFrameworkVersion(rawVersion);
            if (parsedVersion.Class == VersionClass.Empty)
                continue;

            var urlState = TryExtractPackageUrlFromJson(item, out var downloadUrl);
            var releaseDate = TryParseReleaseDate(GetStringOrNumber(item, "releaseDate", "date", "publishedDate", "publishDate"))
                              ?? TryParseUnixTimestamp(GetStringOrNumber(item, "timestamp"));
            var sha256 = TryNormalizeSha256(GetStringOrNumber(item, "sha256", "containerSha256", "sha256Hash", "checksum", "hash"));
            var sizeBytes = TryParseSizeBytes(item, "sizeBytes", "downloadSize", "fileSize", "size");
            var packageId = GetStringOrNumber(item, "packageId", "id", "releaseId", "componentId");
            var severity = ParseSeverity(
                GetStringOrNumber(item, "urgency", "severity", "criticality"),
                GetNullableBool(item, "isCritical", "critical", "security"),
                title,
                description);
            var summary = CleanReleaseSummary(title, description);

            var rawNotes = GetStringOrNumber(item, "releaseNotesUrl", "detailsUrl", "infoUrl", "changelogUrl");
            string? notesUrl = null;
            if (!string.IsNullOrWhiteSpace(rawNotes) && TryValidateVendorUrl(rawNotes, AllowedHostSuffixes, out var parsedNotes))
                notesUrl = parsedNotes.AbsoluteUri;

            var candidate = new FrameworkCatalogCandidate(
                DisplayVersion: parsedVersion.DisplayVersion,
                ParsedVersion: parsedVersion,
                MatchRank: matchRank,
                ReleaseDate: releaseDate,
                Severity: severity,
                PackageId: packageId,
                ReleaseSummary: summary,
                ReleaseNotesUrl: notesUrl,
                DownloadUrl: downloadUrl,
                Sha256: sha256,
                SizeBytes: sizeBytes,
                Source: "framework-json");

            if (urlState == UrlExtractionState.Valid)
            {
                candidates.Add(candidate);
            }
            else if (urlState == UrlExtractionState.Untrusted)
            {
                LogWarn($"Ignoring Framework JSON entry '{parsedVersion.DisplayVersion}' with untrusted or unsupported download URL.", serialNumber);
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

        string[] arrayKeys =
        [
            "releases", "bios", "firmware", "items", "data",
            "packages", "products", "models", "updates", "results",
        ];

        var foundCollection = false;
        foreach (var key in arrayKeys)
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

        if (TryGetPropertyIgnoreCase(element, out _, "biosVersion", "firmwareVersion", "uefiVersion", "version"))
            output.Add(element);
    }

    private static (List<string> Texts, bool HasExplicitModelField) CollectJsonModelTexts(JsonElement item, string? title)
    {
        var texts = new List<string>();
        var hasExplicit = false;

        string[] modelKeys = ["model", "models", "product", "products", "board", "boardProduct", "boards", "sku", "skus", "hardware", "keywords"];
        foreach (var key in modelKeys)
        {
            if (!TryGetPropertyIgnoreCase(item, out var el, key))
                continue;

            if (el.ValueKind == JsonValueKind.String)
            {
                var s = el.GetString()?.Trim();
                if (!string.IsNullOrEmpty(s))
                {
                    texts.Add(s);
                    hasExplicit = true;
                }
            }
            else if (el.ValueKind == JsonValueKind.Array)
            {
                foreach (var entry in el.EnumerateArray())
                {
                    if (entry.ValueKind == JsonValueKind.String)
                    {
                        var s = entry.GetString()?.Trim();
                        if (!string.IsNullOrEmpty(s))
                        {
                            texts.Add(s);
                            hasExplicit = true;
                        }
                    }
                }
            }
        }

        if (!string.IsNullOrWhiteSpace(title))
            texts.Add(title);

        return (texts, hasExplicit);
    }

    private UrlExtractionState TryExtractPackageUrlFromJson(JsonElement item, out string? validatedUrl)
    {
        validatedUrl = null;
        string[] explicitDownloadKeys = ["downloadUrl", "download_url", "packageUrl", "cabUrl", "exeUrl", "installerUrl", "fileUrl"];
        string[] fallbackUrlKeys = ["url", "location", "link"];
        var sawUntrusted = false;

        foreach (var key in explicitDownloadKeys)
        {
            if (!TryGetPropertyIgnoreCase(item, out var prop, key))
                continue;

            var propState = TryExtractPackageUrlFromJsonProperty(prop, out var valid);
            if (propState == UrlExtractionState.Valid)
            {
                validatedUrl = valid;
                return UrlExtractionState.Valid;
            }

            if (propState == UrlExtractionState.Untrusted)
            {
                // Fail closed when an explicit download URL property is poisoned/untrusted
                // or has an invalid JSON value kind rather than falling back to a secondary "url" property.
                return UrlExtractionState.Untrusted;
            }
        }

        foreach (var key in fallbackUrlKeys)
        {
            if (!TryGetPropertyIgnoreCase(item, out var prop, key))
                continue;

            var propState = TryExtractPackageUrlFromJsonProperty(prop, out var valid);
            if (propState == UrlExtractionState.Valid)
            {
                validatedUrl = valid;
                return UrlExtractionState.Valid;
            }

            if (propState == UrlExtractionState.Untrusted)
                sawUntrusted = true;
        }

        return sawUntrusted ? UrlExtractionState.Untrusted : UrlExtractionState.Absent;
    }

    private static UrlExtractionState TryExtractPackageUrlFromJsonProperty(JsonElement prop, out string? validatedUrl)
    {
        validatedUrl = null;
        if (prop.ValueKind == JsonValueKind.String)
        {
            var raw = prop.GetString()?.Trim();
            if (string.IsNullOrEmpty(raw))
                return UrlExtractionState.Absent;

            if (TryValidateFrameworkPackageUrl(raw, out var valid))
            {
                validatedUrl = valid;
                return UrlExtractionState.Valid;
            }

            return UrlExtractionState.Untrusted;
        }

        if (prop.ValueKind == JsonValueKind.Object)
        {
            if (TryGetPropertyIgnoreCase(prop, out var nested, "url", "href", "downloadUrl", "location"))
            {
                if (nested.ValueKind == JsonValueKind.String)
                {
                    var raw = nested.GetString()?.Trim();
                    if (string.IsNullOrEmpty(raw))
                        return UrlExtractionState.Absent;

                    if (TryValidateFrameworkPackageUrl(raw, out var valid))
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

        return UrlExtractionState.Untrusted;
    }

    private static bool TryValidateFrameworkPackageUrl(string rawUrl, out string validatedUrl)
    {
        validatedUrl = "";
        if (!TryValidateVendorUrl(rawUrl, AllowedHostSuffixes, out var uri))
            return false;

        var ext = Path.GetExtension(uri.AbsolutePath);
        if (!ext.Equals(".cab", StringComparison.OrdinalIgnoreCase)
            && !ext.Equals(".exe", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        validatedUrl = uri.AbsoluteUri;
        return true;
    }

    // -------------------------------------------------------------------------
    // Component vendor / peripheral / model matching & anti-cross-model guard
    // -------------------------------------------------------------------------

    private static bool IsFrameworkComponent(
        string? developerName,
        string? compId,
        string? compName,
        string? compSummary,
        XElement comp)
    {
        if (!string.IsNullOrWhiteSpace(developerName))
            return BiosVendorIdentity.MatchesVendorToken(developerName, "Framework");

        if (!string.IsNullOrWhiteSpace(compId)
            && (compId.Contains("framework", StringComparison.OrdinalIgnoreCase)
                || compId.Contains("frame.work", StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        if (BiosVendorIdentity.MatchesVendorToken(compName, "Framework")
            || BiosVendorIdentity.MatchesVendorToken(compSummary, "Framework"))
        {
            return true;
        }

        foreach (var text in comp.Descendants().Select(e => e.Value))
        {
            if (!string.IsNullOrWhiteSpace(text)
                && (text.Contains("FRAN", StringComparison.OrdinalIgnoreCase)
                    || BiosVendorIdentity.MatchesVendorToken(text, "Framework")))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsPeripheralComponent(
        string? compId,
        string? compName,
        string? compSummary,
        IReadOnlyList<string> categories)
    {
        var nameText = compName?.Trim() ?? "";
        var idText = compId?.Trim() ?? "";
        var nameExplicitlySystemBios =
            nameText.Contains("system firmware", StringComparison.OrdinalIgnoreCase)
            || nameText.Contains("system bios", StringComparison.OrdinalIgnoreCase);

        // Inspect component name and ID independently of <summary> so a peripheral mentioning
        // "UEFI" or "BIOS" in <summary> (e.g., "Fingerprint reader update for UEFI systems")
        // is still rejected as a peripheral.
        if (!nameExplicitlySystemBios)
        {
            if (nameText.Length > 0 && ContainsAnyKeyword(nameText, NonBiosPeripheralKeywords))
                return true;

            if (idText.Length > 0 && ContainsAnyKeyword(idText, NonBiosPeripheralKeywords))
                return true;
        }

        var combined = $"{idText} {nameText} {compSummary} {string.Join(' ', categories)}".Trim();
        if (combined.Length == 0)
            return false;

        var clearlySystemBios =
            nameExplicitlySystemBios
            || combined.Contains("system firmware", StringComparison.OrdinalIgnoreCase)
            || combined.Contains("system bios", StringComparison.OrdinalIgnoreCase)
            || combined.Contains("uefi", StringComparison.OrdinalIgnoreCase)
            || MatchesKeywordPhrase(combined, "bios");

        if (ContainsAnyKeyword(combined, NonBiosPeripheralKeywords) && !clearlySystemBios)
            return true;

        return false;
    }

    private static List<string> CollectComponentMatchTexts(XElement comp, string? compId, string? compName, string? compSummary)
    {
        var list = new List<string>();
        if (!string.IsNullOrWhiteSpace(compId)) list.Add(compId);
        if (!string.IsNullOrWhiteSpace(compName)) list.Add(compName);
        if (!string.IsNullOrWhiteSpace(compSummary)) list.Add(compSummary);

        foreach (var el in comp.Elements())
        {
            var local = el.Name.LocalName;
            if (local.Equals("keywords", StringComparison.OrdinalIgnoreCase)
                || local.Equals("custom", StringComparison.OrdinalIgnoreCase)
                || local.Equals("provides", StringComparison.OrdinalIgnoreCase)
                || local.Equals("requires", StringComparison.OrdinalIgnoreCase))
            {
                foreach (var child in el.Elements())
                {
                    var val = child.Value?.Trim();
                    if (!string.IsNullOrEmpty(val))
                        list.Add(val);
                }
            }
        }

        return list;
    }

    /// <summary>
    /// Computes match rank:
    /// 3 = exact BoardProduct / SystemSku token match,
    /// 2 = exact normalized Model phrase match,
    /// 1 = all significant model tokens present with zero cross-model conflicts (or parameterized fallback),
    /// 0 = no match / cross-model conflict.
    /// </summary>
    internal static int ComputeModelMatchRank(
        FrameworkHardwareIdentity identity,
        IReadOnlyList<string> componentTexts,
        bool allowOmittedMatch)
    {
        if (componentTexts.Count == 0)
            return allowOmittedMatch ? 1 : 0;

        var combinedRaw = string.Join(" ", componentTexts);
        var combinedNorm = NormalizeForModelMatch(combinedRaw);

        // 1. Anti-cross-model discriminator conflict guard (Laptop 13 vs 16, Desktop vs Laptop, AMD vs Intel, Intel gen, AMD platform).
        if (HasCrossModelConflict(identity.CombinedNormalized, combinedNorm))
            return 0;

        // 2. Rank 3: Exact BoardProduct or SystemSku token match (e.g., FRANMDCP07).
        foreach (var code in identity.BoardOrSkuTokens)
        {
            if (code.Length >= 4 && MatchesTokenNormalized(combinedNorm, NormalizeForModelMatch(code)))
                return 3;
        }

        // 3. Rank 2: Exact normalized Model phrase match (e.g., "laptop 13 amd ryzen 7040 series").
        if (!string.IsNullOrEmpty(identity.ModelNormalized)
            && combinedNorm.Contains(identity.ModelNormalized, StringComparison.Ordinal))
        {
            return 2;
        }

        // 4. Rank 1: All significant model tokens present in component text.
        if (identity.SignificantModelTokens.Count > 0)
        {
            var compTokenSet = new HashSet<string>(
                combinedNorm.Split(' ', StringSplitOptions.RemoveEmptyEntries),
                StringComparer.Ordinal);

            var allMatched = true;
            foreach (var tok in identity.SignificantModelTokens)
            {
                if (!compTokenSet.Contains(tok))
                {
                    allMatched = false;
                    break;
                }
            }

            if (allMatched)
                return 1;
        }

        return allowOmittedMatch ? 1 : 0;
    }

    private static bool HasCrossModelConflict(string systemNorm, string componentNorm)
    {
        // Laptop size conflict: Laptop 13 vs Laptop 16 vs Laptop 12.
        var sysSize = LaptopSizeRegex().Match(systemNorm);
        var compSize = LaptopSizeRegex().Match(componentNorm);
        if (sysSize.Success && compSize.Success
            && !string.Equals(sysSize.Groups[1].Value, compSize.Groups[1].Value, StringComparison.Ordinal))
        {
            return true;
        }

        // Desktop vs Laptop conflict.
        var sysDesktop = MatchesTokenNormalized(systemNorm, "desktop");
        var sysLaptop = MatchesTokenNormalized(systemNorm, "laptop");
        var compDesktop = MatchesTokenNormalized(componentNorm, "desktop");
        var compLaptop = MatchesTokenNormalized(componentNorm, "laptop");
        if ((sysDesktop && compLaptop && !compDesktop) || (sysLaptop && compDesktop && !compLaptop))
            return true;

        // CPU vendor conflict: AMD / Ryzen vs Intel / Core.
        var sysAmd = MatchesTokenNormalized(systemNorm, "amd") || MatchesTokenNormalized(systemNorm, "ryzen");
        var sysIntel = MatchesTokenNormalized(systemNorm, "intel") || MatchesTokenNormalized(systemNorm, "core");
        var compAmd = MatchesTokenNormalized(componentNorm, "amd") || MatchesTokenNormalized(componentNorm, "ryzen");
        var compIntel = MatchesTokenNormalized(componentNorm, "intel") || MatchesTokenNormalized(componentNorm, "core");
        if ((sysAmd && !sysIntel && compIntel && !compAmd)
            || (sysIntel && !sysAmd && compAmd && !compIntel))
        {
            return true;
        }

        // Intel generation conflict: 11th vs 12th vs 13th vs Core Ultra.
        var sysGen = IntelGenRegex().Match(systemNorm);
        var compGen = IntelGenRegex().Match(componentNorm);
        if (sysGen.Success && compGen.Success
            && !string.Equals(sysGen.Groups[1].Value, compGen.Groups[1].Value, StringComparison.Ordinal))
        {
            return true;
        }

        var sysUltra = MatchesTokenNormalized(systemNorm, "ultra");
        var compUltra = MatchesTokenNormalized(componentNorm, "ultra");
        if ((sysUltra && compGen.Success && !compUltra) || (compUltra && sysGen.Success && !sysUltra))
            return true;

        // AMD platform conflict: 7040 vs AI 300.
        var sysAmdPlat = AmdPlatformRegex().Match(systemNorm);
        var compAmdPlat = AmdPlatformRegex().Match(componentNorm);
        if (sysAmdPlat.Success && compAmdPlat.Success)
        {
            var sVal = WhitespaceRegex().Replace(sysAmdPlat.Groups[1].Value, "");
            var cVal = WhitespaceRegex().Replace(compAmdPlat.Groups[1].Value, "");
            if (!string.Equals(sVal, cVal, StringComparison.Ordinal))
                return true;
        }

        return false;
    }

    /// <summary>
    /// Normalizes model/component strings by lowercasing, replacing punctuation/parentheses with spaces,
    /// splitting digit-to-letter boundaries (so <c>7040Series</c> matches <c>7040 Series</c>),
    /// while preserving ordinal suffixes like <c>12th</c>/<c>13th</c>.
    /// </summary>
    internal static string NormalizeForModelMatch(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return "";

        var sb = new StringBuilder(raw.Length + 8);
        var prevSpace = true;

        for (var i = 0; i < raw.Length; i++)
        {
            var c = raw[i];
            if (char.IsLetterOrDigit(c))
            {
                if (i > 0 && !prevSpace && char.IsAsciiDigit(raw[i - 1]) && char.IsAsciiLetter(c))
                {
                    // Preserve English ordinal suffixes: 11th, 12th, 13th, 1st, 2nd, 3rd.
                    var isOrdinal = i + 1 < raw.Length
                        && (i + 2 >= raw.Length || !char.IsLetterOrDigit(raw[i + 2]))
                        && IsOrdinalSuffix(raw[i], raw[i + 1]);
                    if (!isOrdinal)
                        sb.Append(' ');
                }

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

    private static bool IsOrdinalSuffix(char first, char second)
    {
        var a = char.ToLowerInvariant(first);
        var b = char.ToLowerInvariant(second);
        return (a == 't' && b == 'h')
               || (a == 's' && b == 't')
               || (a == 'n' && b == 'd')
               || (a == 'r' && b == 'd');
    }

    private static bool MatchesTokenNormalized(string normalizedHaystack, string normalizedNeedle)
    {
        if (string.IsNullOrEmpty(normalizedHaystack) || string.IsNullOrEmpty(normalizedNeedle))
            return false;

        var start = 0;
        while (start <= normalizedHaystack.Length - normalizedNeedle.Length)
        {
            var idx = normalizedHaystack.IndexOf(normalizedNeedle, start, StringComparison.Ordinal);
            if (idx < 0)
                return false;

            var leftOk = idx == 0 || normalizedHaystack[idx - 1] == ' ';
            var rightIdx = idx + normalizedNeedle.Length;
            var rightOk = rightIdx == normalizedHaystack.Length || normalizedHaystack[rightIdx] == ' ';
            if (leftOk && rightOk)
                return true;

            start = idx + 1;
        }

        return false;
    }

    // -------------------------------------------------------------------------
    // Framework version parsing & SWO selection (03.03 < 03.03b < 03.05, 03.05 == 3.05)
    // -------------------------------------------------------------------------

    internal static FrameworkParsedVersion ParseFrameworkVersion(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return new("", "", VersionClass.Empty, "0:", [], '\0', "");

        var cleaned = raw.Trim();
        for (var i = 0; i < 3; i++)
        {
            var stripped = LeadingVersionPrefixRegex().Replace(cleaned, "").Trim();
            if (string.Equals(stripped, cleaned, StringComparison.Ordinal))
                break;
            cleaned = stripped;
        }

        var fwMatch = FrameworkDottedVersionRegex().Match(cleaned);
        if (fwMatch.Success && TryParseDottedInt64(fwMatch.Groups[1].Value, out var fwSegs))
        {
            var trailing = fwMatch.Groups[2].Success
                ? char.ToUpperInvariant(fwMatch.Groups[2].Value[0])
                : '\0';
            return new FrameworkParsedVersion(
                NormalizedVersion: cleaned,
                DisplayVersion: cleaned,
                Class: VersionClass.FrameworkNumeric,
                ClassKey: "1:FW_NUM",
                Segments: fwSegs,
                TrailingLetter: trailing,
                RawNormalized: cleaned);
        }

        var (cls, classKey, segments) = ClassifyFallbackVersion(cleaned);
        return new FrameworkParsedVersion(
            NormalizedVersion: cleaned,
            DisplayVersion: cleaned,
            Class: cls,
            ClassKey: classKey,
            Segments: segments,
            TrailingLetter: '\0',
            RawNormalized: cleaned);
    }

    internal static int? CompareComparableVersions(FrameworkParsedVersion a, FrameworkParsedVersion b)
    {
        if (a.Class == VersionClass.Empty || b.Class == VersionClass.Empty)
            return null;

        if (!StringComparer.OrdinalIgnoreCase.Equals(a.ClassKey, b.ClassKey))
            return null;

        return CompareWithinClass(a, b);
    }

    private static int CompareWithinClass(FrameworkParsedVersion a, FrameworkParsedVersion b)
    {
        switch (a.Class)
        {
            case VersionClass.FrameworkNumeric:
                var numCmp = CompareNumericSegmentArrays(a.Segments, b.Segments);
                return numCmp != 0 ? numCmp : a.TrailingLetter.CompareTo(b.TrailingLetter);

            case VersionClass.PrefixNumeric:
                return CompareNumericSegmentArrays(a.Segments, b.Segments);

            case VersionClass.Skeleton:
                return CompareFixedLengthArrays(a.Segments, b.Segments);

            case VersionClass.Literal:
                return StringComparer.OrdinalIgnoreCase.Compare(a.RawNormalized, b.RawNormalized);

            default:
                return 0;
        }
    }

    private static bool IsCandidateNewer(
        FrameworkParsedVersion current,
        DateOnly? currentDate,
        FrameworkParsedVersion candidate,
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

    internal static List<FrameworkCatalogCandidate> OrderCandidates(IReadOnlyList<FrameworkCatalogCandidate> candidates) =>
        BiosProviderCommon.OrderCandidates(
            candidates,
            getPrefRank: static c => 3 - c.MatchRank,
            getClassKey: static c => c.ParsedVersion.ClassKey,
            getReleaseDate: static c => c.ReleaseDate,
            compareWithinClass: static (a, b) => CompareWithinClass(a.ParsedVersion, b.ParsedVersion),
            compareTieBreakers: static (a, b) =>
            {
                var dateCmp = CompareNullableDateDescending(a.ReleaseDate, b.ReleaseDate);
                if (dateCmp != 0)
                    return dateCmp;

                var rawCmp = StringComparer.OrdinalIgnoreCase.Compare(a.DisplayVersion, b.DisplayVersion);
                if (rawCmp != 0)
                    return rawCmp;

                rawCmp = StringComparer.Ordinal.Compare(a.DisplayVersion, b.DisplayVersion);
                if (rawCmp != 0)
                    return rawCmp;

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

                var sizeCmp = CompareNullableLongDescending(a.SizeBytes, b.SizeBytes);
                if (sizeCmp != 0)
                    return sizeCmp;

                return b.Severity.CompareTo(a.Severity);
            },
            comparePrefRankFirst: true,
            prefRankDescending: false);

    private static (VersionClass Class, string ClassKey, long[] Segments) ClassifyFallbackVersion(string normalized)
    {
        if (string.IsNullOrWhiteSpace(normalized))
            return (VersionClass.Empty, "0:", []);

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

    internal static bool TryValidateCabEntriesAndSelectInf(
        IReadOnlyDictionary<string, byte[]> entries,
        out string infRelativePath,
        out string error)
    {
        infRelativePath = "";
        error = "";

        if (entries.Count == 0)
        {
            error = "Framework CAB firmware capsule is empty.";
            return false;
        }

        long totalBytes = 0;
        var filePaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var dirPrefixes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var infCandidates = new List<(string Key, int Depth, bool IsFirmwareNamed)>();

        foreach (var (rawKey, content) in entries)
        {
            if (!TryValidateArchiveEntryPath(rawKey, out var normalizedKey, out var segments, out var pathError))
            {
                error = $"Framework CAB capsule contains unsafe entry path: {pathError}";
                return false;
            }

            if (content is null || content.LongLength > MaxCabExtractBytes - totalBytes)
            {
                error = $"Framework CAB capsule extracted size exceeds maximum allowed limit ({MaxCabExtractBytes} bytes).";
                return false;
            }

            totalBytes += content.LongLength;

            if (!filePaths.Add(normalizedKey))
            {
                error = $"Framework CAB capsule contains duplicate or colliding entry '{normalizedKey}'.";
                return false;
            }

            if (dirPrefixes.Contains(normalizedKey))
            {
                error = $"Framework CAB capsule contains file-vs-directory collision on '{normalizedKey}'.";
                return false;
            }

            var prefix = "";
            for (var i = 0; i < segments.Length - 1; i++)
            {
                prefix = i == 0 ? segments[i] : $"{prefix}/{segments[i]}";
                if (filePaths.Contains(prefix))
                {
                    error = $"Framework CAB capsule contains file-vs-directory collision on '{prefix}'.";
                    return false;
                }

                dirPrefixes.Add(prefix);
            }

            var leaf = segments[^1];
            if (Path.GetExtension(leaf).Equals(".inf", StringComparison.OrdinalIgnoreCase))
            {
                var isFw = leaf.Contains("firmware", StringComparison.OrdinalIgnoreCase)
                           || leaf.Contains("bios", StringComparison.OrdinalIgnoreCase)
                           || leaf.Contains("uefi", StringComparison.OrdinalIgnoreCase);
                infCandidates.Add((normalizedKey, segments.Length, isFw));
            }
        }

        if (infCandidates.Count == 0)
        {
            error = "Framework CAB firmware capsule does not contain a .inf driver file.";
            return false;
        }

        infCandidates.Sort((a, b) =>
        {
            var depthCmp = a.Depth.CompareTo(b.Depth);
            if (depthCmp != 0)
                return depthCmp;

            var fwCmp = b.IsFirmwareNamed.CompareTo(a.IsFirmwareNamed);
            if (fwCmp != 0)
                return fwCmp;

            var ciCmp = StringComparer.OrdinalIgnoreCase.Compare(a.Key, b.Key);
            if (ciCmp != 0)
                return ciCmp;

            return StringComparer.Ordinal.Compare(a.Key, b.Key);
        });

        infRelativePath = infCandidates[0].Key;
        return true;
    }

    private static bool TryValidateArchiveEntryPath(
        string? rawPath,
        out string normalized,
        out string[] segments,
        out string error)
    {
        normalized = "";
        segments = [];
        error = "";

        if (string.IsNullOrEmpty(rawPath))
        {
            error = "Entry path is empty.";
            return false;
        }

        if (rawPath != rawPath.Trim())
        {
            error = "Entry path contains leading or trailing whitespace.";
            return false;
        }

        if (rawPath.Length > MaxArchivePathLength)
        {
            error = $"Entry path exceeds maximum length ({MaxArchivePathLength}).";
            return false;
        }

        if (rawPath.StartsWith('/') || rawPath.StartsWith('\\'))
        {
            error = "Entry path must be relative.";
            return false;
        }

        foreach (var c in rawPath)
        {
            if (char.IsControl(c) || c == ':' || Array.IndexOf(ForbiddenArchivePathChars, c) >= 0)
            {
                error = "Entry path contains forbidden characters.";
                return false;
            }
        }

        var slashed = rawPath.Replace('\\', '/');
        if (slashed.EndsWith('/'))
        {
            error = "Entry path cannot end with a directory separator.";
            return false;
        }

        var parts = slashed.Split('/', StringSplitOptions.None);
        if (parts.Length == 0)
        {
            error = "Entry path has no segments.";
            return false;
        }

        foreach (var seg in parts)
        {
            if (string.IsNullOrWhiteSpace(seg) || seg is "." or "..")
            {
                error = "Entry path contains empty or traversal segments.";
                return false;
            }
        }

        normalized = slashed;
        segments = parts;
        return true;
    }

    private static bool TryMaterializeCabEntriesSafe(
        string stagingDir,
        string extractDir,
        IReadOnlyDictionary<string, byte[]> entries,
        string infRelativePath,
        out string extractedInfPath,
        out string error)
    {
        extractedInfPath = "";
        error = "";

        try
        {
            var fullStaging = Path.TrimEndingDirectorySeparator(Path.GetFullPath(stagingDir));
            if (IsSymlinkOrReparsePoint(fullStaging) || HasSymlinkOrReparseAncestor(fullStaging))
            {
                error = "Staging directory or one of its ancestors is a symbolic link or reparse point.";
                return false;
            }

            var fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(extractDir));
            if (IsSymlinkOrReparsePoint(fullRoot))
            {
                error = "CAB extraction directory is a symbolic link or reparse point.";
                return false;
            }

            Directory.CreateDirectory(fullRoot);
            if (IsSymlinkOrReparsePoint(fullRoot))
            {
                error = "CAB extraction directory became a symbolic link or reparse point.";
                return false;
            }

            var rootWithSep = fullRoot.EndsWith(Path.DirectorySeparatorChar)
                ? fullRoot
                : fullRoot + Path.DirectorySeparatorChar;
            var pathComparison = OperatingSystem.IsWindows()
                ? StringComparison.OrdinalIgnoreCase
                : StringComparison.Ordinal;

            long totalWritten = 0;

            foreach (var (rawKey, content) in entries)
            {
                if (!TryValidateArchiveEntryPath(rawKey, out _, out var segments, out var pathErr))
                {
                    error = $"Refused unsafe CAB entry during extraction: {pathErr}";
                    return false;
                }

                var relative = Path.Combine(segments);
                var destPath = Path.GetFullPath(Path.Combine(fullRoot, relative));
                if (!destPath.StartsWith(rootWithSep, pathComparison))
                {
                    error = "CAB entry escapes extraction root.";
                    return false;
                }

                var currentDir = fullRoot;
                for (var i = 0; i < segments.Length - 1; i++)
                {
                    currentDir = Path.Combine(currentDir, segments[i]);
                    if (File.Exists(currentDir))
                    {
                        error = "CAB entry collides with an existing file.";
                        return false;
                    }

                    if (IsSymlinkOrReparsePoint(currentDir))
                    {
                        error = "CAB intermediate directory is a symbolic link or reparse point.";
                        return false;
                    }

                    if (!Directory.Exists(currentDir))
                        Directory.CreateDirectory(currentDir);

                    if (IsSymlinkOrReparsePoint(currentDir))
                    {
                        error = "CAB intermediate directory became a symbolic link or reparse point.";
                        return false;
                    }
                }

                if (Directory.Exists(destPath))
                {
                    error = "CAB entry collides with an existing directory.";
                    return false;
                }

                if (IsSymlinkOrReparsePoint(destPath))
                {
                    error = "CAB extraction target is a symbolic link or reparse point.";
                    return false;
                }

                if (content.LongLength > MaxCabExtractBytes - totalWritten)
                {
                    error = $"CAB extraction exceeded maximum allowed size ({MaxCabExtractBytes} bytes).";
                    return false;
                }

                File.WriteAllBytes(destPath, content);
                totalWritten += content.LongLength;
            }

            var infSegments = infRelativePath.Split('/', StringSplitOptions.None);
            var candidateInf = Path.GetFullPath(Path.Combine([fullRoot, .. infSegments]));
            if (!candidateInf.StartsWith(rootWithSep, pathComparison)
                || !File.Exists(candidateInf)
                || Directory.Exists(candidateInf)
                || IsSymlinkOrReparsePoint(candidateInf))
            {
                error = "Resolved .inf file could not be verified inside CAB extraction directory.";
                return false;
            }

            extractedInfPath = candidateInf;
            return true;
        }
        catch (Exception ex)
        {
            error = $"Failed to safely extract Framework CAB capsule: {ex.Message}";
            return false;
        }
    }

    private static bool IsSymlinkOrReparsePoint(string path) => IsSymlinkOrReparsePath(path);

    private static bool HasSymlinkOrReparseAncestor(string path) => HasSymlinkOrReparseAncestorOrSelf(path);

    private Task<BiosVerifiedPackageResult> DownloadAndVerifyFrameworkPackageAsync(
        BiosInstallRequest request,
        string stagingDir,
        string fileName,
        string expectedExt,
        IProgress<BiosInstallProgress>? progress,
        ILogger? log,
        CancellationToken ct,
        long maxBytes = DefaultMaxDownloadBytes) =>
        DownloadAndVerifyVendorPackageAsync(
            VendorId,
            _signatureVerifier,
            (url, token) => GetPackageWithSafeRedirectsAsync(url, expectedExt, token),
            request,
            stagingDir,
            fileName,
            progress,
            log,
            ct,
            maxBytes);

    private Task<HttpResponseMessage> GetPackageWithSafeRedirectsAsync(string initialUrl, string expectedExt, CancellationToken ct) =>
        GetVendorUrlWithSafeRedirectsAsync(
            _httpClient,
            initialUrl,
            AllowedHostSuffixes,
            DisplayName,
            acceptHeader: null,
            ct,
            disallowedUrlMessage: "Disallowed Framework package URL.",
            validateUri: (uri, isRedirect) =>
            {
                if (!Path.GetExtension(uri.AbsolutePath).Equals(expectedExt, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException(isRedirect
                        ? $"Rejected redirect target: Framework BIOS installer package must have the expected '{expectedExt}' extension."
                        : $"Framework BIOS installer package must have the expected '{expectedExt}' extension.");
                }
            });

    private static bool TryResolveFrameworkIdentity(
        BiosSystemIdentity system,
        out FrameworkHardwareIdentity identity,
        out string reason)
    {
        identity = default!;
        reason = "";

        var modelStatus = ClassifyModelToken(system.Model, out var modelToken);
        var boardStatus = ClassifyModelToken(system.BoardProduct, out var boardToken);
        var skuStatus = ClassifyModelToken(system.SystemSku, out var skuToken);

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

        if (skuStatus == SmbiosTokenStatus.InvalidUnsafe)
        {
            reason = "SMBIOS SystemSku contains disallowed characters.";
            return false;
        }

        if (modelStatus != SmbiosTokenStatus.Valid
            && boardStatus != SmbiosTokenStatus.Valid
            && skuStatus != SmbiosTokenStatus.Valid)
        {
            reason = "SMBIOS Model, BoardProduct, and SystemSku are empty or OEM placeholders.";
            return false;
        }

        var primary = modelStatus == SmbiosTokenStatus.Valid
            ? modelToken
            : (boardStatus == SmbiosTokenStatus.Valid ? boardToken : skuToken);

        var boardOrSku = new List<string>();
        if (boardStatus == SmbiosTokenStatus.Valid)
            boardOrSku.Add(boardToken);
        if (skuStatus == SmbiosTokenStatus.Valid
            && !boardOrSku.Contains(skuToken, StringComparer.OrdinalIgnoreCase))
        {
            boardOrSku.Add(skuToken);
        }

        var modelNormalized = modelStatus == SmbiosTokenStatus.Valid
            ? NormalizeForModelMatch(modelToken)
            : "";

        var combinedRaw = string.Join(" ", new[] { modelToken, boardToken, skuToken }.Where(s => !string.IsNullOrEmpty(s)));
        var combinedNorm = NormalizeForModelMatch(combinedRaw);

        var significantTokens = new List<string>();
        if (!string.IsNullOrEmpty(modelNormalized))
        {
            foreach (var tok in modelNormalized.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                if (tok.Length >= 2 && !StopWords.Contains(tok) && !significantTokens.Contains(tok, StringComparer.Ordinal))
                    significantTokens.Add(tok);
            }
        }

        identity = new FrameworkHardwareIdentity(
            PrimaryToken: primary,
            ModelToken: modelStatus == SmbiosTokenStatus.Valid ? modelToken : "",
            BoardToken: boardStatus == SmbiosTokenStatus.Valid ? boardToken : "",
            SkuToken: skuStatus == SmbiosTokenStatus.Valid ? skuToken : "",
            BoardOrSkuTokens: boardOrSku,
            ModelNormalized: modelNormalized,
            CombinedNormalized: combinedNorm,
            SignificantModelTokens: significantTokens);

        return true;
    }

    private static string BuildCatalogUrl(string template, string primaryToken)
    {
        if (EndpointPlaceholderRegex().IsMatch(template))
            return EndpointPlaceholderRegex().Replace(template, Uri.EscapeDataString(primaryToken));

        return template;
    }

    private Task<HttpResponseMessage> GetCatalogWithSafeRedirectsAsync(string initialUrl, CancellationToken ct) =>
        GetVendorUrlWithSafeRedirectsAsync(
            _httpClient,
            initialUrl,
            AllowedHostSuffixes,
            DisplayName,
            acceptHeader: "application/xml, text/xml, application/json;q=0.9, application/gzip;q=0.8",
            ct);

    private static async Task<byte[]> ReadBoundedBytesAsync(
        HttpContent content,
        long maxCompressedBytes,
        long maxDecompressedBytes,
        CancellationToken ct)
    {
        var contentLength = content.Headers.ContentLength;
        if (contentLength.HasValue && contentLength.Value > maxDecompressedBytes)
            throw new InvalidDataException($"Framework catalog response ({contentLength.Value} bytes) exceeds maximum allowed limit ({maxDecompressedBytes} bytes).");

        var initialCap = contentLength is > 0
            ? (int)Math.Min(contentLength.Value, MaxInitialStreamCapacity)
            : 4096;

        using var ms = new MemoryStream(initialCap);
        await using var stream = await content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        var buffer = ArrayPool<byte>.Shared.Rent(ReadBufferSize);
        long totalRead = 0;
        var activeLimit = maxDecompressedBytes;
        var checkedGzipMagic = false;
        byte firstByte = 0;
        byte secondByte = 0;

        try
        {
            while (true)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), ct).ConfigureAwait(false);
                if (read == 0)
                    break;

                if (!checkedGzipMagic)
                {
                    if (totalRead == 0)
                    {
                        firstByte = buffer[0];
                        if (read >= 2)
                        {
                            secondByte = buffer[1];
                            checkedGzipMagic = true;
                        }
                    }
                    else if (totalRead == 1)
                    {
                        secondByte = buffer[0];
                        checkedGzipMagic = true;
                    }

                    if (checkedGzipMagic && firstByte == 0x1F && secondByte == 0x8B)
                    {
                        activeLimit = maxCompressedBytes;
                        if (contentLength.HasValue && contentLength.Value > maxCompressedBytes)
                        {
                            throw new InvalidDataException(
                                $"Framework compressed catalog ({contentLength.Value} bytes) exceeds maximum allowed limit ({maxCompressedBytes} bytes).");
                        }
                    }
                }

                totalRead += read;
                if (totalRead > activeLimit)
                {
                    throw new InvalidDataException(
                        activeLimit == maxCompressedBytes
                            ? $"Framework compressed catalog exceeded maximum allowed size ({maxCompressedBytes} bytes)."
                            : $"Framework catalog response exceeded maximum allowed size ({maxDecompressedBytes} bytes).");
                }

                await ms.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        if (totalRead == 0)
            throw new InvalidDataException("Framework catalog response body is empty.");

        return ms.ToArray();
    }

    private static (int Offset, int Length) StripUtf8Bom(byte[] bytes)
    {
        if (bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
            return (3, bytes.Length - 3);
        return (0, bytes.Length);
    }

    private static string? GetChildText(XElement parent, string localName) =>
        parent.Elements()
            .FirstOrDefault(e => string.Equals(e.Name.LocalName, localName, StringComparison.OrdinalIgnoreCase))
            ?.Value?.Trim();

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

    private static bool IsBetaRelease(
        string? version,
        string? title,
        string? description,
        bool? isReleaseFlag,
        bool? isBetaFlag,
        string? relType,
        string? relBranch)
    {
        if (isBetaFlag == true || isReleaseFlag == false)
            return true;

        if (!string.IsNullOrWhiteSpace(relType)
            && (relType.Equals("development", StringComparison.OrdinalIgnoreCase)
                || relType.Equals("beta", StringComparison.OrdinalIgnoreCase)
                || relType.Equals("testing", StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        if (!string.IsNullOrWhiteSpace(relBranch)
            && (relBranch.Equals("testing", StringComparison.OrdinalIgnoreCase)
                || relBranch.Equals("beta", StringComparison.OrdinalIgnoreCase)
                || relBranch.Equals("embargo", StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        if (!string.IsNullOrWhiteSpace(version) && FrameworkBetaTokenRegex().IsMatch(version))
            return true;

        if (!string.IsNullOrWhiteSpace(title) && FrameworkBetaTokenRegex().IsMatch(title))
            return true;

        if (!string.IsNullOrWhiteSpace(description))
        {
            var trimmed = description.Trim();
            if (trimmed.StartsWith("beta", StringComparison.OrdinalIgnoreCase)
                || trimmed.Contains("beta version", StringComparison.OrdinalIgnoreCase)
                || trimmed.Contains("beta bios", StringComparison.OrdinalIgnoreCase)
                || trimmed.Contains("beta release", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }


    private static DateOnly? TryParseUnixTimestamp(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        if (!long.TryParse(raw.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds))
            return null;

        // Plausible BIOS timestamp window: 2000-01-01 .. 2100-01-01 UTC.
        if (seconds < 946_684_800L || seconds > 4_102_444_800L)
            return null;

        return DateOnly.FromDateTime(DateTimeOffset.FromUnixTimeSeconds(seconds).UtcDateTime);
    }


    private void LogWarn(string message, string? serialNumber) =>
        _log?.Warn(RedactText(message, serialNumber));

    internal enum VersionClass
    {
        Empty,
        FrameworkNumeric,
        PrefixNumeric,
        Skeleton,
        Literal,
    }

    internal sealed record FrameworkHardwareIdentity(
        string PrimaryToken,
        string ModelToken,
        string BoardToken,
        string SkuToken,
        IReadOnlyList<string> BoardOrSkuTokens,
        string ModelNormalized,
        string CombinedNormalized,
        IReadOnlyList<string> SignificantModelTokens);

    internal sealed record FrameworkParsedVersion(
        string NormalizedVersion,
        string DisplayVersion,
        VersionClass Class,
        string ClassKey,
        long[] Segments,
        char TrailingLetter,
        string RawNormalized);

    internal sealed record FrameworkCatalogCandidate(
        string DisplayVersion,
        FrameworkParsedVersion ParsedVersion,
        int MatchRank,
        DateOnly? ReleaseDate,
        BiosUpdateSeverity Severity,
        string? PackageId,
        string? ReleaseSummary,
        string? ReleaseNotesUrl,
        string? DownloadUrl,
        string? Sha256,
        long? SizeBytes,
        string Source);

}
