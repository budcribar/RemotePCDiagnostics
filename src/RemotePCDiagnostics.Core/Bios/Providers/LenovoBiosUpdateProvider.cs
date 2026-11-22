using System.Buffers;
using System.Globalization;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Bios;

/// <summary>
/// Built-in pure-C# BIOS update provider for Lenovo systems (ThinkPad, ThinkCentre, ThinkStation, IdeaPad, Yoga).
/// Queries Lenovo Commercial Vantage / Update Retriever XML catalogs on <c>download.lenovo.com</c> using the
/// validated 4-character MTM prefix and stages signed/verified <c>winuptp.exe</c> or silent Lenovo BIOS packages
/// (routing privileged operations through <see cref="IElevatedCommandBridge"/> when un-elevated).
/// </summary>
public sealed partial class LenovoBiosUpdateProvider : IBiosUpdateProvider
{
    public const string ProviderVendorId = "lenovo";
    public const string DefaultCatalogBaseUrl = "https://download.lenovo.com/catalog";
    public static readonly IReadOnlyList<string> AllowedHostSuffixes = ["lenovo.com"];

    private const long MaxCatalogXmlBytes = 16L * 1024 * 1024;
    private const int MaxInitialStreamCapacity = 1024 * 1024;
    private const int CopyBufferSize = 81920;
    private const int MaxDescriptorCandidatesToFetch = 5;

    private static readonly HashSet<int> RebootSuccessExitCodes = [0, 1, 3010];
    private static readonly TimeSpan DefaultInstallerTimeout = TimeSpan.FromMinutes(10);

    [GeneratedRegex(@"^([A-Za-z0-9]{4,12})\s*\(\s*v?(\d+(?:\.\d+)+)\s*\)$", RegexOptions.CultureInvariant)]
    private static partial Regex SymbolicWithNumericRegex();

    [GeneratedRegex(@"^([A-Za-z0-9]{3}[A-Za-z]{2})[0-9A-Fa-f]{2,3}[A-Za-z]{1,2}$", RegexOptions.CultureInvariant)]
    private static partial Regex FiveCharFamilyRegex();

    [GeneratedRegex(@"^([A-Za-z0-9]{2}[A-Za-z]{2})[0-9A-Fa-f]{2,3}[A-Za-z]{2}$", RegexOptions.CultureInvariant)]
    private static partial Regex FourCharFamilyRegex();

    [GeneratedRegex(@"^v?(\d+(?:\.\d+)+)$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex PureNumericRegex();

    [GeneratedRegex(@"\A[0-9A-Fa-f]{64}\z", RegexOptions.CultureInvariant)]
    private static partial Regex Sha256HexRegex();

    [GeneratedRegex(@"\d+", RegexOptions.CultureInvariant)]
    private static partial Regex DigitRunsRegex();

    [GeneratedRegex(@"^([A-Za-z]+)[\.\-\s_]*(\d+(?:\.\d+)*)$", RegexOptions.CultureInvariant)]
    private static partial Regex PrefixNumericRegex();

    private readonly HttpClient _httpClient;
    private readonly SystemCommandRunner? _commands;
    private readonly IBiosSignatureVerifier _signatureVerifier;
    private readonly IElevatedCommandBridge? _elevatedBridge;
    private readonly Func<bool>? _isProcessElevated;
    private readonly ILogger? _log;
    private readonly string _catalogBaseUrl;

    public LenovoBiosUpdateProvider(
        HttpClient? httpClient = null,
        SystemCommandRunner? commands = null,
        IBiosSignatureVerifier? signatureVerifier = null,
        IElevatedCommandBridge? elevatedBridge = null,
        Func<bool>? isProcessElevated = null,
        ILogger? log = null,
        string? catalogBaseUrl = null)
    {
        _httpClient = httpClient ?? BiosProviderHttp.SharedClient;
        _commands = commands;
        _signatureVerifier = signatureVerifier ?? WinVerifyTrustSignatureVerifier.Instance;
        _elevatedBridge = elevatedBridge;
        _isProcessElevated = isProcessElevated;
        _log = log;
        _catalogBaseUrl = string.IsNullOrWhiteSpace(catalogBaseUrl)
            ? DefaultCatalogBaseUrl
            : catalogBaseUrl.Trim().TrimEnd('/');
    }

    public static LenovoBiosUpdateProvider CreateWithHandler(
        HttpMessageHandler httpHandler,
        SystemCommandRunner? commands = null,
        IBiosSignatureVerifier? signatureVerifier = null,
        IElevatedCommandBridge? elevatedBridge = null,
        Func<bool>? isProcessElevated = null,
        ILogger? log = null,
        string? catalogBaseUrl = null) =>
        new(
            BiosProviderHttp.CreateClient(httpHandler),
            commands,
            signatureVerifier,
            elevatedBridge,
            isProcessElevated,
            log,
            catalogBaseUrl);

    public string VendorId => ProviderVendorId;
    public string DisplayName => "Lenovo";
    public int Priority => 100;

    public BiosProviderCapabilities Capabilities { get; } = new(
        CanCheckLatest: true,
        CanInstall: true,
        SupportsSilentInstall: true,
        RequiresReboot: true,
        RequiresElevation: true,
        RequiresInternet: true);

    public bool CanHandle(BiosSystemIdentity system) =>
        system is not null && BiosVendorIdentity.IsLenovo(system);

    public Task<BiosCurrentInfo> GetCurrentVersionAsync(BiosSystemIdentity system, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(system);
        ct.ThrowIfCancellationRequested();

        var current = system.CurrentBios ?? BiosCurrentInfo.Empty;
        var parsed = ParseLenovoVersion(current.Version);
        var effectiveFamily = !string.IsNullOrEmpty(parsed.Family)
            ? parsed.Family
            : current.Family?.Trim() ?? "";

        var metadata = current.Metadata is not null
            ? new Dictionary<string, string>(current.Metadata, StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (!string.IsNullOrEmpty(parsed.NumericVersion))
            metadata["numericVersion"] = parsed.NumericVersion;

        if (BiosVendorIdentity.TryExtractLenovoMtm(system, out var mtm))
            metadata["mtm"] = mtm;

        return Task.FromResult(current with
        {
            Version = parsed.Version,
            Family = effectiveFamily,
            ProviderId = VendorId,
            Metadata = metadata.Count > 0 ? metadata : current.Metadata,
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

        if (!BiosVendorIdentity.TryExtractLenovoMtm(system, out var mtm))
        {
            return BiosLatestInfo.Unsupported(
                VendorId,
                "Unable to determine a valid 4-character Lenovo Machine Type Model (MTM) from SMBIOS Model or SystemSku.");
        }

        var isWin11 = BiosVendorIdentity.IsWindows11(system.OsVersion);
        var effectiveOs = isWin11 ? "Win11" : "Win10";
        var primaryUrl = $"{_catalogBaseUrl}/{mtm}_{effectiveOs}.xml";

        try
        {
            var effectiveIndexUrl = primaryUrl;
            var response = await BiosProviderHttp.GetFollowingAllowedRedirectsAsync(
                _httpClient,
                primaryUrl,
                AllowedHostSuffixes,
                HttpCompletionOption.ResponseHeadersRead,
                ct).ConfigureAwait(false);

            string indexXml;
            try
            {
                if (response.StatusCode == HttpStatusCode.NotFound && isWin11)
                {
                    response.Dispose();
                    effectiveOs = "Win10";
                    effectiveIndexUrl = $"{_catalogBaseUrl}/{mtm}_Win10.xml";
                    response = await BiosProviderHttp.GetFollowingAllowedRedirectsAsync(
                        _httpClient,
                        effectiveIndexUrl,
                        AllowedHostSuffixes,
                        HttpCompletionOption.ResponseHeadersRead,
                        ct).ConfigureAwait(false);
                }

                if (!response.IsSuccessStatusCode)
                {
                    return BiosProviderHttp.ClassifyHttpStatus(
                        VendorId,
                        DisplayName,
                        response.StatusCode,
                        $"MTM {mtm}");
                }

                indexXml = await ReadBoundedStringAsync(response.Content, MaxCatalogXmlBytes, ct).ConfigureAwait(false);
            }
            finally
            {
                response.Dispose();
            }

            var indexDoc = BiosArchiveAndXml.ParseXmlSafe(indexXml);
            var indexUri = new Uri(effectiveIndexUrl, UriKind.Absolute);

            var currentParsed = ParseLenovoVersion(current.Version);
            var currentPrimary = currentParsed.Version;
            var currentFamily = !string.IsNullOrWhiteSpace(current.Family)
                ? current.Family.Trim()
                : currentParsed.Family;
            var currentNumeric = GetMetadataValue(current.Metadata, "numericVersion") ?? currentParsed.NumericVersion;

            var indexEntries = ParseIndexEntries(indexDoc, indexUri, out var biosEntryCount, out var hadDisallowedDescriptorUrl);
            if (biosEntryCount == 0)
            {
                return BiosLatestInfo.Unsupported(
                    VendorId,
                    $"No BIOS/UEFI update package is listed in the Lenovo catalog for MTM {mtm}.");
            }

            if (indexEntries.Count == 0)
            {
                if (hadDisallowedDescriptorUrl)
                {
                    return BiosLatestInfo.Failed(
                        VendorId,
                        "Lenovo catalog BIOS descriptor URL failed HTTPS/domain validation.");
                }

                return BiosLatestInfo.Failed(
                    VendorId,
                    $"Lenovo catalog BIOS entry for MTM {mtm} did not specify a valid descriptor URL.");
            }

            var orderedIndexEntries = OrderIndexEntries(indexEntries, currentFamily);
            var candidates = new List<LenovoDescriptorCandidate>();
            var hadUnsafeInstallerUrl = false;
            var hadMismatchedFamily = false;
            HttpStatusCode? lastDescriptorFailureStatus = null;
            string? lastDescriptorFailureContext = null;
            BiosLatestInfo? firstDescriptorExceptionResult = null;

            foreach (var indexEntry in orderedIndexEntries.Take(MaxDescriptorCandidatesToFetch))
            {
                try
                {
                    using var descResp = await BiosProviderHttp.GetFollowingAllowedRedirectsAsync(
                        _httpClient,
                        indexEntry.DescriptorUrl,
                        AllowedHostSuffixes,
                        HttpCompletionOption.ResponseHeadersRead,
                        ct).ConfigureAwait(false);

                    if (!descResp.IsSuccessStatusCode)
                    {
                        lastDescriptorFailureStatus = descResp.StatusCode;
                        lastDescriptorFailureContext = $"descriptor {indexEntry.DescriptorUrl}";
                        continue;
                    }

                    var descXml = await ReadBoundedStringAsync(descResp.Content, MaxCatalogXmlBytes, ct).ConfigureAwait(false);
                    var descDoc = BiosArchiveAndXml.ParseXmlSafe(descXml);
                    var descUri = new Uri(indexEntry.DescriptorUrl, UriKind.Absolute);

                    var parsedDesc = ParseDescriptor(descDoc, descUri, indexEntry, out var unsafeUrl);
                    if (unsafeUrl)
                    {
                        hadUnsafeInstallerUrl = true;
                        continue;
                    }

                    if (parsedDesc is null)
                        continue;

                    if (parsedDesc.HasDescriptorFamilyConflict || !IsFamilyCompatible(currentFamily, parsedDesc.Family))
                    {
                        hadMismatchedFamily = true;
                        continue;
                    }

                    candidates.Add(parsedDesc);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    var classified = RedactLatestInfo(
                        BiosProviderHttp.ClassifyHttpFailure(VendorId, DisplayName, ex, ct),
                        system.SerialNumber);
                    firstDescriptorExceptionResult ??= classified;
                    _log?.Warn($"[BIOS/Lenovo] Skipping unreadable descriptor candidate: {classified.Message}");
                }
            }

            if (candidates.Count == 0)
            {
                if (hadUnsafeInstallerUrl)
                {
                    return BiosLatestInfo.Failed(
                        VendorId,
                        "Lenovo BIOS descriptor specified an unsafe or disallowed installer URL.");
                }

                if (firstDescriptorExceptionResult is not null)
                    return firstDescriptorExceptionResult;

                if (lastDescriptorFailureStatus.HasValue)
                {
                    return BiosProviderHttp.ClassifyHttpStatus(
                        VendorId,
                        DisplayName,
                        lastDescriptorFailureStatus.Value,
                        lastDescriptorFailureContext);
                }

                if (hadMismatchedFamily)
                {
                    var familyMsg = string.IsNullOrEmpty(currentFamily)
                        ? $"No Lenovo BIOS package with a consistent BIOS family was found for MTM {mtm}."
                        : $"No Lenovo BIOS package matching family '{currentFamily}' was found for MTM {mtm}.";
                    return BiosLatestInfo.Unsupported(VendorId, familyMsg);
                }

                return BiosLatestInfo.Failed(
                    VendorId,
                    $"Lenovo BIOS descriptor for MTM {mtm} did not contain a valid BIOS release.");
            }

            var best = SelectNewestDescriptor(candidates, currentFamily);
            var isNewer = IsCandidateNewer(currentPrimary, currentFamily, currentNumeric, current.ReleaseDate, best);

            var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["mtm"] = mtm,
                ["catalogOs"] = effectiveOs,
                ["descriptorUrl"] = best.DescriptorUrl,
                ["installMode"] = best.InstallMode,
            };

            if (!string.IsNullOrEmpty(best.NumericVersion))
                metadata["numericVersion"] = best.NumericVersion;

            if (!string.IsNullOrEmpty(best.Family))
                metadata["biosFamily"] = best.Family;

            if (!isNewer)
            {
                return RedactLatestInfo(
                    BiosLatestInfo.UpToDate(
                        providerId: VendorId,
                        latestVersion: best.Version,
                        releaseDate: best.ReleaseDate,
                        metadata: metadata),
                    system.SerialNumber);
            }

            return RedactLatestInfo(
                BiosLatestInfo.UpdateAvailable(
                    providerId: VendorId,
                    latestVersion: best.Version,
                    releaseDate: best.ReleaseDate,
                    severity: best.Severity,
                    packageId: best.PackageId,
                    releaseSummary: best.ReleaseSummary,
                    releaseNotesUrl: best.ReleaseNotesUrl,
                    downloadUrl: best.DownloadUrl,
                    sha256: best.Sha256,
                    sizeBytes: best.SizeBytes,
                    requiresReboot: best.RequiresReboot,
                    metadata: metadata),
                system.SerialNumber);
        }
        catch (Exception ex)
        {
            return RedactLatestInfo(
                BiosProviderHttp.ClassifyHttpFailure(VendorId, DisplayName, ex, ct),
                system.SerialNumber);
        }
    }

    public async Task<BiosInstallResult> InstallAsync(
        BiosInstallRequest request,
        IProgress<BiosInstallProgress>? progress = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ct.ThrowIfCancellationRequested();

        var previousVersion = request.Current?.Version;
        var targetVersion = request.Target?.LatestVersion;

        if (request.Target is null || string.IsNullOrWhiteSpace(request.Target.DownloadUrl))
        {
            const string msg = "Lenovo BIOS update target does not specify a download URL.";
            progress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, msg));
            return BiosInstallResult.Failed(msg, previousVersion, targetVersion);
        }

        string? autoStagingDir = null;
        var effectiveRequest = request;
        if (string.IsNullOrWhiteSpace(request.StagingDirectory))
        {
            autoStagingDir = Path.Combine(Path.GetTempPath(), $"rpd-bios-lenovo-{Guid.NewGuid():N}");
            effectiveRequest = request with { StagingDirectory = autoStagingDir };
        }

        try
        {
            var verified = await BiosPackageVerification.DownloadAndVerifyAsync(
                _httpClient,
                effectiveRequest,
                VendorId,
                AllowedHostSuffixes,
                "lenovo-bios-update.exe",
                _signatureVerifier,
                progress,
                _log,
                ct).ConfigureAwait(false);

            if (!verified.Succeeded || string.IsNullOrWhiteSpace(verified.FilePath))
            {
                var err = verified.ErrorMessage ?? "Lenovo BIOS package download or verification failed.";
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, err));
                return BiosInstallResult.Failed(err, previousVersion, targetVersion);
            }

            if (!TryEnsureExecutableExtension(verified.FilePath, out var packagePath, out var extError))
            {
                TryDeleteFile(verified.FilePath);
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, extError));
                return BiosInstallResult.Failed(extError, previousVersion, targetVersion);
            }

            var bitLocker = await BiosBitLockerSuspender.SuspendForOneRebootWithResultAsync(
                effectiveRequest,
                _commands,
                progress,
                _log,
                ct,
                bridge: _elevatedBridge,
                isProcessElevated: _isProcessElevated).ConfigureAwait(false);

            if (bitLocker.ElevationRequired)
            {
                var msg = bitLocker.Message
                    ?? $"Administrator rights (or the elevated Agent service) are required to suspend BitLocker. {ElevationService.AdminRepairHint}";
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, msg));
                return BiosInstallResult.Failed(msg, previousVersion, targetVersion, exitCode: SystemCommandRunner.AgentFailedExitCode);
            }

            var installMode = ResolveInstallMode(request.Target);
            var arguments = BiosAgentInstallModes.BuildArguments(installMode, request.AllowReboot);

            var expectedSha256 = !string.IsNullOrWhiteSpace(verified.ActualSha256)
                ? verified.ActualSha256
                : await BiosPackageVerifier.ComputeSha256HexAsync(packagePath, ct).ConfigureAwait(false);

            var agentRequest = new BiosAgentInstallRequest(
                VendorId: VendorId,
                InstallMode: installMode,
                PackagePath: packagePath,
                ExpectedSha256: expectedSha256,
                AllowReboot: request.AllowReboot,
                InfRelativePath: null,
                TimeoutMs: (int)DefaultInstallerTimeout.TotalMilliseconds);

            progress?.Report(new BiosInstallProgress(
                BiosInstallStage.Staging,
                0,
                $"Staging Lenovo BIOS update {targetVersion ?? "package"}..."));
            progress?.Report(new BiosInstallProgress(
                BiosInstallStage.Installing,
                50,
                $"Running Lenovo BIOS installer ({installMode})..."));

            var result = await BiosInstallerRunner.RunInstallerAsync(
                commands: _commands,
                executablePath: packagePath,
                arguments: arguments,
                request: effectiveRequest,
                bitLockerSuspended: bitLocker.Suspended,
                rebootSuccessExitCodes: RebootSuccessExitCodes,
                completedSuccessExitCodes: null,
                timeout: DefaultInstallerTimeout,
                log: _log,
                ct: ct,
                workingDirectory: Path.GetDirectoryName(packagePath),
                agentRequest: agentRequest,
                bridge: _elevatedBridge,
                isProcessElevated: _isProcessElevated).ConfigureAwait(false);

            if (result.Succeeded && result.RequiresReboot)
                progress?.Report(new BiosInstallProgress(BiosInstallStage.RebootRequired, 100, result.Message));
            else if (result.Succeeded)
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Completed, 100, result.Message));
            else
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, result.Message));

            return result;
        }
        finally
        {
            if (autoStagingDir is not null)
                TryDeleteDirectoryRecursive(autoStagingDir);
        }
    }

    internal static ParsedLenovoVersion ParseLenovoVersion(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return new("", "", null, null, LenovoVersionKind.Empty);

        var trimmed = raw.Trim();

        // Handle Lenovo BIOS/EC slash pairs such as "1.68/1.22" or "N32ET92W/1.22".
        var slashIdx = trimmed.IndexOf('/');
        if (slashIdx > 0 && !trimmed.Contains('(', StringComparison.Ordinal))
            trimmed = trimmed[..slashIdx].Trim();

        var symNum = SymbolicWithNumericRegex().Match(trimmed);
        if (symNum.Success)
        {
            var symbolic = symNum.Groups[1].Value.ToUpperInvariant();
            var family = ExtractFamily(symbolic);
            if (!string.IsNullOrEmpty(family))
            {
                var numeric = symNum.Groups[2].Value;
                return new(symbolic, family, numeric, symbolic, LenovoVersionKind.RecognizedSymbolic);
            }
        }

        var pureNum = PureNumericRegex().Match(trimmed);
        if (pureNum.Success)
        {
            var numeric = pureNum.Groups[1].Value;
            return new(numeric, "", numeric, null, LenovoVersionKind.PureNumeric);
        }

        var upper = trimmed.ToUpperInvariant();
        var extractedFamily = ExtractFamily(upper);
        if (!string.IsNullOrEmpty(extractedFamily))
            return new(trimmed, extractedFamily, null, upper, LenovoVersionKind.RecognizedSymbolic);

        return new(trimmed, "", null, null, LenovoVersionKind.Unrecognized);
    }

    internal static ParsedLenovoVersion ParseIndexVersionHint(
        string? biosVersion,
        string? version,
        out bool hasIndexFamilyConflict)
    {
        var parsedIndexBios = ParseLenovoVersion(biosVersion);
        var parsedIndexVersion = ParseLenovoVersion(version);
        hasIndexFamilyConflict = HasFamilyConflict(parsedIndexBios.Family, parsedIndexVersion.Family);

        if (!string.IsNullOrEmpty(parsedIndexBios.Family))
            return parsedIndexBios;

        if (!string.IsNullOrEmpty(parsedIndexVersion.Family))
            return parsedIndexVersion;

        if (parsedIndexBios.Kind == LenovoVersionKind.PureNumeric)
            return parsedIndexBios;

        if (parsedIndexVersion.Kind == LenovoVersionKind.PureNumeric)
            return parsedIndexVersion;

        return parsedIndexBios.Kind != LenovoVersionKind.Empty
            ? parsedIndexBios
            : parsedIndexVersion;
    }

    internal static string ExtractFamily(string? symbolicVersion)
    {
        if (string.IsNullOrWhiteSpace(symbolicVersion))
            return "";

        var trimmed = symbolicVersion.Trim();
        var five = FiveCharFamilyRegex().Match(trimmed);
        if (five.Success)
            return five.Groups[1].Value.ToUpperInvariant();

        var four = FourCharFamilyRegex().Match(trimmed);
        if (four.Success)
            return four.Groups[1].Value.ToUpperInvariant();

        return "";
    }

    internal static bool TryResolveDescriptorRelativeUrl(
        Uri descriptorUri,
        string? fileName,
        IReadOnlyList<string> allowedHostSuffixes,
        out string resolvedUrl)
    {
        resolvedUrl = "";
        if (string.IsNullOrWhiteSpace(fileName))
            return false;

        var trimmed = fileName.Trim();
        if (trimmed.StartsWith('/') || trimmed.StartsWith('\\') || trimmed.StartsWith("//", StringComparison.Ordinal))
            return false;

        foreach (var c in trimmed)
        {
            if (char.IsControl(c) || char.IsWhiteSpace(c) || c is '\\' or ':' or '?' or '#' or '@' or '%')
                return false;
        }

        if (Uri.TryCreate(trimmed, UriKind.Absolute, out _))
            return false;

        var segments = trimmed.Split('/');
        foreach (var seg in segments)
        {
            if (seg.Length == 0 || IsUnsafePathSegment(seg))
                return false;
        }

        var baseDirUri = new Uri(descriptorUri, "./");
        if (!Uri.TryCreate(baseDirUri, trimmed, out var resolved))
            return false;

        if (!resolved.AbsoluteUri.StartsWith(baseDirUri.AbsoluteUri, StringComparison.OrdinalIgnoreCase)
            || !resolved.AbsolutePath.StartsWith(baseDirUri.AbsolutePath, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!BiosProviderHttp.TryValidateHttpsUrl(resolved.AbsoluteUri, allowedHostSuffixes, out var validUri, out _))
            return false;

        resolvedUrl = validUri.AbsoluteUri;
        return true;
    }

    private List<LenovoIndexEntry> ParseIndexEntries(
        XDocument indexDoc,
        Uri indexUri,
        out int biosEntryCount,
        out bool hadDisallowedDescriptorUrl)
    {
        biosEntryCount = 0;
        hadDisallowedDescriptorUrl = false;
        var results = new List<LenovoIndexEntry>();

        foreach (var pkg in indexDoc.Descendants())
        {
            if (!pkg.Name.LocalName.Equals("package", StringComparison.OrdinalIgnoreCase))
                continue;

            var category = GetChildValue(pkg, "category");
            if (string.IsNullOrWhiteSpace(category)
                || (!category.Contains("BIOS", StringComparison.OrdinalIgnoreCase)
                    && !category.Contains("UEFI", StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            biosEntryCount++;
            var rawLocation = GetChildValue(pkg, "location");
            if (string.IsNullOrWhiteSpace(rawLocation))
                continue;

            if (!TryValidateDescriptorLocation(indexUri, rawLocation, out var descriptorUrl))
            {
                hadDisallowedDescriptorUrl = true;
                _log?.Warn("[BIOS/Lenovo] Rejected BIOS descriptor URL from catalog index.");
                continue;
            }

            var version = GetChildValue(pkg, "version");
            var release = GetChildValue(pkg, "release");
            var biosVersion = GetChildValue(pkg, "BiosVersion");
            var parsedIndexHint = ParseIndexVersionHint(biosVersion, version, out _);

            results.Add(new LenovoIndexEntry(
                DescriptorUrl: descriptorUrl,
                Version: version,
                ReleaseDate: BiosVersionComparer.TryParseReleaseDate(release),
                BiosVersion: biosVersion,
                Family: parsedIndexHint.Family,
                VersionKind: parsedIndexHint.Kind,
                CompareVersion: parsedIndexHint.Version));
        }

        return results;
    }

    private static bool TryValidateDescriptorLocation(Uri indexUri, string rawLocation, out string descriptorUrl)
    {
        descriptorUrl = "";
        var trimmed = rawLocation.Trim();
        if (trimmed.Length == 0)
            return false;

        if (trimmed.Contains("://", StringComparison.Ordinal) || trimmed.StartsWith("//", StringComparison.Ordinal))
        {
            if (trimmed.Contains('\\', StringComparison.Ordinal) || HasUnsafePathSegments(trimmed))
                return false;

            if (!BiosProviderHttp.TryValidateHttpsUrl(trimmed, AllowedHostSuffixes, out var absUri, out _))
                return false;

            descriptorUrl = absUri.AbsoluteUri;
            return true;
        }

        return TryResolveDescriptorRelativeUrl(indexUri, trimmed, AllowedHostSuffixes, out descriptorUrl);
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

    private static BiosLatestInfo RedactLatestInfo(BiosLatestInfo info, string? serialNumber)
    {
        if (string.IsNullOrWhiteSpace(serialNumber))
            return info;

        var safeMessage = info.Message is not null
            ? BiosInstallerRunner.RedactSerialNumber(info.Message, serialNumber)
            : null;
        var safeSummary = info.ReleaseSummary is not null
            ? BiosInstallerRunner.RedactSerialNumber(info.ReleaseSummary, serialNumber)
            : null;

        if (ReferenceEquals(safeMessage, info.Message) && ReferenceEquals(safeSummary, info.ReleaseSummary))
            return info;

        return info with { Message = safeMessage, ReleaseSummary = safeSummary };
    }

    private static int GetIndexEntryFamilyRank(LenovoIndexEntry entry, string currentFamily)
    {
        if (string.IsNullOrEmpty(currentFamily))
            return 0;

        if (string.IsNullOrEmpty(entry.Family))
            return 1;

        return string.Equals(entry.Family, currentFamily, StringComparison.OrdinalIgnoreCase)
            ? 2
            : 0;
    }

    private static int GetIndexEntryVersionKindRank(LenovoVersionKind kind) =>
        kind switch
        {
            LenovoVersionKind.RecognizedSymbolic or LenovoVersionKind.PureNumeric => 2,
            LenovoVersionKind.Empty => 1,
            _ => 0,
        };

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

    private static string GetVersionSortClassKey(string? version)
    {
        if (string.IsNullOrWhiteSpace(version))
            return "0:";

        var normalized = version.Trim();
        if (normalized.StartsWith("Rev.", StringComparison.OrdinalIgnoreCase))
            normalized = normalized[4..].Trim();
        else if (normalized.StartsWith("v", StringComparison.OrdinalIgnoreCase)
                 && normalized.Length > 1
                 && char.IsDigit(normalized[1]))
        {
            normalized = normalized[1..].Trim();
        }

        if (normalized.Length == 0)
            return "0:";

        var prefixMatch = PrefixNumericRegex().Match(normalized);
        if (prefixMatch.Success)
        {
            return AllSegmentsFitInt64(prefixMatch.Groups[2].Value)
                ? "2:PFX:" + prefixMatch.Groups[1].Value.ToUpperInvariant()
                : "4:LIT:" + normalized.ToUpperInvariant();
        }

        if (IsDottedNumeric(normalized))
        {
            return AllSegmentsFitInt64(normalized)
                ? "1:NUM"
                : "4:LIT:" + normalized.ToUpperInvariant();
        }

        var digitMatches = DigitRunsRegex().Matches(normalized);
        if (digitMatches.Count > 0)
        {
            foreach (Match m in digitMatches)
            {
                if (!long.TryParse(m.Value, NumberStyles.None, CultureInfo.InvariantCulture, out _))
                    return "4:LIT:" + normalized.ToUpperInvariant();
            }

            return $"3:SKEL:{digitMatches.Count}:{DigitRunsRegex().Replace(normalized, "#").ToUpperInvariant()}";
        }

        return "4:LIT:" + normalized.ToUpperInvariant();
    }

    private static bool IsDottedNumeric(string value)
    {
        var parts = value.Split('.');
        return parts.Length > 0 && parts.All(p => p.Length > 0 && p.All(char.IsAsciiDigit));
    }

    private static bool AllSegmentsFitInt64(string dottedNumeric)
    {
        foreach (var part in dottedNumeric.Split('.'))
        {
            if (!long.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out _))
                return false;
        }

        return true;
    }

    private static List<LenovoIndexEntry> OrderIndexEntries(List<LenovoIndexEntry> entries, string currentFamily)
    {
        if (!string.IsNullOrEmpty(currentFamily))
        {
            var matchingFamily = entries
                .Where(e => !string.IsNullOrEmpty(e.Family)
                            && string.Equals(e.Family, currentFamily, StringComparison.OrdinalIgnoreCase))
                .ToList();

            if (matchingFamily.Count > 0)
            {
                var unspecifiedFamily = entries.Where(e => string.IsNullOrEmpty(e.Family)).ToList();
                entries = [.. matchingFamily, .. unspecifiedFamily];
            }
        }

        var bucketMaxDates = new Dictionary<(int FamilyRank, int KindRank, string ClassKey), DateOnly?>();
        var keyed = new List<(LenovoIndexEntry Entry, int FamilyRank, int KindRank, string ClassKey, string? CompareVersion)>(entries.Count);

        foreach (var entry in entries)
        {
            var familyRank = GetIndexEntryFamilyRank(entry, currentFamily);
            var kindRank = GetIndexEntryVersionKindRank(entry.VersionKind);
            var compareVersion = !string.IsNullOrEmpty(entry.CompareVersion)
                ? entry.CompareVersion
                : entry.Version ?? entry.BiosVersion;
            var classKey = GetVersionSortClassKey(compareVersion);

            keyed.Add((entry, familyRank, kindRank, classKey, compareVersion));

            var bucketKey = (familyRank, kindRank, classKey);
            if (!bucketMaxDates.TryGetValue(bucketKey, out var existingMax)
                || (entry.ReleaseDate.HasValue && (!existingMax.HasValue || entry.ReleaseDate.Value > existingMax.Value)))
            {
                bucketMaxDates[bucketKey] = entry.ReleaseDate;
            }
        }

        keyed.Sort((a, b) =>
        {
            var familyCmp = b.FamilyRank.CompareTo(a.FamilyRank);
            if (familyCmp != 0)
                return familyCmp;

            var kindCmp = b.KindRank.CompareTo(a.KindRank);
            if (kindCmp != 0)
                return kindCmp;

            var bucketDateCmp = CompareNullableDateDescending(
                bucketMaxDates[(a.FamilyRank, a.KindRank, a.ClassKey)],
                bucketMaxDates[(b.FamilyRank, b.KindRank, b.ClassKey)]);
            if (bucketDateCmp != 0)
                return bucketDateCmp;

            var classCmp = StringComparer.Ordinal.Compare(a.ClassKey, b.ClassKey);
            if (classCmp != 0)
                return classCmp;

            var verCmp = BiosVersionComparer.Compare(b.CompareVersion, a.CompareVersion);
            if (verCmp.HasValue && verCmp.Value != 0)
                return verCmp.Value;

            var dateCmp = CompareNullableDateDescending(a.Entry.ReleaseDate, b.Entry.ReleaseDate);
            if (dateCmp != 0)
                return dateCmp;

            return StringComparer.OrdinalIgnoreCase.Compare(a.Entry.DescriptorUrl, b.Entry.DescriptorUrl);
        });

        return keyed.ConvertAll(k => k.Entry);
    }

    private LenovoDescriptorCandidate? ParseDescriptor(
        XDocument doc,
        Uri descriptorUri,
        LenovoIndexEntry indexEntry,
        out bool hadUnsafeInstallerUrl)
    {
        hadUnsafeInstallerUrl = false;
        var root = doc.Root;
        if (root is null)
            return null;

        var packageId = FirstNonEmpty(GetAttribute(root, "id"), GetAttribute(root, "name"));
        var rawAttrVersion = GetAttribute(root, "version");
        var detectBiosVersion = FindDetectBiosVersion(root);
        var xmlBiosVersion = GetDescendantValue(root, "BiosVersion");

        var primaryRaw = FirstNonEmpty(rawAttrVersion, detectBiosVersion, xmlBiosVersion, indexEntry.BiosVersion, indexEntry.Version);
        var parsedPrimary = ParseLenovoVersion(primaryRaw);
        if (string.IsNullOrWhiteSpace(parsedPrimary.Version))
            return null;

        var parsedDetect = ParseLenovoVersion(detectBiosVersion);
        var parsedXmlBios = ParseLenovoVersion(xmlBiosVersion);
        var parsedDescriptorHint = !string.IsNullOrEmpty(parsedDetect.Family)
            ? parsedDetect
            : !string.IsNullOrEmpty(parsedXmlBios.Family)
                ? parsedXmlBios
                : parsedDetect.Kind != LenovoVersionKind.Empty
                    ? parsedDetect
                    : parsedXmlBios;
        var parsedIndexHint = ParseIndexVersionHint(indexEntry.BiosVersion, indexEntry.Version, out var hasIndexFamilyConflict);

        var hasAnyDescriptorVersion = !string.IsNullOrWhiteSpace(rawAttrVersion)
            || !string.IsNullOrWhiteSpace(detectBiosVersion)
            || !string.IsNullOrWhiteSpace(xmlBiosVersion);

        var hasDescriptorFamilyConflict =
            HasFamilyConflict(parsedPrimary.Family, parsedDetect.Family)
            || HasFamilyConflict(parsedPrimary.Family, parsedXmlBios.Family)
            || HasFamilyConflict(parsedDetect.Family, parsedXmlBios.Family)
            || (!hasAnyDescriptorVersion && hasIndexFamilyConflict);

        string family;
        string? symbolicVersion;
        string? numericVersion;

        switch (parsedPrimary.Kind)
        {
            case LenovoVersionKind.RecognizedSymbolic:
                family = parsedPrimary.Family;
                symbolicVersion = parsedPrimary.SymbolicVersion;
                numericVersion = parsedPrimary.NumericVersion;
                if (string.IsNullOrEmpty(numericVersion)
                    && !hasDescriptorFamilyConflict
                    && !string.IsNullOrEmpty(parsedDescriptorHint.NumericVersion)
                    && (string.IsNullOrEmpty(parsedDescriptorHint.SymbolicVersion)
                        || string.Equals(parsedDescriptorHint.SymbolicVersion, parsedPrimary.SymbolicVersion, StringComparison.OrdinalIgnoreCase)))
                {
                    numericVersion = parsedDescriptorHint.NumericVersion;
                }
                break;

            case LenovoVersionKind.PureNumeric:
                if (!string.IsNullOrEmpty(parsedDescriptorHint.Family))
                {
                    family = parsedDescriptorHint.Family;
                    symbolicVersion = parsedDescriptorHint.SymbolicVersion;
                }
                else
                {
                    family = parsedIndexHint.Family;
                    symbolicVersion = parsedIndexHint.SymbolicVersion;
                    if (hasIndexFamilyConflict)
                        hasDescriptorFamilyConflict = true;
                }

                numericVersion = parsedPrimary.NumericVersion;
                break;

            default: // LenovoVersionKind.Unrecognized
                // Preserve descriptor-local family so cross-family <DetectVersion>/<BiosVersion>
                // is rejected as UnsupportedHardware, while NEVER inheriting numericVersion,
                // symbolicVersion, or index-only family onto an unrecognized Package@version.
                family = parsedDescriptorHint.Family;
                symbolicVersion = null;
                numericVersion = null;
                break;
        }

        var releaseDate = BiosVersionComparer.TryParseReleaseDate(GetChildValue(root, "ReleaseDate"))
            ?? indexEntry.ReleaseDate;

        var severity = ParseSeverity(FindChild(root, "Severity"));
        var requiresReboot = ParseRequiresReboot(FindChild(root, "Reboot"));
        var releaseSummary = FirstNonEmpty(
            ExtractLocalizedDesc(root, "Summary"),
            ExtractLocalizedDesc(root, "Title"));

        var installerFile = SelectInstallerFileElement(root);
        if (installerFile is null)
            return null;

        var installerName = GetChildValue(installerFile, "Name");
        if (string.IsNullOrWhiteSpace(installerName))
            return null;

        if (!TryResolveDescriptorRelativeUrl(descriptorUri, installerName, AllowedHostSuffixes, out var downloadUrl)
            || !Uri.TryCreate(downloadUrl, UriKind.Absolute, out var dlUri)
            || !dlUri.AbsolutePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            hadUnsafeInstallerUrl = true;
            _log?.Warn("[BIOS/Lenovo] Rejected unsafe or non-.exe installer <File><Name> in descriptor XML.");
            return null;
        }

        var sha256 = TryExtractValidSha256(GetChildValue(installerFile, "SHA256"))
            ?? TryExtractValidSha256(GetChildValue(installerFile, "CRC"));
        var sizeBytes = TryParsePositiveLong(GetChildValue(installerFile, "Size"));

        string? releaseNotesUrl = null;
        var readmeName = FindReadmeFileName(root);
        if (!string.IsNullOrWhiteSpace(readmeName)
            && TryResolveDescriptorRelativeUrl(descriptorUri, readmeName, AllowedHostSuffixes, out var resolvedReadme))
        {
            releaseNotesUrl = resolvedReadme;
        }

        var cmdline = ExtractInstallCmdline(root);
        var installMode = ClassifyInstallMode(cmdline, installerName);

        return new LenovoDescriptorCandidate(
            Version: parsedPrimary.Version,
            Family: family,
            NumericVersion: numericVersion,
            SymbolicVersion: symbolicVersion,
            PrimaryKind: parsedPrimary.Kind,
            HasDescriptorFamilyConflict: hasDescriptorFamilyConflict,
            PackageId: packageId,
            ReleaseDate: releaseDate,
            Severity: severity,
            RequiresReboot: requiresReboot,
            ReleaseSummary: releaseSummary,
            DownloadUrl: downloadUrl,
            ReleaseNotesUrl: releaseNotesUrl,
            Sha256: sha256,
            SizeBytes: sizeBytes,
            DescriptorUrl: descriptorUri.AbsoluteUri,
            InstallMode: installMode);
    }

    private static bool HasFamilyConflict(string a, string b) =>
        !string.IsNullOrEmpty(a)
        && !string.IsNullOrEmpty(b)
        && !string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    private static bool IsFamilyCompatible(string currentFamily, string candidateFamily) =>
        string.IsNullOrEmpty(currentFamily)
        || string.IsNullOrEmpty(candidateFamily)
        || string.Equals(currentFamily, candidateFamily, StringComparison.OrdinalIgnoreCase);

    private static bool IsRecognizedPrimaryKind(LenovoVersionKind kind) =>
        kind is LenovoVersionKind.RecognizedSymbolic or LenovoVersionKind.PureNumeric;

    private static bool IsCandidateNewer(
        string currentPrimary,
        string currentFamily,
        string? currentNumeric,
        DateOnly? currentReleaseDate,
        LenovoDescriptorCandidate candidate)
    {
        if (candidate.HasDescriptorFamilyConflict || !IsFamilyCompatible(currentFamily, candidate.Family))
            return false;

        // Defense in depth: never promote an unrecognized Package@version to UpdateAvailable
        // via skeleton digit-run matching, inherited metadata, or <ReleaseDate> fallback.
        if (!IsRecognizedPrimaryKind(candidate.PrimaryKind))
            return false;

        if (!string.IsNullOrEmpty(currentPrimary))
        {
            var primaryCmp = BiosVersionComparer.Compare(currentPrimary, candidate.Version);
            if (primaryCmp.HasValue)
                return primaryCmp.Value < 0;
        }

        if (!string.IsNullOrEmpty(currentNumeric) && !string.IsNullOrEmpty(candidate.NumericVersion))
        {
            var numCmp = BiosVersionComparer.Compare(currentNumeric, candidate.NumericVersion);
            if (numCmp.HasValue)
                return numCmp.Value < 0;
        }

        if (!string.IsNullOrEmpty(currentPrimary) && !string.IsNullOrEmpty(candidate.SymbolicVersion))
        {
            var symCmp = BiosVersionComparer.Compare(currentPrimary, candidate.SymbolicVersion);
            if (symCmp.HasValue)
                return symCmp.Value < 0;
        }

        return BiosVersionComparer.IsNewer(currentPrimary, candidate.Version, currentReleaseDate, candidate.ReleaseDate);
    }

    private static int GetCandidateSelectionRank(LenovoDescriptorCandidate candidate, string currentFamily)
    {
        if (!IsRecognizedPrimaryKind(candidate.PrimaryKind))
            return 0;

        if (!string.IsNullOrEmpty(currentFamily)
            && string.Equals(candidate.Family, currentFamily, StringComparison.OrdinalIgnoreCase))
        {
            return 2;
        }

        return 1;
    }

    private static LenovoDescriptorCandidate SelectNewestDescriptor(
        List<LenovoDescriptorCandidate> candidates,
        string currentFamily)
    {
        var best = candidates[0];
        var bestRank = GetCandidateSelectionRank(best, currentFamily);

        for (var i = 1; i < candidates.Count; i++)
        {
            var candidate = candidates[i];
            var candidateRank = GetCandidateSelectionRank(candidate, currentFamily);

            if (candidateRank != bestRank)
            {
                if (candidateRank > bestRank)
                {
                    best = candidate;
                    bestRank = candidateRank;
                }
                continue;
            }

            int? cmp = null;
            var familiesCompatible = IsFamilyCompatible(best.Family, candidate.Family);

            if (familiesCompatible)
            {
                cmp = BiosVersionComparer.Compare(best.Version, candidate.Version);

                if (!cmp.HasValue && !string.IsNullOrEmpty(best.SymbolicVersion) && !string.IsNullOrEmpty(candidate.SymbolicVersion))
                    cmp = BiosVersionComparer.Compare(best.SymbolicVersion, candidate.SymbolicVersion);

                if (!cmp.HasValue && !string.IsNullOrEmpty(best.NumericVersion) && !string.IsNullOrEmpty(candidate.NumericVersion))
                    cmp = BiosVersionComparer.Compare(best.NumericVersion, candidate.NumericVersion);
            }

            if (cmp < 0)
            {
                best = candidate;
            }
            else if ((cmp is null or 0)
                     && (familiesCompatible || string.IsNullOrEmpty(currentFamily))
                     && candidate.ReleaseDate.HasValue
                     && (!best.ReleaseDate.HasValue || candidate.ReleaseDate.Value > best.ReleaseDate.Value))
            {
                best = candidate;
            }
        }

        return best;
    }

    private static string ResolveInstallMode(BiosLatestInfo target)
    {
        if (target.Metadata is not null
            && target.Metadata.TryGetValue("installMode", out var metaMode)
            && BiosAgentInstallModes.TryValidateVendorAndMode(ProviderVendorId, metaMode, out _, out var normalizedMode))
        {
            return normalizedMode;
        }

        return BiosAgentInstallModes.LenovoWinUptp;
    }

    private static string ClassifyInstallMode(string? cmdline, string installerName)
    {
        if ((!string.IsNullOrWhiteSpace(cmdline) && cmdline.Contains("winuptp", StringComparison.OrdinalIgnoreCase))
            || installerName.Contains("winuptp", StringComparison.OrdinalIgnoreCase))
        {
            return BiosAgentInstallModes.LenovoWinUptp;
        }

        if (!string.IsNullOrWhiteSpace(cmdline)
            && (cmdline.Contains("/VERYSILENT", StringComparison.OrdinalIgnoreCase)
                || cmdline.Contains("/SILENT", StringComparison.OrdinalIgnoreCase)))
        {
            return BiosAgentInstallModes.LenovoPackageSilent;
        }

        return BiosAgentInstallModes.LenovoWinUptp;
    }

    private static string? FindDetectBiosVersion(XElement root)
    {
        string? untypedFallback = null;
        foreach (var el in root.Descendants())
        {
            if (!el.Name.LocalName.Equals("DetectVersion", StringComparison.OrdinalIgnoreCase))
                continue;

            var value = el.Value?.Trim();
            if (string.IsNullOrEmpty(value))
                continue;

            var typeAttr = GetAttribute(el, "type");
            if (string.Equals(typeAttr, "BIOS", StringComparison.OrdinalIgnoreCase)
                || string.Equals(typeAttr, "UEFI", StringComparison.OrdinalIgnoreCase))
            {
                return value;
            }

            if (string.IsNullOrEmpty(typeAttr))
                untypedFallback ??= value;
        }

        return untypedFallback;
    }

    private static XElement? SelectInstallerFileElement(XElement root)
    {
        var filesEl = FindChild(root, "Files");
        var installerEl = filesEl is not null ? FindChild(filesEl, "Installer") : FindChild(root, "Installer");
        if (installerEl is null)
            return null;

        foreach (var file in installerEl.Elements())
        {
            if (!file.Name.LocalName.Equals("File", StringComparison.OrdinalIgnoreCase))
                continue;

            var name = GetChildValue(file, "Name");
            if (string.IsNullOrWhiteSpace(name))
                continue;

            if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                return file;
        }

        return null;
    }

    private static string? FindReadmeFileName(XElement root)
    {
        var filesEl = FindChild(root, "Files");
        var readmeEl = (filesEl is not null ? FindChild(filesEl, "Readme") : null) ?? FindChild(root, "Readme");
        if (readmeEl is null)
            return null;

        var fileEl = FindChild(readmeEl, "File");
        return fileEl is not null ? GetChildValue(fileEl, "Name") : GetChildValue(readmeEl, "Name");
    }

    private static string? ExtractInstallCmdline(XElement root)
    {
        var installEl = FindChild(root, "Install");
        if (installEl is null)
            return null;

        string? first = null;
        foreach (var cmd in installEl.Elements())
        {
            if (!cmd.Name.LocalName.Equals("Cmdline", StringComparison.OrdinalIgnoreCase))
                continue;

            var val = cmd.Value?.Trim();
            if (string.IsNullOrEmpty(val))
                continue;

            first ??= val;
            if (string.Equals(GetAttribute(cmd, "id"), "EN", StringComparison.OrdinalIgnoreCase))
                return val;
        }

        return first;
    }

    private static string? ExtractLocalizedDesc(XElement root, string sectionName)
    {
        var section = FindChild(root, sectionName);
        if (section is null)
            return null;

        string? first = null;
        foreach (var desc in section.Elements())
        {
            if (!desc.Name.LocalName.Equals("Desc", StringComparison.OrdinalIgnoreCase))
                continue;

            var text = desc.Value?.Trim();
            if (string.IsNullOrEmpty(text))
                continue;

            first ??= text;
            if (string.Equals(GetAttribute(desc, "id"), "EN", StringComparison.OrdinalIgnoreCase))
                return text;
        }

        return first;
    }

    private static BiosUpdateSeverity ParseSeverity(XElement? severityEl)
    {
        if (severityEl is null)
            return BiosUpdateSeverity.Recommended;

        var raw = FirstNonEmpty(GetAttribute(severityEl, "type"), severityEl.Value);
        if (string.IsNullOrWhiteSpace(raw))
            return BiosUpdateSeverity.Recommended;

        if (raw.Equals("1", StringComparison.OrdinalIgnoreCase)
            || raw.Contains("critical", StringComparison.OrdinalIgnoreCase)
            || raw.Contains("security", StringComparison.OrdinalIgnoreCase))
        {
            return BiosUpdateSeverity.Critical;
        }

        if (raw.Equals("2", StringComparison.OrdinalIgnoreCase)
            || raw.Contains("recommended", StringComparison.OrdinalIgnoreCase))
        {
            return BiosUpdateSeverity.Recommended;
        }

        if (raw.Equals("3", StringComparison.OrdinalIgnoreCase)
            || raw.Contains("optional", StringComparison.OrdinalIgnoreCase))
        {
            return BiosUpdateSeverity.Optional;
        }

        return BiosUpdateSeverity.Unknown;
    }

    private static bool ParseRequiresReboot(XElement? rebootEl)
    {
        if (rebootEl is null)
            return true;

        var type = GetAttribute(rebootEl, "type");
        return !string.Equals(type, "0", StringComparison.OrdinalIgnoreCase);
    }

    private static string? TryExtractValidSha256(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        var trimmed = raw.Trim();
        return Sha256HexRegex().IsMatch(trimmed) ? trimmed.ToLowerInvariant() : null;
    }

    private static string? GetMetadataValue(IReadOnlyDictionary<string, string>? metadata, string key)
    {
        if (metadata is null)
            return null;

        if (metadata.TryGetValue(key, out var val) && !string.IsNullOrWhiteSpace(val))
            return val.Trim();

        foreach (var kvp in metadata)
        {
            if (kvp.Key.Equals(key, StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(kvp.Value))
                return kvp.Value.Trim();
        }

        return null;
    }

    private static XElement? FindChild(XElement parent, string localName)
    {
        foreach (var child in parent.Elements())
        {
            if (child.Name.LocalName.Equals(localName, StringComparison.OrdinalIgnoreCase))
                return child;
        }

        return null;
    }

    private static string? GetChildValue(XElement parent, string localName)
    {
        var child = FindChild(parent, localName);
        var val = child?.Value?.Trim();
        return string.IsNullOrEmpty(val) ? null : val;
    }

    private static string? GetDescendantValue(XElement root, string localName)
    {
        foreach (var el in root.Descendants())
        {
            if (el.Name.LocalName.Equals(localName, StringComparison.OrdinalIgnoreCase))
            {
                var val = el.Value?.Trim();
                if (!string.IsNullOrEmpty(val))
                    return val;
            }
        }

        return null;
    }

    private static string? GetAttribute(XElement element, string localName)
    {
        foreach (var attr in element.Attributes())
        {
            if (attr.Name.LocalName.Equals(localName, StringComparison.OrdinalIgnoreCase))
            {
                var val = attr.Value?.Trim();
                if (!string.IsNullOrEmpty(val))
                    return val;
            }
        }

        return null;
    }

    private static string? FirstNonEmpty(params string?[] values)
    {
        foreach (var value in values)
        {
            if (!string.IsNullOrWhiteSpace(value))
                return value.Trim();
        }

        return null;
    }

    private static long? TryParsePositiveLong(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        return long.TryParse(raw.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var value) && value > 0
            ? value
            : null;
    }

    private static bool TryEnsureExecutableExtension(string filePath, out string executablePath, out string error)
    {
        executablePath = filePath;
        error = "";

        var ext = Path.GetExtension(filePath);
        if (string.Equals(ext, ".exe", StringComparison.OrdinalIgnoreCase))
            return true;

        if (string.IsNullOrEmpty(ext))
        {
            var renamed = filePath + ".exe";
            File.Move(filePath, renamed, overwrite: true);
            executablePath = renamed;
            return true;
        }

        error = $"Lenovo BIOS installer package must be an .exe file (got '{ext}').";
        return false;
    }

    private static async Task<string> ReadBoundedStringAsync(HttpContent content, long maxBytes, CancellationToken ct)
    {
        var contentLength = content.Headers.ContentLength;
        if (contentLength.HasValue && contentLength.Value > maxBytes)
            throw new InvalidDataException($"Lenovo BIOS XML response ({contentLength.Value} bytes) exceeds maximum allowed limit ({maxBytes} bytes).");

        await using var source = await content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var destination = contentLength is > 0
            ? new MemoryStream((int)Math.Min(contentLength.Value, MaxInitialStreamCapacity))
            : new MemoryStream();

        var buffer = ArrayPool<byte>.Shared.Rent(CopyBufferSize);
        try
        {
            long totalRead = 0;
            while (true)
            {
                var read = await source.ReadAsync(buffer.AsMemory(0, CopyBufferSize), ct).ConfigureAwait(false);
                if (read == 0)
                    break;

                totalRead += read;
                if (totalRead > maxBytes)
                    throw new InvalidDataException($"Lenovo BIOS XML response exceeded maximum allowed limit ({maxBytes} bytes).");

                destination.Write(buffer, 0, read);
            }

            var bytes = destination.ToArray();
            return Encoding.UTF8.GetString(bytes);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
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
            // Best-effort cleanup of provider-owned temporary staging directory.
        }
    }

    internal enum LenovoVersionKind
    {
        Empty = 0,
        RecognizedSymbolic = 1,
        PureNumeric = 2,
        Unrecognized = 3,
    }

    internal sealed record ParsedLenovoVersion(
        string Version,
        string Family,
        string? NumericVersion,
        string? SymbolicVersion,
        LenovoVersionKind Kind);

    private sealed record LenovoIndexEntry(
        string DescriptorUrl,
        string? Version,
        DateOnly? ReleaseDate,
        string? BiosVersion,
        string Family,
        LenovoVersionKind VersionKind,
        string? CompareVersion);

    private sealed record LenovoDescriptorCandidate(
        string Version,
        string Family,
        string? NumericVersion,
        string? SymbolicVersion,
        LenovoVersionKind PrimaryKind,
        bool HasDescriptorFamilyConflict,
        string? PackageId,
        DateOnly? ReleaseDate,
        BiosUpdateSeverity Severity,
        bool RequiresReboot,
        string? ReleaseSummary,
        string DownloadUrl,
        string? ReleaseNotesUrl,
        string? Sha256,
        long? SizeBytes,
        string DescriptorUrl,
        string InstallMode);
}
