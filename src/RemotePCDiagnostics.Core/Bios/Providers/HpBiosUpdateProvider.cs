using System.Buffers;
using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Bios;

/// <summary>
/// Built-in pure-C# BIOS update provider for HP commercial and consumer systems.
/// Queries HP HPIA / SoftPaq HTTPS XML/CAB catalogs using the 4-hex HP SystemId
/// (<c>BoardProduct</c>, falling back to <c>SystemSku</c>) and stages signed/verified
/// SoftPaq or <c>HPBIOSUPDREC</c> executables silently via <see cref="BiosInstallerRunner"/>
/// (routing privileged operations through <see cref="IElevatedCommandBridge"/> when un-elevated).
/// </summary>
public sealed partial class HpBiosUpdateProvider : IBiosUpdateProvider
{
    public const string ProviderVendorId = "hp";
    public const string DefaultCatalogUrlTemplate = "https://hpia.hpcloud.hp.com/ref/{systemId}/{systemId}_64_{osVersion}.cab";
    public static readonly IReadOnlyList<string> AllowedHostSuffixes = ["hp.com", "hpcloud.hp.com"];

    private const long MaxCatalogDownloadBytes = 64L * 1024 * 1024;
    private const long MaxCatalogDecompressedBytes = 64L * 1024 * 1024;
    private const int MaxInitialStreamCapacity = 1024 * 1024;
    private const int CopyBufferSize = 81920;

    private static readonly TimeSpan DefaultInstallerTimeout = TimeSpan.FromMinutes(10);
    private static readonly HashSet<int> RebootSuccessExitCodes = [0, 3010];

    private static readonly string[] PeripheralFirmwareKeywords =
    [
        "dock", "ssd", "hdd", "nvme", "storage", "camera", "webcam",
        "audio", "thunderbolt", "network", "wlan", "bluetooth", "wwan",
        "touchpad", "keyboard", "monitor", "display", "battery", "gpu",
        "management engine", "csme", "configuration utility",
    ];

    [GeneratedRegex(@"\b(?:amt|me)\b", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex ShortPeripheralTokenRegex();

    private static readonly HashSet<string> IgnoredTitleTokens = new(StringComparer.OrdinalIgnoreCase)
    {
        "64-bit", "32-bit", "x64", "x86", "arm64", "uefi", "bios",
        "win10", "win11", "windows", "international", "english", "rev",
    };

    [GeneratedRegex(
        @"^([A-Za-z0-9]{2,6})\s+(?:Ver\.?\s*|v\s*)(\d+(?:\.\d+)*)(?:\s+(?:Rev\.?\s*)?[A-Za-z][A-Za-z0-9]?)?(?:\s+\d{2,4}[/\-]\d{2}[/\-]\d{2,4})?$",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex CommercialVersionRegex();

    [GeneratedRegex(
        @"^([A-Za-z]{1,2})\.(\d+(?:\.\d+)*)(?:\s+(?:Rev\.?\s*)?[A-Za-z][A-Za-z0-9]?)?$",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex ConsumerLetterVersionRegex();

    [GeneratedRegex(
        @"^(\d+(?:\.\d+)+)(?:\s+(?:Rev\.?\s*)?[A-Za-z][A-Za-z0-9]?)?$",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex PureNumericVersionRegex();

    [GeneratedRegex(@"\(((?=[A-Za-z0-9]*[A-Za-z])[A-Za-z0-9]{2,6})\)", RegexOptions.CultureInvariant)]
    private static partial Regex TitleParenthesizedFamilyRegex();

    [GeneratedRegex(@"\A[0-9A-Fa-f]{64}\z", RegexOptions.CultureInvariant)]
    private static partial Regex Sha256HexRegex();

    private readonly HttpClient _http;
    private readonly SystemCommandRunner? _commands;
    private readonly IBiosSignatureVerifier _signatureVerifier;
    private readonly IElevatedCommandBridge? _elevatedBridge;
    private readonly Func<bool>? _isProcessElevated;
    private readonly ILogger? _log;
    private readonly string _catalogUrlTemplate;

    public HpBiosUpdateProvider(
        HttpClient? httpClient = null,
        SystemCommandRunner? commands = null,
        IBiosSignatureVerifier? signatureVerifier = null,
        IElevatedCommandBridge? elevatedBridge = null,
        Func<bool>? isProcessElevated = null,
        ILogger? log = null,
        string? catalogUrlTemplate = null)
    {
        _http = httpClient ?? BiosProviderHttp.SharedClient;
        _commands = commands;
        _signatureVerifier = signatureVerifier ?? WinVerifyTrustSignatureVerifier.Instance;
        _elevatedBridge = elevatedBridge;
        _isProcessElevated = isProcessElevated;
        _log = log;
        _catalogUrlTemplate = string.IsNullOrWhiteSpace(catalogUrlTemplate)
            ? DefaultCatalogUrlTemplate
            : catalogUrlTemplate.Trim();
    }

    public static HpBiosUpdateProvider CreateWithHandler(
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
    public string DisplayName => "HP";
    public int Priority => 100;

    public BiosProviderCapabilities Capabilities { get; } = new(
        CanCheckLatest: true,
        CanInstall: true,
        SupportsSilentInstall: true,
        RequiresReboot: true,
        RequiresElevation: true,
        RequiresInternet: true);

    public bool CanHandle(BiosSystemIdentity system) =>
        system is not null && BiosVendorIdentity.IsHp(system);

    public Task<BiosCurrentInfo> GetCurrentVersionAsync(BiosSystemIdentity system, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(system);
        ct.ThrowIfCancellationRequested();

        var current = system.CurrentBios ?? BiosCurrentInfo.Empty;
        var (parsedFamily, normalizedVersion) = NormalizeHpVersion(current.Version);
        var effectiveFamily = !string.IsNullOrEmpty(parsedFamily)
            ? parsedFamily
            : current.Family?.Trim() ?? "";

        var metadata = current.Metadata is not null
            ? new Dictionary<string, string>(current.Metadata, StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (TryExtractSystemId(system, out var systemId))
            metadata["systemId"] = systemId;

        var rawTrimmed = current.Version?.Trim() ?? "";
        if (rawTrimmed.Length > 0 && !string.Equals(rawTrimmed, normalizedVersion, StringComparison.Ordinal))
            metadata["rawVersion"] = rawTrimmed;

        var normalized = current with
        {
            Version = normalizedVersion,
            Family = effectiveFamily,
            ProviderId = VendorId,
            Metadata = metadata.Count > 0 ? metadata : current.Metadata,
        };

        return Task.FromResult(normalized);
    }

    public async Task<BiosLatestInfo> GetLatestVersionAsync(
        BiosSystemIdentity system,
        BiosCurrentInfo current,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(system);
        ct.ThrowIfCancellationRequested();

        current ??= system.CurrentBios ?? BiosCurrentInfo.Empty;

        if (!TryExtractSystemId(system, out var systemId))
        {
            return BiosLatestInfo.Unsupported(
                VendorId,
                "HP BIOS update lookup requires a valid 4-hex HP SystemId in BoardProduct (or SystemSku).");
        }

        var isWin11 = BiosVendorIdentity.IsWindows11(system.OsVersion);
        var usedOs = isWin11 ? "11.0" : "10.0";
        var primaryUrl = BuildCatalogUrl(_catalogUrlTemplate, systemId, usedOs);

        try
        {
            var response = await BiosProviderHttp.GetFollowingAllowedRedirectsAsync(
                _http,
                primaryUrl,
                AllowedHostSuffixes,
                HttpCompletionOption.ResponseHeadersRead,
                ct).ConfigureAwait(false);

            try
            {
                if (response.StatusCode == HttpStatusCode.NotFound && isWin11)
                {
                    var fallbackUrl = BuildCatalogUrl(_catalogUrlTemplate, systemId, "10.0");
                    if (!string.Equals(fallbackUrl, primaryUrl, StringComparison.OrdinalIgnoreCase))
                    {
                        response.Dispose();
                        usedOs = "10.0";
                        response = await BiosProviderHttp.GetFollowingAllowedRedirectsAsync(
                            _http,
                            fallbackUrl,
                            AllowedHostSuffixes,
                            HttpCompletionOption.ResponseHeadersRead,
                            ct).ConfigureAwait(false);
                    }
                }

                if (!response.IsSuccessStatusCode)
                {
                    return BiosProviderHttp.ClassifyHttpStatus(
                        VendorId,
                        DisplayName,
                        response.StatusCode,
                        $"SystemId {systemId}");
                }

                var payload = await ReadBoundedBytesAsync(response.Content, MaxCatalogDownloadBytes, ct).ConfigureAwait(false);
                var xmlText = await BiosArchiveAndXml.ExtractXmlFromCabOrPlainAsync(
                    payload,
                    $"hp-{systemId}",
                    _commands,
                    ct,
                    MaxCatalogDecompressedBytes).ConfigureAwait(false);

                if (string.IsNullOrWhiteSpace(xmlText))
                {
                    return BiosLatestInfo.Failed(
                        VendorId,
                        $"HP BIOS catalog payload for SystemId {systemId} could not be extracted as valid XML or CAB.");
                }

                var doc = BiosArchiveAndXml.ParseXmlSafe(xmlText);
                return RedactLatestInfo(EvaluateCatalog(doc, systemId, usedOs, current), system.SerialNumber);
            }
            finally
            {
                response.Dispose();
            }
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

        var prev = request.Current?.Version;
        var target = request.Target?.LatestVersion;

        if (request.Target is null || string.IsNullOrWhiteSpace(request.Target.DownloadUrl))
        {
            const string msg = "HP BIOS update target does not include a download URL.";
            progress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, msg));
            return BiosInstallResult.Failed(msg, prev, target);
        }

        string? autoStagingDir = null;
        var effectiveRequest = request;
        if (string.IsNullOrWhiteSpace(request.StagingDirectory))
        {
            autoStagingDir = Path.Combine(Path.GetTempPath(), $"rpd-bios-hp-{Guid.NewGuid():N}");
            effectiveRequest = request with { StagingDirectory = autoStagingDir };
        }

        try
        {
            var defaultFileName = BuildDefaultPackageFileName(request.Target.PackageId);
            var verified = await BiosPackageVerification.DownloadAndVerifyAsync(
                _http,
                effectiveRequest,
                VendorId,
                AllowedHostSuffixes,
                defaultFileName,
                _signatureVerifier,
                progress,
                _log,
                ct).ConfigureAwait(false);

            if (!verified.Succeeded || string.IsNullOrWhiteSpace(verified.FilePath))
            {
                var err = verified.ErrorMessage ?? "HP BIOS package download or verification failed.";
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, err));
                return BiosInstallResult.Failed(err, prev, target);
            }

            if (!TryEnsureExecutableExtension(verified.FilePath, out var packagePath, out var extError))
            {
                TryDeleteFile(verified.FilePath);
                var safeExtError = BiosInstallerRunner.RedactSerialNumber(extError, request.System?.SerialNumber);
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Failed, 0, safeExtError));
                return BiosInstallResult.Failed(safeExtError, prev, target);
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
                return BiosInstallResult.Failed(msg, prev, target, exitCode: SystemCommandRunner.AgentFailedExitCode);
            }

            var installMode = SelectInstallMode(packagePath, request.Target.Metadata);
            // HP HPBIOSUPDREC / SoftPaq uses inverted -r polarity: -r SUPPRESSES reboot when AllowReboot == false.
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
                $"Staging HP BIOS update {target ?? "package"}..."));

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

    internal static bool TryExtractSystemId(BiosSystemIdentity system, out string systemId)
    {
        systemId = "";
        if (system is null)
            return false;

        // Fall back to SystemSku ONLY when BoardProduct is empty/whitespace so invalid/malicious BoardProduct fails fast.
        if (!string.IsNullOrWhiteSpace(system.BoardProduct))
            return BiosVendorIdentity.TryExtractFourHex(system.BoardProduct, out systemId);

        return BiosVendorIdentity.TryExtractFourHex(system.SystemSku, out systemId);
    }

    internal static (string Family, string Version) NormalizeHpVersion(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return ("", "");

        var trimmed = raw.Trim();

        var commercial = CommercialVersionRegex().Match(trimmed);
        if (commercial.Success)
            return (commercial.Groups[1].Value.ToUpperInvariant(), commercial.Groups[2].Value);

        var consumer = ConsumerLetterVersionRegex().Match(trimmed);
        if (consumer.Success)
        {
            var fam = consumer.Groups[1].Value.ToUpperInvariant();
            return (fam, $"{fam}.{consumer.Groups[2].Value}");
        }

        var numeric = PureNumericVersionRegex().Match(trimmed);
        if (numeric.Success)
            return ("", numeric.Groups[1].Value);

        return ("", trimmed);
    }

    private BiosLatestInfo EvaluateCatalog(XDocument doc, string systemId, string usedOs, BiosCurrentInfo current)
    {
        var (parsedCurrentFamily, currentNormalizedVersion) = NormalizeHpVersion(current.Version);
        var effectiveCurrentFamily = !string.IsNullOrWhiteSpace(current.Family)
            ? current.Family.Trim()
            : parsedCurrentFamily;

        var candidates = new List<HpCatalogEntry>();
        var hadDisallowedUrl = false;

        foreach (var el in doc.Descendants())
        {
            var local = el.Name.LocalName;
            if (!local.Equals("UpdateInfo", StringComparison.OrdinalIgnoreCase)
                && !local.Equals("SoftPaq", StringComparison.OrdinalIgnoreCase)
                && !local.Equals("Package", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var category = GetField(el, "Category", "Type", "Class", "ComponentType");
            var name = GetField(el, "Name", "Title", "ProductName");
            if (!IsBiosCategory(category, name))
                continue;

            var rawVersion = GetField(el, "Version", "BiosVersion", "FirmwareVersion");
            var (verFamily, normalizedVersion) = NormalizeHpVersion(rawVersion);
            if (string.IsNullOrWhiteSpace(normalizedVersion))
                continue;

            var explicitFamily = GetField(el, "Family", "BiosFamily", "RomFamily");
            var nameFamily = TryExtractFamilyFromTitle(name);
            var entryFamily = FirstNonEmpty(explicitFamily, verFamily, nameFamily) ?? "";

            if (!string.IsNullOrEmpty(effectiveCurrentFamily)
                && !string.IsNullOrEmpty(entryFamily)
                && !string.Equals(effectiveCurrentFamily, entryFamily, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var rawDownloadUrl = GetField(el, "Url", "DownloadUrl", "DownloadURL", "SoftPaqUrl", "FileUrl");
            string? validatedDownloadUrl = null;
            if (!string.IsNullOrWhiteSpace(rawDownloadUrl))
            {
                if (!TryNormalizeAndValidateUrl(rawDownloadUrl, out validatedDownloadUrl)
                    || !Uri.TryCreate(validatedDownloadUrl, UriKind.Absolute, out var dlUri)
                    || !dlUri.AbsolutePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                {
                    hadDisallowedUrl = true;
                    _log?.Warn($"[BIOS/HP] Ignored catalog entry for SystemId {systemId} with disallowed or non-.exe download URL.");
                    continue;
                }
            }

            var packageId = GetField(el, "Id", "SoftPaqId", "PackageId", "SPNumber");
            var releaseDate = BiosVersionComparer.TryParseReleaseDate(
                GetField(el, "DateReleased", "ReleaseDate", "Date", "PublishedDate"));
            var sizeBytes = TryParsePositiveLong(GetField(el, "Size", "SizeBytes", "FileSize"));
            var sha256 = TryExtractValidSha256(GetField(el, "SHA256", "Sha256", "Sha256Hash", "Checksum", "Hash"));
            var severity = ParseSeverity(GetField(el, "Severity", "Urgency", "Importance", "Priority"));
            var summary = FirstNonEmpty(GetField(el, "Description", "Summary"), name);
            var rawReleaseNotes = GetField(el, "ReleaseNotesUrl", "ReleaseNotesURL", "CvaUrl", "CvaURL", "InfoUrl");
            TryNormalizeAndValidateUrl(rawReleaseNotes, out var releaseNotesUrl);
            var silentInstallHint = GetField(el, "SilentInstall", "CommandLine", "Installer");

            candidates.Add(new HpCatalogEntry(
                Version: normalizedVersion,
                Family: entryFamily,
                PackageId: packageId,
                ReleaseDate: releaseDate,
                SizeBytes: sizeBytes,
                Sha256: sha256,
                Severity: severity,
                ReleaseSummary: summary,
                DownloadUrl: validatedDownloadUrl,
                ReleaseNotesUrl: releaseNotesUrl,
                SilentInstallHint: silentInstallHint));
        }

        if (candidates.Count == 0)
        {
            if (hadDisallowedUrl)
            {
                return BiosLatestInfo.Failed(
                    VendorId,
                    $"HP BIOS catalog for SystemId {systemId} returned a disallowed download URL.");
            }

            return BiosLatestInfo.Unsupported(
                VendorId,
                $"No HP BIOS release was found in catalog for SystemId {systemId}.");
        }

        var best = candidates[0];
        for (var i = 1; i < candidates.Count; i++)
        {
            var candidate = candidates[i];
            var cmp = BiosVersionComparer.Compare(best.Version, candidate.Version);
            if (cmp < 0)
            {
                best = candidate;
            }
            else if ((cmp is null or 0) && candidate.ReleaseDate.HasValue
                     && (!best.ReleaseDate.HasValue || candidate.ReleaseDate.Value > best.ReleaseDate.Value))
            {
                best = candidate;
            }
        }

        var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["systemId"] = systemId,
            ["osVersion"] = usedOs,
        };

        if (!string.IsNullOrEmpty(best.Family))
            metadata["family"] = best.Family;

        if (IsHpBiosUpdRecHint(best.SilentInstallHint) || IsHpBiosUpdRecHint(best.DownloadUrl))
            metadata["installerType"] = BiosAgentInstallModes.HpBiosUpdRec;

        var isNewer = BiosVersionComparer.IsNewer(
            currentNormalizedVersion,
            best.Version,
            current.ReleaseDate,
            best.ReleaseDate);

        if (!isNewer)
        {
            return BiosLatestInfo.UpToDate(
                providerId: VendorId,
                latestVersion: best.Version,
                releaseDate: best.ReleaseDate,
                metadata: metadata);
        }

        return BiosLatestInfo.UpdateAvailable(
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
            requiresReboot: true,
            metadata: metadata);
    }

    private static string BuildCatalogUrl(string template, string systemId, string osVersion) =>
        template
            .Replace("{systemId}", systemId.ToLowerInvariant(), StringComparison.Ordinal)
            .Replace("{SYSTEMID}", systemId.ToUpperInvariant(), StringComparison.Ordinal)
            .Replace("{osVersion}", osVersion, StringComparison.Ordinal)
            .Replace("{os}", osVersion, StringComparison.Ordinal);

    private static bool IsBiosCategory(string? category, string? name)
    {
        if (!string.IsNullOrWhiteSpace(name) && ContainsPeripheralKeyword(name))
            return false;

        if (!string.IsNullOrWhiteSpace(category))
        {
            if (ContainsPeripheralKeyword(category))
                return false;

            if (category.Contains("BIOS", StringComparison.OrdinalIgnoreCase)
                || category.Contains("System Firmware", StringComparison.OrdinalIgnoreCase)
                || category.Contains("System ROM", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (category.Contains("Firmware", StringComparison.OrdinalIgnoreCase)
                && !string.IsNullOrWhiteSpace(name)
                && (name.Contains("BIOS", StringComparison.OrdinalIgnoreCase)
                    || name.Contains("System Firmware", StringComparison.OrdinalIgnoreCase)
                    || name.Contains("System ROM", StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }

            return false;
        }

        if (string.IsNullOrWhiteSpace(name))
            return false;

        return name.Contains("System BIOS", StringComparison.OrdinalIgnoreCase)
            || name.Contains("BIOS Update", StringComparison.OrdinalIgnoreCase)
            || name.Contains("UEFI Firmware", StringComparison.OrdinalIgnoreCase);
    }

    private static bool ContainsPeripheralKeyword(string text)
    {
        foreach (var keyword in PeripheralFirmwareKeywords)
        {
            if (text.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return ShortPeripheralTokenRegex().IsMatch(text);
    }

    private static string? TryExtractFamilyFromTitle(string? title)
    {
        if (string.IsNullOrWhiteSpace(title))
            return null;

        foreach (Match match in TitleParenthesizedFamilyRegex().Matches(title))
        {
            var token = match.Groups[1].Value;
            if (IgnoredTitleTokens.Contains(token))
                continue;

            // HP commercial BIOS families include at least one digit (e.g., U70, T76, S70, 786G1).
            var hasDigit = false;
            foreach (var c in token)
            {
                if (char.IsAsciiDigit(c))
                {
                    hasDigit = true;
                    break;
                }
            }

            if (hasDigit)
                return token.ToUpperInvariant();
        }

        return null;
    }

    private static bool TryNormalizeAndValidateUrl(string? raw, out string? validated)
    {
        validated = null;
        if (string.IsNullOrWhiteSpace(raw))
            return false;

        var trimmed = raw.Trim();
        string candidate;
        if (trimmed.Contains("://", StringComparison.Ordinal) || trimmed.StartsWith("//", StringComparison.Ordinal))
        {
            // Never auto-upgrade explicit http://, ftp://, file://, or protocol-relative URLs.
            candidate = trimmed;
        }
        else if (char.IsAsciiLetterOrDigit(trimmed[0]))
        {
            // Real HPIA catalogs frequently list bare host/path URLs like "ftp.hp.com/pub/softpaq/sp151234.exe".
            candidate = "https://" + trimmed;
        }
        else
        {
            return false;
        }

        if (candidate.Contains('\\', StringComparison.Ordinal) || HasUnsafePathSegments(candidate))
            return false;

        if (!BiosProviderHttp.TryValidateHttpsUrl(candidate, AllowedHostSuffixes, out var uri, out _))
            return false;

        validated = uri.AbsoluteUri;
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

    private static string? GetField(XElement element, params string[] names)
    {
        foreach (var name in names)
        {
            foreach (var child in element.Elements())
            {
                if (child.Name.LocalName.Equals(name, StringComparison.OrdinalIgnoreCase))
                {
                    var val = child.Value?.Trim();
                    if (!string.IsNullOrEmpty(val))
                        return val;
                }
            }

            foreach (var attr in element.Attributes())
            {
                if (attr.Name.LocalName.Equals(name, StringComparison.OrdinalIgnoreCase))
                {
                    var val = attr.Value?.Trim();
                    if (!string.IsNullOrEmpty(val))
                        return val;
                }
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

        return long.TryParse(raw.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) && value > 0
            ? value
            : null;
    }

    private static string? TryExtractValidSha256(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        var trimmed = raw.Trim();
        return Sha256HexRegex().IsMatch(trimmed) ? trimmed.ToLowerInvariant() : null;
    }

    private static BiosUpdateSeverity ParseSeverity(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return BiosUpdateSeverity.Recommended;

        var trimmed = raw.Trim();
        if (trimmed.Equals("1", StringComparison.OrdinalIgnoreCase)
            || trimmed.Contains("critical", StringComparison.OrdinalIgnoreCase)
            || trimmed.Contains("security", StringComparison.OrdinalIgnoreCase)
            || trimmed.Contains("urgent", StringComparison.OrdinalIgnoreCase))
        {
            return BiosUpdateSeverity.Critical;
        }

        if (trimmed.Equals("2", StringComparison.OrdinalIgnoreCase)
            || trimmed.Contains("recommended", StringComparison.OrdinalIgnoreCase)
            || trimmed.Contains("important", StringComparison.OrdinalIgnoreCase))
        {
            return BiosUpdateSeverity.Recommended;
        }

        if (trimmed.Equals("3", StringComparison.OrdinalIgnoreCase)
            || trimmed.Contains("routine", StringComparison.OrdinalIgnoreCase)
            || trimmed.Contains("optional", StringComparison.OrdinalIgnoreCase))
        {
            return BiosUpdateSeverity.Optional;
        }

        if (trimmed.Equals("unknown", StringComparison.OrdinalIgnoreCase))
            return BiosUpdateSeverity.Unknown;

        return BiosUpdateSeverity.Recommended;
    }

    private static string SelectInstallMode(string packagePath, IReadOnlyDictionary<string, string>? metadata)
    {
        if (metadata is not null && metadata.TryGetValue("installerType", out var installerType))
        {
            if (string.Equals(installerType?.Trim(), BiosAgentInstallModes.HpBiosUpdRec, StringComparison.OrdinalIgnoreCase)
                || IsHpBiosUpdRecHint(installerType))
            {
                return BiosAgentInstallModes.HpBiosUpdRec;
            }
        }

        return IsHpBiosUpdRecHint(Path.GetFileName(packagePath))
            ? BiosAgentInstallModes.HpBiosUpdRec
            : BiosAgentInstallModes.HpSoftPaq;
    }

    private static bool IsHpBiosUpdRecHint(string? value) =>
        !string.IsNullOrWhiteSpace(value)
        && (value.Contains("HPBIOSUPDREC", StringComparison.OrdinalIgnoreCase)
            || value.Contains("HpFirmwareUpdRec", StringComparison.OrdinalIgnoreCase));

    private static string BuildDefaultPackageFileName(string? packageId)
    {
        if (string.IsNullOrWhiteSpace(packageId))
            return "hp-bios-update.exe";

        var sanitized = BiosVendorIdentity.SanitizeFileName(packageId, "hp-bios-update.exe");
        return sanitized.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? sanitized
            : sanitized + ".exe";
    }

    private static bool TryEnsureExecutableExtension(string filePath, out string executablePath, out string error) =>
        BiosPackageVerification.TryEnsureExecutableExtension(filePath, "HP", out executablePath, out error);

    private static async Task<byte[]> ReadBoundedBytesAsync(HttpContent content, long maxBytes, CancellationToken ct)
    {
        var contentLength = content.Headers.ContentLength;
        if (contentLength.HasValue && contentLength.Value > maxBytes)
            throw new InvalidDataException($"HP BIOS catalog size ({contentLength.Value} bytes) exceeds maximum allowed limit ({maxBytes} bytes).");

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
                    throw new InvalidDataException($"HP BIOS catalog stream exceeded maximum allowed limit ({maxBytes} bytes).");

                destination.Write(buffer, 0, read);
            }

            return destination.ToArray();
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

    private sealed record HpCatalogEntry(
        string Version,
        string Family,
        string? PackageId,
        DateOnly? ReleaseDate,
        long? SizeBytes,
        string? Sha256,
        BiosUpdateSeverity Severity,
        string? ReleaseSummary,
        string? DownloadUrl,
        string? ReleaseNotesUrl,
        string? SilentInstallHint);
}
