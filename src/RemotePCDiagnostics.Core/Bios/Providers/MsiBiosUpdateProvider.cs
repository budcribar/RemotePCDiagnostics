using System.Buffers;
using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace RemotePCDiagnostics.Core.Bios;

/// <summary>
/// Check-only MSI BIOS/UEFI update provider (<c>VendorId = "msi"</c>).
/// Queries the MSI Support BIOS JSON API over HTTPS (100% pure C#, zero external processes or scripts).
/// Automated installation is not supported because MSI consumer/desktop boards rely on M-Flash.
/// </summary>
public sealed partial class MsiBiosUpdateProvider : IBiosUpdateProvider
{
    public const string ProviderVendorId = "msi";
    public const string DefaultCatalogEndpoint = "https://www.msi.com/api/v1/product/support/panel?product={product}&type=bios";

    public static readonly IReadOnlyList<string> AllowedHostSuffixes = ["msi.com"];

    public const long MaxCatalogJsonBytes = 8L * 1024 * 1024;
    private const int MaxInitialStreamCapacity = 256 * 1024;
    private const int ReadBufferSize = 81920;
    private const int MaxSummaryLength = 1000;

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

    private static readonly string[] NonBiosTitleAlwaysRejectKeywords =
    [
        "bios-utilities",
        "bios utilities",
        "bios utility",
        "meupdatetool",
        "me update tool",
        "management engine",
        "intel me",
        "csme",
        "pd firmware",
        "led firmware",
        "rgb firmware",
        "flash tool",
        "vbios",
        "video bios",
        "vga bios",
        "manual",
        "user guide",
        "driver",
        "drivers",
        "utility",
        "utilities",
        "application",
    ];

    private static readonly string[] NonBiosCategoryKeywords =
    [
        "bios-utilities",
        "bios utilities",
        "bios utility",
        "meupdatetool",
        "me update tool",
        "management engine",
        "intel me",
        "csme",
        "pd firmware",
        "led firmware",
        "rgb firmware",
        "flash tool",
        "audio",
        "lan",
        "wlan",
        "wifi",
        "wireless",
        "bluetooth",
        "vga",
        "vbios",
        "video bios",
        "vga bios",
        "gpu",
        "graphics",
        "chipset",
        "sata",
        "raid",
        "ahci",
        "usb",
        "thunderbolt",
        "camera",
        "webcam",
        "touchpad",
        "fingerprint",
        "card reader",
        "modem",
        "wwan",
        "manual",
        "user guide",
        "driver",
        "drivers",
        "utility",
        "utilities",
        "application",
        "ssd",
        "nvme",
        "dock",
        "monitor",
    ];

    private static readonly IEqualityComparer<(int PrefRank, string ClassKey)> BucketKeyComparer = new BucketKeyEqualityComparer();

    [GeneratedRegex(@"\A[0-9A-Fa-f]{64}\z", RegexOptions.CultureInvariant)]
    private static partial Regex Sha256Regex();

    [GeneratedRegex(@"^MS-([0-9A-Za-z]{4})$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex ExactMsBoardCodeRegex();

    [GeneratedRegex(@"\(\s*MS-([0-9A-Za-z]{4})\s*\)$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex ParenthesizedMsBoardCodeRegex();

    [GeneratedRegex(@"^(?:BIOS\s+Version|Version|Ver\.?|Rev\.?|BIOS)\s*[:\-]?\s*", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex LeadingVersionPrefixRegex();

    [GeneratedRegex(@"\s*\([^)]*(?:beta|alpha|pre-?release|test)[^)]*\)\s*$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex TrailingParenBetaRegex();

    [GeneratedRegex(@"\s+(?:beta(?:\s+version|\s+bios)?|alpha|pre-?release)\s*$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex TrailingWordBetaRegex();

    [GeneratedRegex(@"^(?:MS-?)?([0-9A-Za-z]{4})[vV]([0-9A-Za-z])([0-9A-Za-z])([0-9A-Za-z])?$", RegexOptions.CultureInvariant)]
    private static partial Regex MsiVNotationRegex();

    [GeneratedRegex(@"^E([0-9A-Za-z]{4})[A-Za-z]{2,4}\.([0-9A-Za-z])([0-9A-Za-z])([0-9A-Za-z])$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex MsiAmiRomRegex();

    [GeneratedRegex(@"^([0-9A-Za-z])\.([0-9A-Za-z])([0-9A-Za-z])$", RegexOptions.CultureInvariant)]
    private static partial Regex MsiDottedThreeCharRegex();

    [GeneratedRegex(@"\b(?:beta|alpha|pre-?release|engineering\s+sample|test\s+bios)\b", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
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
    private static partial Regex EndpointPlaceholderRegex();

    private readonly HttpClient _httpClient;
    private readonly ILogger? _log;
    private readonly string _catalogEndpoint;

    /// <summary>
    /// Creates an MSI BIOS update provider. All parameters are optional so MS.DI resolves
    /// this single constructor cleanly with zero optional service registrations.
    /// </summary>
    public MsiBiosUpdateProvider(
        HttpClient? httpClient = null,
        ILogger? log = null,
        string? catalogEndpoint = null)
    {
        _httpClient = httpClient ?? BiosProviderHttp.SharedClient;
        _log = log;
        _catalogEndpoint = string.IsNullOrWhiteSpace(catalogEndpoint)
            ? DefaultCatalogEndpoint
            : catalogEndpoint.Trim();
    }

    /// <summary>Creates a provider backed by a custom <see cref="HttpMessageHandler"/> (e.g., for offline tests).</summary>
    public static MsiBiosUpdateProvider CreateWithHandler(
        HttpMessageHandler httpHandler,
        ILogger? log = null,
        string? catalogEndpoint = null) =>
        new(BiosProviderHttp.CreateClient(httpHandler), log, catalogEndpoint);

    public string VendorId => ProviderVendorId;
    public string DisplayName => "MSI";
    public int Priority => 100;

    public BiosProviderCapabilities Capabilities { get; } = new(
        CanCheckLatest: true,
        CanInstall: false,
        SupportsSilentInstall: false,
        RequiresReboot: false,
        RequiresElevation: false,
        RequiresInternet: true);

    public bool CanHandle(BiosSystemIdentity system) =>
        system is not null && BiosVendorIdentity.IsMsi(system);

    public Task<BiosCurrentInfo> GetCurrentVersionAsync(BiosSystemIdentity system, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(system);
        ct.ThrowIfCancellationRequested();

        var current = system.CurrentBios ?? BiosCurrentInfo.Empty;
        var parsed = ParseMsiVersion(current.Version);
        var metadata = current.Metadata is not null
            ? new Dictionary<string, string>(current.Metadata, StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        string? boardCode = parsed.BoardCode;
        if (TryResolveBoardOrModel(system, out var queryToken, out var extractedBoardCode, out _))
        {
            metadata["model"] = queryToken;
            if (!string.IsNullOrEmpty(extractedBoardCode))
                boardCode ??= extractedBoardCode;
        }

        if (!string.IsNullOrEmpty(boardCode))
            metadata["boardCode"] = boardCode;

        var normalizedVersion = current.Version?.Trim() ?? "";
        var family = current.Family ?? "";

        if (parsed.Kind == MsiVersionKind.MsiReleaseCode)
        {
            normalizedVersion = parsed.CanonicalVersion;
            metadata["msiMajor"] = parsed.Major.ToString();
            family = !string.IsNullOrEmpty(boardCode)
                ? $"{boardCode}-{parsed.Major}"
                : parsed.Major.ToString();

            if (parsed.IsBeta)
                metadata["isBeta"] = "true";

            if (!string.IsNullOrWhiteSpace(current.Version))
            {
                var rawTrimmed = current.Version.Trim();
                if (parsed.IsBeta || !string.Equals(rawTrimmed, normalizedVersion, StringComparison.Ordinal))
                    metadata["rawVersion"] = rawTrimmed;
            }
        }
        else if (parsed.IsBeta)
        {
            metadata["isBeta"] = "true";
            if (!string.IsNullOrWhiteSpace(current.Version))
                metadata["rawVersion"] = current.Version.Trim();
        }

        var safeMetadata = RedactMetadata(metadata, system.SerialNumber);
        var safeVersion = RedactText(normalizedVersion, system.SerialNumber);
        var safeFamily = RedactText(family, system.SerialNumber);

        return Task.FromResult(current with
        {
            Version = safeVersion,
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
        ArgumentNullException.ThrowIfNull(current);
        ct.ThrowIfCancellationRequested();

        if (!TryResolveBoardOrModel(system, out var productToken, out var extractedBoardCode, out var invalidReason))
        {
            LogWarn($"[BIOS/MSI] Unable to determine valid MSI board/model identifier: {invalidReason}", system.SerialNumber);
            return RedactLatestInfo(
                BiosLatestInfo.Unsupported(VendorId, $"Unable to determine a valid MSI motherboard or model identifier: {invalidReason}"),
                system.SerialNumber);
        }

        var requestUrl = BuildCatalogUrl(_catalogEndpoint, productToken);
        if (!TryValidateVendorUrl(requestUrl, AllowedHostSuffixes, out _))
        {
            LogWarn("[BIOS/MSI] Configured MSI catalog endpoint failed HTTPS/domain/path validation.", system.SerialNumber);
            return RedactLatestInfo(
                BiosLatestInfo.Failed(VendorId, "MSI BIOS catalog endpoint URL failed security validation."),
                system.SerialNumber);
        }

        try
        {
            using var response = await GetCatalogWithSafeRedirectsAsync(requestUrl, ct).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                var statusInfo = BiosProviderHttp.ClassifyHttpStatus(VendorId, DisplayName, response.StatusCode, $"product '{productToken}'");
                return RedactLatestInfo(statusInfo, system.SerialNumber);
            }

            using var doc = await ReadBoundedJsonDocumentAsync(response.Content, ct).ConfigureAwait(false);
            var evaluated = EvaluateCatalog(doc, current, productToken, extractedBoardCode, system.SerialNumber);
            return RedactLatestInfo(evaluated, system.SerialNumber);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            LogWarn($"[BIOS/MSI] Catalog lookup failed for '{productToken}': {ex.Message}", system.SerialNumber);
            return RedactLatestInfo(
                BiosProviderHttp.ClassifyHttpFailure(VendorId, DisplayName, ex, ct),
                system.SerialNumber);
        }
    }

    public Task<BiosInstallResult> InstallAsync(
        BiosInstallRequest request,
        IProgress<BiosInstallProgress>? progress = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ct.ThrowIfCancellationRequested();

        var serial = request.System?.SerialNumber;
        var previousVersion = request.Current?.Version is not null
            ? RedactText(request.Current.Version, serial)
            : null;
        var targetVersion = request.Target?.LatestVersion is not null
            ? RedactText(request.Target.LatestVersion, serial)
            : null;
        var message = RedactText(
            "MSI BIOS provider is check-only and does not support automated installation. Download the verified BIOS package manually and flash via MSI M-Flash.",
            serial);

        return Task.FromResult(BiosInstallResult.Unsupported(message, previousVersion, targetVersion));
    }

    private BiosLatestInfo EvaluateCatalog(
        JsonDocument doc,
        BiosCurrentInfo current,
        string productToken,
        string? extractedBoardCode,
        string? serialNumber)
    {
        var root = doc.RootElement;
        if (root.ValueKind is not (JsonValueKind.Object or JsonValueKind.Array))
            return BiosLatestInfo.Failed(VendorId, "MSI BIOS catalog returned an unexpected JSON root type.");

        var parsedCurrent = ParseMsiVersion(current.Version);
        if (!parsedCurrent.IsBeta && current.Metadata is not null)
        {
            var preserveBeta = false;
            if (current.Metadata.TryGetValue("isBeta", out var metaBeta)
                && string.Equals(metaBeta?.Trim(), "true", StringComparison.OrdinalIgnoreCase))
            {
                preserveBeta = true;
            }
            else if (current.Metadata.TryGetValue("rawVersion", out var metaRaw)
                && !string.IsNullOrWhiteSpace(metaRaw))
            {
                var rawParsed = ParseMsiVersion(metaRaw);
                if (rawParsed.IsBeta
                    && string.Equals(rawParsed.CanonicalVersion, parsedCurrent.CanonicalVersion, StringComparison.OrdinalIgnoreCase))
                {
                    preserveBeta = true;
                }
            }

            if (preserveBeta)
                parsedCurrent = parsedCurrent with { IsBeta = true };
        }

        var expectedBoardCode = extractedBoardCode ?? parsedCurrent.BoardCode;
        if (string.IsNullOrEmpty(expectedBoardCode)
            && current.Metadata is not null
            && current.Metadata.TryGetValue("boardCode", out var metaBoard)
            && !string.IsNullOrWhiteSpace(metaBoard))
        {
            expectedBoardCode = metaBoard.Trim();
        }

        var entries = new List<MsiCatalogCandidate>();
        var rejectedUntrusted = new List<MsiCatalogCandidate>();
        var sawAnyBiosEntry = false;
        var sawOnlyBeta = true;

        CollectCandidates(root, entries, rejectedUntrusted, ref sawAnyBiosEntry, ref sawOnlyBeta, serialNumber);

        var compatibleTrusted = FilterCompatibleCandidates(entries, parsedCurrent, expectedBoardCode);
        var compatibleUntrusted = FilterCompatibleCandidates(rejectedUntrusted, parsedCurrent, expectedBoardCode);

        if (compatibleTrusted.Count == 0)
        {
            if (compatibleUntrusted.Count > 0 || rejectedUntrusted.Count > 0)
                return BiosLatestInfo.Failed(VendorId, "MSI BIOS catalog returned BIOS download URL(s) that failed HTTPS/domain security validation.");

            if (sawAnyBiosEntry && sawOnlyBeta)
                return BiosLatestInfo.Unsupported(VendorId, $"MSI BIOS catalog for '{productToken}' contains only beta/pre-release BIOS entries.");

            return BiosLatestInfo.Unsupported(VendorId, $"No compatible MSI system BIOS updates were found for '{productToken}'.");
        }

        var ordered = OrderCandidates(compatibleTrusted, parsedCurrent);
        var best = ordered[0];

        if (compatibleUntrusted.Count > 0)
        {
            foreach (var bad in compatibleUntrusted)
            {
                if (IsCandidateNewer(best.ParsedVersion, best.ReleaseDate, bad.ParsedVersion, bad.ReleaseDate))
                {
                    return BiosLatestInfo.Failed(
                        VendorId,
                        "MSI BIOS catalog contained a newer BIOS entry whose download URL failed HTTPS/domain security validation.");
                }
            }
        }

        var isNewer = IsCandidateNewer(parsedCurrent, current.ReleaseDate, best.ParsedVersion, best.ReleaseDate);
        if (!isNewer)
        {
            if (compatibleUntrusted.Count > 0)
            {
                foreach (var bad in compatibleUntrusted)
                {
                    var cmp = CompareMsiVersions(bad.ParsedVersion, best.ParsedVersion);
                    if (cmp is null or >= 0)
                    {
                        return BiosLatestInfo.Failed(
                            VendorId,
                            "MSI BIOS catalog contained BIOS entries whose download URL failed HTTPS/domain security validation.");
                    }
                }
            }

            var meta = BuildMetadata(productToken, expectedBoardCode ?? best.ParsedVersion.BoardCode, best.ParsedVersion);
            return BiosLatestInfo.UpToDate(
                VendorId,
                best.DisplayVersion,
                best.ReleaseDate,
                message: $"MSI BIOS is up to date ({best.DisplayVersion}).",
                metadata: meta);
        }

        var updateMeta = BuildMetadata(productToken, expectedBoardCode ?? best.ParsedVersion.BoardCode, best.ParsedVersion);
        return BiosLatestInfo.UpdateAvailable(
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
            message: $"MSI BIOS update {best.DisplayVersion} is available for {productToken}.",
            metadata: updateMeta);
    }

    private static Dictionary<string, string> BuildMetadata(string productToken, string? boardCode, MsiParsedVersion parsed)
    {
        var meta = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["product"] = productToken,
        };
        if (!string.IsNullOrEmpty(boardCode))
            meta["boardCode"] = boardCode;
        if (parsed.Kind == MsiVersionKind.MsiReleaseCode)
        {
            meta["msiMajor"] = parsed.Major.ToString();
            meta["canonicalVersion"] = parsed.CanonicalVersion;
        }

        return meta;
    }

    private void CollectCandidates(
        JsonElement root,
        List<MsiCatalogCandidate> trusted,
        List<MsiCatalogCandidate> untrusted,
        ref bool sawAnyBiosEntry,
        ref bool sawOnlyBeta,
        string? serialNumber)
    {
        if (root.ValueKind == JsonValueKind.Array)
        {
            ParseEntriesArray(root, groupCategory: null, trusted, untrusted, ref sawAnyBiosEntry, ref sawOnlyBeta, serialNumber);
            return;
        }

        // Canonical MSI Support Panel structure: result.downloads.<AMI BIOS | BIOS>[]
        if (TryGetPropertyIgnoreCase(root, out var resultEl, "result"))
        {
            if (resultEl.ValueKind == JsonValueKind.Object)
            {
                if (TryGetPropertyIgnoreCase(resultEl, out var downloadsEl, "downloads"))
                {
                    if (downloadsEl.ValueKind == JsonValueKind.Object)
                    {
                        foreach (var section in downloadsEl.EnumerateObject())
                        {
                            if (section.Value.ValueKind != JsonValueKind.Array)
                                continue;

                            if (IsNonBiosCategory(section.Name))
                                continue;

                            ParseEntriesArray(section.Value, section.Name, trusted, untrusted, ref sawAnyBiosEntry, ref sawOnlyBeta, serialNumber);
                        }

                        return;
                    }

                    if (downloadsEl.ValueKind == JsonValueKind.Array)
                    {
                        ParseEntriesArray(downloadsEl, null, trusted, untrusted, ref sawAnyBiosEntry, ref sawOnlyBeta, serialNumber);
                        return;
                    }
                }

                if (TryGetPropertyIgnoreCase(resultEl, out var nestedBios, "BIOS", "bios", "items", "files", "data")
                    && nestedBios.ValueKind == JsonValueKind.Array)
                {
                    ParseEntriesArray(nestedBios, null, trusted, untrusted, ref sawAnyBiosEntry, ref sawOnlyBeta, serialNumber);
                    return;
                }
            }
            else if (resultEl.ValueKind == JsonValueKind.Array)
            {
                ParseEntriesArray(resultEl, null, trusted, untrusted, ref sawAnyBiosEntry, ref sawOnlyBeta, serialNumber);
                return;
            }
        }

        // Fallback flat shapes at root
        if (TryGetPropertyIgnoreCase(root, out var downloadsRoot, "downloads"))
        {
            if (downloadsRoot.ValueKind == JsonValueKind.Object)
            {
                foreach (var section in downloadsRoot.EnumerateObject())
                {
                    if (section.Value.ValueKind != JsonValueKind.Array || IsNonBiosCategory(section.Name))
                        continue;

                    ParseEntriesArray(section.Value, section.Name, trusted, untrusted, ref sawAnyBiosEntry, ref sawOnlyBeta, serialNumber);
                }

                return;
            }

            if (downloadsRoot.ValueKind == JsonValueKind.Array)
            {
                ParseEntriesArray(downloadsRoot, null, trusted, untrusted, ref sawAnyBiosEntry, ref sawOnlyBeta, serialNumber);
                return;
            }
        }

        if (TryGetPropertyIgnoreCase(root, out var flatArray, "BIOS", "bios", "biosUpdates", "items", "files", "data")
            && flatArray.ValueKind == JsonValueKind.Array)
        {
            ParseEntriesArray(flatArray, null, trusted, untrusted, ref sawAnyBiosEntry, ref sawOnlyBeta, serialNumber);
            return;
        }

        if (TryGetPropertyIgnoreCase(root, out _, "download_version", "version", "bios_version", "biosVersion"))
            ParseSingleEntry(root, null, trusted, untrusted, ref sawAnyBiosEntry, ref sawOnlyBeta, serialNumber);
    }

    private void ParseEntriesArray(
        JsonElement array,
        string? groupCategory,
        List<MsiCatalogCandidate> trusted,
        List<MsiCatalogCandidate> untrusted,
        ref bool sawAnyBiosEntry,
        ref bool sawOnlyBeta,
        string? serialNumber)
    {
        foreach (var item in array.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object)
                continue;

            ParseSingleEntry(item, groupCategory, trusted, untrusted, ref sawAnyBiosEntry, ref sawOnlyBeta, serialNumber);
        }
    }

    private void ParseSingleEntry(
        JsonElement item,
        string? groupCategory,
        List<MsiCatalogCandidate> trusted,
        List<MsiCatalogCandidate> untrusted,
        ref bool sawAnyBiosEntry,
        ref bool sawOnlyBeta,
        string? serialNumber)
    {
        var category = GetStringOrNumber(item, "download_type", "type", "category", "group") ?? groupCategory;
        var title = GetStringOrNumber(item, "download_title", "title", "name");
        if (IsNonBiosEntry(category, title))
            return;

        var rawVersion = GetStringOrNumber(item, "download_version", "version", "bios_version", "biosVersion");
        var description = GetStringOrNumber(item, "download_description", "description", "download_note", "notes", "summary");
        if (string.IsNullOrWhiteSpace(rawVersion))
            return;

        sawAnyBiosEntry = true;

        var isBetaFlag = GetNullableBool(item, "is_beta", "isBeta", "beta");
        var isReleaseFlag = GetNullableBool(item, "is_release", "isRelease", "release");
        var parsedVersion = ParseMsiVersion(rawVersion, isBetaFlag, isReleaseFlag);

        if (parsedVersion.IsBeta || IsBetaRelease(rawVersion, title, description, isReleaseFlag, isBetaFlag))
            return;

        sawOnlyBeta = false;

        if (parsedVersion.Kind == MsiVersionKind.Empty)
            return;

        var downloadState = ExtractMsiDownloadUrl(item, out var downloadUrl);

        var releaseDate = TryParseReleaseDate(GetStringOrNumber(item, "download_release", "release_date", "releaseDate", "date", "download_date"));
        var rawNotesUrl = GetStringOrNumber(item, "release_notes_url", "releaseNotesUrl", "notes_url", "readme_url", "support_url");
        string? notesUrl = null;
        if (!string.IsNullOrWhiteSpace(rawNotesUrl) && TryValidateVendorUrl(rawNotesUrl, AllowedHostSuffixes, out var validNotesUri))
            notesUrl = validNotesUri.AbsoluteUri;

        var sha256 = TryNormalizeSha256(GetStringOrNumber(item, "download_sha256", "sha256", "checksum", "hash"));
        var sizeBytes = TryParseSizeBytes(item, "download_size", "file_size", "fileSize", "size", "sizeBytes");
        var packageId = GetStringOrNumber(item, "download_id", "packageId", "id");
        var severity = ParseSeverity(
            GetStringOrNumber(item, "severity", "priority", "importance"),
            GetNullableBool(item, "critical", "isCritical"),
            title,
            description);
        var summary = CleanReleaseSummary(title, description);

        var candidate = new MsiCatalogCandidate(
            DisplayVersion: parsedVersion.DisplayVersion,
            ParsedVersion: parsedVersion,
            ReleaseDate: releaseDate,
            Severity: severity,
            PackageId: packageId,
            ReleaseSummary: summary,
            ReleaseNotesUrl: notesUrl,
            DownloadUrl: downloadUrl,
            Sha256: sha256,
            SizeBytes: sizeBytes);

        if (downloadState == UrlExtractionState.Untrusted)
        {
            LogWarn($"[BIOS/MSI] Rejecting BIOS entry '{candidate.DisplayVersion}' with untrusted download URL.", serialNumber);
            untrusted.Add(candidate);
            return;
        }

        trusted.Add(candidate);
    }

    private static UrlExtractionState ExtractMsiDownloadUrl(JsonElement item, out string? validatedUrl)
    {
        validatedUrl = null;

        if (!TryGetPropertyIgnoreCase(item, out var dlEl, "download_url", "downloadUrl", "url", "download_link", "fileUrl"))
            return UrlExtractionState.Absent;

        if (dlEl.ValueKind != JsonValueKind.String)
            return UrlExtractionState.Untrusted;

        var raw = dlEl.GetString()?.Trim();
        if (string.IsNullOrWhiteSpace(raw))
            return UrlExtractionState.Absent;

        if (TryValidateVendorUrl(raw, AllowedHostSuffixes, out var validUri))
        {
            validatedUrl = validUri.AbsoluteUri;
            return UrlExtractionState.Valid;
        }

        return UrlExtractionState.Untrusted;
    }

    private static List<MsiCatalogCandidate> FilterCompatibleCandidates(
        List<MsiCatalogCandidate> source,
        MsiParsedVersion current,
        string? expectedBoardCode)
    {
        var result = new List<MsiCatalogCandidate>(source.Count);
        foreach (var entry in source)
        {
            // Enforce board code match whenever both system and candidate specify one.
            if (!string.IsNullOrEmpty(expectedBoardCode)
                && !string.IsNullOrEmpty(entry.ParsedVersion.BoardCode)
                && !string.Equals(expectedBoardCode, entry.ParsedVersion.BoardCode, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            // Never cross-upgrade across incompatible MSI letter Major branches (e.g. '1' vs 'A', 'A' vs 'H').
            if (current.Kind == MsiVersionKind.MsiReleaseCode
                && entry.ParsedVersion.Kind == MsiVersionKind.MsiReleaseCode
                && HasIncompatibleMajorBranch(current.Major, entry.ParsedVersion.Major))
            {
                continue;
            }

            result.Add(entry);
        }

        return result;
    }

    private static bool HasIncompatibleMajorBranch(char aMajor, char bMajor)
    {
        if (aMajor == bMajor)
            return false;

        return !char.IsAsciiDigit(aMajor) || !char.IsAsciiDigit(bMajor);
    }

    internal static MsiParsedVersion ParseMsiVersion(string? raw, bool? isBetaFlag = null, bool? isReleaseFlag = null)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return MsiParsedVersion.Empty;

        var trimmed = raw.Trim();
        var hasBetaMarker = isBetaFlag == true || isReleaseFlag == false || BetaTokenRegex().IsMatch(trimmed);

        var cleaned = trimmed;
        while (true)
        {
            var stripped = LeadingVersionPrefixRegex().Replace(cleaned, "").Trim();
            if (stripped.Length == cleaned.Length)
                break;
            cleaned = stripped;
        }

        cleaned = TrailingParenBetaRegex().Replace(cleaned, "").Trim();
        cleaned = TrailingWordBetaRegex().Replace(cleaned, "").Trim();

        if (cleaned.Length == 0)
            return MsiParsedVersion.Empty;

        // Pattern 1: MSI v-notation ("7D75v1G", "7D75v1A", "7D75v19", "7D25vAE", "7D75v1A1", "MS-7D75v1G")
        var vMatch = MsiVNotationRegex().Match(cleaned);
        if (vMatch.Success)
        {
            var board = ToAsciiUpperString(vMatch.Groups[1].Value);
            if (HasAnyAsciiDigit(board))
            {
                var major = ToAsciiUpper(vMatch.Groups[2].Value[0]);
                var minor = FromBase36(vMatch.Groups[3].Value[0]);
                var patch = vMatch.Groups[4].Success ? FromBase36(vMatch.Groups[4].Value[0]) : 0;
                var isBeta = hasBetaMarker || (vMatch.Groups[4].Success && patch != 0);
                var canonical = $"{major}.{ToBase36Char(minor)}{ToBase36Char(patch)}";
                var classKey = char.IsAsciiDigit(major) ? "1:MSI_NUM" : $"2:MSI_BRANCH:{major}";

                return new MsiParsedVersion(
                    Kind: MsiVersionKind.MsiReleaseCode,
                    DisplayVersion: cleaned,
                    CanonicalVersion: canonical,
                    BoardCode: board,
                    Major: major,
                    Minor: minor,
                    Patch: patch,
                    IsBeta: isBeta,
                    ClassKey: classKey,
                    GenericKind: GenericVersionKind.None,
                    Segments: []);
            }
        }

        // Pattern 2: MSI AMI/ROM 8.3 notation ("E7D75AMS.1A0", "E7D75AMS.1G0", "E7D25IMS.AE0", "E16R5IMS.10C")
        var amiMatch = MsiAmiRomRegex().Match(cleaned);
        if (amiMatch.Success)
        {
            var board = ToAsciiUpperString(amiMatch.Groups[1].Value);
            if (HasAnyAsciiDigit(board))
            {
                var major = ToAsciiUpper(amiMatch.Groups[2].Value[0]);
                var minor = FromBase36(amiMatch.Groups[3].Value[0]);
                var patch = FromBase36(amiMatch.Groups[4].Value[0]);
                var isBeta = hasBetaMarker || (minor >= 10 && patch != 0);
                var canonical = $"{major}.{ToBase36Char(minor)}{ToBase36Char(patch)}";
                var classKey = char.IsAsciiDigit(major) ? "1:MSI_NUM" : $"2:MSI_BRANCH:{major}";

                return new MsiParsedVersion(
                    Kind: MsiVersionKind.MsiReleaseCode,
                    DisplayVersion: cleaned,
                    CanonicalVersion: canonical,
                    BoardCode: board,
                    Major: major,
                    Minor: minor,
                    Patch: patch,
                    IsBeta: isBeta,
                    ClassKey: classKey,
                    GenericKind: GenericVersionKind.None,
                    Segments: []);
            }
        }

        // Pattern 3: MSI Dotted 3-char notation ("1.90", "1.A0", "1.G0", "A.E0", "A.G0", "H.20")
        var dotMatch = MsiDottedThreeCharRegex().Match(cleaned);
        if (dotMatch.Success)
        {
            var major = ToAsciiUpper(dotMatch.Groups[1].Value[0]);
            var minor = FromBase36(dotMatch.Groups[2].Value[0]);
            var patch = FromBase36(dotMatch.Groups[3].Value[0]);
            var isBeta = hasBetaMarker || (minor >= 10 && patch != 0);
            var canonical = $"{major}.{ToBase36Char(minor)}{ToBase36Char(patch)}";
            var classKey = char.IsAsciiDigit(major) ? "1:MSI_NUM" : $"2:MSI_BRANCH:{major}";

            return new MsiParsedVersion(
                Kind: MsiVersionKind.MsiReleaseCode,
                DisplayVersion: canonical,
                CanonicalVersion: canonical,
                BoardCode: null,
                Major: major,
                Minor: minor,
                Patch: patch,
                IsBeta: isBeta,
                ClassKey: classKey,
                GenericKind: GenericVersionKind.None,
                Segments: []);
        }

        // Fallback: Generic version classification
        var normalizedGeneric = cleaned;
        if (normalizedGeneric.Length > 1
            && (normalizedGeneric[0] is 'v' or 'V')
            && char.IsAsciiDigit(normalizedGeneric[1]))
        {
            normalizedGeneric = normalizedGeneric[1..].Trim();
        }

        var (genericKind, genericKey, segments) = ClassifyGenericVersion(normalizedGeneric);
        return new MsiParsedVersion(
            Kind: MsiVersionKind.Generic,
            DisplayVersion: cleaned,
            CanonicalVersion: normalizedGeneric,
            BoardCode: null,
            Major: '\0',
            Minor: 0,
            Patch: 0,
            IsBeta: hasBetaMarker,
            ClassKey: "3:" + genericKey,
            GenericKind: genericKind,
            Segments: segments);
    }

    private static bool IsCandidateNewer(
        MsiParsedVersion current,
        DateOnly? currentDate,
        MsiParsedVersion candidate,
        DateOnly? candidateDate)
    {
        if (candidate.Kind == MsiVersionKind.Empty)
            return false;

        // Never cross-upgrade incompatible board codes or letter Major branches even on newer dates.
        if (!string.IsNullOrEmpty(current.BoardCode)
            && !string.IsNullOrEmpty(candidate.BoardCode)
            && !string.Equals(current.BoardCode, candidate.BoardCode, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (current.Kind == MsiVersionKind.MsiReleaseCode
            && candidate.Kind == MsiVersionKind.MsiReleaseCode
            && HasIncompatibleMajorBranch(current.Major, candidate.Major))
        {
            return false;
        }

        var cmp = CompareMsiVersions(current, candidate);
        if (cmp.HasValue)
            return cmp.Value < 0;

        if (currentDate.HasValue && candidateDate.HasValue)
            return candidateDate.Value > currentDate.Value;

        return false;
    }

    internal static int? CompareMsiVersions(MsiParsedVersion a, MsiParsedVersion b)
    {
        if (a.Kind == MsiVersionKind.Empty || b.Kind == MsiVersionKind.Empty)
            return null;

        if (a.Kind == MsiVersionKind.MsiReleaseCode && b.Kind == MsiVersionKind.MsiReleaseCode)
        {
            if (!string.IsNullOrEmpty(a.BoardCode)
                && !string.IsNullOrEmpty(b.BoardCode)
                && !string.Equals(a.BoardCode, b.BoardCode, StringComparison.OrdinalIgnoreCase))
            {
                return null;
            }

            if (HasIncompatibleMajorBranch(a.Major, b.Major))
                return null;

            return CompareMsiReleaseCodeTuple(a, b);
        }

        if (string.Equals(a.ClassKey, b.ClassKey, StringComparison.OrdinalIgnoreCase))
            return CompareWithinClass(a, b);

        // Allow comparing pure dotted numeric generic ("1.9") with non-beta pure-digit MsiReleaseCode ("1.10").
        // Restricting to non-beta entries with numeric major and decimal minor/patch (<= 9) preserves strict weak ordering.
        if ((a.Kind == MsiVersionKind.Generic && a.GenericKind == GenericVersionKind.Numeric && IsNumericBridgeEligible(b))
            || (b.Kind == MsiVersionKind.Generic && b.GenericKind == GenericVersionKind.Numeric && IsNumericBridgeEligible(a)))
        {
            return BiosVersionComparer.Compare(a.CanonicalVersion, b.CanonicalVersion);
        }

        return null;
    }

    private static bool IsNumericBridgeEligible(MsiParsedVersion version) =>
        version.Kind == MsiVersionKind.MsiReleaseCode
        && !version.IsBeta
        && char.IsAsciiDigit(version.Major)
        && version.Minor <= 9
        && version.Patch <= 9;

    private static int CompareMsiReleaseCodeTuple(MsiParsedVersion a, MsiParsedVersion b)
    {
        var c = a.Major.CompareTo(b.Major);
        if (c != 0) return c;

        c = a.Minor.CompareTo(b.Minor);
        if (c != 0) return c;

        var aReleaseRank = a.IsBeta ? 0 : 1;
        var bReleaseRank = b.IsBeta ? 0 : 1;
        c = aReleaseRank.CompareTo(bReleaseRank);
        if (c != 0) return c;

        return a.Patch.CompareTo(b.Patch);
    }

    private static int CompareWithinClass(MsiParsedVersion a, MsiParsedVersion b)
    {
        if (a.Kind == MsiVersionKind.MsiReleaseCode)
            return CompareMsiReleaseCodeTuple(a, b);

        return a.GenericKind switch
        {
            GenericVersionKind.Numeric or GenericVersionKind.PrefixNumeric => CompareNumericSegmentArrays(a.Segments, b.Segments),
            GenericVersionKind.Skeleton => CompareFixedLengthArrays(a.Segments, b.Segments),
            _ => 0,
        };
    }

    private static List<MsiCatalogCandidate> OrderCandidates(List<MsiCatalogCandidate> candidates, MsiParsedVersion current)
    {
        var bucketMaxDates = new Dictionary<(int PrefRank, string ClassKey), DateOnly?>(BucketKeyComparer);
        var keyed = new List<(MsiCatalogCandidate Candidate, int PrefRank)>(candidates.Count);

        foreach (var candidate in candidates)
        {
            var prefRank = GetCandidatePreferenceRank(candidate.ParsedVersion, current);
            keyed.Add((candidate, prefRank));

            var bucketKey = (prefRank, candidate.ParsedVersion.ClassKey);
            if (!bucketMaxDates.TryGetValue(bucketKey, out var existingMax)
                || (candidate.ReleaseDate.HasValue && (!existingMax.HasValue || candidate.ReleaseDate.Value > existingMax.Value)))
            {
                bucketMaxDates[bucketKey] = candidate.ReleaseDate;
            }
        }

        keyed.Sort((a, b) =>
        {
            var prefCmp = b.PrefRank.CompareTo(a.PrefRank);
            if (prefCmp != 0)
                return prefCmp;

            var bucketDateCmp = CompareNullableDateDescending(
                bucketMaxDates[(a.PrefRank, a.Candidate.ParsedVersion.ClassKey)],
                bucketMaxDates[(b.PrefRank, b.Candidate.ParsedVersion.ClassKey)]);
            if (bucketDateCmp != 0)
                return bucketDateCmp;

            var classCmp = StringComparer.OrdinalIgnoreCase.Compare(
                a.Candidate.ParsedVersion.ClassKey,
                b.Candidate.ParsedVersion.ClassKey);
            if (classCmp != 0)
                return classCmp;

            var verCmp = CompareWithinClass(b.Candidate.ParsedVersion, a.Candidate.ParsedVersion);
            if (verCmp != 0)
                return verCmp;

            var dateCmp = CompareNullableDateDescending(a.Candidate.ReleaseDate, b.Candidate.ReleaseDate);
            if (dateCmp != 0)
                return dateCmp;

            var rawCmp = StringComparer.OrdinalIgnoreCase.Compare(a.Candidate.DisplayVersion, b.Candidate.DisplayVersion);
            if (rawCmp != 0)
                return rawCmp;

            rawCmp = StringComparer.Ordinal.Compare(a.Candidate.DisplayVersion, b.Candidate.DisplayVersion);
            if (rawCmp != 0)
                return rawCmp;

            var aHasUrl = !string.IsNullOrEmpty(a.Candidate.DownloadUrl);
            var bHasUrl = !string.IsNullOrEmpty(b.Candidate.DownloadUrl);
            if (aHasUrl != bHasUrl)
                return bHasUrl.CompareTo(aHasUrl);

            var urlCmp = StringComparer.OrdinalIgnoreCase.Compare(a.Candidate.DownloadUrl ?? "", b.Candidate.DownloadUrl ?? "");
            if (urlCmp != 0)
                return urlCmp;

            urlCmp = StringComparer.Ordinal.Compare(a.Candidate.DownloadUrl ?? "", b.Candidate.DownloadUrl ?? "");
            if (urlCmp != 0)
                return urlCmp;

            var pkgCmp = StringComparer.OrdinalIgnoreCase.Compare(a.Candidate.PackageId ?? "", b.Candidate.PackageId ?? "");
            if (pkgCmp != 0)
                return pkgCmp;

            pkgCmp = StringComparer.Ordinal.Compare(a.Candidate.PackageId ?? "", b.Candidate.PackageId ?? "");
            if (pkgCmp != 0)
                return pkgCmp;

            var shaCmp = StringComparer.OrdinalIgnoreCase.Compare(a.Candidate.Sha256 ?? "", b.Candidate.Sha256 ?? "");
            if (shaCmp != 0)
                return shaCmp;

            shaCmp = StringComparer.Ordinal.Compare(a.Candidate.Sha256 ?? "", b.Candidate.Sha256 ?? "");
            if (shaCmp != 0)
                return shaCmp;

            var notesCmp = StringComparer.OrdinalIgnoreCase.Compare(a.Candidate.ReleaseNotesUrl ?? "", b.Candidate.ReleaseNotesUrl ?? "");
            if (notesCmp != 0)
                return notesCmp;

            notesCmp = StringComparer.Ordinal.Compare(a.Candidate.ReleaseNotesUrl ?? "", b.Candidate.ReleaseNotesUrl ?? "");
            if (notesCmp != 0)
                return notesCmp;

            var summaryCmp = StringComparer.Ordinal.Compare(a.Candidate.ReleaseSummary ?? "", b.Candidate.ReleaseSummary ?? "");
            if (summaryCmp != 0)
                return summaryCmp;

            var sizeCmp = CompareNullableLongDescending(a.Candidate.SizeBytes, b.Candidate.SizeBytes);
            if (sizeCmp != 0)
                return sizeCmp;

            return b.Candidate.Severity.CompareTo(a.Candidate.Severity);
        });

        return keyed.ConvertAll(k => k.Candidate);
    }

    private static int GetCandidatePreferenceRank(MsiParsedVersion candidate, MsiParsedVersion current)
    {
        if (current.Kind == MsiVersionKind.MsiReleaseCode && candidate.Kind == MsiVersionKind.MsiReleaseCode)
        {
            if (!HasIncompatibleMajorBranch(candidate.Major, current.Major))
                return 2;
        }
        else if (candidate.Kind == MsiVersionKind.MsiReleaseCode)
        {
            return 1;
        }

        return 0;
    }

    private static (GenericVersionKind Kind, string ClassKey, long[] Segments) ClassifyGenericVersion(string normalized)
    {
        if (string.IsNullOrWhiteSpace(normalized))
            return (GenericVersionKind.None, "0:", []);

        var prefixMatch = PrefixNumericRegex().Match(normalized);
        if (prefixMatch.Success && TryParseDottedInt64(prefixMatch.Groups[2].Value, out var pfxSegs))
            return (GenericVersionKind.PrefixNumeric, "2:PFX:" + prefixMatch.Groups[1].Value, pfxSegs);

        if (IsPureDottedNumeric(normalized) && TryParseDottedInt64(normalized, out var numSegs))
            return (GenericVersionKind.Numeric, "1:NUM", numSegs);

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
                return (GenericVersionKind.Skeleton, $"3:SKEL:{runs.Length}:{skeleton}", runs);
            }
        }

        return (GenericVersionKind.Literal, "4:LIT:" + normalized, []);
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

    private static bool IsPureDottedNumeric(string value)
    {
        if (string.IsNullOrEmpty(value))
            return false;

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

    private static bool TryResolveBoardOrModel(
        BiosSystemIdentity system,
        out string queryToken,
        out string? extractedBoardCode,
        out string reason)
    {
        queryToken = "";
        extractedBoardCode = null;
        reason = "";

        // Validate BOTH BoardProduct and Model in full BEFORE any MS-XXXX extraction (prevents "MS-7D75&whoami" bypass).
        var boardStatus = ClassifyModelToken(system.BoardProduct, out var boardToken);
        var modelStatus = ClassifyModelToken(system.Model, out var modelToken);

        if (boardStatus == SmbiosTokenStatus.InvalidUnsafe)
        {
            reason = "SMBIOS BoardProduct contains disallowed characters.";
            return false;
        }

        if (modelStatus == SmbiosTokenStatus.InvalidUnsafe)
        {
            reason = "SMBIOS Model contains disallowed characters.";
            return false;
        }

        if (boardStatus == SmbiosTokenStatus.Valid && TryExtractMsiBoardCode(boardToken, out var codeFromBoard))
        {
            extractedBoardCode = codeFromBoard;
            queryToken = "MS-" + codeFromBoard;
            return true;
        }

        if (modelStatus == SmbiosTokenStatus.Valid && TryExtractMsiBoardCode(modelToken, out var codeFromModel))
        {
            extractedBoardCode = codeFromModel;
            queryToken = "MS-" + codeFromModel;
            return true;
        }

        if (boardStatus == SmbiosTokenStatus.Valid)
        {
            queryToken = boardToken;
            return true;
        }

        if (modelStatus == SmbiosTokenStatus.Valid)
        {
            queryToken = modelToken;
            return true;
        }

        reason = "SMBIOS BoardProduct and Model are empty or OEM placeholders.";
        return false;
    }

    private static bool TryExtractMsiBoardCode(string validatedToken, out string fourCharCode)
    {
        fourCharCode = "";

        var exact = ExactMsBoardCodeRegex().Match(validatedToken);
        if (exact.Success)
        {
            var candidate = ToAsciiUpperString(exact.Groups[1].Value);
            if (HasAnyAsciiDigit(candidate))
            {
                fourCharCode = candidate;
                return true;
            }
        }

        var paren = ParenthesizedMsBoardCodeRegex().Match(validatedToken);
        if (paren.Success)
        {
            var candidate = ToAsciiUpperString(paren.Groups[1].Value);
            if (HasAnyAsciiDigit(candidate))
            {
                fourCharCode = candidate;
                return true;
            }
        }

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

    private static char ToAsciiUpper(char c) => c is >= 'a' and <= 'z' ? (char)(c - 32) : c;

    private static string ToAsciiUpperString(string value)
    {
        var chars = new char[value.Length];
        for (var i = 0; i < value.Length; i++)
            chars[i] = ToAsciiUpper(value[i]);
        return new string(chars);
    }

    private static int FromBase36(char c)
    {
        var upper = ToAsciiUpper(c);
        if (upper is >= '0' and <= '9')
            return upper - '0';
        if (upper is >= 'A' and <= 'Z')
            return 10 + (upper - 'A');
        return 0;
    }

    private static char ToBase36Char(int value) =>
        value switch
        {
            >= 0 and <= 9 => (char)('0' + value),
            >= 10 and <= 35 => (char)('A' + (value - 10)),
            _ => '0',
        };

    private static bool HasAnyAsciiDigit(string value)
    {
        foreach (var c in value)
        {
            if (char.IsAsciiDigit(c))
                return true;
        }

        return false;
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

    private static string BuildCatalogUrl(string endpointTemplate, string productToken)
    {
        var escaped = Uri.EscapeDataString(productToken);
        if (EndpointPlaceholderRegex().IsMatch(endpointTemplate))
            return EndpointPlaceholderRegex().Replace(endpointTemplate, escaped);

        var fragIdx = endpointTemplate.IndexOf('#');
        var basePart = fragIdx >= 0 ? endpointTemplate[..fragIdx] : endpointTemplate;
        var sep = basePart.Contains('?', StringComparison.Ordinal) ? "&" : "?";
        return $"{basePart}{sep}product={escaped}";
    }

    private static async Task<JsonDocument> ReadBoundedJsonDocumentAsync(HttpContent content, CancellationToken ct)
    {
        var contentLength = content.Headers.ContentLength;
        if (contentLength.HasValue && contentLength.Value > MaxCatalogJsonBytes)
            throw new InvalidDataException($"MSI BIOS catalog response ({contentLength.Value} bytes) exceeds maximum allowed limit ({MaxCatalogJsonBytes} bytes).");

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
                if (totalRead > MaxCatalogJsonBytes)
                    throw new InvalidDataException($"MSI BIOS catalog response exceeded maximum allowed size ({MaxCatalogJsonBytes} bytes).");

                ms.Write(buffer, 0, read);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        if (totalRead == 0)
            throw new InvalidDataException("MSI BIOS catalog response body is empty.");

        var rawBytes = ms.GetBuffer();
        var offset = 0;
        var length = (int)ms.Length;

        if (length >= 3 && rawBytes[0] == 0xEF && rawBytes[1] == 0xBB && rawBytes[2] == 0xBF)
        {
            offset = 3;
            length -= 3;
        }

        var hasNonWhitespace = false;
        for (var i = offset; i < offset + length; i++)
        {
            var b = rawBytes[i];
            if (b is not ((byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n'))
            {
                hasNonWhitespace = true;
                break;
            }
        }

        if (!hasNonWhitespace)
            throw new InvalidDataException("MSI BIOS catalog response body is empty or whitespace.");

        return JsonDocument.Parse(
            new ReadOnlyMemory<byte>(rawBytes, offset, length),
            new JsonDocumentOptions
            {
                MaxDepth = 64,
                CommentHandling = JsonCommentHandling.Disallow,
                AllowTrailingCommas = false,
            });
    }

    private async Task<HttpResponseMessage> GetCatalogWithSafeRedirectsAsync(string initialUrl, CancellationToken ct)
    {
        if (!TryValidateVendorUrl(initialUrl, AllowedHostSuffixes, out var current))
            throw new InvalidOperationException("Disallowed MSI catalog URL.");

        var visited = new HashSet<string>(StringComparer.Ordinal) { current.AbsoluteUri };
        const int maxRedirects = BiosProviderHttp.DefaultMaxRedirects;

        for (var hop = 0; hop <= maxRedirects; hop++)
        {
            ct.ThrowIfCancellationRequested();

            using var request = new HttpRequestMessage(HttpMethod.Get, current);
            request.Headers.Accept.ParseAdd("application/json");

            var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            if ((int)response.StatusCode is not (301 or 302 or 303 or 307 or 308))
                return response;

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

    private static bool IsNonBiosCategory(string category)
    {
        var trimmed = category.Trim();
        if (trimmed.Length == 0)
            return false;

        if (ContainsAnyKeyword(trimmed, NonBiosCategoryKeywords))
            return true;

        return !trimmed.Contains("bios", StringComparison.OrdinalIgnoreCase)
               && !trimmed.Contains("uefi", StringComparison.OrdinalIgnoreCase)
               && !trimmed.Contains("system firmware", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsNonBiosEntry(string? category, string? title)
    {
        var hasExplicitBiosCategory = !string.IsNullOrWhiteSpace(category);
        if (hasExplicitBiosCategory && IsNonBiosCategory(category!))
            return true;

        if (!string.IsNullOrWhiteSpace(title))
        {
            if (ContainsAnyKeyword(title, NonBiosTitleAlwaysRejectKeywords))
                return true;

            if (!hasExplicitBiosCategory)
            {
                var looksLikeBiosTitle = title.Contains("bios", StringComparison.OrdinalIgnoreCase)
                                         || title.Contains("uefi", StringComparison.OrdinalIgnoreCase)
                                         || title.Contains("system firmware", StringComparison.OrdinalIgnoreCase);
                if (!looksLikeBiosTitle && ContainsAnyKeyword(title, NonBiosCategoryKeywords))
                    return true;
            }
        }

        return false;
    }

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
                || trimmed.Contains("beta bios", StringComparison.OrdinalIgnoreCase)
                || trimmed.Contains("beta release", StringComparison.OrdinalIgnoreCase)
                || trimmed.Contains("this is a beta", StringComparison.OrdinalIgnoreCase))
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
        {
            var s = el.GetString()?.Trim();
            if (string.Equals(s, "true", StringComparison.OrdinalIgnoreCase)
                || string.Equals(s, "1", StringComparison.Ordinal)
                || string.Equals(s, "yes", StringComparison.OrdinalIgnoreCase))
                return true;
            if (string.Equals(s, "false", StringComparison.OrdinalIgnoreCase)
                || string.Equals(s, "0", StringComparison.Ordinal)
                || string.Equals(s, "no", StringComparison.OrdinalIgnoreCase))
                return false;
        }

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

        var raw = el.GetString()?.Trim();
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        if (long.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed)
            && parsed is > 0 and <= maxPlausibleBytes)
        {
            return parsed;
        }

        if (ThousandsGroupedIntRegex().IsMatch(raw))
        {
            var ungrouped = raw.Replace(",", "", StringComparison.Ordinal);
            if (long.TryParse(ungrouped, NumberStyles.None, CultureInfo.InvariantCulture, out var groupedParsed)
                && groupedParsed is > 0 and <= maxPlausibleBytes)
            {
                return groupedParsed;
            }
        }

        var match = HumanSizeRegex().Match(raw);
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
                || string.Equals(s, "3", StringComparison.Ordinal))
                return BiosUpdateSeverity.Optional;

            if (s.Contains("recommended", StringComparison.OrdinalIgnoreCase)
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

    private void LogWarn(string message, string? serialNumber) =>
        _log?.Warn(RedactText(message, serialNumber));

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

            var queryStart = decoded.IndexOf('?');
            if (queryStart >= 0 && decoded.IndexOf('+', queryStart) >= 0)
            {
                var queryWithSpaces = decoded[queryStart..].Replace('+', ' ');
                if (queryWithSpaces.Contains(secret, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            if (string.Equals(decoded, candidate, StringComparison.Ordinal))
                break;

            candidate = decoded;
        }

        var rawQueryStart = url.IndexOf('?');
        if (rawQueryStart >= 0 && url.IndexOf('+', rawQueryStart) >= 0)
        {
            var rawQueryWithSpaces = url[rawQueryStart..].Replace('+', ' ');
            if (rawQueryWithSpaces.Contains(secret, StringComparison.OrdinalIgnoreCase))
                return true;

            try
            {
                var decodedQuery = Uri.UnescapeDataString(rawQueryWithSpaces);
                if (decodedQuery.Contains(secret, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            catch (UriFormatException)
            {
                // Ignore malformed percent-encoding sequences.
            }
        }

        return false;
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

    internal enum MsiVersionKind
    {
        Empty,
        MsiReleaseCode,
        Generic,
    }

    internal enum GenericVersionKind
    {
        None,
        Numeric,
        PrefixNumeric,
        Skeleton,
        Literal,
    }

    internal sealed record MsiParsedVersion(
        MsiVersionKind Kind,
        string DisplayVersion,
        string CanonicalVersion,
        string? BoardCode,
        char Major,
        int Minor,
        int Patch,
        bool IsBeta,
        string ClassKey,
        GenericVersionKind GenericKind,
        long[] Segments)
    {
        public static MsiParsedVersion Empty { get; } =
            new(MsiVersionKind.Empty, "", "", null, '\0', 0, 0, false, "0:", GenericVersionKind.None, []);
    }

    private sealed record MsiCatalogCandidate(
        string DisplayVersion,
        MsiParsedVersion ParsedVersion,
        DateOnly? ReleaseDate,
        BiosUpdateSeverity Severity,
        string? PackageId,
        string? ReleaseSummary,
        string? ReleaseNotesUrl,
        string? DownloadUrl,
        string? Sha256,
        long? SizeBytes);

    private sealed class BucketKeyEqualityComparer : IEqualityComparer<(int PrefRank, string ClassKey)>
    {
        public bool Equals((int PrefRank, string ClassKey) x, (int PrefRank, string ClassKey) y) =>
            x.PrefRank == y.PrefRank
            && StringComparer.OrdinalIgnoreCase.Equals(x.ClassKey, y.ClassKey);

        public int GetHashCode((int PrefRank, string ClassKey) obj) =>
            HashCode.Combine(obj.PrefRank, StringComparer.OrdinalIgnoreCase.GetHashCode(obj.ClassKey));
    }
}
