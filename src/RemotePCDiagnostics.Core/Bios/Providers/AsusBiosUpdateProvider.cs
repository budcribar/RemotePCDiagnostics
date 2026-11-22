using System.Buffers;
using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace RemotePCDiagnostics.Core.Bios;

/// <summary>
/// Check-only ASUS BIOS/UEFI update provider (<c>VendorId = "asus"</c>).
/// Queries the ASUS Support BIOS JSON API over HTTPS (100% pure C#, zero external processes or scripts).
/// Automated installation is not supported because ASUS consumer/desktop boards rely on EZ Flash.
/// </summary>
public sealed partial class AsusBiosUpdateProvider : IBiosUpdateProvider
{
    public const string ProviderVendorId = "asus";
    public const string DefaultCatalogEndpoint = "https://www.asus.com/support/api/product.asmx/GetPDBIOS?website=global&model={model}&cpu=";

    public static readonly IReadOnlyList<string> AllowedHostSuffixes = ["asus.com"];

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
        "biosrenamer",
        "bios renamer",
        "meupdatetool",
        "me update tool",
        "management engine",
        "intel me",
        "csme",
        "pd firmware",
        "ez update",
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
        "biosrenamer",
        "bios renamer",
        "meupdatetool",
        "me update tool",
        "management engine",
        "intel me",
        "csme",
        "pd firmware",
        "ez update",
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

    [GeneratedRegex(@"^(?:BIOS\s+Version|Version|Ver\.?|Rev\.?|BIOS)\s*[:\-]?\s*", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex LeadingVersionPrefixRegex();

    [GeneratedRegex(@"^([A-Za-z][A-Za-z0-9\-_]{2,24})\.(\d{2,5})$", RegexOptions.CultureInvariant)]
    private static partial Regex LaptopFamilyBuildRegex();

    [GeneratedRegex(@"(?:^|\s)BIOS\s+(?:Version\s+|Ver\.?\s*)?([0-9][A-Za-z0-9._\-]{0,31})$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex TrailingBiosTokenRegex();

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
    /// Creates an ASUS BIOS update provider. All parameters are optional so MS.DI resolves
    /// this single constructor cleanly with zero optional service registrations.
    /// </summary>
    public AsusBiosUpdateProvider(
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
    public static AsusBiosUpdateProvider CreateWithHandler(
        HttpMessageHandler httpHandler,
        ILogger? log = null,
        string? catalogEndpoint = null) =>
        new(BiosProviderHttp.CreateClient(httpHandler), log, catalogEndpoint);

    public string VendorId => ProviderVendorId;
    public string DisplayName => "ASUS";
    public int Priority => 100;

    public BiosProviderCapabilities Capabilities { get; } = new(
        CanCheckLatest: true,
        CanInstall: false,
        SupportsSilentInstall: false,
        RequiresReboot: false,
        RequiresElevation: false,
        RequiresInternet: true);

    public bool CanHandle(BiosSystemIdentity system) =>
        system is not null && BiosVendorIdentity.IsAsus(system);

    public Task<BiosCurrentInfo> GetCurrentVersionAsync(BiosSystemIdentity system, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(system);
        ct.ThrowIfCancellationRequested();

        var current = system.CurrentBios ?? BiosCurrentInfo.Empty;
        var parsed = ParseAsusVersion(current.Version, current.Family);
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

        var serial = system.SerialNumber;
        var safeVendor = RedactText(current.Vendor ?? "", serial);
        var safeVersion = RedactText(parsed.NormalizedVersion, serial);
        var safeReleaseDateRaw = RedactText(current.ReleaseDateRaw ?? "", serial);
        var safeSmbiosRevision = RedactText(current.SmbiosRevision ?? "", serial);
        var safeFamily = RedactText(parsed.Family, serial);
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
        ArgumentNullException.ThrowIfNull(current);
        ct.ThrowIfCancellationRequested();

        if (!TryResolveModelIdentifier(system, out var modelToken, out var invalidReason))
        {
            LogWarn($"[BIOS/ASUS] Unable to determine valid ASUS model identifier: {invalidReason}", system.SerialNumber);
            return RedactLatestInfo(
                BiosLatestInfo.Unsupported(VendorId, $"Unable to determine a valid ASUS model or board product identifier: {invalidReason}"),
                system.SerialNumber);
        }

        var requestUrl = BuildCatalogUrl(_catalogEndpoint, modelToken);
        if (!TryValidateVendorUrl(requestUrl, AllowedHostSuffixes, out _))
        {
            LogWarn("[BIOS/ASUS] Configured ASUS catalog endpoint failed HTTPS/domain/path validation.", system.SerialNumber);
            return RedactLatestInfo(
                BiosLatestInfo.Failed(VendorId, "ASUS BIOS catalog endpoint URL failed security validation."),
                system.SerialNumber);
        }

        try
        {
            using var response = await GetCatalogWithSafeRedirectsAsync(requestUrl, ct).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                var statusInfo = BiosProviderHttp.ClassifyHttpStatus(VendorId, DisplayName, response.StatusCode, $"model '{modelToken}'");
                return RedactLatestInfo(statusInfo, system.SerialNumber);
            }

            using var doc = await ReadBoundedJsonDocumentAsync(response.Content, ct).ConfigureAwait(false);
            var evaluated = EvaluateCatalog(doc, current, modelToken, system.SerialNumber);
            return RedactLatestInfo(evaluated, system.SerialNumber);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            LogWarn($"[BIOS/ASUS] Catalog lookup failed for '{modelToken}': {ex.Message}", system.SerialNumber);
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
            "ASUS BIOS provider is check-only and does not support automated installation. Download the verified BIOS package manually and flash via ASUS EZ Flash.",
            serial);

        return Task.FromResult(BiosInstallResult.Unsupported(message, previousVersion, targetVersion));
    }

    private BiosLatestInfo EvaluateCatalog(JsonDocument doc, BiosCurrentInfo current, string modelToken, string? serialNumber)
    {
        var root = doc.RootElement;
        if (root.ValueKind is not (JsonValueKind.Object or JsonValueKind.Array))
            return BiosLatestInfo.Failed(VendorId, "ASUS BIOS catalog returned an unexpected JSON root type.");

        var parsedCurrent = ParseAsusVersion(current.Version, current.Family);
        var entries = new List<AsusCatalogCandidate>();
        var rejectedUntrusted = new List<AsusCatalogCandidate>();
        var sawAnyBiosEntry = false;
        var sawOnlyBeta = true;

        CollectCandidates(root, entries, rejectedUntrusted, ref sawAnyBiosEntry, ref sawOnlyBeta, serialNumber);

        var compatibleTrusted = FilterCompatibleFamily(entries, parsedCurrent.Family);
        var compatibleUntrusted = FilterCompatibleFamily(rejectedUntrusted, parsedCurrent.Family);

        if (compatibleTrusted.Count == 0)
        {
            if (compatibleUntrusted.Count > 0 || rejectedUntrusted.Count > 0)
                return BiosLatestInfo.Failed(VendorId, "ASUS BIOS catalog returned BIOS download URL(s) that failed HTTPS/domain security validation.");

            if (sawAnyBiosEntry && sawOnlyBeta)
                return BiosLatestInfo.Unsupported(VendorId, $"ASUS BIOS catalog for '{modelToken}' contains only beta/pre-release BIOS entries.");

            return BiosLatestInfo.Unsupported(VendorId, $"No matching ASUS system BIOS updates were found for '{modelToken}'.");
        }

        var ordered = OrderCandidates(compatibleTrusted);
        var best = ordered[0];

        // If a rejected untrusted BIOS entry is strictly newer than our best trusted candidate, fail closed.
        if (compatibleUntrusted.Count > 0)
        {
            foreach (var bad in compatibleUntrusted)
            {
                if (IsCandidateNewer(best.ParsedVersion, best.ReleaseDate, bad.ParsedVersion, bad.ReleaseDate))
                {
                    return BiosLatestInfo.Failed(
                        VendorId,
                        "ASUS BIOS catalog contained a newer BIOS entry whose download URL failed HTTPS/domain security validation.");
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
                    var cmp = CompareAsusVersions(bad.ParsedVersion, best.ParsedVersion);
                    if (cmp is null or >= 0)
                    {
                        return BiosLatestInfo.Failed(
                            VendorId,
                            "ASUS BIOS catalog contained BIOS entries whose download URL failed HTTPS/domain security validation.");
                    }
                }
            }

            var meta = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["model"] = modelToken,
            };
            if (!string.IsNullOrEmpty(best.ParsedVersion.Family))
                meta["family"] = best.ParsedVersion.Family;

            return BiosLatestInfo.UpToDate(
                VendorId,
                best.DisplayVersion,
                best.ReleaseDate,
                message: $"ASUS BIOS is up to date ({best.DisplayVersion}).",
                metadata: meta);
        }

        var updateMeta = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["model"] = modelToken,
        };
        if (!string.IsNullOrEmpty(best.ParsedVersion.Family))
            updateMeta["family"] = best.ParsedVersion.Family;

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
            message: $"ASUS BIOS update {best.DisplayVersion} is available for {modelToken}.",
            metadata: updateMeta);
    }

    private void CollectCandidates(
        JsonElement root,
        List<AsusCatalogCandidate> trusted,
        List<AsusCatalogCandidate> untrusted,
        ref bool sawAnyBiosEntry,
        ref bool sawOnlyBeta,
        string? serialNumber)
    {
        if (root.ValueKind == JsonValueKind.Array)
        {
            ParseFilesArray(root, groupCategory: null, trusted, untrusted, ref sawAnyBiosEntry, ref sawOnlyBeta, serialNumber);
            return;
        }

        // Primary ASUS GetPDBIOS structure: Result.Obj[].Files[]
        if (TryGetPropertyIgnoreCase(root, out var resultEl, "Result"))
        {
            if (resultEl.ValueKind == JsonValueKind.Object)
            {
                if (TryGetPropertyIgnoreCase(resultEl, out var objEl, "Obj") && objEl.ValueKind == JsonValueKind.Array)
                {
                    foreach (var group in objEl.EnumerateArray())
                    {
                        if (group.ValueKind != JsonValueKind.Object)
                            continue;

                        var groupName = GetStringOrNumber(group, "Name", "Category", "Type");
                        if (!string.IsNullOrWhiteSpace(groupName) && IsNonBiosCategory(groupName))
                            continue;

                        if (TryGetPropertyIgnoreCase(group, out var filesEl, "Files", "Items", "Bios")
                            && filesEl.ValueKind == JsonValueKind.Array)
                        {
                            ParseFilesArray(filesEl, groupName, trusted, untrusted, ref sawAnyBiosEntry, ref sawOnlyBeta, serialNumber);
                        }
                    }

                    return;
                }

                if (TryGetPropertyIgnoreCase(resultEl, out var nestedFiles, "Files", "Bios", "Items", "Data")
                    && nestedFiles.ValueKind == JsonValueKind.Array)
                {
                    ParseFilesArray(nestedFiles, null, trusted, untrusted, ref sawAnyBiosEntry, ref sawOnlyBeta, serialNumber);
                    return;
                }
            }
            else if (resultEl.ValueKind == JsonValueKind.Array)
            {
                ParseFilesArray(resultEl, null, trusted, untrusted, ref sawAnyBiosEntry, ref sawOnlyBeta, serialNumber);
                return;
            }
        }

        // Fallback flat container shapes
        if (TryGetPropertyIgnoreCase(root, out var flatArray, "Files", "Bios", "BiosUpdates", "Items", "Data", "Downloads")
            && flatArray.ValueKind == JsonValueKind.Array)
        {
            ParseFilesArray(flatArray, null, trusted, untrusted, ref sawAnyBiosEntry, ref sawOnlyBeta, serialNumber);
            return;
        }

        // Single BIOS object at root
        if (TryGetPropertyIgnoreCase(root, out _, "Version", "BiosVersion", "Ver"))
            ParseSingleEntry(root, null, trusted, untrusted, ref sawAnyBiosEntry, ref sawOnlyBeta, serialNumber);
    }

    private void ParseFilesArray(
        JsonElement array,
        string? groupCategory,
        List<AsusCatalogCandidate> trusted,
        List<AsusCatalogCandidate> untrusted,
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
        List<AsusCatalogCandidate> trusted,
        List<AsusCatalogCandidate> untrusted,
        ref bool sawAnyBiosEntry,
        ref bool sawOnlyBeta,
        string? serialNumber)
    {
        var category = GetStringOrNumber(item, "Category", "Type", "Group") ?? groupCategory;
        var title = GetStringOrNumber(item, "Title", "Name");
        if (IsNonBiosEntry(category, title))
            return;

        var rawVersion = GetStringOrNumber(item, "Version", "BiosVersion", "Ver");
        var description = GetStringOrNumber(item, "Description", "Notes", "ReleaseNotes", "Summary");
        if (string.IsNullOrWhiteSpace(rawVersion))
            return;

        sawAnyBiosEntry = true;

        var isReleaseFlag = GetNullableBool(item, "IsRelease", "Release");
        var isBetaFlag = GetNullableBool(item, "IsBeta", "Beta");
        if (IsBetaRelease(rawVersion, title, description, isReleaseFlag, isBetaFlag))
            return;

        sawOnlyBeta = false;

        var downloadState = ExtractAsusDownloadUrl(item, out var downloadUrl);
        var parsedVersion = ParseAsusVersion(rawVersion, null);
        if (string.IsNullOrEmpty(parsedVersion.NormalizedVersion))
            return;

        var releaseDate = TryParseReleaseDate(GetStringOrNumber(item, "ReleaseDate", "Date", "PostDate", "PublishDate"));
        var rawNotesUrl = GetStringOrNumber(item, "ReleaseNotesUrl", "NotesUrl", "SupportUrl", "ReadmeUrl");
        string? notesUrl = null;
        if (!string.IsNullOrWhiteSpace(rawNotesUrl) && TryValidateVendorUrl(rawNotesUrl, AllowedHostSuffixes, out var validNotesUri))
            notesUrl = validNotesUri.AbsoluteUri;

        var sha256 = TryNormalizeSha256(GetStringOrNumber(item, "Sha256", "Checksum", "Hash"));
        var sizeBytes = TryParseSizeBytes(item, "FileSize", "Size", "SizeBytes", "FileSizeBytes");
        var packageId = GetStringOrNumber(item, "Id", "PackageId", "FileId");
        var severity = ParseSeverity(
            GetStringOrNumber(item, "Severity", "Priority", "Importance"),
            GetNullableBool(item, "Critical", "IsCritical"),
            title,
            description);
        var summary = CleanReleaseSummary(title, description);

        var candidate = new AsusCatalogCandidate(
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
            LogWarn($"[BIOS/ASUS] Rejecting BIOS entry '{candidate.DisplayVersion}' with untrusted download URL.", serialNumber);
            untrusted.Add(candidate);
            return;
        }

        trusted.Add(candidate);
    }

    private static UrlExtractionState ExtractAsusDownloadUrl(JsonElement item, out string? validatedUrl)
    {
        validatedUrl = null;

        if (TryGetPropertyIgnoreCase(item, out var dlEl, "DownloadUrl", "DownloadLink", "Url", "FileUrl"))
        {
            if (dlEl.ValueKind == JsonValueKind.Object)
            {
                // Prefer Global; if Global is explicitly present (non-null) and untrusted or wrong-kind, fail closed.
                if (TryGetPropertyIgnoreCase(dlEl, out var globalEl, "Global"))
                {
                    if (globalEl.ValueKind != JsonValueKind.String)
                        return UrlExtractionState.Untrusted;

                    var globalRaw = globalEl.GetString()?.Trim();
                    if (!string.IsNullOrWhiteSpace(globalRaw))
                    {
                        if (TryValidateVendorUrl(globalRaw, AllowedHostSuffixes, out var globalUri))
                        {
                            validatedUrl = globalUri.AbsoluteUri;
                            return UrlExtractionState.Valid;
                        }

                        return UrlExtractionState.Untrusted;
                    }
                }

                if (TryGetPropertyIgnoreCase(dlEl, out var fallbackEl, "China", "Url", "Link"))
                {
                    if (fallbackEl.ValueKind != JsonValueKind.String)
                        return UrlExtractionState.Untrusted;

                    var fallbackRaw = fallbackEl.GetString()?.Trim();
                    if (!string.IsNullOrWhiteSpace(fallbackRaw))
                    {
                        if (TryValidateVendorUrl(fallbackRaw, AllowedHostSuffixes, out var fallbackUri))
                        {
                            validatedUrl = fallbackUri.AbsoluteUri;
                            return UrlExtractionState.Valid;
                        }

                        return UrlExtractionState.Untrusted;
                    }
                }

                return UrlExtractionState.Absent;
            }

            if (dlEl.ValueKind == JsonValueKind.String)
            {
                var raw = dlEl.GetString()?.Trim();
                if (string.IsNullOrWhiteSpace(raw))
                    return UrlExtractionState.Absent;

                if (TryValidateVendorUrl(raw, AllowedHostSuffixes, out var uri))
                {
                    validatedUrl = uri.AbsoluteUri;
                    return UrlExtractionState.Valid;
                }

                return UrlExtractionState.Untrusted;
            }

            // Non-null wrong JsonValueKind (e.g., Number, True, False, Array) fails closed as untrusted.
            return UrlExtractionState.Untrusted;
        }

        return UrlExtractionState.Absent;
    }

    private static List<AsusCatalogCandidate> FilterCompatibleFamily(
        List<AsusCatalogCandidate> source,
        string currentFamily)
    {
        if (string.IsNullOrEmpty(currentFamily))
            return source;

        var result = new List<AsusCatalogCandidate>(source.Count);
        foreach (var item in source)
        {
            if (string.IsNullOrEmpty(item.ParsedVersion.Family)
                || string.Equals(item.ParsedVersion.Family, currentFamily, StringComparison.OrdinalIgnoreCase))
            {
                result.Add(item);
            }
        }

        return result;
    }

    private static AsusParsedVersion ParseAsusVersion(string? raw, string? existingFamily)
    {
        var family = existingFamily?.Trim() ?? "";
        if (string.IsNullOrWhiteSpace(raw))
            return new AsusParsedVersion("", "", family, VersionClass.Empty, "0:", [], "");

        var trimmed = raw.Trim();

        // Handle "ROG STRIX Z690-E GAMING WIFI BIOS 2802"
        var trailingBios = TrailingBiosTokenRegex().Match(trimmed);
        if (trailingBios.Success)
            trimmed = trailingBios.Groups[1].Value.Trim();

        // Strip leading "BIOS Version", "Version", "Ver.", "Rev.", "BIOS"
        while (true)
        {
            var stripped = LeadingVersionPrefixRegex().Replace(trimmed, "").Trim();
            if (stripped.Length == trimmed.Length)
                break;
            trimmed = stripped;
        }

        if (trimmed.Length > 1
            && (trimmed[0] is 'v' or 'V')
            && char.IsAsciiDigit(trimmed[1]))
        {
            trimmed = trimmed[1..].Trim();
        }

        if (trimmed.Length == 0)
            return new AsusParsedVersion("", "", family, VersionClass.Empty, "0:", [], "");

        // ASUS laptop format: "UX3402ZA.310", "GA402RJ.318"
        var laptopMatch = LaptopFamilyBuildRegex().Match(trimmed);
        if (laptopMatch.Success)
        {
            var extractedFamily = laptopMatch.Groups[1].Value;
            var build = laptopMatch.Groups[2].Value;
            var resolvedFamily = string.IsNullOrEmpty(family) ? extractedFamily : family;
            var (vClass, classKey, segments) = ClassifyGenericVersion(build);
            return new AsusParsedVersion(build, trimmed, resolvedFamily, vClass, classKey, segments, build);
        }

        var (kind, key, segs) = ClassifyGenericVersion(trimmed);
        return new AsusParsedVersion(trimmed, trimmed, family, kind, key, segs, trimmed);
    }

    private static bool IsCandidateNewer(
        AsusParsedVersion current,
        DateOnly? currentDate,
        AsusParsedVersion candidate,
        DateOnly? candidateDate)
    {
        if (string.IsNullOrEmpty(candidate.NormalizedVersion))
            return false;

        if (!string.IsNullOrEmpty(current.Family)
            && !string.IsNullOrEmpty(candidate.Family)
            && !string.Equals(current.Family, candidate.Family, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var cmp = CompareAsusVersions(current, candidate);
        if (cmp.HasValue)
            return cmp.Value < 0;

        if (currentDate.HasValue && candidateDate.HasValue)
            return candidateDate.Value > currentDate.Value;

        return false;
    }

    private static int? CompareAsusVersions(AsusParsedVersion a, AsusParsedVersion b)
    {
        if (a.Class == VersionClass.Empty || b.Class == VersionClass.Empty)
            return null;

        if (string.Equals(a.ClassKey, b.ClassKey, StringComparison.OrdinalIgnoreCase))
            return CompareWithinClass(a, b);

        return null;
    }

    private static int CompareWithinClass(AsusParsedVersion a, AsusParsedVersion b) =>
        a.Class switch
        {
            VersionClass.Numeric or VersionClass.PrefixNumeric => CompareNumericSegmentArrays(a.Segments, b.Segments),
            VersionClass.Skeleton => CompareFixedLengthArrays(a.Segments, b.Segments),
            _ => 0,
        };

    private static List<AsusCatalogCandidate> OrderCandidates(List<AsusCatalogCandidate> candidates)
    {
        var bucketMaxDates = new Dictionary<(int PrefRank, string ClassKey), DateOnly?>(BucketKeyComparer);

        foreach (var candidate in candidates)
        {
            var bucketKey = (0, candidate.ParsedVersion.ClassKey);
            if (!bucketMaxDates.TryGetValue(bucketKey, out var existingMax)
                || (candidate.ReleaseDate.HasValue && (!existingMax.HasValue || candidate.ReleaseDate.Value > existingMax.Value)))
            {
                bucketMaxDates[bucketKey] = candidate.ReleaseDate;
            }
        }

        var ordered = new List<AsusCatalogCandidate>(candidates);
        ordered.Sort((a, b) =>
        {
            var bucketDateCmp = CompareNullableDateDescending(
                bucketMaxDates[(0, a.ParsedVersion.ClassKey)],
                bucketMaxDates[(0, b.ParsedVersion.ClassKey)]);
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

        var prefixMatch = PrefixNumericRegex().Match(normalized);
        if (prefixMatch.Success && TryParseDottedInt64(prefixMatch.Groups[2].Value, out var pfxSegs))
            return (VersionClass.PrefixNumeric, "2:PFX:" + prefixMatch.Groups[1].Value, pfxSegs);

        if (IsDottedNumeric(normalized) && TryParseDottedInt64(normalized, out var numSegs))
            return (VersionClass.Numeric, "1:NUM", numSegs);

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

    private static string BuildCatalogUrl(string endpointTemplate, string modelToken)
    {
        var escaped = Uri.EscapeDataString(modelToken);
        if (EndpointPlaceholderRegex().IsMatch(endpointTemplate))
            return EndpointPlaceholderRegex().Replace(endpointTemplate, escaped);

        var fragIdx = endpointTemplate.IndexOf('#');
        var basePart = fragIdx >= 0 ? endpointTemplate[..fragIdx] : endpointTemplate;
        var sep = basePart.Contains('?', StringComparison.Ordinal) ? "&" : "?";
        return $"{basePart}{sep}model={escaped}";
    }

    private static async Task<JsonDocument> ReadBoundedJsonDocumentAsync(HttpContent content, CancellationToken ct)
    {
        var contentLength = content.Headers.ContentLength;
        if (contentLength.HasValue && contentLength.Value > MaxCatalogJsonBytes)
            throw new InvalidDataException($"ASUS BIOS catalog response ({contentLength.Value} bytes) exceeds maximum allowed limit ({MaxCatalogJsonBytes} bytes).");

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
                    throw new InvalidDataException($"ASUS BIOS catalog response exceeded maximum allowed size ({MaxCatalogJsonBytes} bytes).");

                ms.Write(buffer, 0, read);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        if (totalRead == 0)
            throw new InvalidDataException("ASUS BIOS catalog response body is empty.");

        var rawBytes = ms.GetBuffer();
        var offset = 0;
        var length = (int)ms.Length;

        // Strip UTF-8 BOM (EF BB BF) if present.
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
            throw new InvalidDataException("ASUS BIOS catalog response body is empty or whitespace.");

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
            throw new InvalidOperationException("Disallowed ASUS catalog URL.");

        var visited = new HashSet<string>(StringComparer.Ordinal) { current.AbsoluteUri };
        const int maxRedirects = BiosProviderHttp.DefaultMaxRedirects;

        for (var hop = 0; hop <= maxRedirects; hop++)
        {
            ct.ThrowIfCancellationRequested();

            using var request = new HttpRequestMessage(HttpMethod.Get, current);
            request.Headers.Accept.ParseAdd("application/json");

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

    private enum VersionClass
    {
        Empty,
        Numeric,
        PrefixNumeric,
        Skeleton,
        Literal,
    }

    private sealed record AsusParsedVersion(
        string NormalizedVersion,
        string DisplayVersion,
        string Family,
        VersionClass Class,
        string ClassKey,
        long[] Segments,
        string RawNormalized);

    private sealed record AsusCatalogCandidate(
        string DisplayVersion,
        AsusParsedVersion ParsedVersion,
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
