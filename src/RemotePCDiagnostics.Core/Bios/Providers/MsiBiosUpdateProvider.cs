using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using static RemotePCDiagnostics.Core.Bios.BiosProviderCommon;

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

    private static readonly string[] MsiExtraNonBiosKeywords = ["led firmware", "rgb firmware"];

    [GeneratedRegex(@"^MS-([0-9A-Za-z]{4})$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex ExactMsBoardCodeRegex();

    [GeneratedRegex(@"\(\s*MS-([0-9A-Za-z]{4})\s*\)$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex ParenthesizedMsBoardCodeRegex();

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

        var serial = system.SerialNumber;
        var safeVendor = RedactText(current.Vendor ?? "", serial);
        var safeVersion = RedactText(normalizedVersion, serial);
        var safeReleaseDateRaw = RedactText(current.ReleaseDateRaw ?? "", serial);
        var safeSmbiosRevision = RedactText(current.SmbiosRevision ?? "", serial);
        var safeFamily = RedactText(family, serial);
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

        if (!TryResolveBoardOrModel(system, out var productToken, out var extractedBoardCode, out var invalidReason))
        {
            LogWarn($"[BIOS/MSI] Unable to determine valid MSI board/model identifier: {invalidReason}", system.SerialNumber);
            return RedactLatestInfo(
                BiosLatestInfo.Unsupported(VendorId, $"Unable to determine a valid MSI motherboard or model identifier: {invalidReason}"),
                system.SerialNumber);
        }

        var requestUrl = BuildCatalogUrl(_catalogEndpoint, productToken, fallbackQueryParam: "product");
        if (!BiosProviderHttp.TryValidateVendorUrl(requestUrl, AllowedHostSuffixes, out _))
        {
            LogWarn("[BIOS/MSI] Configured MSI catalog endpoint failed HTTPS/domain/path validation.", system.SerialNumber);
            return RedactLatestInfo(
                BiosLatestInfo.Failed(VendorId, "MSI BIOS catalog endpoint URL failed security validation."),
                system.SerialNumber);
        }

        try
        {
            using var response = await BiosProviderHttp.GetVendorUrlWithSafeRedirectsAsync(
                _httpClient, requestUrl, AllowedHostSuffixes, DisplayName, "application/json", ct).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                var statusInfo = BiosProviderHttp.ClassifyHttpStatus(VendorId, DisplayName, response.StatusCode, $"product '{productToken}'");
                return RedactLatestInfo(statusInfo, system.SerialNumber);
            }

            using var doc = await BiosProviderHttp.ReadBoundedJsonDocumentAsync(
                response.Content, MaxCatalogJsonBytes, DisplayName, ct).ConfigureAwait(false);
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

        return Task.FromResult(CreateCheckOnlyInstallResult(
            request,
            "MSI BIOS provider is check-only and does not support automated installation. Download the verified BIOS package manually and flash via MSI M-Flash."));
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

        var isNewer = IsCandidateNewer(parsedCurrent, current.ReleaseDate, best.ParsedVersion, best.ReleaseDate);
        if (CheckUntrustedCandidatesFailClosed(
                VendorId,
                DisplayName,
                best,
                compatibleUntrusted,
                isNewer,
                static (b, bad) => IsCandidateNewer(b.ParsedVersion, b.ReleaseDate, bad.ParsedVersion, bad.ReleaseDate),
                static (bad, b) => CompareMsiVersions(bad.ParsedVersion, b.ParsedVersion)) is { } untrustedFailure)
        {
            return untrustedFailure;
        }

        if (!isNewer)
        {
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

                            if (IsMsiNonBiosCategory(section.Name))
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
                    if (section.Value.ValueKind != JsonValueKind.Array || IsMsiNonBiosCategory(section.Name))
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
        if (IsMsiNonBiosEntry(category, title))
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

        var downloadState = ExtractStringDownloadUrl(
            item, AllowedHostSuffixes, out var downloadUrl, "download_url", "downloadUrl", "url", "download_link", "fileUrl");

        var releaseDate = TryParseReleaseDate(GetStringOrNumber(item, "download_release", "release_date", "releaseDate", "date", "download_date"));
        var rawNotesUrl = GetStringOrNumber(item, "release_notes_url", "releaseNotesUrl", "notes_url", "readme_url", "support_url");
        string? notesUrl = null;
        if (!string.IsNullOrWhiteSpace(rawNotesUrl) && BiosProviderHttp.TryValidateVendorUrl(rawNotesUrl, AllowedHostSuffixes, out var validNotesUri))
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

    private static bool IsMsiNonBiosCategory(string category) =>
        ContainsAnyKeyword(category.Trim(), MsiExtraNonBiosKeywords) || IsNonBiosCategory(category);

    private static bool IsMsiNonBiosEntry(string? category, string? title) =>
        (!string.IsNullOrWhiteSpace(category) && ContainsAnyKeyword(category.Trim(), MsiExtraNonBiosKeywords))
        || (!string.IsNullOrWhiteSpace(title) && ContainsAnyKeyword(title, MsiExtraNonBiosKeywords))
        || IsNonBiosEntry(category, title);

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

    private static List<MsiCatalogCandidate> OrderCandidates(List<MsiCatalogCandidate> candidates, MsiParsedVersion current) =>
        BiosProviderCommon.OrderCandidates(
            candidates,
            getPrefRank: c => GetCandidatePreferenceRank(c.ParsedVersion, current),
            getClassKey: static c => c.ParsedVersion.ClassKey,
            compareWithinClass: static (a, b) => CompareWithinClass(a.ParsedVersion, b.ParsedVersion),
            comparePrefRankFirst: true,
            prefRankDescending: true);

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

        if (IsDottedNumeric(normalized) && TryParseDottedInt64(normalized, out var numSegs))
            return (GenericVersionKind.Numeric, "1:NUM", numSegs);

        if (TryExtractSkeletonVersion(normalized, classPrefix: 3, out var skelKey, out var runs))
            return (GenericVersionKind.Skeleton, skelKey, runs);

        return (GenericVersionKind.Literal, "4:LIT:" + normalized, []);
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

    private void LogWarn(string message, string? serialNumber) =>
        _log?.Warn(RedactText(message, serialNumber));

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
        long? SizeBytes) : IBiosCatalogCandidateTieBreak;
}
