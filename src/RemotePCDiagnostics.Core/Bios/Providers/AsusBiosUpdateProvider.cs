using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using static RemotePCDiagnostics.Core.Bios.BiosProviderCommon;

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

    private static readonly string[] AsusExtraNonBiosKeywords = ["biosrenamer", "bios renamer", "ez update"];

    private static bool IsAsusNonBiosCategory(string category) =>
        ContainsAnyKeyword(category.Trim(), AsusExtraNonBiosKeywords) || IsNonBiosCategory(category);

    private static bool IsAsusNonBiosEntry(string? category, string? title) =>
        (!string.IsNullOrWhiteSpace(category) && ContainsAnyKeyword(category.Trim(), AsusExtraNonBiosKeywords))
        || (!string.IsNullOrWhiteSpace(title) && ContainsAnyKeyword(title, AsusExtraNonBiosKeywords))
        || IsNonBiosEntry(category, title);

    [GeneratedRegex(@"^([A-Za-z][A-Za-z0-9\-_]{2,24})\.(\d{2,5})$", RegexOptions.CultureInvariant)]
    private static partial Regex LaptopFamilyBuildRegex();

    [GeneratedRegex(@"(?:^|\s)BIOS\s+(?:Version\s+|Ver\.?\s*)?([0-9][A-Za-z0-9._\-]{0,31})$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex TrailingBiosTokenRegex();

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
        TryResolveModelIdentifier(system, out var modelToken, out _);

        return Task.FromResult(BuildRedactedCurrentInfo(
            current, VendorId, parsed.NormalizedVersion, modelToken, system.SerialNumber, familyOverride: parsed.Family));
    }

    public Task<BiosLatestInfo> GetLatestVersionAsync(
        BiosSystemIdentity system,
        BiosCurrentInfo current,
        CancellationToken ct = default) =>
        BiosProviderHttp.FetchAndEvaluateModelJsonCatalogAsync(
            _httpClient,
            VendorId,
            DisplayName,
            _catalogEndpoint,
            AllowedHostSuffixes,
            MaxCatalogJsonBytes,
            system,
            current,
            _log,
            EvaluateCatalog,
            ct);

    public Task<BiosInstallResult> InstallAsync(
        BiosInstallRequest request,
        IProgress<BiosInstallProgress>? progress = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ct.ThrowIfCancellationRequested();

        return Task.FromResult(CreateCheckOnlyInstallResult(
            request,
            "ASUS BIOS provider is check-only and does not support automated installation. Download the verified BIOS package manually and flash via ASUS EZ Flash."));
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

        var isNewer = IsCandidateNewer(parsedCurrent, current.ReleaseDate, best.ParsedVersion, best.ReleaseDate);
        if (CheckUntrustedCandidatesFailClosed(
                VendorId,
                DisplayName,
                best,
                compatibleUntrusted,
                isNewer,
                static (b, bad) => IsCandidateNewer(b.ParsedVersion, b.ReleaseDate, bad.ParsedVersion, bad.ReleaseDate),
                static (bad, b) => CompareAsusVersions(bad.ParsedVersion, b.ParsedVersion)) is { } untrustedFailure)
        {
            return untrustedFailure;
        }

        if (!isNewer)
        {
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
                        if (!string.IsNullOrWhiteSpace(groupName) && IsAsusNonBiosCategory(groupName))
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
        if (IsAsusNonBiosEntry(category, title))
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
        if (!string.IsNullOrWhiteSpace(rawNotesUrl) && BiosProviderHttp.TryValidateVendorUrl(rawNotesUrl, AllowedHostSuffixes, out var validNotesUri))
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

        if (!TryGetPropertyIgnoreCase(item, out var dlEl, "DownloadUrl", "DownloadLink", "Url", "FileUrl"))
            return UrlExtractionState.Absent;

        if (dlEl.ValueKind == JsonValueKind.Object)
        {
            // Prefer Global; if Global is explicitly present (non-null) and untrusted or wrong-kind, fail closed.
            if (TryGetPropertyIgnoreCase(dlEl, out var globalEl, "Global"))
                return ValidateJsonUrlElement(globalEl, out validatedUrl);

            if (TryGetPropertyIgnoreCase(dlEl, out var fallbackEl, "China", "Url", "Link"))
                return ValidateJsonUrlElement(fallbackEl, out validatedUrl);

            return UrlExtractionState.Absent;
        }

        if (dlEl.ValueKind == JsonValueKind.String)
            return ValidateJsonUrlElement(dlEl, out validatedUrl);

        // Non-null wrong JsonValueKind (e.g., Number, True, False, Array) fails closed as untrusted.
        return UrlExtractionState.Untrusted;
    }

    private static UrlExtractionState ValidateJsonUrlElement(JsonElement el, out string? validatedUrl)
    {
        validatedUrl = null;
        if (el.ValueKind != JsonValueKind.String)
            return UrlExtractionState.Untrusted;

        var raw = el.GetString()?.Trim();
        if (string.IsNullOrWhiteSpace(raw))
            return UrlExtractionState.Absent;

        if (BiosProviderHttp.TryValidateVendorUrl(raw, AllowedHostSuffixes, out var uri))
        {
            validatedUrl = uri.AbsoluteUri;
            return UrlExtractionState.Valid;
        }

        return UrlExtractionState.Untrusted;
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

    private static List<AsusCatalogCandidate> OrderCandidates(List<AsusCatalogCandidate> candidates) =>
        BiosProviderCommon.OrderCandidates(
            candidates,
            getPrefRank: static _ => 0,
            getClassKey: static c => c.ParsedVersion.ClassKey,
            compareWithinClass: static (a, b) => CompareWithinClass(a.ParsedVersion, b.ParsedVersion));

    private static (VersionClass Class, string ClassKey, long[] Segments) ClassifyGenericVersion(string normalized)
    {
        if (string.IsNullOrWhiteSpace(normalized))
            return (VersionClass.Empty, "0:", []);

        var prefixMatch = PrefixNumericRegex().Match(normalized);
        if (prefixMatch.Success && TryParseDottedInt64(prefixMatch.Groups[2].Value, out var pfxSegs))
            return (VersionClass.PrefixNumeric, "2:PFX:" + prefixMatch.Groups[1].Value, pfxSegs);

        if (IsDottedNumeric(normalized) && TryParseDottedInt64(normalized, out var numSegs))
            return (VersionClass.Numeric, "1:NUM", numSegs);

        if (TryExtractSkeletonVersion(normalized, classPrefix: 3, out var skelKey, out var runs))
            return (VersionClass.Skeleton, skelKey, runs);

        return (VersionClass.Literal, "4:LIT:" + normalized, []);
    }

    private void LogWarn(string message, string? serialNumber) =>
        _log?.Warn(RedactText(message, serialNumber));

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
        long? SizeBytes) : IBiosCatalogCandidateTieBreak;
}
