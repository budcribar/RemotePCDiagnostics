using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using static RemotePCDiagnostics.Core.Bios.BiosProviderCommon;

namespace RemotePCDiagnostics.Core.Bios;

/// <summary>
/// Check-only Acer BIOS/UEFI update provider (<c>VendorId = "acer"</c>).
/// Queries the Acer Support BIOS JSON catalog over HTTPS (100% pure C#, zero external processes or scripts).
/// Automated installation is not supported; operators download and flash manually.
/// </summary>
public sealed partial class AcerBiosUpdateProvider : IBiosUpdateProvider
{
    public const string ProviderVendorId = "acer";
    public const string DefaultCatalogEndpoint = "https://www.acer.com/us-en/support/api/product/bios?model={model}";

    public static readonly IReadOnlyList<string> AllowedHostSuffixes = ["acer.com"];

    public const long MaxCatalogJsonBytes = 8L * 1024 * 1024;

    [GeneratedRegex(@"^([A-Za-z])(\d{1,3})[-_]([A-Za-z])(\d{1,3})([A-Za-z])?$", RegexOptions.CultureInvariant)]
    private static partial Regex AcerDesktopRevRegex();

    [GeneratedRegex(@"^(\d+(?:\.\d+)*)([A-Za-z])?$", RegexOptions.CultureInvariant)]
    private static partial Regex AcerDottedNumericRegex();

    private readonly HttpClient _httpClient;
    private readonly ILogger? _log;
    private readonly string _catalogEndpoint;

    /// <summary>
    /// Creates an Acer BIOS update provider. All parameters are optional so MS.DI resolves
    /// this single constructor cleanly with zero optional service registrations.
    /// </summary>
    public AcerBiosUpdateProvider(
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
    public static AcerBiosUpdateProvider CreateWithHandler(
        HttpMessageHandler httpHandler,
        ILogger? log = null,
        string? catalogEndpoint = null) =>
        new(BiosProviderHttp.CreateClient(httpHandler), log, catalogEndpoint);

    public string VendorId => ProviderVendorId;
    public string DisplayName => "Acer";
    public int Priority => 100;

    public BiosProviderCapabilities Capabilities { get; } = new(
        CanCheckLatest: true,
        CanInstall: false,
        SupportsSilentInstall: false,
        RequiresReboot: false,
        RequiresElevation: false,
        RequiresInternet: true);

    public bool CanHandle(BiosSystemIdentity system) =>
        system is not null && BiosVendorIdentity.IsAcer(system);

    public Task<BiosCurrentInfo> GetCurrentVersionAsync(BiosSystemIdentity system, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(system);
        ct.ThrowIfCancellationRequested();

        var current = system.CurrentBios ?? BiosCurrentInfo.Empty;
        var parsed = ParseAcerVersion(current.Version);
        TryResolveModelIdentifier(system, out var modelToken, out _);

        return Task.FromResult(BuildRedactedCurrentInfo(current, VendorId, parsed.NormalizedVersion, modelToken, system.SerialNumber));
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
            LogWarn($"[BIOS/Acer] Unable to determine valid Acer model identifier: {invalidReason}", system.SerialNumber);
            return RedactLatestInfo(
                BiosLatestInfo.Unsupported(VendorId, $"Unable to determine a valid Acer model or board product identifier: {invalidReason}"),
                system.SerialNumber);
        }

        var requestUrl = BuildCatalogUrl(_catalogEndpoint, modelToken);
        if (!BiosProviderHttp.TryValidateVendorUrl(requestUrl, AllowedHostSuffixes, out _))
        {
            LogWarn("[BIOS/Acer] Configured Acer catalog endpoint failed HTTPS/domain/path validation.", system.SerialNumber);
            return RedactLatestInfo(
                BiosLatestInfo.Failed(VendorId, "Acer BIOS catalog endpoint URL failed security validation."),
                system.SerialNumber);
        }

        try
        {
            using var response = await BiosProviderHttp.GetVendorUrlWithSafeRedirectsAsync(
                _httpClient, requestUrl, AllowedHostSuffixes, DisplayName, "application/json", ct).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                var statusInfo = BiosProviderHttp.ClassifyHttpStatus(VendorId, DisplayName, response.StatusCode, $"model '{modelToken}'");
                return RedactLatestInfo(statusInfo, system.SerialNumber);
            }

            using var doc = await BiosProviderHttp.ReadBoundedJsonDocumentAsync(
                response.Content, MaxCatalogJsonBytes, DisplayName, ct).ConfigureAwait(false);
            var evaluated = EvaluateCatalog(doc, current, modelToken, system.SerialNumber);
            return RedactLatestInfo(evaluated, system.SerialNumber);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            LogWarn($"[BIOS/Acer] Catalog lookup failed for '{modelToken}': {ex.Message}", system.SerialNumber);
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
            "Acer BIOS provider is check-only and does not support automated installation. Download the verified BIOS package manually from Acer Support."));
    }

    private BiosLatestInfo EvaluateCatalog(JsonDocument doc, BiosCurrentInfo current, string modelToken, string? serialNumber)
    {
        var root = doc.RootElement;
        if (root.ValueKind is not (JsonValueKind.Object or JsonValueKind.Array))
            return BiosLatestInfo.Failed(VendorId, "Acer BIOS catalog returned an unexpected JSON root type.");

        var parsedCurrent = ParseAcerVersion(current.Version);
        var entries = new List<AcerCatalogCandidate>();
        var rejectedUntrusted = new List<AcerCatalogCandidate>();
        var sawAnyBiosEntry = false;
        var sawOnlyBeta = true;

        CollectCandidates(root, entries, rejectedUntrusted, ref sawAnyBiosEntry, ref sawOnlyBeta, serialNumber);

        if (entries.Count == 0)
        {
            if (rejectedUntrusted.Count > 0)
                return BiosLatestInfo.Failed(VendorId, "Acer BIOS catalog returned BIOS download URL(s) that failed HTTPS/domain security validation.");

            if (sawAnyBiosEntry && sawOnlyBeta)
                return BiosLatestInfo.Unsupported(VendorId, $"Acer BIOS catalog for '{modelToken}' contains only beta/pre-release BIOS entries.");

            return BiosLatestInfo.Unsupported(VendorId, $"No matching Acer system BIOS updates were found for '{modelToken}'.");
        }

        var ordered = OrderCandidates(entries);
        var best = ordered[0];

        if (rejectedUntrusted.Count > 0)
        {
            foreach (var bad in rejectedUntrusted)
            {
                if (IsCandidateNewer(best.ParsedVersion, best.ReleaseDate, bad.ParsedVersion, bad.ReleaseDate))
                {
                    return BiosLatestInfo.Failed(
                        VendorId,
                        "Acer BIOS catalog contained a newer BIOS entry whose download URL failed HTTPS/domain security validation.");
                }
            }
        }

        var isNewer = IsCandidateNewer(parsedCurrent, current.ReleaseDate, best.ParsedVersion, best.ReleaseDate);
        if (!isNewer)
        {
            if (rejectedUntrusted.Count > 0)
            {
                foreach (var bad in rejectedUntrusted)
                {
                    var cmp = CompareAcerVersions(bad.ParsedVersion, best.ParsedVersion);
                    if (cmp is null or >= 0)
                    {
                        return BiosLatestInfo.Failed(
                            VendorId,
                            "Acer BIOS catalog contained BIOS entries whose download URL failed HTTPS/domain security validation.");
                    }
                }
            }

            var meta = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["model"] = modelToken,
            };

            return BiosLatestInfo.UpToDate(
                VendorId,
                best.DisplayVersion,
                best.ReleaseDate,
                message: $"Acer BIOS is up to date ({best.DisplayVersion}).",
                metadata: meta);
        }

        var updateMeta = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["model"] = modelToken,
        };

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
            message: $"Acer BIOS update {best.DisplayVersion} is available for {modelToken}.",
            metadata: updateMeta);
    }

    private void CollectCandidates(
        JsonElement root,
        List<AcerCatalogCandidate> trusted,
        List<AcerCatalogCandidate> untrusted,
        ref bool sawAnyBiosEntry,
        ref bool sawOnlyBeta,
        string? serialNumber)
    {
        if (root.ValueKind == JsonValueKind.Array)
        {
            ParseEntriesArray(root, requireBiosCategory: false, trusted, untrusted, ref sawAnyBiosEntry, ref sawOnlyBeta, serialNumber);
            return;
        }

        // Direct BIOS-specific arrays at root
        if (TryGetPropertyIgnoreCase(root, out var directBios, "bios", "biosUpdates", "firmware")
            && directBios.ValueKind == JsonValueKind.Array)
        {
            ParseEntriesArray(directBios, requireBiosCategory: false, trusted, untrusted, ref sawAnyBiosEntry, ref sawOnlyBeta, serialNumber);
            return;
        }

        // Unwrap nested data / result wrapper objects or arrays
        if (TryGetPropertyIgnoreCase(root, out var wrapper, "data", "result", "results"))
        {
            if (wrapper.ValueKind == JsonValueKind.Array)
            {
                ParseEntriesArray(wrapper, requireBiosCategory: false, trusted, untrusted, ref sawAnyBiosEntry, ref sawOnlyBeta, serialNumber);
                return;
            }

            if (wrapper.ValueKind == JsonValueKind.Object)
            {
                if (TryGetPropertyIgnoreCase(wrapper, out var nestedBios, "bios", "biosUpdates", "firmware")
                    && nestedBios.ValueKind == JsonValueKind.Array)
                {
                    ParseEntriesArray(nestedBios, requireBiosCategory: false, trusted, untrusted, ref sawAnyBiosEntry, ref sawOnlyBeta, serialNumber);
                    return;
                }

                if (TryGetPropertyIgnoreCase(wrapper, out var nestedDrivers, "drivers")
                    && nestedDrivers.ValueKind == JsonValueKind.Array)
                {
                    ParseEntriesArray(nestedDrivers, requireBiosCategory: true, trusted, untrusted, ref sawAnyBiosEntry, ref sawOnlyBeta, serialNumber);
                    return;
                }

                if (TryGetPropertyIgnoreCase(wrapper, out var nestedList, "items", "files", "downloads", "list", "results")
                    && nestedList.ValueKind == JsonValueKind.Array)
                {
                    ParseEntriesArray(nestedList, requireBiosCategory: false, trusted, untrusted, ref sawAnyBiosEntry, ref sawOnlyBeta, serialNumber);
                    return;
                }
            }
        }

        // Mixed drivers array at root -> require BIOS category
        if (TryGetPropertyIgnoreCase(root, out var driversArray, "drivers") && driversArray.ValueKind == JsonValueKind.Array)
        {
            ParseEntriesArray(driversArray, requireBiosCategory: true, trusted, untrusted, ref sawAnyBiosEntry, ref sawOnlyBeta, serialNumber);
            return;
        }

        // Generic list containers at root
        if (TryGetPropertyIgnoreCase(root, out var genericArray, "items", "files", "downloads", "list")
            && genericArray.ValueKind == JsonValueKind.Array)
        {
            ParseEntriesArray(genericArray, requireBiosCategory: false, trusted, untrusted, ref sawAnyBiosEntry, ref sawOnlyBeta, serialNumber);
            return;
        }

        // Single BIOS object at root
        if (TryGetPropertyIgnoreCase(root, out _, "version", "biosVersion", "ver"))
            ParseSingleEntry(root, requireBiosCategory: false, trusted, untrusted, ref sawAnyBiosEntry, ref sawOnlyBeta, serialNumber);
    }

    private void ParseEntriesArray(
        JsonElement array,
        bool requireBiosCategory,
        List<AcerCatalogCandidate> trusted,
        List<AcerCatalogCandidate> untrusted,
        ref bool sawAnyBiosEntry,
        ref bool sawOnlyBeta,
        string? serialNumber)
    {
        foreach (var item in array.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object)
                continue;

            ParseSingleEntry(item, requireBiosCategory, trusted, untrusted, ref sawAnyBiosEntry, ref sawOnlyBeta, serialNumber);
        }
    }

    private void ParseSingleEntry(
        JsonElement item,
        bool requireBiosCategory,
        List<AcerCatalogCandidate> trusted,
        List<AcerCatalogCandidate> untrusted,
        ref bool sawAnyBiosEntry,
        ref bool sawOnlyBeta,
        string? serialNumber)
    {
        var category = GetStringOrNumber(item, "category", "type", "group", "classification");
        var title = GetStringOrNumber(item, "title", "name", "caption");

        if (requireBiosCategory && string.IsNullOrWhiteSpace(category))
        {
            if (string.IsNullOrWhiteSpace(title)
                || (!title.Contains("bios", StringComparison.OrdinalIgnoreCase)
                    && !title.Contains("uefi", StringComparison.OrdinalIgnoreCase)))
            {
                return;
            }
        }

        if (IsNonBiosEntry(category, title))
            return;

        var rawVersion = GetStringOrNumber(item, "version", "biosVersion", "ver");
        var description = GetStringOrNumber(item, "description", "summary", "releaseNotes", "notes");
        if (string.IsNullOrWhiteSpace(rawVersion))
            return;

        sawAnyBiosEntry = true;

        var isReleaseFlag = GetNullableBool(item, "isRelease", "release");
        var isBetaFlag = GetNullableBool(item, "isBeta", "beta");
        if (IsBetaRelease(rawVersion, title, description, isReleaseFlag, isBetaFlag))
            return;

        sawOnlyBeta = false;

        var downloadState = ExtractStringDownloadUrl(
            item, AllowedHostSuffixes, out var downloadUrl, "downloadUrl", "url", "downloadLink", "fileUrl", "link");

        var parsedVersion = ParseAcerVersion(rawVersion);
        if (string.IsNullOrEmpty(parsedVersion.NormalizedVersion))
            return;

        var releaseDate = TryParseReleaseDate(GetStringOrNumber(item, "releaseDate", "date", "postDate", "publishDate", "updatedDate"));
        var rawNotesUrl = GetStringOrNumber(item, "releaseNotesUrl", "readmeUrl", "notesUrl", "supportUrl");
        string? notesUrl = null;
        if (!string.IsNullOrWhiteSpace(rawNotesUrl) && BiosProviderHttp.TryValidateVendorUrl(rawNotesUrl, AllowedHostSuffixes, out var validNotesUri))
            notesUrl = validNotesUri.AbsoluteUri;

        var sha256 = TryNormalizeSha256(GetStringOrNumber(item, "sha256", "checksum", "hash"));
        var sizeBytes = TryParseSizeBytes(item, "fileSize", "size", "sizeBytes", "fileSizeBytes");
        var packageId = GetStringOrNumber(item, "packageId", "id", "documentId", "fileName");
        var severity = ParseSeverity(
            GetStringOrNumber(item, "severity", "priority", "importance"),
            GetNullableBool(item, "critical", "isCritical"),
            title,
            description);
        var summary = CleanReleaseSummary(title, description);

        var candidate = new AcerCatalogCandidate(
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
            LogWarn($"[BIOS/Acer] Rejecting BIOS entry '{candidate.DisplayVersion}' with untrusted download URL.", serialNumber);
            untrusted.Add(candidate);
            return;
        }

        trusted.Add(candidate);
    }

    private static AcerParsedVersion ParseAcerVersion(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return new AcerParsedVersion("", "", AcerVersionKind.Empty, "0:", [], '\0', 0, '\0', 0, '\0');

        var cleaned = raw.Trim();

        while (true)
        {
            var stripped = LeadingVersionPrefixRegex().Replace(cleaned, "").Trim();
            if (stripped.Length == cleaned.Length)
                break;
            cleaned = stripped;
        }

        var vStripped = LeadingVPrefixRegex().Replace(cleaned, "").Trim();
        if (vStripped.Length > 0)
            cleaned = vStripped;

        if (cleaned.Length == 0)
            return new AcerParsedVersion("", "", AcerVersionKind.Empty, "0:", [], '\0', 0, '\0', 0, '\0');

        // Kind 1: Acer Desktop Revision ("R01-A4", "R01-A10", "R01-B1", "R02-A0", "P01-A3")
        var revMatch = AcerDesktopRevRegex().Match(cleaned);
        if (revMatch.Success
            && int.TryParse(revMatch.Groups[2].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var major)
            && int.TryParse(revMatch.Groups[4].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var minor))
        {
            var prefix = ToAsciiUpper(revMatch.Groups[1].Value[0]);
            var revLetter = ToAsciiUpper(revMatch.Groups[3].Value[0]);
            var suffix = revMatch.Groups[5].Success ? ToAsciiUpper(revMatch.Groups[5].Value[0]) : '\0';
            return new AcerParsedVersion(
                NormalizedVersion: cleaned,
                DisplayVersion: cleaned,
                Kind: AcerVersionKind.DesktopRevision,
                ClassKey: $"2:ACER_REV:{prefix}",
                Segments: [],
                TrailingLetter: '\0',
                RevMajor: major,
                RevLetter: revLetter,
                RevMinor: minor,
                RevSuffix: suffix);
        }

        // Kind 2: Dotted numeric with optional trailing ASCII letter ("1.08", "1.08A", "1.14", "1.14.0")
        var numMatch = AcerDottedNumericRegex().Match(cleaned);
        if (numMatch.Success && TryParseDottedInt64(numMatch.Groups[1].Value, out var numSegs))
        {
            var trailing = numMatch.Groups[2].Success ? ToAsciiUpper(numMatch.Groups[2].Value[0]) : '\0';
            var display = trailing == '\0' ? cleaned : numMatch.Groups[1].Value + trailing;
            return new AcerParsedVersion(
                NormalizedVersion: display,
                DisplayVersion: display,
                Kind: AcerVersionKind.DottedNumeric,
                ClassKey: "1:ACER_NUM",
                Segments: numSegs,
                TrailingLetter: trailing,
                RevMajor: 0,
                RevLetter: '\0',
                RevMinor: 0,
                RevSuffix: '\0');
        }

        // Kind 3..5: Generic prefix-numeric, bijective skeleton, or literal
        var prefixMatch = PrefixNumericRegex().Match(cleaned);
        if (prefixMatch.Success && TryParseDottedInt64(prefixMatch.Groups[2].Value, out var pfxSegs))
        {
            return new AcerParsedVersion(
                cleaned,
                cleaned,
                AcerVersionKind.PrefixNumeric,
                "3:PFX:" + prefixMatch.Groups[1].Value,
                pfxSegs,
                '\0', 0, '\0', 0, '\0');
        }

        var digitMatches = DigitRunsRegex().Matches(cleaned);
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
                var skeleton = BuildBijectiveSkeleton(cleaned);
                return new AcerParsedVersion(
                    cleaned,
                    cleaned,
                    AcerVersionKind.Skeleton,
                    $"4:SKEL:{runs.Length}:{skeleton}",
                    runs,
                    '\0', 0, '\0', 0, '\0');
            }
        }

        return new AcerParsedVersion(
            cleaned,
            cleaned,
            AcerVersionKind.Literal,
            "5:LIT:" + cleaned,
            [],
            '\0', 0, '\0', 0, '\0');
    }

    private static bool IsCandidateNewer(
        AcerParsedVersion current,
        DateOnly? currentDate,
        AcerParsedVersion candidate,
        DateOnly? candidateDate)
    {
        if (candidate.Kind == AcerVersionKind.Empty)
            return false;

        var cmp = CompareAcerVersions(current, candidate);
        if (cmp.HasValue)
            return cmp.Value < 0;

        if (currentDate.HasValue && candidateDate.HasValue)
            return candidateDate.Value > currentDate.Value;

        return false;
    }

    private static int? CompareAcerVersions(AcerParsedVersion a, AcerParsedVersion b)
    {
        if (a.Kind == AcerVersionKind.Empty || b.Kind == AcerVersionKind.Empty)
            return null;

        if (string.Equals(a.ClassKey, b.ClassKey, StringComparison.OrdinalIgnoreCase))
            return CompareWithinClass(a, b);

        return null;
    }

    private static int CompareWithinClass(AcerParsedVersion a, AcerParsedVersion b)
    {
        switch (a.Kind)
        {
            case AcerVersionKind.DottedNumeric:
            {
                var segCmp = CompareNumericSegmentArrays(a.Segments, b.Segments);
                if (segCmp != 0)
                    return segCmp;
                return a.TrailingLetter.CompareTo(b.TrailingLetter);
            }
            case AcerVersionKind.DesktopRevision:
            {
                var c = a.RevMajor.CompareTo(b.RevMajor);
                if (c != 0) return c;
                c = a.RevLetter.CompareTo(b.RevLetter);
                if (c != 0) return c;
                c = a.RevMinor.CompareTo(b.RevMinor);
                if (c != 0) return c;
                return a.RevSuffix.CompareTo(b.RevSuffix);
            }
            case AcerVersionKind.PrefixNumeric:
                return CompareNumericSegmentArrays(a.Segments, b.Segments);
            case AcerVersionKind.Skeleton:
                return CompareFixedLengthArrays(a.Segments, b.Segments);
            default:
                return 0;
        }
    }

    private static List<AcerCatalogCandidate> OrderCandidates(List<AcerCatalogCandidate> candidates) =>
        BiosProviderCommon.OrderCandidates(
            candidates,
            getPrefRank: static _ => 0,
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
                a.Severity, b.Severity));

    private void LogWarn(string message, string? serialNumber) =>
        _log?.Warn(RedactText(message, serialNumber));

    private enum AcerVersionKind
    {
        Empty,
        DottedNumeric,
        DesktopRevision,
        PrefixNumeric,
        Skeleton,
        Literal,
    }

    private sealed record AcerParsedVersion(
        string NormalizedVersion,
        string DisplayVersion,
        AcerVersionKind Kind,
        string ClassKey,
        long[] Segments,
        char TrailingLetter,
        int RevMajor,
        char RevLetter,
        int RevMinor,
        char RevSuffix);

    private sealed record AcerCatalogCandidate(
        string DisplayVersion,
        AcerParsedVersion ParsedVersion,
        DateOnly? ReleaseDate,
        BiosUpdateSeverity Severity,
        string? PackageId,
        string? ReleaseSummary,
        string? ReleaseNotesUrl,
        string? DownloadUrl,
        string? Sha256,
        long? SizeBytes);
}
