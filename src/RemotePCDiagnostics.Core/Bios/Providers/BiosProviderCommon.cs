using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace RemotePCDiagnostics.Core.Bios;

internal enum SmbiosTokenStatus
{
    EmptyOrPlaceholder,
    Valid,
    InvalidUnsafe,
}

internal enum UrlExtractionState
{
    Absent,
    Valid,
    Untrusted,
}

/// <summary>
/// Shared internal helpers for BIOS update providers: version/numeric comparison, SMBIOS model
/// token resolution, JSON/XML field extraction, release/beta/category classification, and
/// serial-number redaction.
/// </summary>
internal static partial class BiosProviderCommon
{
    internal const int DefaultMaxSummaryLength = 1000;

    internal static readonly HashSet<string> PlaceholderTokens = new(StringComparer.OrdinalIgnoreCase)
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

    internal static readonly string[] NonBiosTitleAlwaysRejectKeywords =
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

    internal static readonly string[] NonBiosCategoryKeywords =
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

    internal static readonly IEqualityComparer<(int PrefRank, string ClassKey)> BucketKeyComparer =
        new BucketKeyEqualityComparer();

    [GeneratedRegex(@"\A[0-9A-Fa-f]{64}\z", RegexOptions.CultureInvariant)]
    internal static partial Regex Sha256Regex();

    [GeneratedRegex(@"^(?:BIOS\s+Version|Version|Ver\.?|Rev\.?|BIOS)\s*[:\-]?\s*", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    internal static partial Regex LeadingVersionPrefixRegex();

    [GeneratedRegex(@"^[vV](?:\.\s*|\s+|(?=\d))", RegexOptions.CultureInvariant)]
    internal static partial Regex LeadingVPrefixRegex();

    [GeneratedRegex(@"\b(?:beta|alpha|pre-?release|engineering\s+sample|test\s+bios)\b", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    internal static partial Regex BetaTokenRegex();

    [GeneratedRegex(@"\A[1-9]\d{0,2}(?:,\d{3})+\z", RegexOptions.CultureInvariant)]
    internal static partial Regex ThousandsGroupedIntRegex();

    [GeneratedRegex(@"^\s*([1-9][0-9]{0,2}(?:,[0-9]{3})+(?:\.[0-9]+)?|[0-9]+(?:[.,][0-9]+)?)\s*(bytes?|b|kbytes?|kb|kib|mbytes?|mb|mib|gbytes?|gb|gib)\s*$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    internal static partial Regex HumanSizeRegex();

    [GeneratedRegex(@"<br\s*/?>", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    internal static partial Regex HtmlBreakRegex();

    [GeneratedRegex(@"<[^>]+>", RegexOptions.CultureInvariant)]
    internal static partial Regex HtmlTagRegex();

    [GeneratedRegex(@"\s+", RegexOptions.CultureInvariant)]
    internal static partial Regex WhitespaceRegex();

    [GeneratedRegex(@"^([A-Za-z]+)[\.\-\s_]*(\d+(?:\.\d+)*)$", RegexOptions.CultureInvariant)]
    internal static partial Regex PrefixNumericRegex();

    [GeneratedRegex(@"\d+", RegexOptions.CultureInvariant)]
    internal static partial Regex DigitRunsRegex();

    [GeneratedRegex(@"\{(?:model|product|board)\}", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    internal static partial Regex EndpointPlaceholderRegex();

    internal static char ToAsciiUpper(char c) => c is >= 'a' and <= 'z' ? (char)(c - 32) : c;

    internal static string BuildBijectiveSkeleton(string value)
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

    internal static bool IsDottedNumeric(string value)
    {
        var parts = value.Split('.');
        return parts.Length > 0 && parts.All(p => p.Length > 0 && p.All(char.IsAsciiDigit));
    }

    internal static bool TryParseDottedInt64(string dotted, out long[] segments)
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

    internal static int CompareNumericSegmentArrays(long[] a, long[] b)
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

    internal static int CompareFixedLengthArrays(long[] a, long[] b)
    {
        var len = Math.Min(a.Length, b.Length);
        for (var i = 0; i < len; i++)
        {
            if (a[i] != b[i])
                return a[i].CompareTo(b[i]);
        }

        return a.Length.CompareTo(b.Length);
    }

    internal static int CompareNullableDateDescending(DateOnly? a, DateOnly? b)
    {
        if (a.HasValue && b.HasValue)
            return b.Value.CompareTo(a.Value);
        if (b.HasValue)
            return 1;
        if (a.HasValue)
            return -1;
        return 0;
    }

    internal static int CompareNullableLongDescending(long? a, long? b)
    {
        if (a.HasValue && b.HasValue)
            return b.Value.CompareTo(a.Value);
        if (b.HasValue)
            return 1;
        if (a.HasValue)
            return -1;
        return 0;
    }

    internal static bool TryResolveModelIdentifier(BiosSystemIdentity system, out string resolved, out string reason)
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

    internal static SmbiosTokenStatus ClassifyModelToken(string? raw, out string token, HashSet<string>? placeholderTokens = null)
    {
        token = "";
        if (string.IsNullOrWhiteSpace(raw))
            return SmbiosTokenStatus.EmptyOrPlaceholder;

        var trimmed = raw.Trim();
        if ((placeholderTokens ?? PlaceholderTokens).Contains(trimmed))
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

    internal static bool HasAnyAsciiLetterOrDigit(string value)
    {
        foreach (var c in value)
        {
            if (char.IsAsciiLetterOrDigit(c))
                return true;
        }

        return false;
    }

    internal static string BuildCatalogUrl(
        string endpointTemplate,
        string modelToken,
        Regex? placeholderRegex = null,
        string fallbackQueryParam = "model")
    {
        var escaped = Uri.EscapeDataString(modelToken);
        var regex = placeholderRegex ?? EndpointPlaceholderRegex();
        if (regex.IsMatch(endpointTemplate))
            return regex.Replace(endpointTemplate, escaped);

        var fragIdx = endpointTemplate.IndexOf('#');
        var basePart = fragIdx >= 0 ? endpointTemplate[..fragIdx] : endpointTemplate;
        var sep = basePart.Contains('?', StringComparison.Ordinal) ? "&" : "?";
        return $"{basePart}{sep}{fallbackQueryParam}={escaped}";
    }

    internal static bool IsNonBiosCategory(string category, string[]? categoryKeywords = null)
    {
        var trimmed = category.Trim();
        if (trimmed.Length == 0)
            return false;

        if (ContainsAnyKeyword(trimmed, categoryKeywords ?? NonBiosCategoryKeywords))
            return true;

        return !trimmed.Contains("bios", StringComparison.OrdinalIgnoreCase)
               && !trimmed.Contains("uefi", StringComparison.OrdinalIgnoreCase)
               && !trimmed.Contains("system firmware", StringComparison.OrdinalIgnoreCase);
    }

    internal static bool IsNonBiosEntry(
        string? category,
        string? title,
        string[]? alwaysRejectTitleKeywords = null,
        string[]? categoryKeywords = null)
    {
        var catKeywords = categoryKeywords ?? NonBiosCategoryKeywords;
        var hasExplicitBiosCategory = !string.IsNullOrWhiteSpace(category);
        if (hasExplicitBiosCategory && IsNonBiosCategory(category!, catKeywords))
            return true;

        if (!string.IsNullOrWhiteSpace(title))
        {
            if (ContainsAnyKeyword(title, alwaysRejectTitleKeywords ?? NonBiosTitleAlwaysRejectKeywords))
                return true;

            if (!hasExplicitBiosCategory)
            {
                var looksLikeBiosTitle = title.Contains("bios", StringComparison.OrdinalIgnoreCase)
                                         || title.Contains("uefi", StringComparison.OrdinalIgnoreCase)
                                         || title.Contains("system firmware", StringComparison.OrdinalIgnoreCase);
                if (!looksLikeBiosTitle && ContainsAnyKeyword(title, catKeywords))
                    return true;
            }
        }

        return false;
    }

    internal static bool ContainsAnyKeyword(string text, string[] keywords)
    {
        foreach (var keyword in keywords)
        {
            if (MatchesKeywordPhrase(text, keyword))
                return true;
        }

        return false;
    }

    internal static bool MatchesKeywordPhrase(string text, string phrase)
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

    internal static bool IsBetaRelease(
        string? version,
        string? title,
        string? description,
        bool? isReleaseFlag,
        bool? isBetaFlag,
        Regex? betaTokenRegex = null)
    {
        if (isBetaFlag == true || isReleaseFlag == false)
            return true;

        var regex = betaTokenRegex ?? BetaTokenRegex();
        if (!string.IsNullOrWhiteSpace(version) && regex.IsMatch(version))
            return true;

        if (!string.IsNullOrWhiteSpace(title) && regex.IsMatch(title))
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

    internal static bool TryGetPropertyIgnoreCase(JsonElement obj, out JsonElement value, params string[] names)
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

    internal static string? GetStringOrNumber(JsonElement obj, params string[] names)
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

    internal static bool? ParseNullableBoolString(string? raw)
    {
        var s = raw?.Trim();
        if (string.IsNullOrEmpty(s))
            return null;
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

    internal static bool? GetNullableBool(JsonElement obj, params string[] names)
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

    internal static long? TryParseSizeBytes(JsonElement obj, params string[] names)
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

    internal static long? TryParseSizeString(string? rawInput)
    {
        const long maxPlausibleBytes = 10L * 1024 * 1024 * 1024;
        var raw = rawInput?.Trim();
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

    internal static string? TryNormalizeSha256(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        var trimmed = raw.Trim();
        return Sha256Regex().IsMatch(trimmed) ? trimmed.ToLowerInvariant() : null;
    }

    internal static long? TryParsePositiveLong(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;
        return long.TryParse(raw.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) && n > 0
            ? n
            : null;
    }

    internal static string? FirstNonEmpty(params string?[] values)
    {
        foreach (var v in values)
        {
            if (!string.IsNullOrWhiteSpace(v))
                return v.Trim();
        }
        return null;
    }

    internal static XElement? FindChild(XElement parent, string localName) =>
        parent.Elements().FirstOrDefault(e => string.Equals(e.Name.LocalName, localName, StringComparison.OrdinalIgnoreCase));

    internal static string? GetAttribute(XElement element, string localName) =>
        element.Attributes().FirstOrDefault(a => string.Equals(a.Name.LocalName, localName, StringComparison.OrdinalIgnoreCase))?.Value?.Trim();

    internal static string? GetChildValue(XElement parent, string localName)
    {
        var val = FindChild(parent, localName)?.Value?.Trim();
        return string.IsNullOrWhiteSpace(val) ? null : val;
    }

    internal static DateOnly? TryParseReleaseDate(string? raw)
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

    internal static BiosUpdateSeverity ParseSeverity(string? rawSeverity, bool? isCritical, string? title, string? description)
    {
        if (isCritical == true)
            return BiosUpdateSeverity.Critical;

        if (!string.IsNullOrWhiteSpace(rawSeverity))
        {
            var s = rawSeverity.Trim();
            if (s.Contains("critical", StringComparison.OrdinalIgnoreCase)
                || s.Contains("high", StringComparison.OrdinalIgnoreCase)
                || s.Contains("urgent", StringComparison.OrdinalIgnoreCase)
                || s.Contains("security", StringComparison.OrdinalIgnoreCase)
                || string.Equals(s, "1", StringComparison.Ordinal))
                return BiosUpdateSeverity.Critical;

            if (s.Contains("optional", StringComparison.OrdinalIgnoreCase)
                || s.Contains("low", StringComparison.OrdinalIgnoreCase)
                || s.Contains("routine", StringComparison.OrdinalIgnoreCase)
                || string.Equals(s, "3", StringComparison.Ordinal))
                return BiosUpdateSeverity.Optional;

            if (s.Contains("recommended", StringComparison.OrdinalIgnoreCase)
                || s.Contains("medium", StringComparison.OrdinalIgnoreCase)
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

    internal static string? CleanReleaseSummary(string? title, string? description, int maxLength = DefaultMaxSummaryLength)
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

        return text.Length <= maxLength ? text : text[..maxLength].TrimEnd();
    }

    internal static BiosLatestInfo RedactLatestInfo(BiosLatestInfo info, string? serialNumber)
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

    internal static Dictionary<string, string> RedactMetadata(Dictionary<string, string> metadata, string? serialNumber)
    {
        if (string.IsNullOrWhiteSpace(serialNumber) || metadata.Count == 0)
            return metadata;

        var result = new Dictionary<string, string>(metadata.Count, StringComparer.OrdinalIgnoreCase);
        foreach (var kv in metadata)
            result[kv.Key] = RedactText(kv.Value, serialNumber);
        return result;
    }

    internal static string RedactText(string value, string? serialNumber)
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

    internal static bool ContainsSerialInUrl(string? url, string secret)
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

    internal static BiosCurrentInfo BuildRedactedCurrentInfo(
        BiosCurrentInfo current,
        string providerId,
        string normalizedVersion,
        string? modelToken,
        string? serialNumber,
        string? familyOverride = null,
        Action<Dictionary<string, string>>? enrichMetadata = null)
    {
        var metadata = current.Metadata is not null
            ? new Dictionary<string, string>(current.Metadata, StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (!string.IsNullOrWhiteSpace(current.Version))
        {
            var rawTrimmed = current.Version.Trim();
            if (!string.Equals(rawTrimmed, normalizedVersion, StringComparison.Ordinal))
                metadata["rawVersion"] = rawTrimmed;
        }

        if (!string.IsNullOrWhiteSpace(modelToken))
            metadata["model"] = modelToken;

        enrichMetadata?.Invoke(metadata);

        var safeMetadata = RedactMetadata(metadata, serialNumber);
        return current with
        {
            Vendor = RedactText(current.Vendor ?? "", serialNumber),
            Version = RedactText(normalizedVersion, serialNumber),
            ReleaseDateRaw = RedactText(current.ReleaseDateRaw ?? "", serialNumber),
            SmbiosRevision = RedactText(current.SmbiosRevision ?? "", serialNumber),
            Family = RedactText(familyOverride ?? current.Family ?? "", serialNumber),
            ProviderId = providerId,
            Metadata = safeMetadata.Count > 0 ? safeMetadata : null,
        };
    }

    internal static BiosInstallResult CreateCheckOnlyInstallResult(BiosInstallRequest request, string installGuidanceMessage)
    {
        var serial = request.System?.SerialNumber;
        var previousVersion = request.Current?.Version is not null
            ? RedactText(request.Current.Version, serial)
            : null;
        var targetVersion = request.Target?.LatestVersion is not null
            ? RedactText(request.Target.LatestVersion, serial)
            : null;
        var message = RedactText(installGuidanceMessage, serial);

        return BiosInstallResult.Unsupported(message, previousVersion, targetVersion);
    }

    internal static UrlExtractionState ExtractStringDownloadUrl(
        JsonElement item,
        IReadOnlyList<string> allowedHostSuffixes,
        out string? validatedUrl,
        params string[] propertyNames)
    {
        validatedUrl = null;

        if (!TryGetPropertyIgnoreCase(item, out var dlEl, propertyNames))
            return UrlExtractionState.Absent;

        if (dlEl.ValueKind != JsonValueKind.String)
            return UrlExtractionState.Untrusted;

        var raw = dlEl.GetString()?.Trim();
        if (string.IsNullOrWhiteSpace(raw))
            return UrlExtractionState.Absent;

        if (BiosProviderHttp.TryValidateVendorUrl(raw, allowedHostSuffixes, out var validUri))
        {
            validatedUrl = validUri.AbsoluteUri;
            return UrlExtractionState.Valid;
        }

        return UrlExtractionState.Untrusted;
    }

    internal static int CompareCandidateTieBreakers(
        DateOnly? aDate,
        DateOnly? bDate,
        string aDisplayVersion,
        string bDisplayVersion,
        string? aDownloadUrl,
        string? bDownloadUrl,
        string? aPackageId,
        string? bPackageId,
        string? aSha256,
        string? bSha256,
        string? aReleaseNotesUrl,
        string? bReleaseNotesUrl,
        string? aReleaseSummary,
        string? bReleaseSummary,
        long? aSizeBytes,
        long? bSizeBytes,
        BiosUpdateSeverity aSeverity,
        BiosUpdateSeverity bSeverity)
    {
        var dateCmp = CompareNullableDateDescending(aDate, bDate);
        if (dateCmp != 0)
            return dateCmp;

        var rawCmp = StringComparer.OrdinalIgnoreCase.Compare(aDisplayVersion, bDisplayVersion);
        if (rawCmp != 0)
            return rawCmp;

        rawCmp = StringComparer.Ordinal.Compare(aDisplayVersion, bDisplayVersion);
        if (rawCmp != 0)
            return rawCmp;

        var aHasUrl = !string.IsNullOrEmpty(aDownloadUrl);
        var bHasUrl = !string.IsNullOrEmpty(bDownloadUrl);
        if (aHasUrl != bHasUrl)
            return bHasUrl.CompareTo(aHasUrl);

        var urlCmp = StringComparer.OrdinalIgnoreCase.Compare(aDownloadUrl ?? "", bDownloadUrl ?? "");
        if (urlCmp != 0)
            return urlCmp;

        urlCmp = StringComparer.Ordinal.Compare(aDownloadUrl ?? "", bDownloadUrl ?? "");
        if (urlCmp != 0)
            return urlCmp;

        var pkgCmp = StringComparer.OrdinalIgnoreCase.Compare(aPackageId ?? "", bPackageId ?? "");
        if (pkgCmp != 0)
            return pkgCmp;

        pkgCmp = StringComparer.Ordinal.Compare(aPackageId ?? "", bPackageId ?? "");
        if (pkgCmp != 0)
            return pkgCmp;

        var shaCmp = StringComparer.OrdinalIgnoreCase.Compare(aSha256 ?? "", bSha256 ?? "");
        if (shaCmp != 0)
            return shaCmp;

        shaCmp = StringComparer.Ordinal.Compare(aSha256 ?? "", bSha256 ?? "");
        if (shaCmp != 0)
            return shaCmp;

        var notesCmp = StringComparer.OrdinalIgnoreCase.Compare(aReleaseNotesUrl ?? "", bReleaseNotesUrl ?? "");
        if (notesCmp != 0)
            return notesCmp;

        notesCmp = StringComparer.Ordinal.Compare(aReleaseNotesUrl ?? "", bReleaseNotesUrl ?? "");
        if (notesCmp != 0)
            return notesCmp;

        var summaryCmp = StringComparer.Ordinal.Compare(aReleaseSummary ?? "", bReleaseSummary ?? "");
        if (summaryCmp != 0)
            return summaryCmp;

        var sizeCmp = CompareNullableLongDescending(aSizeBytes, bSizeBytes);
        if (sizeCmp != 0)
            return sizeCmp;

        return bSeverity.CompareTo(aSeverity);
    }

    internal static List<TCandidate> OrderCandidates<TCandidate>(
        IReadOnlyList<TCandidate> candidates,
        Func<TCandidate, int> getPrefRank,
        Func<TCandidate, string> getClassKey,
        Func<TCandidate, DateOnly?> getReleaseDate,
        Func<TCandidate, TCandidate, int> compareWithinClass,
        Func<TCandidate, TCandidate, int> compareTieBreakers,
        bool comparePrefRankFirst = false,
        bool prefRankDescending = false)
    {
        var bucketMaxDates = new Dictionary<(int PrefRank, string ClassKey), DateOnly?>(BucketKeyComparer);

        foreach (var candidate in candidates)
        {
            var bucketKey = (getPrefRank(candidate), getClassKey(candidate));
            var releaseDate = getReleaseDate(candidate);
            if (!bucketMaxDates.TryGetValue(bucketKey, out var existingMax)
                || (releaseDate.HasValue && (!existingMax.HasValue || releaseDate.Value > existingMax.Value)))
            {
                bucketMaxDates[bucketKey] = releaseDate;
            }
        }

        var ordered = new List<TCandidate>(candidates);
        ordered.Sort((a, b) =>
        {
            var aPref = getPrefRank(a);
            var bPref = getPrefRank(b);
            if (comparePrefRankFirst && aPref != bPref)
                return prefRankDescending ? bPref.CompareTo(aPref) : aPref.CompareTo(bPref);

            var aClassKey = getClassKey(a);
            var bClassKey = getClassKey(b);

            var bucketDateCmp = CompareNullableDateDescending(
                bucketMaxDates[(aPref, aClassKey)],
                bucketMaxDates[(bPref, bClassKey)]);
            if (bucketDateCmp != 0)
                return bucketDateCmp;

            var classCmp = StringComparer.OrdinalIgnoreCase.Compare(aClassKey, bClassKey);
            if (classCmp != 0)
                return classCmp;

            var verCmp = compareWithinClass(b, a);
            if (verCmp != 0)
                return verCmp;

            return compareTieBreakers(a, b);
        });

        return ordered;
    }

    internal static int FindFirstNonWhitespaceByte(byte[] bytes, int offset, int length)
    {
        var end = offset + length;
        for (var i = offset; i < end; i++)
        {
            if (bytes[i] is not ((byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n'))
                return i;
        }

        return -1;
    }

    internal static string BuildSafePackageFileName(string url, string defaultFileName, string requiredExtension)
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

    internal static BiosInstallResult RedactInstallResult(BiosInstallResult result, string? serialNumber)
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

    internal sealed class RedactingLogger(ILogger inner, string? serialNumber) : ILogger
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

    internal sealed class RedactingProgress(IProgress<BiosInstallProgress> inner, string? serialNumber) : IProgress<BiosInstallProgress>
    {
        public void Report(BiosInstallProgress value)
        {
            if (value is null)
                return;

            var safeDetail = RedactText(value.Detail ?? "", serialNumber);
            inner.Report(ReferenceEquals(safeDetail, value.Detail) ? value : value with { Detail = safeDetail });
        }
    }

    internal sealed class BucketKeyEqualityComparer : IEqualityComparer<(int PrefRank, string ClassKey)>
    {
        public bool Equals((int PrefRank, string ClassKey) x, (int PrefRank, string ClassKey) y) =>
            x.PrefRank == y.PrefRank
            && StringComparer.OrdinalIgnoreCase.Equals(x.ClassKey, y.ClassKey);

        public int GetHashCode((int PrefRank, string ClassKey) obj) =>
            HashCode.Combine(obj.PrefRank, StringComparer.OrdinalIgnoreCase.GetHashCode(obj.ClassKey));
    }
}
