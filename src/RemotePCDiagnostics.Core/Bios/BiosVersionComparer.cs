using System.Globalization;
using System.Text.RegularExpressions;

namespace RemotePCDiagnostics.Core.Bios;

/// <summary>
/// Shared helper for comparing BIOS version strings across common vendor formats
/// (dotted numeric like <c>1.14.0</c>, HP letter-prefixed like <c>F.24</c>, Dell <c>A12</c>, or release dates).
/// Vendor providers may use this directly or apply vendor-specific rules when versions are non-standard.
/// </summary>
public static partial class BiosVersionComparer
{
    [GeneratedRegex(@"\d+", RegexOptions.CultureInvariant)]
    private static partial Regex DigitRunsRegex();

    [GeneratedRegex(@"^([A-Za-z]+)[\.\-\s_]*(\d+(?:\.\d+)*)$", RegexOptions.CultureInvariant)]
    private static partial Regex PrefixNumericRegex();

    /// <summary>
    /// Returns <c>true</c> when <paramref name="latestVersion"/> (or <paramref name="latestDate"/>) is strictly newer than
    /// <paramref name="currentVersion"/> (or <paramref name="currentDate"/>).
    /// </summary>
    public static bool IsNewer(string? currentVersion, string? latestVersion, DateOnly? currentDate = null, DateOnly? latestDate = null)
    {
        var cmp = Compare(currentVersion, latestVersion);
        if (cmp.HasValue)
            return cmp.Value < 0;

        if (currentDate.HasValue && latestDate.HasValue)
            return latestDate.Value > currentDate.Value;

        return false;
    }

    /// <summary>
    /// Compares two BIOS version strings. Returns negative if <paramref name="a"/> &lt; <paramref name="b"/>,
    /// zero if equal, positive if <paramref name="a"/> &gt; <paramref name="b"/>, or <c>null</c> if incomparable.
    /// </summary>
    public static int? Compare(string? a, string? b)
    {
        var left = Normalize(a);
        var right = Normalize(b);
        if (left.Length == 0 || right.Length == 0)
            return null;
        if (string.Equals(left, right, StringComparison.OrdinalIgnoreCase))
            return 0;

        // Same letter prefix followed by numeric version (e.g. HP "F.8" vs "F.24", Dell "A09" vs "A12").
        var lm = PrefixNumericRegex().Match(left);
        var rm = PrefixNumericRegex().Match(right);
        if (lm.Success && rm.Success)
        {
            if (!string.Equals(lm.Groups[1].Value, rm.Groups[1].Value, StringComparison.OrdinalIgnoreCase))
                return null; // Different BIOS families/branches (e.g. "F.10" vs "P.10") are not directly comparable.
            return CompareNumericSegments(lm.Groups[2].Value, rm.Groups[2].Value);
        }

        // Pure dotted numeric versions (e.g. "01.09.00" vs "01.14.00", "1.9" vs "1.14.1").
        if (IsDottedNumeric(left) && IsDottedNumeric(right))
            return CompareNumericSegments(left, right);

        // Fallback: if both share an identical non-digit prefix and only differ in digit runs (e.g. "N32ET89W" vs "N32ET91W").
        var leftSkeleton = DigitRunsRegex().Replace(left, "#");
        var rightSkeleton = DigitRunsRegex().Replace(right, "#");
        if (string.Equals(leftSkeleton, rightSkeleton, StringComparison.OrdinalIgnoreCase))
        {
            var leftNums = DigitRunsRegex().Matches(left);
            var rightNums = DigitRunsRegex().Matches(right);
            if (leftNums.Count > 0 && leftNums.Count == rightNums.Count)
            {
                for (var i = 0; i < leftNums.Count; i++)
                {
                    if (long.TryParse(leftNums[i].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var ln)
                        && long.TryParse(rightNums[i].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var rn)
                        && ln != rn)
                    {
                        return ln.CompareTo(rn);
                    }
                }
                return 0;
            }
        }

        return null;
    }

    /// <summary>Parses common SMBIOS / vendor BIOS release dates (<c>MM/dd/yyyy</c>, <c>yyyy-MM-dd</c>, <c>yyyyMMdd</c>).</summary>
    public static DateOnly? TryParseReleaseDate(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;
        var trimmed = raw.Trim();
        string[] formats = ["yyyy-MM-dd", "MM/dd/yyyy", "M/d/yyyy", "yyyy/MM/dd", "yyyyMMdd", "dd/MM/yyyy"];
        if (DateOnly.TryParseExact(trimmed, formats, CultureInfo.InvariantCulture, DateTimeStyles.None, out var exact))
            return exact;
        if (DateOnly.TryParse(trimmed, CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed))
            return parsed;
        return null;
    }

    private static string Normalize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return "";
        var trimmed = value.Trim();
        if (trimmed.StartsWith("Rev.", StringComparison.OrdinalIgnoreCase))
            trimmed = trimmed[4..].Trim();
        else if (trimmed.StartsWith("v", StringComparison.OrdinalIgnoreCase) && trimmed.Length > 1 && char.IsDigit(trimmed[1]))
            trimmed = trimmed[1..].Trim();
        return trimmed;
    }

    private static bool IsDottedNumeric(string value)
    {
        var parts = value.Split('.');
        return parts.Length > 0 && parts.All(p => p.Length > 0 && p.All(char.IsAsciiDigit));
    }

    private static int CompareNumericSegments(string a, string b)
    {
        var ap = a.Split('.');
        var bp = b.Split('.');
        var count = Math.Max(ap.Length, bp.Length);
        for (var i = 0; i < count; i++)
        {
            var av = i < ap.Length && long.TryParse(ap[i], NumberStyles.None, CultureInfo.InvariantCulture, out var lv) ? lv : 0;
            var bv = i < bp.Length && long.TryParse(bp[i], NumberStyles.None, CultureInfo.InvariantCulture, out var rv) ? rv : 0;
            if (av != bv)
                return av.CompareTo(bv);
        }
        return 0;
    }
}
