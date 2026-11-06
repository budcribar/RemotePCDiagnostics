using System.Globalization;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>The date formats osquery and Windows report (install dates, driver dates, hotfixes), shared by the modules that show them.</summary>
public static class OsqueryDates
{
    private static readonly string[] DateFormats = ["yyyyMMdd", "M/d/yyyy", "MM/dd/yyyy", "yyyy-MM-dd", "M/d/yyyy h:mm:ss tt", "yyyy-MM-dd HH:mm:ss"];

    public static DateOnly? Parse(string s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        s = s.Trim();
        if (DateTime.TryParseExact(s, DateFormats, CultureInfo.InvariantCulture, DateTimeStyles.None, out var d)) return DateOnly.FromDateTime(d);
        // os_version.install_date is Unix seconds.
        if (s.Length is 9 or 10 && long.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out var unix))
            return DateOnly.FromDateTime(DateTimeOffset.FromUnixTimeSeconds(unix).UtcDateTime);
        // Some patches report a hex FILETIME (e.g. "01d9a2b3c4d5e6f7").
        if (s.Length == 16 && long.TryParse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var ft))
        {
            try { return DateOnly.FromDateTime(DateTime.FromFileTimeUtc(ft)); } catch (ArgumentOutOfRangeException) { }
        }
        return null;
    }

    public static string Format(DateOnly? d) => d?.ToString("d MMM yyyy", CultureInfo.InvariantCulture) ?? "";
    public static string SortKey(DateOnly? d) => d?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) ?? "";
}
