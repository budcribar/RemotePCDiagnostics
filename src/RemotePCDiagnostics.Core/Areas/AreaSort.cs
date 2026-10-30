using System.Globalization;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>Reusable sort for drawer tables: uses <see cref="AreaRow.SortKeys"/> when given (e.g. ISO time), numbers numerically, else text.</summary>
public static class AreaSort
{
    public static string KeyOf(AreaRow r, int col) =>
        r.SortKeys is { } k && col < k.Count && k[col] is { } s ? s : col < r.Values.Count ? r.Values[col] : "";

    public static int Compare(string a, string b) =>
        double.TryParse(a, NumberStyles.Float, CultureInfo.InvariantCulture, out var x) && double.TryParse(b, NumberStyles.Float, CultureInfo.InvariantCulture, out var y)
            ? x.CompareTo(y) : string.Compare(a, b, StringComparison.OrdinalIgnoreCase);

    /// <summary>Stable sort; col &lt; 0 keeps the original order.</summary>
    public static IReadOnlyList<AreaRow> Sort(IReadOnlyList<AreaRow> rows, int col, bool descending)
    {
        if (col < 0) return rows;
        var idx = rows.Select((r, i) => (r, i)).ToList();
        idx.Sort((p, q) =>
        {
            var c = Compare(KeyOf(p.r, col), KeyOf(q.r, col));
            if (descending) c = -c;
            return c != 0 ? c : p.i.CompareTo(q.i);
        });
        return idx.Select(p => p.r).ToList();
    }

    /// <summary>Default: newest first when a table is pre-sorted by time ("When"/"Last seen"/"Last time", or Windows updates "Installed"), else original order.</summary>
    public static (int Col, bool Desc) Default(IReadOnlyList<string> columns)
    {
        for (var i = 0; i < columns.Count; i++)
            if (columns[i] is "When" or "Last seen" or "Last time" || (columns[i] == "Installed" && columns[0] == "Update")) return (i, true);
        return (-1, false);
    }

    public static string TimeKey(DateTimeOffset t) => t.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss", CultureInfo.InvariantCulture);
}
