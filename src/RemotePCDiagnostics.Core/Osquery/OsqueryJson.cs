using System.Globalization;
using System.Text.Json;

namespace RemotePCDiagnostics.Core.Osquery;

/// <summary>Tolerant parsing of <c>osqueryi --json</c> output (an array of objects whose values are normally strings).</summary>
public static class OsqueryJson
{
    /// <exception cref="FormatException">Output is empty, not JSON, or not an array of objects.</exception>
    public static IReadOnlyList<IReadOnlyDictionary<string, string>> ParseRows(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) throw new FormatException("osqueryi returned no output.");
        JsonDocument doc;
        try { doc = JsonDocument.Parse(json); }
        catch (JsonException ex) { throw new FormatException($"osqueryi returned invalid JSON: {ex.Message}", ex); }
        using (doc)
        {
            if (doc.RootElement.ValueKind != JsonValueKind.Array)
                throw new FormatException("osqueryi returned JSON that is not an array.");
            var rows = new List<IReadOnlyDictionary<string, string>>();
            foreach (var el in doc.RootElement.EnumerateArray())
            {
                if (el.ValueKind != JsonValueKind.Object) continue;
                var row = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var prop in el.EnumerateObject())
                    row[prop.Name] = prop.Value.ValueKind switch
                    {
                        JsonValueKind.String => prop.Value.GetString() ?? "",
                        JsonValueKind.Null or JsonValueKind.Undefined => "",
                        _ => prop.Value.GetRawText(),
                    };
                rows.Add(row);
            }
            return rows;
        }
    }

    public static string Str(this IReadOnlyDictionary<string, string> row, string key) =>
        row.TryGetValue(key, out var v) ? v.Trim() : "";

    public static long? Long(this IReadOnlyDictionary<string, string> row, string key)
    {
        var s = row.Str(key);
        if (long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var l)) return l;
        if (double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) && !double.IsNaN(d) && !double.IsInfinity(d)) return (long)d;
        return null;
    }

    public static int? Int(this IReadOnlyDictionary<string, string> row, string key)
    {
        var l = row.Long(key);
        return l is >= int.MinValue and <= int.MaxValue ? (int)l.Value : null;
    }
}
