using System.Globalization;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.History;

/// <summary>Rounds a stored measurement to the precision its source can really measure, so a result never claims more than the
/// hardware or the test can tell apart: temperature sensors report whole degrees, and a benchmark speed that varies by a few percent
/// between runs is not worth three decimals. <see cref="Round"/> keeps a plain invariant number (event log, CSV);
/// <see cref="Display"/> is for people (thousands separators, bytes as KB/MB/GB, seconds as minutes).</summary>
public static class MeasurementFormat
{
    private enum Kind { Text, Temperature, Bytes, Count, Seconds, Number }

    private static Kind KindOf(string name)
    {
        var n = name.Trim();
        if (n.EndsWith("TemperatureC", StringComparison.OrdinalIgnoreCase) || n.EndsWith("Temperature", StringComparison.OrdinalIgnoreCase)
            || n.StartsWith("Hottest ", StringComparison.OrdinalIgnoreCase) || n.EndsWith("Celsius", StringComparison.OrdinalIgnoreCase)) return Kind.Temperature;
        if (n.EndsWith("Bytes", StringComparison.OrdinalIgnoreCase)) return Kind.Bytes;
        if (n.EndsWith("Rpm", StringComparison.OrdinalIgnoreCase)) return Kind.Count;
        if (n.EndsWith("Seconds", StringComparison.OrdinalIgnoreCase) || n is "Ran" or "Requested" or "Duration") return Kind.Seconds;
        return Kind.Number;
    }

    /// <summary>The value rounded to its real precision, still as a plain invariant number (no separators, no unit change).
    /// Text that isn't a number comes back unchanged; a "12.3 s" duration keeps its unit.</summary>
    public static string Round(string name, string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return value ?? "";
        var (number, suffix) = Split(value);
        if (number is not { } v) return value;
        return Round(name, v) + suffix;
    }

    /// <summary>A measured number rounded to its real precision, as invariant text.</summary>
    public static string Round(string name, double value) => KindOf(name) switch
    {
        Kind.Temperature or Kind.Bytes or Kind.Count => Math.Round(value, MidpointRounding.AwayFromZero).ToString("0", CultureInfo.InvariantCulture),
        Kind.Seconds => value.ToString("0.0", CultureInfo.InvariantCulture),
        _ => Significant(value, CultureInfo.InvariantCulture, grouping: false),
    };

    /// <summary>The value as a person should read it: "67" (°C, the label carries the unit), "1,598", "1 GB", "2 min 5 s".</summary>
    public static string Display(string name, string? value, CultureInfo? culture = null)
    {
        culture ??= CultureInfo.CurrentCulture;
        if (string.IsNullOrWhiteSpace(value)) return value ?? "";
        var (number, suffix) = Split(value);
        if (number is not { } v) return value;
        var kind = KindOf(name);
        if (suffix.Trim() == "s" || kind == Kind.Seconds && suffix.Length == 0) return HistoryQuery.FormatDuration(v);
        var text = kind switch
        {
            Kind.Temperature => Math.Round(v, MidpointRounding.AwayFromZero).ToString("0", culture),
            Kind.Bytes => HardwareInventory.FormatBytes((long)Math.Round(v)),
            Kind.Count => Math.Round(v, MidpointRounding.AwayFromZero).ToString("N0", culture),
            _ => Significant(v, culture, grouping: true),
        };
        return text + suffix;
    }

    /// <summary><see cref="Display(string, string?, CultureInfo?)"/> for a number already parsed.</summary>
    public static string Display(string name, double value, CultureInfo? culture = null) =>
        Display(name, value.ToString("R", CultureInfo.InvariantCulture), culture);

    /// <summary>Whole numbers at 100 and above, then one more decimal for each step down (12.3, 1.23, 0.123): at most four
    /// significant figures, never fewer than three, and never trailing zeros.</summary>
    public static string Significant(double value, CultureInfo? culture = null, bool grouping = true)
    {
        culture ??= CultureInfo.CurrentCulture;
        if (double.IsNaN(value) || double.IsInfinity(value)) return value.ToString(culture);
        var a = Math.Abs(value);
        string format;
        if (a >= 100 || a == 0 || value == Math.Floor(value)) format = grouping ? "#,0" : "0";
        else if (a >= 10) format = "0.#";
        else if (a >= 1) format = "0.##";
        else
        {
            // Three significant figures below 1 (0.123, 0.0000123), so tiny errors and fractions still show.
            var decimals = Math.Min(15, 2 - (int)Math.Floor(Math.Log10(a)));
            format = "0." + new string('#', decimals);
        }
        return value.ToString(format, culture);
    }

    private static (double? Number, string Suffix) Split(string value)
    {
        var t = value.Trim();
        var i = t.IndexOf(' ');
        var head = i < 0 ? t : t[..i];
        var tail = i < 0 ? "" : t[i..];
        if (tail.Length > 0 && tail.Trim() is not ("s" or "%" or "ms")) return (null, "");
        return double.TryParse(head, NumberStyles.Float, CultureInfo.InvariantCulture, out var v) ? (v, tail) : (null, "");
    }
}
