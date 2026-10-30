using System.Text.Json.Serialization;

namespace RemotePCDiagnostics.Core.Sensors;

[JsonConverter(typeof(JsonStringEnumConverter<HardwareKind>))]
public enum HardwareKind { Cpu, Gpu, Motherboard, Storage, Memory, Controller, Other }

[JsonConverter(typeof(JsonStringEnumConverter<SensorKind>))]
public enum SensorKind { Temperature, Fan }

/// <summary>Neutral = no sourced threshold for this sensor (see docs/sensor-thresholds.md).</summary>
[JsonConverter(typeof(JsonStringEnumConverter<SensorLevel>))]
public enum SensorLevel { Neutral, Ok, Warning, Critical }

/// <summary>One temperature or fan reading. Value/Min/Max are null when the sensor reports no value.</summary>
public sealed record SensorReading(
    string HardwareName, HardwareKind HardwareType, string SensorName, SensorKind SensorType,
    double? Value, double? Min, double? Max, string Unit)
{
    public static string UnitFor(SensorKind k) => k == SensorKind.Temperature ? "°C" : "RPM";

    /// <summary>False when the sensor gives nothing usable: null/NaN, or a temperature of 0 °C or below
    /// (drivers report 0 for unsupported temperature sensors). A 0 RPM fan is real (fan stopped).</summary>
    public bool HasData => Value is { } v && !double.IsNaN(v) && (SensorType != SensorKind.Temperature || v > 0);

    /// <summary>Drops readings without usable data (see <see cref="HasData"/>).</summary>
    public static List<SensorReading> OnlyWithData(IEnumerable<SensorReading> readings) => readings.Where(r => r.HasData).ToList();
}

/// <summary>Result of one provider read.</summary>
public sealed record SensorSnapshot(IReadOnlyList<SensorReading> Readings, bool IsElevated, string? Note = null);

/// <summary>Reading plus its threshold evaluation.</summary>
public sealed record EvaluatedReading(SensorReading Reading, SensorLevel Level, SensorThreshold? Threshold);

/// <summary>Summary group shown as one card on the page.</summary>
public sealed record SensorGroup(string Id, string Title, IReadOnlyList<EvaluatedReading> Readings, string MissingLabel = "")
{
    public SensorLevel Level => Readings.Count == 0 ? SensorLevel.Neutral : Readings.Max(r => r.Level);
    public double? Hottest => Readings.Select(r => r.Reading.Value).Where(v => v.HasValue).DefaultIfEmpty().Max();
}

public sealed record SensorReport(SensorSnapshot Snapshot, IReadOnlyList<SensorGroup> Groups)
{
    /// <summary>Groups with at least one reading; empty groups are hidden on the page.</summary>
    public IReadOnlyList<SensorGroup> VisibleGroups => Groups.Where(g => g.Readings.Count > 0).ToList();

    /// <summary>Friendly line listing groups this PC doesn't report, or null when none (or all) are missing.</summary>
    public string? MissingText
    {
        get
        {
            var missing = Groups.Where(g => g.Readings.Count == 0).Select(g => g.MissingLabel).ToList();
            return missing.Count == 0 || missing.Count == Groups.Count ? null : "Not reported by this PC: " + string.Join(", ", missing);
        }
    }

    public SensorLevel Level => Groups.Count == 0 ? SensorLevel.Neutral : Groups.Max(g => g.Level);
}
