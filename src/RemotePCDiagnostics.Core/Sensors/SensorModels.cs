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
}

/// <summary>Result of one provider read.</summary>
public sealed record SensorSnapshot(IReadOnlyList<SensorReading> Readings, bool IsElevated, string? Note = null);

/// <summary>Reading plus its threshold evaluation.</summary>
public sealed record EvaluatedReading(SensorReading Reading, SensorLevel Level, SensorThreshold? Threshold);

/// <summary>Summary group shown as one card on the page.</summary>
public sealed record SensorGroup(string Id, string Title, IReadOnlyList<EvaluatedReading> Readings)
{
    public SensorLevel Level => Readings.Count == 0 ? SensorLevel.Neutral : Readings.Max(r => r.Level);
    public double? Hottest => Readings.Select(r => r.Reading.Value).Where(v => v.HasValue).DefaultIfEmpty().Max();
}

public sealed record SensorReport(SensorSnapshot Snapshot, IReadOnlyList<SensorGroup> Groups)
{
    public SensorLevel Level => Groups.Count == 0 ? SensorLevel.Neutral : Groups.Max(g => g.Level);
}
