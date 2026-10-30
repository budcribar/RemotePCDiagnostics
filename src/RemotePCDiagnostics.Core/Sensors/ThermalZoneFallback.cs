namespace RemotePCDiagnostics.Core.Sensors;

/// <summary>Reads raw ACPI thermal zone values (tenths of Kelvin), e.g. WMI MSAcpi_ThermalZoneTemperature.</summary>
public interface IThermalZoneReader
{
    IReadOnlyList<double> ReadTenthsKelvin();
}

/// <summary>
/// Fallback when the hardware library exposes no usable CPU temperature (e.g. some Ryzen laptops report 0 °C):
/// add one approximate reading from the ACPI thermal zone. Never used when a real CPU sensor has data.
/// It has no alert threshold, so it never triggers a critical-temperature abort.
/// </summary>
public static class ThermalZoneFallback
{
    public const string HardwareName = "ACPI thermal zone";
    public const string SensorName = "Thermal zone (approximate)";
    public const string FriendlyLabel = "CPU/system temperature (approximate)";

    /// <summary>Converts tenths of Kelvin to °C; null when implausible (≤ 5 °C or ≥ 125 °C, incl. 0).</summary>
    public static double? ToCelsius(double tenthsKelvin)
    {
        if (double.IsNaN(tenthsKelvin) || tenthsKelvin <= 0) return null;
        var c = Math.Round(tenthsKelvin / 10.0 - 273.15, 1);
        return c is > 5 and < 125 ? c : null;
    }

    public static List<SensorReading> Apply(IReadOnlyList<SensorReading> readings, IThermalZoneReader? zones, Action<string>? log = null)
    {
        var list = readings.ToList();
        if (zones is null || list.Any(r => r.SensorType == SensorKind.Temperature && r.HardwareType == HardwareKind.Cpu && r.IsLive)) return list;
        IReadOnlyList<double> raw;
        try { raw = zones.ReadTenthsKelvin(); }
        catch (Exception ex) { log?.Invoke($"Thermal zone fallback failed: {ex.Message}"); return list; }
        var best = raw.Select(ToCelsius).Where(v => v.HasValue).DefaultIfEmpty().Max();
        log?.Invoke($"Thermal zone fallback: raw=[{string.Join(", ", raw)}] used={(best?.ToString("0.0") ?? "none")}");
        if (best is { } v) list.Add(new SensorReading(HardwareName, HardwareKind.Cpu, SensorName, SensorKind.Temperature, v, null, null, "°C"));
        return list;
    }
}
