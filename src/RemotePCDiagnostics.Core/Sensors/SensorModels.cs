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

    /// <summary>Drive-reported thresholds (e.g. NVMe "Warning/Critical Temperature"): limits, not live readings.</summary>
    public bool IsLimit => SensorType == SensorKind.Temperature &&
        (SensorName.Contains("Warning Temperature", StringComparison.OrdinalIgnoreCase) || SensorName.Contains("Critical Temperature", StringComparison.OrdinalIgnoreCase));

    /// <summary>A usable live reading (has data and is not a reported limit).</summary>
    public bool IsLive => HasData && !IsLimit;

    /// <summary>True for the ACPI thermal-zone fallback reading (not a real CPU sensor).</summary>
    public bool IsApproximate => (HardwareName == ThermalZoneFallback.HardwareName && SensorName == ThermalZoneFallback.SensorName)
        || (HardwareType == HardwareKind.Cpu && SensorName == CpuTemperatureFallback.ApuSensorName);

    /// <summary>True for the GPU temperature read through Windows (driver value, not approximate) when LHM had none.</summary>
    public bool IsFromWindows => HardwareType == HardwareKind.Gpu && SensorName == GpuTemperatureFallback.SensorName;

    public string DeviceType => HardwareType switch
    {
        HardwareKind.Cpu => "CPU", HardwareKind.Gpu => "Graphics", HardwareKind.Storage => "Drive", HardwareKind.Memory => "Memory",
        HardwareKind.Motherboard => "Motherboard", HardwareKind.Controller => "Controller", _ => "Device",
    };

    /// <summary>Friendly device label, e.g. "Drive: SAMSUNG MZAL8512HDLU".</summary>
    public string FriendlyDevice => IsApproximate ? "Windows (approximate)" : $"{DeviceType}: {HardwareName}";

    /// <summary>Plain-language sensor label; raw name stays available via SensorName.</summary>
    public string FriendlyName
    {
        get
        {
            var n = SensorName.Trim();
            if (IsApproximate) return SensorName == CpuTemperatureFallback.ApuSensorName ? CpuTemperatureFallback.ApuFriendlyLabel : ThermalZoneFallback.FriendlyLabel;
            if (IsFromWindows) return GpuTemperatureFallback.SensorName;
            if (HardwareName == EcFanMonitor.HardwareName && SensorType == SensorKind.Fan) return SensorName; // "CPU fan (from laptop controller)"
            var num = System.Text.RegularExpressions.Regex.Match(n, @"#\s*(\d+)");
            if (SensorType == SensorKind.Fan) return num.Success ? $"Fan {num.Groups[1].Value} speed" : n.Contains("fan", StringComparison.OrdinalIgnoreCase) ? n + " speed" : $"Fan speed ({n})";
            switch (HardwareType)
            {
                case HardwareKind.Storage:
                    if (n.Contains("Warning Temperature", StringComparison.OrdinalIgnoreCase)) return "Drive warning limit";
                    if (n.Contains("Critical Temperature", StringComparison.OrdinalIgnoreCase)) return "Drive critical limit";
                    if (n.StartsWith("Composite", StringComparison.OrdinalIgnoreCase)) return "Drive temperature (overall)";
                    if (num.Success) return $"Drive temperature, sensor {num.Groups[1].Value}";
                    if (n.Equals("Temperature", StringComparison.OrdinalIgnoreCase)) return "Drive temperature";
                    break;
                case HardwareKind.Cpu:
                    if (n.Contains("Tctl", StringComparison.OrdinalIgnoreCase) || n.Equals("Core (Tdie)", StringComparison.OrdinalIgnoreCase)) return "CPU temperature (overall)";
                    if (n.Equals("CPU Package", StringComparison.OrdinalIgnoreCase) || n.Equals("Package", StringComparison.OrdinalIgnoreCase)) return "CPU temperature (whole chip)";
                    if (n.StartsWith("Core Max", StringComparison.OrdinalIgnoreCase)) return "Hottest CPU core";
                    if (n.StartsWith("Core Average", StringComparison.OrdinalIgnoreCase)) return "Average CPU core";
                    if (n.StartsWith("CPU Core #", StringComparison.OrdinalIgnoreCase) && num.Success) return $"CPU core {num.Groups[1].Value}";
                    if (n.StartsWith("CCD", StringComparison.OrdinalIgnoreCase)) return $"CPU core cluster {n[3..].Trim(' ', '(', ')')}".Trim();
                    if (n.Contains("SoC", StringComparison.OrdinalIgnoreCase)) return "CPU built-in graphics/chipset";
                    break;
                case HardwareKind.Gpu:
                    if (n.Equals("GPU Core", StringComparison.OrdinalIgnoreCase)) return "Graphics chip temperature";
                    if (n.Contains("Hot Spot", StringComparison.OrdinalIgnoreCase)) return "Graphics hottest spot";
                    if (n.Contains("Memory", StringComparison.OrdinalIgnoreCase)) return "Graphics memory temperature";
                    break;
                case HardwareKind.Memory:
                    return num.Success ? $"Memory module {num.Groups[1].Value} temperature" : "Memory temperature";
                case HardwareKind.Motherboard or HardwareKind.Controller or HardwareKind.Other:
                    if (num.Success && n.StartsWith("Temperature", StringComparison.OrdinalIgnoreCase)) return $"Board temperature, sensor {num.Groups[1].Value}";
                    break;
            }
            return n;
        }
    }

    /// <summary>Drops readings without usable data (see <see cref="HasData"/>).</summary>
    public static List<SensorReading> OnlyWithData(IEnumerable<SensorReading> readings) => readings.Where(r => r.HasData).ToList();
}

/// <summary>Result of one provider read.</summary>
public sealed record SensorSnapshot(IReadOnlyList<SensorReading> Readings, bool IsElevated, string? Note = null, string? CpuNote = null);

/// <summary>Reading plus its threshold evaluation.</summary>
public sealed record EvaluatedReading(SensorReading Reading, SensorLevel Level, SensorThreshold? Threshold);

/// <summary>Summary group shown as one card on the page.</summary>
public sealed record SensorGroup(string Id, string Title, IReadOnlyList<EvaluatedReading> Readings, string MissingLabel = "")
{
    public SensorLevel Level => Readings.Count == 0 ? SensorLevel.Neutral : Readings.Max(r => r.Level);
    public double? Hottest => Readings.Where(r => !r.Reading.IsLimit).Select(r => r.Reading.Value).Where(v => v.HasValue).DefaultIfEmpty().Max();
}

public sealed record SensorReport(SensorSnapshot Snapshot, IReadOnlyList<SensorGroup> Groups)
{
    /// <summary>Compact fingerprint of what the page shows; equal fingerprints mean nothing visible changed.</summary>
    public static string Signature(string status, string? message, SensorReport? report)
    {
        var sb = new System.Text.StringBuilder(status).Append('|').Append(message);
        if (report is not null)
            foreach (var r in report.Snapshot.Readings)
                sb.Append('|').Append(r.HardwareName).Append('/').Append(r.SensorName).Append('=')
                  .Append(r.Value?.ToString("0.0")).Append(',').Append(r.Min?.ToString("0.0")).Append(',').Append(r.Max?.ToString("0.0"));
        return sb.ToString();
    }

    /// <summary>Groups with at least one reading; empty groups are hidden on the page.</summary>
    public IReadOnlyList<SensorGroup> VisibleGroups => Groups.Where(g => g.Readings.Count > 0).ToList();

    /// <summary>Friendly line listing groups this PC doesn't report, or null when none (or all) are missing.</summary>
    public string? MissingText
    {
        get
        {
            // Fans with no reading are simply hidden (many PCs don't report fans), not listed as missing.
            var missing = Groups.Where(g => g.Readings.Count == 0 && g.Id != "fans").Select(g => g.MissingLabel).ToList();
            return missing.Count == 0 || missing.Count == Groups.Count(g => g.Id != "fans") ? null : "Not reported by this PC: " + string.Join(", ", missing);
        }
    }

    public SensorLevel Level => Groups.Count == 0 ? SensorLevel.Neutral : Groups.Max(g => g.Level);
}
