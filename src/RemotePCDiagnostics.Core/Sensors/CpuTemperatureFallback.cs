namespace RemotePCDiagnostics.Core.Sensors;

/// <summary>
/// Extra CPU temperature sources used only when the hardware library has no valid CPU temperature.
/// Order: (1) APU shared die — on AMD "with Radeon Graphics" APUs the GPU is on the same chip, so the driver's GPU
/// temperature (via Windows) is a close approximation of the chip temperature; (2) ACPI thermal zone
/// (<see cref="ThermalZoneFallback"/>, last resort). Both are flagged approximate and have no alert threshold.
/// </summary>
public static class CpuTemperatureFallback
{
    public const string ApuSensorName = "Chip temperature (approximate, from built-in graphics)";
    public const string ApuFriendlyLabel = "CPU temperature (approximate, from built-in graphics)";
    public const string DriverMissingNote = "CPU temperature needs a sensor driver that isn't available on this PC.";

    public static bool HasRealCpuTemp(IEnumerable<SensorReading> list) =>
        list.Any(r => r.SensorType == SensorKind.Temperature && r.HardwareType == HardwareKind.Cpu && r.IsLive && !r.IsApproximate);

    /// <summary>True for AMD APUs (CPU and Radeon graphics on one chip), e.g. "AMD Ryzen 7 5700U with Radeon Graphics".</summary>
    public static bool IsAmdApu(string? cpuName) => cpuName is { } n &&
        (n.Contains("AMD", StringComparison.OrdinalIgnoreCase) || n.Contains("Ryzen", StringComparison.OrdinalIgnoreCase)) &&
        n.Contains("Radeon", StringComparison.OrdinalIgnoreCase);

    public static List<SensorReading> ApplyApuDie(IReadOnlyList<SensorReading> readings, string? cpuName, Action<string>? log = null)
    {
        var list = readings.ToList();
        if (HasRealCpuTemp(list) || !IsAmdApu(cpuName)) return list;
        var gpu = list.Where(r => r.IsFromWindows && r.IsLive && r.HardwareName.Contains("Radeon", StringComparison.OrdinalIgnoreCase)).MaxBy(r => r.Value);
        log?.Invoke($"CPU temperature fallback (APU shared die): cpu='{cpuName}' radeonGpuFromWindows={(gpu?.Value?.ToString("0.0") ?? "none")}");
        if (gpu?.Value is { } v) list.Add(new SensorReading(cpuName!, HardwareKind.Cpu, ApuSensorName, SensorKind.Temperature, v, null, null, "°C"));
        return list;
    }

    /// <summary>
    /// Friendly note when there is no real CPU temperature. If the driver is missing it is not available; if it is
    /// registered but still no reading, it is blocked or unsupported, which is "not available" to the user as well.
    /// </summary>
    public static string? Note(IReadOnlyList<SensorReading> readings, bool sensorDriverRegistered) =>
        HasRealCpuTemp(readings) ? null : DriverMissingNote;
}
