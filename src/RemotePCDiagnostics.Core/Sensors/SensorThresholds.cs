namespace RemotePCDiagnostics.Core.Sensors;

public sealed record SensorThreshold(double Warning, double Critical, string Basis);

/// <summary>
/// Default alert thresholds from docs/sensor-thresholds.md, Part 2, limited to rows backed by a published number
/// in Part 1. Rows the doc marks as heuristic (motherboard/chipset, VRM) and fan RPM (no universal threshold)
/// are intentionally absent and evaluate to <see cref="SensorLevel.Neutral"/>.
/// </summary>
public static class SensorThresholds
{
    public static readonly SensorThreshold IntelCpu = new(90, 98, "Intel Tjunction 100°C (i9-14900K)");
    public static readonly SensorThreshold AmdCpu = new(85, 93, "AMD Tjmax 95°C (Ryzen 7 9700X)");
    public static readonly SensorThreshold NvidiaGpu = new(83, 88, "NVIDIA max GPU temperature 90°C (RTX 4070 family)");
    public static readonly SensorThreshold AmdGpuJunction = new(100, 108, "AMD support: 110°C junction in spec (informal)");
    public static readonly SensorThreshold WindowsGpu = new(85, 95, "Conservative default for a GPU temperature read through Windows");
    public static readonly SensorThreshold Ssd = new(65, 70, "Samsung 990 PRO operating max 70°C");
    public static readonly SensorThreshold Hdd = new(50, 58, "Seagate BarraCuda case max 60°C");

    public static SensorThreshold? For(SensorReading r)
    {
        if (r.SensorType != SensorKind.Temperature || r.IsApproximate || r.IsLimit) return null;
        var hw = r.HardwareName; var s = r.SensorName;
        return r.HardwareType switch
        {
            HardwareKind.Cpu when Has(hw, "Intel") => IntelCpu,
            HardwareKind.Cpu when Has(hw, "AMD") || Has(hw, "Ryzen") => AmdCpu,
            HardwareKind.Gpu when r.IsFromWindows => WindowsGpu,
            HardwareKind.Gpu when Has(hw, "NVIDIA") || Has(hw, "GeForce") || Has(hw, "RTX") => NvidiaGpu,
            HardwareKind.Gpu when (Has(hw, "AMD") || Has(hw, "Radeon")) && (Has(s, "Hot Spot") || Has(s, "Hotspot") || Has(s, "Junction")) => AmdGpuJunction,
            HardwareKind.Storage when !IsSecondaryStorageSensor(s) && (Has(s, "Composite") || IsSsdModel(hw)) => Ssd,
            HardwareKind.Storage when !IsSecondaryStorageSensor(s) && (Has(hw, "HDD") || Has(hw, "BarraCuda") || Has(hw, "Hard Disk")) => Hdd,
            _ => null,
        };
    }

    public static SensorLevel Evaluate(SensorReading r) => Evaluate(r.Value, For(r));

    public static SensorLevel Evaluate(double? value, SensorThreshold? t) =>
        t is null || value is null ? SensorLevel.Neutral
        : value >= t.Critical ? SensorLevel.Critical
        : value >= t.Warning ? SensorLevel.Warning
        : SensorLevel.Ok;

    private static bool IsSecondaryStorageSensor(string sensorName) => sensorName.Contains('#');

    private static bool IsSsdModel(string hw) =>
        Has(hw, "NVMe") || Has(hw, "SSD") || Has(hw, "Solid State")
        || Has(hw, "MZVL") || Has(hw, "MZAL") || Has(hw, "MZQL") || Has(hw, "PM9")
        || Has(hw, "SN5") || Has(hw, "SN7") || Has(hw, "SN8")
        || Has(hw, "KIOXIA") || Has(hw, "SK hynix") || Has(hw, "Optane");

    private static bool Has(string s, string v) => s.Contains(v, StringComparison.OrdinalIgnoreCase);
}
