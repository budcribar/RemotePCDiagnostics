using RemotePCDiagnostics.Core.DataSources;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// Reads the PC's batteries from WMI (the <c>root\wmi</c> battery classes, the same driver data osquery reads). Null means the batteries
/// couldn't be read; an empty list means the PC has none. The osquery reader is in RemotePCDiagnostics.Legacy.
/// </summary>
public static class BatteryReader
{
    public const string WmiNamespace = @"root\wmi";
    public const string StaticSql = "SELECT InstanceName, Capabilities, Chemistry, DesignedCapacity, DeviceName, ManufactureName FROM BatteryStaticData";
    public const string FullChargeSql = "SELECT InstanceName, FullChargedCapacity FROM BatteryFullChargedCapacity";
    public const string CycleCountSql = "SELECT InstanceName, CycleCount FROM BatteryCycleCount";
    public const string StatusSql = "SELECT InstanceName, PowerOnline, Charging, Discharging, RemainingCapacity, DischargeRate, ChargeRate FROM BatteryStatus";
    public const string ProcessorPerformanceNamespace = @"root\cimv2";
    public const string ProcessorPerformanceSql = "SELECT Name, PercentPerformanceLimit, PercentofMaximumFrequency FROM Win32_PerfFormattedData_Counters_ProcessorInformation WHERE Name = '_Total'";

    /// <summary>BATTERY_SYSTEM_BATTERY and BATTERY_IS_SHORT_TERM: osquery (and so this) skips a UPS or other short-term battery.</summary>
    public const long SystemBatteryFlag = 0x80000000;
    public const long ShortTermFlag = 0x20000000;
    /// <summary>What a battery driver reports for a capacity it doesn't know (BATTERY_UNKNOWN_CAPACITY).</summary>
    public const long UnknownCapacity = 0xFFFFFFFF;
    /// <summary>What a battery driver reports for a charge/discharge rate it doesn't know (BATTERY_UNKNOWN_RATE).</summary>
    public const long UnknownRate = 0x80000000;

    public static async Task<IReadOnlyList<BatteryStatus>?> ReadWmiAsync(IWmiSource wmi, CancellationToken ct)
    {
        var stat = await wmi.QueryAsync(WmiNamespace, StaticSql, ct).ConfigureAwait(false);
        // A PC without a battery has no instances of these classes: WMI answers "Not supported" rather than an empty list.
        if (!stat.Success) return IsNoBattery(stat.Error) ? [] : null;
        var full = await wmi.QueryAsync(WmiNamespace, FullChargeSql, ct).ConfigureAwait(false);
        var cycles = await wmi.QueryAsync(WmiNamespace, CycleCountSql, ct).ConfigureAwait(false);
        var status = await wmi.QueryAsync(WmiNamespace, StatusSql, ct).ConfigureAwait(false);

        var list = new List<BatteryStatus>();
        foreach (var s in stat.Rows!)
        {
            var caps = s.Long("Capabilities");
            if (caps is { } c && ((c & SystemBatteryFlag) == 0 || (c & ShortTermFlag) != 0)) continue;
            var name = s.Str("InstanceName");
            var f = Match(full, name);
            var st = Match(status, name);
            var design = Capacity(s.Long("DesignedCapacity"));
            var max = Capacity(f?.Long("FullChargedCapacity"));
            var remaining = Capacity(st?.Long("RemainingCapacity"));
            var cycle = Match(cycles, name)?.Long("CycleCount");
            list.Add(new(s.Str("DeviceName"), s.Str("ManufactureName"), Chemistry(s.Long("Chemistry")), State(st),
                Percent(remaining, max), ToInt(design), ToInt(max), cycle is > 0 and <= 100_000 ? (int)cycle.Value : null,
                PowerOnline: st?.Bool("PowerOnline"),
                IsCharging: st?.Bool("Charging"),
                IsDischarging: st?.Bool("Discharging"),
                DischargeRateMw: RateMw(st?.Long("DischargeRate")),
                ChargeRateMw: RateMw(st?.Long("ChargeRate"))));
        }
        return list;
    }

    /// <summary>
    /// Reads <c>PercentPerformanceLimit</c> (1..100; 0 is treated as unknown/unpopulated) and <c>PercentofMaximumFrequency</c>
    /// from WMI perf counters. Returns null when the query fails (perflib disabled or corrupt).
    /// </summary>
    public static async Task<ProcessorPerformanceSample?> ReadProcessorPerformanceWmiAsync(IWmiSource wmi, CancellationToken ct)
    {
        var q = await wmi.QueryAsync(ProcessorPerformanceNamespace, ProcessorPerformanceSql, ct).ConfigureAwait(false);
        if (!q.Success || q.Rows is not { Count: > 0 }) return null;
        var row = q.Rows[0];
        var limit = row.Long("PercentPerformanceLimit") is >= 1 and <= 100 and var l ? (int)l : (int?)null;
        var freq = row.Long("PercentofMaximumFrequency") is >= 1 and <= 1000 and var f ? (int)f : (int?)null;
        return limit is null && freq is null ? null : new ProcessorPerformanceSample(limit, freq);
    }

    private static bool IsNoBattery(string? error) =>
        error is not null && new[] { "Not supported", "NotSupported", "Not found", "NotFound" }.Any(e => error.Contains(e, StringComparison.OrdinalIgnoreCase));

    private static WmiRow? Match(WmiQueryResult r, string instanceName) =>
        r.Rows?.FirstOrDefault(x => string.Equals(x.Str("InstanceName"), instanceName, StringComparison.OrdinalIgnoreCase))
        ?? (r.Rows is { Count: 1 } one ? one[0] : null);

    /// <summary>A capacity in mWh, or null when the driver doesn't know it (0, negative, or BATTERY_UNKNOWN_CAPACITY).</summary>
    public static long? Capacity(long? mWh) => mWh is > 0 and < UnknownCapacity and <= int.MaxValue ? mWh : null;

    /// <summary>A charge/discharge rate in mW, or null when 0, negative, or BATTERY_UNKNOWN_RATE.</summary>
    public static int? RateMw(long? mW) => mW is > 0 and < UnknownRate and <= int.MaxValue ? (int)mW.Value : null;

    private static int? ToInt(long? v) => v is { } l ? (int)l : null;

    private static int? Percent(long? remaining, long? full) =>
        remaining is { } r && full is > 0 ? (int)Math.Round(Math.Clamp(r * 100.0 / full.Value, 0, 100)) : null;

    /// <summary>osquery's wording: "AC Power" when plugged in, "Battery Power" when running on the battery.</summary>
    private static string State(WmiRow? s)
    {
        if (s is null) return "";
        if (s.Bool("PowerOnline") == true) return "AC Power";
        if (s.Bool("Discharging") == true) return "Battery Power";
        return "";
    }

    /// <summary>The chemistry is four ASCII letters packed into a number, first letter in the low byte ("LION", "LiP").</summary>
    public static string Chemistry(long? packed)
    {
        if (packed is not { } p || p <= 0 || p > uint.MaxValue) return "";
        var sb = new System.Text.StringBuilder(4);
        for (var i = 0; i < 4; i++)
        {
            var ch = (char)((p >> (8 * i)) & 0xFF);
            if (ch == '\0') break;
            if (ch < ' ' || ch > '~') return "";
            sb.Append(ch);
        }
        return sb.ToString().Trim();
    }
}
