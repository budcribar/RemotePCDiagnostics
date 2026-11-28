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
    // Condition details, asked separately so the four questions above stay as recorded PCs answered them. Each one may be missing.
    public const string StatusDetailSql = "SELECT InstanceName, Voltage, Critical FROM BatteryStatus";
    public const string IdentitySql = "SELECT InstanceName, SerialNumber, ManufactureDate FROM BatteryStaticData";
    public const string TemperatureSql = "SELECT InstanceName, Temperature FROM BatteryTemperature";
    public const string Win32Namespace = @"root\cimv2";
    public const string Win32Sql = "SELECT DeviceID, DesignVoltage, EstimatedChargeRemaining, Status FROM Win32_Battery";
    /// <summary>Lenovo's battery information (asked only on a Lenovo; it answers only an administrator, so the Agent).</summary>
    public const string LenovoSql = "SELECT InstanceName, CurrentSetting FROM Lenovo_BatteryInformation";
    public const string ProcessorPerformanceNamespace = @"root\cimv2";
    public const string ProcessorPerformanceSql = "SELECT Name, PercentPerformanceLimit, PercentofMaximumFrequency FROM Win32_PerfFormattedData_Counters_ProcessorInformation WHERE Name = '_Total'";

    /// <summary>BATTERY_SYSTEM_BATTERY and BATTERY_IS_SHORT_TERM: osquery (and so this) skips a UPS or other short-term battery.</summary>
    public const long SystemBatteryFlag = 0x80000000;
    public const long ShortTermFlag = 0x20000000;
    /// <summary>What a battery driver reports for a capacity it doesn't know (BATTERY_UNKNOWN_CAPACITY).</summary>
    public const long UnknownCapacity = 0xFFFFFFFF;
    /// <summary>What a battery driver reports for a charge/discharge rate it doesn't know (BATTERY_UNKNOWN_RATE).</summary>
    public const long UnknownRate = 0x80000000;

    public static async Task<IReadOnlyList<BatteryStatus>?> ReadWmiAsync(IWmiSource wmi, CancellationToken ct) =>
        await ReadWmiAsync(wmi, isLenovo: false, ct).ConfigureAwait(false);

    /// <param name="isLenovo">Also ask Lenovo's battery information class.</param>
    public static async Task<IReadOnlyList<BatteryStatus>?> ReadWmiAsync(IWmiSource wmi, bool isLenovo, CancellationToken ct)
    {
        var stat = await wmi.QueryAsync(WmiNamespace, StaticSql, ct).ConfigureAwait(false);
        // A PC without a battery has no instances of these classes: WMI answers "Not supported" rather than an empty list.
        if (!stat.Success) return IsNoBattery(stat.Error) ? [] : null;
        var full = await wmi.QueryAsync(WmiNamespace, FullChargeSql, ct).ConfigureAwait(false);
        var cycles = await wmi.QueryAsync(WmiNamespace, CycleCountSql, ct).ConfigureAwait(false);
        var status = await wmi.QueryAsync(WmiNamespace, StatusSql, ct).ConfigureAwait(false);
        var detail = await wmi.QueryAsync(WmiNamespace, StatusDetailSql, ct).ConfigureAwait(false);
        var identity = await wmi.QueryAsync(WmiNamespace, IdentitySql, ct).ConfigureAwait(false);
        var temperature = await wmi.QueryAsync(WmiNamespace, TemperatureSql, ct).ConfigureAwait(false);
        var win32 = await wmi.QueryAsync(Win32Namespace, Win32Sql, ct).ConfigureAwait(false);
        var lenovo = isLenovo ? await wmi.QueryAsync(WmiNamespace, LenovoSql, ct).ConfigureAwait(false) : null;

        var list = new List<BatteryStatus>();
        for (var index = 0; index < stat.Rows!.Count; index++)
        {
            var s = stat.Rows[index];
            var caps = s.Long("Capabilities");
            if (caps is { } c && ((c & SystemBatteryFlag) == 0 || (c & ShortTermFlag) != 0)) continue;
            var name = s.Str("InstanceName");
            var f = Match(full, name);
            var st = Match(status, name);
            var design = Capacity(s.Long("DesignedCapacity"));
            var max = Capacity(f?.Long("FullChargedCapacity"));
            var remaining = Capacity(st?.Long("RemainingCapacity"));
            var cycle = Match(cycles, name)?.Long("CycleCount");
            var d = Match(detail, name);
            var id = Match(identity, name);
            // Win32_Battery has no instance name: matched by position (and so only when both list the same number of batteries).
            var w = win32.Rows is { } wr && wr.Count == stat.Rows.Count ? wr[index] : null;
            list.Add(new(s.Str("DeviceName"), s.Str("ManufactureName"), Chemistry(s.Long("Chemistry")), State(st),
                Percent(remaining, max), ToInt(design), ToInt(max), cycle is > 0 and <= 100_000 ? (int)cycle.Value : null,
                PowerOnline: st?.Bool("PowerOnline"),
                IsCharging: st?.Bool("Charging"),
                IsDischarging: st?.Bool("Discharging"),
                DischargeRateMw: RateMw(st?.Long("DischargeRate")),
                ChargeRateMw: RateMw(st?.Long("ChargeRate")))
            {
                InstanceName = name,
                RemainingMwh = ToInt(remaining),
                ReportedFullChargeMwh = f?.Long("FullChargedCapacity"),
                VoltageMv = Millivolts(d?.Long("Voltage")),
                Critical = d?.Bool("Critical"),
                DesignVoltageMv = Millivolts(w?.Long("DesignVoltage")),
                WindowsPercent = w?.Long("EstimatedChargeRemaining") is >= 0 and <= 100 and var wp ? (int)wp : null,
                DeviceStatus = w?.Str("Status").Trim() ?? "",
                TemperatureC = Celsius(Match(temperature, name)?.Long("Temperature")),
                SerialNumber = Clean(id?.Str("SerialNumber")),
                ManufactureDate = Date(id?.Str("ManufactureDate")),
                VendorDetail = Vendor(lenovo, name),
            });
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

    public static bool IsNoBattery(string? error) =>
        error is not null && new[] { "Not supported", "NotSupported", "Not found", "NotFound" }.Any(e => error.Contains(e, StringComparison.OrdinalIgnoreCase));

    private static WmiRow? Match(WmiQueryResult r, string instanceName) =>
        r.Rows?.FirstOrDefault(x => string.Equals(x.Str("InstanceName"), instanceName, StringComparison.OrdinalIgnoreCase))
        ?? (r.Rows is { Count: 1 } one ? one[0] : null);

    /// <summary>A capacity in mWh, or null when the driver doesn't know it (0, negative, or BATTERY_UNKNOWN_CAPACITY).</summary>
    public static long? Capacity(long? mWh) => mWh is > 0 and < UnknownCapacity and <= int.MaxValue ? mWh : null;

    /// <summary>A charge/discharge rate in mW, or null when 0, negative, or BATTERY_UNKNOWN_RATE.</summary>
    public static int? RateMw(long? mW) => mW is > 0 and < UnknownRate and <= int.MaxValue ? (int)mW.Value : null;

    /// <summary>A voltage in mV, or null when 0 or unknown (BATTERY_UNKNOWN_VOLTAGE is 0xFFFFFFFF).</summary>
    public static int? Millivolts(long? mV) => mV is > 0 and < 100_000 ? (int)mV.Value : null;

    /// <summary>BatteryTemperature is in tenths of a kelvin (as IOCTL_BATTERY_QUERY_INFORMATION's BatteryTemperature); null outside -40..150 °C.</summary>
    public static double? Celsius(long? tenthsKelvin) =>
        tenthsKelvin is > 0 && Math.Round(tenthsKelvin.Value / 10.0 - 273.15, 1) is var c && c is >= -40 and <= 150 ? c : null;

    /// <summary>A CIM datetime ("20230115000000.000000-000") or a date string as yyyy-MM-dd; empty when unreadable.</summary>
    public static string Date(string? value)
    {
        var v = (value ?? "").Trim();
        if (v.Length >= 8 && v.Take(8).All(char.IsAsciiDigit)
            && DateTime.TryParseExact(v[..8], "yyyyMMdd", System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out var cim))
            return cim.Year >= 1990 ? cim.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture) : "";
        return DateTime.TryParse(v, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AdjustToUniversal, out var dt) && dt.Year >= 1990
            ? dt.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture) : "";
    }

    private static string Clean(string? s)
    {
        var t = (s ?? "").Trim();
        return t.Length is > 0 and <= 64 && !t.Any(char.IsControl) ? t : "";
    }

    /// <summary>Lenovo's CurrentSetting strings for this battery, as rows (what it holds varies by model, so it is shown as given).</summary>
    private static IReadOnlyList<KeyValuePair<string, string>> Vendor(WmiQueryResult? lenovo, string instanceName)
    {
        if (lenovo?.Rows is not { Count: > 0 } rows) return [];
        var mine = rows.Where(r => string.Equals(r.Str("InstanceName"), instanceName, StringComparison.OrdinalIgnoreCase)).ToList();
        return (mine.Count > 0 ? mine : rows)
            .Select(r => r.Str("CurrentSetting").Trim())
            .Where(v => v.Length is > 0 and <= 200 && !v.Any(char.IsControl))
            .Distinct().Take(8)
            .Select(v => new KeyValuePair<string, string>("Lenovo battery information", v)).ToList();
    }

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
