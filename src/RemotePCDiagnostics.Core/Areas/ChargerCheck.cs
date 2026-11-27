using System.Globalization;
using RemotePCDiagnostics.Core.DataSources;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>A Windows device that matters to charging (the ACPI AC adapter, or the USB-C connector manager) and its Device Manager state.</summary>
/// <param name="ErrorCode">Device Manager's problem code (<c>ConfigManagerErrorCode</c>); 0 when it works.</param>
public sealed record ChargingDevice(string Name, string Status, int ErrorCode)
{
    public bool HasProblem => ErrorCode != 0;
    public string ProblemText => new ProblemDevice(Name, "", "", ErrorCode, Status).FriendlyError;
}

/// <summary>A Kernel-Power 105 event: Windows saw the power source change (plugged in or unplugged).</summary>
/// <param name="AcOnline">True when the change was to wall power; null when the event didn't say.</param>
public sealed record PowerSourceChange(DateTimeOffset Time, bool? AcOnline);

/// <summary>
/// What BatteryPower reads to judge the charger, besides the battery itself. Each list is null when it couldn't be read, empty when
/// there was nothing (no event, no device).
/// </summary>
/// <param name="Adapters">The ACPI AC adapter devices (<c>ACPI0003</c>).</param>
/// <param name="UsbC">The USB-C connector manager (UCSI) devices, on PCs that charge over USB-C.</param>
/// <param name="SourceChanges">Kernel-Power 105 events in the last <see cref="ChargerCheck.EventDays"/> days, newest first.</param>
/// <param name="FirmwareLimits">Kernel-Processor-Power 37 events (firmware held the processor's speed back) in the same days.</param>
/// <param name="SlowCharger">USB-C connector manager events about a slow charger in the same days; null when that log isn't on this PC.</param>
/// <param name="NeedsAgent">True when the device reads were skipped because the Agent isn't connected (Store edition).</param>
public sealed record ChargerReading(
    IReadOnlyList<ChargingDevice>? Adapters,
    IReadOnlyList<ChargingDevice>? UsbC,
    IReadOnlyList<PowerSourceChange>? SourceChanges,
    IReadOnlyList<WinEvent>? FirmwareLimits,
    IReadOnlyList<WinEvent>? SlowCharger,
    bool NeedsAgent = false);

/// <summary>The charger card's verdict, worst first in <see cref="ChargerCheck.Level"/>.</summary>
public enum ChargerState
{
    /// <summary>No battery: a desktop on wall power.</summary>
    NotApplicable,
    /// <summary>The batteries couldn't be read, so whether a charger is connected isn't known.</summary>
    Unknown,
    /// <summary>Running on the battery: nothing to judge until it's plugged in.</summary>
    OnBattery,
    Ok,
    /// <summary>Windows warned about a slow USB-C charger, or the charger connection keeps dropping.</summary>
    SlowCharger,
    /// <summary>Plugged in, but the processor is held back: the charger may be below what the PC needs.</summary>
    BelowRequirement,
    /// <summary>Plugged in, yet the battery drains: the PC runs from its battery while plugged in.</summary>
    TooSmall,
    /// <summary>The AC adapter device reports a problem in Device Manager.</summary>
    NotFunctioning,
}

/// <summary>
/// The AC adapter (charger) card on BatteryPower: is a charger connected, does Windows see it working, is it big enough for the PC, and
/// how stable its connection has been. Windows doesn't tell apps a charger's rated wattage, so "too small" and "below requirement" are
/// judged from what the PC does on it: the battery draining while plugged in (too small) and the processor held back while plugged in
/// (below requirement). The interactive unplug and replug test is <see cref="ChargerReplug"/>.
/// </summary>
public static class ChargerCheck
{
    public const string CardId = "charger";
    public const int EventDays = 7;
    /// <summary>An unplug followed by a plug-in within this time is a brief dropout (a loose plug or worn cable), not a person unplugging.</summary>
    public static readonly TimeSpan DropoutWindow = TimeSpan.FromSeconds(5);
    /// <summary>Dropouts in <see cref="EventDays"/> days at which the card warns.</summary>
    public const int DropoutsWarn = 3;

    public const string WmiNamespace = @"root\cimv2";
    // WQL needs the backslash in a LIKE pattern doubled.
    public const string AdapterSql = @"SELECT Name, Status, ConfigManagerErrorCode FROM Win32_PnPEntity WHERE PNPDeviceID LIKE 'ACPI\\ACPI0003%'";
    public const string UsbCSql = "SELECT Name, Status, ConfigManagerErrorCode FROM Win32_PnPEntity WHERE Name LIKE '%UCSI%'";
    public const string UsbCChannel = "Microsoft-Windows-USB-UCMUCSICX/Operational";

    /// <summary>Kernel-Power 105 (power source change) and Kernel-Processor-Power 37 (speed limited by firmware) in the last <paramref name="days"/> days.</summary>
    public static string SystemEventQuery(int days) =>
        "*[System[((Provider[@Name='Microsoft-Windows-Kernel-Power'] and EventID=105)"
        + " or (Provider[@Name='Microsoft-Windows-Kernel-Processor-Power'] and EventID=37))"
        + $" and TimeCreated[timediff(@SystemTime) <= {(long)days * 86_400_000}]]]";

    public static string RecentQuery(int days) => $"*[System[TimeCreated[timediff(@SystemTime) <= {(long)days * 86_400_000}]]]";

    /// <summary>
    /// Reads the charging devices from WMI (<paramref name="wmi"/>: through the Agent in the app; null skips them, <see cref="ChargerReading.NeedsAgent"/>)
    /// and the power events from the event logs (readable without administrator rights).
    /// </summary>
    public static async Task<ChargerReading> ReadAsync(IWmiSource? wmi, WindowsEventLog? events, CancellationToken ct)
    {
        IReadOnlyList<ChargingDevice>? adapters = null, usbC = null;
        if (wmi is not null)
        {
            adapters = Devices(await wmi.QueryAsync(WmiNamespace, AdapterSql, ct).ConfigureAwait(false));
            usbC = Devices(await wmi.QueryAsync(WmiNamespace, UsbCSql, ct).ConfigureAwait(false));
        }
        IReadOnlyList<PowerSourceChange>? changes = null;
        IReadOnlyList<WinEvent>? limits = null, slow = null;
        if (events is not null)
        {
            if (await events.QueryAsync("System", SystemEventQuery(EventDays), 400, ct).ConfigureAwait(false) is { } sys)
            {
                changes = sys.Where(e => e.EventId == 105 && e.Provider.EndsWith("Kernel-Power", StringComparison.OrdinalIgnoreCase))
                    .Select(e => new PowerSourceChange(e.Time, Flag(e.DataAt(0, "AcOnline")))).ToList();
                limits = sys.Where(e => e.EventId == 37 && e.Provider.EndsWith("Kernel-Processor-Power", StringComparison.OrdinalIgnoreCase)).ToList();
            }
            // Only PCs with USB-C charging have this log; on others wevtutil fails and the row says "Not reported".
            if (await events.QueryAsync(UsbCChannel, RecentQuery(EventDays), 200, ct).ConfigureAwait(false) is { } ucm)
                slow = ucm.Where(IsSlowChargerEvent).ToList();
        }
        return new(adapters, usbC, changes, limits, slow, NeedsAgent: wmi is null);
    }

    private static List<ChargingDevice>? Devices(WmiQueryResult q) =>
        q.Rows?.Select(r => new ChargingDevice(r.Str("Name"), r.Str("Status"), (int)(r.Long("ConfigManagerErrorCode") ?? 0))).ToList();

    private static bool? Flag(string? v) => bool.TryParse(v, out var b) ? b : v is "1" ? true : v is "0" ? false : null;

    /// <summary>A USB-C connector manager event about a slow or trickle charger (the reason Windows shows "Slow charger").</summary>
    public static bool IsSlowChargerEvent(WinEvent e)
    {
        bool Says(string s) => s.Contains("slow", StringComparison.OrdinalIgnoreCase) || s.Contains("trickle", StringComparison.OrdinalIgnoreCase);
        return Says(e.Message) || e.Data.Any(Says);
    }

    /// <summary>Brief unplug-then-plug-in pairs (within <see cref="DropoutWindow"/>), newest first.</summary>
    public static IReadOnlyList<DateTimeOffset> Dropouts(IReadOnlyList<PowerSourceChange>? changes)
    {
        if (changes is null) return [];
        var ordered = changes.OrderBy(c => c.Time).ToList();
        var list = new List<DateTimeOffset>();
        for (var i = 0; i + 1 < ordered.Count; i++)
        {
            if (ordered[i].AcOnline == false && ordered[i + 1].AcOnline == true && ordered[i + 1].Time - ordered[i].Time <= DropoutWindow)
            {
                list.Add(ordered[i].Time);
                i++;
            }
        }
        list.Reverse();
        return list;
    }

    /// <summary>The card's verdict from the battery readings and <paramref name="reading"/>.</summary>
    public static ChargerState State(IReadOnlyList<BatteryStatus>? batteries, ChargerReading? reading, bool dischargingOnAc, bool heldBackOnAc)
    {
        if (batteries is null) return ChargerState.Unknown;
        if (batteries.Count == 0) return ChargerState.NotApplicable;
        if (reading?.Adapters?.Any(a => a.HasProblem) == true) return ChargerState.NotFunctioning;
        if (!batteries.Any(b => b.IsOnAc)) return ChargerState.OnBattery;
        if (dischargingOnAc) return ChargerState.TooSmall;
        if (heldBackOnAc) return ChargerState.BelowRequirement;
        if (reading?.SlowCharger is { Count: > 0 } || Dropouts(reading?.SourceChanges).Count >= DropoutsWarn) return ChargerState.SlowCharger;
        return ChargerState.Ok;
    }

    public static AreaLevel Level(ChargerState s) => s switch
    {
        ChargerState.TooSmall or ChargerState.NotFunctioning => AreaLevel.Error,
        ChargerState.BelowRequirement or ChargerState.SlowCharger => AreaLevel.Warning,
        ChargerState.Ok => AreaLevel.Ok,
        _ => AreaLevel.Neutral,
    };

    /// <summary>The state as the report's machine-readable word (the card's first row), the same in the UI and Admin.</summary>
    public static string StateName(ChargerState s) => s switch
    {
        ChargerState.NotApplicable => "Not applicable",
        ChargerState.Unknown => "Not reported",
        ChargerState.OnBattery => "Not connected",
        ChargerState.Ok => "OK",
        ChargerState.SlowCharger => "Slow charger",
        ChargerState.BelowRequirement => "Below requirement",
        ChargerState.TooSmall => "Too small",
        _ => "Not functioning",
    };

    private static string Watts(int mw) => (mw / 1000.0).ToString("0.0", CultureInfo.InvariantCulture) + " W";

    private static string When(DateTimeOffset t) => WindowsEventLog.FormatTime(t);

    /// <summary>
    /// The charger card. <paramref name="dischargingOnAc"/> and <paramref name="heldBackOnAc"/> are BatteryPower's confirmed readings (two
    /// samples 5 s apart), so a moment's dip doesn't fail the charger.
    /// </summary>
    public static AreaCard Card(IReadOnlyList<BatteryStatus>? batteries, ChargerReading? reading, bool dischargingOnAc = false, bool heldBackOnAc = false,
        ProcessorPerformanceSample? perf = null)
    {
        var state = State(batteries, reading, dischargingOnAc, heldBackOnAc);
        var level = Level(state);
        var rows = new List<AreaRow>();
        void Add(string key, string label, string value, AreaLevel lv = AreaLevel.Neutral) => rows.Add(new(lv, [label, value], Key: key));

        Add("state", "Charger state", StateName(state), level);
        if (state == ChargerState.NotApplicable)
        {
            Add("power", "Power source", "Wall power (no battery)");
            return new(CardId, "Charger (AC adapter)", AreaLevel.Neutral, "Not applicable", "This PC has no battery, so it has no charger to test",
                ["Detail", "Value"], rows);
        }

        var onAc = batteries?.Any(b => b.IsOnAc);
        Add("connected", "Charger connected", onAc switch { true => "Yes", false => "No (running on battery)", _ => "Not reported" });
        var b0 = batteries?.FirstOrDefault(b => b.IsOnAc) ?? batteries?.FirstOrDefault();
        if (onAc == true && b0 is not null)
        {
            var charging = b0.IsCharging == true || b0.ChargeRateMw is > 0;
            Add("charging", "Charging", charging
                ? b0.ChargeRateMw is { } mw ? $"Yes, at {Watts(mw)}" : "Yes"
                : dischargingOnAc ? b0.DischargeRateMw is { } d ? $"No, the battery is draining at {Watts(d)}" : "No, the battery is draining"
                : b0.PercentRemaining is >= 95 ? "No (battery full)" : "No", dischargingOnAc ? AreaLevel.Error : AreaLevel.Neutral);
        }
        if (heldBackOnAc && perf?.PerformanceLimitPercent is { } limit)
            Add("perf-limit", "Processor speed on this charger", $"Held back to {limit}% while plugged in", AreaLevel.Warning);
        // Windows has no API that reports a charger's rated wattage, and the PC makers' tools don't publish it to other apps.
        Add("rated", "Rated wattage", "Not reported by Windows");

        if (reading is not null)
        {
            if (reading.NeedsAgent)
                Add("adapter-device", "AC adapter device", "Needs the Agent");
            else if (reading.Adapters is { } adapters)
            {
                if (adapters.Count == 0) Add("adapter-device", "AC adapter device", "Not listed (some USB-C laptops have none)");
                foreach (var a in adapters)
                    Add("adapter-device", "AC adapter device", a.HasProblem ? $"{a.Name}: {a.ProblemText}" : $"{a.Name}: working", a.HasProblem ? AreaLevel.Error : AreaLevel.Ok);
            }
            if (!reading.NeedsAgent && reading.UsbC is { Count: > 0 } usbC)
                foreach (var u in usbC)
                    Add("usbc-device", "USB-C charging (connector manager)", u.HasProblem ? $"{u.Name}: {u.ProblemText}" : $"{u.Name}: working", u.HasProblem ? AreaLevel.Warning : AreaLevel.Ok);

            if (reading.SlowCharger is { } slow)
                Add("slow-charger", "Slow charger warnings", slow.Count == 0 ? "None in the last 7 days" : $"{slow.Count} in the last 7 days, last {When(slow.Max(e => e.Time))}",
                    slow.Count > 0 ? AreaLevel.Warning : AreaLevel.Ok);
            if (reading.SourceChanges is { } changes)
            {
                Add("source-changes", "Plugged in or unplugged", changes.Count == 0 ? "Not in the last 7 days" : $"{changes.Count} times in the last 7 days, last {When(changes.Max(c => c.Time))}");
                var drops = Dropouts(changes);
                Add("dropouts", "Brief power drops", drops.Count == 0 ? "None in the last 7 days" : $"{drops.Count} in the last 7 days, last {When(drops[0])}",
                    drops.Count >= DropoutsWarn ? AreaLevel.Warning : AreaLevel.Neutral);
            }
            if (reading.FirmwareLimits is { Count: > 0 } fw)
                Add("firmware-limit", "Processor slowed by firmware", $"{fw.Count} times in the last 7 days, last {When(fw.Max(e => e.Time))}",
                    heldBackOnAc ? AreaLevel.Warning : AreaLevel.Neutral);
        }

        var (headline, meta, note) = state switch
        {
            ChargerState.Unknown => ("Not reported", "The battery and power state couldn't be read", (string?)null),
            ChargerState.OnBattery => ("Not connected", "Running on battery", "Plug in the charger and run the check again to test it, or run the charger replug test on Interactive tests."),
            ChargerState.NotFunctioning => ("Not functioning", "Windows reports a problem with the AC adapter",
                "Device Manager shows a problem with the AC adapter. Restart the PC; if it stays, update the BIOS and chipset drivers, then try a known good charger."),
            ChargerState.TooSmall => ("Too small", "The PC runs from its battery while plugged in",
                "The battery drains even though the charger is plugged in, so the charger (or the USB-C dock or cable) can't supply what the PC needs. Use the PC maker's charger with the wattage on the PC's label."),
            ChargerState.BelowRequirement => ("Below requirement", "The PC runs slowed on this charger",
                "The processor is held back while plugged in. A charger or USB-C dock below the PC's wattage is the usual cause; heat is another. Try the PC maker's charger."),
            ChargerState.SlowCharger => reading?.SlowCharger is { Count: > 0 }
                ? ("Slow charger", "Windows warned about a slow USB-C charger",
                    "Windows reported a slow charger. Use a USB-C charger with Power Delivery at the wattage on the PC's label, and a cable rated for it.")
                : ("Slow charger", "The charger connection keeps dropping",
                    $"The charger was unplugged and plugged back in within {DropoutWindow.TotalSeconds:0} seconds {Dropouts(reading?.SourceChanges).Count} times in the last 7 days. A loose plug, a worn cable or a worn charging port does this."),
            _ => ("OK", "Charger connected and working", null),
        };
        if (state == ChargerState.Ok && reading?.UsbC?.Any(u => u.HasProblem) == true)
        {
            level = AreaLevel.Warning;
            meta = "Windows reports a problem with USB-C charging";
            note = "The USB-C connector manager has a problem in Device Manager, so charging over USB-C may not work. Update the chipset and USB-C (UCSI) drivers from the PC maker.";
            rows[0] = rows[0] with { Level = level };
        }
        return new(CardId, "Charger (AC adapter)", level, headline, meta, ["Detail", "Value"], rows, Note: note, PreserveRowOrder: true);
    }
}
