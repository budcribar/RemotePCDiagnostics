using System.Globalization;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>One thing the battery condition test found: a row of its own with plain advice.</summary>
/// <param name="Advice">What to do about it, in the card's note; null when the row says enough.</param>
public sealed record BatteryFinding(string Label, AreaLevel Level, string Text, string? Advice = null);

/// <summary>What the charging check saw.</summary>
public enum ChargeOutcome { NotChecked, OnBattery, DrainingOnAc, Charging, FullyCharged, AtChargeLimit, HeldBelowFull, NotCharging }

/// <summary>
/// The charging check's verdict for one battery: the first and last readings it compared and how long it watched in between (zero when one
/// reading was enough).
/// </summary>
public sealed record ChargeCheck(ChargeOutcome Outcome, AreaLevel Level, string Text, TimeSpan Watched, string? Advice = null);

/// <summary>What BatteryPower measured besides the batteries' own readings: the charging check per battery and each battery's full charge
/// capacity in the last History run (for the "calibration needed" jump), both by battery position.</summary>
public sealed record BatteryConditionInput(
    IReadOnlyList<ChargeCheck?>? Charging = null,
    IReadOnlyList<PreviousCapacity?>? Previous = null);

/// <summary>A battery's full charge capacity in an earlier run.</summary>
public sealed record PreviousCapacity(double Mwh, DateTimeOffset When);

/// <summary>
/// The battery condition test (RPCD #281): fault states from the battery driver's flags, voltage, temperature and capacity; whether the
/// battery charges on AC (with the charge limit and "fully charged" respected); and when the fuel gauge needs calibrating. Pure functions
/// over <see cref="BatteryStatus"/> readings, so record/replay and unit tests cover every path without the hardware.
/// </summary>
public static class BatteryCondition
{
    /// <summary>At or above this charge on AC a battery that isn't charging is full, not failing.</summary>
    public const int FullPercent = 95;
    /// <summary>Below this a battery on AC that doesn't charge has failed: no charge limit (Lenovo Conservation mode, Dell, HP, Windows
    /// smart charging) stops this low.</summary>
    public const int NoLimitBelowPercent = 50;
    /// <summary>How close to a known charge limit counts as held at it.</summary>
    public const int LimitSlackPercent = 3;
    public const double HotWarnC = 45, HotFailC = 60, ColdWarnC = 0;
    /// <summary>Pack voltage against design voltage: a Li-ion pack runs about 0.8 (empty) to 1.15 (full) of its nominal voltage.</summary>
    public const double LowVoltageRatio = 0.75, HighVoltageRatio = 1.2, DeepDischargeVoltageRatio = 0.8;
    /// <summary>Full charge capacity this far above design is corrupt data, not a better battery.</summary>
    public const double CorruptAboveDesignRatio = 1.15;
    /// <summary>Percent points Windows' estimate and our remaining / full may differ before the gauge needs calibrating.</summary>
    public const int PercentDisagreement = 10;
    /// <summary>Full charge capacity changing more than this between runs means the gauge needs calibrating.</summary>
    public const double CapacityJumpRatio = 0.10;
    /// <summary>The charging check: how long to watch at most, and how often to read.</summary>
    public static readonly TimeSpan ChargeWatch = TimeSpan.FromSeconds(90);
    public static readonly TimeSpan ChargeSampleEvery = TimeSpan.FromSeconds(10);

    public const string ChargeForAnHour = "Charge for 60 minutes and retest.";
    public const string LetItCool = "Battery too hot to test: let it cool for 20 minutes and retest.";
    public const string Calibrate = "Calibrate the battery: charge it to 100%, unplug and use it until it's below 5%, then charge it to 100% without unplugging. Then retest.";

    /// <summary>The fault states in one reading. Each is its own row; Error ones fail the check.</summary>
    public static IReadOnlyList<BatteryFinding> Faults(BatteryStatus b)
    {
        var list = new List<BatteryFinding>();
        switch (b.DeviceStatus)
        {
            case "Pred Fail" or "Error" or "NonRecover" or "Service":
                list.Add(new("Windows battery status", AreaLevel.Error, $"Windows reports the battery as \"{b.DeviceStatus}\"",
                    "Windows' battery driver reports this battery as failing. Back up, and replace the battery."));
                break;
            case "Degraded":
                list.Add(new("Windows battery status", AreaLevel.Warning, "Windows reports the battery as \"Degraded\""));
                break;
        }

        if (b.Critical == true)
            list.Add(b.PercentRemaining is > 10
                ? new("Critical state", AreaLevel.Error, $"Battery reports a critical state at {b.PercentRemaining}% charge",
                    "A battery that reports critical while it still holds charge usually has a failing cell or controller: replace it.")
                : new("Critical state", AreaLevel.Warning, "Critically low charge", ChargeForAnHour));

        if (b.IsCharging == true && b.IsDischarging == true)
            list.Add(new("Charge state", AreaLevel.Error, "Reports charging and discharging at the same time", ImpossibleState));
        else if (b.IsCharging == true && b.PowerOnline == false)
            list.Add(new("Charge state", AreaLevel.Error, "Reports charging while unplugged", ImpossibleState));

        if (b.TemperatureC is { } t)
        {
            if (t >= HotFailC)
                list.Add(new("Temperature", AreaLevel.Error, $"Too hot: {Temp(t)} (Li-ion limit {HotFailC:0} °C)",
                    "Shut the PC down and let it cool. A battery that runs this hot can swell: stop using it if the case bulges or lifts."));
            else if (t >= HotWarnC)
                list.Add(new("Temperature", AreaLevel.Warning, $"Hot: {Temp(t)}", LetItCool));
            else if (t < ColdWarnC)
                list.Add(new("Temperature", AreaLevel.Warning, $"Too cold to charge: {Temp(t)}", "Let the PC warm up to room temperature and retest."));
        }

        var ratio = VoltageRatio(b);
        var deep = ratio is < DeepDischargeVoltageRatio && (b.PercentRemaining is <= 2 || b.RemainingMwh is { } r && b.DesignCapacity is > 0 && (long)r * 100 <= b.DesignCapacity);
        if (deep)
            list.Add(new("Deep discharge", AreaLevel.Error, $"Deeply discharged: {Volts(b.VoltageMv)} of {Volts(b.DesignVoltageMv)} design",
                "The battery ran down far enough that its voltage collapsed. " + ChargeForAnHour + " If it won't take a charge, replace the battery."));
        else if (ratio is < LowVoltageRatio)
            list.Add(new("Voltage", AreaLevel.Error, $"Far below design: {Volts(b.VoltageMv)} of {Volts(b.DesignVoltageMv)}",
                "Pack voltage this low with charge left points to a failed cell: replace the battery."));
        else if (ratio is > HighVoltageRatio)
            list.Add(new("Voltage", AreaLevel.Error, $"Above the design range: {Volts(b.VoltageMv)} of {Volts(b.DesignVoltageMv)}",
                "Unplug the charger if the PC or battery is warm, and have the battery and charger checked."));

        if (b.ReportedFullChargeMwh == 0 && b.DesignCapacity is > 0)
            list.Add(new("Capacity data", AreaLevel.Error, "Full charge capacity reads 0 mWh", CorruptCapacity));
        else if (b.MaxCapacity is { } max && b.DesignCapacity is > 0 && max > b.DesignCapacity.Value * CorruptAboveDesignRatio)
            list.Add(new("Capacity data", AreaLevel.Error,
                $"Full charge capacity is above design: {N(max)} of {N(b.DesignCapacity.Value)} mWh", CorruptCapacity));
        return list;
    }

    private const string ImpossibleState =
        "The battery's controller is reporting states that can't both be true. Update the BIOS and the battery driver; if it keeps happening, the battery or its controller is faulty.";
    private const string CorruptCapacity =
        "The battery's fuel gauge holds corrupt capacity data. " + Calibrate + " If it stays wrong, update the BIOS or replace the battery.";

    /// <summary>"Calibration needed": the gauge's numbers disagree, or the full charge capacity jumped since the last run. Null when fine.</summary>
    public static BatteryFinding? Calibration(BatteryStatus b, PreviousCapacity? previous = null)
    {
        var reasons = new List<string>();
        if (b.WindowsPercent is { } w && b.PercentRemaining is { } p && Math.Abs(w - p) > PercentDisagreement)
            reasons.Add($"Windows shows {w}% but the battery's capacity says {p}%");
        if (b.RemainingMwh is { } rem && b.MaxCapacity is > 0 && rem > b.MaxCapacity.Value * 1.05)
            reasons.Add($"charge left ({N(rem)} mWh) is more than its full capacity ({N(b.MaxCapacity.Value)} mWh)");
        if (previous is { Mwh: > 0 } prev && b.MaxCapacity is > 0 && Math.Abs(b.MaxCapacity.Value - prev.Mwh) / prev.Mwh > CapacityJumpRatio)
            reasons.Add($"full charge capacity went from {N((long)prev.Mwh)} to {N(b.MaxCapacity.Value)} mWh since the check on {prev.When.ToLocalTime().ToString("d MMM yyyy", CultureInfo.InvariantCulture)}");
        return reasons.Count == 0 ? null
            : new("Calibration", AreaLevel.Warning, "Calibration needed: " + string.Join("; ", reasons), Calibrate);
    }

    /// <summary>The charge level a known limit holds the battery at (HP's BIOS setting), or null.</summary>
    public static int? ChargeLimitPercent(IReadOnlyList<Battery.HpBatterySetting>? settings)
    {
        var s = settings?.FirstOrDefault(x => x.Name == Battery.HpBatteryCharge.HealthManager && x.LimitValue is not null)
            ?? settings?.FirstOrDefault(x => x.LimitValue is not null);
        if (s is null || !s.IsLimited) return null;
        var digits = new string(s.CurrentValue.Trim().TakeWhile(char.IsAsciiDigit).ToArray());
        return int.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out var v) && v is > 0 and < 100 ? v : 80;
    }

    /// <summary>True when one reading can't tell whether the battery charges: on AC, showing no charge going in, and low enough that not
    /// charging would be a failure.
    /// Only below the level a charge limit could hold it at (the known limit, else <see cref="NoLimitBelowPercent"/>): above that, not
    /// charging can't fail the check, so it isn't worth the wait.</summary>
    public static bool NeedsChargeWatch(BatteryStatus b, int? limitPercent) =>
        b.PowerOnline == true && !b.IsDischargingOnAc && b.PercentRemaining is { } p && p < FailBelow(limitPercent)
        && b.IsCharging != true && b.ChargeRateMw is null;

    /// <summary>Not charging below this fails: the known limit (less the slack), or <see cref="NoLimitBelowPercent"/> when none is known.</summary>
    public static int FailBelow(int? limitPercent) => limitPercent is { } l ? Math.Min(FullPercent, l - LimitSlackPercent) : NoLimitBelowPercent;

    /// <summary>Judges charging from the first and last reading of one battery, <paramref name="watched"/> apart.</summary>
    public static ChargeCheck JudgeCharging(BatteryStatus first, BatteryStatus last, TimeSpan watched, int? limitPercent)
    {
        if (!last.IsOnAc)
            return last.IsDischarging == true || last.DischargeRateMw is > 0
                ? new(ChargeOutcome.OnBattery, AreaLevel.Ok, last.DischargeRateMw is { } d ? $"Running on battery, using {W(d)}" : "Running on battery",
                    TimeSpan.Zero)
                : new(ChargeOutcome.OnBattery, AreaLevel.Neutral, "Running on battery", TimeSpan.Zero);
        if (last.IsDischargingOnAc)
            return new(ChargeOutcome.DrainingOnAc, AreaLevel.Warning, "Draining while plugged in", watched);

        var rose = last.RemainingMwh > first.RemainingMwh || last.PercentRemaining > first.PercentRemaining;
        if (last.ChargeRateMw is { } rate)
            return new(ChargeOutcome.Charging, AreaLevel.Ok, $"Charging at {W(rate)}", watched);
        if (rose)
        {
            var text = last.PercentRemaining > first.PercentRemaining
                ? $"Charging: {first.PercentRemaining}% to {last.PercentRemaining}% in {Seconds(watched)}"
                : $"Charging: {N(first.RemainingMwh!.Value)} to {N(last.RemainingMwh!.Value)} mWh in {Seconds(watched)}";
            return new(ChargeOutcome.Charging, AreaLevel.Ok, text, watched);
        }
        if (last.IsCharging == true)
            return new(ChargeOutcome.Charging, AreaLevel.Ok, "Charging", watched);
        if (last.PercentRemaining is not { } p)
            return new(ChargeOutcome.NotChecked, AreaLevel.Neutral, "Not checked: the battery doesn't report its charge", watched);
        if (p >= FullPercent)
            return new(ChargeOutcome.FullyCharged, AreaLevel.Ok, $"Fully charged ({p}%)", watched);
        if (limitPercent is { } l && p >= l - LimitSlackPercent)
            return new(ChargeOutcome.AtChargeLimit, AreaLevel.Ok, $"Held at the {l}% charge limit ({p}%)", watched);
        if (p >= FailBelow(limitPercent))
            return new(ChargeOutcome.HeldBelowFull, AreaLevel.Neutral, $"Holding at {p}% while plugged in (a charge limit may be set)", watched,
                "Plugged in but not charging at this level. A charge limit does this (Lenovo Conservation mode, Dell or HP battery settings, Windows smart charging); " +
                "if none is set, charge for 60 minutes and retest.");
        if (watched <= TimeSpan.Zero)
            return new(ChargeOutcome.NotChecked, AreaLevel.Neutral, $"Not charging at {p}% (not watched)", watched);
        return new(ChargeOutcome.NotCharging, AreaLevel.Error, $"Not charging: stayed at {p}% for {Seconds(watched)} while plugged in", watched,
            "The battery didn't take any charge while plugged in. Try another outlet and the maker's charger; if it still won't charge, the battery or the charging circuit has failed.");
    }

    /// <summary>The battery card for battery <paramref name="index"/> of <paramref name="count"/> (id "battery", then "battery-2", ...).</summary>
    public static AreaCard Card(BatteryStatus b, int index, int count, bool dischargingOnAc, ChargeCheck? charging, PreviousCapacity? previous)
    {
        var health = b.HealthPercent;
        var worn = health is < BatteryStatus.LowHealthPercent;
        var faults = Faults(b);
        var calibration = Calibration(b, previous);
        // Health the battery didn't report is no reason to call it good.
        var healthLevel = worn ? AreaLevel.Warning : health is null ? AreaLevel.Neutral : AreaLevel.Ok;
        var levels = new List<AreaLevel> { dischargingOnAc ? AreaLevel.Warning : healthLevel };
        levels.AddRange(faults.Select(f => f.Level));
        if (calibration is not null) levels.Add(calibration.Level);
        var showCharging = charging is not null && !(dischargingOnAc && charging.Outcome == ChargeOutcome.DrainingOnAc);
        if (showCharging) levels.Add(charging!.Level == AreaLevel.Ok && healthLevel == AreaLevel.Neutral ? AreaLevel.Neutral : charging.Level);
        var level = levels.Max();

        var worstFault = faults.Where(f => f.Level == AreaLevel.Error).Select(f => f.Text).FirstOrDefault();
        var headline = worstFault
            ?? (charging is { Outcome: ChargeOutcome.NotCharging } ? "Plugged in, but not charging"
            : dischargingOnAc ? "Plugged in, but battery is discharging"
            : health is { } h ? $"{h}% battery health" : (b.State.Length > 0 ? b.State : "Battery present"));

        var metaParts = new List<string>();
        if (count > 1) metaParts.Add(index == 0 ? "Primary" : index == 1 ? "Secondary" : $"Battery {index + 1}");
        if (b.CycleCount is > 0) metaParts.Add($"{b.CycleCount} cycles");
        var model = string.Join(" ", new[] { b.Manufacturer, b.Model }.Where(x => x.Length > 0));
        if (model.Length > 0) metaParts.Add(model);
        else if (b.Chemistry.Length > 0) metaParts.Add(b.Chemistry);

        var rows = new List<AreaRow>();
        void Add(string l, string? v, AreaLevel lv = AreaLevel.Neutral) { if (!string.IsNullOrWhiteSpace(v)) rows.Add(new(lv, [l, v])); }
        Add("Power state", b.State, dischargingOnAc ? AreaLevel.Warning : AreaLevel.Neutral);
        if (dischargingOnAc)
            Add("Charger warning", b.DischargeRateMw is > 0
                ? $"Battery is draining ({b.DischargeRateMw.Value / 1000.0:0.0} W) while plugged in"
                : "Battery is draining while plugged in", AreaLevel.Warning);
        Add("Current charge", b.PercentRemaining is { } p ? $"{p}%" : null);
        Add("Estimated battery health", health is { } hp ? $"{hp}% of original capacity ({b.WearPercent}% wear)" : "Not reported", healthLevel);
        Add("Design capacity", b.DesignCapacity is > 0 ? $"{N(b.DesignCapacity.Value)} mWh" : null);
        Add("Full charge capacity", b.MaxCapacity is > 0 ? $"{N(b.MaxCapacity.Value)} mWh" : null);
        Add("Cycle count", b.CycleCount is > 0 ? N(b.CycleCount.Value) : "Not reported");
        Add("Battery model", model);
        Add("Chemistry", b.Chemistry);
        if (showCharging)
            Add("Charging check", charging!.Text, charging.Level);
        foreach (var f in faults) Add(f.Label, f.Text, f.Level);
        if (calibration is not null) Add(calibration.Label, calibration.Text, calibration.Level);
        if (b.VoltageMv is { } v)
            Add("Voltage", b.DesignVoltageMv is { } dv ? $"{Volts(v)} (design {Volts(dv)})" : Volts(v));
        if (b.TemperatureC is { } t && faults.All(f => f.Label != "Temperature")) Add("Temperature", Temp(t), AreaLevel.Ok);
        if (faults.Count == 0 && (b.Critical is not null || b.DeviceStatus.Length > 0)) Add("Fault states", "None reported", AreaLevel.Ok);
        Add("Serial number", b.SerialNumber);
        Add("Manufacture date", b.ManufactureDate);
        foreach (var (label, value) in b.VendorDetail) Add(label, value);

        var notes = new List<string>();
        if (dischargingOnAc)
            notes.Add("This PC is plugged in, yet the battery is still draining. Check the charger wattage or USB-C dock — an under-wattage adapter can cause severe slowdowns.");
        if (worn)
            notes.Add("A battery below 70% health holds significantly less charge than when new and may need replacement.");
        foreach (var advice in faults.Select(f => f.Advice).Append(calibration?.Advice).Append(charging?.Level is AreaLevel.Error or AreaLevel.Warning || charging?.Outcome == ChargeOutcome.HeldBelowFull ? charging.Advice : null))
            if (advice is not null && !notes.Contains(advice)) notes.Add(advice);

        var id = index == 0 ? "battery" : $"battery-{index + 1}";
        var title = count > 1 ? $"Battery {index + 1} health" : "Battery health";
        return new(id, title, level, headline, string.Join(" · ", metaParts), ["Detail", "Value"], rows,
            Note: notes.Count > 0 ? string.Join(" ", notes) : null);
    }

    /// <summary>The key metric ids for battery <paramref name="index"/>: "battery.*" for the first (as History always had), "battery2.*" ...</summary>
    public static string MetricPrefix(int index) => index == 0 ? "battery." : $"battery{index + 1}.";

    /// <summary>Each battery's full charge capacity in the newest earlier BatteryPower result in History (older than <paramref name="notAfter"/>),
    /// from the check or the Agent's scheduled pass.</summary>
    public static IReadOnlyList<PreviousCapacity?> PreviousCapacities(IEnumerable<History.HistoryEntry> entries, int count, DateTimeOffset notAfter)
    {
        var result = new PreviousCapacity?[count];
        foreach (var e in entries.Where(e => e.ModuleId == ModuleIds.BatteryPower && e.TimeUtc < notAfter).OrderByDescending(e => e.TimeUtc))
        {
            for (var i = 0; i < count; i++)
            {
                // The check names a second battery "battery2.*"; the Agent's scheduled pass keeps "battery.*" with instance "battery-1".
                var id = e.InstanceId is null ? MetricPrefix(i) + "capacity" : e.InstanceId == $"battery-{i}" ? "battery.capacity" : null;
                if (result[i] is null && id is not null && e.KeyMetrics.FirstOrDefault(m => m.Id == id) is { Value: > 0 } m)
                    result[i] = new(m.Value, e.TimeUtc);
            }
            if (result.All(r => r is not null)) break;
        }
        return result;
    }

    /// <summary>True when the SMBIOS manufacturer (in the registry, readable by any user) is Lenovo.</summary>
    public static bool IsLenovoPc()
    {
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\BIOS");
            return (key?.GetValue("SystemManufacturer") as string ?? "").Trim().StartsWith("LENOVO", StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException) { return false; }
    }

    private static double? VoltageRatio(BatteryStatus b) =>
        b.VoltageMv is { } v && b.DesignVoltageMv is > 0 and var dv ? v / (double)dv : null;

    private static string N(long v) => v.ToString("N0", CultureInfo.InvariantCulture);
    private static string Volts(int? mV) => mV is { } v ? (v / 1000.0).ToString("0.00", CultureInfo.InvariantCulture) + " V" : "?";
    private static string Temp(double c) => c.ToString("0.#", CultureInfo.InvariantCulture) + " °C";
    private static string W(int mW) => (mW / 1000.0).ToString("0.0", CultureInfo.InvariantCulture) + " W";
    private static string Seconds(TimeSpan t) => $"{Math.Max(0, (int)Math.Round(t.TotalSeconds))} s";
}
