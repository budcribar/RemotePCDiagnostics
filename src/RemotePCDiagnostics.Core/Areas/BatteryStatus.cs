namespace RemotePCDiagnostics.Core.Areas;

/// <summary>One battery. <see cref="DesignCapacity"/> and <see cref="MaxCapacity"/> are in mWh; rates are in mW.</summary>
public sealed record BatteryStatus(
    string Model, string Manufacturer, string Chemistry, string State,
    int? PercentRemaining, int? DesignCapacity, int? MaxCapacity, int? CycleCount,
    bool? PowerOnline = null, bool? IsCharging = null, bool? IsDischarging = null,
    int? DischargeRateMw = null, int? ChargeRateMw = null)
{
    // Condition details (RPCD #281): what the driver's status flags, voltage and identity say. All optional: the osquery path and
    // recordings made before these were read leave them unset, and nothing is judged from a reading that isn't there.

    /// <summary>The battery's WMI instance name (ACPI\PNP0C0A\1_0), so samples taken a few seconds apart are matched to the same battery.</summary>
    public string InstanceName { get; init; } = "";
    /// <summary>Charge left in mWh (BatteryStatus.RemainingCapacity), or null when unknown.</summary>
    public int? RemainingMwh { get; init; }
    /// <summary>What the driver reported as full charge capacity, before unknown values were dropped: 0 here (with a design capacity) is
    /// a corrupt capacity, not a missing one.</summary>
    public long? ReportedFullChargeMwh { get; init; }
    /// <summary>Pack voltage now, in mV (BatteryStatus.Voltage).</summary>
    public int? VoltageMv { get; init; }
    /// <summary>Design voltage in mV (Win32_Battery.DesignVoltage).</summary>
    public int? DesignVoltageMv { get; init; }
    /// <summary>The driver's BATTERY_CRITICAL flag (BatteryStatus.Critical).</summary>
    public bool? Critical { get; init; }
    /// <summary>Windows' own charge estimate in percent (Win32_Battery.EstimatedChargeRemaining), compared with <see cref="PercentRemaining"/>.</summary>
    public int? WindowsPercent { get; init; }
    /// <summary>Win32_Battery.Status: "OK", "Degraded", "Pred Fail", "Error" and so on; empty when not reported.</summary>
    public string DeviceStatus { get; init; } = "";
    /// <summary>Battery temperature in °C (BatteryTemperature, which few drivers fill in), or null.</summary>
    public double? TemperatureC { get; init; }
    public string SerialNumber { get; init; } = "";
    /// <summary>Manufacture date as yyyy-MM-dd, or empty.</summary>
    public string ManufactureDate { get; init; } = "";
    /// <summary>Maker detail read through the Agent (label, value), such as Lenovo's battery information.</summary>
    public IReadOnlyList<KeyValuePair<string, string>> VendorDetail { get; init; } = [];

    /// <summary>Below this health a battery needs attention.</summary>
    public const int LowHealthPercent = 70;

    public int? HealthPercent => DesignCapacity is > 0 && MaxCapacity is > 0
        ? (int)Math.Round(Math.Clamp(MaxCapacity.Value * 100.0 / DesignCapacity.Value, 0, 120))
        : null;

    public int? WearPercent => HealthPercent is { } h ? Math.Max(0, 100 - h) : null;

    /// <summary>True when plugged into AC power (WMI PowerOnline or legacy "AC Power" state).</summary>
    public bool IsOnAc => PowerOnline == true || string.Equals(State, "AC Power", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// True when Windows reports AC power online while the battery is actively discharging (weak charger or USB-C dock).
    /// Deliberately false for "plugged in, not charging" (e.g. Lenovo Conservation mode).
    /// </summary>
    public bool IsDischargingOnAc => PowerOnline == true && (IsDischarging == true || DischargeRateMw is > 0);
}

/// <summary>One reading of WMI <c>Win32_PerfFormattedData_Counters_ProcessorInformation</c> (<c>Name='_Total'</c>).</summary>
public sealed record ProcessorPerformanceSample(int? PerformanceLimitPercent, int? PercentOfMaxFrequency);

/// <summary>Un-elevated Windows power policy snapshot (Power mode overlay and configured AC max processor state).</summary>
public sealed record PowerPolicySnapshot(string? PowerMode, int? AcMaxProcessorStatePercent, bool? AcMaxProcessorStateEditable = null);
