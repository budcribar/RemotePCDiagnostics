namespace RemotePCDiagnostics.Core.Areas;

/// <summary>One battery. <see cref="DesignCapacity"/> and <see cref="MaxCapacity"/> are in mWh; rates are in mW.</summary>
public sealed record BatteryStatus(
    string Model, string Manufacturer, string Chemistry, string State,
    int? PercentRemaining, int? DesignCapacity, int? MaxCapacity, int? CycleCount,
    bool? PowerOnline = null, bool? IsCharging = null, bool? IsDischarging = null,
    int? DischargeRateMw = null, int? ChargeRateMw = null)
{
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
public sealed record PowerPolicySnapshot(string? PowerMode, int? AcMaxProcessorStatePercent);
