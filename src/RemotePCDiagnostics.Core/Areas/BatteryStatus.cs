using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>One battery from osquery <c>battery</c>. <see cref="DesignCapacity"/> and <see cref="MaxCapacity"/> are in mWh.</summary>
public sealed record BatteryStatus(
    string Model, string Manufacturer, string Chemistry, string State,
    int? PercentRemaining, int? DesignCapacity, int? MaxCapacity, int? CycleCount)
{
    /// <summary>Below this health a battery needs attention.</summary>
    public const int LowHealthPercent = 70;

    /// <summary>
    /// On Windows, osquery's <c>battery</c> table divides the capacities Windows reports in mWh by an assumed 12 V, to show them in
    /// mAh like its macOS table (osquery/tables/system/windows/battery.cpp). Multiplying back gives mWh again, to within 12 mWh.
    /// </summary>
    public const int OsqueryAssumedVolts = 12;

    /// <summary>One row of osquery <c>battery</c>, with the capacities in mWh.</summary>
    public static BatteryStatus FromRow(IReadOnlyDictionary<string, string> r) => new(
        r.Str("model"), r.Str("manufacturer"), r.Str("chemistry"), r.Str("state"),
        r.Int("percent_remaining"), ToMilliwattHours(r.Int("designed_capacity")), ToMilliwattHours(r.Int("max_capacity")), r.Int("cycle_count"));

    private static int? ToMilliwattHours(int? osqueryMilliampHours) => osqueryMilliampHours * OsqueryAssumedVolts;

    public int? HealthPercent => DesignCapacity is > 0 && MaxCapacity is > 0
        ? (int)Math.Round(Math.Clamp(MaxCapacity.Value * 100.0 / DesignCapacity.Value, 0, 120))
        : null;

    public int? WearPercent => HealthPercent is { } h ? Math.Max(0, 100 - h) : null;
}
