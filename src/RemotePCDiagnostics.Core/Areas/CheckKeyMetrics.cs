namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// The key metrics of the checks whose numbers the app's module and the Agent's scheduled pass both measure, so the two always name
/// them the same (History and Admin chart one series per id). Drives are in <see cref="DriveHealthModule.KeyMetrics"/>, temperatures in
/// <see cref="Sensors.SensorReport.KeyMetrics"/>.
/// </summary>
public static class CheckKeyMetrics
{
    /// <summary>Health falling (or capacity dropping) faster than normal is the early sign of a battery to replace.</summary>
    /// <param name="index">Which battery: the first keeps the "battery.*" ids, a second one is "battery2.*" and so on.</param>
    public static IReadOnlyList<KeyMetric> Battery(BatteryStatus b, int index = 0)
    {
        var list = new List<KeyMetric>();
        var id = BatteryCondition.MetricPrefix(index);
        var n = index == 0 ? "" : $"Battery {index + 1}: ";
        if (b.HealthPercent is { } h) list.Add(new(id + "health", n + "Battery health", h, "%", MetricTrend.HigherIsBetter));
        if (b.MaxCapacity is > 0) list.Add(new(id + "capacity", n + "Full charge capacity", b.MaxCapacity.Value, "mWh", MetricTrend.HigherIsBetter));
        if (b.CycleCount is > 0) list.Add(new(id + "cycles", n + "Charge cycles", b.CycleCount.Value, ""));
        return list;
    }

    /// <summary>Memory in use creeping up as junk piles up.</summary>
    public static KeyMetric MemoryUsed(int percent) => new("memory.used", "Memory in use", percent, "%", MetricTrend.LowerIsBetter);

    /// <summary>How long the PC goes between restarts.</summary>
    public static KeyMetric Uptime(TimeSpan up) => new("uptime.days", "Days since restart", Math.Round(Math.Max(0, up.TotalDays), 1), "days", MetricTrend.LowerIsBetter);
}
