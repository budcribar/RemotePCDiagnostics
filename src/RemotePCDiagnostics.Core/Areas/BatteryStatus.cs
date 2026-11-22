namespace RemotePCDiagnostics.Core.Areas;

/// <summary>One battery. <see cref="DesignCapacity"/> and <see cref="MaxCapacity"/> are in mWh.</summary>
public sealed record BatteryStatus(
    string Model, string Manufacturer, string Chemistry, string State,
    int? PercentRemaining, int? DesignCapacity, int? MaxCapacity, int? CycleCount)
{
    /// <summary>Below this health a battery needs attention.</summary>
    public const int LowHealthPercent = 70;

    public int? HealthPercent => DesignCapacity is > 0 && MaxCapacity is > 0
        ? (int)Math.Round(Math.Clamp(MaxCapacity.Value * 100.0 / DesignCapacity.Value, 0, 120))
        : null;

    public int? WearPercent => HealthPercent is { } h ? Math.Max(0, 100 - h) : null;
}
