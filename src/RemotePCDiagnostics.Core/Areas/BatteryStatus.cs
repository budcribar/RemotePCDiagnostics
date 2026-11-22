using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>One battery row from osquery <c>battery</c>.</summary>
public sealed record BatteryStatus(
    string Model, string Manufacturer, string Chemistry, string State,
    int? PercentRemaining, int? DesignCapacity, int? MaxCapacity, int? CycleCount)
{
    /// <summary>Below this health a battery needs attention.</summary>
    public const int LowHealthPercent = 70;

    public static BatteryStatus FromRow(IReadOnlyDictionary<string, string> r) => new(
        r.Str("model"), r.Str("manufacturer"), r.Str("chemistry"), r.Str("state"),
        r.Int("percent_remaining"), r.Int("designed_capacity"), r.Int("max_capacity"), r.Int("cycle_count"));

    public int? HealthPercent => DesignCapacity is > 0 && MaxCapacity is > 0
        ? (int)Math.Round(Math.Clamp(MaxCapacity.Value * 100.0 / DesignCapacity.Value, 0, 120))
        : null;

    public int? WearPercent => HealthPercent is { } h ? Math.Max(0, 100 - h) : null;
}
