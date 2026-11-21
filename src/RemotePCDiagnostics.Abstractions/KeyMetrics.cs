namespace RemotePCDiagnostics.Core;

/// <summary>Which way a key metric should move: History colors a change in the bad direction, and Admin's fleet view flags it.</summary>
public enum MetricTrend { Neutral, HigherIsBetter, LowerIsBetter }

/// <summary>
/// One number a check tracks over time (battery health, free space, peak CPU temperature). The check names it: <see cref="Id"/> is
/// stable ("battery.health") and never reused for another meaning; <see cref="Label"/> and <see cref="Unit"/> are what History shows.
/// Each finished run writes its key metrics to History, so the check card's History can chart them and Admin can compare months.
/// </summary>
public sealed record KeyMetric(string Id, string Label, double Value, string Unit, MetricTrend Better = MetricTrend.Neutral);

/// <summary>A payload that carries its check's key metrics. Most checks set <see cref="Areas.AreaReport.KeyMetrics"/>.</summary>
public interface IKeyMetrics
{
    IReadOnlyList<KeyMetric>? KeyMetrics { get; }
}
