using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.History;
using RemotePCDiagnostics.Core.Logging;

namespace RemotePCDiagnostics.Tests;

public sealed class HistoryTrendsTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 1, 12, 0, 0, TimeSpan.Zero);

    private static HistoryEntry Logged(object payload, string module, DateTimeOffset at, string? instance = null)
    {
        var r = new DiagnosticResult(module, DiagnosticStatus.Ok, "summary", at, payload) { InstanceKey = instance, InstanceLabel = instance is null ? null : "Drive " + instance };
        return HistoryEventParser.Parse(ResultEventLogger.Format(r, null), at)!;
    }

    [Fact]
    public void KeyMetricText_RoundTrips_AndKeepsAnyLabelText()
    {
        var k = new KeyMetric("battery.health", "Battery | health: = ok", 87.25, "%", MetricTrend.HigherIsBetter);
        var back = KeyMetricText.Parse(KeyMetricText.Format(k))!;
        Assert.Equal(("battery.health", 87.25, "%", MetricTrend.HigherIsBetter), (back.Id, back.Value, back.Unit, back.Better));
        Assert.Equal("Battery | health: = ok", back.Label);
        Assert.Null(KeyMetricText.Parse("broken"));
        Assert.Null(KeyMetricText.Parse("x=NaN|%|Neutral|X"));
        Assert.Null(KeyMetricText.Parse("x=12|%"));
    }

    [Fact]
    public void BatteryKeyMetrics_AreWrittenToHistory_AndReadBack()
    {
        var report = BatteryPowerModule.Build([new BatteryStatus("M", "Acme", "LiOn", "Charging", 80, 50000, 43500, 312)], "Balanced");
        var e = Logged(report, "BatteryPower", T0);
        Assert.Equal(["battery.health", "battery.capacity", "battery.cycles"], e.KeyMetrics.Select(k => k.Id));
        Assert.Equal(87, e.KeyMetrics[0].Value);
        Assert.Equal("87%", HistoryTrends.KeyValue(e));
        // The card observations are still recorded as before.
        Assert.Contains(e.Measurements, m => m.Name == "Battery health");
    }

    [Fact]
    public void NoBattery_HasNoKeyMetrics()
    {
        var e = Logged(BatteryPowerModule.Build([], "Balanced"), "BatteryPower", T0);
        Assert.Empty(e.KeyMetrics);
        Assert.Null(HistoryTrends.KeyValue(e));
    }

    [Fact]
    public void ResourceHogs_TracksMemoryInUse()
    {
        var report = ResourceHogsModule.Build(null, [], new MemoryUse(16L << 30, 12L << 30));
        Assert.Contains(report.KeyMetrics!, k => k.Id == "memory.used" && k.Better == MetricTrend.LowerIsBetter);
    }

    [Fact]
    public void Series_FollowRunsOldestFirst_AndSayWhichWayTheyMoved()
    {
        AreaReport Battery(int max) => BatteryPowerModule.Build([new BatteryStatus("M", "Acme", "LiOn", "Charging", 80, 50000, max, 300)], "Balanced");
        var entries = new[] { Logged(Battery(45000), "BatteryPower", T0), Logged(Battery(44000), "BatteryPower", T0.AddDays(10)), Logged(Battery(43000), "BatteryPower", T0.AddDays(20)) };
        var runs = HistoryTrends.Runs(entries, "batterypower");
        Assert.Equal(T0.AddDays(20), runs[0].TimeUtc);
        var health = HistoryTrends.Series(runs)[0];
        Assert.Equal("battery.health", health.Id);
        Assert.Equal([90.0, 88.0, 86.0], health.Points.Select(p => p.Value));
        Assert.True(health.Worsening);
        Assert.StartsWith("Down 4%", health.ChangeText());
    }

    [Fact]
    public void Runs_OfOneDrive_LeaveOtherDrivesOut()
    {
        var a = new AreaReport([], "ok", DiagnosticStatus.Ok) { KeyMetrics = [new("drive.free", "Free space", 100, "GB", MetricTrend.HigherIsBetter)] };
        var b = a with { KeyMetrics = [new("drive.free", "Free space", 900, "GB", MetricTrend.HigherIsBetter)] };
        var entries = new[] { Logged(a, "DriveHealth", T0, "d1"), Logged(b, "DriveHealth", T0, "d2"), Logged(a with { KeyMetrics = [new("drive.free", "Free space", 80, "GB", MetricTrend.HigherIsBetter)] }, "DriveHealth", T0.AddDays(1), "d1") };
        Assert.Equal(2, HistoryTrends.Instances(entries).Count);
        var free = Assert.Single(HistoryTrends.Series(HistoryTrends.Runs(entries, "DriveHealth", "d1")));
        Assert.Equal([100.0, 80.0], free.Points.Select(p => p.Value));
    }

    [Fact]
    public void StressTests_WrittenBeforeKeyMetrics_StillChart()
    {
        var e = new HistoryEntry(T0, "CpuStress", "CPU stress", "OK", "s", 60, null, [new("MaxCpuTemperatureC", "81.5")], "PC", "1.0");
        var k = Assert.Single(HistoryTrends.Metrics(e));
        Assert.Equal((81.5, "°C", MetricTrend.LowerIsBetter), (k.Value, k.Unit, k.Better));
    }

    [Fact]
    public void HistoryData_CarriesKeyMetrics_OnlyWhenTheRunHasThem()
    {
        var battery = Logged(BatteryPowerModule.Build([new BatteryStatus("M", "Acme", "LiOn", "Charging", 80, 50000, 43500, 312)], "Balanced"), "BatteryPower", T0);
        var none = Logged(BatteryPowerModule.Build([], "Balanced"), "BatteryPower", T0.AddDays(-1));
        using var doc = System.Text.Json.JsonDocument.Parse(AgentExports.History([battery, none], [], "30d", true));
        var entries = doc.RootElement.GetProperty("entries");
        var health = entries[0].GetProperty("keyMetrics")[0];
        Assert.Equal("battery.health", health.GetProperty("id").GetString());
        Assert.Equal(87, health.GetProperty("value").GetDouble());
        Assert.Equal("87%", health.GetProperty("text").GetString());
        Assert.False(entries[1].TryGetProperty("keyMetrics", out _));
    }
}
