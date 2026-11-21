using Bunit;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.History;
using RemotePCDiagnostics.UI.Shared;

namespace RemotePCDiagnostics.Tests;

public sealed class CheckTrendPanelTests : BunitContext
{
    private static readonly DateTimeOffset T0 = new(2026, 8, 24, 18, 0, 0, TimeSpan.Zero);

    internal static HistoryEntry Run(string module, int day, string outcome, string summary, string? instance, params KeyMetric[] metrics) =>
        new(T0.AddDays(day), module, module, outcome, summary, 3, null, [], "PC", "10.0.851")
        {
            InstanceId = instance, Instance = instance is null ? null : "Drive " + instance, KeyMetrics = metrics, Format = 3,
        };

    internal static List<HistoryEntry> Sample()
    {
        var list = new List<HistoryEntry>();
        for (var d = 0; d < 90; d++)
        {
            var health = Math.Round(93 - d * 0.11, 1);
            list.Add(Run("BatteryPower", d, health < 85 ? "Warning" : "OK", $"Battery health {health}%", null,
                new KeyMetric("battery.health", "Battery health", health, "%", MetricTrend.HigherIsBetter),
                new KeyMetric("battery.capacity", "Full charge capacity", Math.Round(520 * health), "mWh", MetricTrend.HigherIsBetter),
                new KeyMetric("battery.cycles", "Charge cycles", 210 + d / 2, "")));
            if (d % 7 == 0)
            {
                list.Add(Run("DriveHealth", d, "OK", "Healthy", "0", new KeyMetric("drive.free", "Free space", 148 - d, "GB", MetricTrend.HigherIsBetter)));
                list.Add(Run("DriveHealth", d, "OK", "Healthy", "1", new KeyMetric("drive.free", "Free space", 900 - d / 3.0, "GB", MetricTrend.HigherIsBetter)));
            }
        }
        list.Add(Run("BatteryPower", 89, "Cancelled", "Cancelled", null));
        return list;
    }

    [Fact]
    public void Battery_ChartsItsFirstTwoNumbers_AndListsRunsNewestFirst()
    {
        var cut = Render<CheckTrendPanel>(p => p.Add(x => x.Module, "BatteryPower").Add(x => x.Entries, Sample()).Add(x => x.HistoryHref, "history?module=BatteryPower"));
        var series = cut.FindAll("[data-testid=checks-trend-series]");
        Assert.Equal(["battery.health", "battery.capacity"], series.Select(s => s.GetAttribute("data-series-id")));
        Assert.Equal("83.2%", cut.Find("[data-testid=checks-trend-latest]").TextContent);
        Assert.Contains("Down 9.8%", cut.Find("[data-testid=checks-trend-change]").TextContent);
        Assert.Contains("⚠", cut.Find("[data-testid=checks-trend-change]").TextContent);
        // 90 runs (the cancelled one left out), 8 shown, newest first.
        var runs = cut.FindAll("[data-testid=checks-trend-run]");
        Assert.Equal(8, runs.Count);
        Assert.Equal("83.2%", runs[0].QuerySelector("[data-testid=checks-trend-value]")!.TextContent);
        Assert.Contains("90", cut.Find("[data-testid=checks-trend-more]").TextContent);
        Assert.Equal("history?module=BatteryPower", cut.Find("[data-testid=checks-trend-open-history]").GetAttribute("href"));
    }

    [Fact]
    public void ClickingARun_ShowsItsSummaryAndNumbers()
    {
        var cut = Render<CheckTrendPanel>(p => p.Add(x => x.Module, "BatteryPower").Add(x => x.Entries, Sample()).Add(x => x.HistoryHref, "history?module=BatteryPower"));
        Assert.Empty(cut.FindAll("[data-testid=checks-trend-run-detail]"));
        cut.FindAll("[data-testid=checks-trend-run] button")[1].Click();
        var detail = cut.Find("[data-testid=checks-trend-run-detail]");
        Assert.Contains("Battery health 83.3%", detail.TextContent);
        Assert.Contains("Charge cycles", detail.TextContent);
        cut.FindAll("[data-testid=checks-trend-run] button")[1].Click();
        Assert.Empty(cut.FindAll("[data-testid=checks-trend-run-detail]"));
    }

    [Fact]
    public void Drives_AreChartedOneAtATime()
    {
        var cut = Render<CheckTrendPanel>(p => p.Add(x => x.Module, "DriveHealth").Add(x => x.Entries, Sample()));
        Assert.Equal(2, cut.FindAll("[data-testid=checks-trend-instance]").Count);
        var first = cut.Find("[data-testid=checks-trend-latest]").TextContent;
        cut.FindAll("[data-testid=checks-trend-instance]")[1].Click();
        Assert.NotEqual(first, cut.Find("[data-testid=checks-trend-latest]").TextContent);
        Assert.Equal("true", cut.FindAll("[data-testid=checks-trend-instance]")[1].GetAttribute("aria-pressed"));
    }

    [Fact]
    public void NoRuns_SaysSo_AndWhileReadingSaysThat()
    {
        Assert.Contains("Reading", Render<CheckTrendPanel>(p => p.Add(x => x.Module, "Sensors")).Markup);
        var cut = Render<CheckTrendPanel>(p => p.Add(x => x.Module, "Sensors").Add(x => x.Entries, Sample()));
        Assert.NotNull(cut.Find("[data-testid=checks-trend-empty]"));
    }

    [Fact]
    public void ChecksPage_HistoryIsAnInPlaceToggle()
    {
        var page = File.ReadAllText(Path.Combine(CheckEnablementTests.FindRepoRoot(), "src", "RemotePCDiagnostics.UI", "Pages", "ChecksPage.razor"));
        Assert.Contains("data-testid=\"checks-detail-history\"", page);
        Assert.Contains("<CheckTrendPanel", page);
        Assert.DoesNotContain("<a class=\"ct-history-link\"", page);
    }
}
