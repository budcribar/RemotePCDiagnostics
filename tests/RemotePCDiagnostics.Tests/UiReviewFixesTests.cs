using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.History;
using RemotePCDiagnostics.Core.Memory;
using RemotePCDiagnostics.Core.Security;
using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Tests;

/// <summary>Regression tests for the UI review (Oct 2026): logic behind what the pages show.</summary>
public class UiReviewFixesTests
{
    private static WinEvent Ev(DateTimeOffset t, string provider, int id, int level = 2, string msg = "Something failed", string channel = "System") =>
        new(t, channel, provider, id, level, msg, [], new Dictionary<string, string>());

    // ---- Event messages: invisible direction marks / '?' artifacts around dates ----
    [Theory]
    [InlineData("The previous system shutdown at 5:36:20 PM on ?10/?29/?2026 was unexpected.", "The previous system shutdown at 5:36:20 PM on 10/29/2026 was unexpected.")]
    [InlineData("on ‎10/‎29/‎2026", "on 10/29/2026")]
    [InlineData("Is it ok? 2 retries", "Is it ok? 2 retries")]
    [InlineData("value?1 stays", "value?1 stays")]
    [InlineData("", "")]
    public void EventMessage_DirectionMarkArtifactsRemoved(string raw, string expected) =>
        Assert.Equal(expected, WindowsEventLog.CleanMessage(raw));

    // ---- Unexpected restarts: Event 41 + 6008 from one bad shutdown count once ----
    [Fact]
    public void PowerLoss_41And6008FromSameBoot_AreOneIncident()
    {
        var now = new DateTimeOffset(2026, 10, 30, 12, 0, 0, TimeSpan.Zero);
        var boot = now.AddHours(-16);
        var events = new[]
        {
            Ev(boot, "Microsoft-Windows-Kernel-Power", 41, 1),
            Ev(boot.AddSeconds(-3), "EventLog", 6008),
            Ev(now.AddDays(-9), "Microsoft-Windows-Kernel-Power", 41, 1),
        };
        Assert.Equal(2, BsodHistoryModule.PowerLossIncidents(events.Where(BsodHistoryModule.IsPowerLossEvent)).Count);
        var rep = BsodHistoryModule.Build(events.Take(2).ToList(), [], now);
        Assert.Equal("1 unexpected restart", rep.Cards.Single(c => c.Id == "power").Headline);
        Assert.StartsWith("1 unexpected restart", rep.Summary);
        Assert.Equal(2, rep.Cards.Single(c => c.Id == "power").Rows.Count); // both events still listed
    }

    // ---- Error lists: identical errors grouped, full message on expand ----
    [Fact]
    public void ErrorLog_IdenticalErrorsGrouped_WithCountAndDetail()
    {
        var t = new DateTimeOffset(2026, 10, 30, 1, 49, 0, TimeSpan.Zero);
        var sys = new List<WinEvent>
        {
            Ev(t, "Microsoft-Windows-Firewall", 2002, msg: "Config Read Failed"),
            Ev(t.AddMinutes(-1), "Microsoft-Windows-Firewall", 2002, msg: "Config Read Failed"),
            Ev(t.AddMinutes(-2), "Microsoft-Windows-Firewall", 2002, msg: "Config Read Failed"),
            Ev(t.AddMinutes(-3), "DistributedCOM", 10005, msg: "DCOM got error \"1115\" attempting to start the service wuauserv\nwith arguments \"Unavailable\""),
        };
        var rep = EventLogModule.Build(sys, []);
        var card = rep.Cards.Single(c => c.Id == "system");
        Assert.Equal(["When", "Source", "Level", "Times", "What happened"], card.Columns);
        Assert.Equal(2, card.Rows.Count);
        var fw = card.Rows.Single(r => r.Values[1] == "Firewall");
        Assert.Equal("3", fw.Values[3]);
        Assert.Contains("Happened 3 times", fw.Detail);
        var dcom = card.Rows.Single(r => r.Values[1] == "DistributedCOM");
        Assert.Contains("with arguments", dcom.Detail); // second line only in the full message
        Assert.Equal("4 errors", card.Headline);          // headline still counts events
    }

    [Fact]
    public void MostFrequent_SortedByTimes_AndDrillsIntoMessages()
    {
        Assert.Equal((2, true), AreaSort.Default(["Source", "Where", "Times", "Last seen"]));
        var t = DateTimeOffset.UtcNow;
        var rep = EventLogModule.Build([Ev(t, ".NET Runtime", 1026, msg: "App X crashed"), Ev(t.AddMinutes(-5), ".NET Runtime", 1026, msg: "App X crashed"), Ev(t, ".NET Runtime", 1026, msg: "App Y crashed")], []);
        var row = Assert.Single(rep.Cards.Single(c => c.Id == "sources").Rows);
        Assert.StartsWith("2× ", row.Detail);
        Assert.Contains("App Y crashed", row.Detail);
    }

    [Theory]
    [InlineData("Times", true)] [InlineData("Memory", true)] [InlineData("When", true)] [InlineData("Source", false)] [InlineData("What happened", false)]
    public void Sort_FirstClickDirection(string column, bool descending) => Assert.Equal(descending, AreaSort.FirstClickDescending(column));

    // ---- Resource hogs: high RAM use is a warning ----
    [Fact]
    public void ResourceHogs_HighRam_Warns_AndSaysUsable()
    {
        var up = new SystemUptimeInfo(3600, 0, 1, 0, false);
        const long gb = 1L << 30;
        var high = ResourceHogsModule.Build(up, [], new MemoryUse(10 * gb, 1 * gb));
        var ram = high.Cards.Single(c => c.Id == "ram");
        Assert.Equal(AreaLevel.Warning, ram.Level);
        Assert.Equal("90% in use", ram.Headline);
        Assert.Contains("usable", ram.Meta);
        Assert.Equal(DiagnosticStatus.Warning, high.Status);
        Assert.Contains("RAM 90% in use", high.Summary);

        var ok = ResourceHogsModule.Build(up, [], new MemoryUse(10 * gb, 6 * gb));
        Assert.Equal(AreaLevel.Ok, ok.Cards.Single(c => c.Id == "ram").Level);
        Assert.Equal(DiagnosticStatus.Ok, ok.Status);
        Assert.DoesNotContain(ResourceHogsModule.Build(up, []).Cards, c => c.Id == "ram"); // not reported: no card
    }

    [Fact]
    public void ResourceHogs_ScriptReadsMemory() => Assert.Contains("TotalVisibleMemorySize", ResourceHogsModule.FastStartupScript);

    // ---- Temperatures text ----
    [Theory]
    [InlineData(0, "fan speed not reported")] [InlineData(1, "1 fan")] [InlineData(3, "3 fans")]
    public void Fans_Text(int n, string expected) => Assert.Equal(expected, LibreHardwareMonitorModule.FansText(n));

    [Fact]
    public void CpuNote_SaysEstimate_WhenApproximateReadingShown()
    {
        var approx = new SensorReading("AMD Ryzen 7 5700U with Radeon Graphics", HardwareKind.Cpu, CpuTemperatureFallback.ApuSensorName, SensorKind.Temperature, 52.7, null, null, "°C");
        Assert.Equal(CpuTemperatureFallback.ApproximateNote, CpuTemperatureFallback.Note([approx], false));
        Assert.DoesNotContain("isn't available", CpuTemperatureFallback.ApproximateNote);
    }

    // ---- Security audit: only high-risk failures are critical ----
    private static AuditFinding F(string sev, AuditOutcome o) => new("1", "Cat", "Name", sev, "1", "0", o);

    [Fact]
    public void SecurityAudit_MediumFailures_AreWarning_HighAreCritical()
    {
        var medium = new SecurityAuditReport([F("Medium", AuditOutcome.Failed), F("Low", AuditOutcome.Warning), F("", AuditOutcome.Passed)]);
        Assert.Equal(DiagnosticStatus.Warning, medium.Status);
        Assert.Equal("1 failed, 1 warning, 1 passed", medium.Summary);
        var high = new SecurityAuditReport([F("High", AuditOutcome.Failed), F("Medium", AuditOutcome.Failed)]);
        Assert.Equal(DiagnosticStatus.Error, high.Status);
        Assert.StartsWith("1 high-risk · 2 failed", high.Summary);
    }

    // ---- History ----
    private sealed class Mod(string name, string display) : IDiagnosticModule
    {
        public string Name => name;
        public Guid Id => TestIds.For(name);
        public string DisplayName => display;
        public event EventHandler<DiagnosticResult>? Updated { add { } remove { } }
        public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct = default) => Task.FromResult(ModuleAvailability.Available);
        public Task<DiagnosticResult> RefreshAsync(IProgress<string>? p, CancellationToken ct = default) => throw new NotSupportedException();
    }

    private static HistoryEntry H(string module, string test, string outcome = "OK") =>
        new(DateTimeOffset.UtcNow, module, test, outcome, "", 1, null, [], "PC", "1.1.0");

    [Fact]
    public void History_MergedAndRenamedModules_ShareOneName()
    {
        IDiagnosticModule[] mods = [new Mod("Crashes", "Crashes & unexpected restarts"), new Mod("Network", "Network & Wi-Fi")];
        var n = HistoryNames.Normalize([
            H("BsodHistory", "Blue screens & unexpected restarts"), H("Crashes", "App crashes"),
            H("WifiConfig", "Wi-Fi & network config"), H("Network", "Network adapters"), H("Gone", "Old test")], mods);
        Assert.Equal(["Crashes", "Crashes", "Network", "Network", "Gone"], n.Select(e => e.Module));
        Assert.Equal(["Crashes & unexpected restarts", "Crashes & unexpected restarts", "Network & Wi-Fi", "Network & Wi-Fi", "Old test"], n.Select(e => e.Test));
        Assert.Equal(3, HistoryNames.FilterOptions(n, mods).Count);
    }

    [Fact]
    public void History_CancelledRunsIgnored()
    {
        var list = HistoryQuery.WithoutCancelled([H("CpuStress", "CPU stress test", "Cancelled"), H("CpuStress", "CPU stress test", "OK"), H("DiskSpeed", "Disk speed test", "Warning")]);
        Assert.Equal(2, list.Count);
        Assert.DoesNotContain("Cancelled", HistoryQuery.Outcomes);
    }

    [Fact]
    public void History_DayLabels()
    {
        var now = new DateTimeOffset(2026, 10, 30, 12, 0, 0, TimeSpan.FromHours(-6));
        Assert.Equal("Today", HistoryQuery.DayLabel(now.AddHours(-3), now));
        Assert.Equal("Yesterday", HistoryQuery.DayLabel(now.AddDays(-1), now));
        Assert.Equal("Tuesday, Oct 27", HistoryQuery.DayLabel(now.AddDays(-3), now));
        Assert.Equal("Monday, Oct 27 2025", HistoryQuery.DayLabel(new DateTimeOffset(2025, 10, 27, 9, 0, 0, now.Offset), now));
    }

    [Fact]
    public void History_GroupByDay_RollsUpAndOrdersByLatestFirst()
    {
        var localNow = DateTimeOffset.Now;
        var today = new DateTimeOffset(localNow.Year, localNow.Month, localNow.Day, 14, 0, 0, localNow.Offset);
        var yesterday = today.AddDays(-1);
        var older = today.AddDays(-3);

        HistoryEntry EntryAt(DateTimeOffset localTime, string module, string outcome) =>
            new(localTime.ToUniversalTime(), module, module, outcome, outcome, 1.5, null, [], "PC", "1.1.0");

        var entries = new[]
        {
            EntryAt(today, "CpuStress", "OK"),
            EntryAt(today.AddHours(-2), "MemoryTest", "Warning"),
            EntryAt(yesterday, "DiskSpeed", "Critical"),
            EntryAt(older, "NetworkTest", "OK"),
        };

        var groups = HistoryQuery.GroupByDay(entries, localNow);
        Assert.Equal(3, groups.Count);
        Assert.Equal("Today", groups[0].Label);
        Assert.Equal(2, groups[0].Entries.Count);
        Assert.Equal("2 runs", groups[0].CountText);
        Assert.Equal(1, groups[0].PassedCount);
        Assert.Equal(1, groups[0].WarningCount);
        Assert.Equal(0, groups[0].CriticalCount);

        Assert.Equal("Yesterday", groups[1].Label);
        Assert.Single(groups[1].Entries);
        Assert.Equal("1 run", groups[1].CountText);
        Assert.Equal(1, groups[1].CriticalCount);

        var ascGroups = HistoryQuery.GroupByDay(entries, localNow, ascendingDays: true);
        Assert.Equal(groups[2].Date, ascGroups[0].Date);
        Assert.Equal(groups[0].Date, ascGroups[2].Date);

        var fixes = new[]
        {
            new FixHistoryItem(today.ToUniversalTime(), "Disk cleanup", "Local user", true, "Cleaned temp files", "+500 MB disk"),
            new FixHistoryItem(yesterday.ToUniversalTime(), "Service (Restart)", "Local user", false, "Restart failed", null),
        };
        var fixGroups = HistorySummary.GroupFixesByDay(fixes, localNow);
        Assert.Equal(2, fixGroups.Count);
        Assert.Equal("Today", fixGroups[0].Label);
        Assert.Equal(1, fixGroups[0].AppliedCount);
        Assert.Equal(0, fixGroups[0].FailedCount);
        Assert.Equal("Yesterday", fixGroups[1].Label);
        Assert.Equal(0, fixGroups[1].AppliedCount);
        Assert.Equal(1, fixGroups[1].FailedCount);
    }

    [Theory]
    [InlineData("MaxCpuTemperatureC", "Peak CPU temperature (°C)")]
    [InlineData("ChunksDone", "Work units completed")]
    [InlineData("EarlyThroughputChunksPerSec", "Early throughput chunks per sec")]
    [InlineData("LatencyMs", "Latency ms")]
    [InlineData("CPUCount", "CPU count")]
    public void History_MeasurementLabels(string raw, string expected) => Assert.Equal(expected, HistoryLabels.Measurement(raw));

    [Fact]
    public void History_OutcomeMeasurementHidden() => Assert.True(HistoryLabels.IsHidden("Outcome"));

    [Fact]
    public void TimeAgo()
    {
        var now = new DateTimeOffset(2026, 10, 30, 12, 0, 0, TimeSpan.Zero);
        Assert.Equal("just now", TimeText.Ago(now.AddSeconds(-20), now));
        Assert.Equal("5 min ago", TimeText.Ago(now.AddMinutes(-5), now));
    }

    // ---- App names ----
    [Theory]
    [InlineData("claude", "Claude")] [InlineData("chrome", "Chrome")] [InlineData("Grok Bot", "Grok")] [InlineData("RPD", "RPD")] [InlineData("myApp", "myApp")]
    public void FriendlyAppNames(string process, string expected) => Assert.Equal(expected, MemoryText.FriendlyAppName(process));

    // ---- Last run from earlier sessions ----
    [Fact]
    public void LatestByModule_NewestNonCancelled()
    {
        var t = DateTimeOffset.UtcNow;
        HistoryEntry At(string module, string outcome, int minutesAgo) => new(t.AddMinutes(-minutesAgo), module, module, outcome, outcome, 1, null, [], "PC", "1.1.0");
        var latest = HistoryQuery.LatestByModule([At("SecurityAudit", "Critical", 120), At("SecurityAudit", "Cancelled", 5), At("CpuStress", "OK", 30), At("CpuStress", "Warning", 10)]);
        Assert.Equal("Critical", latest["SecurityAudit"].Outcome);
        Assert.Equal("Warning", latest["cpustress"].Outcome);
    }
}
