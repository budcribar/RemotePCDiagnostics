using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.History;
using RemotePCDiagnostics.Core.Logging;

namespace RemotePCDiagnostics.Tests;

public sealed class HistoryTests
{

    private static HistoryEntry E(DateTimeOffset t, string module = "CpuStress", string outcome = "OK", double? dur = 60, (string, string)[]? m = null) =>
        new(t, module, module + " test", outcome, "summary", dur, null, (m ?? []).Select(x => new HistoryMeasurement(x.Item1, x.Item2)).ToList(), "PC1", "1.0");

    private const string OldFormat = "Test result: CpuStress\r\nOutcome: OK\r\nSummary: Passed: no errors\r\nDuration: 61.2 s\r\nStress suite: short run\r\nFinished: 2026-10-30T08:10:00.0000000-06:00\r\nDetails:\r\n  Outcome: Passed\r\n  Ran: 60.0 s\r\n  MaxCpuTemperatureC: 81.5\r\n  SensorsAvailable: yes\r\n  Headline: Passed with flying colours";

    [Fact]
    public void Parser_CurrentFormat_RoundTripsFromWriter()
    {
        var r = new DiagnosticResult("CpuStress", DiagnosticStatus.Ok, "Passed", new DateTimeOffset(2026, 10, 30, 8, 0, 0, TimeSpan.FromHours(-6)),
            new { Outcome = RemotePCDiagnostics.Core.Stress.CpuStressOutcome.Passed, MaxCpuTemperatureC = 81.5, Note = "C:\\x" });
        var msg = ResultEventLogger.Format(r, TimeSpan.FromSeconds(60), "extended run", new ResultEventContext(_ => "CPU stress test", () => "PC1 (LENOVO 82R4)", "1.2.3"));
        Assert.Contains("Format: 2", msg);
        var e = HistoryEventParser.Parse(msg, DateTimeOffset.Now)!;
        Assert.Equal("CpuStress", e.Module);
        Assert.Equal("CPU stress test", e.Test);
        Assert.Equal("OK", e.Outcome);
        Assert.Equal("Passed", e.Summary);
        Assert.Equal(60, e.DurationSeconds);
        Assert.Equal("extended run", e.Suite);
        Assert.Equal("PC1 (LENOVO 82R4)", e.Machine);
        Assert.Equal("1.2.3", e.AppVersion);
        Assert.Equal(r.Timestamp.UtcDateTime, e.TimeUtc.UtcDateTime);
        Assert.Equal("81.5", e.Measurement("MaxCpuTemperatureC"));
        Assert.Null(e.Measurement("Note"));
    }

    [Fact]
    public void Parser_OldFormat_BestEffort()
    {
        var e = HistoryEventParser.Parse(OldFormat, DateTimeOffset.Now)!;
        Assert.Equal("CpuStress", e.Module);
        Assert.Equal("CpuStress", e.Test);
        Assert.Equal("Passed: no errors", e.Summary);
        Assert.Equal(61.2, e.DurationSeconds);
        Assert.Equal("short run", e.Suite);
        Assert.Equal("81.5", e.Measurement("MaxCpuTemperatureC"));
        Assert.Equal("Passed", e.Measurement("Outcome"));
        Assert.Null(e.Measurement("Headline")); // free text dropped
        Assert.Equal("", e.Machine);
        Assert.Equal(new DateTimeOffset(2026, 10, 30, 14, 10, 0, TimeSpan.Zero), e.TimeUtc);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("garbage")]
    [InlineData("Outcome: OK\nSummary: no module line")]
    [InlineData("Test result: X\nSummary: no outcome")]
    public void Parser_SkipsUnparseable(string? msg) => Assert.Null(HistoryEventParser.Parse(msg, DateTimeOffset.Now));

    [Fact]
    public void Parser_BadFinished_FallsBackToEventTime()
    {
        var t = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);
        var e = HistoryEventParser.Parse("Test result: X\nOutcome: Warning\nFinished: not a date\nDuration: ?? s", t)!;
        Assert.Equal(t, e.TimeUtc);
        Assert.Null(e.DurationSeconds);
    }

    [Fact]
    public void XPath_FiltersProviderIdAndRange()
    {
        Assert.Equal("*[System[Provider[@Name='RemotePCDiagnostics'] and (EventID=1100)]]", EventLogHistoryStore.BuildXPath(null));
        Assert.Equal("*[System[Provider[@Name='RemotePCDiagnostics'] and (EventID=1100) and TimeCreated[timediff(@SystemTime) <= 86400000]]]", EventLogHistoryStore.BuildXPath(TimeSpan.FromHours(24)));
    }

    [Fact]
    public void Store_ParsesNewestFirst_SkipsCorrupt_PassesQuery()
    {
        string? xp = null; int max = 0;
        var logs = new List<string>();
        var store = new EventLogHistoryStore((x, m) => { xp = x; max = m; return [new(DateTimeOffset.Now.AddHours(-2), OldFormat), new(DateTimeOffset.Now, "junk"),
            new(DateTimeOffset.Now, "Test result: DiskSpeed\nOutcome: Critical\nFinished: 2026-10-30T15:00:00Z\nFormat: 2")]; }, logs.Add);
        var r = store.Read(TimeSpan.FromDays(7));
        Assert.True(r.Available);
        Assert.Equal(new[] { "DiskSpeed", "CpuStress" }, r.Entries.Select(e => e.Module));
        Assert.Contains("timediff", xp);
        Assert.Equal(EventLogHistoryStore.MaxEvents, max);
        Assert.Contains(logs, l => l.Contains("skipped 1"));
    }

    [Fact]
    public void Store_ReaderThrows_IsUnavailable_NotAnError()
    {
        var logs = new List<string>();
        var r = new EventLogHistoryStore((_, _) => throw new UnauthorizedAccessException("denied"), logs.Add).Read(null);
        Assert.False(r.Available);
        Assert.Empty(r.Entries);
        Assert.Contains("denied", r.Problem);
        Assert.Contains(logs, l => l.Contains("read failed"));
        Assert.False(new NullHistoryStore().Read(null).Available);
    }

    [Fact]
    public void Store_ReaderThrowsMidway_KeepsWhatWasRead()
    {
        static IEnumerable<RawHistoryEvent> Src() { yield return new(DateTimeOffset.Now, OldFormat); throw new InvalidOperationException("log cleared"); }
        var r = new EventLogHistoryStore((_, _) => Src()).Read(null);
        Assert.Single(r.Entries);
        Assert.True(r.Available);
    }

    [Fact]
    public void Filter_ByTestOutcomeAndRange()
    {
        var now = DateTimeOffset.UtcNow;
        var list = new[] { E(now.AddHours(-1)), E(now.AddDays(-3), "DiskSpeed", "Critical"), E(now.AddDays(-20), outcome: "Warning"), E(now.AddDays(-60)) };
        Assert.Single(HistoryQuery.Filter(list, null, null, HistoryRange.Last24Hours, now));
        Assert.Equal(2, HistoryQuery.Filter(list, null, null, HistoryRange.Last7Days, now).Count());
        Assert.Equal(3, HistoryQuery.Filter(list, null, null, HistoryRange.Last30Days, now).Count());
        Assert.Equal(4, HistoryQuery.Filter(list, "", "", HistoryRange.All, now).Count());
        Assert.Equal(3, HistoryQuery.Filter(list, "cpustress", null, HistoryRange.All, now).Count());
        Assert.Single(HistoryQuery.Filter(list, null, "Critical", HistoryRange.All, now));
    }

    [Fact]
    public void Sort_DefaultNewestFirst_AndColumns()
    {
        var now = DateTimeOffset.UtcNow;
        var a = E(now.AddHours(-2), "B", "OK", 10); var b = E(now.AddHours(-1), "A", "Critical", null); var c = E(now, "C", "Warning", 5);
        var list = new[] { a, b, c };
        Assert.Equal(new[] { c, b, a }, HistoryQuery.Sort(list, HistoryQuery.DefaultSort.Col, HistoryQuery.DefaultSort.Desc));
        Assert.Equal(new[] { b, a, c }, HistoryQuery.Sort(list, HistoryColumn.Test, false));
        Assert.Equal(new[] { b, c, a }, HistoryQuery.Sort(list, HistoryColumn.Result, false));
        Assert.Equal(new[] { c, a, b }, HistoryQuery.Sort(list, HistoryColumn.Duration, false)); // missing duration last
        Assert.Equal((HistoryColumn.Test, false), HistoryQuery.Toggle(HistoryQuery.DefaultSort, HistoryColumn.Test));
        Assert.Equal((HistoryColumn.Time, false), HistoryQuery.Toggle(HistoryQuery.DefaultSort, HistoryColumn.Time));
    }

    [Fact]
    public void Trend_UsesKeyMeasurement_OldestFirst()
    {
        var now = DateTimeOffset.UtcNow;
        var list = new[] { E(now, m: [("MaxCpuTemperatureC", "80")]), E(now.AddHours(-1), m: [("MaxCpuTemperatureC", "75.5")]), E(now.AddHours(-2)), E(now, "Osquery") };
        var t = HistoryQuery.Trend(list, "CpuStress");
        Assert.Equal(new[] { 75.5, 80 }, t.Select(p => p.Value));
        Assert.Empty(HistoryQuery.Trend(list, "Osquery"));
    }

    [Fact]
    public void Csv_QuotesFields()
    {
        var csv = HistoryQuery.ToCsv([E(DateTimeOffset.UtcNow) with { Summary = "a, \"b\"" }]);
        Assert.Contains("\"a, \"\"b\"\"\"", csv);
    }
}
