using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.History;
using RemotePCDiagnostics.Core.Logging;

namespace RemotePCDiagnostics.Tests;

public sealed class HistoryTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "rpd-hist-" + Guid.NewGuid().ToString("N"));
    private string FilePath => Path.Combine(_dir, "history.jsonl");
    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    private static HistoryEntry E(DateTimeOffset t, string module = "CpuStress", string outcome = "OK", double? dur = 60, (string, string)[]? m = null) =>
        new(t, module, module + " test", outcome, "summary", dur, null, (m ?? []).Select(x => new HistoryMeasurement(x.Item1, x.Item2)).ToList(), "PC1", "1.0");

    [Fact]
    public void RoundTrip_PersistsAcrossInstances()
    {
        var now = DateTimeOffset.UtcNow;
        var s = new JsonLinesHistoryStore(FilePath);
        s.Append(E(now.AddMinutes(-1), m: [("MaxCpuTemperatureC", "81.5")]));
        s.Append(E(now, "DiskSpeed", "Warning", null));
        Assert.True(s.Flush(TimeSpan.FromSeconds(5)));
        var s2 = new JsonLinesHistoryStore(FilePath);
        var all = s2.ReadAll();
        Assert.Equal(2, all.Count);
        Assert.Equal("81.5", all[0].Measurement("MaxCpuTemperatureC"));
        Assert.Equal("Warning", all[1].Outcome);
        Assert.Null(all[1].DurationSeconds);
        Assert.Equal(now, all[1].TimeUtc);
    }

    [Fact]
    public void Retention_PrunesOldAndCapsCount()
    {
        var now = DateTimeOffset.UtcNow;
        Directory.CreateDirectory(_dir);
        var lines = new List<string> { System.Text.Json.JsonSerializer.Serialize(E(now.AddDays(-100))) };
        for (var i = 0; i < JsonLinesHistoryStore.MaxEntries + 10; i++) lines.Add(System.Text.Json.JsonSerializer.Serialize(E(now.AddMinutes(-i))));
        File.WriteAllLines(FilePath, lines);
        var s = new JsonLinesHistoryStore(FilePath, () => now);
        var all = s.ReadAll();
        Assert.Equal(JsonLinesHistoryStore.MaxEntries, all.Count);
        Assert.All(all, e => Assert.True(e.TimeUtc >= now.AddDays(-90)));
        Assert.Equal(now, all[^1].TimeUtc); // newest kept
        s.Flush(TimeSpan.FromSeconds(10));
        Assert.Equal(JsonLinesHistoryStore.MaxEntries, File.ReadAllLines(FilePath).Length); // file rewritten
    }

    [Fact]
    public void DailyPrune_OnAppend()
    {
        var now = DateTimeOffset.UtcNow;
        var clock = now;
        var s = new JsonLinesHistoryStore(FilePath, () => clock);
        s.Append(E(now));
        clock = now.AddDays(91);
        s.Append(E(clock));
        Assert.Single(s.ReadAll());
    }

    [Fact]
    public void CorruptLines_AreSkipped()
    {
        Directory.CreateDirectory(_dir);
        var s0 = new JsonLinesHistoryStore(FilePath);
        s0.Append(E(DateTimeOffset.UtcNow));
        s0.Flush(TimeSpan.FromSeconds(5));
        File.AppendAllText(FilePath, "{not json\n\n{\"Foo\":1}\n" + "garbage\n");
        var logs = new List<string>();
        var s = new JsonLinesHistoryStore(FilePath, log: logs.Add);
        Assert.Single(s.ReadAll());
        Assert.Equal(3, s.CorruptLinesSkipped);
        Assert.Contains(logs, l => l.Contains("unreadable"));
    }

    [Fact]
    public void Clear_RemovesFileAndEntries()
    {
        var s = new JsonLinesHistoryStore(FilePath);
        var changed = 0; s.Changed += () => changed++;
        s.Append(E(DateTimeOffset.UtcNow));
        s.Flush(TimeSpan.FromSeconds(5));
        s.Clear();
        s.Flush(TimeSpan.FromSeconds(5));
        Assert.Empty(s.ReadAll());
        Assert.False(File.Exists(FilePath));
        Assert.Equal(2, changed);
    }

    [Fact]
    public void UnwritablePath_DoesNotThrow()
    {
        var bad = Path.Combine(_dir, "file-not-dir");
        Directory.CreateDirectory(_dir); File.WriteAllText(bad, "x");
        var s = new JsonLinesHistoryStore(Path.Combine(bad, "history.jsonl"));
        s.Append(E(DateTimeOffset.UtcNow));
        s.Flush(TimeSpan.FromSeconds(5));
        Assert.Single(s.ReadAll()); // kept in memory
    }

    private sealed class ThrowingStore : IHistoryStore
    {
        public void Append(HistoryEntry entry) => throw new IOException("disk full");
        public IReadOnlyList<HistoryEntry> ReadAll() => [];
        public void Clear() { }
        public event Action? Changed { add { } remove { } }
    }

    [Fact]
    public async Task Recorder_LogsOncePerResult_ThrottlesSensors_AndStoreFailureDoesNotAffectRuns()
    {
        var store = new ResultStore();
        var hist = new JsonLinesHistoryStore(FilePath);
        var rec = new HistoryRecorder(hist, n => n == "A" ? "Test A" : n, () => "PC1 (Lenovo 82R4)", "9.9");
        _ = new ResultEventLogger(store, new RecordingSink(), null, rec.Record);
        _ = new ResultEventLogger(store, new RecordingSink(), null, new HistoryRecorder(new ThrowingStore(), n => n, () => "x", "1").Record);
        var svc = new DiagnosticsService(store, [new FakeModule("A", _ => Task.FromResult(new DiagnosticResult("A", DiagnosticStatus.Ok, "fine", DateTimeOffset.Now, new { Peak = 70.5, Note = "C:\\secret\\path" })))]);
        var r = await svc.RunAsync("A");
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        store.Set(r); // same result again
        var e = Assert.Single(hist.ReadAll());
        Assert.Equal("Test A", e.Test);
        Assert.Equal("OK", e.Outcome);
        Assert.Equal("70.5", e.Measurement("Peak"));
        Assert.Null(e.Measurement("Note"));
        Assert.Equal("PC1 (Lenovo 82R4)", e.Machine);
        Assert.NotNull(e.DurationSeconds);

        var name = RemotePCDiagnostics.Core.Sensors.LibreHardwareMonitorModule.ModuleName;
        var t0 = DateTimeOffset.Now;
        for (var i = 0; i < 10; i++) store.Set(new DiagnosticResult(name, DiagnosticStatus.Ok, $"CPU {40 + i}°C", t0.AddSeconds(5 * i)));
        Assert.Equal(2, hist.ReadAll().Count);
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
