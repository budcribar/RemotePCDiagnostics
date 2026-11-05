using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.History;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests;

public sealed class HistoryTests
{
    [Fact]
    public void Expansion_LegacyGenericFieldsAreHidden_AndDetailsAreNotRepeated()
    {
        var entry = E(DateTimeOffset.UtcNow, m: [("Cards", "3 item(s)"), ("Summary", "summary"), ("Status", "Ok"), ("Latency", "26 ms")])
            with { Details = ["Cards: 3 item(s)", "Summary: summary", "Status: Ok", "Latency: 26 ms", "Useful extra detail"] };
        Assert.Equal("Latency", Assert.Single(HistoryPresentation.Measurements(entry)).Name);
        Assert.Equal("Useful extra detail", Assert.Single(HistoryPresentation.Details(entry)));
        var old = entry with { Measurements = entry.Measurements.Take(3).ToList(), Details = entry.Details!.Take(3).ToList() };
        Assert.Empty(HistoryPresentation.Measurements(old));
        Assert.Empty(HistoryPresentation.Details(old));
    }

    [Fact]
    public void AreaResult_RoundTripsCardObservations_WithoutGenericCountsOrDuplicateDetails()
    {
        var payload = new AreaReport([new AreaCard("dns", "DNS lookup", AreaLevel.Ok, "26 ms", "Current: 39 ms", [], [])], "Network healthy", DiagnosticStatus.Ok);
        var result = new DiagnosticResult("Network", DiagnosticStatus.Ok, payload.Summary, DateTimeOffset.UtcNow, payload);
        var entry = HistoryEventParser.Parse(ResultEventLogger.Format(result, null), DateTimeOffset.UtcNow)!;
        var measurement = Assert.Single(HistoryPresentation.Measurements(entry));
        Assert.Equal("DNS lookup", measurement.Name);
        Assert.Contains("26 ms", measurement.Value);
        Assert.Contains("Current: 39 ms", measurement.Value);
        Assert.Empty(HistoryPresentation.Details(entry));
    }

    private static HistoryEntry E(DateTimeOffset t, string module = "CpuStress", string outcome = "OK", double? dur = 60, (string, string)[]? m = null) =>
        new(t, module, module + " test", outcome, "summary", dur, null, (m ?? []).Select(x => new HistoryMeasurement(x.Item1, x.Item2)).ToList(), "PC1", "1.0");

    private const string OldFormat = "Test result: CpuStress\r\nOutcome: OK\r\nSummary: Passed: no errors\r\nDuration: 61.2 s\r\nStress suite: short run\r\nFinished: 2026-10-30T08:10:00.0000000-06:00\r\nDetails:\r\n  Outcome: Passed\r\n  Ran: 60.0 s\r\n  MaxCpuTemperatureC: 81.5\r\n  SensorsAvailable: yes\r\n  Headline: Passed with flying colours";

    [Fact]
    public void Parser_CurrentFormat_RoundTripsFromWriter()
    {
        var r = new DiagnosticResult("CpuStress", DiagnosticStatus.Ok, "Passed", new DateTimeOffset(2026, 10, 30, 8, 0, 0, TimeSpan.FromHours(-6)),
            new { Outcome = RemotePCDiagnostics.Core.Stress.CpuStressOutcome.Passed, MaxCpuTemperatureC = 81.5, Note = "C:\\x" });
        var msg = ResultEventLogger.Format(r, TimeSpan.FromSeconds(60), "extended run", new ResultEventContext(_ => "CPU stress test", () => "PC1 (LENOVO 82R4)", "1.2.3"));
        Assert.Contains("Format: 3", msg);
        Assert.Contains($"Module id: {ModuleIds.CpuStress}", msg);
        var e = HistoryEventParser.Parse(msg, DateTimeOffset.Now)!;
        Assert.Equal("CpuStress", e.Module);
        Assert.Equal(ModuleIds.CpuStress, e.ModuleId);
        Assert.Equal(3, e.Format);
        Assert.False(e.IsLegacy);
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
        Assert.True(e.IsLegacy);
        Assert.Equal(Guid.Empty, e.ModuleId);
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
        Assert.Equal("*[System[Provider[@Name='RemotePCDiagnostics'] and (EventID=1100 or EventID=1400)]]", EventLogHistoryStore.BuildXPath(null));
        Assert.Equal("*[System[Provider[@Name='RemotePCDiagnostics'] and (EventID=1100 or EventID=1400) and TimeCreated[timediff(@SystemTime) <= 86400000]]]", EventLogHistoryStore.BuildXPath(TimeSpan.FromHours(24)));
        var memEvt = HistoryEventParser.Parse("Memory suggestion applied\r\nActor: Remote technician\r\nSuggestion: close-chrome\r\nAction: CloseApp\r\nTarget: chrome\r\nResult: Success\r\nMessage: Done: Closed Chrome. Freed about 640 MB. Available RAM 4.0 → 4.6 GB.", DateTimeOffset.UtcNow)!;
        Assert.Equal(HistorySummary.MemoryFixModuleId, memEvt.Module);
        Assert.Equal("OK", memEvt.Outcome);
        Assert.Equal((640L * 1024 * 1024).ToString(), memEvt.Measurement("FreedMemoryBytes"));
        Assert.Equal("Remote technician", memEvt.Measurement("Actor"));
    }

    [Fact]
    public void Store_ParsesNewestFirst_SkipsCorrupt_PassesQuery()
    {
        string? xp = null; int max = 0;
        var logs = new List<string>();
        var store = new EventLogHistoryStore((x, m) => { xp = x; max = m; return [new(DateTimeOffset.Now.AddHours(-2), OldFormat), new(DateTimeOffset.Now, "junk"),
            new(DateTimeOffset.Now, $"Test result: DiskSpeed\nModule id: {ModuleIds.DiskSpeed}\nOutcome: Critical\nFinished: 2026-10-30T15:00:00Z\nFormat: 3"),
            new(DateTimeOffset.Now.AddHours(-1), $"Test result: CpuStress\nModule id: {ModuleIds.CpuStress}\nOutcome: OK\nFinished: 2026-10-30T14:00:00Z\nFormat: 3"),
            new(DateTimeOffset.Now, "Test result: DiskSpeed\nOutcome: OK\nFormat: 2")]; }, logs.Add);
        var r = store.Read(TimeSpan.FromDays(7));
        Assert.True(r.Available);
        Assert.Equal(new[] { "DiskSpeed", "CpuStress" }, r.Entries.Select(e => e.Module));
        Assert.Equal(2, r.LegacyEntries); // OldFormat and the format 2 event wait for the migration
        Assert.Contains(logs, l => l.Contains("2 event(s) in the old format"));
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
        static IEnumerable<RawHistoryEvent> Src() { yield return new(DateTimeOffset.Now, $"Test result: CpuStress\nModule id: {ModuleIds.CpuStress}\nOutcome: OK\nFormat: 3"); throw new InvalidOperationException("log cleared"); }
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

    private sealed class NamedModule(string name, string display) : IDiagnosticModule
    {
        public string Name => name;
        public Guid Id => TestIds.For(name);
        public string DisplayName => display;
        public event EventHandler<DiagnosticResult>? Updated { add { } remove { } }
        public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct = default) => Task.FromResult(ModuleAvailability.Available);
        public Task<DiagnosticResult> RefreshAsync(IProgress<string>? p, CancellationToken ct = default) => throw new NotSupportedException();
    }

    private static readonly IDiagnosticModule[] Mods = [new NamedModule("DriveHealth", "Drive health"), new NamedModule("EventLog", "Windows error log")];

    [Fact]
    public void Names_MapOldModuleIdsToDisplayName_FallbackToId()
    {
        Assert.Equal("Drive health", HistoryNames.DisplayName("DriveHealth", Mods));
        Assert.Equal("Drive health", HistoryNames.DisplayName("drivehealth", Mods));
        Assert.Equal("Mystery", HistoryNames.DisplayName("Mystery", Mods));
        var now = DateTimeOffset.UtcNow;
        var old = HistoryEventParser.Parse("Test result: DriveHealth\nOutcome: OK", now)!;
        var fresh = HistoryEventParser.Parse("Test result: DriveHealth\nTest: Drive health\nOutcome: OK\nFormat: 2", now)!;
        var unknown = HistoryEventParser.Parse("Test result: Gone\nOutcome: OK", now)!;
        var n = HistoryNames.Normalize([old, fresh, unknown], Mods);
        Assert.Equal(new[] { "Drive health", "Drive health", "Gone" }, n.Select(e => e.Test));
    }

    [Fact]
    public void Names_FilterOptions_OnePerModule_IncludesUnknown_AndFilterMatchesOldAndNew()
    {
        var now = DateTimeOffset.UtcNow;
        var entries = HistoryNames.Normalize([
            HistoryEventParser.Parse("Test result: DriveHealth\nOutcome: OK", now)!,
            HistoryEventParser.Parse("Test result: DriveHealth\nTest: Drive health\nOutcome: OK\nFormat: 2", now)!,
            HistoryEventParser.Parse("Test result: EventLog\nOutcome: Warning", now)!,
            HistoryEventParser.Parse("Test result: Legacy\nOutcome: OK", now)!], Mods);
        var opts = HistoryNames.FilterOptions(entries, Mods);
        Assert.Equal(new[] { ("DriveHealth", "Drive health"), ("Legacy", "Legacy"), ("EventLog", "Windows error log") }, opts);
        Assert.Equal(2, HistoryQuery.Filter(entries, "DriveHealth", null, HistoryRange.All, now).Count());
    }

    [Fact]
    public void Parser_KeepsDetailLines_Capped()
    {
        var msg = "Test result: X\nOutcome: OK\nDetails:\n" + string.Concat(Enumerable.Range(0, 60).Select(i => $"  Line {i}: value {i}\n"));
        var e = HistoryEventParser.Parse(msg, DateTimeOffset.Now)!;
        Assert.Equal(HistoryEventParser.MaxDetailLines, e.Details!.Count);
        Assert.Equal("Line 0: value 0", e.Details[0]);
        var old = HistoryEventParser.Parse(OldFormat, DateTimeOffset.Now)!;
        Assert.Contains("Headline: Passed with flying colours", old.Details!);
    }

    private sealed class StubServiceBackend : IServiceControlBackend
    {
        public ServiceState State = ServiceState.Running;
        public ServiceState GetState(string n) => State;
        public bool IsDriver(string n) => false;
        public IReadOnlyList<DependentService> GetRunningDependents(string n) => [];
        public void Start(string n) => State = ServiceState.Running;
        public void Stop(string n) => State = ServiceState.Stopped;
        public Task<bool> WaitForStateAsync(string n, ServiceState t, TimeSpan to, CancellationToken ct) => Task.FromResult(true);
    }

    [Theory]
    [InlineData("PhoneSvc", 2)]
    [InlineData("WSL", 30)]
    [InlineData("SysMain", 60)]
    [InlineData("Lenovo", 120)]
    public async Task Summary_DeduplicatesServiceStop_TriggeredFromMemoryOptimization(string service, double stopDurationSeconds)
    {
        var svcActions = new ServiceActionService(new StubServiceBackend(), new SessionContext(SessionMode.Local));
        var info = new ServiceInfo(service, service, "RUNNING", "AUTO_START", "LocalSystem", "");
        await svcActions.ExecuteAsync(info, ServiceAction.Stop);

        // Both event streams stamp completion, so even a long service stop is within the dedup window.
        var now = DateTimeOffset.UtcNow;
        var persistedSvc = new HistoryEntry(now, HistorySummary.ServiceFixModuleId, "Service (Stop)", "OK",
            service + " stopped", stopDurationSeconds, null, [new("Action", "Stop"), new("Actor", "Local user"), new("Service", service)], "PC1", "1.0");
        var persistedMem = new HistoryEntry(now.AddSeconds(2), HistorySummary.MemoryFixModuleId, "Memory optimization", "OK",
            $"Done: {service} stopped until the next restart. No measurable change. Available RAM 4.0 → 4.0 GB (used 75% → 75%).",
            null, null, [new("Actor", "Local user")], "PC1", "1.0");

        var summary = HistorySummary.Build([persistedSvc, persistedMem], services: svcActions, now: now);
        Assert.Single(summary.Fixes);
        Assert.Equal(1, summary.TotalFixesCount);
        Assert.Equal(1, summary.SuccessfulFixesCount);
        Assert.Equal(1, summary.MemoryFixesCount);
        Assert.Equal(0, summary.ServicesAdjustedCount);
        Assert.StartsWith($"Done: {service} stopped until the next restart.", summary.Fixes[0].Summary);
    }
}
