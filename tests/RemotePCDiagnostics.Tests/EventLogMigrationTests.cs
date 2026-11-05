using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.History;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Migrations;

namespace RemotePCDiagnostics.Tests;

/// <summary>The one-time event log format 3 migration, on real format 2 and pre-format event text.</summary>
public sealed class EventLogMigrationTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "rpd-migration-" + Guid.NewGuid().ToString("N"));
    private string MarkersPath => Path.Combine(_dir, "migrations.json");
    private string WorkDir => Path.Combine(_dir, "migration");
    private static readonly DateTimeOffset T0 = new(2026, 10, 30, 14, 0, 0, TimeSpan.Zero);

    public void Dispose() { try { Directory.Delete(_dir, recursive: true); } catch { } }

    // Format 2, as ResultEventLogger wrote it before module ids (Build: line already stripped by the reader).
    private const string Format2 = "Test result: DriveHealth\r\nTest: Drive health\r\nOutcome: Warning\r\nSummary: 1 drive needs attention\r\nDuration: 4.2 s\r\n" +
        "Finished: 2026-10-30T08:00:00.0000000-06:00\r\nMachine: BUDSLAPTOP (LENOVO 82R4)\r\nApp version: 1.2.0\r\nFormat: 2\r\nMeasurements:\r\n  Drives=2\r\n  Worst=Samsung 990 Pro: 87% life left";
    // Before the Format line existed: measurements only as numeric Details lines.
    private const string NoFormat = "Test result: CpuStress\r\nOutcome: OK\r\nSummary: Passed: no errors\r\nDuration: 61.2 s\r\nStress suite: short run\r\n" +
        "Finished: 2026-10-29T08:10:00.0000000-06:00\r\nDetails:\r\n  Ran: 60.0 s\r\n  MaxCpuTemperatureC: 81.5";
    private const string Merged = "Test result: BsodHistory\r\nTest: Blue screens & unexpected restarts\r\nOutcome: OK\r\nSummary: None\r\nFinished: 2026-10-28T08:00:00Z\r\nFormat: 2";
    private const string Fix = "Test result: Remediation\r\nTest: Disk cleanup\r\nOutcome: OK\r\nSummary: Freed 2 GB\r\nFinished: 2026-10-28T09:00:00Z\r\nFormat: 2\r\nMeasurements:\r\n  Kind=CleanTempFiles\r\n  Actor=Local";
    private const string AppStart = "Remote PC Diagnostics started (Local).";
    private const string MemorySuggestion = "Memory suggestion applied\r\nActor: Local user\r\nResult: Success\r\nMessage: Done: Closed Chrome. Freed about 640 MB.";

    private static List<RawLogEvent> OldLog() =>
    [
        new(LogEventIds.AppStart, LogLevel.Information, T0.AddDays(-3), AppStart),
        new(LogEventIds.TestResult, LogLevel.Information, T0.AddDays(-2), Merged),
        new(LogEventIds.TestResult, LogLevel.Information, T0.AddDays(-2).AddHours(1), Fix),
        new(LogEventIds.MemorySuggestion, LogLevel.Information, T0.AddDays(-2).AddHours(2), MemorySuggestion),
        new(LogEventIds.TestResult, LogLevel.Information, T0.AddDays(-1), NoFormat),
        new(LogEventIds.TestResult, LogLevel.Warning, T0, Format2),
    ];

    private EventLogV3Migration Migration(FakeLog io, List<string>? logs = null) =>
        new(io, new MigrationMarkers(MarkersPath), WorkDir, l => logs?.Add(l), () => T0.AddDays(1));

    [Fact]
    public void Format2_converts_to_format3_with_the_module_id_and_keeps_every_field()
    {
        var text = EventLogV3Migration.Convert(new(LogEventIds.TestResult, LogLevel.Warning, T0, Format2))!;
        Assert.Contains($"Module id: {ModuleIds.DriveHealth}", text);
        Assert.Contains("Format: 3", text);
        var e = HistoryEventParser.Parse(text, T0.AddDays(5))!;
        Assert.False(e.IsLegacy);
        Assert.Equal(ModuleIds.DriveHealth, e.ModuleId);
        Assert.Equal("DriveHealth", e.Module);
        Assert.Equal("Drive health", e.Test);
        Assert.Equal("Warning", e.Outcome);
        Assert.Equal("1 drive needs attention", e.Summary);
        Assert.Equal(4.2, e.DurationSeconds);
        Assert.Equal(new DateTimeOffset(2026, 10, 30, 14, 0, 0, TimeSpan.Zero), e.TimeUtc); // its own Finished time, not the write time
        Assert.Equal("BUDSLAPTOP (LENOVO 82R4)", e.Machine);
        Assert.Equal("1.2.0", e.AppVersion);
        Assert.Equal("2", e.Measurement("Drives"));
        Assert.Equal("Samsung 990 Pro: 87% life left", e.Measurement("Worst"));
    }

    [Fact]
    public void Events_without_a_format_line_keep_their_measurements()
    {
        var text = EventLogV3Migration.Convert(new(LogEventIds.TestResult, LogLevel.Information, T0, NoFormat))!;
        var e = HistoryEventParser.Parse(text, T0.AddDays(5))!;
        Assert.Equal(ModuleIds.CpuStress, e.ModuleId);
        Assert.Equal("81.5", e.Measurement("MaxCpuTemperatureC"));
        Assert.Equal("short run", e.Suite);
        Assert.Equal(61.2, e.DurationSeconds);
    }

    [Fact]
    public void Fix_records_and_unknown_modules_get_stable_ids()
    {
        var fix = HistoryEventParser.Parse(EventLogV3Migration.Convert(new(LogEventIds.TestResult, LogLevel.Information, T0, Fix)), T0)!;
        Assert.Equal(HistoryIds.Remediation, fix.ModuleId);
        Assert.Equal("CleanTempFiles", fix.Measurement("Kind"));
        var gone = "Test result: SomethingRemoved\r\nOutcome: OK\r\nFormat: 2";
        var a = HistoryEventParser.Parse(EventLogV3Migration.Convert(new(LogEventIds.TestResult, LogLevel.Information, T0, gone)), T0)!;
        var b = HistoryEventParser.Parse(EventLogV3Migration.Convert(new(LogEventIds.TestResult, LogLevel.Information, T0, gone)), T0)!;
        Assert.Equal(a.ModuleId, b.ModuleId);
        Assert.NotEqual(Guid.Empty, a.ModuleId);
        Assert.Equal(HistoryIds.FromName("somethingremoved"), a.ModuleId);
    }

    [Fact]
    public void Other_events_keep_their_text_and_original_time()
    {
        var text = EventLogV3Migration.Convert(new(LogEventIds.MemorySuggestion, LogLevel.Information, T0, MemorySuggestion))!;
        Assert.StartsWith(MemorySuggestion, text);
        var e = HistoryEventParser.Parse(text, T0.AddDays(9))!;
        Assert.Equal(T0, e.TimeUtc);
        Assert.Equal(HistoryIds.MemoryOptimization, e.ModuleId);
        Assert.Equal(text, EventLogV3Migration.Convert(new(LogEventIds.MemorySuggestion, LogLevel.Information, T0, text))); // not added twice
    }

    [Fact]
    public void A_pc_without_old_events_is_marked_done_and_the_log_is_never_cleared()
    {
        var io = new FakeLog([new(LogEventIds.AppStart, LogLevel.Information, T0, AppStart)]) { IsElevated = false };
        Assert.Equal(MigrationOutcome.NothingToMigrate, Migration(io).Run());
        Assert.Equal(0, io.Clears);
        Assert.Equal(0, io.Backups);
        Assert.True(new MigrationMarkers(MarkersPath).IsDone(EventLogV3Migration.MarkerKey));
        Assert.Equal(MigrationOutcome.AlreadyDone, Migration(io).Run());
    }

    [Fact]
    public void Old_events_wait_for_an_elevated_start()
    {
        var io = new FakeLog(OldLog()) { IsElevated = false };
        Assert.Equal(MigrationOutcome.NeedsElevation, Migration(io).Run());
        Assert.Equal(0, io.Clears);
        Assert.False(new MigrationMarkers(MarkersPath).IsDone(EventLogV3Migration.MarkerKey));
    }

    [Fact]
    public void Full_run_backs_up_clears_and_writes_everything_back_oldest_first_in_format_3()
    {
        var io = new FakeLog(OldLog());
        var logs = new List<string>();
        Assert.Equal(MigrationOutcome.Completed, Migration(io, logs).Run());
        Assert.Equal(1, io.Backups);
        Assert.Equal(1, io.Clears);
        Assert.Equal(6, io.Events.Count);
        Assert.Equal(OldLog().Select(e => e.EventId), io.Events.Select(e => e.EventId));
        Assert.Equal(LogLevel.Warning, io.Events[^1].Level);
        Assert.DoesNotContain(io.Events, EventLogV3Migration.IsLegacyResult);
        Assert.True(new MigrationMarkers(MarkersPath).IsDone(EventLogV3Migration.MarkerKey));
        Assert.True(File.Exists(Path.Combine(WorkDir, "pending.done.json")));
        Assert.False(File.Exists(Path.Combine(WorkDir, EventLogV3Migration.PendingFile)));

        // History reads every result back, with its id, its own time, and the merged module under its new home.
        var store = new EventLogHistoryStore((_, _) => io.Events.Where(e => e.EventId is LogEventIds.TestResult or LogEventIds.MemorySuggestion)
            .Select(e => new RawHistoryEvent(e.TimeCreated, e.Message)));
        var read = store.Read(null);
        Assert.Equal(0, read.LegacyEntries);
        Assert.Equal(5, read.Entries.Count);
        var named = HistoryNames.Normalize(read.Entries, new ModuleCatalog());
        Assert.Contains(named, e => e.Module == ModuleSlugs.Crashes && e.ModuleId == ModuleIds.Crashes);
        Assert.Contains(named, e => e.ModuleId == ModuleIds.DriveHealth && e.TimeUtc == T0);

        Assert.Equal(MigrationOutcome.AlreadyDone, Migration(io).Run());
        Assert.Equal(1, io.Clears);
    }

    [Fact]
    public void An_event_that_does_not_convert_stops_before_the_log_is_cleared()
    {
        var log = OldLog();
        log.Add(new(LogEventIds.TestResult, LogLevel.Information, T0.AddHours(1), "not a result at all"));
        var io = new FakeLog(log);
        Assert.Equal(MigrationOutcome.Failed, Migration(io).Run());
        Assert.Equal(0, io.Clears);
        Assert.False(new MigrationMarkers(MarkersPath).IsDone(EventLogV3Migration.MarkerKey));
    }

    [Fact]
    public void A_failed_backup_stops_before_the_log_is_cleared()
    {
        var io = new FakeLog(OldLog()) { FailBackup = true };
        Assert.Equal(MigrationOutcome.Failed, Migration(io).Run());
        Assert.Equal(0, io.Clears);
    }

    [Fact]
    public void An_interrupted_write_resumes_from_pending_without_reading_the_cleared_log()
    {
        var io = new FakeLog(OldLog()) { FailWriteAfter = 3 };
        Assert.Equal(MigrationOutcome.Failed, Migration(io).Run());
        Assert.Equal(1, io.Clears);
        Assert.Equal(3, io.Events.Count);
        Assert.True(File.Exists(Path.Combine(WorkDir, EventLogV3Migration.PendingFile)));

        io.FailWriteAfter = null;
        io.Reads = 0;
        Assert.Equal(MigrationOutcome.Completed, Migration(io).Run());
        Assert.Equal(0, io.Reads);
        Assert.Equal(1, io.Clears);
        Assert.Equal(6, io.Events.Count);
        Assert.Equal(6, io.Events.Select(e => e.Message).Distinct().Count());
    }

    private sealed class FakeLog(List<RawLogEvent> events) : IEventLogMigrationIo
    {
        public List<RawLogEvent> Events { get; } = events;
        public bool IsElevated { get; set; } = true;
        public bool FailBackup { get; set; }
        public int? FailWriteAfter { get; set; }
        public int Backups, Clears, Reads;
        private int _writes;

        public IReadOnlyList<RawLogEvent> ReadOurEvents() { Reads++; return Events.OrderBy(e => e.TimeCreated).ToList(); }
        public void Backup(string evtxPath) { if (FailBackup) throw new IOException("disk full"); Backups++; File.WriteAllText(evtxPath, "evtx"); }
        public void Clear() { Clears++; Events.Clear(); }
        public void Write(RawLogEvent e)
        {
            if (FailWriteAfter is { } n && _writes >= n) throw new InvalidOperationException("power cut");
            _writes++;
            Events.Add(e);
        }
    }
}
