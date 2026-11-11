using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Migrations;

namespace RemotePCDiagnostics.Tests;

/// <summary>The one-time move of the app's events from the Application log to its own log.</summary>
public sealed class EventLogMoveMigrationTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "rpd-logmove-" + Guid.NewGuid().ToString("N"));
    private static readonly DateTimeOffset T0 = new(2026, 11, 10, 12, 0, 0, TimeSpan.Zero);
    private DateTimeOffset _now = T0;
    private const string Result = "Test result: DriveHealth\r\nModule id: 6f0f6c06-9d4c-4f55-8d3a-0d6f0e3d4a11\r\nOutcome: OK\r\nSummary: Fine\r\nFinished: 2026-11-01T08:00:00Z\r\nFormat: 3";

    public void Dispose() { try { Directory.Delete(_dir, recursive: true); } catch { } }

    private MigrationMarkers Markers(bool v3Done = true)
    {
        var m = new MigrationMarkers(Path.Combine(_dir, "migrations.json"));
        if (v3Done && !m.IsDone(EventLogV3Migration.MarkerKey)) m.MarkDone(EventLogV3Migration.MarkerKey, T0);
        return m;
    }

    private EventLogMoveMigration Migration(FakeIo io, MigrationMarkers? markers = null) =>
        new(io, markers ?? Markers(), Path.Combine(_dir, "migration"), null, () => _now);

    private static FakeIo OldPc() => new()
    {
        Registered = EventLogMoveMigration.OldLogName,
        Old =
        {
            new(LogEventIds.AppStart, LogLevel.Information, T0.AddDays(-2), "Remote PC Diagnostics started."),
            new(LogEventIds.TestResult, LogLevel.Information, T0.AddDays(-1), Result),
        },
    };

    [Fact]
    public void A_pc_without_earlier_events_is_done_at_once()
    {
        var io = new FakeIo { Registered = null };
        var markers = Markers();

        Assert.Equal(MigrationOutcome.NothingToMigrate, Migration(io, markers).Run());

        Assert.Equal(EventLogMoveMigration.OwnLogName, EventLogMoveMigration.CurrentLogName(markers));
        Assert.Equal(0, io.Moves);
        Assert.Equal(MigrationOutcome.AlreadyDone, Migration(io, markers).Run());
    }

    [Fact]
    public void It_waits_for_the_format_3_update()
    {
        var io = OldPc();
        var markers = Markers(v3Done: false);

        Assert.Equal(MigrationOutcome.Waiting, Migration(io, markers).Run());

        Assert.Equal(0, io.Moves);
        Assert.Equal(EventLogMoveMigration.OldLogName, EventLogMoveMigration.CurrentLogName(markers));
    }

    [Fact]
    public void Without_administrator_nothing_changes()
    {
        var io = OldPc();
        io.IsElevated = false;

        Assert.Equal(MigrationOutcome.NeedsElevation, Migration(io).Run());

        Assert.Equal(0, io.Moves);
        Assert.Empty(io.Own);
    }

    [Fact]
    public void The_events_are_copied_oldest_first_and_the_originals_stay()
    {
        var io = OldPc();
        var markers = Markers();

        Assert.Equal(MigrationOutcome.Completed, Migration(io, markers).Run());

        Assert.Equal(EventLogMoveMigration.OwnLogName, io.Registered);
        var copied = io.Own.Where(e => e.EventId != LogEventIds.LogMoveProbe).ToList();
        Assert.Equal([LogEventIds.AppStart, LogEventIds.TestResult], copied.Select(e => e.EventId));
        Assert.Contains("Logged: ", copied[0].Message);   // keeps its original time in the text
        Assert.Equal(Result, copied[1].Message);          // a result already carries Finished:
        Assert.Equal(2, io.Old.Count);                    // nothing cleared
        Assert.Equal(EventLogMoveMigration.OwnLogName, EventLogMoveMigration.CurrentLogName(markers));
    }

    [Fact]
    public void Until_the_restart_nothing_is_copied_and_what_was_written_meanwhile_is_added_after_it()
    {
        var io = OldPc();
        io.FollowsAfterRestart = true;
        var markers = Markers();

        Assert.Equal(MigrationOutcome.NeedsRestart, Migration(io, markers).Run());
        Assert.Empty(io.Own);
        Assert.Equal(EventLogMoveMigration.OldLogName, EventLogMoveMigration.CurrentLogName(markers)); // History keeps reading Application

        _now = T0.AddMinutes(5);
        io.Write(new(LogEventIds.TestResult, LogLevel.Information, _now, Result.Replace("Fine", "Later"))); // lands in Application
        Assert.Equal(MigrationOutcome.NeedsRestart, Migration(io, markers).Run());
        Assert.Equal(1, io.Moves); // the source is not moved twice

        io.Restart();
        _now = T0.AddHours(1);
        Assert.Equal(MigrationOutcome.Completed, Migration(io, markers).Run());

        var copied = io.Own.Where(e => e.EventId != LogEventIds.LogMoveProbe).ToList();
        Assert.Equal(3, copied.Count);
        Assert.Contains("Later", copied[2].Message);
        Assert.DoesNotContain(copied, e => e.Message.Contains("moving its events", StringComparison.Ordinal)); // no probes copied
    }

    [Fact]
    public void An_interrupted_copy_resumes_without_writing_an_event_twice()
    {
        var io = OldPc();
        io.FailWriteNumber = 2; // the second copied event fails once
        var markers = Markers();

        Assert.Equal(MigrationOutcome.Failed, Migration(io, markers).Run());
        Assert.Equal(MigrationOutcome.Completed, Migration(io, markers).Run());

        var copied = io.Own.Where(e => e.EventId != LogEventIds.LogMoveProbe).ToList();
        Assert.Equal([LogEventIds.AppStart, LogEventIds.TestResult], copied.Select(e => e.EventId));
    }

    private sealed class FakeIo : IEventLogMoveIo
    {
        public bool IsElevated { get; set; } = true;
        public string? Registered { get; set; }
        public List<RawLogEvent> Old { get; } = [];
        public List<RawLogEvent> Own { get; } = [];
        public int Moves;
        /// <summary>Windows keeps sending the source's events to the old log until <see cref="Restart"/>.</summary>
        public bool FollowsAfterRestart;
        public int FailWriteNumber;
        private int _copies;
        private bool _stale;

        public string? SourceLog() => Registered;
        public IReadOnlyList<RawLogEvent> ReadOurEvents(string logName) => [.. (logName == EventLogMoveMigration.OwnLogName ? Own : Old)];
        public void MoveSource()
        {
            if (Registered == EventLogMoveMigration.OwnLogName) return;
            Moves++;
            Registered = EventLogMoveMigration.OwnLogName;
            _stale = FollowsAfterRestart;
        }
        public void Restart() => _stale = false;
        public void Write(RawLogEvent e)
        {
            if (e.EventId != LogEventIds.LogMoveProbe && !_stale && Registered == EventLogMoveMigration.OwnLogName && ++_copies == FailWriteNumber)
                throw new InvalidOperationException("write failed");
            (Registered == EventLogMoveMigration.OwnLogName && !_stale ? Own : Old).Add(e);
        }
        public bool WritesReachOwnLog(string token)
        {
            Write(new(LogEventIds.LogMoveProbe, LogLevel.Information, DateTimeOffset.Now, "moving its events " + token));
            return Own.Any(e => e.Message.Contains(token, StringComparison.Ordinal));
        }
    }
}
