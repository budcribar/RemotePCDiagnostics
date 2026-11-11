using System.Text.Json;
using System.Text.Json.Serialization;
using RemotePCDiagnostics.Core.Logging;

namespace RemotePCDiagnostics.Core.Migrations;

/// <summary>The Windows Event Log operations <see cref="EventLogMoveMigration"/> needs.</summary>
public interface IEventLogMoveIo
{
    /// <summary>Registering an event source needs administrator.</summary>
    bool IsElevated { get; }
    /// <summary>The log the app's source is registered to, or null when it is not registered.</summary>
    string? SourceLog();
    /// <summary>Every event of the app's source in <paramref name="logName"/>, oldest first, without the "Build:" line the sink adds.</summary>
    IReadOnlyList<RawLogEvent> ReadOurEvents(string logName);
    /// <summary>Registers the source under the app's own log (removing it from any other log first) and sets the log's size.
    /// Safe to call again.</summary>
    void MoveSource();
    /// <summary>Writes an event through the source. Windows decides which log it lands in.</summary>
    void Write(RawLogEvent e);
    /// <summary>Writes a marker event and reports whether it arrived in the app's own log. After a source moves, Windows
    /// can keep sending its events to the old log until the PC restarts.</summary>
    bool WritesReachOwnLog(string token);
}

/// <summary>
/// One-time move of the app's events from the shared Application log to its own log (Event Viewer > Applications and
/// Services Logs > RemotePCDiagnostics). Windows cannot move or delete single events, so: the app's events are read from
/// Application and saved to logmove.json, the source is registered under the new log, and - once Windows really sends the
/// source's events there, which can take a restart - the saved events and anything written in between are written into the
/// new log, oldest first. Nothing is cleared: the originals stay in Application until Windows overwrites them. Each written
/// event is ticked off, so an interrupted run resumes. Runs only after the format 3 update, which works on Application.
/// </summary>
public sealed class EventLogMoveMigration(IEventLogMoveIo io, MigrationMarkers markers, string workDir, ILogger? log = null,
    Func<DateTimeOffset>? now = null, ModuleCatalog? catalog = null)
{
    public const string MarkerKey = "eventlog-own-log";
    public const string StateFile = "logmove.json";
    public const string OldLogName = "Application";
    public const string OwnLogName = "RemotePCDiagnostics";

    /// <summary>The log History reads and Event Viewer shows the app's events in: its own once the move is done.</summary>
    public static string CurrentLogName(MigrationMarkers markers) => markers.IsDone(MarkerKey) ? OwnLogName : OldLogName;

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
    private DateTimeOffset Now => now?.Invoke() ?? DateTimeOffset.Now;
    private string StatePath => Path.Combine(workDir, StateFile);

    /// <summary>Runs whatever part of the move is possible now. Never throws.</summary>
    public MigrationOutcome Run()
    {
        try
        {
            if (markers.IsDone(MarkerKey)) return MigrationOutcome.AlreadyDone;
            if (!markers.IsDone(EventLogV3Migration.MarkerKey)) return MigrationOutcome.Waiting; // that update clears and refills Application

            var state = Load();
            if (state is null)
            {
                var registered = io.SourceLog();
                if (registered is null || string.Equals(registered, OwnLogName, StringComparison.OrdinalIgnoreCase))
                {
                    markers.MarkDone(MarkerKey, Now); // a PC without earlier events: the source is created in the new log
                    return MigrationOutcome.NothingToMigrate;
                }
                if (!io.IsElevated) { Log("waits for an elevated start"); return MigrationOutcome.NeedsElevation; }
                var events = io.ReadOurEvents(OldLogName).Where(e => e.EventId != LogEventIds.LogMoveProbe).Select(ToPending).ToList();
                state = new State(false, null, false, events);
                Save(state);
                Log($"{events.Count} events saved from {OldLogName}");
            }
            if (!io.IsElevated) { Log("waits for an elevated start"); return MigrationOutcome.NeedsElevation; }

            if (!state.Moved)
            {
                io.MoveSource();
                state = state with { Moved = true, MovedAt = Now };
                Save(state);
                Log($"source registered under the {OwnLogName} log");
            }

            if (!io.WritesReachOwnLog(Guid.NewGuid().ToString("N")))
            {
                Log($"Windows still sends events to {OldLogName}; the move finishes after a restart");
                return MigrationOutcome.NeedsRestart;
            }

            if (!state.CaughtUp)
            {
                // Written after the source moved but before Windows followed (until the restart).
                var late = io.ReadOurEvents(OldLogName)
                    .Where(e => e.EventId != LogEventIds.LogMoveProbe && state.MovedAt is { } moved && e.TimeCreated > moved)
                    .Select(ToPending).ToList();
                state = state with { CaughtUp = true, Events = [.. state.Events, .. late] };
                Save(state);
                if (late.Count > 0) Log($"{late.Count} events written since the move were added");
            }

            var list = state.Events.ToList();
            try
            {
                for (var i = 0; i < list.Count; i++)
                {
                    if (list[i].Written) continue;
                    io.Write(new RawLogEvent(list[i].EventId, list[i].Level, Now, list[i].Message));
                    list[i] = list[i] with { Written = true };
                    if (i % 20 == 19) Save(state with { Events = list });
                }
            }
            finally { Save(state with { Events = list }); }

            markers.MarkDone(MarkerKey, Now);
            try { File.Move(StatePath, Path.Combine(workDir, "logmove.done.json"), overwrite: true); } catch { }
            Log($"finished: {list.Count} events in the {OwnLogName} log");
            return MigrationOutcome.Completed;
        }
        catch (Exception ex)
        {
            try { log.Error($"Event log move: failed: {ex.GetType().Name}: {ex.Message}"); } catch { }
            return MigrationOutcome.Failed;
        }
    }

    /// <summary>The text as written into the new log: a test result keeps its own Finished: time; anything else gets a
    /// "Logged:" line with its original time (the copy's own time is the time of the move).</summary>
    private PendingEvent ToPending(RawLogEvent e) => new(e.EventId, e.Level, EventLogV3Migration.Convert(e, catalog) ?? e.Message);

    private State? Load()
    {
        try { return File.Exists(StatePath) ? JsonSerializer.Deserialize<State>(File.ReadAllText(StatePath), Json) : null; }
        catch (JsonException) { return null; }
    }

    private void Save(State s)
    {
        Directory.CreateDirectory(workDir);
        var tmp = StatePath + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(s, Json));
        File.Move(tmp, StatePath, overwrite: true);
    }

    private void Log(string m) { try { log.Info("Event log move: " + m); } catch { } }

    public sealed record PendingEvent(int EventId, LogLevel Level, string Message, bool Written = false);
    public sealed record State(bool Moved, DateTimeOffset? MovedAt, bool CaughtUp, IReadOnlyList<PendingEvent> Events);
}
