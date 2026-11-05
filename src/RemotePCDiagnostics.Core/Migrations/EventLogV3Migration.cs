using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using RemotePCDiagnostics.Core.History;
using RemotePCDiagnostics.Core.Logging;

namespace RemotePCDiagnostics.Core.Migrations;

/// <summary>One event of this app's source in the Application log, as read for (and written back by) the migration.</summary>
public sealed record RawLogEvent(int EventId, LogLevel Level, DateTimeOffset TimeCreated, string Message);

/// <summary>The Windows Event Log operations the migration needs (Host: EventLogReader, wevtutil, EventLog.WriteEntry).</summary>
public interface IEventLogMigrationIo
{
    /// <summary>Clearing the log needs administrator.</summary>
    bool IsElevated { get; }
    /// <summary>Every event of source RemotePCDiagnostics in the Application log, oldest first, message text without the "Build:" line the sink adds.</summary>
    IReadOnlyList<RawLogEvent> ReadOurEvents();
    /// <summary>wevtutil epl Application &lt;path&gt;: a copy of the whole log, so other programs' events can still be opened later.</summary>
    void Backup(string evtxPath);
    /// <summary>wevtutil cl Application.</summary>
    void Clear();
    /// <summary>Writes the event back under source RemotePCDiagnostics with its id, level and message.</summary>
    void Write(RawLogEvent e);
}

/// <summary>Done markers in %ProgramData%\RemotePCDiagnostics\migrations.json: { "eventlog-v3": "&lt;completed time&gt;" }.</summary>
public sealed class MigrationMarkers(string path)
{
    public static string DefaultPath() =>
        System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "RemotePCDiagnostics", "migrations.json");

    public string Path => path;

    public bool IsDone(string key) => Read().ContainsKey(key);

    public void MarkDone(string key, DateTimeOffset when)
    {
        var all = Read();
        all[key] = when.ToString("O", CultureInfo.InvariantCulture);
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(all, new JsonSerializerOptions { WriteIndented = true }));
        File.Move(tmp, path, overwrite: true);
    }

    private Dictionary<string, string> Read()
    {
        try
        {
            return File.Exists(path) ? JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(path)) ?? [] : [];
        }
        catch (JsonException) { return []; }
    }
}

public enum MigrationOutcome
{
    /// <summary>The marker says it already ran.</summary>
    AlreadyDone,
    /// <summary>No old-format events (every PC except the one that had history before format 3): marker written, log untouched.</summary>
    NothingToMigrate,
    /// <summary>Old events exist but this start isn't elevated; History shows "history update pending" until an elevated start.</summary>
    NeedsElevation,
    /// <summary>Stopped before clearing the log (an event didn't convert, or the backup failed); retried next start.</summary>
    Failed,
    /// <summary>Converted, cleared, written back and marked done.</summary>
    Completed,
}

/// <summary>
/// One-time conversion of this app's Event Log history to format 3 (every test result gets "Module id:"). Windows can't edit single
/// events, so the log is backed up, the converted events are saved to pending.json, the Application log is cleared and the events are
/// written back oldest first. Each written event is ticked off in pending.json, so an interrupted run resumes on the next start instead
/// of re-reading the cleared log. The marker is written last. Delete this class once the PCs with old history are done.
/// </summary>
public sealed class EventLogV3Migration(IEventLogMigrationIo io, MigrationMarkers markers, string workDir, ILogger? log = null,
    Func<DateTimeOffset>? now = null, ModuleCatalog? catalog = null)
{
    public const string MarkerKey = "eventlog-v3";
    public const string PendingFile = "pending.json";

    public static string DefaultWorkDir() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "RemotePCDiagnostics", "migration");

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };
    private DateTimeOffset Now => now?.Invoke() ?? DateTimeOffset.Now;
    private string PendingPath => Path.Combine(workDir, PendingFile);

    /// <summary>Runs the migration if it is needed and possible. Never throws.</summary>
    public MigrationOutcome Run()
    {
        try
        {
            if (markers.IsDone(MarkerKey)) return MigrationOutcome.AlreadyDone;
            if (LoadPending() is { Cleared: true } resume)
            {
                if (!io.IsElevated) { Log("an interrupted history update waits for an elevated start"); return MigrationOutcome.NeedsElevation; }
                Log($"resuming: {resume.Events.Count(e => !e.Written)} of {resume.Events.Count} events left to write");
                return WriteBack(resume);
            }

            var events = io.ReadOurEvents();
            var legacy = events.Count(IsLegacyResult);
            if (legacy == 0)
            {
                markers.MarkDone(MarkerKey, Now);
                return MigrationOutcome.NothingToMigrate;
            }
            if (!io.IsElevated) { Log($"{legacy} old-format results wait for an elevated start"); return MigrationOutcome.NeedsElevation; }

            Directory.CreateDirectory(workDir);
            var backup = Path.Combine(workDir, $"Application-{Now.ToUniversalTime():yyyyMMdd-HHmmss}.evtx");
            try { io.Backup(backup); }
            catch (Exception ex) { LogWarn($"backup failed, log not cleared: {ex.Message}"); return MigrationOutcome.Failed; }

            var converted = new List<PendingEvent>(events.Count);
            foreach (var e in events)
            {
                var text = Convert(e, catalog);
                if (text is null) { Log($"an event from {e.TimeCreated:O} did not convert; log not cleared, retrying next start"); return MigrationOutcome.Failed; }
                converted.Add(new PendingEvent(e.EventId, e.Level, text));
            }
            var pending = new PendingState(backup, false, converted);
            SavePending(pending);

            io.Clear();
            pending = pending with { Cleared = true };
            SavePending(pending);
            Log($"Application log cleared (backup {backup}); writing back {converted.Count} events");
            return WriteBack(pending);
        }
        catch (Exception ex)
        {
            LogError($"failed: {ex.GetType().Name}: {ex.Message}");
            return MigrationOutcome.Failed;
        }
    }

    private MigrationOutcome WriteBack(PendingState pending)
    {
        var events = pending.Events.ToList();
        try
        {
            for (var i = 0; i < events.Count; i++)
            {
                if (events[i].Written) continue;
                io.Write(new RawLogEvent(events[i].EventId, events[i].Level, Now, events[i].Message));
                events[i] = events[i] with { Written = true };
                if (i % 20 == 19) SavePending(pending with { Events = events });
            }
        }
        finally { SavePending(pending with { Events = events }); } // a failed write resumes after the last written event
        markers.MarkDone(MarkerKey, Now);
        try { File.Move(PendingPath, Path.Combine(workDir, "pending.done.json"), overwrite: true); } catch { }
        Log($"history update finished: {events.Count} events in format {ResultEventLogger.FormatVersion}");
        return MigrationOutcome.Completed;
    }

    /// <summary>A test result (1100) written before format 3.</summary>
    public static bool IsLegacyResult(RawLogEvent e) =>
        e.EventId == LogEventIds.TestResult && HistoryEventParser.Parse(e.Message, e.TimeCreated) is { IsLegacy: true };

    /// <summary>
    /// The event's text as written back. A legacy test result is rewritten in format 3 from what the parser reads (keeping its own
    /// Finished: time, which History prefers over the write time). Other events keep their text and get a "Logged:" line with their
    /// original time. Null when a test result can't be parsed.
    /// </summary>
    public static string? Convert(RawLogEvent e, ModuleCatalog? catalog = null)
    {
        if (e.EventId != LogEventIds.TestResult) return WithLogged(e);
        var entry = HistoryEventParser.Parse(e.Message, e.TimeCreated);
        if (entry is null) return null;
        if (!entry.IsLegacy) return e.Message;
        return Format3(entry, HistoryIds.For(entry.Module, catalog));
    }

    private static string WithLogged(RawLogEvent e) =>
        e.Message.Contains("\nLogged: ", StringComparison.Ordinal) || e.Message.StartsWith("Logged: ", StringComparison.Ordinal) ? e.Message
            : e.Message.TrimEnd() + Environment.NewLine + "Logged: " + e.TimeCreated.ToString("O", CultureInfo.InvariantCulture);

    /// <summary>Format 3 text for a parsed entry: the same fields <see cref="ResultEventLogger.Format"/> writes.</summary>
    public static string Format3(HistoryEntry e, Guid moduleId)
    {
        static string One(string? s) => (s ?? "").Replace("\r", " ").Replace("\n", " ").Trim();
        var sb = new StringBuilder();
        sb.Append("Test result: ").Append(e.Module).AppendLine();
        sb.Append("Module id: ").Append(moduleId.ToString("D")).AppendLine();
        if (!string.IsNullOrWhiteSpace(e.Test)) sb.Append("Test: ").Append(One(e.Test)).AppendLine();
        if (e.InstanceId is { Length: > 0 } instanceKey)
        {
            sb.Append("Instance id: ").Append(One(instanceKey)).AppendLine();
            if (!string.IsNullOrWhiteSpace(e.Instance)) sb.Append("Instance: ").Append(One(e.Instance)).AppendLine();
        }
        sb.Append("Outcome: ").Append(e.Outcome).AppendLine();
        sb.Append("Summary: ").Append(One(e.Summary)).AppendLine();
        if (e.DurationSeconds is { } d) sb.Append("Duration: ").Append(d.ToString("0.0", CultureInfo.InvariantCulture)).AppendLine(" s");
        if (!string.IsNullOrEmpty(e.Suite)) sb.Append("Stress suite: ").Append(e.Suite).AppendLine();
        sb.Append("Finished: ").Append(e.TimeUtc.ToString("O", CultureInfo.InvariantCulture)).AppendLine();
        if (!string.IsNullOrEmpty(e.Machine)) sb.Append("Machine: ").Append(One(e.Machine)).AppendLine();
        if (!string.IsNullOrEmpty(e.AppVersion)) sb.Append("App version: ").Append(e.AppVersion).AppendLine();
        sb.Append("Format: ").Append(ResultEventLogger.FormatVersion).AppendLine();
        if (e.Measurements.Count > 0)
        {
            sb.AppendLine("Measurements:");
            foreach (var m in e.Measurements) sb.Append("  ").Append(m.Name).Append('=').AppendLine(One(m.Value));
        }
        if (e.Details is { Count: > 0 } details)
        {
            sb.AppendLine("Details:");
            foreach (var line in details) sb.Append("  ").AppendLine(line);
        }
        return sb.ToString().TrimEnd();
    }

    private PendingState? LoadPending()
    {
        try { return File.Exists(PendingPath) ? JsonSerializer.Deserialize<PendingState>(File.ReadAllText(PendingPath), Json) : null; }
        catch (JsonException) { return null; }
    }

    private void SavePending(PendingState p)
    {
        Directory.CreateDirectory(workDir);
        var tmp = PendingPath + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(p, Json));
        File.Move(tmp, PendingPath, overwrite: true);
    }

    private void Log(string m) => log.Info("History update (event log format 3): " + m);
    private void LogWarn(string m) => log.Warn("History update (event log format 3): " + m);
    private void LogError(string m) => log.Error("History update (event log format 3): " + m);

    public sealed record PendingEvent(int EventId, LogLevel Level, string Message, bool Written = false);
    public sealed record PendingState(string Backup, bool Cleared, IReadOnlyList<PendingEvent> Events);
}
