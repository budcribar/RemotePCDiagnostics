using System.Diagnostics;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Migrations;

namespace RemotePCDiagnostics.Host;

/// <summary>Event Log access for <see cref="EventLogMoveMigration"/>.</summary>
public sealed class WindowsEventLogMoveIo : IEventLogMoveIo
{
    public bool IsElevated => App.IsAdministrator();

    public string? SourceLog()
    {
        if (!OperatingSystem.IsWindows() || !EventLog.SourceExists(EventLogSink.SourceName)) return null;
        var name = EventLog.LogNameFromSourceName(EventLogSink.SourceName, ".");
        return string.IsNullOrEmpty(name) ? null : name;
    }

    public IReadOnlyList<RawLogEvent> ReadOurEvents(string logName) => WindowsEventLogMigrationIo.ReadOurEvents(logName);

    public void MoveSource()
    {
        if (!OperatingSystem.IsWindows()) return;
        var current = SourceLog();
        if (current is not null && !string.Equals(current, EventLogSink.OwnLogName, StringComparison.OrdinalIgnoreCase))
            EventLog.DeleteEventSource(EventLogSink.SourceName); // a log cannot be named like a source of another log
        EventLogSink.CreateOwnLog();
    }

    public void Write(RawLogEvent e)
    {
        if (!OperatingSystem.IsWindows()) return;
        using var el = new EventLog { Source = EventLogSink.SourceName };
        var type = e.Level switch { LogLevel.Error => EventLogEntryType.Error, LogLevel.Warning => EventLogEntryType.Warning, _ => EventLogEntryType.Information };
        el.WriteEntry(LogText.Truncate(e.Message) + Environment.NewLine + "Build: " + RemotePCDiagnostics.Core.AppBuildInfo.Version, type, e.EventId);
    }

    public bool WritesReachOwnLog(string token)
    {
        if (!OperatingSystem.IsWindows()) return false;
        Write(new RawLogEvent(LogEventIds.LogMoveProbe, LogLevel.Information, DateTimeOffset.Now, $"Remote PC Diagnostics is moving its events to its own log.{Environment.NewLine}Check: {token}"));
        var recent = $" and (EventID={LogEventIds.LogMoveProbe}) and TimeCreated[timediff(@SystemTime) <= 60000]";
        for (var attempt = 0; attempt < 10; attempt++)
        {
            try
            {
                if (WindowsEventLogMigrationIo.ReadOurEvents(EventLogSink.OwnLogName, recent).Any(e => e.Message.Contains(token, StringComparison.Ordinal))) return true;
            }
            catch (System.Diagnostics.Eventing.Reader.EventLogException) { /* the new log is not readable yet */ }
            Thread.Sleep(200);
        }
        return false;
    }
}
