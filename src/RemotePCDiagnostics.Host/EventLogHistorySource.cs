using System.Diagnostics.Eventing.Reader;
using RemotePCDiagnostics.Core.History;

namespace RemotePCDiagnostics.Host;

/// <summary>Reads RemotePCDiagnostics 1100 events, newest first (EventLogReader + XPath), from the app's own log, or from
/// Application until the one-time move there is done (<see cref="RemotePCDiagnostics.Core.Migrations.EventLogMoveMigration"/>).
/// Failures surface as exceptions handled by <see cref="EventLogHistoryStore"/>.</summary>
public static class EventLogHistorySource
{
    public static IHistoryStore Create(ILogger? log) =>
        OperatingSystem.IsWindows() ? new EventLogHistoryStore(Query, log) : new NullHistoryStore();

    private static IEnumerable<RawHistoryEvent> Query(string xpath, int max)
    {
        var logName = RemotePCDiagnostics.Core.Migrations.EventLogMoveMigration.CurrentLogName(
            new RemotePCDiagnostics.Core.Migrations.MigrationMarkers(RemotePCDiagnostics.Core.Migrations.MigrationMarkers.DefaultPath()));
        var q = new EventLogQuery(logName, PathType.LogName, xpath) { ReverseDirection = true };
        var list = new List<RawHistoryEvent>();
        using var reader = new EventLogReader(q);
        for (var i = 0; i < max; i++)
        {
            using var rec = reader.ReadEvent();
            if (rec is null) break;
            string? msg;
            try { msg = rec.FormatDescription(); } catch { msg = null; }
            // Without a registered message file Windows can't format; the raw insertion string is our text.
            if (string.IsNullOrEmpty(msg)) try { msg = rec.Properties.Count > 0 ? rec.Properties[0].Value?.ToString() : null; } catch { }
            list.Add(new RawHistoryEvent(rec.TimeCreated is { } t ? new DateTimeOffset(t) : DateTimeOffset.Now, msg));
        }
        return list;
    }
}
