using System.Diagnostics.Eventing.Reader;
using RemotePCDiagnostics.Core.History;

namespace RemotePCDiagnostics.Host;

/// <summary>Reads RemotePCDiagnostics 1100 events, newest first (EventLogReader + XPath), from the app's own log.
/// Failures surface as exceptions handled by <see cref="EventLogHistoryStore"/>.</summary>
public static class EventLogHistorySource
{
    public static IHistoryStore Create(ILogger? log) =>
        OperatingSystem.IsWindows() ? new EventLogHistoryStore(Query, log) : new NullHistoryStore();

    private static IEnumerable<RawHistoryEvent> Query(string xpath, int max)
    {
        var list = new List<RawHistoryEvent>();
        var q = new EventLogQuery(RemotePCDiagnostics.Agent.AppEventLog.OwnLogName, PathType.LogName, xpath) { ReverseDirection = true };
        EventLogReader reader;
        try { reader = new EventLogReader(q); }
        catch (EventLogNotFoundException) { return list; } // the Agent hasn't created the log yet: no results so far
        using var _ = reader;
        for (var i = 0; i < max; i++)
        {
            using var rec = reader.ReadEvent();
            if (rec is null) break;
            string? msg;
            try { msg = rec.FormatDescription(); } catch { msg = null; }
            // Without a registered message file Windows can't format; the raw insertion string is our text.
            if (string.IsNullOrEmpty(msg)) try { msg = rec.Properties.Count > 0 ? rec.Properties[0].Value?.ToString() : null; } catch { }
            if (string.IsNullOrWhiteSpace(msg)) continue;
            list.Add(new RawHistoryEvent(rec.TimeCreated is { } t ? new DateTimeOffset(t) : DateTimeOffset.Now, msg));
        }
        return list;
    }
}
