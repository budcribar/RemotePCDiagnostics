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
        var list = new List<RawHistoryEvent>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var logNames = new[]
        {
            RemotePCDiagnostics.Core.Migrations.EventLogMoveMigration.OwnLogName,
            RemotePCDiagnostics.Core.Migrations.EventLogMoveMigration.OldLogName
        };

        foreach (var logName in logNames)
        {
            try
            {
                var q = new EventLogQuery(logName, PathType.LogName, xpath) { ReverseDirection = true };
                using var reader = new EventLogReader(q);
                for (var i = 0; i < max; i++)
                {
                    using var rec = reader.ReadEvent();
                    if (rec is null) break;
                    string? msg;
                    try { msg = rec.FormatDescription(); } catch { msg = null; }
                    // Without a registered message file Windows can't format; the raw insertion string is our text.
                    if (string.IsNullOrEmpty(msg)) try { msg = rec.Properties.Count > 0 ? rec.Properties[0].Value?.ToString() : null; } catch { }
                    if (string.IsNullOrWhiteSpace(msg)) continue;

                    var time = rec.TimeCreated is { } t ? new DateTimeOffset(t) : DateTimeOffset.Now;
                    var key = $"{time.ToUnixTimeSeconds()}|{rec.Id}|{msg.Trim()}";
                    if (seen.Add(key))
                    {
                        list.Add(new RawHistoryEvent(time, msg));
                    }
                }
            }
            catch
            {
                // Gracefully continue to the next log if this one does not exist or access is restricted
            }
        }

        return list.OrderByDescending(e => e.TimeCreated).Take(max);
    }
}
