using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Migrations;

namespace RemotePCDiagnostics.Host;

/// <summary>Event Log access for <see cref="EventLogV3Migration"/>: EventLogReader to read, wevtutil to back up and clear, EventLog to write.</summary>
public sealed class WindowsEventLogMigrationIo(ILogger? log) : IEventLogMigrationIo
{
    public bool IsElevated => App.IsAdministrator();

    public IReadOnlyList<RawLogEvent> ReadOurEvents()
    {
        var list = new List<RawLogEvent>();
        if (!OperatingSystem.IsWindows()) return list;
        var q = new EventLogQuery(EventLogSink.LogName, PathType.LogName, $"*[System[Provider[@Name='{EventLogSink.SourceName}']]]");
        using var reader = new EventLogReader(q);
        for (var rec = reader.ReadEvent(); rec is not null; rec = reader.ReadEvent())
        {
            using (rec)
            {
                string? msg;
                try { msg = rec.FormatDescription(); } catch { msg = null; }
                if (string.IsNullOrEmpty(msg)) try { msg = rec.Properties.Count > 0 ? rec.Properties[0].Value?.ToString() : null; } catch { }
                var level = rec.Level switch { 1 or 2 => LogLevel.Error, 3 => LogLevel.Warning, _ => LogLevel.Information };
                list.Add(new RawLogEvent(rec.Id, level, rec.TimeCreated is { } t ? new DateTimeOffset(t) : DateTimeOffset.Now, StripBuild(msg ?? "")));
            }
        }
        return list.OrderBy(e => e.TimeCreated).ToList();
    }

    /// <summary>The sink appends "Build: …" to every event; it is added again when the event is written back.</summary>
    private static string StripBuild(string message)
    {
        var lines = message.Replace("\r\n", "\n").TrimEnd().Split('\n').ToList();
        if (lines.Count > 1 && lines[^1].StartsWith("Build: ", StringComparison.Ordinal)) lines.RemoveAt(lines.Count - 1);
        return string.Join(Environment.NewLine, lines);
    }

    public void Backup(string evtxPath) => Wevtutil("epl", EventLogSink.LogName, evtxPath);

    public void Clear() => Wevtutil("cl", EventLogSink.LogName);

    public void Write(RawLogEvent e)
    {
        if (!OperatingSystem.IsWindows()) return;
        if (!EventLog.SourceExists(EventLogSink.SourceName))
            EventLog.CreateEventSource(new EventSourceCreationData(EventLogSink.SourceName, EventLogSink.LogName));
        using var el = new EventLog(EventLogSink.LogName) { Source = EventLogSink.SourceName };
        var type = e.Level switch { LogLevel.Error => EventLogEntryType.Error, LogLevel.Warning => EventLogEntryType.Warning, _ => EventLogEntryType.Information };
        el.WriteEntry(LogText.Truncate(e.Message) + Environment.NewLine + "Build: " + RemotePCDiagnostics.Core.AppBuildInfo.Version, type, e.EventId);
    }

    private void Wevtutil(params string[] args)
    {
        var psi = new ProcessStartInfo(System.IO.Path.Combine(Environment.SystemDirectory, "wevtutil.exe")) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardError = true };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("wevtutil did not start");
        var err = p.StandardError.ReadToEnd();
        if (!p.WaitForExit(120_000)) { try { p.Kill(); } catch { } throw new TimeoutException($"wevtutil {args[0]} timed out"); }
        if (p.ExitCode != 0) throw new InvalidOperationException($"wevtutil {args[0]} exited {p.ExitCode}: {err.Trim()}");
        log.Info($"wevtutil {string.Join(' ', args)}: done");
    }
}
