using System.Collections.Concurrent;
using System.Diagnostics;
using RemotePCDiagnostics.Core.Logging;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// Windows Event Log sink: source "RemotePCDiagnostics", in the app's own log "RemotePCDiagnostics" (Applications and Services
/// Logs). A PC with earlier events has the source under "Application" until the one-time move (EventLogMoveMigration); the
/// sink writes through the source, so it follows wherever the source is registered. Writes happen on one background thread
/// (bounded queue, callers never block). Creating the source needs admin the first time; if that or a write fails,
/// the sink turns itself off once and notes why via <paramref name="note"/> (file log only).
/// </summary>
public sealed class EventLogSink : ILogSink, IDisposable
{
    /// <summary>The shared log the app wrote to before it had its own (the format 3 update and the move read it).</summary>
    public const string LogName = "Application";
    public const string OwnLogName = RemotePCDiagnostics.Core.Migrations.EventLogMoveMigration.OwnLogName;
    public const string SourceName = "RemotePCDiagnostics";
    /// <summary>Size of the app's own log; the oldest entries are overwritten when it is full.</summary>
    public const int OwnLogKilobytes = 20480;

    /// <summary>Registers the source under the app's own log and sets the log's size (administrator).</summary>
    public static void CreateOwnLog()
    {
        if (!EventLog.SourceExists(SourceName)) EventLog.CreateEventSource(new EventSourceCreationData(SourceName, OwnLogName));
        using var log = new EventLog(OwnLogName);
        if (log.MaximumKilobytes != OwnLogKilobytes) log.MaximumKilobytes = OwnLogKilobytes;
        log.ModifyOverflowPolicy(OverflowAction.OverwriteAsNeeded, 0);
    }
    private const int MaxQueued = 1000;
    private readonly BlockingCollection<LogEntry> _queue = new(new ConcurrentQueue<LogEntry>(), MaxQueued);
    private readonly Action<string> _note;
    private readonly Thread? _worker;
    private volatile bool _failed;

    public EventLogSink(Action<string> note)
    {
        _note = note;
        if (!OperatingSystem.IsWindows()) { _failed = true; return; }
        _worker = new Thread(Run) { IsBackground = true, Name = "EventLogSink", Priority = ThreadPriority.BelowNormal };
        _worker.Start();
    }

    public void Write(LogEntry entry)
    {
        if (_failed) return;
        try { _queue.TryAdd(entry with { Message = LogText.Truncate(entry.Message) }); } catch { }
    }

    private void Run()
    {
        try
        {
            if (!OperatingSystem.IsWindows()) return;
            try
            {
                if (!EventLog.SourceExists(SourceName)) CreateOwnLog();
            }
            catch (Exception ex) { Fail($"source '{SourceName}' could not be created (needs administrator the first time): {ex.GetType().Name}: {ex.Message}"); return; }
            using var log = new EventLog { Source = SourceName }; // no log name: the one the source is registered to
            foreach (var e in _queue.GetConsumingEnumerable())
            {
                try
                {
                    var type = e.Level switch { LogLevel.Error => EventLogEntryType.Error, LogLevel.Warning => EventLogEntryType.Warning, _ => EventLogEntryType.Information };
                    log.WriteEntry(e.Message + Environment.NewLine + "Build: " + RemotePCDiagnostics.Core.AppBuildInfo.Version, type, e.EventId);
                }
                catch (Exception ex) { Fail($"write failed: {ex.GetType().Name}: {ex.Message}"); return; }
            }
        }
        catch (Exception ex) { Fail($"worker failed: {ex.Message}"); }
    }

    private void Fail(string why)
    {
        if (_failed) return;
        _failed = true;
        try { _note($"Windows Event Log disabled: {why}"); } catch { }
        try { while (_queue.TryTake(out _)) { } } catch { }
    }

    /// <summary>Gives queued events up to <paramref name="timeout"/> to be written (app exit).</summary>
    public void Flush(TimeSpan timeout)
    {
        var sw = Stopwatch.StartNew();
        while (!_failed && _queue.Count > 0 && sw.Elapsed < timeout) Thread.Sleep(20);
    }

    public void Dispose()
    {
        try { _queue.CompleteAdding(); } catch { }
        try { _worker?.Join(TimeSpan.FromSeconds(1)); } catch { }
    }
}
