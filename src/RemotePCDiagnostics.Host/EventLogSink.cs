using System.Collections.Concurrent;
using System.Diagnostics;
using RemotePCDiagnostics.Core.Logging;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// Windows Event Log sink: log "Application", source "RemotePCDiagnostics". Writes happen on one background thread
/// (bounded queue, callers never block). Creating the source needs admin the first time; if that or a write fails,
/// the sink turns itself off once and notes why via <paramref name="note"/> (file log only).
/// </summary>
public sealed class EventLogSink : ILogSink, IDisposable
{
    public const string LogName = "Application";
    public const string SourceName = "RemotePCDiagnostics";
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
                if (!EventLog.SourceExists(SourceName)) EventLog.CreateEventSource(new EventSourceCreationData(SourceName, LogName));
            }
            catch (Exception ex) { Fail($"source '{SourceName}' could not be created (needs administrator the first time): {ex.GetType().Name}: {ex.Message}"); return; }
            using var log = new EventLog(LogName) { Source = SourceName };
            foreach (var e in _queue.GetConsumingEnumerable())
            {
                try
                {
                    var type = e.Level switch { LogLevel.Error => EventLogEntryType.Error, LogLevel.Warning => EventLogEntryType.Warning, _ => EventLogEntryType.Information };
                    log.WriteEntry(e.Message, type, e.EventId);
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
