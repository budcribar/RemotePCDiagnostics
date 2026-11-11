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
    /// <summary>The session audit's own log (Event Viewer > Applications and Services Logs > RemotePCDiagnostics) and its source.
    /// A source belongs to one log, so the audit has its own source.</summary>
    public const string AuditLogName = "RemotePCDiagnostics", AuditSourceName = "RemotePCDiagnostics Audit";
    /// <summary>Size of the audit log (a multiple of 64 KB); the oldest entries are overwritten when it is full.</summary>
    public const int AuditLogKilobytes = 20480;
    private readonly Action<string> _note;
    private readonly Thread? _worker;
    private readonly string _logName, _sourceName;
    private readonly int _maxKilobytes;
    private volatile bool _failed;

    /// <param name="maxKilobytes">When above zero, the log's size is set to this (a log of the app's own only).</param>
    public EventLogSink(Action<string> note, string logName = LogName, string sourceName = SourceName, int maxKilobytes = 0)
    {
        _note = note;
        _logName = logName;
        _sourceName = sourceName;
        _maxKilobytes = maxKilobytes;
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
                if (!EventLog.SourceExists(_sourceName)) EventLog.CreateEventSource(new EventSourceCreationData(_sourceName, _logName));
            }
            catch (Exception ex) { Fail($"source '{_sourceName}' could not be created (needs administrator the first time): {ex.GetType().Name}: {ex.Message}"); return; }
            using var log = new EventLog(_logName) { Source = _sourceName };
            if (_maxKilobytes > 0)
            {
                try
                {
                    if (log.MaximumKilobytes != _maxKilobytes) log.MaximumKilobytes = _maxKilobytes;
                    log.ModifyOverflowPolicy(OverflowAction.OverwriteAsNeeded, 0);
                }
                catch (Exception ex) { try { _note($"Event log '{_logName}' size could not be set: {ex.GetType().Name}: {ex.Message}"); } catch { } }
            }
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
        try { _note($"Windows Event Log ({_logName}) disabled: {why}"); } catch { }
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
