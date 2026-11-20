using System.Collections.Concurrent;
using System.Diagnostics;
using RemotePCDiagnostics.Core.Logging;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// Windows Event Log sink: source "RemotePCDiagnostics", in the app's own log "RemotePCDiagnostics" (Applications and Services
/// Logs). A PC with earlier events has the source under "Application" until the one-time move (EventLogMoveMigration); the
/// sink writes through the source, so it follows wherever the source is registered. Writes happen on one background thread
/// (bounded queue, callers never block). Registering the source needs administrator, so the Agent does it (the app never runs as
/// administrator): until then the sink holds what's queued and waits for <see cref="SourceRegistered"/>. If a write fails, the sink turns
/// itself off once and notes why via <paramref name="note"/> (file log only).
/// </summary>
public sealed class EventLogSink : ILogSink, IDisposable
{
    public const string OwnLogName = RemotePCDiagnostics.Agent.AppEventLog.OwnLogName;
    public const string SourceName = RemotePCDiagnostics.Agent.AppEventLog.SourceName;
    private const int MaxQueued = 1000;
    private readonly BlockingCollection<LogEntry> _queue = new(new ConcurrentQueue<LogEntry>(), MaxQueued);
    private readonly ManualResetEventSlim _sourceRegistered = new(false);
    private readonly Action<string> _note;
    private readonly Thread? _worker;
    private volatile bool _failed, _waitingForSource;

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
            if (!RemotePCDiagnostics.Agent.AppEventLog.SourceRegistered())
            {
                _waitingForSource = true;
                try { _note($"Windows Event Log: source '{SourceName}' isn't registered yet; events are held until the Agent registers it (Admin Repair Mode)."); } catch { }
                while (!RemotePCDiagnostics.Agent.AppEventLog.SourceRegistered())
                {
                    _sourceRegistered.Wait();
                    _sourceRegistered.Reset();
                    if (_queue.IsAddingCompleted) return; // closing before the source was registered
                }
                _waitingForSource = false;
            }
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

    /// <summary>The Agent registered the source: write what's held, and from now on.</summary>
    public void SourceRegistered() => _sourceRegistered.Set();

    /// <summary>Gives queued events up to <paramref name="timeout"/> to be written (app exit). Nothing is written while the source waits for the Agent.</summary>
    public void Flush(TimeSpan timeout)
    {
        var sw = Stopwatch.StartNew();
        while (!_failed && !_waitingForSource && _queue.Count > 0 && sw.Elapsed < timeout) Thread.Sleep(20);
    }

    public void Dispose()
    {
        try { _queue.CompleteAdding(); } catch { }
        try { _sourceRegistered.Set(); } catch { }
        try { _worker?.Join(TimeSpan.FromSeconds(1)); } catch { }
    }
}
