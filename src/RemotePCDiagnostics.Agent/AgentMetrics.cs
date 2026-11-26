using System.Diagnostics;
using System.Runtime.InteropServices;
using Google.Protobuf.WellKnownTypes;
using PeakSWC.RemoteWebView.Agent;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Metrics;

namespace RemotePCDiagnostics.Agent;

/// <summary>
/// The Agent's scheduled metrics: runs a pass when the fleet admin's schedule says so, keeps the runs in a capped outbox, and uploads
/// them on the relay stream whenever one is up. A batch leaves the outbox only when Admin acknowledges it, so a dropped connection,
/// a relay restart or an Admin outage loses nothing, and a resend is never a duplicate (Admin saves by run id).
/// Uploads happen after a pass or a reconnect, one batch at a time, and back off when nobody acknowledges: no retry storm.
/// </summary>
public sealed class AgentMetrics
{
    /// <summary>How long a sent batch waits for Admin's acknowledgement before the upload stops until the next chance.</summary>
    public static readonly TimeSpan AckTimeout = TimeSpan.FromSeconds(60);
    public static readonly TimeSpan MinUploadBackoff = TimeSpan.FromMinutes(5);
    public static readonly TimeSpan MaxUploadBackoff = TimeSpan.FromHours(1);
    public static readonly TimeSpan Tick = TimeSpan.FromMinutes(1);

    private readonly string _machineId;
    private readonly string _schedulePath;
    private readonly string _lastPassPath;
    private readonly MetricsOutbox _outbox;
    private readonly Func<IMetricsProbes> _probes;
    private readonly Action<DiagnosticResult>? _history;
    private readonly Func<string> _appVersion;
    private readonly Func<(bool OnBattery, int? Percent)> _power;
    private readonly Func<DateTimeOffset> _now;
    private readonly Func<DateTimeOffset> _bootTime;
    private readonly Action<string>? _log;
    private readonly object _gate = new();
    private readonly SemaphoreSlim _uploadGate = new(1, 1);
    private readonly SemaphoreSlim _wake = new(0, int.MaxValue);

    private MetricsSchedule _schedule;
    private DateTimeOffset? _lastPass;
    private DateTimeOffset? _lastOnDemand;
    private bool _onDemand;
    private int _passRunning;
    private Func<AgentMessage, CancellationToken, Task>? _write;
    private TaskCompletionSource<long>? _pendingAck;
    private long _pendingThrough;
    private DateTimeOffset _uploadNotBefore;
    private TimeSpan _uploadBackoff = MinUploadBackoff;

    public AgentMetrics(string machineId, string stateFolder, Func<IMetricsProbes> probes, Action<DiagnosticResult>? history, Func<string> appVersion,
        Func<(bool OnBattery, int? Percent)>? power = null, Func<DateTimeOffset>? now = null, Func<DateTimeOffset>? bootTime = null, Action<string>? log = null)
    {
        _machineId = machineId;
        _schedulePath = Path.Combine(stateFolder, MetricsScheduleFile.FileName);
        _lastPassPath = Path.Combine(stateFolder, "metrics-last-pass.txt");
        _now = now ?? (() => DateTimeOffset.UtcNow);
        _outbox = new MetricsOutbox(Path.Combine(stateFolder, "metrics-outbox.json"), _now);
        _probes = probes;
        _history = history;
        _appVersion = appVersion;
        _power = power ?? ReadPower;
        _bootTime = bootTime ?? (() => _now() - TimeSpan.FromMilliseconds(Environment.TickCount64));
        _log = log;
        _schedule = MetricsScheduleFile.Load(_schedulePath);
        _lastPass = ReadLastPass();
    }

    public MetricsSchedule Schedule { get { lock (_gate) return _schedule; } }
    public long ScheduleRevision => Schedule.Revision;
    public int Waiting => _outbox.Count;
    public MetricsOutbox Outbox => _outbox;

    /// <summary>Runs passes on schedule until <paramref name="ct"/> ends. <paramref name="busy"/> is true while the app or a session runs.</summary>
    public async Task RunAsync(Func<bool> busy, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try { await _wake.WaitAsync(Tick, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
            try { await RunIfDueAsync(busy(), ct).ConfigureAwait(false); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex) { Log($"Scheduled metrics: {ex.GetType().Name}: {ex.Message}"); }
        }
    }

    /// <summary>One look at the clock: runs a pass if it's due (or asked for) and nothing says to wait, then uploads. Returns why not.</summary>
    public async Task<MetricsSkip> RunIfDueAsync(bool busy, CancellationToken ct)
    {
        MetricsSchedule schedule;
        bool onDemand;
        DateTimeOffset due;
        lock (_gate)
        {
            schedule = _schedule;
            onDemand = _onDemand;
            due = MetricsPlanner.NextDue(_lastPass, schedule, _machineId, _bootTime());
        }
        var (onBattery, percent) = _power();
        var now = _now();
        var skip = MetricsPlanner.Check(schedule, now, due, Volatile.Read(ref _passRunning) == 1, busy, onBattery, percent, onDemand);
        if (skip is MetricsSkip.SessionRunning or MetricsSkip.LowBattery)
        {
            // Put off, not dropped: look again after a while (sooner would just ask again every minute).
            lock (_gate) if (!onDemand) _lastPass = now - schedule.Interval + MetricsPlanner.RetryAfterSkip;
            Log($"Scheduled metrics put off ({skip}).");
        }
        if (skip != MetricsSkip.None)
        {
            if (skip is MetricsSkip.NotDue or MetricsSkip.Disabled) await UploadAsync(ct).ConfigureAwait(false);
            return skip;
        }
        if (Interlocked.Exchange(ref _passRunning, 1) == 1) return MetricsSkip.PassRunning;
        try
        {
            lock (_gate) _onDemand = false;
            using var lower = LowerPriority();
            await new ScheduledMetricsPass(_probes(), _outbox, _history, _appVersion(), null).RunAsync(schedule, ct).ConfigureAwait(false);
            lock (_gate) _lastPass = now;
            WriteLastPass(now);
        }
        finally { Volatile.Write(ref _passRunning, 0); }
        lock (_gate) _uploadNotBefore = DateTimeOffset.MinValue; // a new pass may upload at once
        await UploadAsync(ct).ConfigureAwait(false);
        return MetricsSkip.None;
    }

    // ------------------------------------------------------------------ relay stream

    /// <summary>A relay stream is up (null when it ended). A new stream may upload right away.</summary>
    public void Attach(Func<AgentMessage, CancellationToken, Task>? write)
    {
        lock (_gate)
        {
            _write = write;
            if (write is not null) { _uploadNotBefore = DateTimeOffset.MinValue; _uploadBackoff = MinUploadBackoff; }
            _pendingAck?.TrySetCanceled();
            _pendingAck = null;
        }
        if (write is not null) _wake.Release();
    }

    /// <summary>Admin's setting. Saved before it's used, so it holds through a restart and while offline. Older revisions are ignored.</summary>
    public bool ApplySchedule(MetricsScheduleCommand command)
    {
        var next = MetricsSchedule.From(command.Revision, command.Enabled, command.IntervalMinutes, command.CheckIds);
        lock (_gate)
        {
            if (next.Revision <= _schedule.Revision) return false;
            try { MetricsScheduleFile.Save(_schedulePath, next); }
            catch (Exception ex) { Log($"Scheduled metrics setting not saved: {ex.Message}"); return false; }
            _schedule = next;
        }
        Log($"Scheduled metrics: revision {next.Revision}, {(next.Enabled ? $"every {next.Interval.TotalHours:0.#} h" : "off")}, {string.Join(", ", next.Checks)}.");
        _wake.Release();
        return true;
    }

    /// <summary>Admin's "Collect now": an extra pass soon, at most one per <see cref="MetricsPlanner.MinOnDemandGap"/>.</summary>
    public bool CollectNow()
    {
        lock (_gate)
        {
            var now = _now();
            if (_lastOnDemand is { } last && now - last < MetricsPlanner.MinOnDemandGap) return false;
            _lastOnDemand = now;
            _onDemand = true;
        }
        _wake.Release();
        return true;
    }

    public void Acknowledge(long throughSeq)
    {
        var removed = _outbox.Acknowledge(throughSeq);
        TaskCompletionSource<long>? pending;
        lock (_gate)
        {
            pending = _pendingAck;
            if (pending is not null && throughSeq >= _pendingThrough) _pendingAck = null;
            else pending = null;
        }
        pending?.TrySetResult(throughSeq);
        if (removed > 0) Log($"Scheduled metrics: Admin saved {removed} run(s); {_outbox.Count} waiting.");
    }

    /// <summary>Sends the outbox a batch at a time, each after the last was acknowledged. Stops at the first silence and backs off.</summary>
    public async Task UploadAsync(CancellationToken ct)
    {
        if (!await _uploadGate.WaitAsync(0, ct).ConfigureAwait(false)) return;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                Func<AgentMessage, CancellationToken, Task>? write;
                TaskCompletionSource<long> ack;
                IReadOnlyList<MetricsRunRecord> batch;
                lock (_gate)
                {
                    write = _write;
                    if (write is null || _now() < _uploadNotBefore) return;
                    batch = _outbox.NextBatch();
                    if (batch.Count == 0) return;
                    ack = _pendingAck = new TaskCompletionSource<long>(TaskCreationOptions.RunContinuationsAsynchronously);
                    _pendingThrough = batch[^1].Seq;
                }
                var message = new AgentMessage { Metrics = ToProto(batch) };
                try { await write(message, ct).ConfigureAwait(false); }
                catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested) { BackOff($"send failed: {ex.Message}"); return; }

                var done = await Task.WhenAny(ack.Task, Task.Delay(AckTimeout, ct)).ConfigureAwait(false);
                if (done != ack.Task || !ack.Task.IsCompletedSuccessfully)
                {
                    lock (_gate) if (ReferenceEquals(_pendingAck, ack)) _pendingAck = null;
                    BackOff("no acknowledgement from Admin");
                    return;
                }
                lock (_gate) _uploadBackoff = MinUploadBackoff;
            }
        }
        finally { _uploadGate.Release(); }
    }

    private void BackOff(string why)
    {
        TimeSpan wait;
        lock (_gate)
        {
            wait = _uploadBackoff;
            _uploadNotBefore = _now() + wait;
            _uploadBackoff = TimeSpan.FromTicks(Math.Min(MaxUploadBackoff.Ticks, _uploadBackoff.Ticks * 2));
        }
        Log($"Scheduled metrics upload paused for {wait.TotalMinutes:0} min ({why}); {_outbox.Count} run(s) kept.");
    }

    public static MetricsBatch ToProto(IEnumerable<MetricsRunRecord> runs)
    {
        var batch = new MetricsBatch();
        foreach (var r in runs)
        {
            var run = new MetricsRun
            {
                RunId = r.RunId, Seq = r.Seq, CheckId = r.CheckId, InstanceId = r.InstanceId ?? "", InstanceLabel = r.InstanceLabel ?? "",
                Finished = Timestamp.FromDateTimeOffset(r.FinishedUtc), Outcome = r.Outcome, Summary = r.Summary, AppVersion = r.AppVersion,
            };
            run.Metrics.AddRange(r.Metrics.Select(m => new MetricValue
            {
                Id = m.Id, Label = m.Label, Value = m.Value, Unit = m.Unit,
                Better = m.Better switch { MetricTrend.HigherIsBetter => MetricDirection.MetricHigherIsBetter, MetricTrend.LowerIsBetter => MetricDirection.MetricLowerIsBetter, _ => MetricDirection.MetricNeutral },
            }));
            batch.Runs.Add(run);
        }
        return batch;
    }

    // ------------------------------------------------------------------ the PC

    private DateTimeOffset? ReadLastPass()
    {
        try { return File.Exists(_lastPassPath) && DateTimeOffset.TryParse(File.ReadAllText(_lastPassPath).Trim(), System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind, out var t) ? t : null; }
        catch { return null; }
    }

    private void WriteLastPass(DateTimeOffset t)
    {
        try { File.WriteAllText(_lastPassPath, t.ToString("O", System.Globalization.CultureInfo.InvariantCulture)); } catch { }
    }

    /// <summary>The pass and the tools it starts (PowerShell, osquery inherit the priority class) run below normal priority.</summary>
    private static IDisposable? LowerPriority()
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            var p = Process.GetCurrentProcess();
            var before = p.PriorityClass;
            p.PriorityClass = ProcessPriorityClass.BelowNormal;
            return new Restore(() => { try { p.PriorityClass = before; } catch { } p.Dispose(); });
        }
        catch { return null; }
    }

    private sealed class Restore(Action undo) : IDisposable { public void Dispose() => undo(); }

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_POWER_STATUS { public byte ACLineStatus, BatteryFlag, BatteryLifePercent, SystemStatusFlag; public int BatteryLifeTime, BatteryFullLifeTime; }

    [DllImport("kernel32.dll")] private static extern bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS s);

    private static (bool OnBattery, int? Percent) ReadPower()
    {
        try
        {
            if (OperatingSystem.IsWindows() && GetSystemPowerStatus(out var s))
                return (s.ACLineStatus == 0, s.BatteryLifePercent <= 100 ? s.BatteryLifePercent : null);
        }
        catch { }
        return (false, null);
    }

    private void Log(string message) => _log?.Invoke(message);

    /// <summary>Writes a scheduled run to the PC's History (event 1100 in the app's log), as the app writes its own runs.</summary>
    public static Action<DiagnosticResult> EventLogHistory(Action<string>? log)
    {
        return r =>
        {
            if (!OperatingSystem.IsWindows() || !AppEventLog.SourceRegistered()) return;
            var text = HistoryText(r);
            var level = ResultEventLogger.LevelFor(r) switch
            {
                LogLevel.Error => EventLogEntryType.Error,
                LogLevel.Warning => EventLogEntryType.Warning,
                _ => EventLogEntryType.Information,
            };
            using var el = new EventLog { Source = AppEventLog.SourceName };
            el.WriteEntry(text, level, LogEventIds.TestResult);
        };
    }

    /// <summary>The 1100 message the Agent writes for a scheduled run: the app's own format, then the build.</summary>
    public static string HistoryText(DiagnosticResult r) =>
        LogText.Truncate(ResultEventLogger.Format(r, null, null, new ResultEventContext(null, () => Environment.MachineName, AppBuildInfo.Version)))
        + Environment.NewLine + "Build: " + AppBuildInfo.Version;
}
