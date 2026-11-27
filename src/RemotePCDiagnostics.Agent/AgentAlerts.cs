using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using Google.Protobuf.WellKnownTypes;
using PeakSWC.RemoteWebView.Agent;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Alerts;
using RemotePCDiagnostics.Core.Logging;

namespace RemotePCDiagnostics.Agent;

/// <summary>
/// The Agent as a sensor (plan v2): watches the System and Application event logs for the events in <see cref="AlertRules"/>, reads
/// free disk space, memory and power every 15 minutes, and keeps the alerts it raises in <see cref="AgentAlertBook"/> until Admin
/// acknowledges them. It runs no checks: an AI agent or a technician reads the alerts in Admin and decides. Each new, escalated or
/// cleared alert is also written to the app's own Windows log (event 2000), which the app can read without admin.
/// Uploads work like scheduled metrics: one batch at a time, each after the last was acknowledged, backing off when nobody answers.
/// </summary>
public sealed class AgentAlerts : IDisposable
{
    public static readonly TimeSpan LevelInterval = TimeSpan.FromMinutes(15);
    public static readonly TimeSpan AckTimeout = TimeSpan.FromSeconds(60);
    public static readonly TimeSpan MinUploadBackoff = TimeSpan.FromMinutes(5);
    public static readonly TimeSpan MaxUploadBackoff = TimeSpan.FromHours(1);
    /// <summary>After a restart the watchers read back what they missed, at most this far.</summary>
    public static readonly TimeSpan MaxLookBack = TimeSpan.FromDays(1);

    private readonly string _settingsPath;
    private readonly string _positionsPath;
    private readonly string _powerPath;
    private readonly AgentAlertBook _book;
    private readonly IAlertReadings _readings;
    private readonly Func<DateTimeOffset> _now;
    private readonly Action<string>? _log;
    private readonly object _gate = new();
    private readonly SemaphoreSlim _uploadGate = new(1, 1);
    private readonly SemaphoreSlim _wake = new(0, int.MaxValue);
    private readonly Dictionary<string, long> _lastRecord = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<EventLogWatcher> _watchers = [];

    private AlertSettings _settings;
    private PowerReading? _lastPower;
    private PowerReading? _notChargingSince;
    private bool _memoryWasHigh;
    private Func<AgentMessage, CancellationToken, Task>? _write;
    private TaskCompletionSource<long>? _pendingAck;
    private long _pendingThrough;
    private DateTimeOffset _uploadNotBefore;
    private TimeSpan _uploadBackoff = MinUploadBackoff;

    /// <param name="readings">Where the events and levels are read: this PC (<see cref="WindowsAlertReadings"/>) unless given, a
    /// recording in the replay tests.</param>
    public AgentAlerts(string stateFolder, Func<string> appVersion, Func<DateTimeOffset>? now = null, Action<string>? log = null,
        IAlertReadings? readings = null)
    {
        _now = now ?? (() => DateTimeOffset.UtcNow);
        _readings = readings ?? new WindowsAlertReadings();
        _log = log;
        _settingsPath = Path.Combine(stateFolder, AlertSettingsFile.FileName);
        _positionsPath = Path.Combine(stateFolder, "alert-positions.txt");
        _powerPath = Path.Combine(stateFolder, "alert-last-power.json");
        _book = new AgentAlertBook(Path.Combine(stateFolder, "alerts.json"), _now, appVersion);
        _settings = AlertSettingsFile.Load(_settingsPath);
        LoadPositions();
        // The last reading before a shutdown is read back at the next start, when Windows logs the unexpected shutdown.
        try { if (File.Exists(_powerPath)) _lastPower = System.Text.Json.JsonSerializer.Deserialize<PowerReading>(File.ReadAllText(_powerPath)); } catch { }
    }

    public AlertSettings Settings { get { lock (_gate) return _settings; } }
    public long SettingsRevision => Settings.Revision;
    public AgentAlertBook Book => _book;

    /// <summary>Watches events and reads levels until <paramref name="ct"/> ends.</summary>
    public async Task RunAsync(CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) return;
        await StartWatchersAsync(ct).ConfigureAwait(false);
        var nextLevels = DateTimeOffset.MinValue;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (_now() >= nextLevels)
                {
                    await ReadLevelsAsync(ct).ConfigureAwait(false);
                    if (_book.ExpireQuiet() is > 0 and var n) Log($"Alerts: {n} quiet alert(s) cleared after 7 days.");
                    nextLevels = _now() + LevelInterval;
                }
                await UploadAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex) { Log($"Alerts: {ex.GetType().Name}: {ex.Message}"); }

            try { await _wake.WaitAsync(TimeSpan.FromMinutes(1), ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }
        StopWatchers();
    }

    public void Dispose() => StopWatchers();

    /// <summary>
    /// One look without watching: reads back each channel's events (as after a restart), then the levels. The replay tests run it on a
    /// recording; the Agent itself watches (<see cref="RunAsync"/>).
    /// </summary>
    public async Task ScanAsync(CancellationToken ct)
    {
        foreach (var channel in AlertRules.EventIds.Keys) await CatchUpAsync(channel, ct).ConfigureAwait(false);
        await ReadLevelsAsync(ct).ConfigureAwait(false);
    }

    // ------------------------------------------------------------------ events

    private async Task StartWatchersAsync(CancellationToken ct)
    {
        foreach (var channel in AlertRules.EventIds.Keys)
        {
            try
            {
                var watcher = new EventLogWatcher(new EventLogQuery(channel, PathType.LogName, AlertRules.Query(channel)));
                watcher.EventRecordWritten += (sender, e) =>
                {
                    if (e.EventRecord is { } record)
                        using (record)
                        {
                            AlertEvent ev;
                            try { ev = WindowsAlertReadings.ToEvent(channel, record); }
                            catch (Exception ex) { Log($"Alerts: an event could not be read: {ex.Message}"); return; }
                            if (OnEvent(ev)) _ = ReadLevelsAsync(CancellationToken.None);
                        }
                };
                // Read back what was missed, start watching, then read once more for anything written in between (a repeat is
                // dropped by its record id).
                await CatchUpAsync(channel, ct).ConfigureAwait(false);
                watcher.Enabled = true;
                lock (_gate) _watchers.Add(watcher);
                await CatchUpAsync(channel, ct).ConfigureAwait(false);
            }
            catch (Exception ex) { Log($"Alerts: cannot watch the {channel} log: {ex.Message}"); }
        }
    }

    private async Task CatchUpAsync(string channel, CancellationToken ct)
    {
        long after;
        lock (_gate) after = _lastRecord.GetValueOrDefault(channel);
        var answer = await _readings.ReadAsync(AlertReadings.Events(channel), after, MaxLookBack, ct).ConfigureAwait(false);
        if (answer.Error is { } error) { Log($"Alerts: cannot read the {channel} log: {error}"); return; }
        var events = AlertReadings.ToEvents(channel, answer);
        var readLevels = false;
        foreach (var e in events.Take(AlertReadings.MaxEvents)) readLevels |= OnEvent(e);
        if (events.Count > 0) Log($"Alerts: read {events.Count} missed {channel} event(s).");
        if (readLevels) await ReadLevelsAsync(ct).ConfigureAwait(false);
    }

    private void StopWatchers()
    {
        List<EventLogWatcher> watchers;
        lock (_gate) { watchers = [.. _watchers]; _watchers.Clear(); }
        foreach (var w in watchers)
        {
            try { w.Enabled = false; } catch { }
            w.Dispose();
        }
    }

    /// <summary>Raises what the event means. True when the levels should be read now (the low-disk and low-memory events: the reading
    /// names the drive and clears it later).</summary>
    private bool OnEvent(AlertEvent e)
    {
        try
        {
            PowerReading? power;
            AlertSettings settings;
            lock (_gate)
            {
                if (e.RecordId > 0 && e.RecordId <= _lastRecord.GetValueOrDefault(e.Channel)) return false; // already seen
                if (e.RecordId > 0) _lastRecord[e.Channel] = e.RecordId;
                power = _lastPower;
                settings = _settings;
            }
            SavePositions();

            var signals = AlertRules.FromEvent(e, settings, power, out var readLevels);
            foreach (var signal in signals)
                Record(_book.Raise(signal, settings), raised: true);
            return readLevels;
        }
        catch (Exception ex) { Log($"Alerts: an event could not be read: {ex.Message}"); return false; }
    }

    // ------------------------------------------------------------------ levels

    /// <summary>Free space on each fixed drive, memory commit charge and power. A reading that fails or is damaged changes no alert.</summary>
    private async Task ReadLevelsAsync(CancellationToken ct)
    {
        try { await ReadLevelsCoreAsync(ct).ConfigureAwait(false); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { Log($"Alerts: levels not read: {ex.GetType().Name}: {ex.Message}"); }
    }

    private async Task ReadLevelsCoreAsync(CancellationToken ct)
    {
        AlertSettings settings;
        lock (_gate) settings = _settings;
        var openKeys = _book.Open;

        var disks = await _readings.ReadAsync(AlertReadings.Disks, 0, TimeSpan.Zero, ct).ConfigureAwait(false);
        if (disks.Error is { } diskError) Log($"Alerts: free space not read: {diskError}");
        foreach (var reading in AlertReadings.ToDisks(disks))
        {
            var open = openKeys.Any(a => a.SameKey(AlertKinds.LowDisk, reading.Drive));
            Apply(AlertRules.Disk(reading, settings, open), AlertKinds.LowDisk, reading.Drive, settings);
        }

        var memory = await _readings.ReadAsync(AlertReadings.Memory, 0, TimeSpan.Zero, ct).ConfigureAwait(false);
        if (AlertReadings.ToCommitPercent(memory) is { } commit)
        {
            bool previousHigh;
            lock (_gate) { previousHigh = _memoryWasHigh; _memoryWasHigh = commit >= settings.MemoryCommitPercent; }
            var open = openKeys.Any(a => a.SameKey(AlertKinds.LowMemory, ""));
            Apply(AlertRules.Memory(commit, previousHigh, settings, open), AlertKinds.LowMemory, "", settings);
        }

        var powerAnswer = await _readings.ReadAsync(AlertReadings.Power, 0, TimeSpan.Zero, ct).ConfigureAwait(false);
        if (AlertReadings.ToPower(powerAnswer, _now()) is { } power)
        {
            PowerReading? since;
            lock (_gate)
            {
                _lastPower = power;
                try { File.WriteAllText(_powerPath, System.Text.Json.JsonSerializer.Serialize(power)); } catch { }
                // The not-charging rule compares with the first reading of a not-charging stretch.
                if (power.OnBattery || power.Charging || !power.HasBattery) _notChargingSince = null;
                else _notChargingSince ??= power;
                since = _notChargingSince;
            }
            if (AlertRules.NotCharging(power, since) is { } signal) Record(_book.Raise(signal, settings), raised: true);
        }
    }

    private void Apply((LevelDecision Decision, AlertSignal? Signal) result, string kind, string instance, AlertSettings settings)
    {
        if (result.Decision == LevelDecision.Raise && result.Signal is { } s) Record(_book.Raise(s, settings), raised: true);
        else if (result.Decision == LevelDecision.Clear) Record(_book.Clear(kind, instance), raised: false);
    }

    /// <summary>New, escalated and cleared alerts go to the app's log and the Agent log; a plain repeat only counts (and is uploaded).</summary>
    private void Record(AlertRecord? alert, bool raised)
    {
        if (alert is null) return;
        _wake.Release(); // upload soon
        if (raised && !LevelChanged(alert)) return;
        Log($"Alert {alert.Status.ToString().ToLowerInvariant()}: {alert.Kind} {alert.InstanceLabel} ({alert.Level}, seen {alert.Count}x): {alert.Summary}");
        WriteAppLog(alert);
    }

    private readonly Dictionary<string, AlertLevel> _loggedLevel = new(StringComparer.OrdinalIgnoreCase);

    private bool LevelChanged(AlertRecord alert)
    {
        lock (_gate)
        {
            if (_loggedLevel.TryGetValue(alert.AlertId, out var was) && was == alert.Level) return false;
            _loggedLevel[alert.AlertId] = alert.Level;
            return true;
        }
    }

    private static void WriteAppLog(AlertRecord alert)
    {
        if (!OperatingSystem.IsWindows() || !AppEventLog.SourceRegistered()) return;
        try
        {
            var type = alert.Status != AlertStatus.Open ? EventLogEntryType.Information
                : alert.Level switch { AlertLevel.Critical => EventLogEntryType.Error, AlertLevel.Warning => EventLogEntryType.Warning, _ => EventLogEntryType.Information };
            using var el = new EventLog { Source = AppEventLog.SourceName };
            el.WriteEntry(LogText.Truncate(AlertEventText.Format(alert)), type, LogEventIds.Alert);
        }
        catch { /* the app's log is a convenience; Admin still gets the alert */ }
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
    public bool ApplySettings(AlertSettingsCommand command)
    {
        var next = AlertSettings.From(command.Revision, command.Enabled, command.DisabledKinds, command.LowDiskFreeGb, command.LowDiskFreePercent,
            command.MemoryCommitPercent, command.AppCrashRepeats, command.AppCrashWindowHours);
        lock (_gate)
        {
            if (next.Revision <= _settings.Revision) return false;
            try { AlertSettingsFile.Save(_settingsPath, next); }
            catch (Exception ex) { Log($"Alert setting not saved: {ex.Message}"); return false; }
            _settings = next;
        }
        Log($"Alerts: revision {next.Revision}, {(next.Enabled ? "on" : "off")}"
            + (next.DisabledKinds.Count > 0 ? $", off for {string.Join(", ", next.DisabledKinds)}" : "") + ".");
        return true;
    }

    /// <summary>A technician or AI handled or cleared the alert in Admin.</summary>
    public void ApplyState(AlertStateCommand command)
    {
        var status = command.State switch { AlertState.AlertHandled => AlertStatus.Handled, AlertState.AlertCleared => AlertStatus.Cleared, _ => AlertStatus.Open };
        if (status != AlertStatus.Open && _book.SetStatus(command.AlertId, status))
            Log($"Alerts: {command.AlertId} marked {status.ToString().ToLowerInvariant()} in Admin.");
    }

    public void Acknowledge(long throughSeq)
    {
        var covered = _book.Acknowledge(throughSeq);
        TaskCompletionSource<long>? pending;
        lock (_gate)
        {
            pending = _pendingAck;
            if (pending is not null && throughSeq >= _pendingThrough) _pendingAck = null;
            else pending = null;
        }
        pending?.TrySetResult(throughSeq);
        if (covered > 0) Log($"Alerts: Admin saved {covered} alert change(s); {_book.Waiting} waiting.");
    }

    /// <summary>Sends what changed a batch at a time, each after the last was acknowledged. Stops at the first silence and backs off.</summary>
    public async Task UploadAsync(CancellationToken ct)
    {
        if (!await _uploadGate.WaitAsync(0, ct).ConfigureAwait(false)) return;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                Func<AgentMessage, CancellationToken, Task>? write;
                TaskCompletionSource<long> ack;
                IReadOnlyList<AlertRecord> batch;
                lock (_gate)
                {
                    write = _write;
                    if (write is null || _now() < _uploadNotBefore) return;
                    batch = _book.NextBatch();
                    if (batch.Count == 0) return;
                    ack = _pendingAck = new TaskCompletionSource<long>(TaskCreationOptions.RunContinuationsAsynchronously);
                    _pendingThrough = batch[^1].Seq;
                }
                try { await write(new AgentMessage { Alerts = ToProto(batch) }, ct).ConfigureAwait(false); }
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
        Log($"Alert upload paused for {wait.TotalMinutes:0} min ({why}); {_book.Waiting} change(s) kept.");
    }

    public static AlertBatch ToProto(IEnumerable<AlertRecord> alerts)
    {
        var batch = new AlertBatch();
        foreach (var a in alerts)
        {
            var alert = new AgentAlert
            {
                AlertId = a.AlertId, Seq = a.Seq, Kind = a.Kind, InstanceId = a.InstanceId, InstanceLabel = a.InstanceLabel,
                Severity = a.Level switch { AlertLevel.Critical => AlertSeverity.AlertCritical, AlertLevel.Warning => AlertSeverity.AlertWarning, _ => AlertSeverity.AlertInfo },
                State = a.Status switch { AlertStatus.Handled => AlertState.AlertHandled, AlertStatus.Cleared => AlertState.AlertCleared, _ => AlertState.AlertOpen },
                FirstSeen = Timestamp.FromDateTimeOffset(a.FirstSeenUtc), LastSeen = Timestamp.FromDateTimeOffset(a.LastSeenUtc),
                Count = a.Count, Summary = a.Summary, AppVersion = a.AppVersion,
            };
            alert.Facts.AddRange(a.Facts.Select(f => new AlertFact { Name = f.Name, Value = f.Value }));
            alert.SourceEvents.AddRange(a.Sources.Select(s => new AlertSourceEvent { Channel = s.Channel, Provider = s.Provider, EventId = s.EventId, RecordId = s.RecordId }));
            alert.RelatedChecks.AddRange(a.RelatedChecks);
            batch.Alerts.Add(alert);
        }
        return batch;
    }

    // ------------------------------------------------------------------ the PC

    private void LoadPositions()
    {
        try
        {
            if (!File.Exists(_positionsPath)) return;
            foreach (var line in File.ReadAllLines(_positionsPath))
            {
                var parts = line.Split('=', 2);
                if (parts.Length == 2 && long.TryParse(parts[1], out var id) && id > 0) _lastRecord[parts[0].Trim()] = id;
            }
        }
        catch { /* start from the last day */ }
    }

    private void SavePositions()
    {
        try
        {
            string text;
            lock (_gate) text = string.Join(Environment.NewLine, _lastRecord.Select(kv => $"{kv.Key}={kv.Value}"));
            File.WriteAllText(_positionsPath, text);
        }
        catch { }
    }

    private void Log(string message) => _log?.Invoke(message);
}
