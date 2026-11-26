using System.Text.Json;

namespace RemotePCDiagnostics.Core.Alerts;

public enum AlertLevel { Info, Warning, Critical }

/// <summary>Open until a technician or AI marks it handled (Admin), or until it clears (the level recovered, or 7 days without a repeat).</summary>
public enum AlertStatus { Open, Handled, Cleared }

/// <summary>
/// The alerts the Agent raises (plan v2: the Agent is a sensor; an AI agent or a technician decides what to run). Each kind names the
/// checks that usually explain it, as a hint for the AI.
/// </summary>
public static class AlertKinds
{
    public const string LowDisk = "low_disk";
    public const string LowMemory = "low_memory";
    public const string DiskErrors = "disk_errors";
    public const string SmartFailure = "smart_failure";
    public const string FsCorruption = "fs_corruption";
    public const string UnexpectedShutdown = "unexpected_shutdown";
    public const string Bluescreen = "bluescreen";
    public const string AppCrash = "app_crash";
    public const string Overheating = "overheating";
    public const string BatteryFailing = "battery_failing";
    public const string UpdateFailed = "update_failed";
    /// <summary>Raised instead of a new alert once a PC has raised <see cref="AgentAlertBook.MaxNewPerDay"/> in a day.</summary>
    public const string TooMany = "too_many_alerts";

    public static readonly IReadOnlyList<string> All =
        [LowDisk, LowMemory, DiskErrors, SmartFailure, FsCorruption, UnexpectedShutdown, Bluescreen, AppCrash, Overheating, BatteryFailing, UpdateFailed, TooMany];

    /// <summary>Level alerts come from a reading and clear themselves once the reading recovers; the others wait for a person or 7 days.</summary>
    public static bool IsLevel(string kind) => kind is LowDisk or LowMemory;

    public static IReadOnlyList<string> RelatedChecks(string kind) => kind switch
    {
        LowDisk => [ModuleSlugs.DriveHealth, ModuleSlugs.DiskSpace],
        LowMemory => [ModuleSlugs.ResourceHogs],
        DiskErrors or SmartFailure or FsCorruption => [ModuleSlugs.DriveHealth],
        UnexpectedShutdown => [ModuleSlugs.EventLog, ModuleSlugs.BatteryPower],
        Bluescreen => [ModuleSlugs.Crashes],
        AppCrash => [ModuleSlugs.Crashes],
        Overheating => [ModuleSlugs.Sensors],
        BatteryFailing => [ModuleSlugs.BatteryPower],
        UpdateFailed => [ModuleSlugs.EventLog],
        _ => [],
    };
}

public sealed record AlertFactItem(string Name, string Value);

/// <summary>The Windows event behind an alert (empty channel for a level reading).</summary>
public sealed record AlertEventRef(string Channel, string Provider, int EventId, long RecordId);

/// <summary>
/// Something the Agent saw: an event that matched a rule, or a reading over a threshold. <paramref name="Escalate"/> raises the level
/// once the same alert repeated that many times within the window (disk errors 3 in 24 h, the same app crashing 3 in 24 h).
/// </summary>
public sealed record AlertSignal(
    string Kind, AlertLevel Level, string InstanceId, string InstanceLabel, string Summary,
    IReadOnlyList<AlertFactItem>? Facts = null, AlertEventRef? Source = null, AlertEscalation? Escalate = null);

public sealed record AlertEscalation(int Repeats, TimeSpan Window, AlertLevel To);

/// <summary>One alert as the Agent keeps and uploads it. <see cref="Occurrences"/> (the last few times it was seen) stays on the PC.</summary>
public sealed record AlertRecord(
    string AlertId, long Seq, string Kind, AlertLevel Level, string InstanceId, string InstanceLabel,
    DateTimeOffset FirstSeenUtc, DateTimeOffset LastSeenUtc, int Count, AlertStatus Status, string Summary,
    IReadOnlyList<AlertFactItem> Facts, IReadOnlyList<AlertEventRef> Sources, IReadOnlyList<string> RelatedChecks, string AppVersion,
    IReadOnlyList<DateTimeOffset> Occurrences)
{
    public bool IsOpen => Status == AlertStatus.Open;
    public bool SameKey(string kind, string instanceId) =>
        string.Equals(Kind, kind, StringComparison.OrdinalIgnoreCase) && string.Equals(InstanceId, instanceId, StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// The fleet admin's alert setting, as last received from Admin (or the default before Admin sends one). Saved by the Agent in its
/// protected state folder.
/// </summary>
public sealed record AlertSettings(long Revision, bool Enabled, IReadOnlyList<string> DisabledKinds, double LowDiskFreeGb,
    double LowDiskFreePercent, double MemoryCommitPercent, int AppCrashRepeats, int AppCrashWindowHours)
{
    public const double DefaultLowDiskFreeGb = 5;
    public const double DefaultLowDiskFreePercent = 10;
    public const double DefaultMemoryCommitPercent = 90;
    public const int DefaultAppCrashRepeats = 3;
    public const int DefaultAppCrashWindowHours = 24;
    /// <summary>Below this much free space a low-disk alert is Critical, whatever the setting.</summary>
    public const double CriticalFreeGb = 2;

    public static AlertSettings Default { get; } = new(0, true, [], DefaultLowDiskFreeGb, DefaultLowDiskFreePercent, DefaultMemoryCommitPercent,
        DefaultAppCrashRepeats, DefaultAppCrashWindowHours);

    public bool Allows(string kind) => Enabled && !DisabledKinds.Contains(kind, StringComparer.OrdinalIgnoreCase);

    public TimeSpan AppCrashWindow => TimeSpan.FromHours(AppCrashWindowHours);

    /// <summary>A setting from Admin, made safe: 0 means the default, the rest is clamped to sensible ranges.</summary>
    public static AlertSettings From(long revision, bool enabled, IEnumerable<string>? disabledKinds, double lowDiskFreeGb, double lowDiskFreePercent,
        double memoryCommitPercent, int appCrashRepeats, int appCrashWindowHours)
    {
        static double Pick(double value, double fallback, double min, double max) =>
            double.IsFinite(value) && value > 0 ? Math.Clamp(value, min, max) : fallback;
        return new(Math.Max(0, revision), enabled,
            (disabledKinds ?? []).Where(k => !string.IsNullOrWhiteSpace(k)).Select(k => k.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).Take(32).ToList(),
            Pick(lowDiskFreeGb, DefaultLowDiskFreeGb, 0.5, 500),
            Pick(lowDiskFreePercent, DefaultLowDiskFreePercent, 1, 50),
            Pick(memoryCommitPercent, DefaultMemoryCommitPercent, 50, 99),
            appCrashRepeats > 0 ? Math.Clamp(appCrashRepeats, 2, 20) : DefaultAppCrashRepeats,
            appCrashWindowHours > 0 ? Math.Clamp(appCrashWindowHours, 1, 168) : DefaultAppCrashWindowHours);
    }
}

/// <summary>Saves and loads <see cref="AlertSettings"/> (the Agent's protected state folder).</summary>
public static class AlertSettingsFile
{
    public const string FileName = "alert-settings.json";

    public static AlertSettings Load(string path)
    {
        try
        {
            if (File.Exists(path) && JsonSerializer.Deserialize<AlertSettings>(File.ReadAllText(path)) is { } s)
                return AlertSettings.From(s.Revision, s.Enabled, s.DisabledKinds, s.LowDiskFreeGb, s.LowDiskFreePercent, s.MemoryCommitPercent,
                    s.AppCrashRepeats, s.AppCrashWindowHours);
        }
        catch { /* a damaged file means the default until Admin sends the setting again */ }
        return AlertSettings.Default;
    }

    public static void Save(string path, AlertSettings settings)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(settings));
        File.Move(tmp, path, overwrite: true);
    }
}

/// <summary>
/// The Agent's alerts and their outbox. A repeat of an open alert (same kind and instance) raises its count instead of making a new
/// one; every change gives the alert a new sequence number, and everything above what Admin acknowledged is uploaded again, so Admin
/// always has the latest of each alert. Rate limits: at most one new alert per kind and instance per hour, and
/// <see cref="MaxNewPerDay"/> per PC per day, then one "too many alerts" alert. Kept until acknowledged and closed, capped at
/// <see cref="MaxAlerts"/> or <see cref="MaxAge"/>. Saved after every change with a write-then-replace. Thread-safe.
/// </summary>
public sealed class AgentAlertBook
{
    public const int MaxAlerts = 500;
    public static readonly TimeSpan MaxAge = TimeSpan.FromDays(30);
    public const int BatchSize = 50;
    public const int MaxNewPerDay = 20;
    public static readonly TimeSpan NewPerKeyGap = TimeSpan.FromHours(1);
    /// <summary>An event alert with no repeat for this long clears itself.</summary>
    public static readonly TimeSpan EventAlertQuietClear = TimeSpan.FromDays(7);
    private const int MaxOccurrences = 20;
    private const int MaxSources = 4;
    private const int MaxFacts = 8;
    private const int MaxText = 300;

    private readonly string? _path;
    private readonly Func<DateTimeOffset> _now;
    private readonly Func<string> _appVersion;
    private readonly ILogger? _log;
    private readonly object _gate = new();
    private State _state = new(1, 0, []);

    private sealed record State(long NextSeq, long AckedThrough, List<AlertRecord> Alerts);

    /// <param name="path">The file (null keeps it in memory only, for tests).</param>
    public AgentAlertBook(string? path, Func<DateTimeOffset>? now = null, Func<string>? appVersion = null, ILogger? log = null)
    {
        _path = path;
        _now = now ?? (() => DateTimeOffset.UtcNow);
        _appVersion = appVersion ?? (() => AppBuildInfo.Version);
        _log = log;
        Load();
    }

    private System.Collections.Immutable.ImmutableArray<AlertRecord> _alertsSnapshot = [];
    private System.Collections.Immutable.ImmutableArray<AlertRecord> _openSnapshot = [];

    public IReadOnlyList<AlertRecord> Alerts { get { lock (_gate) return _alertsSnapshot; } }
    public IReadOnlyList<AlertRecord> Open { get { lock (_gate) return _openSnapshot; } }

    private void RefreshSnapshotsNoLock()
    {
        _alertsSnapshot = [.. _state.Alerts];
        _openSnapshot = [.. _state.Alerts.Where(a => a.IsOpen)];
    }

    /// <summary>How many alerts changed since Admin last acknowledged.</summary>
    public int Waiting { get { lock (_gate) return _state.Alerts.Count(a => a.Seq > _state.AckedThrough); } }

    /// <summary>
    /// Records a signal. Returns the alert it created or updated, or null when the setting turns that kind off. A new alert past the
    /// daily cap becomes (or counts on) the one "too many alerts" alert.
    /// </summary>
    public AlertRecord? Raise(AlertSignal signal, AlertSettings settings)
    {
        ArgumentNullException.ThrowIfNull(signal);
        if (!settings.Allows(signal.Kind)) return null;
        lock (_gate)
        {
            var now = _now();
            var instance = signal.InstanceId ?? "";
            var open = _state.Alerts.FindLastIndex(a => a.IsOpen && a.SameKey(signal.Kind, instance));
            if (open >= 0)
                return ReplaceNoLock(open, Repeat(_state.Alerts[open], signal, now, keepStatus: true));

            // At most one new alert per kind and instance an hour: a repeat right after one was handled counts on that one.
            var recent = _state.Alerts.FindLastIndex(a => a.SameKey(signal.Kind, instance) && now - a.FirstSeenUtc < NewPerKeyGap);
            if (recent >= 0)
                return ReplaceNoLock(recent, Repeat(_state.Alerts[recent], signal, now, keepStatus: true));

            if (signal.Kind != AlertKinds.TooMany
                && _state.Alerts.Count(a => a.Kind != AlertKinds.TooMany && now - a.FirstSeenUtc < TimeSpan.FromDays(1)) >= MaxNewPerDay)
            {
                var tooMany = new AlertSignal(AlertKinds.TooMany, AlertLevel.Warning, "", "",
                    $"This PC raised more than {MaxNewPerDay} alerts in a day; the latest was {signal.Kind}.",
                    [new AlertFactItem("latest_kind", signal.Kind)]);
                var existing = _state.Alerts.FindLastIndex(a => a.IsOpen && a.SameKey(AlertKinds.TooMany, ""));
                if (existing >= 0)
                    return ReplaceNoLock(existing, Repeat(_state.Alerts[existing], tooMany, now, keepStatus: true));
                return AddNoLock(New(tooMany, now));
            }
            return AddNoLock(New(signal, now));
        }
    }

    /// <summary>A level alert's reading recovered: the open alert clears. Returns it, or null when none was open.</summary>
    public AlertRecord? Clear(string kind, string instanceId)
    {
        lock (_gate)
        {
            var open = _state.Alerts.FindLastIndex(a => a.IsOpen && a.SameKey(kind, instanceId ?? ""));
            return open < 0 ? null : ReplaceNoLock(open, _state.Alerts[open] with { Status = AlertStatus.Cleared, Seq = NextSeqNoLock() });
        }
    }

    /// <summary>
    /// Admin says the alert was handled or cleared. Admin already knows, so nothing new is uploaded for it; a later repeat opens a new
    /// alert (after the hourly gap). Returns false for an unknown alert.
    /// </summary>
    public bool SetStatus(string alertId, AlertStatus status)
    {
        if (status == AlertStatus.Open) return false;
        lock (_gate)
        {
            var i = _state.Alerts.FindIndex(a => string.Equals(a.AlertId, alertId, StringComparison.OrdinalIgnoreCase));
            if (i < 0 || _state.Alerts[i].Status == status) return i >= 0;
            _state.Alerts[i] = _state.Alerts[i] with { Status = status };
            SaveNoLock();
            return true;
        }
    }

    /// <summary>Open event alerts with no repeat for 7 days clear themselves. Returns how many did.</summary>
    public int ExpireQuiet()
    {
        lock (_gate)
        {
            var now = _now();
            var cleared = 0;
            for (var i = 0; i < _state.Alerts.Count; i++)
            {
                var a = _state.Alerts[i];
                if (!a.IsOpen || AlertKinds.IsLevel(a.Kind) || now - a.LastSeenUtc < EventAlertQuietClear) continue;
                _state.Alerts[i] = a with { Status = AlertStatus.Cleared, Seq = NextSeqNoLock() };
                cleared++;
            }
            if (cleared > 0) SaveNoLock();
            return cleared;
        }
    }

    /// <summary>The alerts that changed since Admin's last acknowledgement, oldest change first, at most <see cref="BatchSize"/>.</summary>
    public IReadOnlyList<AlertRecord> NextBatch()
    {
        lock (_gate)
            return _state.Alerts.Where(a => a.Seq > _state.AckedThrough).OrderBy(a => a.Seq).Take(BatchSize).ToList();
    }

    /// <summary>Admin saved every change through <paramref name="throughSeq"/>. Returns how many alerts that covered.</summary>
    public int Acknowledge(long throughSeq)
    {
        lock (_gate)
        {
            if (throughSeq <= _state.AckedThrough) return 0;
            var covered = _state.Alerts.Count(a => a.Seq > _state.AckedThrough && a.Seq <= throughSeq);
            _state = _state with { AckedThrough = Math.Min(throughSeq, _state.NextSeq - 1) };
            TrimNoLock();
            SaveNoLock();
            return covered;
        }
    }

    private AlertRecord New(AlertSignal s, DateTimeOffset now) => new(
        Guid.NewGuid().ToString("D"), NextSeqNoLock(), s.Kind, s.Level, s.InstanceId ?? "", Cut(s.InstanceLabel, 128), now, now, 1, AlertStatus.Open,
        Cut(s.Summary, MaxText), (s.Facts ?? []).Take(MaxFacts).ToList(), s.Source is null ? [] : [s.Source], AlertKinds.RelatedChecks(s.Kind),
        _appVersion(), [now]);

    private AlertRecord Repeat(AlertRecord a, AlertSignal s, DateTimeOffset now, bool keepStatus)
    {
        var occurrences = a.Occurrences.Append(now).TakeLast(MaxOccurrences).ToList();
        var level = Max(a.Level, s.Level);
        if (s.Escalate is { } e && occurrences.Count(t => now - t <= e.Window) >= e.Repeats) level = Max(level, e.To);
        return a with
        {
            Seq = NextSeqNoLock(),
            Level = level,
            LastSeenUtc = now,
            Count = a.Count + 1,
            Status = keepStatus ? a.Status : AlertStatus.Open,
            Summary = string.IsNullOrWhiteSpace(s.Summary) ? a.Summary : Cut(s.Summary, MaxText),
            Facts = s.Facts is { Count: > 0 } f ? f.Take(MaxFacts).ToList() : a.Facts,
            Sources = s.Source is null ? a.Sources : a.Sources.Append(s.Source).TakeLast(MaxSources).ToList(),
            AppVersion = _appVersion(),
            Occurrences = occurrences,
        };
    }

    private static AlertLevel Max(AlertLevel a, AlertLevel b) => a >= b ? a : b;

    private long NextSeqNoLock()
    {
        var seq = _state.NextSeq;
        _state = _state with { NextSeq = seq + 1 };
        return seq;
    }

    private AlertRecord AddNoLock(AlertRecord alert)
    {
        _state.Alerts.Add(alert);
        TrimNoLock();
        SaveNoLock();
        return alert;
    }

    private AlertRecord ReplaceNoLock(int index, AlertRecord alert)
    {
        _state.Alerts[index] = alert;
        SaveNoLock();
        return alert;
    }

    /// <summary>Closed alerts Admin has are dropped after 30 days; past the cap the oldest closed ones go first, then the oldest.</summary>
    private void TrimNoLock()
    {
        var oldest = _now() - MaxAge;
        _state.Alerts.RemoveAll(a => !a.IsOpen && a.Seq <= _state.AckedThrough && a.LastSeenUtc < oldest);
        while (_state.Alerts.Count > MaxAlerts)
        {
            var victim = _state.Alerts.Where(a => !a.IsOpen).OrderBy(a => a.LastSeenUtc).FirstOrDefault()
                ?? _state.Alerts.OrderBy(a => a.LastSeenUtc).First();
            _state.Alerts.Remove(victim);
        }
    }

    private void Load()
    {
        if (_path is null || !File.Exists(_path)) return;
        try
        {
            var saved = JsonSerializer.Deserialize<State>(File.ReadAllText(_path), Json);
            if (saved?.Alerts is not null)
            {
                var alerts = saved.Alerts.Where(a => a is not null && a.Seq > 0 && !string.IsNullOrEmpty(a.AlertId) && !string.IsNullOrEmpty(a.Kind))
                    .Select(a => a with
                    {
                        InstanceId = a.InstanceId ?? "", InstanceLabel = a.InstanceLabel ?? "", Summary = a.Summary ?? "", AppVersion = a.AppVersion ?? "",
                        Facts = a.Facts ?? [], Sources = a.Sources ?? [], RelatedChecks = a.RelatedChecks ?? [], Occurrences = a.Occurrences ?? [],
                    })
                    .OrderBy(a => a.Seq).ToList();
                // The next number never goes back, even if the file was edited: Admin acknowledges by sequence.
                var next = Math.Max(saved.NextSeq, alerts.Count > 0 ? alerts.Max(a => a.Seq) + 1 : 1);
                _state = new(next, Math.Clamp(saved.AckedThrough, 0, next - 1), alerts);
                RefreshSnapshotsNoLock();
            }
        }
        catch (Exception ex)
        {
            _log.Warn($"[alerts] alert file unreadable, starting a new one: {ex.Message}");
            try { File.Move(_path, _path + ".bad", overwrite: true); } catch { }
        }
    }

    private void SaveNoLock()
    {
        RefreshSnapshotsNoLock();
        if (_path is null) return;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            var tmp = _path + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(_state, Json));
            File.Move(tmp, _path, overwrite: true);
        }
        catch (Exception ex) { _log.Warn($"[alerts] alert file not saved: {ex.Message}"); }
    }

    private static string Cut(string? text, int max) => string.IsNullOrEmpty(text) ? "" : text.Length <= max ? text : text[..max];

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = false };
}
