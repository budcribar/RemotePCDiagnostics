using System.Text.Json;

namespace RemotePCDiagnostics.Core.Metrics;

/// <summary>
/// The fleet admin's setting for the Agent's scheduled metrics pass, as last received from Admin (or the default before Admin sends one).
/// Saved by the Agent in its protected state folder, so it keeps working while the PC is offline.
/// </summary>
public sealed record MetricsSchedule(long Revision, bool Enabled, int IntervalMinutes, IReadOnlyList<string> CheckIds)
{
    public const int MinIntervalMinutes = 60;
    public const int MaxIntervalMinutes = 7 * 24 * 60;
    public const int DefaultIntervalMinutes = 24 * 60;

    /// <summary>What the pass measures unless Admin picks others: battery, each drive, temperatures, memory and uptime.</summary>
    public static readonly IReadOnlyList<string> DefaultChecks = [ModuleSlugs.BatteryPower, ModuleSlugs.DriveHealth, ModuleSlugs.Sensors, ModuleSlugs.ResourceHogs];

    /// <summary>Before Admin has sent a setting: on, once a day, the default checks.</summary>
    public static MetricsSchedule Default { get; } = new(0, true, DefaultIntervalMinutes, DefaultChecks);

    public TimeSpan Interval => TimeSpan.FromMinutes(Math.Clamp(IntervalMinutes, MinIntervalMinutes, MaxIntervalMinutes));

    /// <summary>The checks to run: the ones Admin picked that the pass knows, else the defaults.</summary>
    public IReadOnlyList<string> Checks
    {
        get
        {
            var known = CheckIds.Select(id => DefaultChecks.FirstOrDefault(d => string.Equals(d, id?.Trim(), StringComparison.OrdinalIgnoreCase)))
                .OfType<string>().Distinct().ToList();
            return known.Count > 0 ? known : DefaultChecks;
        }
    }

    /// <summary>A setting from Admin, made safe: interval clamped, at most 16 check ids.</summary>
    public static MetricsSchedule From(long revision, bool enabled, int intervalMinutes, IEnumerable<string>? checkIds) =>
        new(Math.Max(0, revision), enabled, Math.Clamp(intervalMinutes <= 0 ? DefaultIntervalMinutes : intervalMinutes, MinIntervalMinutes, MaxIntervalMinutes),
            (checkIds ?? []).Where(c => !string.IsNullOrWhiteSpace(c)).Select(c => c.Trim()).Take(16).ToList());
}

/// <summary>One key metric of a scheduled run, as kept in the outbox and uploaded.</summary>
public sealed record MetricsValue(string Id, string Label, double Value, string Unit, MetricTrend Better);

/// <summary>One check's result from a scheduled pass: what Admin stores and charts.</summary>
public sealed record MetricsRunRecord(
    string RunId, long Seq, string CheckId, string? InstanceId, string? InstanceLabel, DateTimeOffset FinishedUtc,
    string Outcome, string Summary, IReadOnlyList<MetricsValue> Metrics, string AppVersion);

/// <summary>
/// The Agent's outbox of scheduled runs Admin hasn't acknowledged. Capped by count and age (oldest dropped first), saved after every
/// change with a write-then-replace, and drained only by an acknowledgement, so a run is never lost to a dropped connection and never
/// sent twice as two different runs (each keeps its run id and sequence number). Thread-safe.
/// </summary>
public sealed class MetricsOutbox
{
    public const int MaxRuns = 500;
    public static readonly TimeSpan MaxAge = TimeSpan.FromDays(30);
    public const int BatchSize = 50;

    private readonly string? _path;
    private readonly Func<DateTimeOffset> _now;
    private readonly ILogger? _log;
    private readonly object _gate = new();
    private State _state = new(1, []);

    private sealed record State(long NextSeq, List<MetricsRunRecord> Runs);

    /// <param name="path">The outbox file (null keeps it in memory only, for tests).</param>
    public MetricsOutbox(string? path, Func<DateTimeOffset>? now = null, ILogger? log = null)
    {
        _path = path;
        _now = now ?? (() => DateTimeOffset.UtcNow);
        _log = log;
        Load();
    }

    public int Count { get { lock (_gate) return _state.Runs.Count; } }

    /// <summary>Adds a finished run with the next sequence number, dropping what is too old or over the cap.</summary>
    public MetricsRunRecord Add(string checkId, string? instanceId, string? instanceLabel, DateTimeOffset finished, string outcome, string summary,
        IReadOnlyList<MetricsValue> metrics, string appVersion)
    {
        lock (_gate)
        {
            var run = new MetricsRunRecord(Guid.NewGuid().ToString("D"), _state.NextSeq, checkId, instanceId, instanceLabel, finished.ToUniversalTime(),
                outcome, summary.Length > 300 ? summary[..300] : summary,
                // NaN and infinity have no JSON form: one would make every later save of the outbox fail.
                metrics.Where(m => double.IsFinite(m.Value)).Take(16).ToList(), appVersion);
            _state = _state with { NextSeq = _state.NextSeq + 1 };
            _state.Runs.Add(run);
            TrimNoLock();
            SaveNoLock();
            return run;
        }
    }

    /// <summary>The oldest runs not yet acknowledged, at most <see cref="BatchSize"/>.</summary>
    public IReadOnlyList<MetricsRunRecord> NextBatch()
    {
        lock (_gate)
        {
            TrimNoLock();
            return _state.Runs.OrderBy(r => r.Seq).Take(BatchSize).ToList();
        }
    }

    /// <summary>Admin saved every run through <paramref name="throughSeq"/>: forget them. Returns how many went.</summary>
    public int Acknowledge(long throughSeq)
    {
        lock (_gate)
        {
            var removed = _state.Runs.RemoveAll(r => r.Seq <= throughSeq);
            if (removed > 0) SaveNoLock();
            return removed;
        }
    }

    private void TrimNoLock()
    {
        var oldest = _now() - MaxAge;
        _state.Runs.RemoveAll(r => r.FinishedUtc < oldest);
        if (_state.Runs.Count > MaxRuns)
            _state.Runs.RemoveRange(0, _state.Runs.Count - MaxRuns); // kept in sequence order: the oldest go
    }

    private void Load()
    {
        if (_path is null || !File.Exists(_path)) return;
        try
        {
            var saved = JsonSerializer.Deserialize<State>(File.ReadAllText(_path), Json);
            if (saved?.Runs is not null)
            {
                var runs = saved.Runs.Where(r => r is not null && r.Seq > 0 && !string.IsNullOrEmpty(r.RunId)).OrderBy(r => r.Seq).ToList();
                // The next number never goes back, even if the file was edited: Admin acknowledges by sequence.
                _state = new(Math.Max(saved.NextSeq, runs.Count > 0 ? runs[^1].Seq + 1 : 1), runs);
            }
        }
        catch (Exception ex)
        {
            // A damaged outbox is set aside, not fatal: the next pass starts a new one.
            _log.Warn($"[metrics] outbox unreadable, starting a new one: {ex.Message}");
            try { File.Move(_path, _path + ".bad", overwrite: true); } catch { }
        }
    }

    private void SaveNoLock()
    {
        if (_path is null) return;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            var tmp = _path + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(_state, Json));
            File.Move(tmp, _path, overwrite: true);
        }
        catch (Exception ex) { _log.Warn($"[metrics] outbox not saved: {ex.Message}"); }
    }

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = false };
}

/// <summary>Saves and loads <see cref="MetricsSchedule"/> (the Agent's protected state folder).</summary>
public static class MetricsScheduleFile
{
    public const string FileName = "metrics-schedule.json";

    public static MetricsSchedule Load(string path)
    {
        try
        {
            if (File.Exists(path) && JsonSerializer.Deserialize<MetricsSchedule>(File.ReadAllText(path)) is { } s)
                return MetricsSchedule.From(s.Revision, s.Enabled, s.IntervalMinutes, s.CheckIds);
        }
        catch { /* a damaged file means the default until Admin sends the setting again */ }
        return MetricsSchedule.Default;
    }

    public static void Save(string path, MetricsSchedule schedule)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(schedule));
        File.Move(tmp, path, overwrite: true);
    }
}

/// <summary>Why a scheduled pass is not run now.</summary>
public enum MetricsSkip { None, Disabled, NotDue, TooSoonAfterBoot, PassRunning, SessionRunning, LowBattery }

/// <summary>
/// When the Agent runs a pass. Each PC gets its own fixed offset into the interval (from its machine id), so a fleet doesn't measure
/// at the same minute. A pass waits until Windows has been up a while, never overlaps another, and is put off while a remote session
/// runs or the PC is on battery below 20%.
/// </summary>
public static class MetricsPlanner
{
    public static readonly TimeSpan AfterBoot = TimeSpan.FromMinutes(10);
    /// <summary>How long a put-off pass waits before trying again.</summary>
    public static readonly TimeSpan RetryAfterSkip = TimeSpan.FromMinutes(30);
    /// <summary>"Collect now" more often than this is ignored.</summary>
    public static readonly TimeSpan MinOnDemandGap = TimeSpan.FromMinutes(5);
    public const int MinBatteryPercent = 20;

    /// <summary>The offset into each interval for this PC: up to a tenth of it, the same on every start.</summary>
    public static TimeSpan Jitter(string machineId, TimeSpan interval)
    {
        var hash = 0u;
        foreach (var c in machineId ?? "") hash = unchecked(hash * 31 + c);
        return TimeSpan.FromSeconds(hash % Math.Max(1, (uint)(interval.TotalSeconds / 10)));
    }

    public static DateTimeOffset NextDue(DateTimeOffset? lastPassUtc, MetricsSchedule schedule, string machineId, DateTimeOffset bootUtc)
    {
        var earliest = bootUtc + AfterBoot;
        if (lastPassUtc is not { } last) return earliest + Jitter(machineId, TimeSpan.FromMinutes(MetricsSchedule.MinIntervalMinutes));
        var due = last + schedule.Interval;
        return due < earliest ? earliest : due;
    }

    public static MetricsSkip Check(MetricsSchedule schedule, DateTimeOffset now, DateTimeOffset nextDue, bool passRunning, bool sessionRunning,
        bool onBattery, int? batteryPercent, bool onDemand = false)
    {
        if (passRunning) return MetricsSkip.PassRunning;
        if (!onDemand && !schedule.Enabled) return MetricsSkip.Disabled;
        if (!onDemand && now < nextDue) return MetricsSkip.NotDue;
        if (sessionRunning) return MetricsSkip.SessionRunning;
        if (onBattery && batteryPercent is { } p && p < MinBatteryPercent) return MetricsSkip.LowBattery;
        return MetricsSkip.None;
    }
}
