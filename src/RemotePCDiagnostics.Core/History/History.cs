using System.Globalization;
using System.Text.Json;
using RemotePCDiagnostics.Core.Logging;

namespace RemotePCDiagnostics.Core.History;

public sealed record HistoryMeasurement(string Name, string Value);

/// <summary>One finished test, as kept in the history file (one JSON object per line).</summary>
public sealed record HistoryEntry(
    DateTimeOffset TimeUtc, string Module, string Test, string Outcome, string Summary, double? DurationSeconds,
    string? Suite, IReadOnlyList<HistoryMeasurement> Measurements, string Machine, string AppVersion)
{
    public DateTimeOffset LocalTime => TimeUtc.ToLocalTime();
    public string? Measurement(string name) => Measurements.FirstOrDefault(m => m.Name == name)?.Value;
}

/// <summary>Persistent result history. Implementations never throw from Append and never block callers.</summary>
public interface IHistoryStore
{
    void Append(HistoryEntry entry);
    /// <summary>All kept entries, oldest first.</summary>
    IReadOnlyList<HistoryEntry> ReadAll();
    void Clear();
    event Action? Changed;
}

/// <summary>Used when no history is kept (tests, failures).</summary>
public sealed class NullHistoryStore : IHistoryStore
{
    public void Append(HistoryEntry entry) { }
    public IReadOnlyList<HistoryEntry> ReadAll() => [];
    public void Clear() { }
    public event Action? Changed { add { } remove { } }
}

/// <summary>
/// JSON Lines history file (Host: %LOCALAPPDATA%\RemotePCDiagnostics\history\history.jsonl). Entries are kept in memory
/// and appended to the file on a background task. Retention: last <see cref="MaxAge"/> and at most <see cref="MaxEntries"/>,
/// pruned on load and at most once a day. Corrupt or unreadable lines are skipped.
/// </summary>
public sealed class JsonLinesHistoryStore : IHistoryStore
{
    public static readonly TimeSpan MaxAge = TimeSpan.FromDays(90);
    public const int MaxEntries = 5000;
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = false };
    private readonly string _path;
    private readonly Func<DateTimeOffset> _now;
    private readonly Action<string>? _log;
    private readonly object _gate = new();
    private readonly List<HistoryEntry> _entries = [];
    private Task _io = Task.CompletedTask;
    private DateTimeOffset _lastPrune;
    private bool _logged;

    public event Action? Changed;

    public JsonLinesHistoryStore(string path, Func<DateTimeOffset>? now = null, Action<string>? log = null)
    {
        _path = path; _now = now ?? (() => DateTimeOffset.UtcNow); _log = log;
        try { Load(); } catch (Exception ex) { Note($"History: load failed: {ex.Message}"); }
    }

    public string FilePath => _path;
    public int CorruptLinesSkipped { get; private set; }

    private void Load()
    {
        if (!File.Exists(_path)) { _lastPrune = _now(); return; }
        foreach (var line in File.ReadLines(_path))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            try
            {
                var e = JsonSerializer.Deserialize<HistoryEntry>(line, Json);
                if (e is null || string.IsNullOrEmpty(e.Module)) { CorruptLinesSkipped++; continue; }
                _entries.Add(e with { Measurements = e.Measurements ?? [], Summary = e.Summary ?? "", Test = e.Test ?? e.Module, Outcome = e.Outcome ?? "" });
            }
            catch { CorruptLinesSkipped++; }
        }
        _entries.Sort((a, b) => a.TimeUtc.CompareTo(b.TimeUtc));
        if (PruneLocked() || CorruptLinesSkipped > 0) Enqueue(RewriteSnapshot());
        if (CorruptLinesSkipped > 0) Note($"History: skipped {CorruptLinesSkipped} unreadable line(s)");
    }

    /// <summary>Drops entries beyond retention; true when something was removed.</summary>
    private bool PruneLocked()
    {
        _lastPrune = _now();
        var cutoff = _now() - MaxAge;
        var before = _entries.Count;
        _entries.RemoveAll(e => e.TimeUtc < cutoff);
        if (_entries.Count > MaxEntries) _entries.RemoveRange(0, _entries.Count - MaxEntries);
        return _entries.Count != before;
    }

    public void Append(HistoryEntry entry)
    {
        try
        {
            lock (_gate)
            {
                _entries.Add(entry);
                if (_now() - _lastPrune > TimeSpan.FromDays(1) || _entries.Count > MaxEntries)
                {
                    PruneLocked();
                    Enqueue(RewriteSnapshot());
                }
                else
                {
                    var line = JsonSerializer.Serialize(entry, Json);
                    Enqueue(() => { EnsureDir(); File.AppendAllText(_path, line + Environment.NewLine); });
                }
            }
            RaiseChanged();
        }
        catch (Exception ex) { Note($"History: append failed: {ex.Message}"); }
    }

    public IReadOnlyList<HistoryEntry> ReadAll() { lock (_gate) return _entries.ToList(); }

    public void Clear()
    {
        try
        {
            lock (_gate) { _entries.Clear(); Enqueue(() => { if (File.Exists(_path)) File.Delete(_path); }); }
            RaiseChanged();
        }
        catch (Exception ex) { Note($"History: clear failed: {ex.Message}"); }
    }

    /// <summary>Waits for pending file writes (tests, app exit).</summary>
    public bool Flush(TimeSpan timeout) { Task t; lock (_gate) t = _io; try { return t.Wait(timeout); } catch { return false; } }

    private Action RewriteSnapshot()
    {
        var lines = _entries.Select(e => JsonSerializer.Serialize(e, Json)).ToList();
        return () =>
        {
            EnsureDir();
            var tmp = _path + ".tmp";
            File.WriteAllLines(tmp, lines);
            File.Move(tmp, _path, true);
        };
    }

    private void Enqueue(Action write) =>
        _io = _io.ContinueWith(_ => { try { write(); } catch (Exception ex) { Note($"History: write failed: {ex.Message}"); } }, TaskScheduler.Default);

    private void EnsureDir() { var d = Path.GetDirectoryName(_path); if (!string.IsNullOrEmpty(d)) Directory.CreateDirectory(d); }

    private void RaiseChanged() { try { Changed?.Invoke(); } catch { } }

    private void Note(string m)
    {
        if (_logged && m.StartsWith("History: write", StringComparison.Ordinal)) return;
        if (m.StartsWith("History: write", StringComparison.Ordinal)) _logged = true;
        try { _log?.Invoke(m); } catch { }
    }
}

/// <summary>Builds history entries from finished results (called by <see cref="ResultEventLogger"/> after its dedup/throttle).</summary>
public sealed class HistoryRecorder(IHistoryStore store, Func<string, string> displayName, Func<string> machine, string appVersion)
{
    public void Record(DiagnosticResult r, TimeSpan? duration, string? suite)
    {
        try
        {
            store.Append(new HistoryEntry(r.Timestamp.ToUniversalTime(), r.ModuleName, SafeName(r.ModuleName), ResultEventLogger.Outcome(r), r.Message,
                duration is { } d ? Math.Round(d.TotalSeconds, 1) : null, suite,
                ResultEventLogger.Measurements(r.Payload).Select(m => new HistoryMeasurement(m.Name, m.Value)).ToList(), SafeMachine(), appVersion));
        }
        catch { /* history must never affect a run */ }
    }

    private string SafeMachine() { try { return machine(); } catch { return Environment.MachineName; } }

    private string SafeName(string module) { try { return displayName(module); } catch { return module; } }
}

public enum HistoryColumn { Time, Test, Result, Summary, Duration }
public enum HistoryRange { Last24Hours, Last7Days, Last30Days, All }

/// <summary>Filter, sort and trend logic for the History page.</summary>
public static class HistoryQuery
{
    public static readonly (HistoryColumn Col, bool Desc) DefaultSort = (HistoryColumn.Time, true);
    public static readonly IReadOnlyList<(HistoryColumn Col, string Title)> Columns =
        [(HistoryColumn.Time, "Time"), (HistoryColumn.Test, "Test"), (HistoryColumn.Result, "Result"), (HistoryColumn.Summary, "Summary"), (HistoryColumn.Duration, "Duration")];
    public static readonly IReadOnlyList<string> Outcomes = ["OK", "Warning", "Critical", "Cancelled", "Unavailable"];

    public static TimeSpan? RangeSpan(HistoryRange r) => r switch
    {
        HistoryRange.Last24Hours => TimeSpan.FromHours(24), HistoryRange.Last7Days => TimeSpan.FromDays(7), HistoryRange.Last30Days => TimeSpan.FromDays(30), _ => null,
    };

    public static IEnumerable<HistoryEntry> Filter(IEnumerable<HistoryEntry> entries, string? module, string? outcome, HistoryRange range, DateTimeOffset now)
    {
        var span = RangeSpan(range);
        return entries.Where(e => string.IsNullOrEmpty(module) || string.Equals(e.Module, module, StringComparison.OrdinalIgnoreCase))
            .Where(e => string.IsNullOrEmpty(outcome) || string.Equals(e.Outcome, outcome, StringComparison.OrdinalIgnoreCase))
            .Where(e => span is null || e.TimeUtc >= now - span.Value);
    }

    /// <summary>Critical first when ascending.</summary>
    public static int OutcomeRank(string o) => o switch { "Critical" => 0, "Warning" => 1, "Cancelled" => 2, "Unavailable" => 3, "OK" => 4, _ => 5 };

    public static int Compare(HistoryEntry a, HistoryEntry b, HistoryColumn col) => col switch
    {
        HistoryColumn.Time => a.TimeUtc.CompareTo(b.TimeUtc),
        HistoryColumn.Test => string.Compare(a.Test, b.Test, StringComparison.OrdinalIgnoreCase),
        HistoryColumn.Result => OutcomeRank(a.Outcome).CompareTo(OutcomeRank(b.Outcome)),
        HistoryColumn.Summary => string.Compare(a.Summary, b.Summary, StringComparison.OrdinalIgnoreCase),
        HistoryColumn.Duration => (a.DurationSeconds is null, b.DurationSeconds is null) switch
        {
            (true, true) => 0, (true, false) => 1, (false, true) => -1, _ => a.DurationSeconds!.Value.CompareTo(b.DurationSeconds!.Value),
        },
        _ => 0,
    };

    /// <summary>Stable sort; ties fall back to newest first.</summary>
    public static IReadOnlyList<HistoryEntry> Sort(IEnumerable<HistoryEntry> entries, HistoryColumn col, bool desc)
    {
        var list = entries.Select((e, i) => (e, i)).ToList();
        list.Sort((p, q) =>
        {
            var c = Compare(p.e, q.e, col);
            if (desc) c = -c;
            if (c == 0) c = q.e.TimeUtc.CompareTo(p.e.TimeUtc);
            return c != 0 ? c : p.i.CompareTo(q.i);
        });
        return list.Select(p => p.e).ToList();
    }

    public static (HistoryColumn Col, bool Desc) Toggle((HistoryColumn Col, bool Desc) current, HistoryColumn col) =>
        current.Col == col ? (col, !current.Desc) : (col, col is HistoryColumn.Time or HistoryColumn.Duration);

    /// <summary>Key measurement per stress test for the trend list: (measurement, friendly label, unit).</summary>
    public static (string Name, string Label, string Unit)? TrendKey(string module) => module switch
    {
        "CpuStress" => ("MaxCpuTemperatureC", "Peak CPU temperature", "°C"),
        "MemoryTest" => ("MaxCpuTemperatureC", "Peak CPU temperature", "°C"),
        "GpuStress" => ("MaxGpuTemperatureC", "Peak GPU temperature", "°C"),
        "DiskSpeed" => ("SequentialReadMBps", "Read speed", "MB/s"),
        "NetworkTest" => ("DownloadMbps", "Download speed", "Mbps"),
        _ => null,
    };

    /// <summary>Last <paramref name="max"/> values of the module's key measurement, oldest first (runs without it are skipped).</summary>
    public static IReadOnlyList<(DateTimeOffset Time, double Value)> Trend(IEnumerable<HistoryEntry> entries, string module, int max = 12)
    {
        if (TrendKey(module) is not { } key) return [];
        return entries.Where(e => e.Module == module)
            .Select(e => (e.TimeUtc, V: double.TryParse(e.Measurement(key.Name), NumberStyles.Float, CultureInfo.InvariantCulture, out var v) ? v : (double?)null))
            .Where(x => x.V is not null).OrderBy(x => x.TimeUtc).TakeLast(max).Select(x => (x.TimeUtc, x.V!.Value)).ToList();
    }

    public static string FormatDuration(double? seconds) => seconds switch
    {
        null => "—",
        < 60 => $"{seconds.Value:0} s",
        < 3600 => $"{(int)(seconds.Value / 60)} min {(int)(seconds.Value % 60)} s",
        _ => $"{(int)(seconds.Value / 3600)} h {(int)(seconds.Value % 3600 / 60)} min",
    };

    /// <summary>CSV export (invariant, RFC 4180 quoting).</summary>
    public static string ToCsv(IEnumerable<HistoryEntry> entries)
    {
        static string Q(string? s) => s is null ? "" : s.Contains('"') || s.Contains(',') || s.Contains('\n') ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;
        var sb = new System.Text.StringBuilder("TimeUtc,Test,Result,Summary,DurationSeconds,Suite,Measurements,Machine,AppVersion\n");
        foreach (var e in entries)
            sb.Append(Q(e.TimeUtc.ToString("O", CultureInfo.InvariantCulture))).Append(',').Append(Q(e.Test)).Append(',').Append(Q(e.Outcome)).Append(',')
              .Append(Q(e.Summary)).Append(',').Append(e.DurationSeconds?.ToString(CultureInfo.InvariantCulture)).Append(',').Append(Q(e.Suite)).Append(',')
              .Append(Q(string.Join("; ", e.Measurements.Select(m => $"{m.Name}={m.Value}")))).Append(',').Append(Q(e.Machine)).Append(',').Append(Q(e.AppVersion)).Append('\n');
        return sb.ToString();
    }
}
