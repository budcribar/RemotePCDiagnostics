using System.Globalization;
using RemotePCDiagnostics.Core.Logging;

namespace RemotePCDiagnostics.Core.History;

public sealed record HistoryMeasurement(string Name, string Value);

/// <summary>One finished test, as kept in the history file (one JSON object per line).</summary>
public sealed record HistoryEntry(
    DateTimeOffset TimeUtc, string Module, string Test, string Outcome, string Summary, double? DurationSeconds,
    string? Suite, IReadOnlyList<HistoryMeasurement> Measurements, string Machine, string AppVersion, IReadOnlyList<string>? Details = null)
{
    public DateTimeOffset LocalTime => TimeUtc.ToLocalTime();
    public string? Measurement(string name) => Measurements.FirstOrDefault(m => m.Name == name)?.Value;
}

/// <summary>Result of reading history. Available=false when the source can't be read (Problem has the technical reason, log only).</summary>
public sealed record HistoryReadResult(IReadOnlyList<HistoryEntry> Entries, bool Available, string? Problem = null);

/// <summary>Read-only result history (Host: Windows Event Log, Application, source RemotePCDiagnostics, event 1100).</summary>
public interface IHistoryStore
{
    /// <summary>Entries newest first, limited to <paramref name="within"/> (null = all). Never throws.</summary>
    HistoryReadResult Read(TimeSpan? within);
}

/// <summary>Used where no history source exists (non-Windows, tests).</summary>
public sealed class NullHistoryStore : IHistoryStore
{
    public HistoryReadResult Read(TimeSpan? within) => new([], false, "no history source");
}

/// <summary>Raw event as read from the log: time created and rendered message.</summary>
public sealed record RawHistoryEvent(DateTimeOffset TimeCreated, string? Message);

/// <summary>
/// History from raw Event Log events: builds the query, parses each 1100 message (current and older formats; unparseable
/// ones are skipped) and turns any reader failure (no source, access denied, not Windows) into Available=false.
/// </summary>
public sealed class EventLogHistoryStore(Func<string, int, IEnumerable<RawHistoryEvent>> query, Action<string>? log = null) : IHistoryStore
{
    public const string ProviderName = "RemotePCDiagnostics";
    public const string LogName = "Application";
    public const int MaxEvents = 5000;

    /// <summary>XPath for 1100 events of our provider, optionally within the last <paramref name="within"/>.</summary>
    public static string BuildXPath(TimeSpan? within)
    {
        var time = within is { } w ? $" and TimeCreated[timediff(@SystemTime) <= {(long)Math.Max(0, w.TotalMilliseconds)}]" : "";
        return $"*[System[Provider[@Name='{ProviderName}'] and (EventID={LogEventIds.TestResult}){time}]]";
    }

    public HistoryReadResult Read(TimeSpan? within)
    {
        var list = new List<HistoryEntry>();
        var skipped = 0;
        try
        {
            foreach (var raw in query(BuildXPath(within), MaxEvents))
            {
                if (list.Count >= MaxEvents) break;
                if (HistoryEventParser.Parse(raw.Message, raw.TimeCreated) is { } e) list.Add(e); else skipped++;
            }
        }
        catch (Exception ex)
        {
            try { log?.Invoke($"History: Event Log read failed: {ex.GetType().Name}: {ex.Message}"); } catch { }
            return new(list.OrderByDescending(e => e.TimeUtc).ToList(), list.Count > 0, $"{ex.GetType().Name}: {ex.Message}");
        }
        if (skipped > 0) try { log?.Invoke($"History: skipped {skipped} unparseable event(s)"); } catch { }
        return new(list.OrderByDescending(e => e.TimeUtc).ToList(), true);
    }
}

/// <summary>Parses the 1100 "Test result" message. Format 2 (current): "Key: value" lines + "Measurements:" ("  Name=value").
/// Older messages (no Format line): measurements taken from numeric "  Name: value" lines under "Details:".</summary>
public static class HistoryEventParser
{
    public const int MaxDetailLines = 40;

    public static HistoryEntry? Parse(string? message, DateTimeOffset timeCreated)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(message)) return null;
            var lines = message.Replace("\r\n", "\n").Split('\n');
            var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var measurements = new List<HistoryMeasurement>();
            var oldDetails = new List<HistoryMeasurement>();
            var details = new List<string>();
            string? section = null;
            foreach (var raw in lines)
            {
                if (raw.Length == 0) continue;
                if (raw[0] == ' ')
                {
                    var t = raw.Trim();
                    if (section == "Measurements") { var i = t.IndexOf('='); if (i > 0) measurements.Add(new(t[..i].Trim(), t[(i + 1)..].Trim())); }
                    else if (section == "Details") { if (details.Count < MaxDetailLines) details.Add(t.Length > 300 ? t[..300] + "…" : t); var i = t.IndexOf(": ", StringComparison.Ordinal); if (i > 0 && IsSimpleValue(t[(i + 2)..])) oldDetails.Add(new(t[..i].Trim(), t[(i + 2)..].Trim())); }
                    continue;
                }
                var c = raw.IndexOf(':');
                if (c <= 0) continue;
                var key = raw[..c].Trim();
                var value = raw[(c + 1)..].Trim();
                if (value.Length == 0 && key is "Measurements" or "Details") { section = key; continue; }
                section = null;
                fields.TryAdd(key, value);
            }
            if (!fields.TryGetValue("Test result", out var module) || module.Length == 0) return null;
            if (!fields.TryGetValue("Outcome", out var outcome) || outcome.Length == 0) return null;
            var time = fields.TryGetValue("Finished", out var f) && DateTimeOffset.TryParse(f, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var ft) ? ft : timeCreated;
            double? dur = fields.TryGetValue("Duration", out var d) && double.TryParse(d.Replace(" s", ""), NumberStyles.Float, CultureInfo.InvariantCulture, out var dv) ? dv : null;
            return new HistoryEntry(time.ToUniversalTime(), module, fields.GetValueOrDefault("Test") is { Length: > 0 } t2 ? t2 : module, outcome,
                fields.GetValueOrDefault("Summary") ?? "", dur, fields.GetValueOrDefault("Stress suite"),
                fields.ContainsKey("Format") ? measurements : oldDetails,
                fields.GetValueOrDefault("Machine") ?? "", fields.GetValueOrDefault("App version") ?? "", details);
        }
        catch { return null; }
    }

    /// <summary>Old Details lines: keep numbers, durations, yes/no and single-word enum values only.</summary>
    private static bool IsSimpleValue(string v)
    {
        v = v.Trim();
        if (v.EndsWith(" s", StringComparison.Ordinal)) v = v[..^2];
        return double.TryParse(v, NumberStyles.Float, CultureInfo.InvariantCulture, out _) || v is "yes" or "no" || (v.Length is > 0 and < 40 && v.All(char.IsLetterOrDigit));
    }
}

/// <summary>Consistent test names: events without a "Test:" line (older builds) get the module's display name.</summary>
public static class HistoryNames
{
    /// <summary>Display name for a module ID from the registered modules; the ID itself for unknown modules.</summary>
    public static string DisplayName(string module, IEnumerable<IDiagnosticModule> modules)
    {
        var m = modules.FirstOrDefault(x => string.Equals(x.Name, module, StringComparison.OrdinalIgnoreCase));
        return m is null || string.IsNullOrWhiteSpace(m.DisplayName) ? module : m.DisplayName;
    }

    /// <summary>Replaces Test with the display name where the event had none (Test equals the module ID).</summary>
    public static IReadOnlyList<HistoryEntry> Normalize(IEnumerable<HistoryEntry> entries, IEnumerable<IDiagnosticModule> modules)
    {
        var mods = modules.ToList();
        return entries.Select(e => string.IsNullOrWhiteSpace(e.Test) || string.Equals(e.Test, e.Module, StringComparison.OrdinalIgnoreCase)
            ? e with { Test = DisplayName(e.Module, mods) } : e).ToList();
    }

    /// <summary>Test filter options (module ID, name): every module present in the data, once, sorted by name.</summary>
    public static IReadOnlyList<(string Module, string Test)> FilterOptions(IEnumerable<HistoryEntry> entries, IEnumerable<IDiagnosticModule> modules)
    {
        var mods = modules.ToList();
        return entries.GroupBy(e => e.Module, StringComparer.OrdinalIgnoreCase)
            .Select(g => (Module: g.Key, Test: DisplayName(g.Key, mods) is var d && !string.Equals(d, g.Key, StringComparison.OrdinalIgnoreCase) ? d : g.First().Test))
            .OrderBy(t => t.Test, StringComparer.OrdinalIgnoreCase).ToList();
    }
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
