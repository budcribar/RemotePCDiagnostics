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
    /// <summary>The module's permanent id ("Module id:", format 3). History groups and matches on it.</summary>
    public Guid ModuleId { get; init; }
    /// <summary>The event's "Format:" version (0 when it has none).</summary>
    public int Format { get; init; }
    /// <summary>A test result written before format 3. The app no longer shows these; the one-time migration rewrites them.</summary>
    public bool IsLegacy { get; init; }
    /// <summary>The hardware instance the test ran against ("Instance id:"), or null for a system-wide test.</summary>
    public string? InstanceId { get; init; }
    /// <summary>The instance's label at run time ("Instance:"), so History can name a drive that has since been removed.</summary>
    public string? Instance { get; init; }
    public string? Measurement(string name) => Measurements.FirstOrDefault(m => m.Name == name)?.Value;
}

/// <summary>Useful expansion fields, including cleanup of older generic payload snapshots.</summary>
public static class HistoryPresentation
{
    private static bool Generic(string name) => name is "Cards" or "Summary" or "Status" or "Outcome";

    public static IReadOnlyList<HistoryMeasurement> Measurements(HistoryEntry entry) =>
        entry.Measurements.Where(m => !Generic(m.Name) && !HistoryLabels.IsHidden(m.Name)).Distinct().ToList();

    public static IReadOnlyList<string> Details(HistoryEntry entry)
    {
        return (entry.Details ?? []).Where(line =>
        {
            var text = line.Trim();
            var split = text.IndexOfAny([':', '=']);
            if (split < 0) return text != entry.Summary;
            var name = text[..split].Trim();
            var value = text[(split + 1)..].Trim();
            return !Generic(name) && !entry.Measurements.Any(m => m.Name == name && m.Value == value);
        }).Distinct().ToList();
    }
}

/// <summary>Result of reading history. Available=false when the source can't be read (Problem has the technical reason, log only).</summary>
public sealed record HistoryReadResult(IReadOnlyList<HistoryEntry> Entries, bool Available, string? Problem = null)
{
    /// <summary>Results in an older format that were left out; the one-time history update hasn't run yet (it needs administrator).</summary>
    public int LegacyEntries { get; init; }
}

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
public sealed class EventLogHistoryStore(Func<string, int, IEnumerable<RawHistoryEvent>> query, ILogger? log = null) : IHistoryStore
{
    public const string ProviderName = "RemotePCDiagnostics";
    public const string LogName = "Application";
    public const int MaxEvents = 5000;

    /// <summary>XPath for 1100 events of our provider, optionally within the last <paramref name="within"/>.</summary>
    public static string BuildXPath(TimeSpan? within)
    {
        var time = within is { } w ? $" and TimeCreated[timediff(@SystemTime) <= {(long)Math.Max(0, w.TotalMilliseconds)}]" : "";
        return $"*[System[Provider[@Name='{ProviderName}'] and (EventID={LogEventIds.TestResult} or EventID={LogEventIds.MemorySuggestion}){time}]]";
    }

    public HistoryReadResult Read(TimeSpan? within)
    {
        var list = new List<HistoryEntry>();
        var skipped = 0;
        var legacy = 0;
        try
        {
            foreach (var raw in query(BuildXPath(within), MaxEvents))
            {
                if (list.Count >= MaxEvents) break;
                if (HistoryEventParser.Parse(raw.Message, raw.TimeCreated) is not { } e) skipped++;
                else if (e.IsLegacy) legacy++; // the app reads only format 3; see StartupMigration
                else list.Add(e);
            }
        }
        catch (Exception ex)
        {
            try { log.Error($"History: Event Log read failed: {ex.GetType().Name}: {ex.Message}"); } catch { }
            return new(list.OrderByDescending(e => e.TimeUtc).ToList(), list.Count > 0, $"{ex.GetType().Name}: {ex.Message}") { LegacyEntries = legacy };
        }
        if (skipped > 0) try { log.Info($"History: skipped {skipped} unparseable event(s)"); } catch { }
        if (legacy > 0) try { log.Info($"History: {legacy} event(s) in the old format wait for the one-time history update"); } catch { }
        return new(list.OrderByDescending(e => e.TimeUtc).ToList(), true) { LegacyEntries = legacy };
    }
}

/// <summary>Parses the 1100 "Test result" message. Format 3 (current): "Key: value" lines including "Module id:", then "Measurements:"
/// ("  Name=value"). Older messages parse too, marked <see cref="HistoryEntry.IsLegacy"/>: History leaves them out and only the one-time
/// migration reads them (format 2 has no Module id; messages without a Format line keep numeric "  Name: value" Details lines).</summary>
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
            if (lines[0].Trim().Equals("Memory suggestion applied", StringComparison.OrdinalIgnoreCase) && fields.TryGetValue("Result", out var memRes) && fields.TryGetValue("Message", out var memMsg))
            {
                var memOk = string.Equals(memRes, "Success", StringComparison.OrdinalIgnoreCase) ? "OK" : "Warning";
                var memMeas = new List<HistoryMeasurement>
                {
                    new("Actor", fields.GetValueOrDefault("Actor") ?? "Local user"),
                    new("Kind", fields.GetValueOrDefault("Action") ?? HistorySummary.MemoryFixModuleId),
                };
                var freed = HistorySummary.ParseFreedBytesFromText(memMsg);
                if (freed > 0) memMeas.Add(new("FreedMemoryBytes", freed.ToString(CultureInfo.InvariantCulture)));
                var memTime = fields.TryGetValue("Logged", out var lg) && DateTimeOffset.TryParse(lg, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var lt) ? lt : timeCreated;
                return new HistoryEntry(memTime.ToUniversalTime(), HistorySummary.MemoryFixModuleId, "Memory optimization", memOk, memMsg, null, null, memMeas, "", "")
                    { ModuleId = HistoryIds.MemoryOptimization };
            }
            if (!fields.TryGetValue("Test result", out var module) || module.Length == 0) return null;
            if (!fields.TryGetValue("Outcome", out var outcome) || outcome.Length == 0) return null;
            if (outcome.Equals("Unavailable", StringComparison.OrdinalIgnoreCase)) outcome = CouldNotRun.OutcomeText; // written before "Couldn't run"
            var time = fields.TryGetValue("Finished", out var f) && DateTimeOffset.TryParse(f, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var ft) ? ft : timeCreated;
            double? dur = fields.TryGetValue("Duration", out var d) && double.TryParse(d.Replace(" s", ""), NumberStyles.Float, CultureInfo.InvariantCulture, out var dv) ? dv : null;
            var format = fields.TryGetValue("Format", out var fv) && int.TryParse(fv, NumberStyles.Integer, CultureInfo.InvariantCulture, out var fn) ? fn : 0;
            var moduleId = fields.TryGetValue("Module id", out var mid) && Guid.TryParse(mid, out var g) ? g : Guid.Empty;
            return new HistoryEntry(time.ToUniversalTime(), module, fields.GetValueOrDefault("Test") is { Length: > 0 } t2 ? t2 : module, outcome,
                fields.GetValueOrDefault("Summary") ?? "", dur, fields.GetValueOrDefault("Stress suite"),
                fields.ContainsKey("Format") ? measurements : oldDetails,
                fields.GetValueOrDefault("Machine") ?? "", fields.GetValueOrDefault("App version") ?? "", details)
                {
                    ModuleId = moduleId, Format = format, IsLegacy = format < ResultEventLogger.FormatVersion || moduleId == Guid.Empty,
                    InstanceId = fields.GetValueOrDefault("Instance id"), Instance = fields.GetValueOrDefault("Instance"),
                };
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

/// <summary>Consistent test names: every result is named through the module catalog, which knows every module that ever shipped
/// (including ones whose hardware is missing or that were retired). Events from unknown modules keep the name they were logged with.</summary>
public static class HistoryNames
{
    /// <summary>Display name for a module slug from the catalog; the slug itself for unknown modules.</summary>
    public static string DisplayName(string module, ModuleCatalog catalog) => catalog.DisplayName(module);

    /// <inheritdoc cref="DisplayName(string, ModuleCatalog)"/>
    public static string DisplayName(string module, IEnumerable<IDiagnosticModule> modules) => DisplayName(module, ModuleCatalog.For(modules));

    /// <summary>Modules that were merged into another one: their old results count as the new module's (from the catalog's MergedInto).</summary>
    public static IReadOnlyDictionary<string, string> ModuleAliases { get; } = BuiltInModules.Descriptors
        .Where(d => d.MergedInto is not null)
        .ToDictionary(d => d.Slug, d => BuiltInModules.Descriptors.First(t => t.Id == d.MergedInto).Slug, StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Maps merged modules to their current ID, and gives every known module its current display name (so a renamed
    /// test isn't listed twice). Unknown modules keep the name they were logged with.
    /// </summary>
    public static IReadOnlyList<HistoryEntry> Normalize(IEnumerable<HistoryEntry> entries, ModuleCatalog catalog) =>
        entries.Select(e =>
        {
            if (e.ModuleId != Guid.Empty && catalog.Get(e.ModuleId) is { } byId)
            {
                var current = byId.MergedInto is { } into && catalog.Get(into) is { } target ? target : byId;
                return e with { Module = current.Slug, ModuleId = current.Id, Test = current.DisplayName };
            }
            var module = catalog.CurrentSlug(e.Module);
            var known = catalog.Find(module) is not null;
            var test = known ? catalog.DisplayName(module)
                : string.IsNullOrWhiteSpace(e.Test) || string.Equals(e.Test, e.Module, StringComparison.OrdinalIgnoreCase) ? module : e.Test;
            return e with { Module = module, Test = test };
        }).ToList();

    /// <inheritdoc cref="Normalize(IEnumerable{HistoryEntry}, ModuleCatalog)"/>
    public static IReadOnlyList<HistoryEntry> Normalize(IEnumerable<HistoryEntry> entries, IEnumerable<IDiagnosticModule> modules) =>
        Normalize(entries, ModuleCatalog.For(modules));

    /// <summary>Test filter options (module ID, name): every module present in the data, once, sorted by name.</summary>
    public static IReadOnlyList<(string Module, string Test)> FilterOptions(IEnumerable<HistoryEntry> entries, ModuleCatalog catalog) =>
        entries.GroupBy(e => e.Module, StringComparer.OrdinalIgnoreCase)
            .Select(g => (Module: g.Key, Test: catalog.Find(g.Key) is { } d ? d.DisplayName : g.First().Test))
            .OrderBy(t => t.Test, StringComparer.OrdinalIgnoreCase).ToList();

    /// <inheritdoc cref="FilterOptions(IEnumerable{HistoryEntry}, ModuleCatalog)"/>
    public static IReadOnlyList<(string Module, string Test)> FilterOptions(IEnumerable<HistoryEntry> entries, IEnumerable<IDiagnosticModule> modules) =>
        FilterOptions(entries, ModuleCatalog.For(modules));
}

public enum HistoryColumn { Time, Test, Result, Summary, Duration }
public enum HistoryRange { Last24Hours, Last7Days, Last30Days, All }

/// <summary>One local calendar day of history entries, rolled up with outcome counts.</summary>
public sealed record HistoryDayGroup(
    DateOnly Date,
    string Label,
    IReadOnlyList<HistoryEntry> Entries,
    int PassedCount,
    int WarningCount,
    int CriticalCount,
    int OtherCount)
{
    public string CountText => Entries.Count == 1 ? "1 run" : $"{Entries.Count} runs";
}

/// <summary>Filter, sort and trend logic for the History page.</summary>
public static class HistoryQuery
{
    public static readonly (HistoryColumn Col, bool Desc) DefaultSort = (HistoryColumn.Time, true);
    public static readonly IReadOnlyList<(HistoryColumn Col, string Title)> Columns =
        [(HistoryColumn.Time, "Time"), (HistoryColumn.Test, "Test"), (HistoryColumn.Result, "Result"), (HistoryColumn.Summary, "Summary"), (HistoryColumn.Duration, "Duration")];
    /// <summary>Result filter choices. Cancelled runs aren't part of history (see <see cref="WithoutCancelled"/>).</summary>
    public static readonly IReadOnlyList<string> Outcomes = ["OK", "Warning", "Critical", CouldNotRun.OutcomeText, "Skipped", "Blocked"];

    /// <summary>A cancelled run didn't produce a result, so history ignores it (lists, counts and trends).</summary>
    public static IReadOnlyList<HistoryEntry> WithoutCancelled(IEnumerable<HistoryEntry> entries) =>
        entries.Where(e => !string.Equals(e.Outcome, "Cancelled", StringComparison.OrdinalIgnoreCase)).ToList();

    /// <summary>Day heading for the history list: "Today", "Yesterday", "Tuesday, Oct 27" (year added when not this year).</summary>
    public static string DayLabel(DateTimeOffset localTime, DateTimeOffset localNow)
    {
        var d = localTime.Date; var today = localNow.Date;
        if (d == today) return "Today";
        if (d == today.AddDays(-1)) return "Yesterday";
        return localTime.ToString(d.Year == today.Year ? "dddd, MMM d" : "dddd, MMM d yyyy", CultureInfo.InvariantCulture);
    }

    /// <summary>Groups entries by local calendar day for collapsible day-by-day rollup on the History page.</summary>
    public static IReadOnlyList<HistoryDayGroup> GroupByDay(
        IEnumerable<HistoryEntry> entries,
        DateTimeOffset localNow,
        bool ascendingDays = false)
    {
        var groups = entries.GroupBy(e => DateOnly.FromDateTime(e.LocalTime.Date));
        var ordered = ascendingDays ? groups.OrderBy(g => g.Key) : groups.OrderByDescending(g => g.Key);
        return ordered.Select(g =>
        {
            var list = g.ToList();
            var passed = 0;
            var warning = 0;
            var critical = 0;
            var other = 0;
            foreach (var e in list)
            {
                if (string.Equals(e.Outcome, "OK", StringComparison.OrdinalIgnoreCase)) passed++;
                else if (string.Equals(e.Outcome, "Warning", StringComparison.OrdinalIgnoreCase)) warning++;
                else if (string.Equals(e.Outcome, "Critical", StringComparison.OrdinalIgnoreCase)) critical++;
                else other++;
            }
            return new HistoryDayGroup(
                g.Key,
                DayLabel(list[0].LocalTime, localNow),
                list,
                passed,
                warning,
                critical,
                other);
        }).ToList();
    }

    /// <summary>Newest result per module (cancelled runs ignored), for "last run" on tests not run in this session.</summary>
    public static IReadOnlyDictionary<string, HistoryEntry> LatestByModule(IEnumerable<HistoryEntry> entries) =>
        WithoutCancelled(entries).GroupBy(e => e.Module, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.MaxBy(e => e.TimeUtc)!, StringComparer.OrdinalIgnoreCase);

    /// <summary>Rows shown at first (and added per "Show more").</summary>
    public const int PageSize = 100;

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
    public static int OutcomeRank(string o) => o switch { "Critical" => 0, "Warning" => 1, "Cancelled" => 2, CouldNotRun.OutcomeText => 3, "Skipped" => 4, "Blocked" => 5, "OK" => 6, _ => 7 };

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
        ModuleSlugs.CpuStress => ("MaxCpuTemperatureC", "Peak CPU temperature", "°C"),
        ModuleSlugs.MemoryTest => ("MaxCpuTemperatureC", "Peak CPU temperature", "°C"),
        ModuleSlugs.GpuStress => ("MaxGpuTemperatureC", "Peak GPU temperature", "°C"),
        ModuleSlugs.DiskSpeed => ("SequentialReadMBps", "Read speed", "MB/s"),
        ModuleSlugs.NetworkTest => ("DownloadMbps", "Download speed", "Mbps"),
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

    public static string FormatDuration(double? seconds)
    {
        if (seconds is not { } raw || double.IsNaN(raw)) return "—";
        // Round once, then split, so 59.6 s reads "1 min 0 s" (not "60 s") and 3599.6 s reads "1 h 0 min".
        var s = (long)Math.Round(Math.Max(0, raw), MidpointRounding.AwayFromZero);
        return s < 60 ? $"{s} s" : s < 3600 ? $"{s / 60} min {s % 60} s" : $"{s / 3600} h {s % 3600 / 60} min";
    }

    /// <summary>CSV export (invariant, RFC 4180 quoting). The ids come first, next to the names, so any viewer can re-resolve the names in
    /// another language: Module id (GUID), Module (slug), Test (name at export), Instance id, Instance (label), then the result columns.</summary>
    public static string ToCsv(IEnumerable<HistoryEntry> entries, ModuleCatalog? catalog = null)
    {
        static string Q(string? s) => s is null ? "" : s.Contains('"') || s.Contains(',') || s.Contains('\n') ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;
        var sb = new System.Text.StringBuilder("Module id,Module,Test,Instance id,Instance,TimeUtc,Result,Summary,DurationSeconds,Suite,Measurements,Machine,AppVersion\n");
        foreach (var e in entries)
        {
            var id = e.ModuleId != Guid.Empty ? e.ModuleId : HistoryIds.For(e.Module, catalog);
            var test = catalog?.Get(id)?.DisplayName ?? e.Test;
            sb.Append(id.ToString("D")).Append(',').Append(Q(e.Module)).Append(',').Append(Q(test)).Append(',')
              .Append(Q(e.InstanceId)).Append(',').Append(Q(e.Instance)).Append(',')
              .Append(Q(e.TimeUtc.ToString("O", CultureInfo.InvariantCulture))).Append(',').Append(Q(e.Outcome)).Append(',')
              .Append(Q(e.Summary)).Append(',').Append(e.DurationSeconds?.ToString(CultureInfo.InvariantCulture)).Append(',').Append(Q(e.Suite)).Append(',')
              .Append(Q(string.Join("; ", e.Measurements.Select(m => $"{m.Name}={m.Value}")))).Append(',').Append(Q(e.Machine)).Append(',').Append(Q(e.AppVersion)).Append('\n');
        }
        return sb.ToString();
    }
}

/// <summary>Friendly names for the measurements stored with each result (the raw names are for the log).</summary>
public static class HistoryLabels
{
    private static readonly Dictionary<string, string> Known = new(StringComparer.OrdinalIgnoreCase)
    {
        ["MaxCpuTemperatureC"] = "Peak CPU temperature (°C)", ["MaxGpuTemperatureC"] = "Peak GPU temperature (°C)",
        ["MaxDriveTemperatureC"] = "Peak drive temperature (°C)", ["SequentialReadMBps"] = "Read speed (MB/s)",
        ["SequentialWriteMBps"] = "Write speed (MB/s)", ["RandomReadIops"] = "Random reads per second",
        ["RandomWriteIops"] = "Random writes per second", ["DownloadMbps"] = "Download speed (Mbps)", ["UploadMbps"] = "Upload speed (Mbps)",
        ["Ran"] = "Ran for", ["Requested"] = "Planned length", ["Threads"] = "Processor threads used", ["Errors"] = "Errors found",
        ["ChunksDone"] = "Work units completed", ["TestBytes"] = "Memory tested", ["Passes"] = "Test passes",
    };

    /// <summary>Measurements not worth showing to a person (already shown elsewhere on the row).</summary>
    public static bool IsHidden(string name) => name.Equals("Outcome", StringComparison.OrdinalIgnoreCase);

    /// <summary>Known label, otherwise the raw name split into words ("EarlyThroughput" → "Early throughput").</summary>
    public static string Measurement(string name)
    {
        if (Known.TryGetValue(name, out var k)) return k;
        var words = System.Text.RegularExpressions.Regex.Split(name, "(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
            .Where(w => w.Length > 0).ToList();
        if (words.Count == 0) return name;
        return string.Join(' ', words.Select((w, i) => i == 0 ? char.ToUpperInvariant(w[0]) + w[1..] : w.All(char.IsUpper) && w.Length > 1 ? w : w.ToLowerInvariant()));
    }
}

/// <summary>Relative times for "Updated …" lines.</summary>
public static class TimeText
{
    /// <summary>"just now", "5 min ago", "3 h ago", "yesterday", else the date/time.</summary>
    public static string Ago(DateTimeOffset t, DateTimeOffset now)
    {
        var d = now - t;
        if (d < TimeSpan.FromMinutes(1)) return "just now";
        if (d < TimeSpan.FromHours(1)) return $"{(int)d.TotalMinutes} min ago";
        if (d < TimeSpan.FromHours(24) && t.ToLocalTime().Date == now.ToLocalTime().Date) return $"{(int)d.TotalHours} h ago";
        if (t.ToLocalTime().Date == now.ToLocalTime().Date.AddDays(-1)) return "yesterday " + t.ToLocalTime().ToString("h:mm tt", CultureInfo.InvariantCulture);
        return t.ToLocalTime().ToString("g", CultureInfo.InvariantCulture);
    }
}

