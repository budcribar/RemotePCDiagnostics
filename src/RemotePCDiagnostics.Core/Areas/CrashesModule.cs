namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// App crashes ("Application Error", event 1000) and freezes ("Application Hang", event 1002) from the Windows
/// Application log over the last 30 days, via <see cref="WindowsEventLog"/>.
/// </summary>
public sealed class CrashesModule(SystemCommandRunner commands, bool includeSystemCrashes = false, Func<IReadOnlyList<MinidumpFile>>? minidumpReader = null) : AreaModuleBase(commands.Log)
{
    public const string ModuleName = "Crashes";
    public const int Days = 30, Max = 500, RecentDays = 7, RepeatCrashes = 3;
    public override string Name => ModuleName;
    public override string DisplayName => includeSystemCrashes ? "Crashes & unexpected restarts" : "App crashes";
    protected override string FailedMessage => "Couldn't read app crash reports on this PC.";
    private readonly WindowsEventLog _log = new(commands);

    public static string Query =>
        $"*[System[Provider[@Name='Application Error' or @Name='Application Hang'] and (EventID=1000 or EventID=1002) and TimeCreated[timediff(@SystemTime) <= {(long)Days * 86_400_000}]]]";

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        progress?.Report("Looking for app crashes…");
        var events = await _log.QueryAsync("Application", Query, Max, ct).ConfigureAwait(false);
        Log($"{Name}: source=wevtutil Application log (Application Error 1000 / Application Hang 1002) events={events?.Count.ToString() ?? "failed"}");
        var runtime = events?.Any(e => e.EventId == 1000) == true
            ? await _log.QueryAsync("Application",
                $"*[System[Provider[@Name='.NET Runtime'] and EventID=1026 and TimeCreated[timediff(@SystemTime) <= {(long)Days * 86_400_000 + 2000}]]]",
                Max, ct).ConfigureAwait(false)
            : null;
        var reviewed = EventReviews.Read();
        var runtimeEvents = (runtime ?? []).Where(e => e.EventId == 1026).ToList();
        var appReport = events is null ? AreaReport.Failed(FailedMessage)
            : Build(events.Where(e => !reviewed.Contains(EventReviews.Key(e))).Concat(runtimeEvents).ToList()) with
            {
                ReviewedCards = Build(events.Where(e => reviewed.Contains(EventReviews.Key(e))).Concat(runtimeEvents).ToList()).Cards
            };
        if (!includeSystemCrashes || events is null)
            return appReport;

        var sysEvents = await _log.QueryAsync("System", BsodHistoryModule.Query, BsodHistoryModule.MaxEvents, ct).ConfigureAwait(false);
        if (sysEvents is null)
            return appReport;

        IReadOnlyList<MinidumpFile> dumps = [];
        try { dumps = (minidumpReader ?? BsodHistoryModule.ReadSystemMinidumps)(); } catch { }
        var bsodReport = BsodHistoryModule.BuildReviewed(sysEvents, dumps);
        var combinedCards = bsodReport.Cards.Concat(appReport.Cards).ToList();
        var combinedStatus = (DiagnosticStatus)Math.Max((int)bsodReport.Status, (int)appReport.Status);
        var combinedSummary = $"{bsodReport.Summary} · {appReport.Summary}";
        return new(combinedCards, combinedSummary, combinedStatus, ReviewedCards: (bsodReport.ReviewedCards ?? []).Concat(appReport.ReviewedCards ?? []).ToList());
    }

    public sealed record Incident(DateTimeOffset Time, string App, string Version, bool IsCrash, string Part, string Message)
    {
        public HangOccurrence? Hang { get; init; }
        public string? ReviewKey { get; init; }
        public string Code { get; init; } = "";
        public string? RuntimeError { get; init; }
        public string? Stack { get; init; }
        public string Metadata { get; init; } = "";

        public string? Cause => RuntimeError is { } error ? $"Unhandled error: {error.Split(':')[0].Split('.').Last()}"
            : Code.ToUpperInvariant() switch
            {
                "0XC0000005" => "Access violation",
                "0XE0434352" => "Unhandled .NET error",
                "0XC0000409" => "App shut down after detecting a problem",
                "0XC00000FD" => "Stack overflow",
                "" => null,
                _ => $"Exception {Code}"
            };

        public string Details => !IsCrash ? "Stopped responding"
            : Cause is { } cause ? Part.Length > 0 ? $"{cause} (in {Part})" : cause
            : Part.Length > 0 ? $"Closed unexpectedly (problem in {Part})" : "Closed unexpectedly";

        public string Expanded => string.Join("\n", new[]
        {
            Details, Code.Length > 0 ? $"Exception code: {Code}" : null, Metadata,
            RuntimeError is null ? null : $".NET error: {RuntimeError}", Stack
        }.Where(line => !string.IsNullOrWhiteSpace(line)));
    }

    public static Incident ToIncident(WinEvent e)
    {
        var isCrash = e.EventId == 1000;
        var app = e.DataAt(0, "AppName");
        var part = isCrash ? e.DataAt(3, "ModuleName") : "";
        var version = e.DataAt(1, "AppVersion");
        var code = isCrash ? e.DataAt(6, "ExceptionCode") : "";
        var fields = isCrash
            ? new[] { ("Module version", 4, "ModuleVersion"), ("Fault offset", 7, "FaultingOffset"),
                ("Process ID", 8, "ProcessId"), ("Program path", 10, "AppPath"),
                ("Module path", 11, "ModulePath"), ("Report ID", 12, "IntegratorReportId") }
            : new[] { ("Program path", 5, "ExeFileName"), ("Freeze type", 9, "HangType"), ("Report ID", 6, "ReportId") };
        var metadata = fields.Select(f => (f.Item1, Value: e.DataAt(f.Item2, f.Item3)))
            .Prepend(("Program version", Value: version))
            .Where(f => !string.IsNullOrWhiteSpace(f.Value))
            .Select(f => $"{f.Item1}: {f.Value}");
        return new(e.Time, app.Length > 0 ? app : "Unknown app", version, isCrash, part, e.ShortMessage)
        {
            Hang = isCrash ? null : new(e.Time, app, e.DataAt(5, "ExeFileName"), e.DataAt(7, "PackageFullName"),
                e.DataAt(9, "HangType"), e.DataAt(6, "ReportId")),
            ReviewKey = EventReviews.Key(e),
            Code = code.Length > 0 && !code.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? $"0x{code}" : code,
            Metadata = string.Join("\n", metadata)
        };
    }

    /// <summary>Yellow only for a crash/freeze in the last 7 days; red when one app crashed 3+ times in 7 days.
    /// Older incidents are still listed but shown neutral.</summary>
    public static AreaReport Build(IReadOnlyList<WinEvent> events, DateTimeOffset? now = null)
    {
        var cutoff = (now ?? DateTimeOffset.Now).AddDays(-RecentDays);
        var all = events.Where(e => e.EventId is 1000 or 1002).Select(ToIncident).OrderByDescending(i => i.Time).ToList();
        var runtime = events.Where(e => e.EventId == 1026 && e.Provider.Equals(".NET Runtime", StringComparison.OrdinalIgnoreCase))
            .Select(e =>
            {
                var lines = (e.Data.FirstOrDefault() ?? e.Message).Split('\n', StringSplitOptions.TrimEntries);
                const string appPrefix = "Application: ", errorPrefix = "Exception Info: ";
                var app = lines.FirstOrDefault(line => line.StartsWith(appPrefix, StringComparison.Ordinal))?[appPrefix.Length..];
                var error = lines.FirstOrDefault(line => line.StartsWith(errorPrefix, StringComparison.Ordinal))?[errorPrefix.Length..];
                var stack = string.Join("\n", lines.Where(line => line.StartsWith("at ", StringComparison.Ordinal)).Take(5));
                return (e.Time, App: app, Error: error, Stack: stack);
            }).Where(e => e.App is not null && e.Error is not null).ToList();

        var matches = from index in Enumerable.Range(0, all.Count)
                      where all[index].IsCrash && all[index].Time != default
                      from entry in runtime.Select((value, id) => (value, id))
                      where string.Equals(all[index].App, entry.value.App, StringComparison.OrdinalIgnoreCase)
                      let distance = (all[index].Time - entry.value.Time).Duration()
                      where distance <= TimeSpan.FromSeconds(2)
                      orderby distance
                      select (index, entry);
        var matchedCrashes = new HashSet<int>();
        var matchedRuntime = new HashSet<int>();
        foreach (var (index, entry) in matches.ToList())
        {
            if (matchedCrashes.Contains(index) || !matchedRuntime.Add(entry.id)) continue;
            matchedCrashes.Add(index);
            all[index] = all[index] with { RuntimeError = entry.value.Error, Stack = entry.value.Stack };
        }

        bool Recent(Incident i) => i.Time >= cutoff;
        var recent = all.Where(Recent).ToList();
        var older = all.Count - recent.Count;
        var repeatApp = recent.Where(i => i.IsCrash).GroupBy(i => i.App, StringComparer.OrdinalIgnoreCase).FirstOrDefault(g => g.Count() >= RepeatCrashes);
        var crashes = all.Where(i => i.IsCrash).ToList();
        var hangs = all.Where(i => !i.IsCrash).ToList();
        string[] cols = ["When", "App", "Type", "Version", "Details"];
        AreaRow Row(Incident i) => new(i.IsCrash && Recent(i) ? AreaLevel.Warning : AreaLevel.Neutral,
            [WindowsEventLog.FormatTime(i.Time), i.App, i.IsCrash ? "Crash" : "Freeze", i.Version, i.Details],
            [AreaSort.TimeKey(i.Time), null, null, null, null], Detail: i.Expanded, ReviewKeys: i.ReviewKey is { } key ? [key] : null);

        var byApp = all.GroupBy(i => i.App, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count()).ThenByDescending(g => g.Max(i => i.Time)).ToList();
        var top = byApp.FirstOrDefault();
        var cards = new List<AreaCard>
        {
            new("crashes", "Apps that closed unexpectedly", repeatApp is not null ? AreaLevel.Error : crashes.Any(Recent) ? AreaLevel.Warning : crashes.Count > 0 ? AreaLevel.Neutral : AreaLevel.Ok,
                crashes.Count == 0 ? "None" : AreaModuleBase.Plural(crashes.Count, "crash", "crashes"),
                crashes.FirstOrDefault() is { } c ? $"Latest: {c.App}, {WindowsEventLog.FormatTime(c.Time)}" : $"In the last {Days} days",
                cols, crashes.Select(Row).ToList()),
            new("hangs", "Apps that stopped responding", hangs.Any(Recent) ? AreaLevel.Warning : hangs.Count > 0 ? AreaLevel.Neutral : AreaLevel.Ok,
                hangs.Count == 0 ? "None" : AreaModuleBase.Plural(hangs.Count, "time"),
                hangs.FirstOrDefault() is { } h ? $"Latest: {h.App}, {WindowsEventLog.FormatTime(h.Time)}" : $"In the last {Days} days",
                [.. cols, "Count"], hangs.GroupBy(i => (i.Hang!.Path.Length > 0 ? i.Hang.Path : i.App) + "\n" + i.Hang.Package,
                    StringComparer.OrdinalIgnoreCase).Select(g =>
                {
                    var latest = g.First();
                    var row = Row(latest);
                    var occurrences = g.Select(i => i.Hang!).ToList();
                    var package = latest.Hang!.Package;
                    var detail = string.Join("\n\n", g.Select(i => $"{WindowsEventLog.FormatTime(i.Time)}\n{i.Expanded}"));
                    return row with
                    {
                        Values = [row.Values[0], package.Length == 0 ? latest.App : $"{latest.App} · {package.Split('_')[0]}",
                            row.Values[2], row.Values[3], row.Values[4], g.Count().ToString()],
                        Detail = package.Length == 0 ? detail : $"Recorded package: {package}\n\n{detail}",
                        ReviewKeys = g.Select(i => i.ReviewKey).OfType<string>().ToList(),
                        HangOccurrences = occurrences
                    };
                }).OrderByDescending(row => row.HangOccurrences!.Count).ToList()),
            new("apps", "Most affected apps", top is null ? AreaLevel.Ok : AreaLevel.Neutral,
                top is null ? "No problems recorded" : top.Key, top is null ? $"In the last {Days} days" : $"{AreaModuleBase.Plural(top.Count(), "problem")} in the last {Days} days",
                ["App", "Crashes", "Freezes", "Last time"],
                byApp.Select(g => new AreaRow(AreaLevel.Neutral, [g.Key, g.Count(i => i.IsCrash).ToString(), g.Count(i => !i.IsCrash).ToString(), WindowsEventLog.FormatTime(g.Max(i => i.Time))],
                    [null, null, null, AreaSort.TimeKey(g.Max(i => i.Time))], Detail: AppDetails(g), ReviewKeys: g.Select(i => i.ReviewKey).OfType<string>().ToList())).ToList(), PreserveRowOrder: true),
        };
        var summary = all.Count == 0 ? $"No app crashes in the last {Days} days"
            : recent.Count == 0 ? $"No crashes in the last {RecentDays} days ({older} older)"
            : repeatApp is not null ? $"{repeatApp.Key} crashed {repeatApp.Count()} times in the last {RecentDays} days"
            : $"{AreaModuleBase.Plural(crashes.Count, "crash", "crashes")}, {AreaModuleBase.Plural(hangs.Count, "freeze")} in the last {Days} days · most: {top!.Key}";
        var status = repeatApp is not null ? DiagnosticStatus.Error : recent.Count > 0 ? DiagnosticStatus.Warning : DiagnosticStatus.Ok;
        return new(cards, summary, status);
    }
    public async Task<string> FindHangEvidenceAsync(IReadOnlyList<HangOccurrence> occurrences, CancellationToken ct)
    {
        var lines = new List<string>();
        foreach (var hang in occurrences.Take(5))
        {
            var start = hang.Time.AddMinutes(-2).UtcDateTime.ToString("O");
            var end = hang.Time.AddMinutes(2).UtcDateTime.ToString("O");
            var time = $"TimeCreated[@SystemTime >= '{start}' and @SystemTime <= '{end}']";
            var app = await _log.QueryAsync("Application",
                $"*[System[{time} and (EventID=1000 or EventID=1001 or EventID=1002)]]", 40, ct);
            var system = await _log.QueryAsync("System",
                $"*[System[{time} and (Level=1 or Level=2)]]", 30, ct);
            lines.Add($"{WindowsEventLog.FormatTime(hang.Time)} · {hang.App}");
            if (app is null || system is null) lines.Add("Some event logs could not be read.");
            var related = (app ?? []).Concat(system ?? []).Where(e => e.EventId != 1002 || e.Time != hang.Time)
                .Select(e => (Event: e, Exact: Guid.TryParse(hang.ReportId, out var id) && e.EventId == 1001 &&
                    (e.Data.Any(value => Guid.TryParse(value, out var other) && other == id) ||
                     e.Message.Contains(id.ToString(), StringComparison.OrdinalIgnoreCase))))
                .OrderByDescending(item => item.Exact).ThenBy(item => (item.Event.Time - hang.Time).Duration()).Take(8).ToList();
            if (related.Count == 0) lines.Add("No related entries found in the two-minute window.");
            foreach (var (e, exact) in related)
                lines.Add($"{(exact ? "Matching report ID" : "Nearby event")} · {WindowsEventLog.FormatTime(e.Time)} · {e.Source} {e.EventId}\n{(exact ? e.Message : e.ShortMessage)}");
            lines.Add("");
        }
        if (occurrences.Count > 5) lines.Add("Showing evidence for the five latest freezes in this group.");
        return string.Join("\n", lines);
    }

    private static string AppDetails(IEnumerable<Incident> incidents)
    {
        var crashes = incidents.Where(i => i.IsCrash).ToList();
        var cause = crashes.GroupBy(i => i.Cause ?? "Cause unavailable", StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count()).FirstOrDefault();
        var error = crashes.FirstOrDefault(i => i.RuntimeError is not null)?.RuntimeError;
        var versions = string.Join(", ", incidents.Select(i => i.Version).Where(v => v.Length > 0).Distinct());
        return string.Join("\n", new[]
        {
            cause is null ? "No crashes recorded" : $"Most common cause: {cause.Key} ({cause.Count()} of {crashes.Count} crashes)",
            error is null ? null : $"Latest .NET error: {error}",
            $"App versions: {(versions.Length > 0 ? versions : "Unavailable")}"
        }.Where(line => line is not null));
    }
}

public sealed record HangOccurrence(DateTimeOffset Time, string App, string Path, string Package, string Type, string ReportId);
