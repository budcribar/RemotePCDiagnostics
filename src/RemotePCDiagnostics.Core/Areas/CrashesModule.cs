namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// App crashes ("Application Error", event 1000) and freezes ("Application Hang", event 1002) from the Windows
/// Application log over the last 30 days, via <see cref="WindowsEventLog"/>.
/// </summary>
public sealed class CrashesModule(SystemCommandRunner commands) : AreaModuleBase(commands.Log)
{
    public const string ModuleName = "Crashes";
    public const int Days = 30, Max = 500, RecentDays = 7, RepeatCrashes = 3;
    public override string Name => ModuleName;
    public override string DisplayName => "App crashes";
    protected override string FailedMessage => "Couldn't read app crash reports on this PC.";
    private readonly WindowsEventLog _log = new(commands);

    public static string Query =>
        $"*[System[Provider[@Name='Application Error' or @Name='Application Hang'] and (EventID=1000 or EventID=1002) and TimeCreated[timediff(@SystemTime) <= {(long)Days * 86_400_000}]]]";

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        progress?.Report("Looking for app crashes…");
        var events = await _log.QueryAsync("Application", Query, Max, ct).ConfigureAwait(false);
        Log($"{Name}: source=wevtutil Application log (Application Error 1000 / Application Hang 1002) events={events?.Count.ToString() ?? "failed"}");
        return events is null ? AreaReport.Failed(FailedMessage) : Build(events);
    }

    public sealed record Incident(DateTimeOffset Time, string App, string Version, bool IsCrash, string Part, string Message);

    public static Incident ToIncident(WinEvent e)
    {
        var isCrash = e.EventId == 1000;
        var app = e.DataAt(0, "AppName");
        var part = isCrash ? e.DataAt(3, "ModuleName") : "";
        return new(e.Time, app.Length > 0 ? app : "Unknown app", e.DataAt(1, "AppVersion"), isCrash, part, e.ShortMessage);
    }

    /// <summary>Yellow only for a crash/freeze in the last 7 days; red when one app crashed 3+ times in 7 days.
    /// Older incidents are still listed but shown neutral.</summary>
    public static AreaReport Build(IReadOnlyList<WinEvent> events, DateTimeOffset? now = null)
    {
        var cutoff = (now ?? DateTimeOffset.Now).AddDays(-RecentDays);
        var all = events.Where(e => e.EventId is 1000 or 1002).Select(ToIncident).OrderByDescending(i => i.Time).ToList();
        bool Recent(Incident i) => i.Time >= cutoff;
        var recent = all.Where(Recent).ToList();
        var older = all.Count - recent.Count;
        var repeatApp = recent.Where(i => i.IsCrash).GroupBy(i => i.App, StringComparer.OrdinalIgnoreCase).FirstOrDefault(g => g.Count() >= RepeatCrashes);
        var crashes = all.Where(i => i.IsCrash).ToList();
        var hangs = all.Where(i => !i.IsCrash).ToList();
        string[] cols = ["When", "App", "Type", "Version", "Details"];
        AreaRow Row(Incident i) => new(i.IsCrash && Recent(i) ? AreaLevel.Warning : AreaLevel.Neutral,
            [WindowsEventLog.FormatTime(i.Time), i.App, i.IsCrash ? "Crash" : "Freeze", i.Version, i.IsCrash ? (i.Part.Length > 0 ? $"Closed unexpectedly (problem in {i.Part})" : "Closed unexpectedly") : "Stopped responding"],
            [AreaSort.TimeKey(i.Time), null, null, null, null]);

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
                cols, hangs.Select(Row).ToList()),
            new("apps", "Most affected apps", top is null ? AreaLevel.Ok : AreaLevel.Neutral,
                top is null ? "No problems recorded" : top.Key, top is null ? $"In the last {Days} days" : $"{AreaModuleBase.Plural(top.Count(), "problem")} in the last {Days} days",
                ["App", "Crashes", "Stopped responding", "Last time"],
                byApp.Select(g => new AreaRow(AreaLevel.Neutral, [g.Key, g.Count(i => i.IsCrash).ToString(), g.Count(i => !i.IsCrash).ToString(), WindowsEventLog.FormatTime(g.Max(i => i.Time))],
                    [null, null, null, AreaSort.TimeKey(g.Max(i => i.Time))])).ToList()),
        };
        var summary = all.Count == 0 ? $"No app crashes in the last {Days} days"
            : recent.Count == 0 ? $"No crashes in the last {RecentDays} days ({older} older)"
            : repeatApp is not null ? $"{repeatApp.Key} crashed {repeatApp.Count()} times in the last {RecentDays} days"
            : $"{AreaModuleBase.Plural(crashes.Count, "crash", "crashes")}, {AreaModuleBase.Plural(hangs.Count, "freeze")} in the last {Days} days · most: {top!.Key}";
        var status = repeatApp is not null ? DiagnosticStatus.Error : recent.Count > 0 ? DiagnosticStatus.Warning : DiagnosticStatus.Ok;
        return new(cards, summary, status);
    }
}
