namespace RemotePCDiagnostics.Core.Areas;

/// <summary>Critical events and errors from the Windows System and Application logs over the last week (via <see cref="WindowsEventLog"/>).</summary>
public sealed class EventLogModule(SystemCommandRunner commands) : AreaModuleBase(commands.Log)
{
    public const string ModuleName = "EventLog";
    public const int Days = 7, MaxPerLog = 300;
    public override string Name => ModuleName;
    public override string DisplayName => "Windows error log";
    protected override string FailedMessage => "Couldn't read the Windows error log on this PC.";
    private readonly WindowsEventLog _log = new(commands);

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        progress?.Report("Reading the Windows error log…");
        var q = WindowsEventLog.LevelQuery(Days, 1, 2);
        var system = await _log.QueryAsync("System", q, MaxPerLog, ct).ConfigureAwait(false);
        var app = await _log.QueryAsync("Application", q, MaxPerLog, ct).ConfigureAwait(false);
        Log($"{Name}: source=wevtutil (windows_events needs the osquery event subscriber) system={system?.Count.ToString() ?? "failed"} application={app?.Count.ToString() ?? "failed"}");
        return Build(system, app);
    }

    private static readonly string[] Cols = ["When", "Source", "What happened"];
    private static AreaRow Row(WinEvent e) => new(e.Level == 1 ? AreaLevel.Error : AreaLevel.Warning, [WindowsEventLog.FormatTime(e.Time), e.Source, e.ShortMessage]);

    public static AreaReport Build(IReadOnlyList<WinEvent>? system, IReadOnlyList<WinEvent>? app)
    {
        if (system is null && app is null) return AreaReport.Failed("Couldn't read the Windows error log on this PC.");
        var all = (system ?? []).Concat(app ?? []).OrderByDescending(e => e.Time).ToList();
        var critical = all.Where(e => e.Level == 1).ToList();
        var cards = new List<AreaCard>
        {
            new("critical", "Critical problems", critical.Count > 0 ? AreaLevel.Error : AreaLevel.Ok,
                critical.Count == 0 ? "None" : AreaModuleBase.Plural(critical.Count, "critical problem"),
                critical.FirstOrDefault() is { } c ? $"Latest: {c.Source}, {WindowsEventLog.FormatTime(c.Time)}" : $"In the last {Days} days",
                Cols, critical.Select(Row).ToList(),
                Note: "Critical problems often mean Windows shut down or restarted unexpectedly (for example a power loss or a crash)."),
        };
        AreaCard LogCard(string id, string title, IReadOnlyList<WinEvent>? events, string what) => events is null
            ? AreaCard.Failed(id, title, $"Couldn't read {what}.")
            : new(id, title, events.Count > 0 ? AreaLevel.Warning : AreaLevel.Ok,
                events.Count == 0 ? "No errors" : AreaModuleBase.Plural(events.Count, "error") + (events.Count >= MaxPerLog ? " or more" : ""),
                $"In the last {Days} days", Cols, events.Select(Row).ToList(),
                Note: "Most PCs log some errors; they only matter if they repeat or match a problem you're seeing.");
        cards.Add(LogCard("system", "Windows errors", system, "Windows' own error list"));
        cards.Add(LogCard("apps", "App errors", app, "the app error list"));

        var groups = all.GroupBy(e => (e.Source, e.Channel)).OrderByDescending(g => g.Count()).ThenByDescending(g => g.Max(e => e.Time)).ToList();
        var top = groups.FirstOrDefault();
        cards.Add(new("sources", "Most frequent", top is null ? AreaLevel.Ok : AreaLevel.Neutral,
            top is null ? "Nothing repeated" : top.Key.Source, top is null ? "" : $"{AreaModuleBase.Plural(top.Count(), "time")} in the last {Days} days",
            ["Source", "Where", "Times", "Last seen"],
            groups.Select(g => new AreaRow(g.Any(e => e.Level == 1) ? AreaLevel.Error : AreaLevel.Warning,
                [g.Key.Source, g.Key.Channel == "System" ? "Windows" : "Apps", g.Count().ToString(), WindowsEventLog.FormatTime(g.Max(e => e.Time))])).ToList()));

        var summary = all.Count == 0 && critical.Count == 0
            ? $"No errors in the last {Days} days"
            : $"Last {Days} days: " + string.Join(", ", new[]
            {
                critical.Count > 0 ? AreaModuleBase.Plural(critical.Count, "critical problem") : null,
                system is not null ? $"{system.Count(e => e.Level == 2)} Windows errors" : null,
                app is not null ? $"{app.Count(e => e.Level == 2)} app errors" : null,
            }.Where(x => x is not null));
        var status = critical.Count > 0 || system is null || app is null ? DiagnosticStatus.Warning : DiagnosticStatus.Ok;
        return new(cards, summary, status);
    }
}
