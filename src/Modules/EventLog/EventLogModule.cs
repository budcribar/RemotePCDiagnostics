namespace RemotePCDiagnostics.Core.Areas;

/// <summary>Critical events and errors from the Windows System and Application logs over the last week (via <see cref="WindowsEventLog"/>).
/// In user mode (the module host) <paramref name="host"/> is set: the event logs and the reviewed list are read by the app
/// (<c>eventlog.query</c>, <c>events.reviewed</c>).</summary>
public sealed class EventLogModule(SystemCommandRunner commands, bool excludeCrashEvents = false, Plugins.IHostQueries? host = null) : AreaModuleBase(commands.Log)
{
    public const string ModuleName = ModuleSlugs.EventLog;
    public const int Days = 7, MaxPerLog = 300, RepeatErrors = 5;
    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.EventLog;
    public override string DisplayName => "Windows error log";
    protected override string FailedMessage => "Couldn't read the Windows error log on this PC.";
    private readonly WindowsEventLog _log = new(commands, host, ModuleName);

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        progress.ReportStep(1, 2, "Reading the Windows System error log…");
        var q = WindowsEventLog.LevelQuery(Days, 1, 2);
        var system = await _log.QueryAsync("System", q, MaxPerLog, ct).ConfigureAwait(false);
        progress.ReportStep(2, 2, "Reading the Windows Application error log…");
        var app = await _log.QueryAsync("Application", q, MaxPerLog, ct).ConfigureAwait(false);
        Log($"{Name}: source=wevtutil (windows_events needs the osquery event subscriber) system={system?.Count.ToString() ?? "failed"} application={app?.Count.ToString() ?? "failed"}");
        if (excludeCrashEvents)
        {
            system = system?.Where(e => !BsodHistoryModule.IsBugCheckEvent(e) && !BsodHistoryModule.IsPowerLossEvent(e)).ToList();
            app = app?.Where(e => !(e.EventId is 1000 or 1002 && (e.Provider.Contains("Application Error", StringComparison.OrdinalIgnoreCase) || e.Provider.Contains("Application Hang", StringComparison.OrdinalIgnoreCase)))).ToList();
        }
        var reviewed = await EventReviews.ReadAsync(host, ct).ConfigureAwait(false);

        var report = Build(system?.Where(e => !reviewed.Contains(EventReviews.Key(e))).ToList(),
            app?.Where(e => !reviewed.Contains(EventReviews.Key(e))).ToList());
        return report with { ReviewedCards = Build(system?.Where(e => reviewed.Contains(EventReviews.Key(e))).ToList(),
            app?.Where(e => reviewed.Contains(EventReviews.Key(e))).ToList()).Cards };
    }

    private static readonly string[] Cols = ["When", "Source", "Level", "What happened"];
    private static readonly string[] GroupedCols = ["When", "Source", "Level", "Times", "What happened"];
    public const int MaxDetailChars = 2000, MaxListedTimes = 20;
    private static AreaRow Row(WinEvent e) => new(e.Level == 1 ? AreaLevel.Error : AreaLevel.Warning, [WindowsEventLog.FormatTime(e.Time), e.Source, e.Level == 1 ? "Critical" : "Error", e.ShortMessage],
        [AreaSort.TimeKey(e.Time), null, e.Level == 1 ? "2" : "1", null], Detail: FullMessage(e), GetHelpUri: GetHelpFor(e), EventCopyText: CopyText(e), ReviewKeys: [EventReviews.Key(e)]);

    private static string CopyText(WinEvent e) =>
        $"Source: {e.Provider}\nEvent ID: {e.EventId}\nLog: {e.Channel}\nTime: {e.Time:O}\n\n{e.Message}";

    private static string? GetHelpFor(WinEvent e) =>
        e.Source.Equals("WindowsUpdateClient", StringComparison.OrdinalIgnoreCase) ||
        (e.Source.Equals("DistributedCOM", StringComparison.OrdinalIgnoreCase) && e.EventId == 10005 &&
         e.Message.Contains(" wuauserv ", StringComparison.OrdinalIgnoreCase))
            ? "ms-contact-support://smc-to-emerald/WUTroubleshooter"
            : null;

    /// <summary>Full message for the expanded row, or null when the table cell already shows all of it.</summary>
    public static string? FullMessage(WinEvent e)
    {
        var m = e.Message.Trim();
        if (m.Length == 0 || m == e.ShortMessage) return null;
        return m.Length > MaxDetailChars ? m[..MaxDetailChars] + "…" : m;
    }

    /// <summary>
    /// Identical events (same source, level and message) collapse into one row with a count; expanding it shows when each
    /// happened (newest first) and the full message. Rows stay newest first.
    /// </summary>
    public static IReadOnlyList<AreaRow> GroupedRows(IEnumerable<WinEvent> events) =>
        events.GroupBy(e => (Source: e.Source.ToUpperInvariant(), e.Level, e.ShortMessage))
            .Select(g =>
            {
                var list = g.OrderByDescending(e => e.Time).ToList();
                var e = list[0];
                var times = list.Count > 1
                    ? "Happened " + list.Count + " times: " + string.Join(", ", list.Take(MaxListedTimes).Select(x => WindowsEventLog.FormatTime(x.Time))) + (list.Count > MaxListedTimes ? ", …" : "")
                    : null;
                var detail = string.Join("\n\n", new[] { times, FullMessage(e) }.Where(x => x is not null));
                return new AreaRow(e.Level == 1 ? AreaLevel.Error : AreaLevel.Warning,
                    [WindowsEventLog.FormatTime(e.Time), e.Source, e.Level == 1 ? "Critical" : "Error", list.Count.ToString(System.Globalization.CultureInfo.InvariantCulture), e.ShortMessage],
                    [AreaSort.TimeKey(e.Time), null, e.Level == 1 ? "2" : "1", list.Count.ToString(System.Globalization.CultureInfo.InvariantCulture), null],
                    Detail: detail.Length > 0 ? detail : null, GetHelpUri: GetHelpFor(e), EventCopyText: CopyText(e), ReviewKeys: list.Select(EventReviews.Key).ToList());
            })
            .OrderByDescending(r => r.SortKeys![0], StringComparer.Ordinal).ToList();

    public const int MaxSourceMessages = 5;

    /// <summary>The distinct messages a source logged (most frequent first, with counts), for the "Most frequent" drill-down.</summary>
    public static string SourceDetail(IEnumerable<WinEvent> events) =>
        string.Join("\n", events.GroupBy(e => e.ShortMessage).OrderByDescending(m => m.Count()).ThenByDescending(m => m.Max(e => e.Time))
            .Take(MaxSourceMessages)
            .Select(m => $"{m.Count()}× (last {WindowsEventLog.FormatTime(m.Max(e => e.Time))}): {m.Key}"));

    public static AreaReport Build(IReadOnlyList<WinEvent>? system, IReadOnlyList<WinEvent>? app)
    {
        if (system is null && app is null) return AreaReport.Failed("Couldn't read the Windows error log on this PC.");
        var all = (system ?? []).Concat(app ?? []).OrderByDescending(e => e.Time).ToList();
        var critical = all.Where(e => e.Level == 1).ToList();
        // Yellow only for critical problems or 5+ errors from the same source; routine/isolated errors stay green but listed.
        static (string Source, string Channel) Key(WinEvent e) => (e.Source.ToUpperInvariant(), e.Channel.ToUpperInvariant());
        var repeated = all.Where(e => e.Level == 2).GroupBy(Key).Where(g => g.Count() >= RepeatErrors).Select(g => g.Key).ToHashSet();
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
            : new(id, title, events.Any(e => e.Level == 2 && repeated.Contains(Key(e))) ? AreaLevel.Warning : AreaLevel.Ok,
                events.Count == 0 ? "No errors" : AreaModuleBase.Plural(events.Count, "error") + (events.Count >= MaxPerLog ? " or more" : ""),
                $"In the last {Days} days", GroupedCols, GroupedRows(events),
                Note: "Most PCs log some errors; they only matter if they repeat or match a problem you're seeing. Identical errors are grouped; click a row for the full message.");
        cards.Add(LogCard("system", "Windows errors", system, "Windows' own error list"));
        cards.Add(LogCard("apps", "App errors", app, "the app error list"));

        var groups = all.GroupBy(Key).OrderByDescending(g => g.Count()).ThenByDescending(g => g.Max(e => e.Time)).ToList();
        var top = groups.FirstOrDefault();
        cards.Add(new("sources", "Most frequent", top is null ? AreaLevel.Ok : AreaLevel.Neutral,
            top is null ? "Nothing repeated" : top.First().Source, top is null ? "" : $"{AreaModuleBase.Plural(top.Count(), "time")} in the last {Days} days",
            ["Source", "Where", "Times", "Last seen"],
            groups.Select(g => new AreaRow(g.Any(e => e.Level == 1) ? AreaLevel.Error : AreaLevel.Warning,
                [g.First().Source, string.Equals(g.First().Channel, "System", StringComparison.OrdinalIgnoreCase) ? "Windows" : "Apps", g.Count().ToString(), WindowsEventLog.FormatTime(g.Max(e => e.Time))],
                [null, null, null, AreaSort.TimeKey(g.Max(e => e.Time))],
                Detail: SourceDetail(g), ReviewKeys: g.Select(EventReviews.Key).ToList())).ToList(),
            Note: "Click a source to see what it reported."));

        var summary = all.Count == 0 && critical.Count == 0
            ? $"No errors in the last {Days} days"
            : $"Last {Days} days: " + string.Join(", ", new[]
            {
                critical.Count > 0 ? AreaModuleBase.Plural(critical.Count, "critical problem") : null,
                system is not null ? $"{system.Count(e => e.Level == 2)} Windows errors" : null,
                app is not null ? $"{app.Count(e => e.Level == 2)} app errors" : null,
            }.Where(x => x is not null));
        var status = critical.Count > 0 || repeated.Count > 0 || system is null || app is null ? DiagnosticStatus.Warning : DiagnosticStatus.Ok;
        return new(cards, summary, status);
    }
}
