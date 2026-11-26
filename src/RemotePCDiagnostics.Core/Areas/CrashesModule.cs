namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// App crashes ("Application Error", event 1000) and freezes ("Application Hang", event 1002) from the Windows
/// Application log over the last 30 days, via <see cref="WindowsEventLog"/>. With system crashes included it also shows blue screens and
/// unexpected restarts, the blue screen dumps, and graphics driver crashes and resets (<see cref="GraphicsDriverCrashes"/>): the dump files
/// come from <paramref name="dumps"/> and the graphics drivers from <paramref name="drivers"/> (both WMI through the Agent in the app).
/// In user mode (the module host) <paramref name="host"/> is set: the event logs and the reviewed list are read by the app
/// (<c>eventlog.query</c>, <c>events.reviewed</c>), and WMI goes through the app to the Agent (<c>wmi.query</c>).
/// </summary>
/// <param name="clock">The report's "now" and time zone (<see cref="ReportClock"/>); the PC's when null.</param>
public sealed class CrashesModule(SystemCommandRunner commands, bool includeSystemCrashes = false, ICrashDumpSource? dumps = null,
    IDeviceDriverSource? drivers = null, Plugins.IHostQueries? host = null, TimeProvider? clock = null)
    : AreaModuleBase(commands.Log), IHangEvidenceSource
{
    public const string HangsCardId = "hangs";
    string IHangEvidenceSource.HangCardId => HangsCardId;
    public const string ModuleName = ModuleSlugs.Crashes;
    public const int Days = 30, Max = 500, RecentDays = 7, RepeatCrashes = 3;
    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.Crashes;
    public override string DisplayName => includeSystemCrashes ? "Crashes & unexpected restarts" : "App crashes";
    protected override string FailedMessage => "Couldn't read app crash reports on this PC.";
    private readonly WindowsEventLog _log = new(commands, host, ModuleName);

    private async Task<IReadOnlyList<MinidumpFile>> DumpsAsync(CancellationToken ct)
    {
        if (dumps is null) return [];
        try { return await dumps.ReadMinidumpsAsync(ct).ConfigureAwait(false); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogWarn($"{Name}: crash dumps unreadable: {ex.Message}");
            return [];
        }
    }

    public static string Query =>
        $"*[System[Provider[@Name='Application Error' or @Name='Application Hang'] and (EventID=1000 or EventID=1002) and TimeCreated[timediff(@SystemTime) <= {(long)Days * 86_400_000}]]]";

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        using var _ = ReportClock.Use(clock);
        var total = includeSystemCrashes ? 4 : 2;
        progress.ReportStep(1, total, "Looking for app crashes and hangs…");
        var eventsTask = _log.QueryAsync("Application", Query, Max, ct);
        var werTask = includeSystemCrashes
            ? _log.QueryAsync("Application", GraphicsDriverCrashes.ReportQuery, GraphicsDriverCrashes.MaxEvents, ct)
            : Task.FromResult<IReadOnlyList<WinEvent>?>(null);
        await Task.WhenAll(eventsTask, werTask).ConfigureAwait(false);
        var events = await eventsTask;
        var werReports = await werTask;
        Log($"{Name}: source=wevtutil Application log (Application Error 1000 / Application Hang 1002) events={events?.Count.ToString() ?? "failed"} wer={werReports?.Count.ToString() ?? "n/a"}");
        progress.ReportStep(2, total, "Checking .NET runtime crash details…");
        var runtime = events?.Any(e => e.EventId == 1000) == true
            ? await _log.QueryAsync("Application",
                $"*[System[Provider[@Name='.NET Runtime'] and EventID=1026 and TimeCreated[timediff(@SystemTime) <= {(long)Days * 86_400_000 + 2000}]]]",
                Max, ct).ConfigureAwait(false)
            : null;
        var reviewed = await EventReviews.ReadAsync(host, ct).ConfigureAwait(false);
        var runtimeEvents = (runtime ?? []).Where(e => e.EventId == 1026).ToList();
        var werAppEvents = (werReports ?? []).Where(IsWerAppEvent).ToList();
        var appEvents = events is null ? null : events.Concat(werAppEvents).ToList();
        var appReport = appEvents is null ? AreaReport.Failed(FailedMessage)
            : Build(appEvents.Where(e => !reviewed.Contains(EventReviews.Key(e))).Concat(runtimeEvents).ToList()) with
            {
                ReviewedCards = Build(appEvents.Where(e => reviewed.Contains(EventReviews.Key(e))).Concat(runtimeEvents).ToList()).Cards
            };
        if (!includeSystemCrashes)
            return appReport;

        progress.ReportStep(3, total, "Checking for blue screens and unexpected restarts…");
        var sysEvents = await _log.QueryAsync("System", BsodHistoryModule.Query, BsodHistoryModule.MaxEvents, ct).ConfigureAwait(false);
        var dumpFiles = await DumpsAsync(ct).ConfigureAwait(false);

        if (events is null && sysEvents is null && dumpFiles.Count == 0)
            return AreaReport.Failed(FailedMessage);

        AreaReport bsodReport;
        if (sysEvents is null)
        {
            const string sysFailed = "Couldn't read blue screen and shutdown history on this PC.";
            var dumpCard = BsodHistoryModule.Build([], dumpFiles).Cards.Single(c => c.Id == "minidumps");
            bsodReport = new(
                [
                    AreaCard.Failed("bsods", "Blue screen crashes (BSOD)", sysFailed),
                    AreaCard.Failed("power", "Unexpected power losses & resets", sysFailed),
                    AreaCard.Failed("whea", "Hardware error events (WHEA)", sysFailed),
                    dumpCard
                ],
                "Couldn't read blue screen and shutdown history",
                DiagnosticStatus.Warning);
        }
        else
        {
            bsodReport = BsodHistoryModule.Build(sysEvents.Where(e => !reviewed.Contains(EventReviews.Key(e))).ToList(), dumpFiles) with
            {
                ReviewedCards = BsodHistoryModule.Build(sysEvents.Where(e => reviewed.Contains(EventReviews.Key(e))).ToList(), dumpFiles).Cards
            };
        }

        var appSection = events is null
            ? new AreaReport(
                [AreaCard.Failed("crashes", "Apps that closed unexpectedly", FailedMessage), AreaCard.Failed(HangsCardId, "Apps that stopped responding", FailedMessage)],
                "Couldn't read app crash reports",
                DiagnosticStatus.Warning)
            : appReport;

        progress.ReportStep(4, total, "Checking for graphics driver crashes and resets…");
        var (graphics, reviewedGraphics) = await GraphicsAsync(sysEvents, werReports, reviewed, ct).ConfigureAwait(false);

        var combinedCards = bsodReport.Cards.Append(graphics).Concat(appSection.Cards).ToList();
        var graphicsStatus = graphics.ErrorText is not null ? DiagnosticStatus.Warning : AreaReport.Worst([graphics.Level]);
        var combinedStatus = (DiagnosticStatus)Math.Max(Math.Max((int)bsodReport.Status, (int)appSection.Status), (int)graphicsStatus);
        var combinedSummary = graphics.EventCount > 0
            ? $"{bsodReport.Summary} · {graphics.Headline} · {appSection.Summary}"
            : $"{bsodReport.Summary} · {appSection.Summary}";
        return new(combinedCards, combinedSummary, combinedStatus,
            ReviewedCards: (bsodReport.ReviewedCards ?? []).Append(reviewedGraphics).Concat(appSection.ReviewedCards ?? []).ToList());
    }

    /// <summary>The graphics driver crashes &amp; resets card, and the same card for the events marked reviewed.</summary>
    private async Task<(AreaCard Card, AreaCard Reviewed)> GraphicsAsync(IReadOnlyList<WinEvent>? bsodEvents,
        IReadOnlyList<WinEvent>? reports, IReadOnlyCollection<string> reviewed, CancellationToken ct)
    {
        var resetsTask = _log.QueryAsync("System", GraphicsDriverCrashes.SystemQuery, GraphicsDriverCrashes.MaxEvents, ct);
        var installsTask = _log.QueryAsync("System", GraphicsDriverCrashes.InstallQuery, GraphicsDriverCrashes.MaxEvents, ct);
        var dumpsTask = LiveKernelReportsAsync(ct);
        var driversTask = GpuDriversAsync(ct);
        await Task.WhenAll(resetsTask, installsTask, dumpsTask, driversTask).ConfigureAwait(false);
        var resets = await resetsTask;
        var installs = (await installsTask ?? []).Select(GraphicsDriverCrashes.ToInstall).OfType<GpuDriverInstall>().ToList();
        var liveDumps = await dumpsTask;
        var gpuDrivers = await driversTask;
        Log($"{Name}: graphics resets={resets?.Count.ToString() ?? "failed"} reports={reports?.Count.ToString() ?? "failed"} installs={installs.Count} " +
            $"liveDumps={liveDumps.Count} drivers={gpuDrivers?.Count.ToString() ?? "failed"}");
        if (resets is null)
        {
            var failed = AreaCard.Failed(GraphicsDriverCrashes.CardId, GraphicsDriverCrashes.Title, "Couldn't read graphics driver events on this PC.");
            return (failed, GraphicsDriverCrashes.Build([], [], installs, gpuDrivers));
        }
        var events = resets.Where(GraphicsDriverCrashes.IsResetEvent)
            .Concat((reports ?? []).Where(e => GraphicsDriverCrashes.LiveKernelCode(e) is not null))
            .Concat((bsodEvents ?? []).Where(e => GraphicsDriverCrashes.GraphicsBugCheck(e) is not null))
            .ToList();
        return (GraphicsDriverCrashes.Build(events.Where(e => !reviewed.Contains(EventReviews.Key(e))).ToList(), liveDumps, installs, gpuDrivers),
            GraphicsDriverCrashes.Build(events.Where(e => reviewed.Contains(EventReviews.Key(e))).ToList(), [], installs, gpuDrivers));
    }

    private async Task<IReadOnlyList<MinidumpFile>> LiveKernelReportsAsync(CancellationToken ct)
    {
        if (dumps is null) return [];
        try
        {
            var cutoff = ReportClock.Now.AddDays(-GraphicsDriverCrashes.Days);
            return (await dumps.ReadLiveKernelReportsAsync(ct).ConfigureAwait(false)).Where(d => d.Created >= cutoff)
                .OrderByDescending(d => d.Created).Take(WmiCrashDumpSource.MaxFiles).ToList();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogWarn($"{Name}: live kernel reports unreadable: {ex.Message}");
            return [];
        }
    }

    private async Task<IReadOnlyList<GpuDriver>?> GpuDriversAsync(CancellationToken ct)
    {
        if (drivers is null) return null;
        try
        {
            return (await drivers.ReadDriversAsync(ct).ConfigureAwait(false))?.Where(GraphicsDriverCrashes.IsDisplayDriver).Select(GpuDriver.From).ToList();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogWarn($"{Name}: graphics drivers unreadable: {ex.Message}");
            return null;
        }
    }

    public sealed record Incident(DateTimeOffset Time, string App, string Version, bool IsCrash, string Part, string Message)
    {
        public HangOccurrence? Hang { get; init; }
        public HangOccurrence? Evidence { get; init; }
        public string? ReviewKey { get; init; }
        public string ReportId { get; init; } = "";
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

        public string Details => !IsCrash
            ? (string.Equals(Hang?.Type, "Quiesce", StringComparison.OrdinalIgnoreCase)
                ? "Stopped responding (background suspend)"
                : "Stopped responding")
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
        var reportId = isCrash ? e.DataAt(12, "IntegratorReportId") : e.DataAt(6, "ReportId");
        var fields = isCrash
            ? new[] { ("Module version", 4, "ModuleVersion"), ("Fault offset", 7, "FaultingOffset"),
                ("Process ID", 8, "ProcessId"), ("Program path", 10, "AppPath"),
                ("Module path", 11, "ModulePath"), ("Report ID", 12, "IntegratorReportId"),
                ("Package name", 13, "PackageFullName"), ("Package app ID", 14, "PackageRelativeAppId") }
            : new[] { ("Program path", 5, "ExeFileName"), ("Freeze type", 9, "HangType"), ("Report ID", 6, "ReportId") };
        var eventLabel = string.IsNullOrWhiteSpace(e.Source) ? e.EventId.ToString() : $"{e.EventId} ({e.Source})";
        var metadata = fields.Select(f => (f.Item1, Value: e.DataAt(f.Item2, f.Item3)))
            .Prepend(("Program version", Value: version))
            .Prepend(("Event ID", Value: eventLabel))
            .Where(f => !string.IsNullOrWhiteSpace(f.Value))
            .Select(f => $"{f.Item1}: {f.Value}");
        return new(e.Time, app.Length > 0 ? app : "Unknown app", version, isCrash, part, e.ShortMessage)
        {
            Hang = isCrash ? null : new(e.Time, app, e.DataAt(5, "ExeFileName"), e.DataAt(7, "PackageFullName"),
                e.DataAt(9, "HangType"), reportId),
            Evidence = !isCrash ? null : new(e.Time, app, e.DataAt(10, "AppPath"), e.DataAt(13, "PackageFullName"),
                "Crash", reportId),
            ReviewKey = EventReviews.Key(e),
            ReportId = reportId,
            Code = code.Length > 0 && !code.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? $"0x{code}" : code,
            Metadata = string.Join("\n", metadata)
        };
    }

    private static readonly HashSet<string> WerCrashEventNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "APPCRASH", "BEX", "BEX64", "MoAppCrash", "MoBEX", "CLR20r3", "StowedException"
    };

    private static readonly HashSet<string> WerHangEventNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "AppHangB1", "MoAppHang"
    };

    private static bool IsWerAppEvent(WinEvent e) =>
        e.EventId == 1001 && e.Provider.Equals("Windows Error Reporting", StringComparison.OrdinalIgnoreCase);

    /// <summary>Converts a Windows Error Reporting Event 1001 into an app crash/hang incident when it represents a real app/service
    /// failure (ignoring BlueScreen, LiveKernelEvent, and telemetry buckets).</summary>
    public static Incident? TryWerToIncident(WinEvent e)
    {
        if (!IsWerAppEvent(e)) return null;
        var eventName = e.DataAt(2, "EventName");
        var isCrash = WerCrashEventNames.Contains(eventName);
        var isHang = !isCrash && WerHangEventNames.Contains(eventName);
        if (!isCrash && !isHang) return null;

        var fields = ParseWerFields(e, eventName, isCrash, isHang);
        if (string.IsNullOrWhiteSpace(fields.App)) return null;

        var bucket = e.DataAt(0, "Bucket");
        var reportId = e.DataAt(19, "ReportId");
        var metadata = BuildWerMetadata(fields.Version, eventName, bucket, fields.HangType, reportId);

        return new(e.Time, fields.App, fields.Version, isCrash, fields.Part, e.ShortMessage)
        {
            Hang = isCrash ? null : new(e.Time, fields.App, "", fields.Package, fields.HangType, reportId),
            ReviewKey = EventReviews.Key(e),
            ReportId = reportId,
            Code = fields.Code,
            Metadata = metadata
        };
    }

    private readonly record struct WerFields(string App, string Version, string Part, string Code, string Package, string HangType);

    private static WerFields ParseWerFields(WinEvent e, string eventName, bool isCrash, bool isHang)
    {
        var p1 = e.DataAt(5, "P1");
        var p2 = e.DataAt(6, "P2");
        if (eventName.StartsWith("Mo", StringComparison.OrdinalIgnoreCase))
            return ParseMoWerFields(e, p1, p2, isCrash);
        if (eventName.Equals("CLR20r3", StringComparison.OrdinalIgnoreCase))
            return new(p1, p2, e.DataAt(13, "P9"), "", "", "");
        if (eventName.Equals("StowedException", StringComparison.OrdinalIgnoreCase))
            return new(p1.Split('_')[0], p2, e.DataAt(7, "P3"), "", p1.Contains('_') ? p1 : "", "");
        if (isHang)
        {
            var p5 = e.DataAt(9, "P5");
            return new(p1, p2, "", "", "", p5 == "2097152" ? "Quiesce" : p5);
        }
        var p7 = e.DataAt(11, "P7");
        return new(p1, p2, e.DataAt(8, "P4"), LooksHexCode(p7) ? NormalizeHexCode(p7) : "", "", "");
    }

    private static WerFields ParseMoWerFields(WinEvent e, string p1, string p2, bool isCrash)
    {
        var app = p2.StartsWith("praid:", StringComparison.OrdinalIgnoreCase) && p2.Length > 6
            ? p2[6..]
            : p1.Split('_')[0];
        var version = e.DataAt(7, "P3");
        if (!isCrash)
        {
            var p6 = e.DataAt(10, "P6");
            return new(app, version, "", "", p1, p6 == "2097152" ? "Quiesce" : p6);
        }
        var p4 = e.DataAt(8, "P4");
        var p7 = e.DataAt(11, "P7");
        var part = p4.Contains('.') ? p4 : "";
        var code = LooksHexCode(p7) ? NormalizeHexCode(p7) : "";
        return new(app, version, part, code, p1, "");
    }

    private static string BuildWerMetadata(string version, string eventName, string bucket, string hangType, string reportId)
    {
        var metadata = new[]
        {
            string.IsNullOrWhiteSpace(version) ? null : $"Program version: {version}",
            $"WER event: {eventName}",
            string.IsNullOrWhiteSpace(bucket) ? null : $"Fault bucket: {bucket}",
            string.IsNullOrWhiteSpace(hangType) ? null : $"Freeze type: {hangType}",
            string.IsNullOrWhiteSpace(reportId) ? null : $"Report ID: {reportId}"
        }.Where(line => line is not null);
        return string.Join("\n", metadata);
    }

    private static bool LooksHexCode(string value)
    {
        var trimmed = value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? value[2..] : value;
        return trimmed.Length is >= 6 and <= 8 && trimmed.All(Uri.IsHexDigit);
    }

    private static string NormalizeHexCode(string value) =>
        value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? value : $"0x{value}";

    /// <summary>Yellow only for a crash/freeze in the last 7 days; red when one app crashed 3+ times in 7 days.
    /// Older incidents are still listed but shown neutral.</summary>
    public static AreaReport Build(IReadOnlyList<WinEvent> events, DateTimeOffset? now = null)
    {
        var cutoff = (now ?? ReportClock.Now).AddDays(-RecentDays);
        var all = CollectIncidents(events);
        AttachRuntimeErrors(all, events);

        var recent = all.Where(i => i.Time >= cutoff).ToList();
        var older = all.Count - recent.Count;
        var repeatApp = recent.Where(i => i.IsCrash).GroupBy(i => i.App, StringComparer.OrdinalIgnoreCase).FirstOrDefault(g => g.Count() >= RepeatCrashes);
        var crashes = all.Where(i => i.IsCrash).ToList();
        var hangs = all.Where(i => !i.IsCrash).ToList();
        var byApp = all.GroupBy(i => i.App, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count()).ThenByDescending(g => g.Max(i => i.Time)).ToList();
        var top = byApp.FirstOrDefault();

        var cards = new List<AreaCard>
        {
            BuildCrashesCard(crashes, repeatApp, cutoff),
            BuildHangsCard(hangs, cutoff),
            BuildAppsCard(byApp, top),
        };
        var summary = BuildReportSummary(all.Count, recent.Count, older, crashes.Count, hangs.Count, repeatApp, top);
        var status = repeatApp is not null ? DiagnosticStatus.Error : recent.Count > 0 ? DiagnosticStatus.Warning : DiagnosticStatus.Ok;
        return new(cards, summary, status);
    }

    private static List<Incident> CollectIncidents(IReadOnlyList<WinEvent> events)
    {
        var primary = events.Where(e => e.EventId is 1000 or 1002).Select(ToIncident).ToList();
        // Append WER-only Event 1001 incidents that don't duplicate an Event 1000/1002 (or another Event 1001 with the same ReportId).
        var knownReportIds = new HashSet<string>(
            primary.Select(i => i.ReportId).Where(id => !string.IsNullOrWhiteSpace(id)),
            StringComparer.OrdinalIgnoreCase);
        var all = new List<Incident>(primary);
        foreach (var wer in events.Where(IsWerAppEvent).Select(TryWerToIncident).OfType<Incident>())
        {
            if (!string.IsNullOrWhiteSpace(wer.ReportId) && !knownReportIds.Add(wer.ReportId))
                continue;
            if (IsDuplicateOfPrimary(primary, wer))
                continue;
            all.Add(wer);
        }
        all.Sort((a, b) => b.Time.CompareTo(a.Time));
        return all;
    }

    private static bool IsDuplicateOfPrimary(List<Incident> primary, Incident wer) =>
        primary.Any(p => p.IsCrash == wer.IsCrash
            && (p.Time - wer.Time).Duration() <= TimeSpan.FromSeconds(10)
            && AppsMatch(p, wer));

    private static bool AppsMatch(Incident primaryIncident, Incident werIncident)
    {
        if (string.Equals(primaryIncident.App, werIncident.App, StringComparison.OrdinalIgnoreCase))
            return true;
        return !string.IsNullOrWhiteSpace(primaryIncident.Hang?.Package)
            && !string.IsNullOrWhiteSpace(werIncident.Hang?.Package)
            && string.Equals(primaryIncident.Hang.Package, werIncident.Hang.Package, StringComparison.OrdinalIgnoreCase);
    }

    private static void AttachRuntimeErrors(List<Incident> all, IReadOnlyList<WinEvent> events)
    {
        var runtime = events.Where(e => e.EventId == 1026 && e.Provider.Equals(".NET Runtime", StringComparison.OrdinalIgnoreCase))
            .Select(ParseRuntimeError)
            .Where(e => e.App is not null && e.Error is not null)
            .ToList();

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
    }

    private static (DateTimeOffset Time, string? App, string? Error, string Stack) ParseRuntimeError(WinEvent e)
    {
        var lines = (e.Data.FirstOrDefault() ?? e.Message).Split('\n', StringSplitOptions.TrimEntries);
        const string appPrefix = "Application: ", errorPrefix = "Exception Info: ";
        var app = lines.FirstOrDefault(line => line.StartsWith(appPrefix, StringComparison.Ordinal))?[appPrefix.Length..];
        var error = lines.FirstOrDefault(line => line.StartsWith(errorPrefix, StringComparison.Ordinal))?[errorPrefix.Length..];
        var stack = string.Join("\n", lines.Where(line => line.StartsWith("at ", StringComparison.Ordinal)).Take(5));
        return (e.Time, app, error, stack);
    }

    private static AreaRow BuildIncidentRow(Incident i, DateTimeOffset cutoff) =>
        new(i.IsCrash && i.Time >= cutoff ? AreaLevel.Warning : AreaLevel.Neutral,
            [WindowsEventLog.FormatTime(i.Time), i.App, i.IsCrash ? "Crash" : "Freeze", i.Version, i.Details],
            [AreaSort.TimeKey(i.Time), null, null, null, null], Detail: i.Expanded,
            ReviewKeys: i.ReviewKey is { } key ? [key] : null,
            EvidenceOccurrences: i.Evidence is { } ev ? [ev] : null);

    private static AreaCard BuildCrashesCard(List<Incident> crashes, IGrouping<string, Incident>? repeatApp, DateTimeOffset cutoff)
    {
        var hasRecent = crashes.Any(i => i.Time >= cutoff);
        var level = repeatApp is not null ? AreaLevel.Error : hasRecent ? AreaLevel.Warning : crashes.Count > 0 ? AreaLevel.Neutral : AreaLevel.Ok;
        return new("crashes", "Apps that closed unexpectedly", level,
            crashes.Count == 0 ? "None" : AreaModuleBase.Plural(crashes.Count, "crash", "crashes"),
            crashes.FirstOrDefault() is { } c ? $"Latest: {c.App}, {WindowsEventLog.FormatTime(c.Time)}" : $"In the last {Days} days",
            ["When", "App", "Type", "Version", "Details"],
            crashes.Select(i => BuildIncidentRow(i, cutoff)).ToList())
        {
            EventCount = crashes.Count,
            WindowDays = Days,
            RecentEventCount = crashes.Count(i => i.Time >= cutoff),
            RecentWindowDays = RecentDays
        };
    }

    private static AreaCard BuildHangsCard(List<Incident> hangs, DateTimeOffset cutoff)
    {
        var hasRecent = hangs.Any(i => i.Time >= cutoff);
        var level = hasRecent ? AreaLevel.Warning : hangs.Count > 0 ? AreaLevel.Neutral : AreaLevel.Ok;
        var rows = hangs
            .GroupBy(i => (i.Hang!.Path.Length > 0 ? i.Hang.Path : i.App) + "\n" + i.Hang.Package, StringComparer.OrdinalIgnoreCase)
            .Select(g => BuildGroupedHangRow(g, cutoff))
            .OrderByDescending(row => row.HangOccurrences!.Count)
            .ToList();
        return new(HangsCardId, "Apps that stopped responding", level,
            hangs.Count == 0 ? "None" : AreaModuleBase.Plural(hangs.Count, "time"),
            hangs.FirstOrDefault() is { } h ? $"Latest: {h.App}, {WindowsEventLog.FormatTime(h.Time)}" : $"In the last {Days} days",
            ["When", "App", "Type", "Version", "Details", "Count"],
            rows)
        {
            EventCount = hangs.Count,
            WindowDays = Days,
            RecentEventCount = hangs.Count(i => i.Time >= cutoff),
            RecentWindowDays = RecentDays
        };
    }

    private static AreaRow BuildGroupedHangRow(IGrouping<string, Incident> g, DateTimeOffset cutoff)
    {
        var latest = g.First();
        var row = BuildIncidentRow(latest, cutoff);
        var occurrences = g.Select(i => i.Hang!).ToList();
        var package = latest.Hang!.Package;
        var detail = string.Join("\n\n", g.Select(i => $"{WindowsEventLog.FormatTime(i.Time)}\n{i.Expanded}"));
        return row with
        {
            Values =
            [
                row.Values[0],
                package.Length == 0 ? latest.App : $"{latest.App} · {package.Split('_')[0]}",
                row.Values[2], row.Values[3], row.Values[4], g.Count().ToString()
            ],
            Detail = package.Length == 0 ? detail : $"Recorded package: {package}\n\n{detail}",
            ReviewKeys = g.Select(i => i.ReviewKey).OfType<string>().ToList(),
            HangOccurrences = occurrences
        };
    }

    private static AreaCard BuildAppsCard(List<IGrouping<string, Incident>> byApp, IGrouping<string, Incident>? top) =>
        new("apps", "Most affected apps", top is null ? AreaLevel.Ok : AreaLevel.Neutral,
            top is null ? "No problems recorded" : top.Key,
            top is null ? $"In the last {Days} days" : $"{AreaModuleBase.Plural(top.Count(), "problem")} in the last {Days} days",
            ["App", "Crashes", "Freezes", "Last time"],
            byApp.Select(g => new AreaRow(AreaLevel.Neutral,
                [g.Key, g.Count(i => i.IsCrash).ToString(), g.Count(i => !i.IsCrash).ToString(), WindowsEventLog.FormatTime(g.Max(i => i.Time))],
                [null, null, null, AreaSort.TimeKey(g.Max(i => i.Time))],
                Detail: AppDetails(g),
                ReviewKeys: g.Select(i => i.ReviewKey).OfType<string>().ToList(),
                EvidenceOccurrences: g.Select(i => i.Evidence ?? i.Hang).OfType<HangOccurrence>().ToList())).ToList(),
            PreserveRowOrder: true);

    private static string BuildReportSummary(
        int totalCount, int recentCount, int older, int crashCount, int hangCount,
        IGrouping<string, Incident>? repeatApp, IGrouping<string, Incident>? top)
    {
        if (totalCount == 0) return $"No app crashes in the last {Days} days";
        if (recentCount == 0) return $"No crashes in the last {RecentDays} days ({older} older)";
        if (repeatApp is not null) return $"{repeatApp.Key} crashed {repeatApp.Count()} times in the last {RecentDays} days";
        return $"{AreaModuleBase.Plural(crashCount, "crash", "crashes")}, {AreaModuleBase.Plural(hangCount, "freeze")} in the last {Days} days · most: {top!.Key}";
    }

    public async Task<string> FindHangEvidenceAsync(IReadOnlyList<HangOccurrence> occurrences, CancellationToken ct)
    {
        const int maxOccurrences = 20;
        var selected = occurrences.Where(h => h.Time != default).Distinct().OrderByDescending(h => h.Time)
            .Take(maxOccurrences).OrderBy(h => h.Time).ToList();
        var (windows, changeWindows) = MergeEvidenceWindows(selected);

        var reportIds = selected.Select(h => Guid.TryParse(h.ReportId, out var id) ? id : Guid.Empty)
            .Where(id => id != Guid.Empty).ToHashSet();
        var lines = new List<string> { "Historical timeline. Nearby events are timestamp matches only." };
        foreach (var (start, end) in windows)
            await AppendHangWindowEvidenceAsync(lines, start, end, reportIds, ct).ConfigureAwait(false);
        foreach (var (start, end) in changeWindows)
            await AppendChangeWindowEvidenceAsync(lines, start, end, ct).ConfigureAwait(false);

        if (occurrences.Count > maxOccurrences) lines.Add($"Timeline limited to the {maxOccurrences} latest incidents.");
        lines.Add("Historical disk latency and wait-chain measurements were not collected by this lookup.");
        return string.Join("\n", lines);
    }

    private static (List<(DateTimeOffset Start, DateTimeOffset End)> Windows, List<(DateTimeOffset Start, DateTimeOffset End)> ChangeWindows)
        MergeEvidenceWindows(List<HangOccurrence> selected)
    {
        var windows = new List<(DateTimeOffset Start, DateTimeOffset End)>();
        var changeWindows = new List<(DateTimeOffset Start, DateTimeOffset End)>();
        foreach (var incident in selected)
        {
            var end = incident.Time.AddMinutes(5);
            AddMergedWindow(windows, incident.Time.AddMinutes(-5), end);
            AddMergedWindow(changeWindows, incident.Time.AddHours(-24), end);
        }
        return (windows, changeWindows);
    }

    private static void AddMergedWindow(List<(DateTimeOffset Start, DateTimeOffset End)> windows, DateTimeOffset start, DateTimeOffset end)
    {
        if (windows.Count > 0 && start <= windows[^1].End)
            windows[^1] = (windows[^1].Start, end);
        else
            windows.Add((start, end));
    }

    private async Task AppendHangWindowEvidenceAsync(
        List<string> lines, DateTimeOffset start, DateTimeOffset end, HashSet<Guid> reportIds, CancellationToken ct)
    {
        var time = $"TimeCreated[@SystemTime >= '{start.UtcDateTime:O}' and @SystemTime <= '{end.UtcDateTime:O}']";
        var appQuery = $"*[System[{time} and (EventID=1000 or EventID=1001 or EventID=1002 or Level=1 or Level=2)]]";
        var systemQuery = $"*[System[{time} and (Level=1 or Level=2 or Level=3 or Provider[@Name='Microsoft-Windows-WindowsUpdateClient' or @Name='Microsoft-Windows-Kernel-PnP'])]]";
        var storageQuery = $"*[System[{time} and Provider[@Name='disk' or @Name='Ntfs' or @Name='Microsoft-Windows-Ntfs' or @Name='Microsoft-Windows-StorPort' or @Name='stornvme' or @Name='storahci' or @Name='iaStorAC' or @Name='iaStorVD' or @Name='volmgr'] and (Level=1 or Level=2 or Level=3 or EventID=7 or EventID=11 or EventID=15 or EventID=51 or EventID=129 or EventID=153 or EventID=157)]]";
        var serviceQuery = $"*[System[{time} and Provider[@Name='Service Control Manager'] and (EventID=7000 or EventID=7001 or EventID=7009 or EventID=7011 or EventID=7022 or EventID=7023 or EventID=7024)]]";
        var memoryQuery = $"*[System[{time} and ((Provider[@Name='Microsoft-Windows-Resource-Exhaustion-Detector'] and EventID=2004) or (Provider[@Name='Application Popup'] and EventID=26) or Provider[@Name='Microsoft-Windows-MemoryDiagnostics-Results'] or Provider[@Name='Microsoft-Windows-Kernel-Memory'])]]";
        var storageTask = _log.QueryAsync("System", storageQuery, 20, ct);
        var serviceTask = _log.QueryAsync("System", serviceQuery, 20, ct);
        var memoryTask = _log.QueryAsync("System", memoryQuery, 20, ct);
        var appTask = _log.QueryAsync("Application", appQuery, 60, ct);
        var systemTask = _log.QueryAsync("System", systemQuery, 60, ct);
        await Task.WhenAll(appTask, systemTask, storageTask, serviceTask, memoryTask).ConfigureAwait(false);

        lines.Add($"\n{WindowsEventLog.FormatTime(start)} to {WindowsEventLog.FormatTime(end)}");
        AppendFollowUpSection(lines, "Storage stalls and file-system events", await storageTask);
        AppendFollowUpSection(lines, "Service startup, dependency, and timeout events", await serviceTask);
        AppendFollowUpSection(lines, "Memory pressure and low-memory events", await memoryTask);

        var app = await appTask;
        var system = await systemTask;
        if (app is null || system is null) lines.Add("Some event logs could not be read.");
        var related = (app ?? []).Concat(system ?? [])
            .Select(e => (Event: e, Exact: IsExactReportMatch(e, reportIds)))
            .OrderByDescending(item => item.Exact).ThenBy(item => item.Event.Time).Take(20).ToList();
        if (related.Count == 0) lines.Add("No matching log entries found in this window.");
        foreach (var (e, exact) in related)
        {
            var message = exact && e.Message.Length > 0 ? e.Message : e.ShortMessage;
            lines.Add($"{(exact ? "Matching report ID" : "Nearby event")} · {WindowsEventLog.FormatTime(e.Time)} · {e.Source} {e.EventId}\n{message}");
        }
    }

    private static bool IsExactReportMatch(WinEvent e, HashSet<Guid> reportIds) =>
        e.EventId == 1001 &&
        (e.Data.Any(value => Guid.TryParse(value, out var id) && reportIds.Contains(id)) ||
         reportIds.Any(id => e.Message.Contains(id.ToString(), StringComparison.OrdinalIgnoreCase)));

    private async Task AppendChangeWindowEvidenceAsync(List<string> lines, DateTimeOffset start, DateTimeOffset end, CancellationToken ct)
    {
        var time = $"TimeCreated[@SystemTime >= '{start.UtcDateTime:O}' and @SystemTime <= '{end.UtcDateTime:O}']";
        var updateQuery = $"*[System[{time} and Provider[@Name='Microsoft-Windows-WindowsUpdateClient'] and (EventID=19 or EventID=20 or EventID=43 or EventID=44)]]";
        var installQuery = $"*[System[{time} and Provider[@Name='MsiInstaller'] and (EventID=1033 or EventID=1034 or EventID=11707 or EventID=11708)]]";
        var updateTask = _log.QueryAsync("System", updateQuery, 15, ct);
        var installTask = _log.QueryAsync("Application", installQuery, 15, ct);
        await Task.WhenAll(updateTask, installTask).ConfigureAwait(false);
        var updates = await updateTask;
        var installs = await installTask;
        lines.Add($"\nRecent Windows Update and app install activity ({WindowsEventLog.FormatTime(start)} to {WindowsEventLog.FormatTime(end)})");
        if (updates is null && installs is null)
        {
            lines.Add("Could not read this event query.");
            return;
        }
        var changes = (updates ?? []).Concat(installs ?? []).OrderBy(e => e.Time).Take(15).ToList();
        if (changes.Count == 0)
        {
            lines.Add("No Windows Update or MSI installer events in this window.");
            return;
        }
        foreach (var e in changes)
            lines.Add($"Nearby event · {WindowsEventLog.FormatTime(e.Time)} · {e.Source} {e.EventId} · {e.ShortMessage}");
    }

    private static void AppendFollowUpSection(List<string> lines, string title, IReadOnlyList<WinEvent>? events)
    {
        lines.Add(title);
        if (events is null)
        {
            lines.Add("Could not read this event query.");
            return;
        }
        if (events.Count == 0)
        {
            lines.Add("No matching events in this window.");
            return;
        }
        foreach (var e in events.OrderBy(e => e.Time))
            lines.Add($"Nearby event · {WindowsEventLog.FormatTime(e.Time)} · {e.Source} {e.EventId} · {e.ShortMessage}");
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
