using RemotePCDiagnostics.Agent;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.History;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Metrics;
using RemotePCDiagnostics.Core.Recording;

namespace RemotePCDiagnostics.Tests.Replay;

/// <summary>
/// History on recorded PCs: every check's result, as is and with every answer broken, goes through the app's real logging path (the
/// result store and <see cref="ResultEventLogger"/>, which writes event 1100) and is read back through <see cref="EventLogHistoryStore"/>,
/// as the History page reads it. What History shows must be what the check found: the same outcome (a failed or broken check never reads
/// as OK), summary, card values and key metrics. The Agent's scheduled pass writes History too, under the same module ids, so its runs
/// and the app's land on one trend.
/// </summary>
public sealed class HistoryReplayTests : IDisposable
{
    public static TheoryData<string> Recordings => RecordingLibrary.Names();

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "rpcd-history-" + Guid.NewGuid().ToString("N"));

    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    /// <summary>The checks the recording holds answers for: the Setup edition's, the Store edition's, Sound and the security audit.</summary>
    private static IReadOnlyList<IDiagnosticModule> Checks(ReplayedPc pc)
    {
        List<IDiagnosticModule> list =
        [
            pc.Inventory(), pc.BatteryPower(), pc.DriveHealth(), pc.Services(), pc.DeviceDrivers(), pc.Programs(),
            pc.Network(), pc.SecurityEssentials(), pc.ResourceHogs(), pc.Crashes(), pc.EventLog(), pc.SleepWake(),
        ];
        if (pc.HasAudio) list.Add(pc.Sound());
        if (pc.HasSecurityAudit) list.Add(pc.SecurityAudit());
        return list;
    }

    private sealed class Sink : ILogSink
    {
        public List<LogEntry> Entries { get; } = [];
        public void Write(LogEntry entry) { lock (Entries) Entries.Add(entry); }
    }

    /// <summary>Runs every check through a result store watched by the app's event logger, then reads History back from what it wrote.</summary>
    private static async Task<(List<DiagnosticResult> Logged, IReadOnlyList<HistoryEntry> History, ModuleCatalog Catalog)> RunAndReadAsync(
        ReplayedPc pc, CancellationToken ct)
    {
        var checks = Checks(pc);
        var catalog = ModuleCatalog.For(checks);
        var store = new ResultStore();
        var sink = new Sink();
        var context = new ResultEventContext(n => catalog.DisplayName(n), () => "<pc>", "1.2.3.4", n => HistoryIds.For(n, catalog));
        _ = new ResultEventLogger(store, sink, context: context);
        var logged = new List<DiagnosticResult>();
        foreach (var check in checks)
        {
            var r = await check.RefreshAsync(null, ct);
            store.Set(r);
            if (r.Payload is InstanceResults each)
                foreach (var i in each.Results) { store.Set(i); logged.Add(i); }
            else logged.Add(r);
        }
        // The sink truncates as EventLogSink does before the message reaches the Event Log.
        var events = sink.Entries.Where(e => e.EventId == LogEventIds.TestResult)
            .Select(e => new RawHistoryEvent(DateTimeOffset.UtcNow, LogText.Truncate(e.Message))).ToList();
        Assert.Equal(logged.Count, events.Count);
        var read = new EventLogHistoryStore((_, _) => events).Read(null);
        Assert.True(read.Available, read.Problem);
        return (logged, read.Entries, catalog);
    }

    private static string One(string? s) => (s ?? "").Replace("\r", " ").Replace("\n", " ").Trim();

    /// <summary>What's wrong with how History shows <paramref name="r"/> (nothing when it reads back as the check found it).</summary>
    private static IEnumerable<string> Differences(DiagnosticResult r, IReadOnlyList<HistoryEntry> history, ModuleCatalog? catalog)
    {
        var name = r.ModuleName + (r.InstanceKey is { } ik ? " #" + ik : "");
        var matches = history.Where(e => e.Module == r.ModuleName && e.InstanceId == r.InstanceKey).ToList();
        if (matches.Count != 1) { yield return $"{name}: {matches.Count} History entries"; yield break; }
        var e = matches[0];
        var outcome = ResultEventLogger.Outcome(r);
        if (e.Outcome != outcome) yield return $"{name}: outcome {e.Outcome}, the check said {outcome}";
        if (r.Status is DiagnosticStatus.Warning or DiagnosticStatus.Error && e.Outcome == "OK") yield return $"{name}: a {r.Status} result reads as OK";
        if (e.Summary != One(r.Message)) yield return $"{name}: summary \"{e.Summary}\", the check said \"{One(r.Message)}\"";
        if (e.TimeUtc != r.Timestamp.ToUniversalTime()) yield return $"{name}: time {e.TimeUtc:O}, the check finished {r.Timestamp:O}";
        if (e.ModuleId != HistoryIds.For(r.ModuleName, catalog)) yield return $"{name}: module id {e.ModuleId}";
        if (r.InstanceKey is not null && !string.IsNullOrWhiteSpace(r.InstanceLabel) && e.Instance != One(r.InstanceLabel))
            yield return $"{name}: instance \"{e.Instance}\", the check said \"{One(r.InstanceLabel)}\"";

        var measured = ResultEventLogger.Measurements(r.Payload).Select(m => (m.Name.Trim(), One(m.Value).Trim())).ToList();
        var shown = e.Measurements.Select(m => (m.Name, m.Value)).ToList();
        if (!measured.SequenceEqual(shown))
            yield return $"{name}: History shows {shown.Count} card values, the check had {measured.Count}; first difference: "
                + string.Join(" vs ", measured.Zip(shown).Where(p => p.First != p.Second).Select(p => $"{p.First} / {p.Second}").Take(1));

        var metrics = r.Payload is IKeyMetrics { KeyMetrics: { } km } ? km.Take(ResultEventLogger.MaxKeyMetrics).ToList() : [];
        if (metrics.Count != e.KeyMetrics.Count) yield return $"{name}: {e.KeyMetrics.Count} key metrics in History, the check had {metrics.Count}";
        foreach (var (want, got) in metrics.Zip(e.KeyMetrics))
            if (want.Value != got.Value || One(want.Unit).Replace("|", "/") != got.Unit || want.Better != got.Better || got.Id != One(want.Id).Replace("|", "/").Replace("=", "-"))
                yield return $"{name}: key metric {want.Id}={want.Value} {want.Unit} reads back as {got.Id}={got.Value} {got.Unit}";
    }

    /// <summary>The recorded answers, then every whole-answer fault on every source: History shows each result as the check found it.</summary>
    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task Every_result_reads_back_from_History(string name)
    {
        var ct = TestContext.Current.CancellationToken;
        var rec = RecordingLibrary.Load(name);
        var problems = new List<string>();
        foreach (var fault in new List<string?> { null }.Concat(Faults.WholeAnswer))
        {
            var plan = fault is null ? null : new FaultPlan([new FaultRule { Source = "*", Fault = fault, Ms = 1 }]);
            var (logged, history, catalog) = await RunAndReadAsync(new ReplayedPc(rec, plan), ct);
            foreach (var r in logged)
                problems.AddRange(Differences(r, history, catalog).Select(p => $"{fault ?? "as recorded"}: {p}"));
            // Each check shows once on the History page, under its own name.
            var latest = HistoryQuery.LatestByModule(HistoryNames.Normalize(history, catalog));
            foreach (var r in logged.Where(r => r.InstanceKey is null && !latest.ContainsKey(r.ModuleName)))
                problems.Add($"{fault ?? "as recorded"}: {r.ModuleName} missing from the latest-by-check view");
        }
        Assert.True(problems.Count == 0, string.Join("\n", problems.Distinct().Take(40)));
    }

    /// <summary>
    /// The Agent's scheduled pass on the recorded answers and with each fault: what it writes to History reads back as it measured, under
    /// the module id the app's own runs use (the Agent has no module catalog), so both land on one trend.
    /// </summary>
    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task Agent_runs_read_back_from_History_under_the_apps_ids(string name)
    {
        var ct = TestContext.Current.CancellationToken;
        var rec = RecordingLibrary.Load(name);
        var appCatalog = ModuleCatalog.For(Checks(new ReplayedPc(rec)));
        var problems = new List<string>();
        foreach (var fault in new List<string?> { null }.Concat(Faults.WholeAnswer))
        {
            var plan = fault is null ? null : new FaultPlan([new FaultRule { Source = "*", Fault = fault, Ms = 1 }]);
            var pc = new ReplayedPc(rec, plan);
            var written = new List<(DiagnosticResult Result, string Text)>();
            var probes = new CoreMetricsProbes(appFolder: null, sensors: null, wmi: pc.Wmi, driveHistoryPath: Path.Combine(_dir, Guid.NewGuid().ToString("N") + ".json"));
            var outbox = new MetricsOutbox(Path.Combine(_dir, Guid.NewGuid().ToString("N") + ".json"), () => DateTimeOffset.UtcNow);
            var schedule = new MetricsSchedule(1, true, MetricsSchedule.DefaultIntervalMinutes, [ModuleSlugs.DriveHealth, ModuleSlugs.BatteryPower]);
            await new ScheduledMetricsPass(probes, outbox, r => written.Add((r, AgentMetrics.HistoryText(r))), "test").RunAsync(schedule, ct);
            Assert.NotEmpty(written);
            var history = new EventLogHistoryStore((_, _) => written.Select(w => new RawHistoryEvent(DateTimeOffset.UtcNow, w.Text))).Read(null).Entries;
            foreach (var (r, _) in written)
                problems.AddRange(Differences(r, history, appCatalog).Select(p => $"{fault ?? "as recorded"}: {p}"));
        }
        Assert.True(problems.Count == 0, string.Join("\n", problems.Distinct().Take(40)));
    }
}
