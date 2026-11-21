using PeakSWC.RemoteWebView.Agent;
using RemotePCDiagnostics.Agent;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Metrics;

namespace RemotePCDiagnostics.Tests;

public sealed class ScheduledMetricsTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "rpcd-metrics-" + Guid.NewGuid().ToString("N"));
    private DateTimeOffset _now = new(2026, 11, 1, 12, 0, 0, TimeSpan.Zero);

    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    private sealed class FakeProbes : IMetricsProbes
    {
        public int Calls;
        public Task<IReadOnlyList<DiagnosticResult>> MeasureAsync(string checkId, CancellationToken ct)
        {
            Calls++;
            if (checkId == ModuleSlugs.Sensors) throw new InvalidOperationException("driver");
            var report = new AreaReport([], "ok", DiagnosticStatus.Ok) { KeyMetrics = [new("x." + checkId, "X", 42, "%", MetricTrend.HigherIsBetter)] };
            return Task.FromResult<IReadOnlyList<DiagnosticResult>>([new DiagnosticResult(checkId, DiagnosticStatus.Ok, "fine", DateTimeOffset.UtcNow, report)]);
        }
    }

    private AgentMetrics New(FakeProbes probes, List<DiagnosticResult>? history = null, (bool, int?)? power = null) =>
        new("machine-1", _dir, () => probes, history is null ? null : history.Add, () => "1.2.3", () => power ?? (false, null), () => _now, () => _now - TimeSpan.FromHours(5));

    [Fact]
    public void Outbox_IsCapped_KeepsSequence_AndSurvivesARestart()
    {
        var path = Path.Combine(_dir, "outbox.json");
        var box = new MetricsOutbox(path, () => _now);
        for (var i = 0; i < MetricsOutbox.MaxRuns + 5; i++) box.Add("BatteryPower", null, null, _now, "OK", "s", [], "1");
        Assert.Equal(MetricsOutbox.MaxRuns, box.Count);
        Assert.Equal(6, box.NextBatch()[0].Seq); // the five oldest went
        Assert.Equal(MetricsOutbox.BatchSize, box.NextBatch().Count);

        var again = new MetricsOutbox(path, () => _now);
        Assert.Equal(MetricsOutbox.MaxRuns, again.Count);
        Assert.Equal(50, again.Acknowledge(55));
        var next = again.Add("BatteryPower", null, null, _now, "OK", "s", [], "1");
        Assert.Equal(MetricsOutbox.MaxRuns + 6, next.Seq); // numbers never go back

        _now += MetricsOutbox.MaxAge + TimeSpan.FromDays(1);
        Assert.Empty(again.NextBatch()); // too old to matter
    }

    [Fact]
    public void Outbox_ADamagedFile_IsSetAside()
    {
        Directory.CreateDirectory(_dir);
        var path = Path.Combine(_dir, "outbox.json");
        File.WriteAllText(path, "{ not json");
        var box = new MetricsOutbox(path, () => _now);
        Assert.Equal(0, box.Count);
        Assert.True(File.Exists(path + ".bad"));
        Assert.Equal(1, box.Add("x", null, null, _now, "OK", "", [], "").Seq);
    }

    [Fact]
    public void Schedule_IsClamped_AndUnknownChecksFallBackToTheDefaults()
    {
        var s = MetricsSchedule.From(3, true, 5, ["Sensors", "nope", "SENSORS"]);
        Assert.Equal(TimeSpan.FromHours(1), s.Interval);
        Assert.Equal([ModuleSlugs.Sensors], s.Checks);
        Assert.Equal(MetricsSchedule.DefaultChecks, MetricsSchedule.From(1, true, 999_999, ["nope"]).Checks);
        Assert.Equal(TimeSpan.FromDays(7), MetricsSchedule.From(1, true, 999_999, null).Interval);
    }

    [Fact]
    public void Planner_WaitsAfterBoot_NeverOverlaps_AndPutsOffForSessionsAndLowBattery()
    {
        var boot = _now - TimeSpan.FromMinutes(2);
        var due = MetricsPlanner.NextDue(null, MetricsSchedule.Default, "m", boot);
        Assert.True(due >= boot + MetricsPlanner.AfterBoot);
        Assert.Equal(MetricsSkip.NotDue, MetricsPlanner.Check(MetricsSchedule.Default, _now, due, false, false, false, null));
        Assert.Equal(MetricsSkip.PassRunning, MetricsPlanner.Check(MetricsSchedule.Default, due, due, true, false, false, null));
        Assert.Equal(MetricsSkip.SessionRunning, MetricsPlanner.Check(MetricsSchedule.Default, due, due, false, true, false, null));
        Assert.Equal(MetricsSkip.LowBattery, MetricsPlanner.Check(MetricsSchedule.Default, due, due, false, false, true, 15));
        Assert.Equal(MetricsSkip.None, MetricsPlanner.Check(MetricsSchedule.Default, due, due, false, false, true, 60));
        var off = MetricsSchedule.Default with { Enabled = false };
        Assert.Equal(MetricsSkip.Disabled, MetricsPlanner.Check(off, due, due, false, false, false, null));
        Assert.Equal(MetricsSkip.None, MetricsPlanner.Check(off, _now, due, false, false, false, null, onDemand: true));
        Assert.NotEqual(MetricsPlanner.Jitter("pc-a", TimeSpan.FromDays(1)), MetricsPlanner.Jitter("pc-b", TimeSpan.FromDays(1)));
    }

    [Fact]
    public async Task Pass_WritesHistory_QueuesEveryCheck_AndAFailingCheckDoesNotStopTheRest()
    {
        var probes = new FakeProbes();
        var history = new List<DiagnosticResult>();
        var metrics = New(probes, history);
        _now += TimeSpan.FromHours(2);
        Assert.Equal(MetricsSkip.None, await metrics.RunIfDueAsync(false, CancellationToken.None));
        Assert.Equal(4, probes.Calls);
        Assert.Equal(4, history.Count);
        Assert.Equal(4, metrics.Waiting);
        var sensors = metrics.Outbox.NextBatch().Single(r => r.CheckId == ModuleSlugs.Sensors);
        Assert.Equal("Couldn't run", sensors.Outcome);
        Assert.Contains(metrics.Outbox.NextBatch(), r => r.Metrics.Any(m => m.Id == "x.BatteryPower" && m.Value == 42));

        // Not due again until the interval has passed.
        Assert.Equal(MetricsSkip.NotDue, await metrics.RunIfDueAsync(false, CancellationToken.None));
    }

    [Fact]
    public async Task BusyOrLowBattery_PutsThePassOff_WithoutRunningAnything()
    {
        var probes = new FakeProbes();
        _now += TimeSpan.FromHours(2);
        Assert.Equal(MetricsSkip.SessionRunning, await New(probes).RunIfDueAsync(true, CancellationToken.None));
        Assert.Equal(MetricsSkip.LowBattery, await New(probes, power: (true, 10)).RunIfDueAsync(false, CancellationToken.None));
        Assert.Equal(0, probes.Calls);
    }

    [Fact]
    public async Task Upload_SendsABatch_AndForgetsItOnlyWhenAdminAcknowledges()
    {
        var metrics = New(new FakeProbes());
        _now += TimeSpan.FromHours(2);
        await metrics.RunIfDueAsync(false, CancellationToken.None); // offline: kept
        Assert.Equal(4, metrics.Waiting);

        var sent = new List<MetricsBatch>();
        metrics.Attach((m, _) =>
        {
            sent.Add(m.Metrics);
            metrics.Acknowledge(m.Metrics.Runs.Max(r => r.Seq));
            return Task.CompletedTask;
        });
        await metrics.UploadAsync(CancellationToken.None);
        Assert.Single(sent);
        Assert.Equal(4, sent[0].Runs.Count);
        Assert.Equal(MetricDirection.MetricHigherIsBetter, sent[0].Runs[0].Metrics[0].Better);
        Assert.Equal(0, metrics.Waiting);
    }

    [Fact]
    public async Task NoAcknowledgement_KeepsTheRuns_AndBacksOff()
    {
        var metrics = New(new FakeProbes());
        _now += TimeSpan.FromHours(2);
        await metrics.RunIfDueAsync(false, CancellationToken.None);
        var sends = 0;
        metrics.Attach((_, _) => { sends++; throw new IOException("stream gone"); });
        await metrics.UploadAsync(CancellationToken.None);
        await metrics.UploadAsync(CancellationToken.None); // backing off: not sent again yet
        Assert.Equal(1, sends);
        Assert.Equal(4, metrics.Waiting);

        _now += AgentMetrics.MinUploadBackoff + TimeSpan.FromSeconds(1);
        await metrics.UploadAsync(CancellationToken.None);
        Assert.Equal(2, sends);
        // A reconnect may try again at once.
        metrics.Attach((_, _) => { sends++; throw new IOException("again"); });
        await metrics.UploadAsync(CancellationToken.None);
        Assert.Equal(3, sends);
    }

    [Fact]
    public void Schedule_FromAdmin_IsSaved_OlderRevisionsIgnored_AndCollectNowIsRateLimited()
    {
        var metrics = New(new FakeProbes());
        Assert.Equal(0, metrics.ScheduleRevision);
        Assert.True(metrics.ApplySchedule(new MetricsScheduleCommand { Revision = 4, Enabled = false, IntervalMinutes = 120, CheckIds = { "DriveHealth" } }));
        Assert.False(metrics.ApplySchedule(new MetricsScheduleCommand { Revision = 3, Enabled = true }));
        var reloaded = New(new FakeProbes());
        Assert.Equal((4L, false, ModuleSlugs.DriveHealth), (reloaded.ScheduleRevision, reloaded.Schedule.Enabled, reloaded.Schedule.Checks.Single()));

        Assert.True(metrics.CollectNow());
        Assert.False(metrics.CollectNow());
        _now += MetricsPlanner.MinOnDemandGap;
        Assert.True(metrics.CollectNow());
    }

    [Fact]
    public async Task CollectNow_RunsEvenWhenTheScheduleIsOff()
    {
        var probes = new FakeProbes();
        var metrics = New(probes);
        metrics.ApplySchedule(new MetricsScheduleCommand { Revision = 1, Enabled = false, IntervalMinutes = 1440 });
        Assert.Equal(MetricsSkip.Disabled, await metrics.RunIfDueAsync(false, CancellationToken.None));
        metrics.CollectNow();
        Assert.Equal(MetricsSkip.None, await metrics.RunIfDueAsync(false, CancellationToken.None));
        Assert.Equal(4, probes.Calls);
    }
}
