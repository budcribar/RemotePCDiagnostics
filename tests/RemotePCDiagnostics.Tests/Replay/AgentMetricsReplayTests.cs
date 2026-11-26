using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Metrics;
using RemotePCDiagnostics.Core.Recording;

namespace RemotePCDiagnostics.Tests.Replay;

/// <summary>
/// The Agent's scheduled metrics pass (drive health and battery, read through WMI) on recorded PCs, as is and with each answer broken:
/// it measures what the checks measure, and a broken answer never stops the pass or sends Admin a number no PC has.
/// </summary>
public sealed class AgentMetricsReplayTests : IDisposable
{
    public static TheoryData<string> Recordings => RecordingLibrary.Names();

    private static readonly string[] WmiChecks = [ModuleSlugs.DriveHealth, ModuleSlugs.BatteryPower];

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "rpcd-agent-metrics-" + Guid.NewGuid().ToString("N"));

    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    private CoreMetricsProbes Probes(ReplayedPc pc) =>
        new(appFolder: null, sensors: null, wmi: pc.Wmi, driveHistoryPath: Path.Combine(_dir, Guid.NewGuid().ToString("N") + ".json"));

    private static void AssertSane(IEnumerable<DiagnosticResult> results, string context)
    {
        foreach (var r in results)
            foreach (var m in KeyMetricsOf(r))
            {
                Assert.True(double.IsFinite(m.Value), $"{context}: {r.ModuleName} {m.Id} = {m.Value}");
                if (m.Unit == "%") Assert.InRange(m.Value, 0, 200);
                Assert.False(m.Value is 4294967295 or 18446744073709551615d or -1, $"{context}: {r.ModuleName} {m.Id} = {m.Value}");
            }
    }

    private static IReadOnlyList<KeyMetric> KeyMetricsOf(DiagnosticResult r) => r.Payload is IKeyMetrics { KeyMetrics: { } km } ? km : [];

    /// <summary>On the recorded answers, the pass sees the drives and battery the checks see, with the same key metrics.</summary>
    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task Measures_what_the_checks_measure(string name)
    {
        var ct = TestContext.Current.CancellationToken;
        var pc = new ReplayedPc(RecordingLibrary.Load(name));
        var probes = Probes(pc);

        var drives = await probes.MeasureAsync(ModuleSlugs.DriveHealth, ct);
        var detection = await pc.DriveHealth().DetectAsync(ct);
        Assert.SkipWhen(pc.Replay.Misses.Count > 0, "Recorded before the drive check asked its current questions: record this PC again.");
        Assert.Equal(detection.Instances.Count, drives.Count);
        Assert.All(drives, d => Assert.True(d.Status != DiagnosticStatus.Error, $"{d.InstanceLabel}: {d.Message}; misses: {string.Join(" | ", pc.Replay.Misses)}"));

        var battery = await probes.MeasureAsync(ModuleSlugs.BatteryPower, ct);
        var check = await pc.BatteryPower().RefreshAsync(null, ct);
        if (battery.Count == 0) Assert.DoesNotContain("health", check.Message, StringComparison.OrdinalIgnoreCase); // no battery on this PC
        else
        {
            Assert.Single(battery);
            var health = KeyMetricsOf(battery[0]).FirstOrDefault(m => m.Unit == "%");
            if (health is not null && KeyMetricsOf(check).FirstOrDefault(m => m.Id == health.Id) is { } same)
                Assert.Equal(same.Value, health.Value);
        }
        AssertSane([.. drives, .. battery], name);
    }

    /// <summary>The whole pass on the recorded answers puts one outbox entry per drive and battery, all of them measured.</summary>
    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task Pass_fills_the_outbox(string name)
    {
        var pc = new ReplayedPc(RecordingLibrary.Load(name));
        var outbox = new MetricsOutbox(Path.Combine(_dir, "outbox.json"), () => DateTimeOffset.UtcNow);
        var history = new List<DiagnosticResult>();
        var schedule = new MetricsSchedule(1, true, MetricsSchedule.DefaultIntervalMinutes, WmiChecks);
        var added = await new ScheduledMetricsPass(Probes(pc), outbox, history.Add, "test").RunAsync(schedule, TestContext.Current.CancellationToken);
        Assert.True(added > 0);
        Assert.Equal(added, outbox.Count);
        Assert.Equal(added, history.Count);
    }

    /// <summary>Each whole-answer fault on every WMI answer: both measurements finish, and no nonsense number reaches Admin.</summary>
    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task Every_whole_answer_fault_finishes_without_nonsense(string name)
    {
        var rec = RecordingLibrary.Load(name);
        foreach (var fault in Faults.WholeAnswer.Append(Faults.Disconnected))
            foreach (var check in WmiChecks)
            {
                var plan = new FaultPlan([new FaultRule { Source = "wmi", Fault = fault, Ms = 1 }]);
                var probes = Probes(new ReplayedPc(rec, plan));
                var results = await probes.MeasureAsync(check, TestContext.Current.CancellationToken);
                Assert.NotEmpty(plan.Hits);
                AssertSane(results, $"{name} {check} {fault}");
                Assert.All(results, r => Assert.False(string.IsNullOrWhiteSpace(r.Message), $"{name} {check} {fault}: no summary"));
            }
    }

    /// <summary>One broken answer at a time (first match only) for each question the measurement asks: it still finishes sanely.</summary>
    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task Each_question_broken_alone_finishes_without_nonsense(string name)
    {
        var rec = RecordingLibrary.Load(name);
        foreach (var check in WmiChecks)
        {
            var ask = new FaultPlan();
            await Probes(new ReplayedPc(rec, ask)).MeasureAsync(check, TestContext.Current.CancellationToken);
            foreach (var q in ask.Questions().Distinct())
                foreach (var fault in new[] { Faults.MissingClass, Faults.Empty, Faults.Garbage })
                {
                    var plan = new FaultPlan([new FaultRule { Source = "wmi", Match = q, Fault = fault }]);
                    var results = await Probes(new ReplayedPc(rec, plan)).MeasureAsync(check, TestContext.Current.CancellationToken);
                    AssertSane(results, $"{name} {check} {fault} on {q}");
                }
        }
    }

    /// <summary>A WMI read that never answers is ended by the pass's own time limit and recorded as not measured; the next check still runs.</summary>
    [Fact]
    public async Task A_hang_is_cut_off_and_the_pass_moves_on()
    {
        var rec = RecordingLibrary.Load("sample/sample-laptop");
        var plan = new FaultPlan([new FaultRule { Source = "wmi", Match = "BatteryStaticData", Fault = Faults.Hang }]);
        var probes = new TimedProbes(Probes(new ReplayedPc(rec, plan)), TimeSpan.FromMilliseconds(200));
        var outbox = new MetricsOutbox(Path.Combine(_dir, "outbox.json"), () => DateTimeOffset.UtcNow);
        var schedule = new MetricsSchedule(1, true, MetricsSchedule.DefaultIntervalMinutes, [ModuleSlugs.BatteryPower, ModuleSlugs.DriveHealth]);
        var added = await new ScheduledMetricsPass(probes, outbox, null, "test").RunAsync(schedule, TestContext.Current.CancellationToken);
        Assert.True(added >= 2); // the battery as not measured, then each drive
        Assert.NotEmpty(plan.Hits);
    }

    /// <summary>The pass's three-minute limit, shortened for the test.</summary>
    private sealed class TimedProbes(IMetricsProbes inner, TimeSpan limit) : IMetricsProbes
    {
        public async Task<IReadOnlyList<DiagnosticResult>> MeasureAsync(string checkId, CancellationToken ct)
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(limit);
            return await inner.MeasureAsync(checkId, cts.Token);
        }
    }
}
