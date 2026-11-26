using RemotePCDiagnostics.Agent;
using RemotePCDiagnostics.Core.Alerts;
using RemotePCDiagnostics.Core.Recording;

namespace RemotePCDiagnostics.Tests.Replay;

/// <summary>
/// The Agent's alerts on recorded PCs (recorder v10 on, and the hand-made sample): one look at the recorded events and levels, as the
/// Agent makes after a restart, as is and with each reading broken. A broken reading must not stop the others, raise an alert from
/// nothing, or put a number no PC has in an alert.
/// </summary>
public sealed class AgentAlertsReplayTests : IDisposable
{
    public static TheoryData<string> Recordings => RecordingLibrary.Names();

    private static readonly string[] Nonsense = ["NaN", "Infinity", "-1 GB", "4294967295", "18446744073709551615"];
    private readonly List<string> _dirs = [];

    public void Dispose()
    {
        foreach (var d in _dirs) try { Directory.Delete(d, true); } catch { }
    }

    private async Task<IReadOnlyList<AlertRecord>> ScanAsync(ReplayedPc pc, CancellationToken ct)
    {
        var dir = Path.Combine(Path.GetTempPath(), "rpcd-alerts-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        _dirs.Add(dir);
        var now = pc.Recording.CapturedAt.ToUniversalTime();
        using var alerts = new AgentAlerts(dir, () => "test", () => now, readings: pc.Alerts);
        await alerts.ScanAsync(ct);
        return alerts.Book.Alerts;
    }

    private static string Describe(AlertRecord a) => $"{a.Kind} {a.InstanceId} {a.Level} x{a.Count}";

    private static void AssertSane(IEnumerable<AlertRecord> alerts, string context)
    {
        foreach (var a in alerts)
        {
            Assert.False(string.IsNullOrWhiteSpace(a.Summary), $"{context}: {Describe(a)} has no summary");
            var text = string.Join(" ", [a.Summary, a.InstanceLabel, .. a.Facts.Select(f => f.Value)]);
            foreach (var bad in Nonsense) Assert.DoesNotContain(bad, text, StringComparison.Ordinal);
        }
    }

    /// <summary>The sample's events and levels give the alerts they should.</summary>
    [Fact]
    public async Task Sample_raises_the_alerts_its_events_and_levels_mean()
    {
        var alerts = await ScanAsync(new ReplayedPc(RecordingLibrary.Load("sample/sample-laptop")), TestContext.Current.CancellationToken);
        var kinds = alerts.Select(a => a.Kind).ToHashSet();
        Assert.Contains(AlertKinds.UnexpectedShutdown, kinds);
        Assert.Contains(AlertKinds.UpdateFailed, kinds);
        Assert.Contains(AlertKinds.DiskErrors, kinds);
        var crash = Assert.Single(alerts, a => a.Kind == AlertKinds.AppCrash);
        Assert.Equal(AlertLevel.Warning, crash.Level); // three crashes in a day escalate
        var disk = Assert.Single(alerts, a => a.Kind == AlertKinds.LowDisk);
        Assert.Equal("C:", disk.InstanceId); // D: has plenty free
        Assert.DoesNotContain(AlertKinds.LowMemory, kinds); // 72% and one reading
        Assert.DoesNotContain(AlertKinds.BatteryFailing, kinds); // charging
        AssertSane(alerts, "sample");
    }

    /// <summary>Every recording that holds the readings: one look finishes, reads every recorded answer, and its alerts make sense.</summary>
    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task Scan_reads_everything_and_makes_sense(string name)
    {
        var pc = new ReplayedPc(RecordingLibrary.Load(name));
        Assert.SkipUnless(pc.HasAlerts, "Recorded before recorder v10: no alert readings.");
        var alerts = await ScanAsync(pc, TestContext.Current.CancellationToken);
        Assert.Empty(pc.Replay.Misses.Where(m => m.StartsWith("alerts", StringComparison.Ordinal)));
        AssertSane(alerts, name);
    }

    /// <summary>
    /// Each whole-answer fault on each reading in turn: the look still finishes, the alerts that come from the other readings are all
    /// still raised, and no alert says anything a PC couldn't.
    /// </summary>
    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task A_broken_reading_only_loses_its_own_alerts(string name)
    {
        var rec = RecordingLibrary.Load(name);
        Assert.SkipUnless(new ReplayedPc(rec).HasAlerts, "Recorded before recorder v10: no alert readings.");
        var ct = TestContext.Current.CancellationToken;
        var baseline = (await ScanAsync(new ReplayedPc(rec), ct)).Select(Describe).ToHashSet();

        foreach (var reading in AlertReadings.All)
            foreach (var fault in Faults.WholeAnswer) // the alerts run in the Agent itself, so "disconnected" doesn't apply
            {
                var plan = new FaultPlan([new FaultRule { Source = RecordedCall.AlertsKind, Match = reading, Fault = fault, Ms = 1 }]);
                var alerts = await ScanAsync(new ReplayedPc(rec, plan), ct);
                var context = $"{name}: {fault} on {reading}";
                Assert.True(plan.Hits.Count > 0, $"{context}: the fault never applied");
                AssertSane(alerts, context);
                // Alerts from readings left alone are all still there. The low-disk and low-memory alerts can also come from an event,
                // and an app crash's level from how many were read, so those are left out of the comparison.
                var unaffected = baseline.Where(a => !FromReading(a, reading)).ToList();
                var now = alerts.Select(Describe).ToHashSet();
                Assert.All(unaffected, a => Assert.True(now.Contains(a) || IsCountOrLevelOf(a, now), $"{context}: lost {a}"));
                // A broken reading never raises an alert the recorded answers didn't.
                Assert.All(now, a => Assert.True(baseline.Contains(a) || IsCountOrLevelOf(a, baseline), $"{context}: new {a}"));
            }
    }

    private static bool FromReading(string described, string reading) => reading switch
    {
        AlertReadings.Disks => described.StartsWith(AlertKinds.LowDisk, StringComparison.Ordinal),
        AlertReadings.Memory => described.StartsWith(AlertKinds.LowMemory, StringComparison.Ordinal),
        AlertReadings.Power => described.StartsWith(AlertKinds.BatteryFailing, StringComparison.Ordinal),
        _ => !described.StartsWith(AlertKinds.LowDisk, StringComparison.Ordinal) && !described.StartsWith(AlertKinds.BatteryFailing, StringComparison.Ordinal),
    };

    /// <summary>The same alert (kind and instance) with another count or level: fewer events read can mean fewer repeats.</summary>
    private static bool IsCountOrLevelOf(string described, IReadOnlySet<string> others)
    {
        var parts = described.Split(' ');
        var key = string.Join(' ', parts.Take(parts.Length - 2));
        return others.Any(o => o.StartsWith(key + " ", StringComparison.Ordinal) && o.Split(' ').Length == parts.Length);
    }

    /// <summary>A reading that never answers holds up only the look it is in, which the Agent's own loop cancels.</summary>
    [Fact]
    public async Task A_hung_reading_ends_with_its_cancellation()
    {
        var plan = new FaultPlan([new FaultRule { Source = RecordedCall.AlertsKind, Match = AlertReadings.Disks, Fault = Faults.Hang }]);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        cts.CancelAfter(TimeSpan.FromMilliseconds(300));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ScanAsync(new ReplayedPc(RecordingLibrary.Load("sample/sample-laptop"), plan), cts.Token));
    }

    /// <summary>Garbage in the level rows (text where numbers go) is dropped, not read as zero free space or an empty battery.</summary>
    [Fact]
    public async Task Garbage_levels_raise_nothing()
    {
        var plan = new FaultPlan(
        [
            new FaultRule { Source = RecordedCall.AlertsKind, Match = AlertReadings.Disks, Fault = Faults.Garbage },
            new FaultRule { Source = RecordedCall.AlertsKind, Match = AlertReadings.Memory, Fault = Faults.Garbage },
            new FaultRule { Source = RecordedCall.AlertsKind, Match = AlertReadings.Power, Fault = Faults.Garbage },
        ]);
        var alerts = await ScanAsync(new ReplayedPc(RecordingLibrary.Load("sample/sample-laptop"), plan), TestContext.Current.CancellationToken);
        Assert.DoesNotContain(alerts, a => a.Kind is AlertKinds.LowDisk or AlertKinds.LowMemory or AlertKinds.BatteryFailing);
    }
}
