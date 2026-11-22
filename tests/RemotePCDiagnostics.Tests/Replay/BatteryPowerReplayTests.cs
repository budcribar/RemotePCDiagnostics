using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Recording;
using RemotePCDiagnostics.Legacy;

namespace RemotePCDiagnostics.Tests.Replay;

/// <summary>BatteryPower replayed from recorded PCs: snapshots, old and new paths agreeing, damaged answers, and known failures.</summary>
public sealed class BatteryPowerReplayTests
{
    public static TheoryData<string> Recordings => RecordingLibrary.Names();

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task MatchesApprovedSnapshot(string name)
    {
        var pc = new ReplayedPc(RecordingLibrary.Load(name));
        var result = await pc.BatteryPower().RefreshAsync(null, TestContext.Current.CancellationToken);
        Assert.Empty(pc.Replay.Misses);
        Snapshot.Match(RecordingLibrary.Folder(name), "BatteryPower", result);
    }

    /// <summary>The WMI path reads the same battery and plan as the osquery and powercfg path it replaces, on the same PC at the same moment.</summary>
    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task WmiAndOsqueryAgree(string name)
    {
        var rec = RecordingLibrary.Load(name);
        var pc = new ReplayedPc(rec);
        Assert.SkipUnless(pc.Has(c => c.Query == BatteryReader.StaticSql) && pc.Has(c => c.Args?.LastOrDefault() == OsqueryBatteryPowerSource.BatterySql),
            "This recording doesn't hold both the WMI and the osquery battery answers.");
        var ct = TestContext.Current.CancellationToken;

        var wmi = await BatteryReader.ReadWmiAsync(pc.Wmi, ct);
        var osq = await new OsqueryBatteryPowerSource(pc.Osquery).ReadBatteriesAsync(ct);
        Assert.NotNull(wmi);
        Assert.NotNull(osq);
        Assert.Equal(osq.Count, wmi.Count);
        for (var i = 0; i < wmi.Count; i++)
        {
            var (w, o) = (wmi[i], osq[i]);
            Assert.Equal(o.Model, w.Model);
            Assert.Equal(o.Manufacturer, w.Manufacturer);
            Assert.Equal(o.Chemistry, w.Chemistry);
            Assert.Equal(o.CycleCount, w.CycleCount);
            // osquery divides by 12 and drops the remainder, so its mWh can be up to 11 lower.
            AssertClose(o.DesignCapacity, w.DesignCapacity);
            AssertClose(o.MaxCapacity, w.MaxCapacity);
            Assert.InRange(Math.Abs((o.HealthPercent ?? -1) - (w.HealthPercent ?? -1)), 0, 1);
        }

        var newReport = (AreaReport)(await pc.BatteryPower().RefreshAsync(null, ct)).Payload!;
        var oldReport = (AreaReport)(await new ReplayedPc(rec).BatteryPowerOld().RefreshAsync(null, ct)).Payload!;
        // Win32_PowerPlan answers only an administrator (the Agent): a recording made without admin rights has no WMI plan to compare.
        if (rec.Machine.Elevated)
        {
            Assert.Equal(Plan(oldReport), Plan(newReport));
            Assert.Equal(oldReport.Status, newReport.Status);
        }

        static void AssertClose(int? expected, int? actual)
        {
            Assert.Equal(expected is null, actual is null);
            if (expected is { } e && actual is { } a) Assert.InRange(a - e, 0, OsqueryBatteryPowerSource.OsqueryAssumedVolts - 1);
        }
        static string Plan(AreaReport r) => r.Cards.Single(c => c.Id == "plan").Headline;
    }

    /// <summary>Every recording, damaged one answer at a time, on both paths: no crash, no nonsense numbers, and no "good" without a reading.</summary>
    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task SurvivesDamagedAnswers(string name)
    {
        var ct = TestContext.Current.CancellationToken;
        var failures = new List<string>();
        var variants = 0;
        var source = RecordingLibrary.Load(name);
        // Only the answers the battery check asks for (a recording holds the other checks' answers too).
        var asked = await ReplayedPc.AskedByAsync(source, ct, pc => pc.BatteryPower(), pc => pc.BatteryPowerOld());
        foreach (var (fault, rec) in FaultInjector.Variants(source, asked))
        {
            foreach (var (path, module) in new[] { ("WMI", new ReplayedPc(rec).BatteryPower()), ("osquery", new ReplayedPc(rec).BatteryPowerOld()) })
            {
                variants++;
                try
                {
                    var r = await module.RefreshAsync(null, ct);
                    failures.AddRange(Problems(r).Select(p => $"{path}, {fault}: {p}"));
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    failures.Add($"{path}, {fault}: threw {ex.GetType().Name}: {ex.Message}");
                }
            }
        }
        Assert.True(variants > 50, $"only {variants} damaged variants");
        Assert.True(failures.Count == 0, $"{failures.Count} of {variants} damaged runs went wrong:\n" + string.Join("\n", failures.Take(40)));
    }

    private static IEnumerable<string> Problems(DiagnosticResult r)
    {
        if (r.Payload is not AreaReport report) { yield return "no report"; yield break; }
        foreach (var card in report.Cards)
        {
            if (string.IsNullOrWhiteSpace(card.Headline) && card.ErrorText is null) yield return $"card {card.Id} has no headline";
            foreach (var row in card.Rows)
                foreach (var v in row.Values)
                    if (v.Contains("NaN") || v.Contains("Infinity") || v.Contains("∞")) yield return $"{card.Id}: \"{v}\"";
        }
        if (report.Cards.FirstOrDefault(c => c.Id == "battery") is { } battery && battery.ErrorText is null)
        {
            string? Row(string label) => battery.Rows.FirstOrDefault(x => x.Values[0] == label)?.Values[1];
            if (battery.Level == AreaLevel.Ok && Row("Estimated battery health") is null or "Not reported")
                yield return "battery called good without a health reading";
            foreach (var label in new[] { "Design capacity", "Full charge capacity", "Cycle count", "Current charge" })
                if (Row(label) is { } v && (v.StartsWith('-') || v.StartsWith("0 ")))
                    yield return $"{label} shows \"{v}\"";
            if (Row("Current charge") is { } charge && int.TryParse(charge.TrimEnd('%'), out var pct) && pct is < 0 or > 100)
                yield return $"current charge {charge}";
        }
        foreach (var m in report.KeyMetrics ?? [])
            if (!double.IsFinite(m.Value) || m.Value < 0) yield return $"metric {m.Id} = {m.Value}";
    }

    // Known failures, made from the sample recording: each has one right answer.

    private static MachineRecording Sample => RecordingLibrary.Load("sample/sample-laptop");

    private static async Task<AreaCard> BatteryCard(MachineRecording rec) =>
        ((AreaReport)(await new ReplayedPc(rec).BatteryPower().RefreshAsync(null, TestContext.Current.CancellationToken)).Payload!)
        .Cards.Single(c => c.Id == "battery");

    [Fact]
    public async Task WornBattery_IsAWarning()
    {
        var card = await BatteryCard(Sample.SetWmi("BatteryFullChargedCapacity", "FullChargedCapacity", 23625));
        Assert.Equal(AreaLevel.Warning, card.Level);
        Assert.Equal("45% battery health", card.Headline);
        Assert.NotNull(card.Note);
    }

    [Fact]
    public async Task PowerSaverPlan_IsAWarningWithTheFix()
    {
        var rec = Sample.SetWmi("Win32_PowerPlan", "ElementName", "Power saver");
        var report = (AreaReport)(await new ReplayedPc(rec).BatteryPower().RefreshAsync(null, TestContext.Current.CancellationToken)).Payload!;
        var plan = report.Cards.Single(c => c.Id == "plan");
        Assert.Equal(AreaLevel.Warning, plan.Level);
        Assert.Contains(plan.Actions!, a => a.Kind == RemediationKind.SetBalancedPowerPlan);
    }

    [Fact]
    public async Task NoBattery_IsADesktop()
    {
        var card = await BatteryCard(Sample.FailWmi("Battery", "Not supported"));
        Assert.Equal("No battery (desktop / AC only)", card.Headline);
        Assert.Equal(AreaLevel.Neutral, card.Level);
    }

    [Fact]
    public async Task UnknownCapacity_IsNotReportedRatherThanGood()
    {
        var card = await BatteryCard(Sample.SetWmi("BatteryStaticData", "DesignedCapacity", 4294967295L));
        Assert.Equal(AreaLevel.Neutral, card.Level);
        Assert.Contains(card.Rows, r => r.Values.SequenceEqual(["Estimated battery health", "Not reported"]));
        Assert.DoesNotContain(card.Rows, r => r.Values[0] == "Design capacity");
    }

    [Fact]
    public void Chemistry_UnpacksFourLetters()
    {
        Assert.Equal("LiP", BatteryReader.Chemistry('L' | ('i' << 8) | ('P' << 16)));
        Assert.Equal("LION", BatteryReader.Chemistry('L' | ('I' << 8) | ('O' << 16) | ((long)'N' << 24)));
        Assert.Equal("", BatteryReader.Chemistry(0));
        Assert.Equal("", BatteryReader.Chemistry(0x01020304));
    }

    [Fact]
    public void Replay_ListsQuestionsTheRecordingDoesNotHold()
    {
        var pc = new ReplayedPc(Sample);
        var r = pc.Wmi.QueryAsync(@"root\cimv2", "SELECT * FROM Win32_Nothing", TestContext.Current.CancellationToken).Result;
        Assert.False(r.Success);
        Assert.Equal([@"wmi root\cimv2 ""SELECT * FROM Win32_Nothing"""], pc.Replay.Misses);
    }
}
