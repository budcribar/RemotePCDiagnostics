using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Recording;

namespace RemotePCDiagnostics.Tests.Replay;

/// <summary>
/// A WMI class or namespace a PC doesn't have, on recorded PCs: the checks run as the app runs them (<see cref="DiagnosticsService"/>), and
/// what can't be read because it isn't there says "Not available on this PC", never "Couldn't read", is never an error, and is listed in
/// the report for the shop's connector. Failures that may pass another time (access denied, a timeout) still say they failed.
/// </summary>
public sealed class NotOnThisPcReplayTests
{
    public static TheoryData<string> Recordings => RecordingLibrary.Names();

    private static IDiagnosticModule[] Checks(ReplayedPc pc) =>
    [
        pc.Inventory(), pc.BatteryPower(), pc.DriveHealth(), pc.Services(), pc.DeviceDrivers(), pc.Programs(),
        pc.Network(), pc.SecurityEssentials(), pc.ResourceHogs(), pc.Crashes(), pc.EventLog(), pc.SleepWake(),
    ];

    private static async Task<IReadOnlyList<DiagnosticResult>> RunAllAsync(ReplayedPc pc, CancellationToken ct)
    {
        var checks = Checks(pc);
        var service = new DiagnosticsService(new ResultStore(), checks);
        var results = new List<DiagnosticResult>();
        foreach (var c in checks)
        {
            var r = await service.RunAsync(c.Name, ct: ct);
            if (r.Payload is InstanceResults each) results.AddRange(each.Results);
            else results.Add(r);
        }
        return results;
    }

    private static IEnumerable<AreaCard> Cards(DiagnosticResult r) => r.Payload is AreaReport a ? a.Cards : [];

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task A_missing_class_or_namespace_reads_not_available(string name)
    {
        var ct = TestContext.Current.CancellationToken;
        var rec = RecordingLibrary.Load(name);
        foreach (var fault in new[] { Faults.MissingClass, Faults.MissingNamespace })
        {
            var plan = new FaultPlan([new FaultRule { Source = RecordedCall.WmiKind, Fault = fault }]);
            var results = await RunAllAsync(new ReplayedPc(rec, plan), ct);
            Assert.NotEmpty(plan.Hits);
            var noted = 0;
            foreach (var r in results)
            {
                var context = $"{name}: {fault}: {r.ModuleName}{(r.InstanceLabel is { } l ? " (" + l + ")" : "")}";
                Assert.True(r.Status != DiagnosticStatus.Error, $"{context}: Error: {r.Message}; cards: "
                    + string.Join(" | ", Cards(r).Where(c => c.Level == AreaLevel.Error).Select(c => $"{c.Title}: {c.ErrorText ?? c.Headline}"))
                    + $"; noted: {(r.Payload as AreaReport)?.NotAvailable?.Count}");
                foreach (var card in Cards(r).Where(c => c.ErrorText is not null))
                {
                    Assert.Equal(NotOnThisPc.Text, card.ErrorText);
                    Assert.NotEqual(AreaLevel.Error, card.Level);
                }
                if (r.Payload is AreaReport { NotAvailable: { Count: > 0 } missing } report)
                {
                    noted++;
                    Assert.All(missing, m => Assert.True(NotOnThisPc.IsMissing(m.Error), $"{context}: {m.Error}"));
                    // What the page hands the connector lists them too.
                    Assert.Contains("\"notAvailable\"", AreaReportExport.ToJson(report));
                    if (report.NotOnThisPc)
                    {
                        Assert.Equal(NotOnThisPc.Text, r.Message);
                        Assert.Equal("Skipped", ResultEventLogger.Outcome(r));
                    }
                }
            }
            Assert.True(noted > 0, $"{name}: {fault}: no check listed what was missing");
        }
    }

    /// <summary>A failure that may pass another time is not "not available": the checks still say they couldn't read it.</summary>
    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task Access_denied_is_not_not_available(string name)
    {
        var plan = new FaultPlan([new FaultRule { Source = RecordedCall.WmiKind, Fault = Faults.AccessDenied }]);
        var results = await RunAllAsync(new ReplayedPc(RecordingLibrary.Load(name), plan), TestContext.Current.CancellationToken);
        Assert.NotEmpty(plan.Hits);
        Assert.DoesNotContain(results, r => r.Message == NotOnThisPc.Text || Cards(r).Any(c => c.ErrorText == NotOnThisPc.Text)
            || r.Payload is AreaReport { NotAvailable: not null });
    }

    /// <summary>One class missing among answers that work: only what needed it changes, and the check keeps its own verdict.</summary>
    [Fact]
    public void Apply_keeps_what_was_read()
    {
        using var answers = WmiAnswers.Begin();
        WmiAnswers.Note(WmiQueryResult.Failed(@"root\wmi", "select * from BatteryStaticData", "InvalidClass (0x80041010): Invalid class"));
        var report = new AreaReport(
        [
            new AreaCard("plan", "Power plan", AreaLevel.Ok, "Balanced", "", [], []),
            AreaCard.Failed("battery", "Battery", "Couldn't read the battery."),
        ], "Balanced plan", DiagnosticStatus.Error);
        var r = NotOnThisPc.Apply(new DiagnosticResult("BatteryPower", DiagnosticStatus.Error, "Balanced plan", DateTimeOffset.Now, report), answers);
        var after = Assert.IsType<AreaReport>(r.Payload);
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        Assert.False(after.NotOnThisPc);
        Assert.Equal(NotOnThisPc.Text, after.Cards[1].ErrorText);
        Assert.Equal("Balanced", after.Cards[0].Headline);
        Assert.Single(after.NotAvailable!);
    }

    [Fact]
    public void Nothing_noted_outside_a_run()
    {
        WmiAnswers.Note(WmiQueryResult.Failed("root", "q", "InvalidClass (0x80041010)")); // no run: ignored, no throw
        using var answers = WmiAnswers.Begin();
        Assert.Empty(answers.Missing);
    }
}
