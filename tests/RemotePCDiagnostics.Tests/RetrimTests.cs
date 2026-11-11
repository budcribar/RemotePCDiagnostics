using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Tests;

public class RetrimTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 3, 8, 0, 0, TimeSpan.FromHours(-7));

    private static DriveHealth Ssd(string letters, string name = "SAMSUNG MZAL8512HDLU-00BL2") =>
        new(name, "S1", "SSD", "NVMe", "Healthy", "OK", 512_000_000_000, 40, 2, 0, 0, 100, letters);

    private static Dictionary<char, RetrimRecord> R(params (char C, int DaysAgo, RetrimSource S)[] x) =>
        x.ToDictionary(e => e.C, e => new RetrimRecord(Now.AddDays(-e.DaysAgo), e.S));

    private static AreaCard Card(DriveHealth d, IReadOnlyDictionary<char, RetrimRecord>? r) => Assert.Single(DriveHealthModule.Build([d], r, Now).Cards);
    private static bool Offers(AreaCard c) => (c.Actions ?? []).Any(a => a.Kind == RemediationKind.OptimizeSsd);
    private static string? Row(AreaCard c, string label) => c.Rows.FirstOrDefault(r => r.Values[0] == label)?.Values[1];

    private sealed class FakeWindows(params (char, DateTimeOffset)[] events) : IWindowsRetrimEvents
    {
        public IReadOnlyList<(char Letter, DateTimeOffset When)> Read(TimeSpan window) => events;
    }

    [Fact]
    public void RecentRetrimByWindows_HidesAction_ShowsRow()
    {
        var c = Card(Ssd("C"), R(('C', 6, RetrimSource.Windows)));
        Assert.False(Offers(c));
        Assert.Equal("6 days ago (by Windows)", Row(c, "Last optimized"));
    }

    [Fact]
    public void OldOrUnknown_KeepsAction()
    {
        var old = Card(Ssd("C"), R(('C', 45, RetrimSource.Windows)));
        Assert.True(Offers(old));
        Assert.Equal("45 days ago (by Windows)", Row(old, "Last optimized"));
        var unknown = Card(Ssd("C"), null);
        Assert.True(Offers(unknown));
        Assert.Equal("Not reported", Row(unknown, "Last optimized"));
        Assert.True(Offers(Card(Ssd("C"), R())));
    }

    [Fact]
    public void MultiLetter_OnlyTargetsVolumesWithoutRecentRetrim()
    {
        var mixed = Card(Ssd("CD"), R(('C', 1, RetrimSource.ThisApp)));
        Assert.True(Offers(mixed));
        Assert.Equal("D", mixed.Actions!.Single(a => a.Kind == RemediationKind.OptimizeSsd).Target);
        Assert.Equal("C: yesterday (by this app); D: Not reported", Row(mixed, "Last optimized"));
        var both = Card(Ssd("CD"), R(('C', 1, RetrimSource.ThisApp), ('D', 2, RetrimSource.Windows)));
        Assert.False(Offers(both));
    }

    [Fact]
    public void HardDrive_NoRowNoAction()
    {
        var hdd = new DriveHealth("WD", "S", "HDD", "SATA", "Healthy", "OK", 1, null, null, 0, 0, 1, "E");
        var c = Card(hdd, null);
        Assert.False(Offers(c));
        Assert.Null(Row(c, "Last optimized"));
    }

    [Fact]
    public async Task History_TakesNewestPerLetter_FromWindowsAndThisApp()
    {
        var app = new RetrimLog();
        app.Record("c", Now.AddDays(-2));
        var h = new RetrimHistory(app, new FakeWindows(('C', Now.AddDays(-10)), ('D', Now.AddDays(-3)), ('c', Now.AddDays(-1))));
        var r = await h.LatestAsync();
        Assert.Equal(new RetrimRecord(Now.AddDays(-1), RetrimSource.Windows), r['C']);
        Assert.Equal(RetrimSource.Windows, r['D'].Source);
        app.Record("C", Now);
        Assert.Equal(new RetrimRecord(Now, RetrimSource.ThisApp), (await h.LatestAsync())['C']);
    }

    [Fact]
    public async Task WindowsSourceFailure_IsIgnored()
    {
        var h = new RetrimHistory(new RetrimLog(), new ThrowingWindows());
        Assert.Empty(await h.LatestAsync());
    }
    private sealed class ThrowingWindows : IWindowsRetrimEvents { public IReadOnlyList<(char, DateTimeOffset)> Read(TimeSpan w) => throw new UnauthorizedAccessException(); }

    [Fact]
    public void RetrimLog_PersistsAcrossInstances()
    {
        var path = Path.Combine(Path.GetTempPath(), $"retrim-{Guid.NewGuid():N}.json");
        try
        {
            new RetrimLog(path).Record("C:", Now);
            Assert.Equal(Now, new RetrimLog(path).All()['C']);

            // Corrupt JSON on disk is ignored cleanly rather than crashing reads or subsequent writes.
            File.WriteAllText(path, "{not-valid-json");
            var recovered = new RetrimLog(path);
            Assert.Empty(recovered.All());
            recovered.Record("D:", Now);
            Assert.Equal(Now, new RetrimLog(path).All()['D']);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task AppliedRetrim_IsSeenAtOnce_SecondPassDoesNotOfferIt_AndWorkflowCatalogExcludesIt()
    {
        var log = new RetrimLog();
        var launcher = new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""));
        var svc = new RemediationService(new SystemCommandRunner(launcher), new SessionContext(SessionMode.Local), retrimLog: log);
        var history = new RetrimHistory(log, new FakeWindows()); // Windows hasn't logged its event yet

        var first = DriveHealthModule.Build([Ssd("C")], await history.LatestAsync(), Now);
        var action = first.Cards[0].Actions!.Single(a => a.Kind == RemediationKind.OptimizeSsd);
        Assert.Contains(FixCatalog.Build([Result(first)], []), f => f.Remediation?.Kind == RemediationKind.OptimizeSsd);

        Assert.True((await svc.ExecuteAsync(action)).Success);

        var second = DriveHealthModule.Build([Ssd("C")], await history.LatestAsync(), DateTimeOffset.Now);
        Assert.False(Offers(second.Cards[0]));
        Assert.Equal("today (by this app)", Row(second.Cards[0], "Last optimized"));
        Assert.DoesNotContain(FixCatalog.Build([Result(second)], []), f => f.Remediation?.Kind == RemediationKind.OptimizeSsd);
    }

    [Fact]
    public async Task FailedRetrim_IsNotRecorded()
    {
        var log = new RetrimLog();
        var svc = new RemediationService(new SystemCommandRunner(new ScriptedLauncher((_, _) => new ProcessResult(1, "", "denied", false))), new SessionContext(SessionMode.Local), retrimLog: log);
        Assert.False((await svc.ExecuteAsync(new(RemediationKind.OptimizeSsd, "Optimize / Retrim SSD", "C", "SSD"))).Success);
        Assert.Empty(log.All());
    }

    private static DiagnosticResult Result(AreaReport rep) => new(DriveHealthModule.ModuleName, rep.Status, rep.Summary, Now, rep);
}
