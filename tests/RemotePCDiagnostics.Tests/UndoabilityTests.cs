using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Memory;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Tests;

public class UndoabilityTests
{
    private static ChangeRecord Rec(ChangeKind k, string target, string? prev, int minutesAgo) =>
        new(Guid.NewGuid(), DateTimeOffset.UtcNow.AddMinutes(-minutesAgo), k, target, prev, $"{k} {target}", "Remote technician");

    [Fact]
    public void Classification_PermanentPlaceholderAndFull()
    {
        Assert.Equal(UndoSupport.None, Undoability.Of(RemediationKind.CheckAndInstallWindowsUpdates));
        Assert.Equal(UndoSupport.None, Undoability.Of(RemediationKind.CheckAndInstallDriverUpdates));
        Assert.Equal(UndoSupport.None, Undoability.Of(RemediationKind.CleanTempFiles));
        Assert.Equal(UndoSupport.Full, Undoability.Of(RemediationKind.SetPublicDns));
        Assert.Equal(UndoSupport.NothingToUndo, Undoability.Of(RemediationKind.FlushDnsAndRenewIp));
        Assert.Equal(UndoSupport.Full, Undoability.Of(MemoryActionType.SetServiceManual));
        Assert.Equal("can't be undone", Undoability.Chip(UndoSupport.None));
        Assert.Null(Undoability.Chip(UndoSupport.Full));
    }

    [Fact]
    public void Catalog_LabelsEachFixWithItsUndoSupport()
    {
        AreaAction[] actions = [new(RemediationKind.CheckAndInstallWindowsUpdates, "Install updates"), new(RemediationKind.CleanTempFiles, "Clean"),
            new(RemediationKind.SetBalancedPowerPlan, "Balanced")];
        var report = new AreaReport([new AreaCard("c", "Card", AreaLevel.Warning, "Headline", "", [], [], Actions: actions)], "3 things", DiagnosticStatus.Warning);
        var fixes = FixCatalog.Build([new DiagnosticResult("Programs", DiagnosticStatus.Warning, "", DateTimeOffset.Now, report)], []);
        Assert.Equal(UndoSupport.None, fixes.Single(f => f.Remediation!.Kind == RemediationKind.CheckAndInstallWindowsUpdates).Undo);
        Assert.Equal(UndoSupport.None, fixes.Single(f => f.Remediation!.Kind == RemediationKind.CleanTempFiles).Undo);
        Assert.Equal(UndoSupport.Full, fixes.Single(f => f.Remediation!.Kind == RemediationKind.SetBalancedPowerPlan).Undo);
    }

    [Fact]
    public async Task UndoAll_ReportsPermanentChangesAsLeftAsIs_NotFailures_AndForgetsThem()
    {
        var j = new MemoryChangeJournal();
        j.Add(Rec(ChangeKind.PowerPlan, "", "a1841308-3541-4fab-bc81-f71556f20b4a", 10));
        j.Add(Undoability.Permanent("updates:1", "Windows updates installed", "Remote technician"));
        var undo = new UndoService(j, new SystemCommandRunner(new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""))));
        var r = await undo.UndoAllAsync("x");
        Assert.Equal((1, 0, 1), (r.Succeeded, r.Failed, r.Skipped));
        Assert.Contains("Undid 1 of 1 change", r.Summary);
        Assert.Contains("1 permanent change was left as is", r.Summary);
        Assert.Equal("Windows updates installed", Assert.Single(r.Permanent).Change.Label);
        Assert.Empty(j.All);
    }

    [Fact]
    public async Task UndoAll_OnlyPermanent_SaysNothingCanBeUndone()
    {
        var j = new MemoryChangeJournal();
        j.Add(Undoability.Permanent("updates:1", "Windows updates installed", "x"));
        var r = await new UndoService(j, new SystemCommandRunner(new ScriptedLauncher((_, _) => ScriptedLauncher.Ok("")))).UndoAllAsync("x");
        Assert.Equal(0, r.Failed);
        Assert.StartsWith("Nothing that can be undone; 1 permanent change", r.Summary);
    }

    [Theory]
    [InlineData("""{"Count":2,"Installed":2,"InstallResult":2,"Titles":["KB1","KB2"]}""", true)]
    [InlineData("""{"Count":0,"Installed":0}""", false)]
    public async Task Remediation_JournalsInstalledUpdatesAsPermanent_OnlyWhenSomethingWasInstalled(string updateJson, bool journaled)
    {
        var j = new MemoryChangeJournal();
        var svc = new RemediationService(new SystemCommandRunner(new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(updateJson))),
            new SessionContext(SessionMode.Remote), journal: j);
        Assert.True((await svc.ExecuteAsync(new(RemediationKind.CheckAndInstallWindowsUpdates, "Install updates"))).Success);
        Assert.Equal(journaled, j.All.Any(c => c.Kind == ChangeKind.NotUndoable));
    }

    [Fact]
    public async Task TempCleanup_IsJournaledOnce()
    {
        var j = new MemoryChangeJournal();
        var svc = new RemediationService(new SystemCommandRunner(new ScriptedLauncher((_, _) => ScriptedLauncher.Ok("""{"RemovedFiles":42,"FreedBytes":524288000}"""))),
            new SessionContext(SessionMode.Remote), journal: j);
        Assert.True((await svc.ExecuteAsync(new(RemediationKind.CleanTempFiles, "Clean"))).Success);
        Assert.Equal(ChangeKind.TempFiles, Assert.Single(j.All).Kind);
    }

    [Fact]
    public async Task StorageCleanupCache_ReusesRecentScan_RefreshAndExpiry()
    {
        var now = DateTimeOffset.UtcNow;
        var scans = 0;
        var cache = new StorageCleanupCache(_ => { scans++; return Task.FromResult<IReadOnlyList<StorageCleanupItem>>([new("a", "A", "", scans)]); },
            TimeSpan.FromMinutes(5), () => now);
        Assert.Equal(1, (await cache.GetAsync()).Single().SizeBytes);
        Assert.Equal(1, (await cache.GetAsync()).Single().SizeBytes); // cached
        now = now.AddMinutes(6);
        Assert.Equal(2, (await cache.GetAsync()).Single().SizeBytes); // expired
        Assert.Equal(3, (await cache.GetAsync(refresh: true)).Single().SizeBytes);
        cache.Invalidate();
        Assert.Equal(4, (await cache.GetAsync()).Single().SizeBytes);
        Assert.Equal(4, scans);
    }
}
