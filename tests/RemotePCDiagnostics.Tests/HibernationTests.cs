using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Tests;

public class HibernationTests
{
    private const long Gb = 1L << 30;
    private static readonly HibernateInfo FullDesktop = new(true, false, false, (long)(5.67 * Gb), true, false);

    private sealed class Sys(HibernateInfo? hib) : IMemorySystem
    {
        public HibernateInfo? Hib = hib;
        public HibernateInfo? After;
        public bool Fail;
        public List<bool> Calls = [];
        public MemoryReading ReadMemory() => new(16 * Gb, 8 * Gb);
        public Task<MemorySnapshot> CaptureAsync(IReadOnlyList<ServiceInfo> s, CancellationToken ct) => Task.FromResult(new MemorySnapshot(ReadMemory(), [], Hibernate: Hib));
        public Task<ActionOutcome> CloseAppAsync(string p, CancellationToken ct) => Task.FromResult(new ActionOutcome(true, ""));
        public Task<ActionOutcome> ForceCloseAppAsync(string p, CancellationToken ct) => Task.FromResult(new ActionOutcome(true, ""));
        public Task<ActionOutcome> RunCommandAsync(string f, IReadOnlyList<string> a, CancellationToken ct) => Task.FromResult(new ActionOutcome(true, ""));
        public byte[]? GetStartupApproved(string n) => null;
        public void SetStartupApproved(string n, byte[]? v) { }
        public bool IsBrowserRunning(BrowserKind k) => false;
        public string? ReadBrowserLocalState(BrowserKind k) => null;
        public void WriteBrowserLocalState(BrowserKind k, string json) { }
        public void OpenUri(string uri) { }
        public string GetServiceStartType(string n) => "Automatic";
        public void SetServiceStartType(string n, string t) { }
        public HibernateInfo? ReadHibernate() => After;
        public Task<ActionOutcome> SetHibernateTypeAsync(bool reduced, CancellationToken ct)
        {
            Calls.Add(reduced);
            return Task.FromResult(new ActionOutcome(!Fail, Fail ? "powercfg refused" : "ok"));
        }
    }

    private static IReadOnlyList<MemorySuggestion> Build(HibernateInfo? h) => MemorySuggestionEngine.Build(new MemorySnapshot(new(16 * Gb, 8 * Gb), [], Hibernate: h));

    [Theory]
    [InlineData(2, 6L * (1L << 30), false)]  // HiberFileType full
    [InlineData(1, 6L * (1L << 30), true)]   // HiberFileType reduced
    [InlineData(null, 6L * (1L << 30), false)] // missing: ~40% of 16 GB → full
    [InlineData(null, 3L * (1L << 30), true)]  // missing: ~20% → reduced
    public void IsReduced_FromTypeOrSize(int? type, long bytes, bool expected) => Assert.Equal(expected, Hibernation.IsReduced(type, bytes, 16 * Gb));

    [Fact]
    public void IsReduced_UnknownWithoutAnything_AndCustomSize()
    {
        Assert.Null(Hibernation.IsReduced(null, null, 16 * Gb));
        Assert.True(Hibernation.IsCustomSize(60));
        Assert.False(Hibernation.IsCustomSize(40));
        Assert.False(Hibernation.IsCustomSize(null));
    }

    [Fact]
    public void Desktop_OfferedTicked_WithSizes()
    {
        var s = Build(FullDesktop).Single(x => x.Id == "hiberfile-reduced");
        Assert.True(s.DefaultOn);
        Assert.Equal(SuggestionRisk.Low, s.Risk);
        Assert.Equal(MemoryActionType.ReduceHibernateFile, Assert.Single(s.Actions).Type);
        Assert.Contains("5.7 GB", s.Why);
        Assert.DoesNotContain(s.Steps, x => x.Contains("laptop"));
        Assert.Null(s.SavingBytes); // disk, not memory
    }

    [Theory]
    [InlineData(true)]
    [InlineData(null)]
    public void LaptopOrUnknown_OfferedOptIn_WithBatteryWarning(bool? battery)
    {
        var s = Build(FullDesktop with { HasBattery = battery }).Single(x => x.Id == "hiberfile-reduced");
        Assert.False(s.DefaultOn);
        Assert.Contains(s.Steps, x => x.Contains("shuts down instead of hibernating"));
    }

    public static TheoryData<HibernateInfo> NotOffered => new()
    {
        FullDesktop with { Reduced = true },
        FullDesktop with { Reduced = null },
        FullDesktop with { Enabled = false },
        FullDesktop with { CustomSize = true },
        FullDesktop with { FastStartup = false },
        FullDesktop with { FileBytes = null },
    };

    [Theory]
    [MemberData(nameof(NotOffered))]
    public void NotOffered_WhenAlreadyReducedOffCustomNoFastStartupOrUnknown(HibernateInfo h) =>
        Assert.DoesNotContain(Build(h), x => x.Id == "hiberfile-reduced");

    [Fact]
    public async Task Apply_RunsReduced_Journals_PerItemUndoRunsFull()
    {
        var sys = new Sys(FullDesktop) { After = FullDesktop with { Reduced = true, FileBytes = (long)(2.84 * Gb) } };
        var j = new MemoryChangeJournal();
        var svc = new MemorySuggestionService(sys, session: new SessionContext(SessionMode.Remote), settle: TimeSpan.Zero, journal: j);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "hiberfile-reduced");
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.True(r.Success, r.Message);
        Assert.Contains("Freed 2.8 GB", r.Message);
        Assert.Equal([true], sys.Calls);
        var rec = Assert.Single(j.All);
        Assert.Equal((ChangeKind.HiberFileType, "full"), (rec.Kind, rec.Previous));

        Assert.True((await svc.UndoAsync(svc.UndoFor("hiberfile-reduced")!)).Success);
        Assert.Equal([true, false], sys.Calls);
        Assert.Empty(j.All);
    }

    [Fact]
    public async Task Apply_Refused_OrNotReadBack_IsAFailure_NothingJournaled()
    {
        foreach (var sys in new[] { new Sys(FullDesktop) { Fail = true }, new Sys(FullDesktop) { After = FullDesktop } })
        {
            var j = new MemoryChangeJournal();
            var svc = new MemorySuggestionService(sys, settle: TimeSpan.Zero, journal: j);
            await svc.ScanAsync();
            var s = svc.Suggestions.Single(x => x.Id == "hiberfile-reduced");
            Assert.False((await svc.ApplyAsync(s, s.Actions[0])).Success);
            Assert.Empty(j.All);
        }
    }

    [Fact]
    public async Task UndoAll_RunsPowercfgFull()
    {
        var j = new MemoryChangeJournal();
        j.Add(ChangeRecord.New(ChangeKind.HiberFileType, "", "full", "Hibernation file shrunk", "x"));
        var launcher = new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""));
        var r = await new UndoService(j, new SystemCommandRunner(launcher)).UndoAllAsync("x");
        Assert.Equal(1, r.Succeeded);
        var call = Assert.Single(launcher.Calls);
        Assert.EndsWith("powercfg.exe", call.File, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(["/h", "/type", "full"], call.Args);
    }

    [Fact]
    public void Workflow_AdminFix_FullUndo_TickedOnDesktopOnly()
    {
        var desktop = FixCatalog.Build([], Build(FullDesktop)).Single(f => f.MemoryAction == MemoryActionType.ReduceHibernateFile);
        Assert.True(desktop.NeedsAdmin);
        Assert.Equal(UndoSupport.Full, desktop.Undo);
        Assert.True(desktop.DefaultOn);
        Assert.False(FixCatalog.Build([], Build(FullDesktop with { HasBattery = true })).Single(f => f.MemoryAction == MemoryActionType.ReduceHibernateFile).DefaultOn);
    }
}
