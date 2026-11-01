using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Memory;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Tests;

public class DefenderExclusionTests
{
    private sealed class Sys(DefenderInfo? defender) : IMemorySystem
    {
        public List<string> Scripts = [];
        public string ReadBack = """{"Paths":["D:\\work","C:\\Users\\bud\\.nuget\\packages"],"Procs":["C:\\VS\\MSBuild.exe"]}""";
        public bool Fail;
        public DefenderInfo? Defender = defender;
        public MemoryReading ReadMemory() => new(16L << 30, 8L << 30);
        public Task<MemorySnapshot> CaptureAsync(IReadOnlyList<ServiceInfo> s, CancellationToken ct) =>
            Task.FromResult(new MemorySnapshot(ReadMemory(), [new("MsMpEng", 1, 300L << 20, IsService: true)], Defender: Defender));
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
        public Task<(bool Ok, string? Output)> RunDefenderScriptAsync(string script, CancellationToken ct)
        {
            Scripts.Add(script);
            return Task.FromResult<(bool, string?)>(Fail ? (false, null) : (true, script.Contains("Add-MpPreference") ? ReadBack : ""));
        }
    }

    private static readonly DefenderInfo Work = new(true, [@"D:\work"], [@"D:\work", @"C:\Users\bud\.nuget\packages"], [@"C:\VS\MSBuild.exe", @"C:\VS\devenv.exe"]);

    [Fact]
    public void Parse_ActiveDefender_PassiveMode_AndNonAdminReads()
    {
        var s = DefenderProbe.Parse("""{"On":"True","Mode":"Normal","Paths":["C:\\src"],"Procs":[]}""")!;
        Assert.True(s.Active);
        Assert.Equal([@"C:\src"], s.Paths);
        Assert.False(DefenderProbe.Parse("""{"On":"True","Mode":"Passive Mode","Paths":[],"Procs":[]}""")!.Active); // another antivirus is active
        Assert.False(DefenderProbe.Parse("""{"On":"False","Mode":"Normal","Paths":[],"Procs":[]}""")!.Active);
        Assert.False(DefenderProbe.Parse("""{"On":"True","Mode":"Normal","Paths":["N/A: Must be an administrator to view exclusions"],"Procs":[]}""")!.ExclusionsReadable);
        Assert.Equal([@"C:\one"], DefenderProbe.Parse("""{"On":"True","Mode":"Normal","Paths":"C:\\one"}""")!.Paths); // single value, not an array
        Assert.Null(DefenderProbe.Parse("junk"));
    }

    [Theory]
    [InlineData(@"C:\src", @"C:\src\app", true)]
    [InlineData(@"C:\src\*", @"C:\src\app", true)]
    [InlineData(@"c:\SRC\", @"C:\src", true)]
    [InlineData(@"C:\src", @"C:\srcother", false)]
    [InlineData(@"C:\*.tmp", @"C:\src", false)]
    public void Covers(string existing, string folder, bool expected) => Assert.Equal(expected, DefenderProbe.Covers(existing, folder));

    [Fact]
    public void Plan_OnlyMissingExclusions_NothingWhenInactiveOrNoProjects()
    {
        var status = new DefenderProbe.Status(true, [@"D:\work"], [@"C:\VS\devenv.exe"], true);
        var plan = DefenderProbe.Plan(status, [@"D:\work\shop", @"E:\code"], @"C:\Users\bud\.nuget\packages", [@"C:\VS\devenv.exe", @"C:\VS\MSBuild.exe"]);
        Assert.Equal([@"E:\code", @"C:\Users\bud\.nuget\packages"], plan.MissingFolders);
        Assert.Equal([@"C:\VS\MSBuild.exe"], plan.MissingProcesses);
        Assert.True(plan.HasWork);
        Assert.False(DefenderProbe.Plan(status with { Active = false }, [@"E:\code"], null, []).HasWork);
        Assert.False(DefenderProbe.Plan(status, [], @"C:\Users\bud\.nuget\packages", [@"C:\VS\MSBuild.exe"]).HasWork); // no code on this PC
    }

    [Fact]
    public void Scripts_QuoteSingleQuotes()
    {
        var add = DefenderProbe.AddScript([@"D:\Bud's code"], [@"C:\VS\MSBuild.exe"]);
        Assert.Contains(@"Add-MpPreference -ExclusionPath @('D:\Bud''s code')", add);
        Assert.Contains(@"Add-MpPreference -ExclusionProcess @('C:\VS\MSBuild.exe')", add);
        Assert.Equal(@"$ErrorActionPreference='Stop';Remove-MpPreference -ExclusionPath @('D:\x');", DefenderProbe.RemoveScript([@"D:\x"], []));
    }

    [Fact]
    public void Engine_OneClickSuggestion_WhenThereIsWork_GuidedFallbackWhenUnknown()
    {
        var snap = new MemorySnapshot(new(16L << 30, 8L << 30), [new("MsMpEng", 1, 300L << 20, IsService: true), new("devenv", 1, 900L << 20, HasWindow: true)], Defender: Work);
        var s = MemorySuggestionEngine.Build(snap).Single(x => x.Id == "defender-exclusions");
        Assert.Equal(SuggestionKind.Automated, s.Kind);
        Assert.Equal(MemoryActionType.AddDefenderExclusions, Assert.Single(s.Actions).Type);
        Assert.Contains(s.Steps, x => x.Contains(@"D:\work"));
        Assert.Contains(s.Steps, x => x.Contains("MSBuild.exe") && x.Contains("devenv.exe"));

        Assert.DoesNotContain(MemorySuggestionEngine.Build(snap with { Defender = Work with { MissingFolders = [], MissingProcesses = [] } }), x => x.Id == "defender-exclusions");
        Assert.Equal(SuggestionKind.Guided, MemorySuggestionEngine.Build(snap with { Defender = null }).Single(x => x.Id == "defender-exclusions").Kind);
    }

    [Fact]
    public async Task Apply_AddsConfirmedExclusions_JournalsEach_PerItemUndoRemovesThem()
    {
        var sys = new Sys(Work);
        var j = new MemoryChangeJournal();
        var svc = new MemorySuggestionService(sys, session: new SessionContext(SessionMode.Remote), settle: TimeSpan.Zero, journal: j);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "defender-exclusions");
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.True(r.Success, r.Message);
        Assert.Contains("1 build tool", r.Message);   // devenv wasn't kept by Defender (read back)
        Assert.Contains("1 weren't kept", r.Message);
        Assert.Equal(["path|D:\\work", "path|C:\\Users\\bud\\.nuget\\packages", "process|C:\\VS\\MSBuild.exe"],
            j.All.Where(c => c.Kind == ChangeKind.DefenderExclusion).Select(c => c.Target));

        var undo = svc.UndoFor("defender-exclusions")!;
        Assert.True((await svc.UndoAsync(undo)).Success);
        Assert.Contains(sys.Scripts, x => x.Contains("Remove-MpPreference -ExclusionPath @('D:\\work','C:\\Users\\bud\\.nuget\\packages')") && x.Contains("-ExclusionProcess @('C:\\VS\\MSBuild.exe')"));
        Assert.DoesNotContain(j.All, c => c.Kind == ChangeKind.DefenderExclusion);
    }

    [Fact]
    public async Task Apply_PolicyKeepsNothing_IsAFailure_NothingJournaled()
    {
        var sys = new Sys(Work) { ReadBack = """{"Paths":[],"Procs":[]}""" };
        var j = new MemoryChangeJournal();
        var svc = new MemorySuggestionService(sys, settle: TimeSpan.Zero, journal: j);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "defender-exclusions");
        Assert.False((await svc.ApplyAsync(s, s.Actions[0])).Success);
        Assert.Empty(j.All);
    }

    [Fact]
    public async Task UndoAll_RemovesEachJournaledExclusion()
    {
        var j = new MemoryChangeJournal();
        j.Add(ChangeRecord.New(ChangeKind.DefenderExclusion, @"path|D:\work", null, "Defender no longer scans D:\\work", "x"));
        j.Add(ChangeRecord.New(ChangeKind.DefenderExclusion, @"process|C:\VS\MSBuild.exe", null, "MSBuild", "x"));
        var launcher = new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""));
        var r = await new UndoService(j, new SystemCommandRunner(launcher)).UndoAllAsync("x");
        Assert.Equal(2, r.Succeeded);
        var scripts = launcher.Calls.Select(c => c.Args[^1]).ToList();
        Assert.Contains(scripts, x => x.Contains(@"Remove-MpPreference -ExclusionPath @('D:\work')"));
        Assert.Contains(scripts, x => x.Contains(@"Remove-MpPreference -ExclusionProcess @('C:\VS\MSBuild.exe')"));
    }

    [Fact]
    public void Workflow_ListsDefenderExclusions_AsAdminFixWithFullUndo()
    {
        var snap = new MemorySnapshot(new(16L << 30, 8L << 30), [new("MsMpEng", 1, 300L << 20, IsService: true)], Defender: Work);
        var fix = FixCatalog.Build([], MemorySuggestionEngine.Build(snap)).Single(f => f.MemoryAction == MemoryActionType.AddDefenderExclusions);
        Assert.True(fix.NeedsAdmin);
        Assert.Equal(UndoSupport.Full, fix.Undo);
    }
}
