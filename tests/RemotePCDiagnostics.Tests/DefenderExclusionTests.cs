using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests;

/// <summary>
/// The "Stop Defender rescanning code and build folders" fix is gone (builds use a Dev Drive, which Defender's performance mode covers).
/// What stays: reading Defender's state, and undoing exclusions an earlier version journaled.
/// </summary>
public class DefenderExclusionTests
{
    private sealed class Sys : IMemorySystem
    {
        public List<(IReadOnlyList<string> Folders, IReadOnlyList<string> Processes)> Removed = [];
        public MemoryReading ReadMemory() => new(16L << 30, 8L << 30);
        public Task<MemorySnapshot> CaptureAsync(IReadOnlyList<ServiceInfo> s, CancellationToken ct) =>
            Task.FromResult(new MemorySnapshot(ReadMemory(), []));
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
        public Task<bool> RemoveDefenderExclusionsAsync(IReadOnlyList<string> folders, IReadOnlyList<string> processes, CancellationToken ct)
        {
            Removed.Add((folders, processes));
            return Task.FromResult(true);
        }
    }

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
    public void NoDefenderExclusionSuggestion_EvenWhileDefenderIsBusyDuringABuild()
    {
        var snap = new MemorySnapshot(new(16L << 30, 8L << 30),
            [new("MsMpEng", 1, 600L << 20, IsService: true), new("devenv", 2, 900L << 20, true), new("MSBuild", 3, 300L << 20, true)]);
        var suggestions = MemorySuggestionEngine.Build(snap);
        Assert.DoesNotContain(suggestions, x => x.Id == "defender-exclusions");
        Assert.DoesNotContain(suggestions, x => x.Title.Contains("Defender", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task UndoAll_StillRemovesExclusionsAnEarlierVersionJournaled()
    {
        var j = new MemoryChangeJournal();
        j.Add(ChangeRecord.New(ChangeKind.DefenderExclusion, @"path|D:\work", null, "Defender no longer scans D:\\work", "x"));
        j.Add(ChangeRecord.New(ChangeKind.DefenderExclusion, @"process|C:\VS\MSBuild.exe", null, "MSBuild", "x"));
        var launcher = new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""));
        var sys = new Sys();
        var r = await new UndoService(j, new SystemCommandRunner(launcher), sys).UndoAllAsync("x");
        Assert.Equal(2, r.Succeeded);
        Assert.Empty(launcher.Calls); // the Agent removes them, never a script from the app
        Assert.Contains(sys.Removed, x => x.Folders.SequenceEqual([@"D:\work"]) && x.Processes.Count == 0);
        Assert.Contains(sys.Removed, x => x.Processes.SequenceEqual([@"C:\VS\MSBuild.exe"]) && x.Folders.Count == 0);
    }
}
