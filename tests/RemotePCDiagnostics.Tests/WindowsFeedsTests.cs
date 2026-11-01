using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Memory;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Tests;

/// <summary>#16 Widgets and #17 Search highlights: when they're offered, the policy writes, journal and undo.</summary>
public class WindowsFeedsTests
{
    private sealed class Sys : IMemorySystem
    {
        public Dictionary<string, int> Reg = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>Targets whose writes "succeed" but don't stick (UCPD / organization policy).</summary>
        public HashSet<string> Ignored = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Denied = new(StringComparer.OrdinalIgnoreCase);
        public List<string> Calls = [];
        public WindowsFeedsInfo? Feeds = new(22631, WidgetsInstalled: true);
        public List<AppUsage> Apps = [new("WidgetBoard", 1, 43L << 20), new("WidgetService", 1, 14L << 20), new("msedgewebview2", 6, 420L << 20), new("SearchHost", 1, 83L << 20)];
        public MemoryReading ReadMemory() => new(16L << 30, 8L << 30);
        public Task<MemorySnapshot> CaptureAsync(IReadOnlyList<ServiceInfo> s, CancellationToken ct) =>
            Task.FromResult(new MemorySnapshot(ReadMemory(), Apps, Feeds: Feeds));
        public Task<ActionOutcome> CloseAppAsync(string p, CancellationToken ct) => Task.FromResult(new ActionOutcome(true, ""));
        public Task<ActionOutcome> ForceCloseAppAsync(string p, CancellationToken ct) { Calls.Add("kill:" + p); return Task.FromResult(new ActionOutcome(true, "")); }
        public Task<ActionOutcome> RunCommandAsync(string f, IReadOnlyList<string> a, CancellationToken ct) => Task.FromResult(new ActionOutcome(true, ""));
        public byte[]? GetStartupApproved(string n) => null;
        public void SetStartupApproved(string n, byte[]? v) { }
        public bool IsBrowserRunning(BrowserKind k) => false;
        public string? ReadBrowserLocalState(BrowserKind k) => null;
        public void WriteBrowserLocalState(BrowserKind k, string json) { }
        public void OpenUri(string uri) { }
        public string GetServiceStartType(string n) => "Automatic";
        public void SetServiceStartType(string n, string t) { }
        public int? ReadDword(RegistrySetting s) => Reg.TryGetValue(s.Target, out var v) ? v : null;
        public void WriteDword(RegistrySetting s, int value)
        {
            Calls.Add($"write:{s.Target}={value}");
            if (Denied.Contains(s.Target)) throw new UnauthorizedAccessException();
            if (!Ignored.Contains(s.Target)) Reg[s.Target] = value;
        }
        public void DeleteDword(RegistrySetting s) { Calls.Add("delete:" + s.Target); Reg.Remove(s.Target); }
    }

    private static readonly string Widgets = RegistryAllowlist.WidgetsPolicy.Target;
    private static readonly string Policy = RegistryAllowlist.SearchHighlightsPolicy.Target;
    private static readonly string Toggle = RegistryAllowlist.SearchHighlightsToggle.Target;

    private static MemorySnapshot Snap(WindowsFeedsInfo? feeds, params AppUsage[] apps) => new(new(16L << 30, 8L << 30), apps, Feeds: feeds);
    private static readonly AppUsage Board = new("WidgetBoard", 1, 43L << 20);

    private static (Sys, MemoryChangeJournal, MemorySuggestionService) Make(Sys? sys = null)
    {
        var s = sys ?? new Sys();
        var j = new MemoryChangeJournal();
        return (s, j, new MemorySuggestionService(s, session: new SessionContext(SessionMode.Remote), settle: TimeSpan.Zero, journal: j));
    }

    [Fact]
    public void Targets_AreTheDocumentedPolicies()
    {
        Assert.Equal(@"HKLM\SOFTWARE\Policies\Microsoft\Dsh|AllowNewsAndInterests", Widgets);
        Assert.Equal(@"HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search|EnableDynamicContentInWSB", Policy);
        Assert.Equal(@"HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings|IsDynamicSearchBoxEnabled", Toggle);
        Assert.Same(RegistryAllowlist.WidgetsPolicy, RegistryAllowlist.Find(Widgets.ToLowerInvariant()));
        Assert.Null(RegistryAllowlist.Find(@"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced|TaskbarDa")); // UCPD-blocked: never written
        Assert.Null(RegistryAllowlist.Find(@"HKCU\Software\Policies\Microsoft\Windows\Explorer|DisableSearchBoxSuggestions")); // deliberately not used
    }

    // ---- engine: Widgets ----

    [Fact]
    public void Widgets_OfferedOnWindows11_WhenPresentAndPolicyUnset()
    {
        var s = MemorySuggestionEngine.Build(Snap(new(22631, WidgetsInstalled: true), Board)).Single(x => x.Id == "widgets");
        Assert.Equal(SuggestionKind.Automated, s.Kind);
        Assert.Equal(MemoryActionType.DisableWidgets, Assert.Single(s.Actions).Type);
        Assert.Equal(43L << 20, s.SavingBytes);
        Assert.Contains("Takes full effect after a restart", string.Join(" ", s.Steps));
        // Installed but not running (taskbar button not hidden) still counts as present; running but not registered too.
        Assert.Contains(MemorySuggestionEngine.Build(Snap(new(22000, WidgetsInstalled: true))), x => x.Id == "widgets");
        Assert.Contains(MemorySuggestionEngine.Build(Snap(new(22631, WidgetsPolicy: 1), Board)), x => x.Id == "widgets");
    }

    [Theory]
    [InlineData(22631, 0, true, true)]     // policy already 0
    [InlineData(19045, null, true, true)]  // Windows 10: no Widgets fix
    [InlineData(22631, null, false, false)] // not installed, not running
    public void Widgets_NotOffered(int build, int? policy, bool installed, bool running)
    {
        var snap = running ? Snap(new(build, policy, installed), Board) : Snap(new(build, policy, installed));
        Assert.DoesNotContain(MemorySuggestionEngine.Build(snap), x => x.Id == "widgets");
    }

    [Fact]
    public void Widgets_InstalledButButtonHiddenAndNotRunning_NotOffered_UnknownStateKeepsGuidedCard()
    {
        Assert.DoesNotContain(MemorySuggestionEngine.Build(Snap(new(22631, WidgetsInstalled: true, TaskbarWidgetsButton: 0))), x => x.Id == "widgets");
        var guided = MemorySuggestionEngine.Build(Snap(null, new AppUsage("Widgets", 1, 60L << 20))).Single(x => x.Id == "widgets");
        Assert.Equal(SuggestionKind.Guided, guided.Kind);
    }

    // ---- engine: Search highlights ----

    [Theory]
    [InlineData(22631, null, null)]
    [InlineData(19044, null, 1)]
    [InlineData(19045, 1, null)]
    public void Highlights_Offered_WhenOn(int build, int? policy, int? toggle)
    {
        var s = MemorySuggestionEngine.Build(Snap(new(build, HighlightsPolicy: policy, HighlightsToggle: toggle))).Single(x => x.Id == "search-highlights");
        Assert.Equal(SuggestionKind.Automated, s.Kind);
        Assert.Equal(MemoryActionType.DisableSearchHighlights, Assert.Single(s.Actions).Type);
    }

    [Theory]
    [InlineData(22631, 0, null)]  // policy already 0
    [InlineData(22631, null, 0)]  // turned off in Settings
    [InlineData(19043, null, null)] // Windows 10 21H1: before Search highlights
    public void Highlights_NotOffered(int build, int? policy, int? toggle) =>
        Assert.DoesNotContain(MemorySuggestionEngine.Build(Snap(new(build, HighlightsPolicy: policy, HighlightsToggle: toggle))), x => x.Id == "search-highlights");

    // ---- service: apply, journal, per-item undo ----

    [Fact]
    public async Task Widgets_Apply_WritesPolicy_JournalsAbsent_EndsWidgetsOnly_UndoDeletes()
    {
        var (sys, j, svc) = Make();
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "widgets");
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.True(r.Success, r.Message);
        Assert.Equal(0, sys.Reg[Widgets]);
        var rec = Assert.Single(j.All);
        Assert.Equal((ChangeKind.RegistryValue, Widgets, (string?)null, true), (rec.Kind, rec.Target, rec.Previous, rec.NeedsRestart));
        Assert.Equal("Widgets turned off for everyone on this PC (policy was not set)", rec.Label);
        Assert.Equal(["kill:WidgetBoard", "kill:WidgetService"], sys.Calls.Where(c => c.StartsWith("kill:")));
        Assert.DoesNotContain("kill:msedgewebview2", sys.Calls);

        var u = svc.UndoFor("widgets")!;
        Assert.True((await svc.UndoAsync(u)).Success);
        Assert.False(sys.Reg.ContainsKey(Widgets));
        Assert.Contains("delete:" + Widgets, sys.Calls);
        Assert.Empty(j.All);
    }

    [Fact]
    public async Task Widgets_ExistingValue_IsJournaled_AndRestored()
    {
        var sys = new Sys();
        sys.Reg[Widgets] = 1;
        sys.Feeds = sys.Feeds! with { WidgetsPolicy = 1 };
        var (_, j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "widgets");
        Assert.True((await svc.ApplyAsync(s, s.Actions[0])).Success);
        var rec = Assert.Single(j.All);
        Assert.Equal("1", rec.Previous);
        Assert.Contains("(policy was set to 1)", rec.Label);
        Assert.True((await svc.UndoAsync(svc.UndoFor("widgets")!)).Success);
        Assert.Equal(1, sys.Reg[Widgets]);
        Assert.Empty(j.All);
    }

    [Theory]
    [InlineData(false)] // write "works" but reads back unchanged (organization policy / UCPD-style protection)
    [InlineData(true)]  // access denied
    public async Task Widgets_WriteThatDoesNotStick_IsAFailure_NothingJournaled_NothingEnded(bool denied)
    {
        var sys = new Sys();
        (denied ? sys.Denied : sys.Ignored).Add(Widgets);
        var (_, j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "widgets");
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.False(r.Success);
        Assert.Contains("Nothing was changed", r.Message);
        Assert.Empty(j.All);
        Assert.Null(svc.UndoFor("widgets"));
        Assert.DoesNotContain(sys.Calls, c => c.StartsWith("kill:"));
    }

    [Fact]
    public async Task Highlights_Apply_WritesPolicyAndToggle_JournalsBoth_UndoRestoresBoth()
    {
        var sys = new Sys();
        sys.Reg[Toggle] = 1;
        sys.Feeds = sys.Feeds! with { HighlightsToggle = 1 };
        var (_, j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "search-highlights");
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.True(r.Success, r.Message);
        Assert.Equal(0, sys.Reg[Policy]);
        Assert.Equal(0, sys.Reg[Toggle]);
        Assert.Null(j.All.Single(c => c.Target == Policy).Previous);
        Assert.Equal("1", j.All.Single(c => c.Target == Toggle).Previous);
        Assert.All(j.All, c => Assert.Equal(ChangeKind.RegistryValue, c.Kind));
        Assert.Contains(j.All, c => c.Label == "Search highlights turned off for everyone on this PC (policy was not set)");
        Assert.DoesNotContain(sys.Calls, c => c.Contains("DisableSearchBoxSuggestions"));

        Assert.True((await svc.UndoAsync(svc.UndoFor("search-highlights")!)).Success);
        Assert.False(sys.Reg.ContainsKey(Policy));
        Assert.Equal(1, sys.Reg[Toggle]);
        Assert.Empty(j.All);
    }

    [Fact]
    public async Task Highlights_PolicyDoesNotStick_IsAFailure_ToggleNotTouched()
    {
        var sys = new Sys();
        sys.Ignored.Add(Policy);
        var (_, j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "search-highlights");
        Assert.False((await svc.ApplyAsync(s, s.Actions[0])).Success);
        Assert.Empty(j.All);
        Assert.DoesNotContain(sys.Calls, c => c.Contains(Toggle));
    }

    [Fact]
    public async Task Highlights_ToggleDoesNotStick_PolicyStillApplied_OnlyPolicyJournaled()
    {
        var sys = new Sys();
        sys.Denied.Add(Toggle);
        var (_, j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "search-highlights");
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.True(r.Success, r.Message);
        Assert.Contains("couldn't be changed", r.Message);
        Assert.Equal(Policy, Assert.Single(j.All).Target);
    }

    // ---- UndoService (Undo all) ----

    [Fact]
    public async Task UndoAll_RestoresOrDeletes_AndRefusesTargetsNotOnTheAllowlist()
    {
        var sys = new Sys();
        sys.Reg[Widgets] = 0;
        sys.Reg[Toggle] = 0;
        var j = new MemoryChangeJournal();
        j.Add(ChangeRecord.New(ChangeKind.RegistryValue, Widgets, null, "Widgets turned off (policy was not set)", "x", true));
        j.Add(ChangeRecord.New(ChangeKind.RegistryValue, Toggle, "1", "Search highlights setting turned off (was set to 1)", "x", true));
        const string evil = @"HKLM\SYSTEM\CurrentControlSet\Services\WinDefend|Start";
        j.Add(ChangeRecord.New(ChangeKind.RegistryValue, evil, "4", "tampered", "x"));
        var r = await new UndoService(j, new SystemCommandRunner(new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""))), sys).UndoAllAsync("x");

        Assert.Equal(2, r.Succeeded);
        Assert.Equal(1, r.Failed);
        Assert.True(r.NeedsRestart);
        Assert.False(sys.Reg.ContainsKey(Widgets));
        Assert.Equal(1, sys.Reg[Toggle]);
        Assert.DoesNotContain(sys.Calls, c => c.Contains("WinDefend"));
        Assert.Equal(evil, Assert.Single(j.All).Target); // refused, left in the journal
    }

    [Fact]
    public async Task UndoAll_BadPreviousValue_IsNotWritten()
    {
        var sys = new Sys();
        var j = new MemoryChangeJournal();
        j.Add(ChangeRecord.New(ChangeKind.RegistryValue, Widgets, "not-a-number", "x", "x"));
        var r = await new UndoService(j, new SystemCommandRunner(new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""))), sys).UndoAllAsync("x");
        Assert.Equal(1, r.Failed);
        Assert.Empty(sys.Calls);
    }

    // ---- workflow ----

    [Fact]
    public void Workflow_ListsBoth_AsAdminFixesWithFullUndo_DeferredEffect()
    {
        var fixes = FixCatalog.Build([], MemorySuggestionEngine.Build(Snap(new(22631, WidgetsInstalled: true), Board)));
        foreach (var t in new[] { MemoryActionType.DisableWidgets, MemoryActionType.DisableSearchHighlights })
        {
            var fix = fixes.Single(f => f.MemoryAction == t);
            Assert.True(fix.NeedsAdmin);
            Assert.Equal(UndoSupport.Full, fix.Undo);
            Assert.True(MemoryFeedback.IsDeferred(t));
        }
        Assert.DoesNotContain(FixCatalog.Recommendations(MemorySuggestionEngine.Build(Snap(new(22631, WidgetsInstalled: true), Board))), x => x.StartsWith("Turn off Widgets"));
    }
}
