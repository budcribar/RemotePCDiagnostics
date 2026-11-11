using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Tests;

/// <summary>#19 Stop the non-default browser running in the background: detection, Local State + Startup Boost policy writes, journal, undo.</summary>
public class BrowserBackgroundTests
{
    private const long Mb = 1L << 20;
    private const string EdgeAutoLaunch = "MicrosoftEdgeAutoLaunch_0A1B2C3D4E5F";
    private const string ChromeAutoLaunch = "GoogleChromeAutoLaunch_9F8E7D6C5B4A";
    private const string EdgeCmd = "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --no-startup-window --win-session-start";
    private const string ChromeCmd = "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --no-startup-window /prefetch:5";
    private static readonly string Boost = RegistryAllowlist.EdgeStartupBoostPolicy.Target;
    private const string EdgeId = "browser-background-edge";
    private const string ChromeId = "browser-background-chrome";

    private sealed class Sys : IMemorySystem
    {
        public BrowserKind? Default = BrowserKind.Chrome;
        public Dictionary<BrowserKind, string?> LocalState = new() { [BrowserKind.Edge] = """{"browser":{"enabled_labs_experiments":[]},"other":1}""" };
        public HashSet<BrowserKind> Running = [BrowserKind.Edge];
        public HashSet<BrowserKind> Window = [];
        public HashSet<BrowserKind> IgnoreLocalStateWrites = [];
        public List<StartupEntry> Startup = [new(EdgeAutoLaunch, EdgeCmd, true)];
        public Dictionary<string, int> Reg = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Ignored = new(StringComparer.OrdinalIgnoreCase);
        public int? BoostUserPolicy;
        public List<string> Calls = [];

        public MemoryReading ReadMemory() => new(16L << 30, 8L << 30);
        public Task<MemorySnapshot> CaptureAsync(IReadOnlyList<ServiceInfo> s, CancellationToken ct) => Task.FromResult(Capture());
        public MemorySnapshot Capture() => new(ReadMemory(),
            Running.Select(k => new AppUsage(BrowserPrefs.ProcessName(k), 6, 240 * Mb, Window.Contains(k))).ToList(),
            Startup: Startup.ToList(), DefaultBrowser: Default,
            BrowserBackground: LocalState.Select(kv =>
            {
                var ok = BrowserBackground.TryReadBackgroundMode(kv.Value, out var pref);
                return new BrowserBackgroundInfo(kv.Key, ok, pref, null,
                    kv.Key == BrowserKind.Edge && Reg.TryGetValue(Boost, out var b) ? b : null, kv.Key == BrowserKind.Edge ? BoostUserPolicy : null);
            }).ToList());
        public Task<ActionOutcome> CloseAppAsync(string p, CancellationToken ct) => Task.FromResult(new ActionOutcome(true, ""));
        public Task<ActionOutcome> ForceCloseAppAsync(string p, CancellationToken ct) { Calls.Add("kill:" + p); return Task.FromResult(new ActionOutcome(true, "")); }
        public Task<ActionOutcome> RunCommandAsync(string f, IReadOnlyList<string> a, CancellationToken ct) => Task.FromResult(new ActionOutcome(true, ""));
        public Dictionary<string, byte[]?> Approved = [];
        public byte[]? GetStartupApproved(string n) => Approved.GetValueOrDefault(n);
        public void SetStartupApproved(string n, byte[]? v) { Calls.Add("approved:" + n); Approved[n] = v; }
        public bool IsBrowserRunning(BrowserKind k) => Running.Contains(k);
        public string? ReadBrowserLocalState(BrowserKind k) => LocalState.GetValueOrDefault(k);
        public void WriteBrowserLocalState(BrowserKind k, string json)
        {
            if (Running.Contains(k)) throw new InvalidOperationException("Browser is running");
            Calls.Add("localstate:" + k);
            if (!IgnoreLocalStateWrites.Contains(k)) LocalState[k] = json;
        }
        public Task<ActionOutcome> EndBrowserBackgroundAsync(BrowserKind k, CancellationToken ct)
        {
            Calls.Add("end:" + k);
            if (Window.Contains(k)) return Task.FromResult(new ActionOutcome(false, "window open"));
            Running.Remove(k);
            return Task.FromResult(new ActionOutcome(true, "ended"));
        }
        public void OpenUri(string uri) { }
        public string GetServiceStartType(string n) => "Automatic";
        public void SetServiceStartType(string n, string t) { }
        public int? ReadDword(RegistrySetting s) => Reg.TryGetValue(s.Target, out var v) ? v : null;
        public void WriteDword(RegistrySetting s, int value) { Calls.Add($"write:{s.Target}={value}"); if (!Ignored.Contains(s.Target)) Reg[s.Target] = value; }
        public void DeleteDword(RegistrySetting s) { Calls.Add("delete:" + s.Target); Reg.Remove(s.Target); }
    }

    private static (Sys, MemoryChangeJournal, MemorySuggestionService) Make(Sys? sys = null)
    {
        var s = sys ?? new Sys();
        var j = new MemoryChangeJournal();
        return (s, j, new MemorySuggestionService(s, session: new SessionContext(SessionMode.Remote), settle: TimeSpan.Zero, journal: j));
    }

    private static IReadOnlyList<MemorySuggestion> Build(Sys sys) => MemorySuggestionEngine.Build(sys.Capture());

    // ---- Local State JSON ----

    [Fact]
    public void LocalState_ReadsAndSetsOnlyBackgroundModeEnabled_KeepsEverythingElse()
    {
        Assert.True(BrowserBackground.TryReadBackgroundMode("""{"other":1}""", out var v) && v is null);
        Assert.True(BrowserBackground.TryReadBackgroundMode("""{"background_mode":{"enabled":true}}""", out v) && v == true);
        Assert.True(BrowserBackground.TryReadBackgroundMode("""{"background_mode":{"enabled":false}}""", out v) && v == false);
        Assert.False(BrowserBackground.TryReadBackgroundMode("""{"background_mode":{"enabled":1}}""", out _)); // not a bool: leave it alone
        Assert.False(BrowserBackground.TryReadBackgroundMode("""{"background_mode":true}""", out _));
        Assert.False(BrowserBackground.TryReadBackgroundMode("not json", out _));
        Assert.False(BrowserBackground.TryReadBackgroundMode(null, out _));

        var off = BrowserBackground.SetBackgroundMode("""{"other":1,"performance_tuning":{"x":2}}""", false)!;
        Assert.True(BrowserBackground.TryReadBackgroundMode(off, out v) && v == false);
        Assert.Contains("\"other\":1", off);
        Assert.Contains("\"performance_tuning\":{\"x\":2}", off);
        // Back to "not set": the key (and the emptied object) go away; a sibling key is kept.
        Assert.Equal("""{"other":1,"performance_tuning":{"x":2}}""", BrowserBackground.SetBackgroundMode(off, null));
        Assert.Equal("""{"background_mode":{"x":1}}""", BrowserBackground.SetBackgroundMode("""{"background_mode":{"enabled":true,"x":1}}""", null));
        Assert.Null(BrowserBackground.SetBackgroundMode("not json", false));
        Assert.Null(BrowserBackground.SetBackgroundMode("""{"background_mode":{"enabled":"yes"}}""", false));
    }

    [Fact]
    public void JournalTargets_OnlyTheTwoBrowsers_AndOnlyTheStartupBoostPolicyIsAllowlisted()
    {
        Assert.Equal("Edge|background_mode.enabled", BrowserBackground.Target(BrowserKind.Edge));
        Assert.Equal(BrowserKind.Chrome, BrowserBackground.ParseTarget("Chrome|background_mode.enabled"));
        Assert.Null(BrowserBackground.ParseTarget("Edge|browser.enabled_labs_experiments"));
        Assert.Null(BrowserBackground.ParseTarget("Firefox|background_mode.enabled"));
        Assert.Null(BrowserBackground.ParseTarget(null));
        Assert.Equal(@"HKLM\SOFTWARE\Policies\Microsoft\Edge|StartupBoostEnabled", Boost);
        Assert.Same(RegistryAllowlist.EdgeStartupBoostPolicy, RegistryAllowlist.Find(Boost.ToLowerInvariant()));
        Assert.Null(RegistryAllowlist.Find(@"HKLM\SOFTWARE\Policies\Microsoft\Edge|BackgroundModeEnabled")); // Local State is used instead
        Assert.Null(RegistryAllowlist.Find(@"HKLM\SOFTWARE\Policies\Google\Chrome|BackgroundModeEnabled"));
        Assert.Null(RegistryAllowlist.Find(@"HKCU\SOFTWARE\Policies\Microsoft\Edge|StartupBoostEnabled"));
    }

    // ---- engine ----

    [Fact]
    public void Offered_ForEdge_WhenChromeIsDefault_AndEdgeRunsWithNoWindow_Ticked()
    {
        var sys = new Sys { Startup = [] };
        var s = Build(sys).Single(x => x.Id == EdgeId);
        Assert.Equal("Stop Microsoft Edge from running in the background", s.Title);
        Assert.Equal(SuggestionKind.Automated, s.Kind);
        Assert.True(s.DefaultOn);
        Assert.Equal(240 * Mb, s.SavingBytes);
        var a = Assert.Single(s.Actions);
        Assert.Equal((MemoryActionType.StopBrowserBackground, "Edge"), (a.Type, a.Target));
        Assert.StartsWith("Chrome is your default browser, but Microsoft Edge keeps running in the background (Startup Boost and background apps)", s.Why);
        var steps = string.Join(" ", s.Steps);
        Assert.Contains("Continue running background extensions and apps when Microsoft Edge is closed", steps);
        Assert.Contains("Startup Boost", steps);
        Assert.Contains("managed by your organization", steps);
        Assert.Contains("never closed", steps);
        Assert.Equal("Undo turns both back on.", s.Steps[^1]);
        Assert.DoesNotContain(Build(sys), x => x.Id == ChromeId);
    }

    [Fact]
    public void Offered_ForChrome_WhenEdgeIsDefault_WithAutoLaunch_NoPolicyText()
    {
        var sys = new Sys
        {
            Default = BrowserKind.Edge, Running = [],
            LocalState = { [BrowserKind.Chrome] = """{"background_mode":{"enabled":true}}""" },
            Startup = [new(ChromeAutoLaunch, ChromeCmd, true), new(EdgeAutoLaunch, EdgeCmd, true)],
        };
        var all = Build(sys);
        var s = all.Single(x => x.Id == ChromeId);
        Assert.Null(s.SavingBytes); // not running right now
        var steps = string.Join(" ", s.Steps);
        Assert.Contains("Continue running background apps when Google Chrome is closed", steps);
        Assert.DoesNotContain("managed by your organization", steps);
        Assert.DoesNotContain("Startup Boost", steps);
        Assert.Equal("Undo turns it back on.", s.Steps[^1]);
        Assert.DoesNotContain(all, x => x.Id == EdgeId); // Edge is the default: never a target
        // Only the non-default browser's own launcher is offered as a startup app; the default browser's is left alone.
        var startup = all.Single(x => x.Id == $"startup-{ChromeAutoLaunch}".ToLowerInvariant());
        Assert.Equal("Stop Chrome from starting in the background with Windows", startup.Title);
        Assert.Equal((MemoryActionType.DisableStartup, ChromeAutoLaunch), (startup.Actions[0].Type, startup.Actions[0].Target));
        Assert.True(startup.DefaultOn);
        Assert.DoesNotContain(all, x => x.Id == $"startup-{EdgeAutoLaunch}".ToLowerInvariant());
    }

    [Fact]
    public void DefaultBrowsersOwnAutoLaunch_NotOfferedByTheGenericStartupRule_EvenWhenHeavy()
    {
        // Chrome is the default and heavy; its auto-launch entry used to qualify as a 150 MB+ startup app.
        var sys = new Sys { Running = [BrowserKind.Chrome], Window = [BrowserKind.Chrome], LocalState = { [BrowserKind.Chrome] = "{}" },
            Startup = [new(ChromeAutoLaunch, ChromeCmd, true)] };
        Assert.DoesNotContain(Build(sys), x => x.Id.StartsWith("startup-", StringComparison.Ordinal));
        // An ordinary "open Chrome at sign-in" entry (no --no-startup-window) is still a normal startup app.
        var normal = new StartupEntry("Chrome", "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\"", true);
        Assert.False(BrowserBackground.IsAutoLaunch(normal));
        Assert.Contains(Build(new Sys { Running = [BrowserKind.Chrome], Window = [BrowserKind.Chrome], Startup = [normal] }), x => x.Id == "startup-chrome");
        // An HKLM entry or a lookalike name for another program isn't the browser's launcher.
        Assert.False(BrowserBackground.IsAutoLaunch(new(EdgeAutoLaunch, EdgeCmd, true, StartupScope.LocalMachine)));
        Assert.False(BrowserBackground.IsAutoLaunch(new(EdgeAutoLaunch, "\"C:\\x\\other.exe\" --no-startup-window", true)));
    }

    [Fact]
    public void NotOffered_WhenDefaultUnknown_NoSignOfBackground_OrNothingToTurnOff()
    {
        Assert.DoesNotContain(Build(new Sys { Default = null }), x => x.Id.StartsWith("browser-background", StringComparison.Ordinal));
        Assert.DoesNotContain(Build(new Sys { Default = null }), x => x.Id.Contains("autolaunch", StringComparison.Ordinal));
        // Edge open with a window and no auto-launch entry: it's in use right now, no sign it runs in the background.
        Assert.DoesNotContain(Build(new Sys { Window = [BrowserKind.Edge], Startup = [] }), x => x.Id == EdgeId);
        // Not installed / Local State unreadable and Startup Boost already off by policy.
        Assert.DoesNotContain(Build(new Sys { LocalState = [] }), x => x.Id == EdgeId);
        var sys = new Sys { LocalState = { [BrowserKind.Edge] = "not json" } };
        sys.Reg[Boost] = 0;
        Assert.DoesNotContain(Build(sys), x => x.Id == EdgeId);
        // Already off in Local State, Startup Boost managed by the organization (HKCU policy).
        Assert.DoesNotContain(Build(new Sys { LocalState = { [BrowserKind.Edge] = """{"background_mode":{"enabled":false}}""" }, BoostUserPolicy = 1 }), x => x.Id == EdgeId);
        // A BackgroundModeEnabled policy controls it (Local State would be ignored) and Startup Boost is already off.
        var managed = new MemorySnapshot(new(16L << 30, 8L << 30), [new("msedge", 3, 100 * Mb)], DefaultBrowser: BrowserKind.Chrome,
            BrowserBackground: [new(BrowserKind.Edge, true, null, BackgroundModePolicy: 1, StartupBoostPolicy: 0)]);
        Assert.False(BrowserBackground.Offer(managed));
    }

    [Fact]
    public void OnlyStartupBoostLeft_CardSaysSo()
    {
        var sys = new Sys { LocalState = { [BrowserKind.Edge] = """{"background_mode":{"enabled":false}}""" } };
        var s = Build(sys).Single(x => x.Id == EdgeId);
        Assert.Contains("(Startup Boost)", s.Why);
        Assert.DoesNotContain(s.Steps, x => x.Contains("Continue running", StringComparison.Ordinal));
        Assert.Equal("Undo turns it back on.", s.Steps[^1]);
    }

    // ---- service: apply, journal, per-item undo ----

    [Fact]
    public async Task Apply_EndsBackgroundEdge_WritesLocalStateAndPolicy_JournalsBoth_UndoPutsBoth()
    {
        var (sys, j, svc) = Make();
        var original = sys.LocalState[BrowserKind.Edge];
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == EdgeId);
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.True(r.Success, r.Message);
        Assert.Contains("background apps off", r.Message);
        Assert.Contains("managed by your organization", r.Message);
        Assert.Contains("background processes were ended", r.Message);
        Assert.Equal(["end:Edge", "localstate:Edge", $"write:{Boost}=0"], sys.Calls);
        Assert.True(BrowserBackground.TryReadBackgroundMode(sys.LocalState[BrowserKind.Edge], out var v) && v == false);
        Assert.Contains("\"other\":1", sys.LocalState[BrowserKind.Edge]);
        Assert.Equal(0, sys.Reg[Boost]);

        Assert.Equal(2, j.All.Count);
        var ls = j.All.Single(c => c.Kind == ChangeKind.BrowserLocalStateValue);
        Assert.Equal("Edge|background_mode.enabled", ls.Target);
        Assert.Null(ls.Previous);
        Assert.Equal("Microsoft Edge no longer runs background apps when it's closed (\"Continue running background apps\" was not set, so on)", ls.Label);
        var pol = j.All.Single(c => c.Kind == ChangeKind.RegistryValue);
        Assert.Equal(Boost, pol.Target);
        Assert.Null(pol.Previous);
        Assert.Equal("Microsoft Edge Startup Boost turned off for everyone on this PC (policy was not set)", pol.Label);
        Assert.All(j.All, c => Assert.False(c.NeedsRestart));
        Assert.DoesNotContain(svc.Suggestions, x => x.Id == EdgeId); // rescanned: nothing left

        sys.Calls.Clear();
        var undone = await svc.UndoAsync(svc.UndoFor(EdgeId)!);
        Assert.True(undone.Success, undone.Message);
        Assert.Contains("Startup Boost policy removed", undone.Message);
        Assert.False(sys.Reg.ContainsKey(Boost));
        Assert.Equal(original, sys.LocalState[BrowserKind.Edge]);
        Assert.Contains("delete:" + Boost, sys.Calls);
        Assert.Empty(j.All);
        Assert.Null(svc.UndoFor(EdgeId));
    }

    [Fact]
    public async Task Apply_ChromeWithBackgroundModeOn_NoPolicyEverWritten_UndoRestoresTrue()
    {
        var sys = new Sys { Default = BrowserKind.Edge, Running = [BrowserKind.Chrome],
            LocalState = { [BrowserKind.Chrome] = """{"background_mode":{"enabled":true},"x":1}""" }, Startup = [] };
        var (_, j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == ChromeId);
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.True(r.Success, r.Message);
        Assert.DoesNotContain(sys.Calls, c => c.StartsWith("write:", StringComparison.Ordinal));
        Assert.Equal("true", Assert.Single(j.All).Previous);
        Assert.Contains("was on", j.All[0].Label);
        sys.Running.Add(BrowserKind.Chrome); // came back in the background: undo ends it again, then writes
        var undone = await svc.UndoAsync(svc.UndoFor(ChromeId)!);
        Assert.True(undone.Success, undone.Message);
        Assert.True(BrowserBackground.TryReadBackgroundMode(sys.LocalState[BrowserKind.Chrome], out var v) && v == true);
        Assert.Empty(j.All);
    }

    [Fact]
    public async Task WindowOpen_NothingChanged_NothingJournaled()
    {
        var (sys, j, svc) = Make();
        await svc.ScanAsync(); // offered because of the auto-launch entry
        sys.Window.Add(BrowserKind.Edge); // the person opened Edge since
        var s = svc.Suggestions.Single(x => x.Id == EdgeId);
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.False(r.Success);
        Assert.Contains("Nothing was changed", r.Message);
        Assert.DoesNotContain(sys.Calls, c => c.StartsWith("localstate:", StringComparison.Ordinal) || c.StartsWith("write:", StringComparison.Ordinal));
        Assert.Empty(j.All);
        Assert.Null(svc.UndoFor(EdgeId));
    }

    [Fact]
    public async Task LocalStateDoesNotStick_Failure_PolicyNotWritten_NothingJournaled()
    {
        var sys = new Sys { IgnoreLocalStateWrites = [BrowserKind.Edge] };
        var (_, j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == EdgeId);
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.False(r.Success);
        Assert.Contains("didn't keep the setting", r.Message);
        Assert.DoesNotContain(sys.Calls, c => c.StartsWith("write:", StringComparison.Ordinal));
        Assert.Empty(j.All);
        Assert.Null(svc.UndoFor(EdgeId));
    }

    [Fact]
    public async Task PolicyDoesNotStick_LocalStateStillApplied_OnlyItJournaled()
    {
        var sys = new Sys();
        sys.Ignored.Add(Boost);
        var (_, j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == EdgeId);
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.True(r.Success, r.Message);
        Assert.Contains("Startup Boost couldn't be turned off", r.Message);
        Assert.Equal(ChangeKind.BrowserLocalStateValue, Assert.Single(j.All).Kind);
        var undo = BrowserBackground.DecodeUndo(svc.UndoFor(EdgeId)!.Previous)!;
        Assert.True(undo.LocalStateChanged);
        Assert.Empty(undo.Registry);
    }

    [Fact]
    public async Task OnlyPolicyDoesNotStick_IsAFailure_NothingJournaled()
    {
        var sys = new Sys { LocalState = { [BrowserKind.Edge] = """{"background_mode":{"enabled":false}}""" } };
        sys.Ignored.Add(Boost);
        sys.Window.Add(BrowserKind.Edge); // a window is fine when only the policy is needed: Edge isn't closed
        var (_, j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == EdgeId);
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.False(r.Success);
        Assert.Contains("Nothing was changed", r.Message);
        Assert.Contains(BrowserKind.Edge, sys.Running);
        Assert.Empty(j.All);
    }

    [Fact]
    public async Task NotTheSecondaryBrowser_Refused()
    {
        var (sys, j, svc) = Make();
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == EdgeId);
        var forged = s with { Actions = [new(MemoryActionType.StopBrowserBackground, "Chrome", "x")] };
        var r = await svc.ApplyAsync(forged, forged.Actions[0]);
        Assert.False(r.Success);
        Assert.Empty(sys.Calls);
        Assert.Empty(j.All);
    }

    // ---- UndoService (Undo all) ----

    [Fact]
    public async Task UndoAll_RestoresLocalStateAndPolicy_RefusesTargetsNotAllowlisted()
    {
        var sys = new Sys { Running = [] };
        sys.LocalState[BrowserKind.Edge] = """{"background_mode":{"enabled":false},"other":1}""";
        sys.Reg[Boost] = 0;
        var j = new MemoryChangeJournal();
        j.Add(ChangeRecord.New(ChangeKind.BrowserLocalStateValue, "Edge|background_mode.enabled", null, "Edge background", "x"));
        j.Add(ChangeRecord.New(ChangeKind.RegistryValue, Boost, null, "Startup Boost", "x"));
        j.Add(ChangeRecord.New(ChangeKind.BrowserLocalStateValue, "Edge|browser.enabled_labs_experiments", "true", "tampered", "x"));
        j.Add(ChangeRecord.New(ChangeKind.BrowserLocalStateValue, "Chrome|background_mode.enabled", "maybe", "tampered", "x"));
        var r = await new UndoService(j, new SystemCommandRunner(new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""))), sys).UndoAllAsync("x");

        Assert.Equal(2, r.Succeeded);
        Assert.Equal(2, r.Failed);
        Assert.False(sys.Reg.ContainsKey(Boost));
        Assert.Equal("""{"other":1}""", sys.LocalState[BrowserKind.Edge]);
        Assert.False(sys.LocalState.ContainsKey(BrowserKind.Chrome));
        Assert.Equal(2, j.All.Count); // refused, left in the journal
        Assert.Equal(UndoSupport.Full, Undoability.Of(j.All[0]));
    }

    [Fact]
    public async Task UndoAll_BrowserWindowOpen_FailsAndKeepsTheRecord()
    {
        var sys = new Sys { Running = [BrowserKind.Edge], Window = [BrowserKind.Edge] };
        sys.LocalState[BrowserKind.Edge] = """{"background_mode":{"enabled":false}}""";
        var j = new MemoryChangeJournal();
        j.Add(ChangeRecord.New(ChangeKind.BrowserLocalStateValue, "Edge|background_mode.enabled", "true", "Edge background", "x"));
        var r = await new UndoService(j, new SystemCommandRunner(new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""))), sys).UndoAllAsync("x");
        Assert.Equal(1, r.Failed);
        Assert.Contains("Close Microsoft Edge first", r.Items[0].Message);
        Assert.Single(j.All);
        Assert.DoesNotContain(sys.Calls, c => c.StartsWith("localstate:", StringComparison.Ordinal));
    }

    // ---- workflow ----

    [Fact]
    public void Workflow_ListsBoth_Ticked_FullUndo_EdgeNeedsAdmin_ChromeDoesNot()
    {
        var fixes = FixCatalog.Build([], Build(new Sys()));
        var edge = fixes.Single(f => f.MemoryAction == MemoryActionType.StopBrowserBackground);
        Assert.True(edge.DefaultOn);
        Assert.True(edge.NeedsAdmin);
        Assert.Equal(UndoSupport.Full, edge.Undo);
        Assert.Equal(EdgeId, edge.SuggestionId);
        var launch = fixes.Single(f => f.MemoryTarget == EdgeAutoLaunch);
        Assert.Equal(MemoryActionType.DisableStartup, launch.MemoryAction);
        Assert.True(launch.DefaultOn);

        var chrome = FixCatalog.Build([], Build(new Sys { Default = BrowserKind.Edge, Running = [BrowserKind.Chrome], LocalState = { [BrowserKind.Chrome] = "{}" } }))
            .Single(f => f.MemoryAction == MemoryActionType.StopBrowserBackground);
        Assert.False(chrome.NeedsAdmin);
        Assert.Contains(MemoryActionType.StopBrowserBackground, FixCatalog.UnattendedMemoryActions);
        Assert.Equal(UndoSupport.Full, Undoability.Of(MemoryActionType.StopBrowserBackground));
        Assert.False(MemoryFeedback.IsDeferred(MemoryActionType.StopBrowserBackground)); // ends the background processes now
    }

    [Fact]
    public async Task EnableMemorySaver_StopBackground_UndoMemorySaver_PreservesBackgroundAndOtherLocalStateKeys()
    {
        var initial = """{"background_mode":{"enabled":true},"performance_tuning":{"high_efficiency_mode":{"state":0}},"profiles":{"last_used":"Default"}}""";
        var sys = new Sys
        {
            Default = BrowserKind.Edge,
            Running = [],
            LocalState = { [BrowserKind.Chrome] = initial },
            Startup = [new(ChromeAutoLaunch, ChromeCmd, true)],
        };
        var (_, j, svc) = Make(sys);

        var memSug = new MemorySuggestion("browser-chrome", "Turn on Chrome Memory Saver", "", null, SuggestionRisk.Low, SuggestionKind.Automated, [],
            [new(MemoryActionType.EnableBrowserMemorySaver, "Chrome", "Turn on")]);
        Assert.True((await svc.ApplyAsync(memSug, memSug.Actions[0])).Success);
        Assert.True(BrowserPrefs.ReadMemorySaver(sys.LocalState[BrowserKind.Chrome], BrowserKind.Chrome));

        await svc.ScanAsync();
        var bgSug = svc.Suggestions.Single(x => x.Id == ChromeId);
        Assert.True((await svc.ApplyAsync(bgSug, bgSug.Actions[0])).Success);
        Assert.True(BrowserBackground.TryReadBackgroundMode(sys.LocalState[BrowserKind.Chrome], out var bgAfterStop) && bgAfterStop == false);

        // Undo Memory Saver only: background_mode.enabled must remain false and profiles must remain intact.
        var memUndo = svc.UndoFor("browser-chrome")!;
        Assert.True((await svc.UndoAsync(memUndo)).Success);
        Assert.False(BrowserPrefs.ReadMemorySaver(sys.LocalState[BrowserKind.Chrome], BrowserKind.Chrome));
        Assert.True(BrowserBackground.TryReadBackgroundMode(sys.LocalState[BrowserKind.Chrome], out var bgAfterUndo) && bgAfterUndo == false);
        Assert.Contains("\"last_used\":\"Default\"", sys.LocalState[BrowserKind.Chrome]);

        // Legacy full-file journal entry in UndoService also patches only high_efficiency_mode without clobbering background_mode.
        sys.LocalState[BrowserKind.Chrome] = """{"background_mode":{"enabled":false},"performance_tuning":{"high_efficiency_mode":{"state":2}},"os_crypt":{"encrypted_key":"NEW"}}""";
        var legacyJournal = new MemoryChangeJournal();
        legacyJournal.Add(ChangeRecord.New(ChangeKind.BrowserSettings, "Chrome", initial, "Memory Saver turned on in Chrome", "x"));
        var undoAll = await new UndoService(legacyJournal, new SystemCommandRunner(new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""))), sys).UndoAllAsync("x");
        Assert.Equal(1, undoAll.Succeeded);
        Assert.False(BrowserPrefs.ReadMemorySaver(sys.LocalState[BrowserKind.Chrome], BrowserKind.Chrome));
        Assert.True(BrowserBackground.TryReadBackgroundMode(sys.LocalState[BrowserKind.Chrome], out var bgAfterLegacy) && bgAfterLegacy == false);
        Assert.Contains("\"encrypted_key\":\"NEW\"", sys.LocalState[BrowserKind.Chrome]);
    }

    [Fact]
    public async Task Undo_PartialFailure_PrunesCompletedStep_SoRetryDoesNotRepeat()
    {
        var (sys, j, svc) = Make();
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == EdgeId);
        Assert.True((await svc.ApplyAsync(s, s.Actions[0])).Success);

        // Edge window opens before undo: policy registry undo succeeds, Local State undo fails.
        sys.Running.Add(BrowserKind.Edge);
        sys.Window.Add(BrowserKind.Edge);
        sys.Calls.Clear();
        var first = await svc.UndoAsync(svc.UndoFor(EdgeId)!);
        Assert.False(first.Success);
        Assert.False(sys.Reg.ContainsKey(Boost));
        Assert.Contains("delete:" + Boost, sys.Calls);
        Assert.Single(j.All, c => c.Kind == ChangeKind.BrowserLocalStateValue);

        // Close window and retry: Startup Boost must not be deleted a second time.
        sys.Running.Clear();
        sys.Window.Clear();
        sys.Calls.Clear();
        var second = await svc.UndoAsync(svc.UndoFor(EdgeId)!);
        Assert.True(second.Success, second.Message);
        Assert.DoesNotContain(sys.Calls, c => c.StartsWith("delete:", StringComparison.Ordinal) || c.StartsWith("write:", StringComparison.Ordinal));
        Assert.Empty(j.All);
        Assert.Null(svc.UndoFor(EdgeId));
    }
}
