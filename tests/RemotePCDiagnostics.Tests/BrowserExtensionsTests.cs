using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Tests;

/// <summary>#22 Block junk / discontinued browser extensions: allowlist, detection parsing, offer rules, apply, journal and undo.</summary>
public class BrowserExtensionsTests
{
    private const string Honey = "bmnlcjabgnpnenekpadlanbbkooimhnj";
    private const string HoneyEdge = "amnbcmdbanbkjhnfoeceemmmdiepnbpp";
    private const string Msn = "lklfbkdigihjaaeamncibechhgalldgl";
    private const string Amazon = "pbjikboenpfhbbejgkoklgkhjpfogcam";
    private const string Other = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // a well-formed ID that isn't allowlisted

    private sealed class Sys : IMemorySystem
    {
        /// <summary>Blocklist values per browser (name → data); a missing browser = key absent.</summary>
        public Dictionary<BrowserKind, Dictionary<string, string>> Lists = [];
        public HashSet<BrowserKind> Unreadable = [];
        /// <summary>Writes "succeed" but don't stick (organization policy overwrites them).</summary>
        public HashSet<BrowserKind> Ignored = [];
        public HashSet<BrowserKind> Denied = [];
        public List<string> Calls = [];
        public List<FoundExtension> Found = [new(BrowserKind.Chrome, Honey, ["Person 1"])];

        public MemoryReading ReadMemory() => new(16L << 30, 8L << 30);
        public Task<MemorySnapshot> CaptureAsync(IReadOnlyList<ServiceInfo> s, CancellationToken ct) =>
            Task.FromResult(new MemorySnapshot(ReadMemory(), [],
                Extensions: new BrowserExtensionsInfo(Found, ReadExtensionBlocklist(BrowserKind.Chrome), ReadExtensionBlocklist(BrowserKind.Edge))));
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

        public IReadOnlyList<BlocklistEntry>? ReadExtensionBlocklist(BrowserKind b) =>
            Unreadable.Contains(b) ? null : Lists.TryGetValue(b, out var l) ? l.Select(kv => new BlocklistEntry(kv.Key, kv.Value)).ToList() : [];

        public void AddExtensionBlock(BrowserKind b, string name, string id)
        {
            Calls.Add($"add:{b}:{name}={id}");
            if (Denied.Contains(b)) throw new UnauthorizedAccessException();
            if (BrowserExtensions.Known(b, id) is null) throw new InvalidOperationException("not allowlisted");
            if (Ignored.Contains(b)) return;
            if (!Lists.TryGetValue(b, out var l)) Lists[b] = l = [];
            if (l.ContainsKey(name)) throw new InvalidOperationException("exists");
            l[name] = id;
        }

        public void RemoveExtensionBlock(BrowserKind b, string name, string id)
        {
            Calls.Add($"remove:{b}:{name}={id}");
            if (BrowserExtensions.Known(b, id) is null) throw new InvalidOperationException("not allowlisted");
            if (Lists.TryGetValue(b, out var l) && l.TryGetValue(name, out var d) && d == id) l.Remove(name);
        }
    }

    private static MemorySnapshot Snap(BrowserExtensionsInfo? info) => new(new(16L << 30, 8L << 30), [], Extensions: info);
    private static BrowserExtensionsInfo Info(IReadOnlyList<FoundExtension> found, IReadOnlyList<BlocklistEntry>? chrome = null, IReadOnlyList<BlocklistEntry>? edge = null) =>
        new(found, chrome ?? [], edge ?? []);
    private static string Sid(BrowserKind b, string id) => BrowserExtensions.SuggestionId(b, id);

    private static (Sys, MemoryChangeJournal, MemorySuggestionService) Make(Sys? sys = null)
    {
        var s = sys ?? new Sys();
        var j = new MemoryChangeJournal();
        return (s, j, new MemorySuggestionService(s, session: new SessionContext(SessionMode.Remote), settle: TimeSpan.Zero, journal: j));
    }

    // ---- allowlist ----

    [Fact]
    public void Allowlist_IsSmall_WellFormed_AndPerBrowser()
    {
        Assert.Equal(4, BrowserExtensions.Allowlist.Count);
        Assert.All(BrowserExtensions.Allowlist, e => Assert.True(BrowserExtensions.IsExtensionId(e.Id), e.Id));
        Assert.Equal(BrowserExtensions.Allowlist.Count, BrowserExtensions.Allowlist.Select(e => e.Id).Distinct().Count());
        Assert.Equal("PayPal Honey", BrowserExtensions.Known(BrowserKind.Chrome, Honey)!.Name);
        Assert.Equal("PayPal Honey", BrowserExtensions.Known(BrowserKind.Edge, Honey)!.Name); // Chrome Web Store install in Edge
        Assert.Equal("PayPal Honey", BrowserExtensions.Known(BrowserKind.Edge, HoneyEdge)!.Name);
        Assert.Null(BrowserExtensions.Known(BrowserKind.Chrome, HoneyEdge)); // Edge Add-ons ID: Edge only
        Assert.Equal("MSN New Tab", BrowserExtensions.Known(BrowserKind.Chrome, Msn)!.Name);
        Assert.Equal("Amazon Assistant", BrowserExtensions.Known(BrowserKind.Edge, Amazon)!.Name);
        Assert.Null(BrowserExtensions.Known(BrowserKind.Chrome, Other));
        Assert.Null(BrowserExtensions.Known(BrowserKind.Chrome, null));
        Assert.Equal(@"SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist", BrowserExtensions.BlocklistKey(BrowserKind.Chrome));
        Assert.Equal(@"SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist", BrowserExtensions.BlocklistKey(BrowserKind.Edge));
    }

    [Theory]
    [InlineData("Chrome|" + Honey, true)]
    [InlineData("Edge|" + HoneyEdge, true)]
    [InlineData("chrome|" + Honey, false)]
    [InlineData("0|" + Honey, false)]
    [InlineData("Firefox|" + Honey, false)]
    [InlineData("Chrome|" + Honey + "x", false)]
    [InlineData("Chrome|ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", false)]
    [InlineData("Chrome", false)]
    [InlineData(null, false)]
    public void Target_Parsing(string? target, bool ok) => Assert.Equal(ok, BrowserExtensions.TryParseTarget(target, out _, out _));

    // ---- blocklist numbering ----

    [Fact]
    public void NextName_AppendsAfterOneToN_AndRefusesGaps()
    {
        Assert.Equal("1", BrowserExtensions.NextName([]));
        Assert.Equal("3", BrowserExtensions.NextName([new("1", Other), new("2", Other)]));
        Assert.Equal("2", BrowserExtensions.NextName([new("1", Other), new("", "x"), new("note", "y")])); // non-numeric names are ignored
        Assert.Null(BrowserExtensions.NextName([new("1", Other), new("3", Other)]));
        Assert.Null(BrowserExtensions.NextName([new("2", Other)]));
        Assert.Equal("2", BrowserExtensions.NextName([new("1", Other), new("02", Other)])); // "02" isn't an entry name browsers read: ignored like text
        Assert.True(BrowserExtensions.IsEntryName("12"));
        Assert.False(BrowserExtensions.IsEntryName("0"));
        Assert.False(BrowserExtensions.IsEntryName("-1"));
        Assert.False(BrowserExtensions.IsEntryName(null));
    }

    [Fact]
    public void IsBlocked_ById_OrWildcard()
    {
        Assert.True(BrowserExtensions.IsBlocked([new("1", " " + Honey.ToUpperInvariant() + " ")], Honey));
        Assert.True(BrowserExtensions.IsBlocked([new("1", "*")], Honey));
        Assert.False(BrowserExtensions.IsBlocked([new("1", Other), new("2", null)], Honey));
    }

    // ---- profile files ----

    [Fact]
    public void ProfileNames_FromLocalState()
    {
        var names = BrowserExtensions.ProfileNames("""{"profile":{"info_cache":{"Default":{"name":"Person 1"},"Profile 2":{"name":"Work"},"Profile 3":{}}}}""");
        Assert.Equal("Person 1", names["Default"]);
        Assert.Equal("Work", names["profile 2"]);
        Assert.False(names.ContainsKey("Profile 3"));
        Assert.Empty(BrowserExtensions.ProfileNames(null));
        Assert.Empty(BrowserExtensions.ProfileNames("not json"));
        Assert.Empty(BrowserExtensions.ProfileNames("""{"profile":[]}"""));
    }

    [Fact]
    public void IdsInPreferences_UnionOfBothFiles_NullWhenNeitherListsExtensions()
    {
        var secure = """{"extensions":{"settings":{"ID":{"state":1}}}}""".Replace("ID", Honey);
        var prefs = """{"extensions":{"settings":{"ID":{}}}}""".Replace("ID", Msn);
        var ids = BrowserExtensions.IdsInPreferences(secure, prefs)!;
        Assert.Contains(Honey, ids);
        Assert.Contains(Msn, ids);
        Assert.Contains(Honey.ToUpperInvariant(), ids);
        Assert.Empty(BrowserExtensions.IdsInPreferences("""{"extensions":{"settings":{}}}""", null)!);
        Assert.Null(BrowserExtensions.IdsInPreferences("""{"extensions":{}}""", "garbage", null));
    }

    // ---- engine ----

    [Fact]
    public void Offered_OnePerExtensionPerBrowser_OptIn_WithManagedNote()
    {
        var found = new List<FoundExtension>
        {
            new(BrowserKind.Chrome, Honey, ["Person 1", "Work"], 21L << 20),
            new(BrowserKind.Chrome, Msn, ["Person 1"]),
            new(BrowserKind.Edge, HoneyEdge, ["Profile 1"]),
            new(BrowserKind.Edge, Amazon, ["Profile 1"]),
        };
        var all = MemorySuggestionEngine.Build(Snap(Info(found)));
        var ext = all.Where(x => x.Id.StartsWith("ext-block-", StringComparison.Ordinal)).ToList();
        Assert.Equal(4, ext.Count);
        Assert.All(ext, s =>
        {
            Assert.False(s.DefaultOn);
            Assert.Equal(SuggestionKind.Automated, s.Kind);
            Assert.Equal(MemoryActionType.BlockBrowserExtension, Assert.Single(s.Actions).Type);
            Assert.Contains("Managed by your organization", string.Join(" ", s.Steps));
            Assert.Contains("can't be turned back on or reinstalled until you undo this", s.Steps[0]);
            Assert.Contains("Undo removes the blocklist entry", s.Steps[^1]);
            Assert.Null(s.SavingBytes);
        });
        var honey = ext.Single(x => x.Id == Sid(BrowserKind.Chrome, Honey));
        Assert.Equal("Turn off PayPal Honey in Chrome", honey.Title);
        Assert.Contains("2 Chrome profiles (Person 1 and Work)", honey.Why);
        Assert.Contains("21 MB on disk", honey.Why);
        Assert.Equal("Chrome|" + Honey, honey.Actions[0].Target);
        Assert.Contains("You lose automatic coupon codes", honey.Steps[1]);
        Assert.Contains("the Chrome profile \"Person 1\"", ext.Single(x => x.Id == Sid(BrowserKind.Chrome, Msn)).Why);
        Assert.Contains("Microsoft Edge", ext.Single(x => x.Id == Sid(BrowserKind.Edge, Amazon)).Title);
    }

    [Fact]
    public void NotOffered_Unknown_AlreadyBlocked_Unreadable_GapList_OrWrongBrowser()
    {
        bool Offered(BrowserExtensionsInfo? i) => MemorySuggestionEngine.Build(Snap(i)).Any(x => x.Id.StartsWith("ext-block-", StringComparison.Ordinal));
        var honey = new FoundExtension(BrowserKind.Chrome, Honey, ["Person 1"]);
        Assert.True(Offered(Info([honey])));
        Assert.False(Offered(null));
        Assert.False(Offered(Info([])));
        Assert.False(Offered(Info([new(BrowserKind.Chrome, Other, ["Person 1"])]))); // not allowlisted
        Assert.False(Offered(Info([new(BrowserKind.Chrome, HoneyEdge, ["Person 1"])]))); // Edge Add-ons ID found in Chrome
        Assert.False(Offered(Info([new(BrowserKind.Chrome, Honey, [])])));
        Assert.False(Offered(Info([honey], chrome: [new("1", Honey)])));
        Assert.False(Offered(Info([honey], chrome: [new("1", "*")])));
        Assert.False(Offered(Info([honey], chrome: [new("1", Other), new("3", Other)]))); // unusual numbering: left alone
        Assert.False(Offered(new BrowserExtensionsInfo([honey], null, [])));
        Assert.True(Offered(new BrowserExtensionsInfo([honey], [], null))); // Edge's list being unreadable doesn't matter for Chrome
        Assert.True(Offered(Info([honey], edge: [new("1", Honey)]))); // blocked in Edge only
    }

    // ---- service: apply, journal, per-item undo ----

    [Fact]
    public async Task Apply_AddsNextEntry_JournalsIt_UndoRemovesOnlyThatEntry()
    {
        var sys = new Sys();
        sys.Lists[BrowserKind.Chrome] = new() { ["1"] = Other, ["2"] = "cccccccccccccccccccccccccccccccc" };
        var (_, j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == Sid(BrowserKind.Chrome, Honey));
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.True(r.Success, r.Message);
        Assert.Contains("can't be turned back on or reinstalled until you undo this", r.Message);
        Assert.Contains("Managed by your organization", r.Message);
        Assert.Contains("Takes effect next launch", r.Message); // deferred: no memory delta claimed
        Assert.Equal(Honey, sys.Lists[BrowserKind.Chrome]["3"]);
        Assert.Equal(3, sys.Lists[BrowserKind.Chrome].Count);
        var c = Assert.Single(j.All);
        Assert.Equal(ChangeKind.ExtensionBlock, c.Kind);
        Assert.Equal("Chrome|" + Honey, c.Target);
        Assert.Equal("3", c.Previous);
        Assert.Equal("PayPal Honey turned off in Chrome for everyone on this PC (blocklist entry 3 added; was not blocked)", c.Label);
        Assert.False(c.NeedsRestart);
        Assert.DoesNotContain(svc.Suggestions, x => x.Id == s.Id); // rescanned: blocked, not offered

        var u = svc.UndoFor(s.Id)!;
        Assert.Equal("3", u.Previous);
        var undone = await svc.UndoAsync(u);
        Assert.True(undone.Success, undone.Message);
        Assert.Contains("allowed in Chrome again", undone.Message);
        Assert.Equal(new Dictionary<string, string> { ["1"] = Other, ["2"] = "cccccccccccccccccccccccccccccccc" }, sys.Lists[BrowserKind.Chrome]);
        Assert.Empty(j.All);
        Assert.Contains(svc.Suggestions, x => x.Id == s.Id); // offered again
    }

    [Fact]
    public async Task Apply_EmptyKey_StartsAtOne_PerBrowser()
    {
        var sys = new Sys { Found = [new(BrowserKind.Edge, HoneyEdge, ["Profile 1"]), new(BrowserKind.Chrome, Msn, ["Default"])] };
        var (_, j, svc) = Make(sys);
        await svc.ScanAsync();
        foreach (var id in new[] { Sid(BrowserKind.Edge, HoneyEdge), Sid(BrowserKind.Chrome, Msn) })
        {
            var s = svc.Suggestions.Single(x => x.Id == id);
            Assert.True((await svc.ApplyAsync(s, s.Actions[0])).Success);
        }
        Assert.Equal(HoneyEdge, sys.Lists[BrowserKind.Edge]["1"]);
        Assert.Equal(Msn, sys.Lists[BrowserKind.Chrome]["1"]);
        Assert.Equal(2, j.All.Count);
        Assert.Equal(2, svc.Undos.Count);
    }

    [Theory]
    [InlineData(false)] // write "works" but doesn't read back (organization policy)
    [InlineData(true)]  // access denied
    public async Task WriteThatDoesNotStick_IsAFailure_NothingJournaled(bool denied)
    {
        var sys = new Sys();
        (denied ? sys.Denied : sys.Ignored).Add(BrowserKind.Chrome);
        var (_, j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == Sid(BrowserKind.Chrome, Honey));
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.False(r.Success);
        Assert.Contains("Nothing was changed", r.Message);
        Assert.Empty(j.All);
        Assert.Null(svc.UndoFor(s.Id));
    }

    [Fact]
    public async Task Apply_RefusesTargetsNotOnTheAllowlist()
    {
        var (sys, j, svc) = Make();
        var forged = new MemorySuggestion("x", "x", "x", null, SuggestionRisk.Low, SuggestionKind.Automated, [],
            [new(MemoryActionType.BlockBrowserExtension, "Chrome|" + Other, "x"), new(MemoryActionType.BlockBrowserExtension, "Chrome|" + HoneyEdge, "x")]);
        foreach (var a in forged.Actions)
        {
            var r = await svc.ApplyAsync(forged, a);
            Assert.False(r.Success);
            Assert.Contains("isn't one this app may block", r.Message);
        }
        Assert.Empty(sys.Calls);
        Assert.Empty(j.All);
    }

    [Fact]
    public async Task PerItemUndo_LeavesTheList_WhenAnEntryWasAddedAfterOurs()
    {
        var (sys, j, svc) = Make();
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == Sid(BrowserKind.Chrome, Honey));
        Assert.True((await svc.ApplyAsync(s, s.Actions[0])).Success);
        sys.Lists[BrowserKind.Chrome]["2"] = Other; // someone else added an entry after ours
        var r = await svc.UndoAsync(svc.UndoFor(s.Id)!);
        Assert.False(r.Success);
        Assert.Contains("never renumbers", r.Message);
        Assert.Equal(2, sys.Lists[BrowserKind.Chrome].Count);
        Assert.Single(j.All); // still journaled for a later retry
        Assert.DoesNotContain(sys.Calls, c => c.StartsWith("remove:", StringComparison.Ordinal));
    }

    // ---- UndoService (Undo all) ----

    [Fact]
    public async Task UndoAll_NewestFirst_RemovesOnlyOurEntries_RefusesOthers()
    {
        var sys = new Sys();
        sys.Lists[BrowserKind.Chrome] = new() { ["1"] = Other, ["2"] = Honey, ["3"] = Msn };
        sys.Lists[BrowserKind.Edge] = new() { ["1"] = Amazon, ["2"] = Other };
        var j = new MemoryChangeJournal();
        var t0 = DateTimeOffset.UtcNow;
        j.Add(new(Guid.NewGuid(), t0, ChangeKind.ExtensionBlock, "Chrome|" + Honey, "2", "PayPal Honey turned off in Chrome", "x"));
        j.Add(new(Guid.NewGuid(), t0.AddSeconds(1), ChangeKind.ExtensionBlock, "Chrome|" + Msn, "3", "MSN New Tab turned off in Chrome", "x"));
        // Edge: the recorded entry "2" now holds another ID, and Amazon is blocked by entry "1", which this app didn't add.
        j.Add(new(Guid.NewGuid(), t0.AddSeconds(2), ChangeKind.ExtensionBlock, "Edge|" + Amazon, "2", "Amazon Assistant turned off in Microsoft Edge", "x"));
        // Tampered journal records: not allowlisted / bad value name.
        j.Add(new(Guid.NewGuid(), t0.AddSeconds(3), ChangeKind.ExtensionBlock, "Chrome|" + Other, "1", "tampered", "x"));
        j.Add(new(Guid.NewGuid(), t0.AddSeconds(4), ChangeKind.ExtensionBlock, "Edge|" + HoneyEdge, "1; rm", "tampered", "x"));
        var r = await new UndoService(j, new SystemCommandRunner(new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""))), sys).UndoAllAsync("x");

        Assert.Equal(2, r.Succeeded);
        Assert.Equal(3, r.Failed);
        Assert.Equal(new Dictionary<string, string> { ["1"] = Other }, sys.Lists[BrowserKind.Chrome]); // 3 then 2 removed; "1" untouched
        Assert.Equal(new Dictionary<string, string> { ["1"] = Amazon, ["2"] = Other }, sys.Lists[BrowserKind.Edge]); // not ours: left as is
        Assert.DoesNotContain(sys.Calls, c => c.Contains(Other) || c.StartsWith("remove:Edge", StringComparison.Ordinal));
        Assert.Equal(3, j.All.Count);
        Assert.Contains("didn't add", r.Items.Single(i => i.Change.Target == "Edge|" + Amazon).Message);
    }

    [Fact]
    public async Task UndoAll_EntryAlreadyGone_CountsAsDone()
    {
        var sys = new Sys();
        var j = new MemoryChangeJournal();
        j.Add(ChangeRecord.New(ChangeKind.ExtensionBlock, "Chrome|" + Honey, "1", "PayPal Honey turned off in Chrome", "x"));
        var r = await new UndoService(j, new SystemCommandRunner(new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""))), sys).UndoAllAsync("x");
        Assert.Equal(1, r.Succeeded);
        Assert.Contains("wasn't blocked", r.Items[0].Message);
        Assert.Empty(j.All);
        Assert.Equal(UndoSupport.Full, Undoability.Of(ChangeRecord.New(ChangeKind.ExtensionBlock, "Chrome|" + Honey, "1", "", "")));
    }

    // ---- workflow ----

    [Fact]
    public void Workflow_ListsEachExtension_Unticked_Admin_FullUndo_Deferred()
    {
        var found = new List<FoundExtension> { new(BrowserKind.Chrome, Honey, ["Person 1"]), new(BrowserKind.Edge, Amazon, ["Profile 1"]) };
        var fixes = FixCatalog.Build([], MemorySuggestionEngine.Build(Snap(Info(found)))).Where(f => f.MemoryAction == MemoryActionType.BlockBrowserExtension).ToList();
        Assert.Equal(2, fixes.Count);
        Assert.All(fixes, f =>
        {
            Assert.False(f.DefaultOn);
            Assert.True(f.NeedsAdmin);
            Assert.Equal(UndoSupport.Full, f.Undo);
        });
        Assert.Contains(fixes, f => f.SuggestionId == Sid(BrowserKind.Chrome, Honey) && f.MemoryTarget == "Chrome|" + Honey);
        Assert.Contains(MemoryActionType.BlockBrowserExtension, FixCatalog.UnattendedMemoryActions);
        Assert.Equal(UndoSupport.Full, Undoability.Of(MemoryActionType.BlockBrowserExtension));
        Assert.True(MemoryFeedback.IsDeferred(MemoryActionType.BlockBrowserExtension));
    }
}
