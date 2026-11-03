using System.Text.Json;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Memory;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests;

/// <summary>
/// Findings from the apply-then-undo run on a Windows 11 26H2 laptop: UCPD blocking the Widgets policy, empty keys left by undo,
/// DelayedAutostart / hibernation values added by undo, and result wording.
/// </summary>
public class TestFindingsFixesTests
{
    private const long Gb = 1L << 30;

    /// <summary>A registry with real keys: writes create every missing key in the path (like CreateSubKey), keys can be empty.</summary>
    private sealed class Sys : IMemorySystem
    {
        public HashSet<string> Keys = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, int> Dwords = new(StringComparer.OrdinalIgnoreCase);       // "HKLM\Key|Name"
        public Dictionary<string, string> Strings = new(StringComparer.OrdinalIgnoreCase);   // blocklist entries, same form
        public HashSet<string> DenyWrite = new(StringComparer.OrdinalIgnoreCase);            // targets: the key is created, then SetValue is denied
        public bool DenyKeyDelete;
        public List<string> Deleted = [];
        public MemorySnapshot? Snap;
        public HibernateInfo? HibAfter;
        public Dictionary<string, int> Power = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> StartTypes = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, int> Delayed = new(StringComparer.OrdinalIgnoreCase);
        public List<string> Calls = [];
        public string? DefenderReadBack;

        public Sys(params string[] keys) { foreach (var k in keys) AddKey(k); }

        private static string P(RegistryRoot r) => r == RegistryRoot.LocalMachine ? "HKLM" : "HKCU";
        public void AddKey(string full)
        {
            var i = full.IndexOf('\\');
            var root = full[..i];
            foreach (var k in RegistryKeyCleanup.Chain(full[(i + 1)..])) Keys.Add(root + "\\" + k);
        }
        public bool Has(string full) => Keys.Contains(full);

        public MemoryReading ReadMemory() => new(16 * Gb, 8 * Gb);
        public Task<MemorySnapshot> CaptureAsync(IReadOnlyList<ServiceInfo> s, CancellationToken ct) => Task.FromResult(Snap ?? new MemorySnapshot(ReadMemory(), []));
        public Task<ActionOutcome> CloseAppAsync(string p, CancellationToken ct) => Task.FromResult(new ActionOutcome(true, ""));
        public Task<ActionOutcome> ForceCloseAppAsync(string p, CancellationToken ct) => Task.FromResult(new ActionOutcome(true, ""));
        public Task<ActionOutcome> RunCommandAsync(string f, IReadOnlyList<string> a, CancellationToken ct) => Task.FromResult(new ActionOutcome(true, ""));
        public byte[]? GetStartupApproved(string n) => null;
        public void SetStartupApproved(string n, byte[]? v) { }
        public bool IsBrowserRunning(BrowserKind k) => false;
        public string? ReadBrowserLocalState(BrowserKind k) => null;
        public void WriteBrowserLocalState(BrowserKind k, string json) { }
        public void OpenUri(string uri) { }

        // ---- registry ----
        public int? ReadDword(RegistrySetting s) => Dwords.TryGetValue(s.Target, out var v) ? v : null;
        public void WriteDword(RegistrySetting s, int value)
        {
            AddKey($"{P(s.Root)}\\{s.Key}");
            if (DenyWrite.Contains(s.Target)) throw new UnauthorizedAccessException("UCPD");
            Dwords[s.Target] = value;
        }
        public void DeleteDword(RegistrySetting s) => Dwords.Remove(s.Target);
        public bool RegistryKeyExists(RegistryRoot root, string key) => Keys.Contains($"{P(root)}\\{key}");
        public bool DeleteRegistryKeyIfEmpty(RegistryRoot root, string key)
        {
            if (!RegistryKeyCleanup.IsCleanupKey(root, key)) return false;
            var full = $"{P(root)}\\{key}";
            if (!Keys.Contains(full)) return true;
            if (Keys.Any(k => k.StartsWith(full + "\\", StringComparison.OrdinalIgnoreCase))
                || Dwords.Keys.Concat(Strings.Keys).Any(t => t.StartsWith(full + "|", StringComparison.OrdinalIgnoreCase))) return false;
            if (DenyKeyDelete) throw new UnauthorizedAccessException("denied");
            Keys.Remove(full);
            Deleted.Add(full);
            return true;
        }

        // ---- extension blocklist ----
        private static string Bl(BrowserKind b) => "HKLM\\" + BrowserExtensions.BlocklistKey(b);
        public IReadOnlyList<BlocklistEntry>? ReadExtensionBlocklist(BrowserKind b) =>
            Strings.Where(e => e.Key.StartsWith(Bl(b) + "|", StringComparison.OrdinalIgnoreCase)).Select(e => new BlocklistEntry(e.Key[(Bl(b).Length + 1)..], e.Value)).ToList();
        public void AddExtensionBlock(BrowserKind b, string name, string id) { AddKey(Bl(b)); Strings[$"{Bl(b)}|{name}"] = id; }
        public void RemoveExtensionBlock(BrowserKind b, string name, string id) => Strings.Remove($"{Bl(b)}|{name}");

        // ---- services (SetServiceStartType acts like the old Host: "Automatic" writes DelayedAutostart = 0) ----
        public string GetServiceStartType(string n) => StartTypes.GetValueOrDefault(n, "Automatic");
        public void SetServiceStartType(string n, string t)
        {
            Calls.Add($"start-type:{n}={t}");
            StartTypes[n] = t;
            if (t == "Automatic") Delayed[n] = 0; else if (t == "AutomaticDelayed") Delayed[n] = 1;
        }
        public (bool Known, int? Value) ReadServiceValue(string service, string name) => (true, Delayed.TryGetValue(service, out var v) ? (int?)v : null);
        public void RestoreServiceValue(string service, string name, int? value)
        {
            Calls.Add($"delayed:{service}={(value is { } v ? v.ToString() : "deleted")}");
            if (value is { } x) Delayed[service] = x; else Delayed.Remove(service);
        }

        // ---- hibernation (powercfg /h /type writes both values) ----
        public HibernateInfo? ReadHibernate() => HibAfter;
        public Task<ActionOutcome> SetHibernateTypeAsync(bool reduced, CancellationToken ct)
        {
            Power["HiberFileType"] = reduced ? 1 : 2;
            Power["HibernateEnabled"] = 1;
            return Task.FromResult(new ActionOutcome(true, "ok"));
        }
        public IReadOnlyDictionary<string, int?>? ReadHibernateValues() => Hibernation.TrackedValues.ToDictionary(n => n, n => Power.TryGetValue(n, out var v) ? v : (int?)null);
        public void DeleteHibernateValue(string name) { Calls.Add("hib-delete:" + name); Power.Remove(name); }

        public Task<(bool Ok, string? Output)> RunDefenderScriptAsync(string script, CancellationToken ct) =>
            Task.FromResult<(bool, string?)>((true, script.Contains("Add-MpPreference") ? DefenderReadBack : ""));
    }

    private static (Sys, MemoryChangeJournal, MemorySuggestionService) Make(Sys sys)
    {
        var j = new MemoryChangeJournal();
        return (sys, j, new MemorySuggestionService(sys, session: new SessionContext(SessionMode.Remote), settle: TimeSpan.Zero, journal: j));
    }

    private static UndoService Undo(MemoryChangeJournal j, Sys sys, ScriptedLauncher? launcher = null) =>
        new(j, new SystemCommandRunner(launcher ?? new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""))), sys);

    private static MemorySnapshot Feeds(WindowsFeedsInfo f) => new(new(16 * Gb, 8 * Gb), [new("WidgetBoard", 1, 43L << 20)], Feeds: f);

    // =========================================================================================
    // #1 Widgets: UCPD blocks the policy
    // =========================================================================================

    [Theory]
    [InlineData(null, null, false)]  // no UCPD service (older Windows)
    [InlineData(1, true, true)]      // UCPD running: blocked
    [InlineData(4, true, true)]      // just disabled but still loaded until a restart: still blocked
    [InlineData(1, false, false)]    // installed but not running
    [InlineData(4, false, false)]    // disabled
    [InlineData(1, null, true)]      // state unknown, enabled: assume blocked (don't offer)
    [InlineData(4, null, false)]     // state unknown, disabled
    public void Ucpd_BlocksTheWidgetsPolicy_WhenRunning(int? start, bool? running, bool blocked) =>
        Assert.Equal(blocked, WindowsFeeds.PolicyBlockedByUcpd(start, running));

    [Fact]
    public void Widgets_NotOffered_WhenThePolicyIsBlocked()
    {
        var open = new WindowsFeedsInfo(26300, WidgetsInstalled: true);
        Assert.True(WindowsFeeds.OfferWidgets(Feeds(open)));
        Assert.Contains(MemorySuggestionEngine.Build(Feeds(open)), x => x.Id == "widgets");
        var blocked = open with { WidgetsPolicyBlocked = true };
        Assert.False(WindowsFeeds.OfferWidgets(Feeds(blocked)));
        Assert.DoesNotContain(MemorySuggestionEngine.Build(Feeds(blocked)), x => x.Id == "widgets");
        Assert.DoesNotContain(RemotePCDiagnostics.Core.Workflow.FixCatalog.Build([], MemorySuggestionEngine.Build(Feeds(blocked))),
            f => f.MemoryAction == MemoryActionType.DisableWidgets);
    }

    [Fact]
    public async Task Widgets_DeniedWrite_JournalsNothing_AndRemovesTheKeyItCreated()
    {
        var sys = new Sys(@"HKLM\SOFTWARE\Policies\Microsoft") { Snap = Feeds(new(26300, WidgetsInstalled: true)) };
        sys.DenyWrite.Add(RegistryAllowlist.WidgetsPolicy.Target);
        var (_, j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "widgets");
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.False(r.Success);
        Assert.Empty(j.All);
        Assert.Empty(svc.Undos);
        Assert.False(sys.Has(@"HKLM\SOFTWARE\Policies\Microsoft\Dsh")); // the key CreateSubKey made is gone again
        Assert.True(sys.Has(@"HKLM\SOFTWARE\Policies\Microsoft"));      // existed before: kept
    }

    [Fact]
    public async Task Widgets_DeniedWrite_KeyDeleteAlsoDenied_DoesNotThrow()
    {
        var sys = new Sys(@"HKLM\SOFTWARE\Policies\Microsoft") { Snap = Feeds(new(26300, WidgetsInstalled: true)), DenyKeyDelete = true };
        sys.DenyWrite.Add(RegistryAllowlist.WidgetsPolicy.Target);
        var (_, j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "widgets");
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.False(r.Success);
        Assert.Empty(j.All);
    }

    [Fact]
    public async Task Widgets_ClickFromAnOlderReview_RefusedWhenBlocked()
    {
        var sys = new Sys(@"HKLM\SOFTWARE\Policies\Microsoft") { Snap = Feeds(new(26300, WidgetsInstalled: true)) };
        var (_, j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "widgets");
        sys.Snap = Feeds(new(26300, WidgetsInstalled: true, WidgetsPolicyBlocked: true));
        await svc.ScanAsync();
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.False(r.Success);
        Assert.Contains("blocks the Widgets policy", r.Message);
        Assert.Empty(sys.Dwords);
        Assert.Empty(j.All);
    }

    // =========================================================================================
    // #2 Keys the app created are removed again on undo
    // =========================================================================================

    [Fact]
    public void TopmostMissing_RecordsTheFirstKeyThatDidntExist()
    {
        var existing = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Software", "Software\\Policies", "Software\\Policies\\Microsoft" };
        Assert.Equal(@"Software\Policies\Microsoft\Office",
            RegistryKeyCleanup.TopmostMissing(RegistryAllowlist.OfficeOptionalConnectedExperiences.Key, existing.Contains));
        existing.Add(@"Software\Policies\Microsoft\Office\16.0\Common\Privacy");
        Assert.Null(RegistryKeyCleanup.TopmostMissing(RegistryAllowlist.OfficeOptionalConnectedExperiences.Key, existing.Contains)); // already there: nothing to record
        Assert.Equal(@"SOFTWARE\Policies", RegistryKeyCleanup.TopmostMissing(@"SOFTWARE\Policies\Google\Chrome", _ => false)); // never a hive's top-level key
    }

    [Fact]
    public void DeleteOrder_DeepestFirst_OnlyWithinTheValuesOwnPath()
    {
        Assert.Equal([@"SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist", @"SOFTWARE\Policies\Google\Chrome", @"SOFTWARE\Policies\Google"],
            RegistryKeyCleanup.DeleteOrder(@"SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist", @"SOFTWARE\Policies\Google"));
        Assert.Equal([@"SOFTWARE\Policies\Microsoft\Windows\Windows Search"],
            RegistryKeyCleanup.DeleteOrder(@"SOFTWARE\Policies\Microsoft\Windows\Windows Search", @"software\policies\microsoft\windows\windows search"));
        Assert.Empty(RegistryKeyCleanup.DeleteOrder(@"SOFTWARE\Policies\Google\Chrome", null));
        Assert.Empty(RegistryKeyCleanup.DeleteOrder(@"SOFTWARE\Policies\Google\Chrome", @"SOFTWARE\Policies\Microsoft")); // not an ancestor (edited journal)
        Assert.Empty(RegistryKeyCleanup.DeleteOrder(@"SOFTWARE\Policies\Google\Chrome", "SOFTWARE"));                   // too shallow
    }

    [Fact]
    public void IsCleanupKey_OnlyAllowlistedKeysAndTheirAncestors()
    {
        Assert.True(RegistryKeyCleanup.IsCleanupKey(RegistryRoot.LocalMachine, @"SOFTWARE\Policies\Google"));
        Assert.True(RegistryKeyCleanup.IsCleanupKey(RegistryRoot.LocalMachine, @"SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist"));
        Assert.True(RegistryKeyCleanup.IsCleanupKey(RegistryRoot.CurrentUser, @"Software\Policies\Microsoft\Office\16.0\Common\Privacy"));
        Assert.True(RegistryKeyCleanup.IsCleanupKey(RegistryRoot.CurrentUser, @"Software\Microsoft\Office\16.0\PowerPoint\Options"));
        Assert.False(RegistryKeyCleanup.IsCleanupKey(RegistryRoot.CurrentUser, @"Software\Policies\Google")); // Chrome's policy is HKLM only
        Assert.False(RegistryKeyCleanup.IsCleanupKey(RegistryRoot.LocalMachine, "SOFTWARE"));
        Assert.False(RegistryKeyCleanup.IsCleanupKey(RegistryRoot.LocalMachine, @"SOFTWARE\Policies\Mozilla"));
        Assert.False(RegistryKeyCleanup.IsCleanupKey(RegistryRoot.LocalMachine, @"SOFTWARE\Policies\Google\Chrome\ExtensionInstallAllowlist"));
    }

    [Fact]
    public void Remove_KeepsKeysThatStillHoldSomething()
    {
        var sys = new Sys(@"HKCU\Software\Policies\Microsoft\Office\16.0\Common\Privacy", @"HKCU\Software\Policies\Microsoft\Office\16.0\Common\Roaming");
        var deleted = RegistryKeyCleanup.Remove(sys, RegistryRoot.CurrentUser, RegistryAllowlist.OfficeOptionalConnectedExperiences.Key, @"Software\Policies\Microsoft\Office");
        Assert.Equal([@"Software\Policies\Microsoft\Office\16.0\Common\Privacy"], deleted);
        Assert.True(sys.Has(@"HKCU\Software\Policies\Microsoft\Office\16.0\Common")); // has another subkey: kept, and so are its parents
        Assert.True(sys.Has(@"HKCU\Software\Policies\Microsoft\Office"));

        var withValue = new Sys(@"HKCU\Software\Microsoft\Office\16.0\PowerPoint\Options");
        withValue.Dwords[@"HKCU\Software\Microsoft\Office\16.0\PowerPoint\Options|Other"] = 1;
        Assert.Empty(RegistryKeyCleanup.Remove(withValue, RegistryRoot.CurrentUser, RegistryAllowlist.PowerPointStartScreen.Key, @"Software\Microsoft\Office\16.0\PowerPoint\Options"));
        Assert.True(withValue.Has(@"HKCU\Software\Microsoft\Office\16.0\PowerPoint\Options"));

        var denied = new Sys(@"HKCU\Software\Microsoft\Office\16.0\PowerPoint\Options") { DenyKeyDelete = true };
        Assert.Empty(RegistryKeyCleanup.Remove(denied, RegistryRoot.CurrentUser, RegistryAllowlist.PowerPointStartScreen.Key, @"Software\Microsoft\Office\16.0\PowerPoint")); // logged, not thrown
    }

    [Fact]
    public async Task SearchHighlights_Apply_RecordsCreatedKey_UndoAll_RemovesIt()
    {
        var sys = new Sys(@"HKLM\SOFTWARE\Policies\Microsoft\Windows", @"HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings")
        { Snap = Feeds(new(22631)) };
        var (_, j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "search-highlights");
        Assert.True((await svc.ApplyAsync(s, s.Actions[0])).Success);
        var policy = j.All.Single(c => c.Target == RegistryAllowlist.SearchHighlightsPolicy.Target);
        Assert.Equal(@"SOFTWARE\Policies\Microsoft\Windows\Windows Search", policy.CreatedKey);
        Assert.Null(j.All.Single(c => c.Target == RegistryAllowlist.SearchHighlightsToggle.Target).CreatedKey); // its key existed

        var r = await Undo(j, sys).UndoAllAsync("x");
        Assert.Equal(2, r.Succeeded);
        Assert.False(sys.Has(@"HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search"));
        Assert.True(sys.Has(@"HKLM\SOFTWARE\Policies\Microsoft\Windows"));
        Assert.True(sys.Has(@"HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings"));
        Assert.Empty(sys.Dwords);
    }

    [Fact]
    public async Task SearchHighlights_PerItemUndo_RemovesTheCreatedKey()
    {
        var sys = new Sys(@"HKLM\SOFTWARE\Policies\Microsoft\Windows", @"HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings")
        { Snap = Feeds(new(22631)) };
        var (_, j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "search-highlights");
        await svc.ApplyAsync(s, s.Actions[0]);
        Assert.True((await svc.UndoAsync(Assert.Single(svc.Undos))).Success);
        Assert.False(sys.Has(@"HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search"));
        Assert.Empty(j.All);
    }

    [Fact]
    public async Task UndoAll_OldValueRestored_KeyKept_AndRecordsWithoutCreatedKeyLeaveKeys()
    {
        var sys = new Sys(@"HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search");
        var j = new MemoryChangeJournal();
        // A journal written before CreatedKey existed: the value is deleted, the key is left as it was.
        j.Add(ChangeRecord.New(ChangeKind.RegistryValue, RegistryAllowlist.SearchHighlightsPolicy.Target, null, "Search highlights", "x"));
        sys.Dwords[RegistryAllowlist.SearchHighlightsPolicy.Target] = 0;
        Assert.Equal(1, (await Undo(j, sys).UndoAllAsync("x")).Succeeded);
        Assert.True(sys.Has(@"HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search"));
        Assert.Empty(sys.Deleted);
    }

    [Fact]
    public async Task UndoAll_SameClick_LastWrittenFirst_SoTheCreatingRecordCleansUp()
    {
        var key = @"HKCU\" + RegistryAllowlist.SilentInstalledApps.Key;
        var sys = new Sys(@"HKCU\Software\Microsoft\Windows\CurrentVersion");
        var j = new MemoryChangeJournal();
        var t = DateTimeOffset.UtcNow;
        var first = RegistryAllowlist.SilentInstalledApps;
        var second = RegistryAllowlist.SoftLanding;
        j.Add(new ChangeRecord(Guid.NewGuid(), t, ChangeKind.RegistryValue, first.Target, null, "a", "x", CreatedKey: first.Key));
        j.Add(new ChangeRecord(Guid.NewGuid(), t, ChangeKind.RegistryValue, second.Target, null, "b", "x"));
        sys.AddKey(key);
        sys.Dwords[first.Target] = 0;
        sys.Dwords[second.Target] = 0;
        var r = await Undo(j, sys).UndoAllAsync("x");
        Assert.Equal([second.Target, first.Target], r.Items.Select(i => i.Change.Target));
        Assert.False(sys.Has(key));
    }

    private const string HoneyId = "bmnlcjabgnpnenekpadlanbbkooimhnj";

    [Fact]
    public async Task ChromeBlock_RecordsCreatedPolicyKeys_UndoRemovesThem_SoChromeIsntManaged()
    {
        var sys = new Sys(@"HKLM\SOFTWARE\Policies\Microsoft");
        sys.Snap = new MemorySnapshot(new(16 * Gb, 8 * Gb), [],
            Extensions: new BrowserExtensionsInfo([new(BrowserKind.Chrome, HoneyId, ["Person 1"])], [], []));
        var (_, j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == BrowserExtensions.SuggestionId(BrowserKind.Chrome, HoneyId));
        Assert.True((await svc.ApplyAsync(s, s.Actions.Single(a => a.Type == MemoryActionType.BlockBrowserExtension))).Success);
        var rec = Assert.Single(j.All);
        Assert.Equal(ChangeKind.ExtensionBlock, rec.Kind);
        Assert.Equal(@"SOFTWARE\Policies\Google", rec.CreatedKey);

        Assert.Equal(1, (await Undo(j, sys).UndoAllAsync("x")).Succeeded);
        Assert.False(sys.Has(@"HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist"));
        Assert.False(sys.Has(@"HKLM\SOFTWARE\Policies\Google\Chrome"));
        Assert.False(sys.Has(@"HKLM\SOFTWARE\Policies\Google"));
        Assert.True(sys.Has(@"HKLM\SOFTWARE\Policies\Microsoft"));
        Assert.True(sys.Has(@"HKLM\SOFTWARE\Policies"));
    }

    [Fact]
    public void ChromeBlock_RemoveBlock_KeepsTheListWhenOtherEntriesRemain()
    {
        var sys = new Sys(@"HKLM\SOFTWARE\Policies\Microsoft");
        sys.AddExtensionBlock(BrowserKind.Chrome, "1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); // someone else's entry
        sys.AddExtensionBlock(BrowserKind.Chrome, "2", HoneyId);
        var (ok, _) = BrowserExtensions.RemoveBlock(sys, BrowserExtensions.Target(BrowserKind.Chrome, HoneyId), "2", @"SOFTWARE\Policies\Google");
        Assert.True(ok);
        Assert.True(sys.Has(@"HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist"));
        Assert.Empty(sys.Deleted);
    }

    [Fact]
    public void Journal_Json_IsBackwardTolerant_AndKeepsTheNewFields()
    {
        var dir = Path.Combine(Path.GetTempPath(), "rpd-findings-" + Guid.NewGuid().ToString("N"));
        var path = Path.Combine(dir, "changes.json");
        Directory.CreateDirectory(dir);
        try
        {
            // Written by an older build: no CreatedKey / PreviousExtra.
            File.WriteAllText(path, """
                [{"Id":"6f1c2c1e-6d3e-4e35-9d77-0f0c7f2b7a11","TimeUtc":"2026-10-30T10:00:00+00:00","Kind":"ServiceStartType","Target":"SysMain","Previous":"Automatic","Label":"SysMain set to Manual","Actor":"Local user","NeedsRestart":false}]
                """);
            var old = Assert.Single(new FileChangeJournal(path).All);
            Assert.Equal(ChangeKind.ServiceStartType, old.Kind);
            Assert.Null(old.CreatedKey);
            Assert.Null(old.PreviousExtra);

            var j = new FileChangeJournal(path);
            j.Add(ChangeRecord.New(ChangeKind.RegistryValue, RegistryAllowlist.WidgetsPolicy.Target, null, "Widgets", "x", true, @"SOFTWARE\Policies\Microsoft\Dsh"));
            j.Add(ChangeRecord.New(ChangeKind.HiberFileType, "", "full", "Hibernation", "x", previousExtra: PreviousDwords.Encode(new Dictionary<string, int?> { ["HiberFileType"] = null })));
            var back = new FileChangeJournal(path).All;
            Assert.Equal(@"SOFTWARE\Policies\Microsoft\Dsh", back.Single(c => c.Kind == ChangeKind.RegistryValue).CreatedKey);
            Assert.Equal(["HiberFileType"], Hibernation.ValuesToDelete(back.Single(c => c.Kind == ChangeKind.HiberFileType).PreviousExtra));
            Assert.Contains("\"Kind\": \"RegistryValue\"", File.ReadAllText(path)); // kinds stay names
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void RegistryUndoItems_FromBeforeCreatedKey_StillDecode()
    {
        var items = RegistryUndo.Decode("""[{"Target":"HKCU\\Software\\X|Y","Previous":null}]""");
        var item = Assert.Single(items);
        Assert.Null(item.CreatedKey);
        Assert.Null(item.Extra);
        Assert.Equal("a", RegistryUndo.Decode(RegistryUndo.Encode([new RegistryUndo.Item("t", null, "a")])).Single().CreatedKey);
    }

    // =========================================================================================
    // #3 DelayedAutostart and hibernation values put back exactly
    // =========================================================================================

    [Fact]
    public void DelayedAutostart_Plan()
    {
        Assert.Equal((true, (int?)null), ServiceDelayedStart.Plan("""{"DelayedAutostart":null}"""));
        Assert.Equal((true, (int?)0), ServiceDelayedStart.Plan("""{"DelayedAutostart":0}"""));
        Assert.Equal((true, (int?)1), ServiceDelayedStart.Plan("""{"DelayedAutostart":1}"""));
        Assert.Equal((false, (int?)null), ServiceDelayedStart.Plan(null));     // older journal: leave it alone
        Assert.Equal((false, (int?)null), ServiceDelayedStart.Plan("junk"));
    }

    private static MemorySnapshot ServiceSnap(string name) =>
        new(new(16 * Gb, 8 * Gb), [], Services: [new(new ServiceInfo(name, name + " display", "RUNNING", "AUTO_START", "LocalSystem", ""), 6L << 20)]);

    [Fact]
    public async Task ServiceManual_UndoAll_DeletesDelayedAutostart_WhenItWasAbsent()
    {
        const string name = "AdobeARMservice";
        var sys = new Sys { Snap = ServiceSnap(name) };
        var (_, j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "svc-adobearmservice");
        Assert.True((await svc.ApplyAsync(s, s.Actions.Single(a => a.Type == MemoryActionType.SetServiceManual))).Success);
        var rec = Assert.Single(j.All);
        Assert.EndsWith(" set to Manual (was Automatic)", rec.Label);
        Assert.Equal((true, (int?)null), ServiceDelayedStart.Plan(rec.PreviousExtra));

        Assert.Equal(1, (await Undo(j, sys).UndoAllAsync("x")).Succeeded);
        Assert.Equal("Automatic", sys.StartTypes[name]);
        Assert.False(sys.Delayed.ContainsKey(name)); // not DelayedAutostart = 0
    }

    [Fact]
    public async Task ServiceManual_PerItemUndo_PutsAnExistingDelayedAutostartBack()
    {
        const string name = "AdobeARMservice";
        var sys = new Sys { Snap = ServiceSnap(name) };
        sys.Delayed[name] = 0; // the value existed
        var (_, j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "svc-adobearmservice");
        await svc.ApplyAsync(s, s.Actions.First(a => a.Type == MemoryActionType.SetServiceManual));
        sys.Delayed[name] = 7; // something changed it meanwhile
        Assert.True((await svc.UndoAsync(Assert.Single(svc.Undos))).Success);
        Assert.Equal(0, sys.Delayed[name]);
        Assert.Contains($"delayed:{name}=0", sys.Calls);
    }

    [Fact]
    public async Task ServiceStartType_OldJournalWithoutExtra_LeavesDelayedAutostartAlone()
    {
        var sys = new Sys();
        var j = new MemoryChangeJournal();
        j.Add(ChangeRecord.New(ChangeKind.ServiceStartType, "SysMain", "Automatic", "SysMain set to Manual", "x"));
        Assert.Equal(1, (await Undo(j, sys).UndoAllAsync("x")).Succeeded);
        Assert.DoesNotContain(sys.Calls, c => c.StartsWith("delayed:"));
    }

    [Fact]
    public void Hibernation_ValuesToDelete()
    {
        Assert.Equal(["HiberFileType", "HibernateEnabled"], Hibernation.ValuesToDelete("""{"HiberFileType":null,"HibernateEnabled":null}"""));
        Assert.Equal(["HiberFileType"], Hibernation.ValuesToDelete("""{"HiberFileType":null,"HibernateEnabled":1}"""));
        Assert.Empty(Hibernation.ValuesToDelete("""{"HiberFileType":2,"HibernateEnabled":1}"""));
        Assert.Empty(Hibernation.ValuesToDelete("""{"Start":null}""")); // never anything but the two tracked values
        Assert.Empty(Hibernation.ValuesToDelete(null));
    }

    private static readonly HibernateInfo FullDesktop = new(true, false, false, 6 * Gb, true, false);
    private static readonly HibernateInfo ReducedDesktop = new(true, true, false, 3 * Gb, true, false);

    [Fact]
    public async Task Hibernate_UndoAll_RemovesTheValuesPowercfgAdded()
    {
        var sys = new Sys { Snap = new MemorySnapshot(new(16 * Gb, 8 * Gb), [], Hibernate: FullDesktop), HibAfter = ReducedDesktop };
        var (_, j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "hiberfile-reduced");
        Assert.True((await svc.ApplyAsync(s, s.Actions[0])).Success);
        var rec = Assert.Single(j.All);
        Assert.Equal(["HiberFileType", "HibernateEnabled"], Hibernation.ValuesToDelete(rec.PreviousExtra));

        var launcher = new ScriptedLauncher((_, _) => ScriptedLauncher.Ok("")); // powercfg /h /type full
        Assert.Equal(1, (await Undo(j, sys, launcher).UndoAllAsync("x")).Succeeded);
        Assert.Equal(["/h", "/type", "full"], Assert.Single(launcher.Calls).Args);
        Assert.Contains("hib-delete:HiberFileType", sys.Calls);
        Assert.Contains("hib-delete:HibernateEnabled", sys.Calls);
    }

    [Fact]
    public async Task Hibernate_PerItemUndo_KeepsValuesThatExistedBefore()
    {
        var sys = new Sys { Snap = new MemorySnapshot(new(16 * Gb, 8 * Gb), [], Hibernate: FullDesktop), HibAfter = ReducedDesktop };
        sys.Power["HibernateEnabled"] = 1;
        var (_, j, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "hiberfile-reduced");
        await svc.ApplyAsync(s, s.Actions[0]);
        Assert.True((await svc.UndoAsync(Assert.Single(svc.Undos))).Success);
        Assert.False(sys.Power.ContainsKey("HiberFileType"));
        Assert.Equal(1, sys.Power["HibernateEnabled"]);
        Assert.Empty(j.All);
    }

    [Fact]
    public async Task Hibernate_PowercfgFails_NothingDeleted()
    {
        var sys = new Sys();
        var j = new MemoryChangeJournal();
        j.Add(ChangeRecord.New(ChangeKind.HiberFileType, "", "full", "Hibernation", "x", previousExtra: """{"HiberFileType":null,"HibernateEnabled":null}"""));
        var launcher = new ScriptedLauncher((_, _) => ScriptedLauncher.Fail());
        Assert.Equal(1, (await Undo(j, sys, launcher).UndoAllAsync("x")).Failed);
        Assert.DoesNotContain(sys.Calls, c => c.StartsWith("hib-delete:"));
    }

    // =========================================================================================
    // #5 Wording
    // =========================================================================================

    [Fact]
    public async Task UndoAll_RestartSentence_NamesOnlyWhatWasUndone()
    {
        var sys = new Sys(@"HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search", @"HKCU\Software\Policies\Microsoft\Office\16.0\Common\Privacy");
        var j = new MemoryChangeJournal();
        j.Add(ChangeRecord.New(ChangeKind.RegistryValue, RegistryAllowlist.OfficeOptionalConnectedExperiences.Target, null, "Office optional connected experiences turned off (policy was not set)", "x"));
        sys.Dwords[RegistryAllowlist.OfficeOptionalConnectedExperiences.Target] = 2;
        var none = await Undo(j, sys).UndoAllAsync("x");
        Assert.DoesNotContain("Restart", none.Summary);
        Assert.EndsWith("Undid 1 of 1 change.", none.Summary);

        j.Add(ChangeRecord.New(ChangeKind.RegistryValue, RegistryAllowlist.SearchHighlightsPolicy.Target, null, "Search highlights turned off", "x", needsRestart: true));
        sys.Dwords[RegistryAllowlist.SearchHighlightsPolicy.Target] = 0;
        var one = await Undo(j, sys).UndoAllAsync("x");
        Assert.EndsWith("Restart to finish (Search highlights).", one.Summary);
        Assert.DoesNotContain("Widgets", one.Summary);
        Assert.DoesNotContain("page file", one.Summary);
    }

    [Fact]
    public void RestartNames()
    {
        Assert.Equal("Widgets", UndoAllResult.RestartName(ChangeRecord.New(ChangeKind.RegistryValue, RegistryAllowlist.WidgetsPolicy.Target, null, "l", "x")));
        Assert.Equal("Search highlights", UndoAllResult.RestartName(ChangeRecord.New(ChangeKind.RegistryValue, RegistryAllowlist.SearchHighlightsToggle.Target, null, "l", "x")));
        Assert.Equal("Fast Startup", UndoAllResult.RestartName(ChangeRecord.New(ChangeKind.FastStartup, "", "1", "Fast Startup turned off", "x")));
        Assert.Equal("page file", UndoAllResult.RestartName(ChangeRecord.New(ChangeKind.PageFile, "", "x", "Page file managed by Windows", "x")));
        Assert.Equal("Game DVR turned off for this account", UndoAllResult.RestartName(ChangeRecord.New(ChangeKind.RegistryValue, RegistryAllowlist.GameDvrEnabled.Target, null, "Game DVR turned off for this account (was not set)", "x")));
    }

    [Fact]
    public void Defender_CardAndResult_CountTheSameWay()
    {
        var folders = Enumerable.Range(1, 18).Select(i => $@"D:\src\repo{i}").ToList();
        var nuget = @"C:\Users\user\.nuget\packages";
        var tools = Enumerable.Range(1, 7).Select(i => $@"C:\VS\tool{i}.exe").ToList();
        var info = new DefenderInfo(true, folders, [.. folders, nuget], tools);
        var card = MemorySuggestionEngine.Build(new MemorySnapshot(new(16 * Gb, 8 * Gb), [new("MsMpEng", 1, 300L << 20, IsService: true)], Defender: info))
            .Single(x => x.Id == "defender-exclusions");
        Assert.Contains("Excluding 19 folders and 7 build tools", card.Why);
        Assert.Equal("19 folders and 7 build tools", DefenderProbe.Describe(19, 7));
        Assert.Equal("1 folder", DefenderProbe.Describe(1, 0));
        Assert.Equal("2 build tools", DefenderProbe.Describe(0, 2));
    }

    [Fact]
    public async Task Defender_Result_MatchesTheCard()
    {
        var folders = new List<string> { @"D:\work", @"C:\Users\user\.nuget\packages" };
        var tools = new List<string> { @"C:\VS\MSBuild.exe" };
        var sys = new Sys
        {
            Snap = new MemorySnapshot(new(16 * Gb, 8 * Gb), [new("MsMpEng", 1, 300L << 20, IsService: true)], Defender: new(true, [@"D:\work"], folders, tools)),
            DefenderReadBack = JsonSerializer.Serialize(new { Paths = folders, Procs = tools }),
        };
        var (_, _, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "defender-exclusions");
        Assert.Contains("Excluding 2 folders and 1 build tool", s.Why);
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.Contains("Defender no longer scans 2 folders and 1 build tool.", r.Message);
    }

    [Theory]
    [InlineData("Codex now starts only when needed. Takes effect after the next restart.", true)]
    [InlineData("Word will open straight to a blank document. Takes effect the next time each app opens.", true)]
    [InlineData("Widgets turned off. Takes full effect after a restart.", true)]
    [InlineData("Spotify won't start with Windows (your account only).", false)]
    [InlineData(null, false)]
    public void SaysWhen(string? message, bool expected) => Assert.Equal(expected, MemoryFeedback.SaysWhen(message));

    [Fact]
    public async Task Result_DoesntRepeatWhenItTakesEffect()
    {
        var sys = new Sys(@"HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search", @"HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings") { Snap = Feeds(new(22631)) };
        var (_, _, svc) = Make(sys);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "search-highlights");
        var r = await svc.ApplyAsync(s, s.Actions[0]);
        Assert.EndsWith("Takes full effect after a restart.", r.Message);
        Assert.DoesNotContain("Takes effect next launch", r.Message);
    }

    [Fact]
    public void RetiredApps_SayTheyMayNotBeReinstallable_ButStayPermanent()
    {
        var maps = AppRemoval.Packages.Single(p => p.Id == "maps");
        Assert.True(AppRemoval.IsRetiredPermanent(maps));
        Assert.Equal(AppRemoval.RetiredGetBack, AppRemoval.GetBack(maps));
        Assert.EndsWith("Microsoft has retired it, so it may not be available to reinstall", AppRemoval.RemovedLabel(maps, null));
        var journalApp = AppRemoval.Packages.Single(p => p.Id == "journal"); // grouped with them, but it's still on the Store: undo reinstalls it
        Assert.False(AppRemoval.IsRetiredPermanent(journalApp));
        Assert.Equal(AppRemoval.StoreUndo, AppRemoval.GetBack(journalApp));
        var weather = AppRemoval.Packages.Single(p => p.Id == "bing-weather");
        Assert.False(AppRemoval.IsRetiredPermanent(weather));
        Assert.Equal(UndoSupport.None, Undoability.Of(MemoryActionType.RemoveApp));
    }
}
