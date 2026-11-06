using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Memory;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests;

public class UndoTests
{
    private sealed class Sys : IMemorySystem
    {
        public List<string> Calls = [];
        public Dictionary<string, byte[]?> Approved = new();
        public Dictionary<string, string> StartTypes = new(StringComparer.OrdinalIgnoreCase);
        public bool? Transparency = true;
        public string? LocalState;
        public bool BrowserRunning;
        public MemoryReading ReadMemory() => new(16L << 30, 4L << 30); // 75% used: transparency suggested
        public MemorySnapshot? CustomSnapshot;
        public Task<MemorySnapshot> CaptureAsync(IReadOnlyList<ServiceInfo> s, CancellationToken ct) => Task.FromResult(CustomSnapshot ?? new MemorySnapshot(ReadMemory(), []));
        public Task<ActionOutcome> CloseAppAsync(string p, CancellationToken ct) => Task.FromResult(new ActionOutcome(true, ""));
        public Task<ActionOutcome> ForceCloseAppAsync(string p, CancellationToken ct) => Task.FromResult(new ActionOutcome(true, ""));
        public Task<ActionOutcome> RunCommandAsync(string f, IReadOnlyList<string> a, CancellationToken ct) => Task.FromResult(new ActionOutcome(true, ""));
        public byte[]? GetStartupApproved(string n) => Approved.GetValueOrDefault(n);
        public void SetStartupApproved(string n, byte[]? v) { Calls.Add("approved:" + n + "=" + (v is null ? "null" : Convert.ToBase64String(v))); Approved[n] = v; }
        public bool IsBrowserRunning(BrowserKind k) => BrowserRunning;
        public string? ReadBrowserLocalState(BrowserKind k) => LocalState;
        public void WriteBrowserLocalState(BrowserKind k, string json) { Calls.Add("browser:" + k); LocalState = json; }
        public void OpenUri(string uri) { }
        public string GetServiceStartType(string n) => StartTypes.GetValueOrDefault(n, "Automatic");
        public void SetServiceStartType(string n, string t) { Calls.Add($"start-type:{n}={t}"); StartTypes[n] = t; }
        public bool? GetTransparency() => Transparency;
        public void SetTransparency(bool on) { Calls.Add("transparency:" + on); Transparency = on; }
        public Task<ActionOutcome> EnableAutoPageFileAsync(CancellationToken ct) => Task.FromResult(new ActionOutcome(true, "managed"));
        public Task<string?> ReadPageFileSettingsAsync(CancellationToken ct) => Task.FromResult<string?>("W3siTmFtZSI6IkM6XFxwYWdlZmlsZS5zeXMifV0=");
        public Task<ActionOutcome> RestorePageFileAsync(string s, CancellationToken ct) { Calls.Add("pagefile:" + s); return Task.FromResult(new ActionOutcome(true, "restored")); }
    }

    private sealed class Backend : IServiceControlBackend
    {
        public List<string> Calls = [];
        public ServiceState State = ServiceState.Running;
        public ServiceState GetState(string n) => State;
        public bool IsDriver(string n) => false;
        public IReadOnlyList<DependentService> GetRunningDependents(string n) => [];
        public void Start(string n) { Calls.Add("start:" + n); State = ServiceState.Running; }
        public void Stop(string n) { Calls.Add("stop:" + n); State = ServiceState.Stopped; }
        public Task<bool> WaitForStateAsync(string n, ServiceState t, TimeSpan to, CancellationToken ct) => Task.FromResult(true);
    }

    private static ChangeRecord Rec(ChangeKind k, string target, string? prev, int minutesAgo) =>
        new(Guid.NewGuid(), DateTimeOffset.UtcNow.AddMinutes(-minutesAgo), k, target, prev, $"{k} {target}", "Remote technician");

    // ---- journal ----
    [Fact]
    public void Journal_KeepsOldestBefore_RemoveLatest_AndPersists()
    {
        var path = Path.Combine(Path.GetTempPath(), "rpd-undo-" + Guid.NewGuid().ToString("N"), "changes.json");
        var j = new FileChangeJournal(path);
        j.Add(Rec(ChangeKind.ServiceStartType, "WSearch", "Automatic", 10));
        j.Add(Rec(ChangeKind.ServiceStartType, "wsearch", "Manual", 5)); // later change: the original "before" stays
        j.Add(Rec(ChangeKind.Transparency, "", "1", 1));
        Assert.Equal(2, j.All.Count);
        Assert.Equal("Automatic", j.All.Single(x => x.Kind == ChangeKind.ServiceStartType).Previous);
        var reloaded = new FileChangeJournal(path);
        Assert.Equal(2, reloaded.All.Count);
        reloaded.RemoveLatest(ChangeKind.Transparency, "");
        Assert.Single(new FileChangeJournal(path).All);
        Directory.Delete(Path.GetDirectoryName(path)!, true);
    }

    // ---- undo ----
    [Fact]
    public async Task UndoAll_RevertsNewestFirst_KeepsFailures()
    {
        var j = new MemoryChangeJournal();
        j.Add(Rec(ChangeKind.StartupApp, "Spotify", null, 30));
        j.Add(Rec(ChangeKind.ServiceStartType, "WSearch", "AutomaticDelayed", 20));
        j.Add(Rec(ChangeKind.ServiceRunning, "Spooler", "Running", 15));
        j.Add(Rec(ChangeKind.Transparency, "", "1", 10));
        j.Add(Rec(ChangeKind.BrowserSettings, "Chrome", "{\"old\":true}", 5));
        j.Add(Rec(ChangeKind.PowerPlan, "", "a1841308-3541-4fab-bc81-f71556f20b4a", 4));
        j.Add(Rec(ChangeKind.AdapterDns, "Wi-Fi", "192.168.1.1", 3));
        j.Add(Rec(ChangeKind.AdapterDns, "Ethernet", "", 2));
        var sys = new Sys { BrowserRunning = true, Transparency = false };
        var backend = new Backend { State = ServiceState.Stopped };
        var launcher = new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""));
        var settings = new FakeSystemSettings();
        var events = new List<string>();
        var r = await new UndoService(j, new SystemCommandRunner(launcher), sys, backend, (_, t) => events.Add(t), settings: settings).UndoAllAsync("Local user");

        Assert.Equal(8, r.Items.Count);
        Assert.Equal(ChangeKind.AdapterDns, r.Items[0].Change.Kind);                  // newest first
        Assert.Equal(7, r.Succeeded);
        var browser = Assert.Single(r.Items, i => !i.Success);
        Assert.Equal(ChangeKind.BrowserSettings, browser.Change.Kind);               // browser open: kept for later
        Assert.Single(j.All);
        Assert.Contains("approved:Spotify=null", sys.Calls);
        Assert.Contains("start-type:WSearch=AutomaticDelayed", sys.Calls);
        Assert.Contains("start:Spooler", backend.Calls);
        Assert.Equal(true, sys.Transparency);
        Assert.Contains(launcher.Calls, c => c.Args.SequenceEqual(["/setactive", "a1841308-3541-4fab-bc81-f71556f20b4a"]));
        Assert.Contains("dns:Wi-Fi=192.168.1.1", settings.Calls);
        Assert.Contains("dns:Ethernet=", settings.Calls);                             // automatic again
        Assert.Contains("1 couldn't be undone", r.Summary);
        Assert.Contains(events, e => e.Contains("Undo all changes") && e.Contains("FAILED"));
    }

    [Fact]
    public async Task Undo_RejectsBadDnsValues_AndNeedsRestartFlag()
    {
        var j = new MemoryChangeJournal();
        j.Add(Rec(ChangeKind.AdapterDns, "Wi-Fi", "1.1.1.1; Remove-Item C:\\", 2));     // not an IP → treated as automatic, never injected
        j.Add(Rec(ChangeKind.FastStartup, "", "1", 1) with { NeedsRestart = true });
        var launcher = new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""));
        var settings = new FakeSystemSettings();
        var r = await new UndoService(j, new SystemCommandRunner(launcher), new Sys(), settings: settings).UndoAllAsync("x");
        Assert.True(r.NeedsRestart);
        Assert.Contains("dns:Wi-Fi=", settings.Calls);                                // not an IP: automatic, never passed on
        Assert.DoesNotContain(settings.Calls, c => c.Contains("Remove-Item"));
        Assert.Contains("fast-startup=1", settings.Calls);
    }

    [Fact]
    public async Task Undo_TempFiles_IsSkippedWithoutCreatingFilesOrRunningCommands()
    {
        var j = new MemoryChangeJournal();
        j.Add(Rec(ChangeKind.TempFiles, "run1", "3:3000000", 1));
        var launcher = new ScriptedLauncher((_, _) => throw new Exception("Undo must not run commands"));
        var r = await new UndoService(j, new SystemCommandRunner(launcher)).UndoAllAsync("x");
        var item = Assert.Single(r.Items);
        Assert.True(item.Skipped);
        Assert.False(item.Success);
        Assert.Equal(0, r.Failed);
        Assert.Equal(0, r.Succeeded);
        Assert.Contains("cannot be restored", item.Message);
        Assert.Empty(launcher.Calls);
        Assert.Empty(j.All);
    }

    // ---- recording ----
    [Fact]
    public async Task Remediation_RecordsPreviousPowerPlan_AndCleanup()
    {
        var launcher = new ScriptedLauncher((file, args) =>
            file.Equals("powercfg.exe", StringComparison.OrdinalIgnoreCase) && args.Contains("/getactivescheme")
                ? ScriptedLauncher.Ok("Power Scheme GUID: a1841308-3541-4fab-bc81-f71556f20b4a  (Power saver)")
                : ScriptedLauncher.Ok("""{"RemovedFiles":42,"FreedBytes":524288000}"""));
        var j = new MemoryChangeJournal();
        var svc = new RemediationService(new SystemCommandRunner(launcher), new SessionContext(SessionMode.Remote), journal: j);
        Assert.True((await svc.ExecuteAsync(new(RemediationKind.SetBalancedPowerPlan, "Switch to Balanced"))).Success);
        Assert.True((await svc.ExecuteAsync(new(RemediationKind.CleanTempFiles, "Clean"))).Success);
        var plan = Assert.Single(j.All, c => c.Kind == ChangeKind.PowerPlan);
        Assert.Equal("a1841308-3541-4fab-bc81-f71556f20b4a", plan.Previous);
        Assert.Equal("Remote technician", plan.Actor);
        Assert.Equal("42:524288000", Assert.Single(j.All, c => c.Kind == ChangeKind.TempFiles).Previous);
    }

    [Fact]
    public async Task ServiceStop_IsRecordedAsRunning()
    {
        var j = new MemoryChangeJournal();
        var svc = new ServiceActionService(new Backend(), new SessionContext(SessionMode.Local), journal: j);
        var info = new ServiceInfo("VendorUpdater", "Vendor Updater", "RUNNING", "AUTO_START", "LocalSystem", "");
        await svc.ExecuteAsync(info, ServiceAction.Stop);
        var c = Assert.Single(j.All);
        Assert.Equal((ChangeKind.ServiceRunning, "VendorUpdater", "Running"), (c.Kind, c.Target, c.Previous));
    }

    [Fact]
    public async Task MemorySuggestion_Transparency_IsJournaled_AndPerItemUndoClearsIt()
    {
        var sys = new Sys();
        var j = new MemoryChangeJournal();
        var svc = new MemorySuggestionService(sys, session: new SessionContext(SessionMode.Remote), settle: TimeSpan.Zero, journal: j);
        await svc.ScanAsync();
        var s = svc.Suggestions.Single(x => x.Id == "transparency");
        await svc.ApplyAsync(s, s.Actions.Single(a => a.Type == MemoryActionType.DisableTransparency));
        Assert.Single(j.All, c => c.Kind == ChangeKind.Transparency && c.Previous == "1");
        await svc.UndoAsync(svc.Undos.Single());
        Assert.Empty(j.All);
    }

    [Theory]
    [InlineData("Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced)", "381b4222-f694-41f0-9685-ff5bb260df2e")]
    [InlineData("nothing here", null)]
    public void SchemeGuid(string output, string? expected) => Assert.Equal(expected, UndoService.ParseSchemeGuid(output));

    [Fact]
    public async Task Journal_PrunesStaleServiceRunningEntries_OnLoadAndScan()
    {
        var path = Path.Combine(Path.GetTempPath(), "rpd-undo-prune-" + Guid.NewGuid().ToString("N"), "changes.json");
        var j = new FileChangeJournal(path);
        var beforeBoot = FileChangeJournal.CurrentBootUtc().AddHours(-5);
        j.Add(new ChangeRecord(Guid.NewGuid(), beforeBoot, ChangeKind.ServiceRunning, "SysMain", "Running", "SysMain stopped", "Local user"));
        j.Add(new ChangeRecord(Guid.NewGuid(), beforeBoot, ChangeKind.ServiceStartType, "WSearch", "Automatic", "Windows Search set to Manual", "Local user"));

        var reloaded = new FileChangeJournal(path);
        Assert.Single(reloaded.All);
        Assert.Equal(ChangeKind.ServiceStartType, reloaded.All[0].Kind);
        Directory.Delete(Path.GetDirectoryName(path)!, true);

        var memJournal = new MemoryChangeJournal();
        memJournal.Add(Rec(ChangeKind.ServiceRunning, "Spooler", "Running", 1));
        memJournal.Add(Rec(ChangeKind.ServiceRunning, "Fax", "Running", 30));
        var sys = new Sys
        {
            CustomSnapshot = new MemorySnapshot(new(16L << 30, 8L << 30), [],
                Uptime: TimeSpan.FromMinutes(10),
                Services: [new ServiceUsage(new ServiceInfo("Spooler", "Print Spooler", "RUNNING", "AUTO_START", "LocalSystem", ""), 10L << 20)])
        };
        var svc = new MemorySuggestionService(sys, session: new SessionContext(SessionMode.Local), settle: TimeSpan.Zero, journal: memJournal);
        await svc.ScanAsync();
        Assert.Empty(memJournal.All);
    }
}
