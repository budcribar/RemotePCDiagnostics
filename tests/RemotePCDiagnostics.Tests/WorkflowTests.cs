using Bunit;
using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Checks;
using RemotePCDiagnostics.Core.Benchmarks;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Tests;

public class WorkflowTests
{
    // ---- fakes ----
    private sealed class AreaModule(string name, AreaReport report) : IDiagnosticModule
    {
        public string Name => name;
        public Guid Id => TestIds.For(name);
        public event EventHandler<DiagnosticResult>? Updated { add { } remove { } }
        public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct = default) => Task.FromResult(ModuleAvailability.Available);
        public Task<DiagnosticResult> RefreshAsync(IProgress<string>? p, CancellationToken ct = default) =>
            Task.FromResult(new DiagnosticResult(name, report.Status, report.Summary, DateTimeOffset.Now, report));
    }

    private sealed class Sys : IWorkflowSystem
    {
        public List<string> Calls = [];
        public bool RegisterOk = true, RemoveOk = true;
        public RestartSignInStatus SignIn = new(false, true);
        public TimeSpan Uptime { get; set; } = TimeSpan.FromDays(3);
        public string? Report;
        public Task<bool> RegisterResumeAsync(CancellationToken ct) { Calls.Add("register"); return Task.FromResult(RegisterOk); }
        public Task<bool> RemoveResumeAsync(CancellationToken ct) { Calls.Add("unregister"); return Task.FromResult(RemoveOk); }
        public Task<bool> RestartAsync(TimeSpan d, string m, CancellationToken ct) { Calls.Add("restart"); return Task.FromResult(true); }
        public Task AbortRestartAsync(CancellationToken ct) { Calls.Add("abort"); return Task.CompletedTask; }
        public RestartSignInStatus GetRestartSignIn() => SignIn;
        public string ReportFile(DateTimeOffset when) => @"C:\Users\Public\Documents\Remote PC Diagnostics\Service report.html";
        public void SaveReport(string path, string html) { Report = html; Calls.Add("report"); }
    }

    private sealed class Probes : IBenchmarkProbes
    {
        public double ProgramMs = 300;
        public BenchmarkConditions ReadConditions() => new(false, 50, "Balanced");
        public Task<IdleSample?> SampleIdleAsync(TimeSpan d, CancellationToken ct) => Task.FromResult<IdleSample?>(new(5, 50));
        public Task<double?> StartProgramAsync(BuiltInProgram p, CancellationToken ct) => Task.FromResult<double?>(ProgramMs);
        public Task<double?> DiskRandomReadIopsAsync(TimeSpan d, CancellationToken ct) => Task.FromResult<double?>(5000);
        public Task<IReadOnlyList<WinEvent>> ReadBootEventsAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<WinEvent>>([]);
    }

    private sealed class MemFlowStore : IWorkflowStore
    {
        public WorkflowState? State;
        public WorkflowState? Load() => State is null ? null : WorkflowState.FromJson(State.ToJson());
        public void Save(WorkflowState s) => State = s;
    }

    private sealed class MemBenchStore : IBenchmarkStore
    {
        public BenchmarkState? State;
        public BenchmarkState? Load() => State;
        public void Save(BenchmarkState s) => State = s;
    }

    private static AreaReport Report(params AreaAction[] actions) =>
        new([new AreaCard("c", "Card", AreaLevel.Warning, "Headline", "", [], [], Actions: actions)], "1 thing", DiagnosticStatus.Warning);

    private static readonly AreaAction PowerPlan = new(RemediationKind.SetBalancedPowerPlan, "Switch to Balanced");
    private static readonly AreaAction Clean = new(RemediationKind.CleanTempFiles, "Clean up temporary files", "", "Temporary files");
    private static readonly AreaAction Updates = new(RemediationKind.CheckAndInstallWindowsUpdates, "Check & install updates");

    private static IDiagnosticModule[] DefaultModules() =>
    [
            new AreaModule("ResourceHogs", Report(PowerPlan, new AreaAction(RemediationKind.ScheduleCleanRestart, "Restart"), new AreaAction(RemediationKind.EndProcessGroup, "End task", "chrome.exe"))),
            new AreaModule("DriveHealth", Report(Clean, PowerPlan)),
            new AreaModule("Programs", Report(Updates)),
    ];

    private static (WorkflowService Flow, Sys Sys, IWorkflowStore Store, List<TimeSpan> Delays, ScriptedLauncher Launcher, Probes Probes) Make(
        IWorkflowStore? flowStore = null, IBenchmarkStore? benchmarkStore = null, Sys? system = null, Probes? benchmarkProbes = null,
        Func<TimeSpan, CancellationToken, Task>? delay = null) =>
        Make(null, null, null, DefaultModules(), flowStore, benchmarkStore, system, benchmarkProbes, delay);

    private static (WorkflowService Flow, Sys Sys, IWorkflowStore Store, List<TimeSpan> Delays, ScriptedLauncher Launcher, Probes Probes) Make(
        Func<string, IReadOnlyList<string>, ProcessResult>? run, IChangeJournal? journal, IMemorySystem? memorySystem, IDiagnosticModule[] modules,
        IWorkflowStore? flowStore = null, IBenchmarkStore? benchmarkStore = null, Sys? system = null, Probes? benchmarkProbes = null,
        Func<TimeSpan, CancellationToken, Task>? delay = null, ISystemSettings? settings = null, CheckSettingsService? checks = null)
    {
        var results = new ResultStore();
        var diag = new DiagnosticsService(results, modules, checks: checks);
        var launcher = new ScriptedLauncher(run ?? ((file, args) => ScriptedLauncher.Ok(args.Any(a => a.Contains("RemovedFiles")) ? """{"RemovedFiles":42,"FreedBytes":524288000}""" : """{"Count":0}""")));
        var rem = new RemediationService(new SystemCommandRunner(launcher), new SessionContext(SessionMode.Remote), journal: journal,
            settings: settings ?? new FakeSystemSettings { DefaultDns = "" });
        var memory = memorySystem is null ? null : new MemorySuggestionService(memorySystem, session: new SessionContext(SessionMode.Remote), settle: TimeSpan.Zero, remediation: rem, journal: journal);
        var probes = benchmarkProbes ?? new Probes();
        var bench = new BenchmarkService(new BenchmarkRunner(probes, resolve: (_, _) => Task.CompletedTask), benchmarkStore ?? new MemBenchStore());
        if (benchmarkStore?.Load() is null)
            bench.UpdateSettings(new BenchmarkSettings { Runs = 1, IdleSample = TimeSpan.Zero, CpuSingleRun = TimeSpan.FromMilliseconds(50), CpuMultiRun = TimeSpan.FromMilliseconds(50), DiskRun = TimeSpan.Zero });
        var sys = system ?? new Sys();
        var store = flowStore ?? new MemFlowStore();
        var delays = new List<TimeSpan>();
        var flow = new WorkflowService(diag, results, rem, bench, sys, store, memory, session: new SessionContext(SessionMode.Remote),
            delay: (d, c) => { delays.Add(d); return delay?.Invoke(d, c) ?? Task.CompletedTask; }, journal: journal);
        return (flow, sys, store, delays, launcher, probes);
    }

    // ---- the Agent keeps the state: it can connect after the app started ----
    [Fact]
    public void Reload_picks_up_the_saved_workflow_only_while_nothing_happened_in_this_run()
    {
        var store = new MemFlowStore();
        var (flow, _, _, _, _, _) = Make(store);
        Assert.Equal(WorkflowStage.Idle, flow.State.Stage);
        Assert.False(flow.Reload()); // still nothing saved

        store.State = new WorkflowState { ReviewRulesVersion = WorkflowService.CurrentReviewRulesVersion, Stage = WorkflowStage.RestartAfter, StartedUtc = DateTimeOffset.UtcNow };
        Assert.True(flow.Reload());
        Assert.Equal(WorkflowStage.RestartAfter, flow.State.Stage);

        store.State = store.State with { Stage = WorkflowStage.Done };
        Assert.False(flow.Reload()); // never replaces a workflow this run already has
        Assert.Equal(WorkflowStage.RestartAfter, flow.State.Stage);
    }

    // ---- catalog ----
    [Fact]
    public void DismissParkedReview_clears_a_review_and_leaves_an_active_stage()
    {
        var fix = new WorkflowFix("temp", "Clean temp", "space", "Storage", SuggestionRisk.Low, FixSource.Remediation, 1);
        var parked = new WorkflowState
        {
            Stage = WorkflowStage.Review,
            ReviewRulesVersion = WorkflowService.CurrentReviewRulesVersion,
            ReviewedUtc = DateTimeOffset.Parse("2026-11-20T17:06:00Z"),
            Approved = [fix.Id],
            Fixes = [fix],
        };
        var store = new MemFlowStore { State = parked };
        var flow = Make(store).Flow;
        Assert.Equal(WorkflowStage.Review, flow.State.Stage);
        Assert.False(flow.State.IsRunning);
        Assert.False(WorkflowState.IsActiveStage(flow.State.Stage));

        Assert.True(flow.DismissParkedReview());
        Assert.Equal(WorkflowStage.Idle, flow.State.Stage);
        Assert.Empty(flow.State.Fixes);
        Assert.False(flow.DismissParkedReview());

        store.State = new WorkflowState { Stage = WorkflowStage.Applying, ReviewRulesVersion = WorkflowService.CurrentReviewRulesVersion };
        var running = Make(store).Flow;
        Assert.False(running.DismissParkedReview());
        Assert.Equal(WorkflowStage.Applying, running.State.Stage);
        Assert.True(WorkflowService.IsWorkflowRoute("workflow"));
        Assert.True(WorkflowService.IsWorkflowRoute("/workflow?x=1"));
        Assert.False(WorkflowService.IsWorkflowRoute("dashboard"));
    }

    [Fact]
    public async Task LegacyReviewRequiresFreshChecksInsteadOfRestoringStaleDnsApprovals()
    {
        var stale = new WorkflowFix("dns", "Reset DNS", "old recommendation", "Network", SuggestionRisk.Medium,
            FixSource.Remediation, 60, Remediation: new(RemediationKind.ResetDhcpDns, "Reset DNS to DHCP", "Wi-Fi"));
        var store = new MemFlowStore { State = new WorkflowState { Stage = WorkflowStage.Review, Fixes = [stale], Approved = [stale.Id] } };
        var (flow, sys, _, _, _, _) = Make(store);
        Assert.Equal(WorkflowStage.Idle, flow.State.Stage);
        Assert.Empty(flow.State.Fixes);
        Assert.Empty(flow.State.Approved);
        Assert.NotNull(await flow.StartAsync());
        Assert.Empty(sys.Calls);
        await flow.RunChecksAsync();
        Assert.Equal(WorkflowService.CurrentReviewRulesVersion, flow.State.ReviewRulesVersion);
        Assert.Equal(WorkflowStage.Review, Make(store).Flow.State.Stage);
    }

    [Theory]
    [InlineData(WorkflowStage.RestartBefore)]
    [InlineData(WorkflowStage.Applying)]
    [InlineData(WorkflowStage.RestartAfter)]
    [InlineData(WorkflowStage.Reporting)]
    public void LegacyRunningWorkflowKeepsResumeAndCleanupState(WorkflowStage stage)
    {
        var store = new MemFlowStore { State = new WorkflowState { Stage = stage, SignsInAfterRestart = true, ResumeTaskCreated = true } };
        var flow = Make(store).Flow;
        Assert.Equal(stage, flow.State.Stage);
        Assert.True(flow.State.SignsInAfterRestart);
        Assert.True(flow.State.ResumeTaskCreated);
    }

    [Fact]
    public async Task Checks_BuildDeduplicatedReviewList_AllTicked_RestartsAndEndTaskLeftOut()
    {
        var (flow, _, _, _, _, _) = Make();
        await flow.RunChecksAsync();
        var s = flow.State;
        Assert.Equal(WorkflowStage.Review, s.Stage);
        Assert.Equal(3, s.Fixes.Count);                                          // power plan listed once
        Assert.DoesNotContain(s.Fixes, f => f.Remediation?.Kind is RemediationKind.ScheduleCleanRestart or RemediationKind.EndProcessGroup);
        Assert.Equal(s.Fixes.Select(f => f.Id), s.Approved);                     // everything starts ticked
        Assert.Equal(RemediationKind.CheckAndInstallWindowsUpdates, s.Fixes[^1].Remediation!.Kind); // slow ones last
        Assert.True(s.Fixes[^1].Slow);
        Assert.Equal(3, s.Findings.Count);
        Assert.NotNull(s.ReviewedUtc);
        Assert.All(s.Findings, finding => Assert.Contains("(scan ", finding));
    }

    [Fact]
    public void Catalog_MemorySuggestions_UnattendedOnly_SkipsFastStartupAndRestart()
    {
        MemorySuggestion Sug(string id, SuggestionKind k, params MemoryAction[] a) => new(id, id, "why", null, SuggestionRisk.Low, k, [], a);
        var fixes = FixCatalog.Build(
            [new DiagnosticResult("ResourceHogs", DiagnosticStatus.Warning, "", DateTimeOffset.Now, Report(new AreaAction(RemediationKind.DisableFastStartup, "Turn off Fast Startup")))],
            [
                Sug("svc-wsearch", SuggestionKind.Automated, new MemoryAction(MemoryActionType.StopService, "WSearch", "Stop now"), new MemoryAction(MemoryActionType.SetServiceManual, "WSearch", "Manual")),
                Sug("close-chrome", SuggestionKind.Automated, new MemoryAction(MemoryActionType.CloseApp, "chrome", "Close")),
                Sug("restart", SuggestionKind.Automated, new MemoryAction(MemoryActionType.RestartPc, "", "Restart"), new MemoryAction(MemoryActionType.DisableFastStartup, "", "Fast Startup")),
                Sug("defender", SuggestionKind.Guided, new MemoryAction(MemoryActionType.OpenSettings, "windowsdefender://", "Open")),
            ]);
        Assert.Single(fixes);
        Assert.Contains(fixes, f => f.MemoryAction == MemoryActionType.SetServiceManual && f.MemoryTarget == "WSearch");
        Assert.DoesNotContain(fixes, f => f.Id.Contains("disablefaststartup"));
        Assert.Equal(["defender: why"], FixCatalog.Recommendations([Sug("defender", SuggestionKind.Guided)]));
    }

    [Fact]
    public void Catalog_ManualAction_DescribesStartupChangeAndLeavesRunningServiceAlone()
    {
        var suggestion = new MemorySuggestion("sql", "Stop \"SQL Server VSS Writer\"", "Uses 20 MB.", null,
            SuggestionRisk.Medium, SuggestionKind.Automated, [],
            [new(MemoryActionType.StopService, "SQLWriter", "Stop now"), new(MemoryActionType.SetServiceManual, "SQLWriter", "Manual")]);
        var fix = Assert.Single(FixCatalog.Build([], [suggestion]));
        Assert.Equal("Set \"SQL Server VSS Writer\" to Manual", fix.Title);
        Assert.Equal(MemoryActionType.SetServiceManual, fix.MemoryAction);
        Assert.Contains("running service is left running", fix.Why);
    }

    [Fact]
    public void Catalog_DnsEvidenceSurvivesSavedStateAndClientReport()
    {
        var scan = DateTimeOffset.Parse("2026-11-02T10:00:00Z");
        var action = new AreaAction(RemediationKind.SetPublicDns, "Use Cloudflare & Google DNS (26 ms vs 39 ms now)", "Wi-Fi", "Wi-Fi");
        var report = new AreaReport([new("ipdns", "DNS", AreaLevel.Ok, "192.168.1.1", "", [],
            [new(AreaLevel.Ok, ["Wi-Fi"], Actions: [action])], Note: "Current DNS 39 ms; Cloudflare 26 ms; Google 41 ms.")], "Network", DiagnosticStatus.Ok);
        var fixes = FixCatalog.Build([new("Network", DiagnosticStatus.Ok, "Network", scan, report)], []);
        var state = new WorkflowState { Fixes = fixes, ReviewedUtc = scan };
        var saved = WorkflowState.FromJson(state.ToJson())!;
        Assert.Equal(scan, saved.ReviewedUtc);
        var why = Assert.Single(saved.Fixes).Why;
        Assert.Contains("Google 41 ms", why);
        Assert.Contains(scan.ToString("O"), why);
        var html = ClientReport.Build(saved, null, null, new BenchmarkComparison([], null, []), scan);
        Assert.Contains("DNS measurement evidence", html);
        Assert.Contains("Google 41 ms", html);
        Assert.Contains("Saved scan snapshot", html);
    }

    // ---- opt-in fixes (DefaultOn = false) ----

    /// <summary>A small PC (8 GB, 90% in use, no classic Outlook) running Windows Search (opt-in) and DiagTrack (ticked by default).</summary>
    private sealed class SmallPcMem : IMemorySystem
    {
        private static ServiceInfo Svc(string name) => new(name, name + " display", "RUNNING", "AUTO_START", "LocalSystem", "");
        public MemoryReading ReadMemory() => new(8L << 30, (long)(0.8 * (1L << 30)));
        public Task<MemorySnapshot> CaptureAsync(IReadOnlyList<ServiceInfo> s, CancellationToken ct) =>
            Task.FromResult(new MemorySnapshot(ReadMemory(), [], Services: [new(Svc("WSearch"), 40L << 20), new(Svc("DiagTrack"), 30L << 20)],
                Devices: new(HasClassicOutlook: false), TransparencyOn: false));
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
    }

    private static WorkflowService MakeWithMemory(IMemorySystem mem)
    {
        var results = new ResultStore();
        var diag = new DiagnosticsService(results, [new AreaModule("ResourceHogs", Report(PowerPlan))]);
        var rem = new RemediationService(new SystemCommandRunner(new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""))), new SessionContext(SessionMode.Remote));
        var bench = new BenchmarkService(new BenchmarkRunner(new Probes(), resolve: (_, _) => Task.CompletedTask), new MemBenchStore());
        var memory = new MemorySuggestionService(mem, session: new SessionContext(SessionMode.Remote), settle: TimeSpan.Zero);
        return new WorkflowService(diag, results, rem, bench, new Sys(), new MemFlowStore(), memory, session: new SessionContext(SessionMode.Remote),
            delay: (_, _) => Task.CompletedTask);
    }

    [Fact]
    public async Task WindowsSearch_IsOptIn_ListedUnticked_OthersTicked_CanBeTickedByHand_ReportListsItWhenLeft()
    {
        var flow = MakeWithMemory(new SmallPcMem());
        await flow.RunChecksAsync();
        var s = flow.State;
        Assert.Equal(WorkflowStage.Review, s.Stage);
        var wsearch = s.Fixes.Single(f => f.MemoryAction == MemoryActionType.SetServiceManual && f.MemoryTarget == "WSearch");
        Assert.False(wsearch.DefaultOn);
        Assert.DoesNotContain(wsearch.Id, s.Approved);                                    // opt-in: starts unticked
        var others = s.Fixes.Where(f => f.Id != wsearch.Id).ToList();
        Assert.Contains(others, f => f.MemoryTarget == "DiagTrack");
        Assert.Contains(others, f => f.Remediation?.Kind == RemediationKind.SetBalancedPowerPlan);
        Assert.All(others, f => { Assert.True(f.DefaultOn); Assert.Contains(f.Id, s.Approved); }); // everything else still ticked

        // Left unticked: the client report lists it under "Left as they were, by choice".
        var html = ClientReport.Build(s, null, null, BenchmarkComparison.Build(null, null), DateTimeOffset.Now);
        Assert.Contains("Left as they were, by choice", html);
        Assert.Contains(System.Net.WebUtility.HtmlEncode(wsearch.Title), html);

        // The tech can tick it by hand.
        flow.SetApproved(wsearch.Id, true);
        Assert.Contains(wsearch.Id, flow.State.Approved);
        Assert.Equal(s.Fixes.Count, flow.State.Approved.Count);
        flow.SetApproved(wsearch.Id, false);
        Assert.DoesNotContain(wsearch.Id, flow.State.Approved);

        // Select all -> Select none -> Select recommended restores DefaultOn approvals (opt-in stays unticked).
        flow.SetAllApproved(true);
        Assert.Contains(wsearch.Id, flow.State.Approved);
        flow.SetAllApproved(false);
        Assert.Empty(flow.State.Approved);
        flow.SetRecommendedApproved();
        Assert.DoesNotContain(wsearch.Id, flow.State.Approved);
        Assert.All(others, f => Assert.Contains(f.Id, flow.State.Approved));
    }

    /// <summary>Any memory snapshot, for workflow tests of individual rules.</summary>
    private sealed class SnapMem(MemorySnapshot snap) : IMemorySystem
    {
        public MemoryReading ReadMemory() => snap.Memory;
        public Task<MemorySnapshot> CaptureAsync(IReadOnlyList<ServiceInfo> s, CancellationToken ct) => Task.FromResult(snap);
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
    }

    [Fact]
    public async Task Teams_StartupIsOptIn_AdobeServicesTickedWhenAutomatic_AndLeftOutWhenManual()
    {
        static ServiceInfo Svc(string name, string start) => new(name, name + " display", "RUNNING", start, "LocalSystem", "");
        var snap = new MemorySnapshot(new(16L << 30, 8L << 30), [],
            Services: [new(Svc("AdobeARMservice", "AUTO_START"), 6L << 20), new(Svc("AGSService", "AUTO_START"), 12L << 20), new(Svc("AGMService", "DEMAND_START"), 9L << 20)],
            Startup:
            [
                new(@"uwp:MSTeams_8wekyb3d8bbwe\TeamsTfwStartupTask", @"MSTeams_8wekyb3d8bbwe\TeamsTfwStartupTask", true, StartupScope.PackagedUwp),
                new(@"uwp:MicrosoftTeams_8wekyb3d8bbwe\TeamsStartupTask", @"MicrosoftTeams_8wekyb3d8bbwe\TeamsStartupTask", true, StartupScope.PackagedUwp),
                new("com.squirrel.Teams.Teams", @"C:\Users\b\AppData\Local\Microsoft\Teams\Update.exe --processStart ""Teams.exe""", true),
                new("Spotify", "\"C:\\s\\Spotify.exe\" /minimized", true),
            ],
            TransparencyOn: false);
        var flow = MakeWithMemory(new SnapMem(snap));
        await flow.RunChecksAsync();
        var s = flow.State;
        Assert.Equal(WorkflowStage.Review, s.Stage);

        var teams = s.Fixes.Where(f => f.MemoryAction == MemoryActionType.DisableStartup && f.Title.Contains("Microsoft Teams")).ToList();
        Assert.Equal(3, teams.Count);
        Assert.Contains(teams, f => f.Title == "Stop Microsoft Teams from starting with Windows");
        Assert.Contains(teams, f => f.Title == "Stop Microsoft Teams (free) from starting with Windows");
        Assert.Contains(teams, f => f.Title == "Stop Microsoft Teams (classic) from starting with Windows");
        Assert.All(teams, f => { Assert.False(f.DefaultOn); Assert.DoesNotContain(f.Id, s.Approved); });   // opt-in: unticked
        Assert.Contains(s.Fixes, f => f.MemoryTarget == "Spotify" && f.DefaultOn && s.Approved.Contains(f.Id));

        foreach (var name in new[] { "AdobeARMservice", "AGSService" })
        {
            var fix = s.Fixes.Single(f => f.MemoryTarget == name);
            Assert.Equal(MemoryActionType.SetServiceManual, fix.MemoryAction);
            Assert.True(fix.DefaultOn);
            Assert.Contains(fix.Id, s.Approved);
        }
        Assert.DoesNotContain(s.Fixes, f => f.MemoryTarget == "AGMService");                // already Manual: Stop-now only, not in the workflow

        // Still tickable by hand.
        flow.SetApproved(teams[0].Id, true);
        Assert.Contains(teams[0].Id, flow.State.Approved);
    }

    [Fact]
    public async Task AiVmServices_TickedWhenAutomatic_WslShutdownNotListed()
    {
        // #14: Claude / Codex VM services to Manual are ticked; the idle WSL VM shutdown stays on the live page (the workflow restarts the PC).
        static ServiceUsage Use(string name, string start) => new(new(name, name + " display", "RUNNING", start, "LocalSystem", ""), 26L << 20, 1, UsersCanStart: true);
        var snap = new MemorySnapshot(new(16L << 30, 8L << 30), [new AppUsage("vmmemWSL", 1, 2L << 30)],
            Services: [Use("CoworkVMService", "AUTO_START"), Use("CodexSandboxService.OpenAI.Codex_2p2nqf0c97628", "AUTO_START")], TransparencyOn: false);
        var flow = MakeWithMemory(new SnapMem(snap));
        await flow.RunChecksAsync();
        var s = flow.State;
        foreach (var name in new[] { "CoworkVMService", "CodexSandboxService.OpenAI.Codex_2p2nqf0c97628" })
        {
            var fix = s.Fixes.Single(f => f.MemoryTarget == name);
            Assert.Equal(MemoryActionType.SetServiceManual, fix.MemoryAction);
            Assert.True(fix.DefaultOn);
            Assert.Contains(fix.Id, s.Approved);
        }
        Assert.DoesNotContain(s.Fixes, f => f.MemoryAction == MemoryActionType.ShutdownWsl);

        // Already Manual: nothing to do, not listed.
        var manual = snap with { Services = [Use("CoworkVMService", "DEMAND_START")] };
        var flow2 = MakeWithMemory(new SnapMem(manual));
        await flow2.RunChecksAsync();
        Assert.DoesNotContain(flow2.State.Fixes, f => f.MemoryTarget == "CoworkVMService");
    }

    [Fact]
    public void Catalog_CarriesDefaultOn_FromSuggestion()
    {
        MemorySuggestion Sug(string id, bool on) => new(id, id, "why", null, SuggestionRisk.Low, SuggestionKind.Automated, [],
            [new MemoryAction(MemoryActionType.SetServiceManual, id, "Manual")], DefaultOn: on);
        var fixes = FixCatalog.Build([], [Sug("svc-a", true), Sug("svc-b", false)]);
        Assert.True(fixes.Single(f => f.SuggestionId == "svc-a").DefaultOn);
        Assert.False(fixes.Single(f => f.SuggestionId == "svc-b").DefaultOn);
    }

    // ---- the whole run ----
    [Fact]
    public async Task FullRun_OneDecision_ThenRestartBenchmarkApplyRestartBenchmarkReport()
    {
        var (flow, sys, store, delays, launcher, probes) = Make();
        await flow.RunChecksAsync();
        var powerPlanId = flow.State.Fixes.Single(f => f.Remediation?.Kind == RemediationKind.SetBalancedPowerPlan).Id;
        flow.SetApproved(powerPlanId, false);

        Assert.Null(await flow.StartAsync());
        Assert.Equal(WorkflowStage.RestartBefore, flow.State.Stage);
        Assert.Equal(["register", "restart"], sys.Calls);                         // no password asked for or stored
        Assert.True(store.Load()!.SignsInAfterRestart);

        // First restart: Windows booted after the request.
        sys.Uptime = TimeSpan.Zero;
        await flow.ResumeAsync();
        Assert.Equal(WorkflowStage.RestartAfter, flow.State.Stage);
        Assert.Single(delays);                                                     // settled before benchmarking
        Assert.Equal(2, sys.Calls.Count(c => c == "restart"));
        Assert.Equal(2, flow.State.Outcomes.Count);                                // clean + updates (power plan unticked)
        Assert.All(flow.State.Outcomes, o => Assert.True(o.Success, o.Message));
        Assert.DoesNotContain(launcher.Calls, c => c.Args.Contains("/setactive"));

        // Second restart.
        probes.ProgramMs = 200;
        await flow.ResumeAsync();
        var s = flow.State;
        Assert.Equal(WorkflowStage.Done, s.Stage);
        Assert.NotNull(s.ReportPath);
        Assert.Contains("unregister", sys.Calls);
        Assert.Contains("Windows signed the PC back in after each restart by itself", sys.Report);
        Assert.Contains("Program start time", sys.Report);
        Assert.Contains("Left as they were, by choice", sys.Report);
    }

    [Fact]
    public async Task FullRun_ReloadsFromDiskAfterEachRestart_AndDoesNotReplayCompletedFixes()
    {
        var folder = Path.Combine(Path.GetTempPath(), "rpd-workflow-ci-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            var workflowPath = Path.Combine(folder, "workflow.json");
            var benchmarkPath = Path.Combine(folder, "benchmarks.json");
            var first = Make(new FileWorkflowStore(workflowPath), new FileBenchmarkStore(benchmarkPath));
            await first.Flow.RunChecksAsync();
            var skipped = first.Flow.State.Fixes.Single(f => f.Remediation?.Kind == RemediationKind.SetBalancedPowerPlan).Id;
            first.Flow.SetApproved(skipped, false);
            Assert.Null(await first.Flow.StartAsync());

            var second = Make(new FileWorkflowStore(workflowPath), new FileBenchmarkStore(benchmarkPath), first.Sys);
            Assert.Equal(WorkflowStage.RestartBefore, second.Flow.State.Stage);
            second.Sys.Uptime = TimeSpan.Zero;
            await second.Flow.ResumeAsync();
            Assert.Equal(WorkflowStage.RestartAfter, second.Flow.State.Stage);
            Assert.Equal(2, second.Flow.State.Outcomes.Count);
            Assert.All(second.Flow.State.Outcomes, o => Assert.True(o.Success, o.Message));
            Assert.NotNull(new FileBenchmarkStore(benchmarkPath).Load()!.Before);

            var third = Make(new FileWorkflowStore(workflowPath), new FileBenchmarkStore(benchmarkPath), first.Sys,
                new Probes { ProgramMs = 200 });
            await third.Flow.ResumeAsync();
            Assert.Equal(WorkflowStage.Done, third.Flow.State.Stage);
            Assert.Empty(third.Launcher.Calls); // completed fixes were not applied a second time
            Assert.DoesNotContain(second.Launcher.Calls, c => c.Args.Contains("/setactive"));
            var benchmarks = new FileBenchmarkStore(benchmarkPath).Load()!;
            Assert.Equal(300, benchmarks.Before!.Get(BenchmarkKind.ProgramStart)!.Median);
            Assert.Equal(200, benchmarks.After!.Get(BenchmarkKind.ProgramStart)!.Median);
            Assert.Contains("Program start time", third.Sys.Report);
            Assert.Contains("Left as they were, by choice", third.Sys.Report);
            Assert.Contains("unregister", third.Sys.Calls);

            var finished = Make(new FileWorkflowStore(workflowPath), new FileBenchmarkStore(benchmarkPath), first.Sys);
            var calls = first.Sys.Calls.Count;
            await finished.Flow.ResumeAsync();
            Assert.Equal(calls, first.Sys.Calls.Count);
            Assert.Empty(finished.Launcher.Calls);
        }
        finally { Directory.Delete(folder, recursive: true); }
    }

    [Fact]
    public async Task Resume_WithoutARealRestart_Waits()
    {
        var (flow, sys, _, delays, _, _) = Make();
        await flow.RunChecksAsync();
        await flow.StartAsync();
        sys.Uptime = TimeSpan.FromDays(3); // booted long before the request: the restart didn't happen
        await flow.ResumeAsync();
        Assert.Equal(WorkflowStage.RestartBefore, flow.State.Stage);
        Assert.Empty(delays);
        Assert.Contains("Waiting for the restart", flow.Status);
    }

    [Fact]
    public async Task AfterRestart_NewAppInstance_LeavesRestartStageAtOnce_HidesRestartNow_AndOpensWorkflowPage()
    {
        var (flow, sys, store, _, _, _) = Make();
        await flow.RunChecksAsync();
        Assert.False(flow.ShouldOpenWorkflowPage);
        Assert.Null(await flow.StartAsync());
        Assert.Equal(WorkflowStage.RestartBefore, flow.State.Stage);
        Assert.True(flow.WaitingForRestart);                       // before the restart: "Restart now" is offered

        // The PC restarts; a new app instance loads workflow.json and resumes. Hold it in the start-up settle.
        sys.Uptime = TimeSpan.Zero;
        var gate = new TaskCompletionSource();
        var (after, _, _, _, _, _) = Make(flowStore: store, system: sys, delay: (_, _) => gate.Task);
        Assert.True(after.ShouldOpenWorkflowPage);                 // app opens on the Service workflow page
        var restartsBefore = sys.Calls.Count(c => c == "restart");
        var resume = after.ResumeAsync();
        Assert.Equal(WorkflowStage.BeforeBenchmark, after.State.Stage); // not still "RestartBefore" while settling
        Assert.Equal(WorkflowStage.BeforeBenchmark, store.Load()!.Stage);
        Assert.False(after.WaitingForRestart);                     // no stale "Restart now" button
        Assert.Equal("Nothing is waiting for a restart.", await after.RestartNowAsync());
        Assert.Equal(restartsBefore, sys.Calls.Count(c => c == "restart"));
        Assert.NotNull(after.State.Restarts.Last().BootedUtc);
        Assert.NotNull(after.SettleRemaining);
        Assert.Equal(0.0, after.SettleFraction);
        Assert.Contains("3:00 left of 3 min", after.Status);
        gate.SetResult();
        await resume;
        Assert.Null(after.SettleRemaining);
        Assert.Null(after.SettleFraction);
        Assert.Equal(WorkflowStage.RestartAfter, after.State.Stage);
        sys.Uptime = TimeSpan.FromHours(1);                        // the second restart hasn't happened yet
        Assert.True(after.WaitingForRestart);                      // waiting for the second restart again
    }

    [Fact]
    public async Task RestartNotHappenedYet_KeepsRestartNowButton()
    {
        var (flow, sys, _, _, _, _) = Make();
        await flow.RunChecksAsync();
        Assert.Null(await flow.StartAsync());
        sys.Uptime = TimeSpan.FromDays(3);
        await flow.ResumeAsync();
        Assert.Equal(WorkflowStage.RestartBefore, flow.State.Stage);
        Assert.True(flow.WaitingForRestart);
    }

    [Fact]
    public async Task ResumeTaskFails_SaysToTurnOnAdminRepairMode_AndChangesNothing()
    {
        var (flow, sys, _, _, _, _) = Make();
        await flow.RunChecksAsync();
        sys.RegisterOk = false;
        Assert.EndsWith(WorkflowService.NeedsAgentMessage, await flow.StartAsync());
        Assert.Equal(WorkflowStage.Review, flow.State.Stage);
        Assert.DoesNotContain("restart", sys.Calls);
        Assert.DoesNotContain("as administrator", WorkflowService.NeedsAgentMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Cancel_RemovesTask_AbortsRestart()
    {
        var (flow, sys, _, _, _, _) = Make();
        await flow.RunChecksAsync();
        await flow.StartAsync();
        await flow.CancelAsync();
        Assert.Equal(WorkflowStage.Cancelled, flow.State.Stage);
        Assert.Contains("abort", sys.Calls);
        Assert.Contains("unregister", sys.Calls);
    }

    [Fact]
    public void Catalog_StopOnlyServices_AreNeitherFixesNorRecommendations()
    {
        MemorySuggestion Svc(string name, params MemoryActionType[] types) => new($"svc-{name}".ToLowerInvariant(), $"Stop \"{name}\"", "why", 17L << 20,
            SuggestionRisk.Medium, SuggestionKind.Automated, [], types.Select(t => new MemoryAction(t, name, t.ToString())).ToList(), "Services");
        var suggestions = new[]
        {
            Svc("PhoneSvc", MemoryActionType.StopService),                                   // Manual already: Stop now only
            Svc("lfsvc", MemoryActionType.StopService),
            Svc("WSearch", MemoryActionType.StopService, MemoryActionType.SetServiceManual),   // Automatic: a lasting change exists
            new MemorySuggestion("defender", "Exclude folders", "why", null, SuggestionRisk.Low, SuggestionKind.Guided, [], []),
        };
        var fixes = FixCatalog.Build([], suggestions);
        Assert.DoesNotContain(fixes, f => f.MemoryTarget is "PhoneSvc" or "lfsvc");
        Assert.Contains(fixes, f => f.MemoryTarget == "WSearch" && f.MemoryAction == MemoryActionType.SetServiceManual);
        Assert.Equal(["Exclude folders: why"], FixCatalog.Recommendations(suggestions));
        Assert.Empty(FixCatalog.NotOffered([], suggestions));
    }

    [Fact]
    public async Task ReviewTicks_AreRememberedForTheNextRun_AndRecommendedResetsThem()
    {
        var prefs = new RemotePCDiagnostics.Core.Preferences.PreferencesService(new RemotePCDiagnostics.Core.Preferences.MemoryPreferencesStore());
        WorkflowService Flow()
        {
            var results = new ResultStore();
            var diag = new DiagnosticsService(results, DefaultModules());
            var launcher = new ScriptedLauncher((_, _) => ScriptedLauncher.Ok("""{"Count":0}"""));
            var rem = new RemediationService(new SystemCommandRunner(launcher), new SessionContext(SessionMode.Remote));
            var bench = new BenchmarkService(new BenchmarkRunner(new Probes(), resolve: (_, _) => Task.CompletedTask), new MemBenchStore());
            return new WorkflowService(diag, results, rem, bench, new Sys(), new MemFlowStore(), session: new SessionContext(SessionMode.Remote),
                delay: (_, _) => Task.CompletedTask, prefs: prefs);
        }
        var first = Flow();
        await first.RunChecksAsync();
        var plan = first.State.Fixes.Single(f => f.Remediation?.Kind == RemediationKind.SetBalancedPowerPlan).Id;
        first.SetApproved(plan, false);

        var second = Flow();                       // next client visit / app restart
        await second.RunChecksAsync();
        Assert.DoesNotContain(plan, second.State.Approved);
        Assert.Contains(second.State.Approved, id => id != plan); // the others keep their defaults

        second.SetRecommendedApproved();
        Assert.Contains(plan, second.State.Approved);
        var third = Flow();
        await third.RunChecksAsync();
        Assert.Contains(plan, third.State.Approved);
    }

    [Fact]
    public void Report_EncodesText()
    {
        var s = new WorkflowState { Machine = "PC<1>", Findings = ["<script>x</script>"], Outcomes = [new("a", "Fix & go", true, "ok")] };
        var html = ClientReport.Build(s, null, null, BenchmarkComparison.Build(null, null), DateTimeOffset.Now);
        Assert.DoesNotContain("<script>x", html);
        Assert.Contains("&lt;script&gt;", html);
        Assert.Contains("Fix &amp; go", html);
        Assert.Contains("PC&lt;1&gt;", html);
    }

    // ---- the report is a complete record of what the run did ----

    /// <summary>Memory side: Spotify starts with Windows; transparency is suggested only while memory is tight.</summary>
    private sealed class MemSys : IMemorySystem
    {
        public long Available = 4L << 30; // 75% of 16 GB used: transparency suggested
        public bool? Transparency = true;
        public Dictionary<string, byte[]?> Approved = new();
        private static readonly StartupEntry Spotify = new("Spotify", "\"C:\\Users\\user\\AppData\\Roaming\\Spotify\\Spotify.exe\" /minimized", true);
        public MemoryReading ReadMemory() => new(16L << 30, Available);
        public Task<MemorySnapshot> CaptureAsync(IReadOnlyList<ServiceInfo> s, CancellationToken ct) =>
            Task.FromResult(new MemorySnapshot(ReadMemory(), [], Startup: Approved.ContainsKey("Spotify") ? [] : [Spotify], TransparencyOn: Transparency));
        public Task<ActionOutcome> CloseAppAsync(string p, CancellationToken ct) => Task.FromResult(new ActionOutcome(true, ""));
        public Task<ActionOutcome> ForceCloseAppAsync(string p, CancellationToken ct) => Task.FromResult(new ActionOutcome(true, ""));
        public Task<ActionOutcome> RunCommandAsync(string f, IReadOnlyList<string> a, CancellationToken ct) => Task.FromResult(new ActionOutcome(true, ""));
        public byte[]? GetStartupApproved(string n) => null;
        public void SetStartupApproved(string n, byte[]? v) => Approved[n] = v;
        public bool IsBrowserRunning(BrowserKind k) => false;
        public string? ReadBrowserLocalState(BrowserKind k) => null;
        public void WriteBrowserLocalState(BrowserKind k, string json) { }
        public void OpenUri(string uri) { }
        public string GetServiceStartType(string n) => "Automatic";
        public void SetServiceStartType(string n, string t) { }
        public bool? GetTransparency() => Transparency;
        public void SetTransparency(bool on) => Transparency = on;
    }

    private static readonly AreaAction Proxy = new(RemediationKind.DisableSystemProxy, "Turn off the proxy");
    private static readonly AreaAction Dns = new(RemediationKind.SetPublicDns, "Use public DNS", "Wi-Fi", "Wi-Fi");

    /// <summary>Power plan (High performance now), temp files, 3 updates to install. Proxy and DNS: <see cref="FakeSettings"/>.</summary>
    private static ProcessResult FakeWindows(string file, IReadOnlyList<string> args)
    {
        var cmd = string.Join(" ", args);
        if (file.StartsWith("powercfg", StringComparison.OrdinalIgnoreCase))
            return ScriptedLauncher.Ok(args.Contains("/getactivescheme") ? "Power Scheme GUID: 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c  (High performance)" : "");
        if (file == "agent:CleanTemp") return ScriptedLauncher.Ok("""{"RemovedFiles":42,"FreedBytes":524288000}""");
        if (file == "agent:WindowsUpdate") return ScriptedLauncher.Ok("""{"Count":3,"Installed":3,"InstallResult":2,"Titles":["KB5001 Security update","KB5002 .NET update","KB5003 Defender update"]}""");
        return ScriptedLauncher.Ok("");
    }

    /// <summary>Proxy on (turning it off fails), DNS automatic now.</summary>
    private static FakeSystemSettings FakeSettings()
    {
        var s = new FakeSystemSettings { ProxyEnable = 1, DefaultDns = "" };
        s.FailWrites.Add("proxy");
        return s;
    }

    private static (WorkflowService Flow, Sys Sys, IWorkflowStore Store, MemSys Mem, MemoryChangeJournal Journal) MakeFull()
    {
        var journal = new MemoryChangeJournal();
        var mem = new MemSys();
        var (flow, sys, store, _, _, _) = Make(FakeWindows, journal, mem, [
            new AreaModule("ResourceHogs", Report(PowerPlan, Proxy, new AreaAction(RemediationKind.ScheduleCleanRestart, "Restart"), new AreaAction(RemediationKind.EndProcessGroup, "End task", "chrome.exe"))),
            new AreaModule("Network", Report(Dns)),
            new AreaModule("DriveHealth", Report(Clean)),
            new AreaModule("Programs", Report(Updates)),
        ], settings: FakeSettings());
        return (flow, sys, store, mem, journal);
    }

    private static string Id(WorkflowService flow, Func<WorkflowFix, bool> which) => flow.State.Fixes.Single(which).Id;

    [Fact]
    public async Task ReportBox_UndoesOneChange_ThenAppliesTheFixAgain_AndRewritesTheReport()
    {
        var (flow, sys, _, mem, journal) = MakeFull();
        await flow.RunChecksAsync();
        Assert.Null(await flow.StartAsync());
        sys.Uptime = TimeSpan.Zero;
        await flow.ResumeAsync();
        await flow.ResumeAsync();
        Assert.Equal(WorkflowStage.Done, flow.State.Stage);
        Assert.True(flow.CanChangeAfterRun);

        var startup = flow.State.Outcomes.Single(o => o.Changes?.Any(c => c.Text.Contains("Spotify")) == true);
        var change = startup.Changes!.Single(c => c.Text.Contains("Spotify"));
        Assert.Equal(UndoSupport.Full, change.Undo);
        var item = ReportItems.Applied(flow.State).Single(i => i.JournalId == change.JournalId);
        Assert.Equal(ReportTag.Undoable, item.Tag);
        Assert.True(item.CanUndo);
        Assert.Contains($"id=\"change-{change.JournalId:N}\"", flow.State.ReportHtml);
        Assert.Contains("data-tag=\"Undoable\">Can be undone</span>", flow.State.ReportHtml);

        // A permanent change has no Undo.
        var permanent = flow.State.Outcomes.SelectMany(o => o.Changes ?? []).First(c => c.Undo == UndoSupport.None);
        var undo = new UndoService(journal, new SystemCommandRunner(new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""))), mem);
        Assert.Equal("This change is permanent, so it can't be undone.", await flow.UndoChangeAsync(undo, permanent.JournalId));
        Assert.Contains(journal.All, c => c.Id == permanent.JournalId);

        // Undo just the startup app: the journal forgets it, the report marks it undone, the file is saved again.
        await flow.UndoChangeAsync(undo, change.JournalId);
        Assert.DoesNotContain(journal.All, c => c.Id == change.JournalId);
        Assert.NotNull(flow.State.Outcomes.SelectMany(o => o.Changes ?? []).Single(c => c.JournalId == change.JournalId).UndoneUtc);
        Assert.Equal(flow.State.ReportHtml, sys.Report);
        Assert.Contains("data-tag=\"Undone\">Undone", sys.Report);
        Assert.Contains("Already put back after the service", sys.Report);
        Assert.Equal("Already undone.", await flow.UndoChangeAsync(undo, change.JournalId));
        var undone = ReportItems.Applied(flow.State).Single(i => i.JournalId == change.JournalId);
        Assert.Equal(ReportTag.Undone, undone.Tag);
        Assert.True(undone.CanReapply);

        // Apply again: the fix runs again and its new change can be undone again.
        mem.Approved.Remove("Spotify"); // the fake reports Spotify at startup again once it's back
        await flow.ReapplyFixAsync(startup.FixId);
        var again = flow.State.Outcomes.Single(o => o.FixId == startup.FixId).Changes!;
        var redo = Assert.Single(again);
        Assert.Null(redo.UndoneUtc);
        Assert.NotEqual(change.JournalId, redo.JournalId);
        Assert.Contains(journal.All, c => c.Id == redo.JournalId);
        Assert.DoesNotContain("data-tag=\"Undone\"", sys.Report);
    }

    [Fact]
    public void ReportBox_ShowsEachChange_WithItsColourLabelAndButton()
    {
        var now = DateTimeOffset.Now;
        var state = new WorkflowState
        {
            Stage = WorkflowStage.Done, StartedUtc = now.AddMinutes(-35), FinishedUtc = now, ReviewedUtc = now.AddMinutes(-40), ChangesTracked = true, Machine = "DESKTOP-TEST01",
            ReviewRulesVersion = WorkflowService.CurrentReviewRulesVersion,
            Fixes =
            [
                new("startup", "Stop Spotify starting with Windows", "", "Startup", SuggestionRisk.Low, FixSource.Remediation, 1),
                new("dns", "Use public DNS on Wi-Fi", "", "Network", SuggestionRisk.Low, FixSource.Remediation, 2),
                new("weather", "Remove Weather", "", "Apps", SuggestionRisk.Low, FixSource.Memory, 3, Undo: UndoSupport.Reinstall),
                new("updates", "Install Windows updates", "", "Updates", SuggestionRisk.Low, FixSource.Remediation, 4, Undo: UndoSupport.None),
                new("flush", "Flush DNS cache", "", "Network", SuggestionRisk.Low, FixSource.Remediation, 5, Undo: UndoSupport.NothingToUndo),
                new("transparency", "Turn off transparency effects", "", "Display", SuggestionRisk.Low, FixSource.Memory, 6),
                new("clips", "Remove Clipchamp", "", "Apps", SuggestionRisk.Low, FixSource.Memory, 7, Undo: UndoSupport.Reinstall),
            ],
            Approved = ["startup", "dns", "weather", "updates", "flush", "transparency", "clips"],
            Outcomes =
            [
                new("startup", "Stop Spotify starting with Windows", true, "Spotify won't start with Windows.", Changes: [new(Guid.NewGuid(), "Spotify won't start with Windows", UndoSupport.Full)]),
                new("dns", "Use public DNS on Wi-Fi", true, "Public DNS set.", Changes: [new(Guid.NewGuid(), "Public DNS set on Wi-Fi (was automatic)", UndoSupport.Full, now.AddMinutes(2))]),
                new("weather", "Remove Weather", true, "Weather removed.", Changes: [new(Guid.NewGuid(), "Removed Weather (Microsoft.BingWeather)", UndoSupport.Reinstall)]),
                new("clips", "Remove Clipchamp", true, "Clipchamp removed.", Changes: [new(Guid.NewGuid(), "Removed Clipchamp (Clipchamp.Clipchamp)", UndoSupport.Reinstall, now.AddMinutes(3))]),
                new("updates", "Install Windows updates", true, "Installed 2 of 2 Windows update(s)", Changes: [new(Guid.NewGuid(), "Installed KB5001 Security update, KB5002 .NET update", UndoSupport.None)]),
                new("flush", "Flush DNS cache", true, "DNS cache flushed."),
                new("transparency", "Turn off transparency effects", true, "Not needed any more after the restart.", Skipped: true),
            ],
        };
        state = state with { ReportPath = @"C:\Users\Public\Documents\Remote PC Diagnostics\Service report 2026-11-21.html" };
        var html = ClientReport.Build(state, null, null, BenchmarkComparison.Build(null, null), now);
        state = state with { ReportHtml = html };
        var store = new MemFlowStore { State = state };
        var (flow, _, _, _, _, _) = Make(store);
        Assert.NotNull(flow.State.Outcomes.Single(o => o.FixId == "dns").Changes![0].UndoneUtc); // survives the JSON round trip
        using var ctx = new Bunit.BunitContext();
        ctx.JSInterop.Mode = Bunit.JSRuntimeMode.Loose;
        ctx.Services.AddSingleton(flow);
        var cut = ctx.Render<RemotePCDiagnostics.UI.Shared.WorkflowReportBox>(ps => ps.Add(x => x.Html, html));
        Assert.Null(cut.FindAll("[data-testid='wf-report']").FirstOrDefault()); // the full report only on request
        // Grouped by category in first-appearance order: Startup, Network (dns, flush), Apps (weather, clips), Updates, Display.
        Assert.Equal(["Startup", "Network", "Apps", "Updates", "Display"], cut.FindAll("[data-testid='wf-change-group']").Select(g => g.GetAttribute("data-area-key")));
        Assert.Equal(["undo", "reapply", "reinstall", "reapply"], cut.FindAll("[data-testid^='wf-change-']").Where(b => b.TagName == "BUTTON").Select(b => b.GetAttribute("data-action")));
        Assert.Equal(["Undo", "Apply again", "Reinstall", "Remove again"], cut.FindAll("button[data-testid^='wf-change-']").Select(b => b.TextContent.Trim()));
        Assert.Equal(["Undoable", "Undone", "NothingToUndo", "Reinstallable", "Undone", "Permanent", "Skipped"], cut.FindAll("[data-testid='wf-change']").Select(li => li.GetAttribute("data-tag")));
        // A row with a button has no label pill too; the rest keep theirs.
        Assert.Equal(["Nothing to undo", "Permanent", "Skipped"], cut.FindAll("[data-testid='wf-change-label']").Select(x => x.TextContent.Trim()));

        // The summary pills filter the list; pressing the same one again (or Show all) shows every row.
        Assert.Equal(["Undoable", "Reinstallable", "Permanent", "NothingToUndo", "Undone", "Skipped"], cut.FindAll("[data-testid='wf-filter']").Select(b => b.GetAttribute("data-tag")));
        cut.Find("[data-testid='wf-filter'][data-tag='Undone']").Click();
        Assert.Equal(["dns", "clips"], cut.FindAll("[data-testid='wf-change']").Select(li => li.GetAttribute("data-fix-id")));
        Assert.Equal("true", cut.Find("[data-testid='wf-filter'][data-tag='Undone']").GetAttribute("aria-pressed"));
        Assert.Equal(["Apply again", "Remove again"], cut.FindAll("button[data-testid^='wf-change-']").Select(b => b.TextContent.Trim()));
        cut.Find("[data-testid='wf-filter'][data-tag='Undone']").Click();
        Assert.Equal(7, cut.FindAll("[data-testid='wf-change']").Count);
        cut.Find("[data-testid='wf-filter'][data-tag='Permanent']").Click();
        Assert.Equal(["updates"], cut.FindAll("[data-testid='wf-change']").Select(li => li.GetAttribute("data-fix-id")));
        cut.Find("[data-testid='wf-filter-clear']").Click();
        Assert.Equal(7, cut.FindAll("[data-testid='wf-change']").Count);
        Assert.Empty(cut.FindAll("[data-testid='wf-filter-clear']"));
        cut.Find("[data-testid='wf-toggle-preview']").Click();
        Assert.NotNull(cut.Find("[data-testid='wf-report']"));
    }

    [Fact]
    public void ReportBox_GroupsByCategory_AndNestsMultiChangeFixes()
    {
        var now = DateTimeOffset.Now;
        var defenderChanges = Enumerable.Range(1, 7)
            .Select(i => new FixChange(Guid.NewGuid(), $@"Defender no longer scans C:\src\repo{i}", UndoSupport.Full))
            .ToList();
        var state = new WorkflowState
        {
            Stage = WorkflowStage.Done, StartedUtc = now.AddMinutes(-10), FinishedUtc = now, ReviewedUtc = now.AddMinutes(-15), ChangesTracked = true, Machine = "DESKTOP-TEST01",
            ReviewRulesVersion = WorkflowService.CurrentReviewRulesVersion,
            Fixes =
            [
                new("browser-ext", "Turn off MSN New Tab in Chrome", "", "Browser", SuggestionRisk.Low, FixSource.Memory, 1),
                new("office-start", "Skip the Office start screen", "", "Office", SuggestionRisk.Low, FixSource.Memory, 2),
                new("defender", "Stop Defender rescanning code and build folders", "", "Windows", SuggestionRisk.Medium, FixSource.Memory, 3),
            ],
            Approved = ["browser-ext", "office-start", "defender"],
            Outcomes =
            [
                new("browser-ext", "Turn off MSN New Tab in Chrome", true, "Done.", Changes: [new(Guid.NewGuid(), "MSN New Tab turned off in Chrome", UndoSupport.Full)]),
                new("office-start", "Skip the Office start screen", true, "Done.", Changes:
                [
                    new(Guid.NewGuid(), "Word start screen turned off", UndoSupport.Full),
                    new(Guid.NewGuid(), "Excel start screen turned off", UndoSupport.Full),
                    new(Guid.NewGuid(), "PowerPoint start screen turned off", UndoSupport.Full),
                ]),
                new("defender", "Stop Defender rescanning code and build folders", true, "Done.", Changes: defenderChanges),
            ],
        };
        var store = new MemFlowStore { State = state };
        var (flow, _, _, _, _, _) = Make(store);
        using var ctx = new Bunit.BunitContext();
        ctx.JSInterop.Mode = Bunit.JSRuntimeMode.Loose;
        ctx.Services.AddSingleton(flow);

        var cut = ctx.Render<RemotePCDiagnostics.UI.Shared.WorkflowReportBox>(ps => ps.Add(x => x.Html, "<html/>"));

        // Categories appear as top-level tree groups (all open by default).
        var groups = cut.FindAll("[data-testid='wf-change-group']");
        Assert.Equal(["Browser", "Office", "Windows"], groups.Select(g => g.GetAttribute("data-area-key")));
        Assert.All(groups, g => Assert.True(g.HasAttribute("open")));

        // Single-item fix (Browser) is a direct row; multi-item fixes (Office, Defender) are nested sub-groups.
        var fixGroups = cut.FindAll("[data-testid='wf-change-fix-group']");
        Assert.Equal(["office-start", "defender"], fixGroups.Select(g => g.GetAttribute("data-fix-id")));
        // 3 items <= threshold (5): open by default; 7 items > threshold (5): collapsed by default.
        Assert.True(fixGroups[0].HasAttribute("open"));
        Assert.False(fixGroups[1].HasAttribute("open"));

        // Expand all opens everything; clicking again collapses everything.
        Assert.Equal("Expand all", cut.Find("[data-testid='wf-changes-expand-all']").TextContent.Trim());
        cut.Find("[data-testid='wf-changes-expand-all']").Click();
        Assert.Equal("Collapse all", cut.Find("[data-testid='wf-changes-expand-all']").TextContent.Trim());
        Assert.All(cut.FindAll("[data-testid='wf-change-fix-group']"), g => Assert.True(g.HasAttribute("open")));
        cut.Find("[data-testid='wf-changes-expand-all']").Click();
        Assert.All(cut.FindAll("[data-testid='wf-change-group']"), g => Assert.False(g.HasAttribute("open")));
    }

    [Fact]
    public void ReportItems_Tags_EachChange_WithColourAndLabel()
    {
        var s = new WorkflowState
        {
            ChangesTracked = true,
            Fixes = [new("a", "A", "", "X", SuggestionRisk.Low, FixSource.Remediation, 1), new("r", "R", "", "X", SuggestionRisk.Low, FixSource.Memory, 2)],
            Outcomes =
            [
                new("a", "A", true, "ok", Changes: [new(Guid.NewGuid(), "one", UndoSupport.Full), new(Guid.NewGuid(), "two", UndoSupport.None)]),
                new("r", "R", true, "ok", Changes: [new(Guid.NewGuid(), "app", UndoSupport.Reinstall, DateTimeOffset.UtcNow)]),
                new("s", "S", true, "skipped", Skipped: true),
            ],
        };
        var items = ReportItems.Applied(s);
        Assert.Equal([ReportTag.Undoable, ReportTag.Permanent, ReportTag.Undone], items.Select(i => i.Tag));
        Assert.Equal("Reinstalled", ReportItems.Label(items[2].Tag, items[2].WasReinstall));
        Assert.True(items[2].CanReapply);                       // every change it can put back is put back
        Assert.False(items[0].CanReapply);
        Assert.Equal(["undo", "perm", "none"], items.Select(i => ReportItems.Css(i.Tag)));
        var html = ClientReport.Build(s, null, null, BenchmarkComparison.Build(null, null), DateTimeOffset.Now);
        Assert.Contains("data-tag=\"Skipped\">Skipped</span>", html);
        Assert.Contains("data-tag=\"Undone\">Reinstalled ", html);
        Assert.Contains("report-legend", html);
    }

    [Fact]
    public async Task FullRun_Report_RecordsEveryChange_Failure_Skip_Unticked_SideEffects_Undo_AndBenchmarks()
    {
        var (flow, sys, store, mem, journal) = MakeFull();
        journal.Add(ChangeRecord.New(ChangeKind.ServiceStartType, "WSearch", "Automatic", "Windows Search set to Manual", "Local technician")); // from an earlier visit
        await flow.RunChecksAsync();
        Assert.Contains(flow.State.Fixes, f => f.MemoryAction == MemoryActionType.DisableStartup);
        Assert.Contains(flow.State.Fixes, f => f.MemoryAction == MemoryActionType.DisableTransparency);
        flow.SetApproved(Id(flow, f => f.Remediation?.Kind == RemediationKind.SetBalancedPowerPlan), false); // un-ticked by the tech

        Assert.Null(await flow.StartAsync());
        sys.Uptime = TimeSpan.Zero;
        mem.Available = 12L << 30; // fresh boot: memory isn't tight any more, so transparency is no longer suggested (skipped)
        await flow.ResumeAsync();
        Assert.Equal(WorkflowStage.RestartAfter, flow.State.Stage);
        await flow.ResumeAsync();
        var s = flow.State;
        Assert.Equal(WorkflowStage.Done, s.Stage);
        var html = sys.Report!;
        Assert.Equal(html, s.ReportHtml);                                             // page shows exactly the saved file
        Assert.DoesNotContain("secret", store.Load()!.ToJson());

        // Each approved fix with its real result.
        Assert.Contains(s.Outcomes, o => o.Success && o.Message.Contains("Installed 3 of 3 Windows update(s): KB5001 Security update, KB5002 .NET update, KB5003 Defender update"));
        Assert.Contains("Installed 3 of 3 Windows update(s): KB5001 Security update, KB5002 .NET update, KB5003 Defender update", html);
        Assert.Contains("Cleaned 42 temporary file(s)", html);
        Assert.Contains("Spotify won&#39;t start with Windows", html);
        Assert.Contains("Cloudflare (1.1.1.1) and Google (8.8.8.8)", html);
        Assert.Contains("Public DNS set on Wi-Fi (was automatic)", html);   // old → new
        // The failure, the skip and the un-ticked fix.
        var proxy = s.Outcomes.Single(o => o.FixId == Id(flow, f => f.Remediation?.Kind == RemediationKind.DisableSystemProxy));
        Assert.False(proxy.Success);
        Assert.Empty(proxy.Changes!);                                                  // nothing journaled for a failed change
        Assert.Contains("Couldn't be applied", html);
        Assert.Contains("Couldn&#39;t disable the system proxy.", html);
        var transparency = s.Outcomes.Single(o => o.FixId == Id(flow, f => f.MemoryAction == MemoryActionType.DisableTransparency));
        Assert.True(transparency.Skipped);
        Assert.Contains("<h2>Skipped</h2>", html);
        Assert.Contains("Not needed any more after the restart.", html);
        Assert.Contains("Left as they were, by choice", html);
        Assert.Contains(E(s.Fixes.Single(f => f.Remediation?.Kind == RemediationKind.SetBalancedPowerPlan).Title), html);
        // Found but not offered, with why.
        Assert.Contains("Found but not done by the service", html);
        Assert.Contains("End task (chrome.exe): not needed, the restart closes it.", html);
        Assert.Contains("the service restarts the PC itself", html);

        // The workflow's own side effects.
        Assert.Equal(2, s.Restarts.Count);
        Assert.All(s.Restarts, r => { Assert.True(r.Accepted); Assert.NotNull(r.BootedUtc); });
        Assert.Equal(2, CountOf(html, "Restarted the PC at "));
        Assert.Contains("Windows signed the PC back in after each restart by itself. The service never asked for or stored a password.", html);
        Assert.Contains(WorkflowService.ResumeTaskName, html);
        Assert.Contains("removed it again at the end", html);
        Assert.Contains(@"This report was saved on this PC: C:\Users\Public\Documents\Remote PC Diagnostics\Service report.html", html);
        Assert.DoesNotContain("class=\"alert\"", html);

        // Undo: every journal entry written during the run is in the report, and every recorded change is in the journal.
        var fromRun = journal.All.Where(c => c.Target != "WSearch").ToList();
        Assert.Equal(4, fromRun.Count); // startup app, temp files, DNS, permanent update record
        var recorded = s.Outcomes.SelectMany(o => o.Changes ?? []).ToList();
        Assert.Equal(fromRun.Select(c => c.Id).OrderBy(x => x), recorded.Select(c => c.JournalId).OrderBy(x => x));
        foreach (var c in recorded) Assert.Contains(E(c.Text), html);
        Assert.Contains(recorded, c => c.Undo == UndoSupport.None && c.Text.Contains("KB5001"));
        Assert.Contains(recorded, c => c.Undo == UndoSupport.None && c.Text.Contains("Temporary files"));
        Assert.Contains("Undoing changes", html);
        Assert.Contains("Can be put back exactly as it was", html);
        Assert.Contains("Can't be undone (for example", html);
        Assert.DoesNotContain("placeholder", html);
        Assert.Contains("--undo-all", html);
        Assert.Contains("Undo all changes", html);
        Assert.Equal(1, s.EarlierChanges);
        Assert.Contains("also puts back 1 earlier change this app made", html);

        // Benchmarks before/after.
        Assert.Contains("<h2>Before and after</h2><table>", html);
        Assert.Contains("Program start time", html);
    }

    [Fact]
    public async Task WhenWindowsDoesNotSignBackIn_TheWorkflowStillStarts_AndTheReportSaysSomeoneSignedIn()
    {
        var (flow, sys, _, _, _, _) = Make();
        sys.SignIn = new(false, false);
        Assert.False(flow.RestartSignIn().SignsInBySelf);
        await flow.RunChecksAsync();
        Assert.Null(await flow.StartAsync());
        Assert.False(flow.State.SignsInAfterRestart);
        sys.Uptime = TimeSpan.Zero;
        await flow.ResumeAsync();
        await flow.ResumeAsync();
        Assert.Equal(WorkflowStage.Done, flow.State.Stage);
        Assert.Contains("Someone signed in after each restart. The service never asked for or stored a password.", sys.Report);
    }

    [Fact]
    public async Task TaskNotRemoved_ReportSaysSo()
    {
        var (flow, sys, _, _, _, _) = Make();
        await flow.RunChecksAsync();
        await flow.StartAsync();
        sys.RemoveOk = false;
        sys.Uptime = TimeSpan.Zero;
        await flow.ResumeAsync();
        await flow.ResumeAsync();
        Assert.False(flow.State.ResumeTaskRemoved);
        Assert.Contains("A scheduled task was left behind.", sys.Report);
        Assert.Contains("never asked for or stored a password", sys.Report);
    }

    [Fact]
    public async Task Cancel_AfterFixes_WritesReport_WithAppliedFixes_Restore_AndNoComparison()
    {
        var (flow, sys, _, _, journal) = MakeFull();
        await flow.RunChecksAsync();
        await flow.StartAsync();
        sys.Uptime = TimeSpan.Zero;
        await flow.ResumeAsync();                                                     // before benchmark + fixes; waiting for the 2nd restart
        await flow.CancelAsync();
        var s = flow.State;
        Assert.Equal(WorkflowStage.Cancelled, s.Stage);
        Assert.True(s.RestartAborted);
        var html = sys.Report!;
        Assert.Equal(html, s.ReportHtml);
        Assert.Contains("Service stopped before it finished", html);
        Assert.Contains("the service stopped before the after measurement", html);
        Assert.Contains("called off when the service was cancelled", html);
        Assert.Contains("never asked for or stored a password", html);
        Assert.Contains("Fixes applied before the service stopped stay in place", html);
        foreach (var c in journal.All) Assert.Contains(E(Undoability.Describe(c)), html);
    }

    [Fact]
    public void Report_BeforeStart_HasNoSideEffectSection_AndUndoTextFollowsTheFix()
    {
        var fixes = new List<WorkflowFix>
        {
            new("a", "Rescan devices", "", "Drivers", SuggestionRisk.Low, FixSource.Remediation, 1, Undo: UndoSupport.NothingToUndo),
            new("b", "Enable the webcam", "", "Drivers", SuggestionRisk.Low, FixSource.Remediation, 2, Undo: UndoSupport.None),
        };
        var s = new WorkflowState { Fixes = fixes, Approved = ["a", "b"], Outcomes = [new("a", "Rescan devices", true, "Scanned."), new("b", "Enable the webcam", true, "Enabled webcam")] };
        var html = ClientReport.Build(s, null, null, BenchmarkComparison.Build(null, null), DateTimeOffset.Now);
        Assert.DoesNotContain("What the service itself did", html);
        Assert.Contains("data-tag=\"NothingToUndo\">Nothing to undo</span>", html);
        Assert.Contains("Undo: can't be undone.", html);
        Assert.Contains("data-tag=\"Permanent\">Permanent</span>", html);       // no journal to read: go by the fix
        Assert.Contains("The before measurement couldn&#39;t be taken", html);
    }

    [Fact]
    public void Describe_ShowsOldValues()
    {
        Assert.Equal("Power plan switched to Balanced (was High performance)",
            Undoability.Describe(ChangeRecord.New(ChangeKind.PowerPlan, "", "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c", "Power plan switched to Balanced", "x")));
        Assert.Equal("Power plan switched to Balanced (was Power saver)",
            Undoability.Describe(ChangeRecord.New(ChangeKind.PowerPlan, "", "a1841308-3541-4fab-bc81-f71556f20b4a", "Power plan switched to Balanced", "x")));
        Assert.Equal("Public DNS set on Wi-Fi (was 192.168.1.1, 8.8.4.4)",
            Undoability.Describe(ChangeRecord.New(ChangeKind.AdapterDns, "Wi-Fi", "192.168.1.1,8.8.4.4", "Public DNS set on Wi-Fi", "x")));
        Assert.Equal("Windows Search set to Manual (was Automatic)",
            Undoability.Describe(ChangeRecord.New(ChangeKind.ServiceStartType, "WSearch", "Automatic", "Windows Search set to Manual", "x")));
        Assert.Equal("Fast Startup turned off (was on)", Undoability.Describe(ChangeRecord.New(ChangeKind.FastStartup, "", "1", "Fast Startup turned off", "x")));
        Assert.Equal(UndoSupport.None, Undoability.Of(Undoability.Permanent("t", "Installed updates", "x")));
    }

    // ---- storage cleanups (#1, #2, #5, #6, #13): one permanent fix per measured category ----

    private sealed class StorageMem : IMemorySystem
    {
        public readonly List<string> Cleaned = [];
        public bool VsCodeOpen = true;
        public readonly IReadOnlyList<StorageCleanupItem> Items =
        [
            new("storage-nuget", "NuGet", "d", 4L << 30, AutoCheckedByDefault: true),
            new("storage-vscode", "VS Code", "d", 3L << 30, AutoCheckedByDefault: true),
            new("storage-playwright", "Playwright", "d", 2L << 30, AutoCheckedByDefault: false),
            new("storage-temp", "Temp", "d", 5L << 30, AutoCheckedByDefault: true),
            new("storage-grok-worktrees", "Worktrees", "d", 7L << 30, AutoCheckedByDefault: false, Category: "Review"),
        ];
        public MemoryReading ReadMemory() => new(16L << 30, 8L << 30);
        public Task<MemorySnapshot> CaptureAsync(IReadOnlyList<ServiceInfo> s, CancellationToken ct) => Task.FromResult(new MemorySnapshot(ReadMemory(), []));
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
        public Task<IReadOnlyList<StorageCleanupItem>> ScanStorageCleanupsAsync(bool refresh, CancellationToken ct) =>
            Task.FromResult<IReadOnlyList<StorageCleanupItem>>(Items.Where(i => !Cleaned.Contains(i.Id)).ToList());
        public Task<RemotePCDiagnostics.Core.Storage.StorageCleanResult> CleanStorageAsync(string id, CancellationToken ct)
        {
            Cleaned.Add(id);
            return Task.FromResult(id == "storage-vscode" && VsCodeOpen
                ? new RemotePCDiagnostics.Core.Storage.StorageCleanResult(id, false, 0, 0, 0, "Skipped: VS Code is open, so nothing was deleted. Close it and run this again.", ["Code"])
                : new RemotePCDiagnostics.Core.Storage.StorageCleanResult(id, true, 1234, 4L << 30, 0, "Freed 4.0 GB (1,234 files deleted)."));
        }
    }

    [Fact]
    public async Task StorageCleanups_OneFixPerCategory_DefaultsFromScan_RunAfterRestart_JournaledAsPermanent()
    {
        var journal = new MemoryChangeJournal();
        var mem = new StorageMem();
        var (flow, sys, _, _, _, _) = Make(null, journal, mem, DefaultModules());
        await flow.RunChecksAsync();
        var storage = flow.State.Fixes.Where(f => f.MemoryAction == MemoryActionType.CleanStorage).ToList();
        Assert.Equal(["storage-nuget", "storage-playwright", "storage-vscode"], storage.Select(f => f.MemoryTarget).OrderBy(x => x));
        Assert.All(storage, f => { Assert.Equal(UndoSupport.None, f.Undo); Assert.Equal("Storage", f.Area); Assert.False(f.NeedsAdmin); });
        Assert.Contains(Id(flow, f => f.MemoryTarget == "storage-nuget"), flow.State.Approved);
        Assert.DoesNotContain(Id(flow, f => f.MemoryTarget == "storage-playwright"), flow.State.Approved); // opt-in
        Assert.Empty(mem.Cleaned); // nothing is deleted before the tech starts the run

        Assert.Null(await flow.StartAsync());
        sys.Uptime = TimeSpan.Zero;
        await flow.ResumeAsync();
        await flow.ResumeAsync();
        var s = flow.State;
        Assert.Equal(WorkflowStage.Done, s.Stage);
        Assert.Equal(["storage-nuget", "storage-vscode"], mem.Cleaned.OrderBy(x => x));
        var nuget = s.Outcomes.Single(o => o.FixId == Id(flow, f => f.MemoryTarget == "storage-nuget"));
        Assert.True(nuget.Success);
        Assert.Contains("Freed 4.0 GB", nuget.Message);
        var change = Assert.Single(nuget.Changes!);
        Assert.Equal(UndoSupport.None, change.Undo);
        Assert.Contains("4.0 GB freed", change.Text);
        var vscode = s.Outcomes.Single(o => o.FixId == Id(flow, f => f.MemoryTarget == "storage-vscode"));
        Assert.True(vscode.Skipped);
        Assert.Empty(vscode.Changes!);
        Assert.Single(journal.All, c => c.Kind == ChangeKind.NotUndoable && c.Label.Contains("4.0 GB freed"));
        Assert.Contains("Freed 4.0 GB", sys.Report!);
    }

    private sealed class SteppedModule(string name, AreaReport report) : IDiagnosticModule
    {
        public string Name => name;
        public Guid Id => TestIds.For(name);
        public event EventHandler<DiagnosticResult>? Updated { add { } remove { } }
        public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct = default) => Task.FromResult(ModuleAvailability.Available);
        public Task<DiagnosticResult> RefreshAsync(IProgress<string>? p, CancellationToken ct = default)
        {
            p.ReportStep(1, 3, "Step one…");
            p.ReportStep(2, 3, "Step two…");
            p.ReportStep(3, 3, "Step three…");
            return Task.FromResult(new DiagnosticResult(name, report.Status, report.Summary, DateTimeOffset.Now, report));
        }
    }

    [Fact]
    public async Task RunChecksAsync_ReportsStepProgressAndPerCheckProgressBars()
    {
        var modules = new IDiagnosticModule[]
        {
            new SteppedModule("Programs", Report(Updates)),
            new AreaModule("DriveHealth", Report(Clean)),
        };
        var (flow, _, _, _, _, _) = Make(null, null, null, modules);
        var seenSteps = new List<(int Step, int Total, string Msg, double Overall)>();
        flow.Changed += () =>
        {
            var prog = flow.CheckItems.FirstOrDefault(c => c.Id == "Programs");
            if (prog is { Status: DiagnosticStatus.Running, HasProgress: true })
                seenSteps.Add((prog.Step, prog.Total, prog.Message, flow.CheckProgressFraction));
        };

        await flow.RunChecksAsync();

        Assert.Equal(3, seenSteps.Count);
        Assert.Equal((1, 3, "Step one…"), (seenSteps[0].Step, seenSteps[0].Total, seenSteps[0].Msg));
        Assert.Equal((2, 3, "Step two…"), (seenSteps[1].Step, seenSteps[1].Total, seenSteps[1].Msg));
        Assert.Equal((3, 3, "Step three…"), (seenSteps[2].Step, seenSteps[2].Total, seenSteps[2].Msg));
        Assert.True(seenSteps[1].Overall > seenSteps[0].Overall);
        Assert.Equal(2, flow.CompletedChecksCount);
        Assert.Equal(2, flow.TotalChecksCount);
        Assert.Equal(1.0, flow.CheckProgressFraction);
        Assert.Contains(flow.State.Log, l => l.Contains("Programs: 1 thing (1 of 2)"));
        Assert.Contains(flow.State.Log, l => l.Contains("DriveHealth: 1 thing (2 of 2)"));
    }

    private sealed class CountingAreaModule(string name, AreaReport report) : IDiagnosticModule
    {
        public int Runs;
        public string Name => name;
        public Guid Id => TestIds.For(name);
        public event EventHandler<DiagnosticResult>? Updated { add { } remove { } }
        public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct = default) => Task.FromResult(ModuleAvailability.Available);
        public Task<DiagnosticResult> RefreshAsync(IProgress<string>? p, CancellationToken ct = default)
        {
            Runs++;
            return Task.FromResult(new DiagnosticResult(name, report.Status, report.Summary, DateTimeOffset.Now, report));
        }
    }

    [Fact]
    public async Task RunChecksAsync_ReusesAlreadyCompletedCheckResults_UnlessForced()
    {
        var mod1 = new CountingAreaModule("Programs", Report(Updates));
        var mod2 = new CountingAreaModule("DriveHealth", Report(Clean));
        var results = new ResultStore();
        var diag = new DiagnosticsService(results, [mod1, mod2]);
        var rem = new RemediationService(new SystemCommandRunner(new ScriptedLauncher((_, _) => ScriptedLauncher.Ok("""{"Count":0}"""))), new SessionContext(SessionMode.Remote));
        var bench = new BenchmarkService(new BenchmarkRunner(new Probes(), resolve: (_, _) => Task.CompletedTask), new MemBenchStore());
        var flow = new WorkflowService(diag, results, rem, bench, new Sys(), new MemFlowStore(), session: new SessionContext(SessionMode.Remote), delay: (_, _) => Task.CompletedTask);

        // Simulate checks already run from the main page (Dashboard / Checks screen).
        await diag.RunAsync("Programs");
        await diag.RunAsync("DriveHealth");
        Assert.Equal(1, mod1.Runs);
        Assert.Equal(1, mod2.Runs);
        Assert.True(flow.HasCompletedCheckModuleResults);

        // Service workflow should reuse the completed check results without re-running the modules.
        await flow.RunChecksAsync();
        Assert.Equal(WorkflowStage.Review, flow.State.Stage);
        Assert.Equal(1, mod1.Runs);
        Assert.Equal(1, mod2.Runs);
        Assert.NotEmpty(flow.State.Fixes);

        // Reset + forceRerun should re-run the modules when explicitly requested.
        flow.Reset();
        await flow.RunChecksAsync(forceRerun: true);
        Assert.Equal(2, mod1.Runs);
        Assert.Equal(2, mod2.Runs);
    }

    [Fact]
    public async Task RunChecksAsync_SkipsATurnedOffCheck_AndDoesNotKeepTheEarlierResult()
    {
        var drive = new CountingAreaModule(ModuleSlugs.DriveHealth, Report(Clean));
        var hogs = new CountingAreaModule(ModuleSlugs.ResourceHogs, Report(PowerPlan));
        var settings = new CheckSettingsService(new MemoryCheckSettingsStore());
        var (flow, _, _, _, _, _) = Make(null, null, null, [hogs, drive], checks: settings);

        await flow.RunChecksAsync();
        Assert.Equal(1, drive.Runs);
        Assert.Equal(1, hogs.Runs);

        settings.SetEnabled(drive.Name, on: false, available: true);
        await flow.RunChecksAsync();

        Assert.Equal(1, drive.Runs);
        Assert.Equal(1, hogs.Runs);
        var skipped = flow.CheckItems.Single(c => c.Id == drive.Name);
        Assert.Equal(DiagnosticStatus.Warning, skipped.Status);
        Assert.Contains("Skipped", skipped.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(flow.State.Findings, f => f.Contains("turned off", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(RowKind.Skipped, CheckRows.KindOf(CheckEnableRules.SkippedResult(drive.Name, drive.Id)));
    }

    private sealed class MemoryCheckSettingsStore : ICheckSettingsStore
    {
        public CheckSettings? State;
        public CheckSettings? Load() => State;
        public void Save(CheckSettings settings) => State = settings;
    }

    private static string E(string s) => System.Net.WebUtility.HtmlEncode(s);
    private static int CountOf(string text, string part) { var n = 0; for (var i = text.IndexOf(part, StringComparison.Ordinal); i >= 0; i = text.IndexOf(part, i + part.Length, StringComparison.Ordinal)) n++; return n; }

    // ---- Windows repair (DISM RestoreHealth / SFC scannow) ----
    private sealed class RepairScript
    {
        public bool DismCorrupt = true, SfcCorrupt = true, Repaired = false, Reboot = false, DismFails = false;
        public List<string> Order = [];
        public ProcessResult Run(string file, IReadOnlyList<string> args)
        {
            if (args.Contains("/ScanHealth"))
                return ScriptedLauncher.Ok(DismCorrupt && !Repaired ? "The component store is repairable.\nThe operation completed successfully." : "No component store corruption detected.\nThe operation completed successfully.");
            if (args.Contains("/verifyonly"))
                return ScriptedLauncher.Ok(SfcCorrupt && !Repaired ? "Windows Resource Protection found integrity violations." : "Windows Resource Protection did not find any integrity violations.");
            if (args.Contains("/RestoreHealth"))
            {
                Order.Add("dism");
                return DismFails ? new ProcessResult(unchecked((int)0x800f081f), "Error: 0x800f081f\nThe source files could not be found.", "")
                    : new ProcessResult(Reboot ? 3010 : 0, "[====100.0%====]\nThe restore operation completed successfully.\nThe operation completed successfully.", "");
            }
            if (args.Contains("/scannow"))
            {
                Order.Add("sfc");
                Repaired = !DismFails;
                return ScriptedLauncher.Ok(DismFails ? "Windows Resource Protection found corrupt files but was unable to fix some of them." : "Windows Resource Protection found corrupt files and successfully repaired them.");
            }
            return ScriptedLauncher.Ok("""{"Count":0}""");
        }
    }

    private static (WorkflowService Flow, Sys Sys, ScriptedLauncher Launcher) MakeRepair(RepairScript script)
    {
        SystemCommandRunner? runner = null;
        var launcher = new ScriptedLauncher(script.Run);
        runner = new SystemCommandRunner(launcher);
        IDiagnosticModule[] modules = [new AreaModule("Programs", Report(Updates)), new DismScanHealthModule(runner), new SfcVerifyOnlyModule(runner)];
        var m = Make(script.Run, null, null, modules);
        return (m.Flow, m.Sys, m.Launcher);
    }

    private static async Task RunWorkflow(WorkflowService flow, Sys sys)
    {
        Assert.Null(await flow.StartAsync());
        sys.Uptime = TimeSpan.Zero;
        await flow.ResumeAsync();
        await flow.ResumeAsync();
        Assert.Equal(WorkflowStage.Done, flow.State.Stage);
    }

    [Fact]
    public async Task Repair_Corruption_OffersBoth_RunsDismThenSfc_ReportsAndRescans()
    {
        var script = new RepairScript();
        var (flow, sys, _) = MakeRepair(script);
        await flow.RunChecksAsync();
        var repairs = flow.State.Fixes.Where(f => f.Remediation?.Kind is RemediationKind.RepairComponentStore or RemediationKind.RepairSystemFiles).ToList();
        Assert.Equal(2, repairs.Count);
        Assert.All(repairs, f => Assert.Contains(f.Id, flow.State.Approved));
        await RunWorkflow(flow, sys);
        Assert.Equal(["dism", "sfc"], script.Order);
        var f = flow.State.RepairFindings;
        Assert.Equal(DiagnosticStatus.Ok, f.Single(x => x.Id == WindowsRepair.DismId).Level);
        var sfc = f.Single(x => x.Id == WindowsRepair.SfcId);
        Assert.Contains("repaired", sfc.Summary);
        Assert.Equal("Exit code 0", sfc.Evidence);
        Assert.Contains(f, x => x.AfterRestart && x.Level == DiagnosticStatus.Ok);
        Assert.Contains("Windows repair", sys.Report);
        Assert.Contains(E(WindowsRepair.DismTitle), sys.Report);
    }

    [Fact]
    public async Task Repair_RescanAfterRestart_IsShownAsRunningStep_AndClearedAfter()
    {
        var script = new RepairScript();
        var (flow, sys, _) = MakeRepair(script);
        await flow.RunChecksAsync();
        var seen = new List<WorkflowRescan>();
        flow.Changed += () => { if (flow.Rescan is { } r && (seen.Count == 0 || seen[^1].Title != r.Title)) seen.Add(r); };
        await RunWorkflow(flow, sys);
        Assert.Equal(2, seen.Count);
        Assert.All(seen, r => Assert.Equal(2, r.Count));
        Assert.Equal(new[] { 1, 2 }, seen.Select(r => r.Number));
        Assert.Null(flow.Rescan);
        Assert.Contains(flow.State.Log, l => l.Contains("Checking again after the restart (1 of 2)"));
    }

    [Fact]
    public async Task Repair_CleanScans_OfferNothing()
    {
        var script = new RepairScript { DismCorrupt = false, SfcCorrupt = false };
        var (flow, _, _) = MakeRepair(script);
        await flow.RunChecksAsync();
        Assert.DoesNotContain(flow.State.Fixes, f => f.Remediation?.Kind is RemediationKind.RepairComponentStore or RemediationKind.RepairSystemFiles);
    }

    [Fact]
    public async Task Repair_RebootRequired_IsRecorded()
    {
        var script = new RepairScript { Reboot = true };
        var (flow, sys, _) = MakeRepair(script);
        await flow.RunChecksAsync();
        await RunWorkflow(flow, sys);
        Assert.True(flow.State.RepairRebootPending);
        Assert.True(flow.State.RepairFindings.Single(x => x.Id == WindowsRepair.DismId).RebootRequired);
    }

    [Fact]
    public async Task Repair_Failure_ReportsErrorWithHint()
    {
        var script = new RepairScript { DismFails = true };
        var (flow, sys, _) = MakeRepair(script);
        await flow.RunChecksAsync();
        await RunWorkflow(flow, sys);
        var dism = flow.State.RepairFindings.Single(x => x.Id == WindowsRepair.DismId);
        Assert.Equal(DiagnosticStatus.Error, dism.Level);
        Assert.Contains("0x800F081F", dism.Summary, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Next step", dism.Summary);
        Assert.Contains(dism.Details, d => d.Label == "DISM log excerpt");
        Assert.Equal(DiagnosticStatus.Error, flow.State.RepairFindings.Single(x => x.Id == WindowsRepair.SfcId).Level);
        Assert.Contains("0x800F081F", sys.Report, StringComparison.OrdinalIgnoreCase);
    }

    private sealed class GatedReinstallMemorySystem : IMemorySystem
    {
        public readonly List<string> Started = [];
        public readonly Dictionary<string, TaskCompletionSource<bool>> Gates = new(StringComparer.OrdinalIgnoreCase);
        public readonly Dictionary<string, TaskCompletionSource<bool>> Entered = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _installed = new(StringComparer.OrdinalIgnoreCase);

        public GatedReinstallMemorySystem(params RemovableAppx[] apps)
        {
            foreach (var app in apps)
            {
                Gates[app.StoreId!] = new(TaskCreationOptions.RunContinuationsAsynchronously);
                Entered[app.StoreId!] = new(TaskCreationOptions.RunContinuationsAsynchronously);
            }
        }

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
        public async Task<WingetResult> RunWingetAsync(WingetCommand command, CancellationToken ct)
        {
            Started.Add(command.StoreId);
            if (Entered.TryGetValue(command.StoreId, out var entered)) entered.TrySetResult(true);
            if (Gates.TryGetValue(command.StoreId, out var gate)) await gate.Task.WaitAsync(ct);
            var app = AppRemoval.Packages.Single(p => p.StoreId == command.StoreId);
            _installed.Add(app.FamilyName);
            return WingetResult.Exited(0);
        }
        public Task<bool?> IsStorePackageInstalledAsync(RemovableAppx app, CancellationToken ct) =>
            Task.FromResult<bool?>(_installed.Contains(app.FamilyName));
    }

    private static (WorkflowService Flow, UndoService Undo, GatedReinstallMemorySystem Mem, Guid WeatherId, Guid ClipsId, Guid TodoId) MakeQueuedReinstallSetup()
    {
        var weather = AppRemoval.Packages.Single(p => p.Id == "bing-weather");
        var clips = AppRemoval.Packages.Single(p => p.Id == "clipchamp");
        var todo = AppRemoval.Packages.Single(p => p.Id == "todo");
        var mem = new GatedReinstallMemorySystem(weather, clips, todo);
        var journal = new MemoryChangeJournal();
        var wRec = StoreReinstall.Record(weather, 1024, "tech");
        var cRec = StoreReinstall.Record(clips, 2048, "tech");
        var tRec = StoreReinstall.Record(todo, 512, "tech");
        journal.Add(wRec);
        journal.Add(cRec);
        journal.Add(tRec);
        var undo = new UndoService(journal, new SystemCommandRunner(new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""))), mem);

        var now = DateTimeOffset.Now;
        var state = new WorkflowState
        {
            Stage = WorkflowStage.Done, StartedUtc = now.AddMinutes(-20), FinishedUtc = now, ReviewedUtc = now.AddMinutes(-25),
            ChangesTracked = true, Machine = "DESKTOP-TEST01", ReviewRulesVersion = WorkflowService.CurrentReviewRulesVersion,
            Fixes =
            [
                new("weather", "Remove Weather", "", "Apps", SuggestionRisk.Low, FixSource.Memory, 1, Undo: UndoSupport.Reinstall),
                new("clips", "Remove Clipchamp", "", "Apps", SuggestionRisk.Low, FixSource.Memory, 2, Undo: UndoSupport.Reinstall),
                new("todo", "Remove Microsoft To Do", "", "Apps", SuggestionRisk.Low, FixSource.Memory, 3, Undo: UndoSupport.Reinstall),
            ],
            Approved = ["weather", "clips", "todo"],
            Outcomes =
            [
                new("weather", "Remove Weather", true, "Weather removed.", Changes: [new(wRec.Id, "Removed Weather", UndoSupport.Reinstall)]),
                new("clips", "Remove Clipchamp", true, "Clipchamp removed.", Changes: [new(cRec.Id, "Removed Clipchamp", UndoSupport.Reinstall)]),
                new("todo", "Remove Microsoft To Do", true, "Microsoft To Do removed.", Changes: [new(tRec.Id, "Removed Microsoft To Do", UndoSupport.Reinstall)]),
            ],
        };
        var store = new MemFlowStore { State = state };
        var (flow, _, _, _, _, _) = Make(null, journal, mem, DefaultModules(), flowStore: store);
        return (flow, undo, mem, wRec.Id, cRec.Id, tRec.Id);
    }

    [Fact]
    public async Task ReportBox_QueuesPostRunChangesSequentially_AndAllowsDequeuing()
    {
        var (flow, undo, mem, wId, cId, tId) = MakeQueuedReinstallSetup();
        var weather = AppRemoval.Packages.Single(p => p.Id == "bing-weather");
        var todo = AppRemoval.Packages.Single(p => p.Id == "todo");

        var t1 = flow.UndoChangeAsync(undo, wId);
        await mem.Entered[weather.StoreId!].Task.WaitAsync(TimeSpan.FromSeconds(5));
        var t2 = flow.UndoChangeAsync(undo, cId);
        var t3 = flow.UndoChangeAsync(undo, tId);

        Assert.True(flow.Busy);
        Assert.False(flow.CanChangeAfterRun);
        Assert.True(flow.CanQueueChangeAfterRun);
        Assert.Equal(PostRunChangeState.Running, flow.GetChangeQueueState(wId.ToString("N")));
        Assert.Equal(PostRunChangeState.Queued, flow.GetChangeQueueState(cId.ToString("N")));
        Assert.Equal(PostRunChangeState.Queued, flow.GetChangeQueueState(tId.ToString("N")));
        Assert.Equal(2, flow.QueuedChangeCount);
        Assert.Single(mem.Started); // only the first one has started

        // Dequeue the second item before it starts.
        Assert.True(flow.DequeueChange(cId.ToString("N")));
        Assert.Equal("Removed from queue.", await t2);
        Assert.Equal(PostRunChangeState.Idle, flow.GetChangeQueueState(cId.ToString("N")));
        Assert.Equal(1, flow.QueuedChangeCount);

        // Finish item 1 -> item 1 flips to Done and item 3 starts automatically.
        mem.Gates[weather.StoreId!].SetResult(true);
        await t1;
        Assert.Equal(PostRunChangeState.Done, flow.GetChangeQueueState("weather"));
        await mem.Entered[todo.StoreId!].Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(PostRunChangeState.Running, flow.GetChangeQueueState(tId.ToString("N")));
        Assert.Equal(0, flow.QueuedChangeCount);

        // Finish item 3 -> queue is drained and Busy clears.
        mem.Gates[todo.StoreId!].SetResult(true);
        await t3;
        Assert.Equal(PostRunChangeState.Done, flow.GetChangeQueueState("todo"));
        Assert.False(flow.Busy);
        Assert.True(flow.CanChangeAfterRun);
        Assert.Equal([weather.StoreId!, todo.StoreId!], mem.Started);
    }

    [Fact]
    public async Task ReportBox_UiShowsQueuedRunningDoneColors_AndClickDequeues()
    {
        var (flow, undo, mem, wId, cId, tId) = MakeQueuedReinstallSetup();
        var weather = AppRemoval.Packages.Single(p => p.Id == "bing-weather");
        var todo = AppRemoval.Packages.Single(p => p.Id == "todo");

        using var ctx = new Bunit.BunitContext();
        ctx.JSInterop.Mode = Bunit.JSRuntimeMode.Loose;
        ctx.Services.AddSingleton(flow);
        ctx.Services.AddSingleton(undo);
        var cut = ctx.Render<RemotePCDiagnostics.UI.Shared.WorkflowReportBox>(ps => ps.Add(x => x.Html, "<html/>"));

        // Click Weather -> starts running immediately.
        cut.Find($"button[data-fix-id='weather']").Click();
        await mem.Entered[weather.StoreId!].Task.WaitAsync(TimeSpan.FromSeconds(5));
        cut.WaitForAssertion(() =>
        {
            var btn = cut.Find("button[data-fix-id='weather']");
            Assert.Equal("running", btn.GetAttribute("data-queue-state"));
            Assert.Contains("wf-act-running", btn.ClassList);
            Assert.True(btn.HasAttribute("disabled"));
            Assert.Equal("Reinstalling…", btn.TextContent.Trim());
        });

        // Click Clipchamp and To Do while Weather is running -> both show queued color and stay clickable.
        cut.Find("button[data-fix-id='clips']").Click();
        cut.Find("button[data-fix-id='todo']").Click();
        cut.WaitForAssertion(() =>
        {
            var cBtn = cut.Find("button[data-fix-id='clips']");
            Assert.Equal("queued", cBtn.GetAttribute("data-queue-state"));
            Assert.Contains("wf-act-queued", cBtn.ClassList);
            Assert.False(cBtn.HasAttribute("disabled"));
            Assert.Equal("Queued ×", cBtn.TextContent.Trim());

            var tBtn = cut.Find("button[data-fix-id='todo']");
            Assert.Equal("queued", tBtn.GetAttribute("data-queue-state"));
            Assert.Contains("wf-act-queued", tBtn.ClassList);
        });

        // Click Clipchamp again while queued -> dequeues it back to idle.
        cut.Find("button[data-fix-id='clips']").Click();
        cut.WaitForAssertion(() =>
        {
            var cBtn = cut.Find("button[data-fix-id='clips']");
            Assert.Equal("idle", cBtn.GetAttribute("data-queue-state"));
            Assert.DoesNotContain("wf-act-queued", cBtn.ClassList);
            Assert.Equal("Reinstall", cBtn.TextContent.Trim());
        });

        // Complete Weather -> turns green (done) as "Remove again", and To Do starts running.
        mem.Gates[weather.StoreId!].SetResult(true);
        await mem.Entered[todo.StoreId!].Task.WaitAsync(TimeSpan.FromSeconds(5));
        cut.WaitForAssertion(() =>
        {
            var wBtn = cut.Find("button[data-fix-id='weather']");
            Assert.Equal("done", wBtn.GetAttribute("data-queue-state"));
            Assert.Contains("wf-act-done", wBtn.ClassList);
            Assert.Equal("Remove again", wBtn.TextContent.Trim());

            var tBtn = cut.Find("button[data-fix-id='todo']");
            Assert.Equal("running", tBtn.GetAttribute("data-queue-state"));
            Assert.Contains("wf-act-running", tBtn.ClassList);
        });

        // Complete To Do -> turns green (done) as "Remove again".
        mem.Gates[todo.StoreId!].SetResult(true);
        cut.WaitForAssertion(() =>
        {
            var tBtn = cut.Find("button[data-fix-id='todo']");
            Assert.Equal("done", tBtn.GetAttribute("data-queue-state"));
            Assert.Contains("wf-act-done", tBtn.ClassList);
            Assert.Equal("Remove again", tBtn.TextContent.Trim());
        });
        Assert.Equal([weather.StoreId!, todo.StoreId!], mem.Started);
    }
}
