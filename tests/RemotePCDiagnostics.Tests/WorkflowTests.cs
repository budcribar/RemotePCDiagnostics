using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Benchmarks;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Memory;
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
        public event EventHandler<DiagnosticResult>? Updated { add { } remove { } }
        public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct = default) => Task.FromResult(ModuleAvailability.Available);
        public Task<DiagnosticResult> RefreshAsync(IProgress<string>? p, CancellationToken ct = default) =>
            Task.FromResult(new DiagnosticResult(name, report.Status, report.Summary, DateTimeOffset.Now, report));
    }

    private sealed class Sys : IWorkflowSystem
    {
        public List<string> Calls = [];
        public bool PasswordOk = true, RegisterOk = true, RemoveOk = true, DisableFails;
        public TimeSpan Uptime { get; set; } = TimeSpan.FromDays(3);
        public string? Report;
        public Task<bool> RegisterResumeAsync(CancellationToken ct) { Calls.Add("register"); return Task.FromResult(RegisterOk); }
        public Task<bool> RemoveResumeAsync(CancellationToken ct) { Calls.Add("unregister"); return Task.FromResult(RemoveOk); }
        public Task<bool> RestartAsync(TimeSpan d, string m, CancellationToken ct) { Calls.Add("restart"); return Task.FromResult(true); }
        public Task AbortRestartAsync(CancellationToken ct) { Calls.Add("abort"); return Task.CompletedTask; }
        public AutoLogonStatus GetAutoLogonStatus() => new("bud", "PC1", false, false);
        public bool ValidateCredentials(string u, string d, string p) { Calls.Add($"validate:{d}\\{u}"); return PasswordOk; }
        public AutoLogonBackup EnableAutoLogon(string u, string d, string p, int n) { Calls.Add($"autologon-on:{n}"); return new("0", "old", "PC1", null); }
        public void DisableAutoLogon(AutoLogonBackup? b)
        {
            Calls.Add("autologon-off:" + b?.DefaultUserName);
            if (DisableFails) throw new UnauthorizedAccessException("Access to the Winlogon key was denied.");
        }
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
        IWorkflowStore? flowStore = null, IBenchmarkStore? benchmarkStore = null, Sys? system = null, Probes? benchmarkProbes = null) =>
        Make(null, null, null, DefaultModules(), flowStore, benchmarkStore, system, benchmarkProbes);

    private static (WorkflowService Flow, Sys Sys, IWorkflowStore Store, List<TimeSpan> Delays, ScriptedLauncher Launcher, Probes Probes) Make(
        Func<string, IReadOnlyList<string>, ProcessResult>? run, IChangeJournal? journal, IMemorySystem? memorySystem, IDiagnosticModule[] modules,
        IWorkflowStore? flowStore = null, IBenchmarkStore? benchmarkStore = null, Sys? system = null, Probes? benchmarkProbes = null)
    {
        var results = new ResultStore();
        var diag = new DiagnosticsService(results, modules);
        var launcher = new ScriptedLauncher(run ?? ((file, args) => ScriptedLauncher.Ok(args.Any(a => a.Contains("RemovedFiles")) ? """{"RemovedFiles":42,"FreedBytes":524288000}""" : """{"Count":0}""")));
        var rem = new RemediationService(new SystemCommandRunner(launcher), new SessionContext(SessionMode.Remote), journal: journal);
        var memory = memorySystem is null ? null : new MemorySuggestionService(memorySystem, session: new SessionContext(SessionMode.Remote), settle: TimeSpan.Zero, remediation: rem, journal: journal);
        var probes = benchmarkProbes ?? new Probes();
        var bench = new BenchmarkService(new BenchmarkRunner(probes, resolve: (_, _) => Task.CompletedTask), benchmarkStore ?? new MemBenchStore());
        if (benchmarkStore?.Load() is null)
            bench.UpdateSettings(new BenchmarkSettings { Runs = 1, IdleSample = TimeSpan.Zero, CpuSingleRun = TimeSpan.FromMilliseconds(50), CpuMultiRun = TimeSpan.FromMilliseconds(50), DiskRun = TimeSpan.Zero });
        var sys = system ?? new Sys();
        var store = flowStore ?? new MemFlowStore();
        var delays = new List<TimeSpan>();
        var flow = new WorkflowService(diag, results, rem, bench, sys, store, memory, session: new SessionContext(SessionMode.Remote),
            delay: (d, _) => { delays.Add(d); return Task.CompletedTask; }, journal: journal);
        return (flow, sys, store, delays, launcher, probes);
    }

    // ---- catalog ----
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
        Assert.NotNull(await flow.StartAsync(null));
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
        var backup = new AutoLogonBackup("0", "old", "PC1", null);
        var store = new MemFlowStore { State = new WorkflowState { Stage = stage, AutoLogonEnabled = true, AutoLogonBackup = backup } };
        var flow = Make(store).Flow;
        Assert.Equal(stage, flow.State.Stage);
        Assert.True(flow.State.AutoLogonEnabled);
        Assert.Equal(backup, flow.State.AutoLogonBackup);
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

        Assert.Null(await flow.StartAsync(new AutoLogonRequest("bud", "PC1", "secret")));
        Assert.Equal(WorkflowStage.RestartBefore, flow.State.Stage);
        Assert.Equal(["validate:PC1\\bud", "autologon-on:2", "register", "restart"], sys.Calls);
        Assert.DoesNotContain("secret", store.Load()!.ToJson());                  // password never saved

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
        Assert.Contains("autologon-off:old", sys.Calls);                          // previous settings restored
        Assert.False(s.AutoLogonEnabled);
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
            Assert.Null(await first.Flow.StartAsync(new AutoLogonRequest("bud", "PC1", "test-secret")));
            Assert.DoesNotContain("test-secret", File.ReadAllText(workflowPath));

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
            Assert.False(third.Flow.State.AutoLogonEnabled);
            Assert.Contains("autologon-off:old", third.Sys.Calls);
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
        await flow.StartAsync(null);
        sys.Uptime = TimeSpan.FromDays(3); // booted long before the request: the restart didn't happen
        await flow.ResumeAsync();
        Assert.Equal(WorkflowStage.RestartBefore, flow.State.Stage);
        Assert.Empty(delays);
        Assert.Contains("Waiting for the restart", flow.Status);
    }

    [Fact]
    public async Task WrongPassword_ChangesNothing()
    {
        var (flow, sys, _, _, _, _) = Make();
        await flow.RunChecksAsync();
        sys.PasswordOk = false;
        Assert.Contains("didn't work", await flow.StartAsync(new AutoLogonRequest("bud", "PC1", "nope")));
        Assert.Equal(WorkflowStage.Review, flow.State.Stage);
        Assert.DoesNotContain(sys.Calls, c => c.StartsWith("autologon-on") || c == "restart");
    }

    [Fact]
    public async Task ResumeTaskFails_AutoLogonRolledBack()
    {
        var (flow, sys, _, _, _, _) = Make();
        await flow.RunChecksAsync();
        sys.RegisterOk = false;
        Assert.NotNull(await flow.StartAsync(new AutoLogonRequest("bud", "PC1", "pw")));
        Assert.Contains("autologon-off:old", sys.Calls);
        Assert.DoesNotContain("restart", sys.Calls);
    }

    [Fact]
    public async Task Cancel_RemovesAutoLogonAndTask_AbortsRestart()
    {
        var (flow, sys, _, _, _, _) = Make();
        await flow.RunChecksAsync();
        await flow.StartAsync(new AutoLogonRequest("bud", "PC1", "pw"));
        await flow.CancelAsync();
        Assert.Equal(WorkflowStage.Cancelled, flow.State.Stage);
        Assert.Contains("abort", sys.Calls);
        Assert.Contains("unregister", sys.Calls);
        Assert.Contains("autologon-off:old", sys.Calls);
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
        private static readonly StartupEntry Spotify = new("Spotify", "\"C:\\Users\\bud\\AppData\\Roaming\\Spotify\\Spotify.exe\" /minimized", true);
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

    /// <summary>Power plan (High performance now), proxy (on; turning it off fails), DNS (automatic now), temp files, 3 updates to install.</summary>
    private static ProcessResult FakeWindows(string file, IReadOnlyList<string> args)
    {
        var cmd = string.Join(" ", args);
        if (file.StartsWith("powercfg", StringComparison.OrdinalIgnoreCase))
            return ScriptedLauncher.Ok(args.Contains("/getactivescheme") ? "Power Scheme GUID: 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c  (High performance)" : "");
        if (cmd.Contains("RemovedFiles")) return ScriptedLauncher.Ok("""{"RemovedFiles":42,"FreedBytes":524288000}""");
        if (cmd.Contains("CreateUpdateSearcher")) return ScriptedLauncher.Ok("""{"Count":3,"Installed":3,"InstallResult":2,"Titles":["KB5001 Security update","KB5002 .NET update","KB5003 Defender update"]}""");
        if (cmd.Contains("ProxyEnable -Value 0")) return ScriptedLauncher.Fail("Access denied");
        if (cmd.Contains("ProxyEnable")) return ScriptedLauncher.Ok("1");
        if (cmd.Contains("NameServer")) return ScriptedLauncher.Ok("");
        return ScriptedLauncher.Ok("");
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
        ]);
        return (flow, sys, store, mem, journal);
    }

    private static string Id(WorkflowService flow, Func<WorkflowFix, bool> which) => flow.State.Fixes.Single(which).Id;

    [Fact]
    public async Task FullRun_Report_RecordsEveryChange_Failure_Skip_Unticked_SideEffects_Undo_AndBenchmarks()
    {
        var (flow, sys, store, mem, journal) = MakeFull();
        journal.Add(ChangeRecord.New(ChangeKind.ServiceStartType, "WSearch", "Automatic", "Windows Search set to Manual", "Local technician")); // from an earlier visit
        await flow.RunChecksAsync();
        Assert.Contains(flow.State.Fixes, f => f.MemoryAction == MemoryActionType.DisableStartup);
        Assert.Contains(flow.State.Fixes, f => f.MemoryAction == MemoryActionType.DisableTransparency);
        flow.SetApproved(Id(flow, f => f.Remediation?.Kind == RemediationKind.SetBalancedPowerPlan), false); // un-ticked by the tech

        Assert.Null(await flow.StartAsync(new AutoLogonRequest("bud", "PC1", "secret")));
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
        Assert.Contains("Turned on automatic sign-in for PC1\\bud", html);
        Assert.Contains("turned it off again", html);
        Assert.NotNull(s.AutoLogonRestoredUtc);
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
        Assert.Contains("Permanent (can't be undone", html);
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
    public async Task AutoLogonNotRestored_ReportAndPageSayItLoudly()
    {
        var (flow, sys, _, _, _, _) = Make();
        await flow.RunChecksAsync();
        await flow.StartAsync(new AutoLogonRequest("bud", "PC1", "pw"));
        sys.DisableFails = true;
        sys.Uptime = TimeSpan.Zero;
        await flow.ResumeAsync();
        await flow.ResumeAsync();
        var s = flow.State;
        Assert.Equal(WorkflowStage.Done, s.Stage);
        Assert.True(s.AutoLogonEnabled);
        Assert.Contains("Access to the Winlogon key was denied.", s.AutoLogonRestoreError);
        var html = sys.Report!;
        Assert.Contains("class=\"alert\"><strong>Important: automatic sign-in could not be turned off.</strong>", html);
        Assert.Contains("to PC1\\bud by itself", html);
        Assert.Contains("could NOT be turned off again", html);
        Assert.DoesNotContain("turned it off again", html);
        Assert.Contains("could NOT be turned off", string.Join("\n", s.Log));
    }

    [Fact]
    public async Task TaskNotRemoved_ReportSaysSo()
    {
        var (flow, sys, _, _, _, _) = Make();
        await flow.RunChecksAsync();
        await flow.StartAsync(null);
        sys.RemoveOk = false;
        sys.Uptime = TimeSpan.Zero;
        await flow.ResumeAsync();
        await flow.ResumeAsync();
        Assert.False(flow.State.ResumeTaskRemoved);
        Assert.Contains("A scheduled task was left behind.", sys.Report);
        Assert.Contains("Automatic sign-in wasn't used", sys.Report);
    }

    [Fact]
    public async Task Cancel_AfterFixes_WritesReport_WithAppliedFixes_Restore_AndNoComparison()
    {
        var (flow, sys, _, _, journal) = MakeFull();
        await flow.RunChecksAsync();
        await flow.StartAsync(new AutoLogonRequest("bud", "PC1", "pw"));
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
        Assert.Contains("turned it off again", html);
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
        Assert.Contains("Undo: nothing lasting to undo.", html);
        Assert.Contains("Undo: permanent, can't be undone.", html);       // no journal to read: go by the fix
        Assert.Contains("The before measurement couldn&#39;t be taken", html);
    }

    [Fact]
    public void Describe_ShowsOldValues()
    {
        Assert.Equal("Power plan switched to Balanced (was High performance)",
            Undoability.Describe(ChangeRecord.New(ChangeKind.PowerPlan, "", "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c", "Power plan switched to Balanced", "x")));
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

        Assert.Null(await flow.StartAsync(null));
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

    private static string E(string s) => System.Net.WebUtility.HtmlEncode(s);
    private static int CountOf(string text, string part) { var n = 0; for (var i = text.IndexOf(part, StringComparison.Ordinal); i >= 0; i = text.IndexOf(part, i + part.Length, StringComparison.Ordinal)) n++; return n; }
}
