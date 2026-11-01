using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Benchmarks;
using RemotePCDiagnostics.Core.Memory;
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
        public bool PasswordOk = true, RegisterOk = true;
        public TimeSpan Uptime { get; set; } = TimeSpan.FromDays(3);
        public string? Report;
        public Task<bool> RegisterResumeAsync(CancellationToken ct) { Calls.Add("register"); return Task.FromResult(RegisterOk); }
        public Task RemoveResumeAsync(CancellationToken ct) { Calls.Add("unregister"); return Task.CompletedTask; }
        public Task<bool> RestartAsync(TimeSpan d, string m, CancellationToken ct) { Calls.Add("restart"); return Task.FromResult(true); }
        public Task AbortRestartAsync(CancellationToken ct) { Calls.Add("abort"); return Task.CompletedTask; }
        public AutoLogonStatus GetAutoLogonStatus() => new("bud", "PC1", false, false);
        public bool ValidateCredentials(string u, string d, string p) { Calls.Add($"validate:{d}\\{u}"); return PasswordOk; }
        public AutoLogonBackup EnableAutoLogon(string u, string d, string p, int n) { Calls.Add($"autologon-on:{n}"); return new("0", "old", "PC1", null); }
        public void DisableAutoLogon(AutoLogonBackup? b) => Calls.Add("autologon-off:" + b?.DefaultUserName);
        public string SaveReport(string html, DateTimeOffset when) { Report = html; Calls.Add("report"); return @"C:\Users\Public\Documents\Remote PC Diagnostics\Service report.html"; }
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

    private static (WorkflowService Flow, Sys Sys, IWorkflowStore Store, List<TimeSpan> Delays, ScriptedLauncher Launcher, Probes Probes) Make(
        IWorkflowStore? flowStore = null, IBenchmarkStore? benchmarkStore = null, Sys? system = null, Probes? benchmarkProbes = null)
    {
        var results = new ResultStore();
        var diag = new DiagnosticsService(results, [
            new AreaModule("ResourceHogs", Report(PowerPlan, new AreaAction(RemediationKind.ScheduleCleanRestart, "Restart"), new AreaAction(RemediationKind.EndProcessGroup, "End task", "chrome.exe"))),
            new AreaModule("DriveHealth", Report(Clean, PowerPlan)),
            new AreaModule("Programs", Report(Updates)),
        ]);
        var launcher = new ScriptedLauncher((file, args) => ScriptedLauncher.Ok(args.Any(a => a.Contains("RemovedFiles")) ? """{"RemovedFiles":42,"FreedBytes":524288000}""" : """{"Count":0}"""));
        var rem = new RemediationService(new SystemCommandRunner(launcher), new SessionContext(SessionMode.Remote));
        var probes = benchmarkProbes ?? new Probes();
        var bench = new BenchmarkService(new BenchmarkRunner(probes, resolve: (_, _) => Task.CompletedTask), benchmarkStore ?? new MemBenchStore());
        if (benchmarkStore?.Load() is null)
            bench.UpdateSettings(new BenchmarkSettings { Runs = 1, IdleSample = TimeSpan.Zero, CpuSingleRun = TimeSpan.FromMilliseconds(50), CpuMultiRun = TimeSpan.FromMilliseconds(50), DiskRun = TimeSpan.Zero });
        var sys = system ?? new Sys();
        var store = flowStore ?? new MemFlowStore();
        var delays = new List<TimeSpan>();
        var flow = new WorkflowService(diag, results, rem, bench, sys, store, session: new SessionContext(SessionMode.Remote),
            delay: (d, _) => { delays.Add(d); return Task.CompletedTask; });
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
    public void Report_EncodesText()
    {
        var s = new WorkflowState { Machine = "PC<1>", Findings = ["<script>x</script>"], Outcomes = [new("a", "Fix & go", true, "ok")] };
        var html = ClientReport.Build(s, null, null, BenchmarkComparison.Build(null, null), DateTimeOffset.Now);
        Assert.DoesNotContain("<script>x", html);
        Assert.Contains("&lt;script&gt;", html);
        Assert.Contains("Fix &amp; go", html);
        Assert.Contains("PC&lt;1&gt;", html);
    }
}
