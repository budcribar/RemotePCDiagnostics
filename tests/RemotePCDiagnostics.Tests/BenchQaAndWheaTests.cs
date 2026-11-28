using System.Collections.Concurrent;
using System.Net;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Benchmarks;
using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Plugins;
using RemotePCDiagnostics.Core.Preferences;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Tests;

public class BenchQaAndWheaTests
{
    private sealed class OnDemandFakeModule(string name, Func<CancellationToken, Task<DiagnosticResult>> run) : IDiagnosticModule
    {
        public string Name => name;
        public Guid Id => TestIds.For(name);
        public bool IncludeInRunAll => false;
        public event EventHandler<DiagnosticResult>? Updated { add { } remove { } }
        public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct = default) =>
            Task.FromResult(ModuleAvailability.Available);
        public Task<DiagnosticResult> RefreshAsync(IProgress<string>? progress, CancellationToken ct = default) =>
            run(ct);
    }

    private sealed class CapturingWorkflowSystem : IWorkflowSystem
    {
        public string? SavedPath { get; private set; }
        public string? SavedHtml { get; private set; }
        public TimeSpan Uptime => TimeSpan.FromHours(2);
        public Task<bool> RegisterResumeAsync(CancellationToken ct) => Task.FromResult(true);
        public Task<bool> RemoveResumeAsync(CancellationToken ct) => Task.FromResult(true);
        public Task<bool> RestartAsync(TimeSpan delay, string message, CancellationToken ct) => Task.FromResult(true);
        public Task AbortRestartAsync(CancellationToken ct) => Task.CompletedTask;
        public RestartSignInStatus GetRestartSignIn() => new(false, true);
        public string ReportFile(DateTimeOffset when) => @"C:\Users\Public\Documents\Remote PC Diagnostics\Service report.html";
        public void SaveReport(string path, string html)
        {
            SavedPath = path;
            SavedHtml = html;
        }
    }

    private sealed class NullWorkflowStore : IWorkflowStore
    {
        public WorkflowState? State { get; private set; }
        public WorkflowState? Load() => State;
        public void Save(WorkflowState state) => State = state;
    }

    private sealed class NullBenchmarkStore : IBenchmarkStore
    {
        public BenchmarkState? State { get; private set; }
        public BenchmarkState? Load() => State;
        public void Save(BenchmarkState state) => State = state;
    }

    private sealed class FastProbes : IBenchmarkProbes
    {
        public BenchmarkConditions ReadConditions() => new(false, 42, "Balanced");
        public Task<IdleSample?> SampleIdleAsync(TimeSpan d, CancellationToken ct) => Task.FromResult<IdleSample?>(new(3, 45));
        public Task<double?> StartProgramAsync(BuiltInProgram p, CancellationToken ct) => Task.FromResult<double?>(120);
        public Task<double?> DiskRandomReadIopsAsync(TimeSpan d, CancellationToken ct) => Task.FromResult<double?>(12000);
        public Task<IReadOnlyList<WinEvent>> ReadBootEventsAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<WinEvent>>([]);
    }

    [Fact]
    public void WheaEvents_UncorrectedEvent18AndCorrectedEvent19_RollUpInBsodHistoryAndCertificate()
    {
        Assert.Contains("Microsoft-Windows-WHEA-Logger", BsodHistoryModule.Query);
        Assert.True(BsodHistoryModule.Query.Length <= HostCapabilities.MaxXPathLength);

        var now = new DateTimeOffset(2026, 11, 12, 15, 0, 0, TimeSpan.Zero);

        var uncorrectedCpu = new WinEvent(
            now.AddDays(-2),
            "System",
            "Microsoft-Windows-WHEA-Logger",
            18,
            2,
            "A fatal hardware error has occurred. Reported by component: Processor Core. Error Source: Machine Check Exception. Error Type: Cache Hierarchy Error.",
            [],
            new Dictionary<string, string> { ["ProcessorAPICID"] = "4", ["ErrorType"] = "Cache Hierarchy Error" });

        Assert.True(BsodHistoryModule.IsWheaEvent(uncorrectedCpu));
        Assert.True(BsodHistoryModule.IsUncorrectedWheaEvent(uncorrectedCpu));
        Assert.Equal("Processor Core / Cache", BsodHistoryModule.WheaComponentHint(uncorrectedCpu));

        var fatalRep = BsodHistoryModule.Build([uncorrectedCpu], [], now);
        Assert.Equal(DiagnosticStatus.Error, fatalRep.Status);
        Assert.Contains("1 uncorrected WHEA hardware error", fatalRep.Summary);
        Assert.Equal(AreaLevel.Ok, fatalRep.Cards.Single(c => c.Id == "bsods").Level);
        Assert.Equal(AreaLevel.Ok, fatalRep.Cards.Single(c => c.Id == "power").Level);
        Assert.Equal(AreaLevel.Ok, fatalRep.Cards.Single(c => c.Id == "minidumps").Level);

        var wheaCard = fatalRep.Cards.Single(c => c.Id == "whea");
        Assert.Equal(AreaLevel.Error, wheaCard.Level);
        Assert.Equal("1 uncorrected error", wheaCard.Headline);
        Assert.Contains("Processor Core / Cache (Event 18)", wheaCard.Rows[0].Values[2]);

        // Recent corrected Event 19 -> Warning; older corrected PCIe Event 17 -> Neutral.
        var correctedRecent = new WinEvent(
            now.AddDays(-3),
            "System",
            "Microsoft-Windows-WHEA-Logger",
            19,
            3,
            "A corrected hardware error has occurred. Reported by component: Processor Core.",
            [],
            new Dictionary<string, string>());
        Assert.False(BsodHistoryModule.IsUncorrectedWheaEvent(correctedRecent));

        var warnRep = BsodHistoryModule.Build([correctedRecent], [], now);
        Assert.Equal(DiagnosticStatus.Warning, warnRep.Status);
        Assert.Equal(AreaLevel.Warning, warnRep.Cards.Single(c => c.Id == "whea").Level);

        var correctedOlderPcie = new WinEvent(
            now.AddDays(-18),
            "System",
            "Microsoft-Windows-WHEA-Logger",
            17,
            3,
            "A corrected hardware error has occurred. Component: PCI Express Root Port.",
            [],
            new Dictionary<string, string>());
        Assert.Equal("PCI Express Root Port", BsodHistoryModule.WheaComponentHint(correctedOlderPcie));
        var olderRep = BsodHistoryModule.Build([correctedOlderPcie], [], now);
        Assert.Equal(DiagnosticStatus.Ok, olderRep.Status);
        Assert.Equal(AreaLevel.Neutral, olderRep.Cards.Single(c => c.Id == "whea").Level);

        // Certificate stability roll-up ignores unrelated user app hangs on CrashesModule when system BSOD/power/WHEA cards are clean.
        var store = new ResultStore();
        store.Set(new DiagnosticResult(ModuleSlugs.Osquery, DiagnosticStatus.Ok, "Hardware collected", now));
        store.Set(new DiagnosticResult(ModuleSlugs.BatteryPower, DiagnosticStatus.Ok, "95% health", now));
        store.Set(new DiagnosticResult(ModuleSlugs.DriveHealth, DiagnosticStatus.Ok, "Healthy", now));
        store.Set(new DiagnosticResult(ModuleSlugs.Sensors, DiagnosticStatus.Ok, "Normal", now));

        var cleanSysRep = BsodHistoryModule.Build([], [], now);
        var crashesWithAppHang = new AreaReport(
            [
                new AreaCard("hangs", "Application hangs", AreaLevel.Warning, "2 hangs", "notepad.exe", ["When", "App"], []),
                .. cleanSysRep.Cards,
            ],
            "2 app hangs",
            DiagnosticStatus.Warning);
        store.Set(new DiagnosticResult(ModuleSlugs.Crashes, DiagnosticStatus.Warning, "2 app hangs", now, crashesWithAppHang));

        var cleanSnap = HardwareQaCertificate.Capture(store, "BENCH-01", now);
        var stabilityClean = cleanSnap.Items.Single(i => i.Id == "stability");
        Assert.Equal(DiagnosticStatus.Ok, stabilityClean.Status);
        Assert.Equal(HardwareQaVerdict.CertifiedPass, cleanSnap.Verdict);

        // Once an uncorrected WHEA error is present, the certificate flags AttentionRequired.
        store.Set(new DiagnosticResult(ModuleSlugs.Crashes, DiagnosticStatus.Error, fatalRep.Summary, now, fatalRep));
        var wheaFailSnap = HardwareQaCertificate.Capture(store, "BENCH-01", now);
        var stabilityFail = wheaFailSnap.Items.Single(i => i.Id == "stability");
        Assert.Equal(DiagnosticStatus.Error, stabilityFail.Status);
        Assert.Contains("WHEA: 1 uncorrected error", stabilityFail.Summary);
        Assert.Equal(HardwareQaVerdict.AttentionRequired, wheaFailSnap.Verdict);
    }

    [Fact]
    public void PhysicalBenchQa_KeyboardRolloverAndDisplayTouch_RollUpOntoCertificateAndChangeHash()
    {
        var now = new DateTimeOffset(2026, 11, 12, 16, 0, 0, TimeSpan.Zero);
        var store = new ResultStore();
        store.Set(new DiagnosticResult(ModuleSlugs.Osquery, DiagnosticStatus.Ok, "Hardware collected", now));
        store.Set(new DiagnosticResult(ModuleSlugs.BatteryPower, DiagnosticStatus.Ok, "91% health", now));
        store.Set(new DiagnosticResult(ModuleSlugs.DriveHealth, DiagnosticStatus.Ok, "Healthy", now));
        store.Set(new DiagnosticResult(ModuleSlugs.Sensors, DiagnosticStatus.Ok, "Temperatures normal", now));

        var svc = new PhysicalBenchQaService();
        int changedCount = 0;
        svc.Changed += () => Interlocked.Increment(ref changedCount);

        var baselineSnap = HardwareQaCertificate.Capture(store, "BENCH-02", now, physicalQa: svc.Current);
        Assert.Equal(HardwareQaVerdict.CertifiedPass, baselineSnap.Verdict);
        Assert.Equal(DiagnosticStatus.NotRun, baselineSnap.Items.Single(i => i.Id == "keyboard").Status);
        Assert.Equal(DiagnosticStatus.NotRun, baselineSnap.Items.Single(i => i.Id == "display").Status);

        svc.Update(s => s with
        {
            KeyboardOutcome = PhysicalCheckOutcome.Passed,
            UniqueKeysPressed = 48,
            PeakKeyRollover = 6,
            DisplayOutcome = PhysicalCheckOutcome.Passed,
            SolidColorsInspected = 6,
            MaxTouchPoints = 10,
        });
        Assert.True(changedCount >= 1);

        var passedSnap = HardwareQaCertificate.Capture(store, "BENCH-02", now, physicalQa: svc.Current);
        Assert.Equal(HardwareQaVerdict.CertifiedPass, passedSnap.Verdict);
        Assert.NotEqual(baselineSnap.VerificationHash, passedSnap.VerificationHash);

        var kbItem = passedSnap.Items.Single(i => i.Id == "keyboard");
        var dispItem = passedSnap.Items.Single(i => i.Id == "display");
        Assert.Equal(DiagnosticStatus.Ok, kbItem.Status);
        Assert.Equal(DiagnosticStatus.Ok, dispItem.Status);

        var decodedHtml = WebUtility.HtmlDecode(HardwareQaCertificate.BuildHtml(passedSnap));
        Assert.Contains("48 keys verified · 6-key rollover", decodedHtml);
        Assert.Contains("6 test patterns inspected · 10-point touch verified", decodedHtml);

        svc.Update(s => s with
        {
            DisplayOutcome = PhysicalCheckOutcome.PassedWithNote,
            DisplayNotes = "Faint 2mm pressure mark near bottom bezel",
        });
        var noteSnap = HardwareQaCertificate.Capture(store, "BENCH-02", now, physicalQa: svc.Current);
        Assert.Equal(HardwareQaVerdict.PassedWithNotes, noteSnap.Verdict);
        Assert.NotEqual(passedSnap.VerificationHash, noteSnap.VerificationHash);
        Assert.Contains("Faint 2mm pressure mark near bottom bezel", WebUtility.HtmlDecode(HardwareQaCertificate.BuildHtml(noteSnap)));

        svc.Update(s => s with { KeyboardOutcome = PhysicalCheckOutcome.Failed, KeyboardNotes = "Dead F8 & G keys" });
        var failSnap = HardwareQaCertificate.Capture(store, "BENCH-02", now, physicalQa: svc.Current);
        Assert.Equal(HardwareQaVerdict.AttentionRequired, failSnap.Verdict);
        Assert.NotEqual(noteSnap.VerificationHash, failSnap.VerificationHash);

        svc.Reset();
        Assert.False(svc.Current.HasAny);
    }

    [Fact]
    public async Task BenchQaRunner_ExecutesChecksIntegrityLocalStressAudioWebcam_SkipsNetworkTest_AndSavesCertificate()
    {
        var store = new ResultStore();
        var ran = new ConcurrentQueue<string>();

        IDiagnosticModule Quick(string slug) => new FakeModule(slug, _ =>
        {
            ran.Enqueue(slug);
            return Task.FromResult(FakeModule.Ok(slug));
        });

        IDiagnosticModule OnDemand(string slug) => new OnDemandFakeModule(slug, _ =>
        {
            ran.Enqueue(slug);
            return Task.FromResult(FakeModule.Ok(slug));
        });

        var cpuStress = new FakeStressModule(ModuleSlugs.CpuStress, "CPU", (_, _) => { ran.Enqueue(ModuleSlugs.CpuStress); return Task.FromResult(FakeModule.Ok(ModuleSlugs.CpuStress)); });
        var memStress = new FakeStressModule(ModuleSlugs.MemoryTest, "Memory", (_, _) => { ran.Enqueue(ModuleSlugs.MemoryTest); return Task.FromResult(FakeModule.Ok(ModuleSlugs.MemoryTest)); });
        var diskStress = new FakeStressModule(ModuleSlugs.DiskSpeed, "Disk", (_, _) => { ran.Enqueue(ModuleSlugs.DiskSpeed); return Task.FromResult(FakeModule.Ok(ModuleSlugs.DiskSpeed)); });
        var gpuStress = new FakeStressModule(ModuleSlugs.GpuStress, "GPU", (_, _) => { ran.Enqueue(ModuleSlugs.GpuStress); return Task.FromResult(FakeModule.Ok(ModuleSlugs.GpuStress)); });
        var netStress = new FakeStressModule(ModuleSlugs.NetworkTest, "Network", (_, _) => { ran.Enqueue(ModuleSlugs.NetworkTest); return Task.FromResult(FakeModule.Ok(ModuleSlugs.NetworkTest)); });

        var diag = new DiagnosticsService(store,
        [
            Quick(ModuleSlugs.Osquery),
            Quick(ModuleSlugs.BatteryPower),
            Quick(ModuleSlugs.DriveHealth),
            Quick(ModuleSlugs.Sensors),
            Quick(ModuleSlugs.Crashes),
            OnDemand(ModuleSlugs.DismScanHealth),
            OnDemand(ModuleSlugs.SfcVerifyOnly),
            cpuStress,
            memStress,
            diskStress,
            gpuStress,
            netStress,
            OnDemand(ModuleSlugs.SpeakerToMic),
            OnDemand(ModuleSlugs.Webcam),
        ]);

        var launcher = new ScriptedLauncher((_, _) => ScriptedLauncher.Ok("""{"Count":0}"""));
        var rem = new RemediationService(new SystemCommandRunner(launcher), new SessionContext(SessionMode.Local), settings: new FakeSystemSettings());
        var bench = new BenchmarkService(new BenchmarkRunner(new FastProbes(), resolve: (_, _) => Task.CompletedTask), new NullBenchmarkStore());
        var sys = new CapturingWorkflowSystem();
        var prefs = new PreferencesService(new MemoryPreferencesStore());
        prefs.Update(p => p with
        {
            Branding = new ShopBranding { ShopName = "Summit Laptop Refurb", WarrantyFooter = "180-Day Bench QA Warranty" }.Normalized(),
        });

        var workflow = new WorkflowService(diag, store, rem, bench, sys, new NullWorkflowStore(), prefs: prefs, session: new SessionContext(SessionMode.Local));
        var physicalQa = new PhysicalBenchQaService();
        physicalQa.Update(s => s with
        {
            KeyboardOutcome = PhysicalCheckOutcome.Passed,
            UniqueKeysPressed = 52,
            PeakKeyRollover = 6,
            DisplayOutcome = PhysicalCheckOutcome.Passed,
            SolidColorsInspected = 6,
        });

        var runner = new BenchQaRunner(diag, store, workflow, prefs, physicalQa);
        await runner.RunIntakeAsync(includeStress: true, includeAudioCamera: true);

        Assert.False(runner.IsRunning);
        Assert.Equal(runner.TotalSteps, runner.CompletedSteps);
        Assert.Equal(1.0, runner.ProgressFraction);

        var executed = ran.ToArray();
        Assert.Contains(ModuleSlugs.Osquery, executed);
        Assert.Contains(ModuleSlugs.Crashes, executed);
        Assert.Contains(ModuleSlugs.DismScanHealth, executed);
        Assert.Contains(ModuleSlugs.SfcVerifyOnly, executed);
        Assert.Contains(ModuleSlugs.CpuStress, executed);
        Assert.Contains(ModuleSlugs.MemoryTest, executed);
        Assert.Contains(ModuleSlugs.DiskSpeed, executed);
        Assert.Contains(ModuleSlugs.GpuStress, executed);
        Assert.Contains(ModuleSlugs.SpeakerToMic, executed);
        Assert.Contains(ModuleSlugs.Webcam, executed);

        // Offline refurbisher benches have no internet: NetworkTest must NOT be executed by BenchQaRunner.
        Assert.DoesNotContain(ModuleSlugs.NetworkTest, executed);
        Assert.Equal(DiagnosticStatus.NotRun, store.Get(ModuleSlugs.NetworkTest).Status);
        Assert.Equal(TimeSpan.FromMinutes(1), Assert.Single(cpuStress.DurationsSeen));

        Assert.NotNull(runner.LastSavedCertificatePath);
        Assert.Equal(sys.SavedPath, runner.LastSavedCertificatePath);
        Assert.NotNull(sys.SavedHtml);

        var decoded = WebUtility.HtmlDecode(sys.SavedHtml!);
        Assert.Contains("CERTIFIED HARDWARE PASS", decoded);
        Assert.Contains("Summit Laptop Refurb", decoded);
        Assert.Contains("52 keys verified · 6-key rollover", decoded);
        Assert.Contains("6 test patterns inspected", decoded);
    }

    [Fact]
    public async Task BenchQaRunner_CancelMidRun_StopsCleanly()
    {
        var store = new ResultStore();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        var slowCheck = new FakeModule(ModuleSlugs.Osquery, async ct =>
        {
            entered.TrySetResult();
            await Task.Delay(TimeSpan.FromSeconds(30), ct);
            return FakeModule.Ok(ModuleSlugs.Osquery);
        });

        var diag = new DiagnosticsService(store, [slowCheck]);
        var runner = new BenchQaRunner(diag, store);

        var runTask = runner.RunIntakeAsync(includeStress: false, includeAudioCamera: false);
        await entered.Task;
        Assert.True(runner.IsRunning);

        runner.Cancel();
        await runTask;

        Assert.False(runner.IsRunning);
        Assert.Equal("Bench QA intake stopped.", runner.Status);
    }

    [Fact]
    public void HardwareQaCertificate_IncludesSecurityAuditAndFixedTableLayoutCss()
    {
        var now = new DateTimeOffset(2026, 11, 14, 12, 0, 0, TimeSpan.Zero);
        var store = new ResultStore();
        store.Set(new DiagnosticResult(ModuleSlugs.Osquery, DiagnosticStatus.Ok, "Hardware collected", now));
        store.Set(new DiagnosticResult(ModuleSlugs.BatteryPower, DiagnosticStatus.Ok, "95% health", now));
        store.Set(new DiagnosticResult(ModuleSlugs.DriveHealth, DiagnosticStatus.Ok, "Healthy", now));
        store.Set(new DiagnosticResult(ModuleSlugs.Sensors, DiagnosticStatus.Ok, "Temps OK", now));

        // When not run
        var snapNotRun = HardwareQaCertificate.Capture(store, "BENCH-SEC-01", now);
        var secItemNotRun = snapNotRun.Items.Single(i => i.Id == "security");
        Assert.Equal(DiagnosticStatus.NotRun, secItemNotRun.Status);
        Assert.Equal("Not run", secItemNotRun.Summary);
        Assert.Equal(HardwareQaVerdict.CertifiedPass, snapNotRun.Verdict);

        // When security audit reports warnings
        store.Set(new DiagnosticResult(ModuleSlugs.SecurityAudit, DiagnosticStatus.Warning, "Score: 78 · 4 warnings", now));
        var snapWarn = HardwareQaCertificate.Capture(store, "BENCH-SEC-01", now);
        var secItemWarn = snapWarn.Items.Single(i => i.Id == "security");
        Assert.Equal(DiagnosticStatus.Warning, secItemWarn.Status);
        Assert.Equal("Score: 78 · 4 warnings", secItemWarn.Summary);
        Assert.Equal(HardwareQaVerdict.PassedWithNotes, snapWarn.Verdict);

        var html = HardwareQaCertificate.BuildHtml(snapWarn);
        Assert.Contains("table{width:100%;table-layout:fixed;border-collapse:collapse;font-size:12.5px}", html);
        Assert.Contains("th:nth-child(1),td:nth-child(1){width:32%}th:nth-child(2),td:nth-child(2){width:16%}th:nth-child(3),td:nth-child(3){width:52%}", html);
        Assert.Contains("td{text-align:left;padding:6px 8px;border-bottom:1px solid #e5e7eb;vertical-align:middle;overflow-wrap:anywhere;word-break:break-word;overflow:hidden}", html);
        Assert.Contains("body{overflow-x:hidden;", html);
        Assert.Contains(".cert-shell{overflow:hidden;", html);
        Assert.Contains(".qr-card{display:flex;align-items:center;gap:10px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:10px;padding:8px 10px;width:270px;flex-shrink:0}", html);
        Assert.Contains(".qr-box{width:84px;height:84px;flex-shrink:0}", html);
        Assert.Contains("Windows security &amp; baseline audit", html);
    }

    [Fact]
    public async Task BenchQaRunner_RunsSecurityAudit_WhenIncluded()
    {
        var store = new ResultStore();
        var ran = new ConcurrentQueue<string>();

        IDiagnosticModule Quick(string slug) => new FakeModule(slug, _ =>
        {
            ran.Enqueue(slug);
            return Task.FromResult(FakeModule.Ok(slug));
        });

        IDiagnosticModule OnDemand(string slug) => new OnDemandFakeModule(slug, _ =>
        {
            ran.Enqueue(slug);
            return Task.FromResult(FakeModule.Ok(slug));
        });

        var diag = new DiagnosticsService(store, [
            Quick(ModuleSlugs.Osquery),
            OnDemand(ModuleSlugs.SecurityAudit),
        ]);

        var runner = new BenchQaRunner(diag, store);
        var task = runner.StartBenchQaAsync(includeStress: false, includeAudioCamera: false, includeSecurityAudit: true);
        await task;

        Assert.False(runner.IsRunning);
        Assert.Equal(runner.TotalSteps, runner.CompletedSteps);
        var executed = ran.ToArray();
        Assert.Contains(ModuleSlugs.Osquery, executed);
        Assert.Contains(ModuleSlugs.SecurityAudit, executed);
        Assert.Equal(DiagnosticStatus.Ok, store.Get(ModuleSlugs.SecurityAudit).Status);
    }

    [Fact]
    public async Task BenchQaRunner_RunsOnlySelectedItems_AndCertificateRendersGroups()
    {
        var store = new ResultStore();
        var ran = new ConcurrentQueue<string>();

        IDiagnosticModule Quick(string slug) => new FakeModule(slug, _ =>
        {
            ran.Enqueue(slug);
            return Task.FromResult(FakeModule.Ok(slug));
        });

        IDiagnosticModule OnDemand(string slug) => new OnDemandFakeModule(slug, _ =>
        {
            ran.Enqueue(slug);
            return Task.FromResult(FakeModule.Ok(slug));
        });

        var diag = new DiagnosticsService(store, [
            Quick(ModuleSlugs.Osquery),
            Quick(ModuleSlugs.BatteryPower),
            OnDemand(ModuleSlugs.CpuStress),
            OnDemand(ModuleSlugs.GpuStress),
            OnDemand(ModuleSlugs.SpeakerToMic),
            OnDemand(ModuleSlugs.Webcam),
            OnDemand(ModuleSlugs.DismScanHealth),
        ]);

        var runner = new BenchQaRunner(diag, store);
        await runner.RunIntakeAsync(["cpu-stress", "webcam"]);

        var executed = ran.ToArray();
        Assert.Contains(ModuleSlugs.CpuStress, executed);
        Assert.Contains(ModuleSlugs.Webcam, executed);
        Assert.DoesNotContain(ModuleSlugs.GpuStress, executed);
        Assert.DoesNotContain(ModuleSlugs.SpeakerToMic, executed);
        Assert.DoesNotContain(ModuleSlugs.DismScanHealth, executed);
        Assert.DoesNotContain(ModuleSlugs.Osquery, executed);

        var snap = HardwareQaCertificate.Capture(store, "BENCH-GROUP-01");
        var html = HardwareQaCertificate.BuildHtml(snap);
        Assert.Contains("data-qa-group=\"Hardware &amp; health\"", html);
        Assert.Contains("data-qa-group=\"Stress tests\"", html);
        Assert.Contains("data-qa-group=\"Audio, camera &amp; interactive I/O\"", html);
        Assert.Contains("data-qa-group=\"Windows &amp; security\"", html);
    }

    [Fact]
    public async Task BenchQaRunner_ExecutesKeyboardAndDisplayInteractiveChecks_WhenRequested()
    {
        var store = new ResultStore();
        var ran = new ConcurrentQueue<string>();
        var interactiveCalls = new List<string>();

        IDiagnosticModule Quick(string slug) => new FakeModule(slug, _ =>
        {
            ran.Enqueue(slug);
            return Task.FromResult(FakeModule.Ok(slug));
        });

        var diag = new DiagnosticsService(store, [Quick(ModuleSlugs.Osquery)]);
        var runner = new BenchQaRunner(diag, store);

        Task WaitInteractive(string section, CancellationToken ct)
        {
            interactiveCalls.Add(section);
            return Task.CompletedTask;
        }

        var task = runner.StartBenchQaAsync(
            includeStress: false,
            includeAudioCamera: false,
            includeSecurityAudit: false,
            includeKeyboard: true,
            includeDisplay: true,
            waitInteractive: WaitInteractive);

        await task;

        Assert.False(runner.IsRunning);
        Assert.Equal(3, runner.TotalSteps); // 1 (osquery) + 1 (keyboard) + 1 (display)
        Assert.Equal(3, runner.CompletedSteps);
        Assert.Equal(["keyboard", "display"], interactiveCalls);
    }

    [Fact]
    public async Task BenchQaRunner_WaitsOnThePersonItself_AndReChecksAFixedItemWithoutStoppingTheRun()
    {
        var store = new ResultStore();
        var crashRuns = 0;
        var diag = new DiagnosticsService(store,
        [
            new FakeModule(ModuleSlugs.Osquery, _ => Task.FromResult(FakeModule.Ok(ModuleSlugs.Osquery))),
            new FakeModule(ModuleSlugs.Crashes, _ => { Interlocked.Increment(ref crashRuns); return Task.FromResult(FakeModule.Ok(ModuleSlugs.Crashes)); }),
        ]);
        var physicalQa = new PhysicalBenchQaService();
        var runner = new BenchQaRunner(diag, store, physicalQa: physicalQa);

        // No page callback: the run owns the wait, so closing the QA page can't stop it.
        var run = runner.StartBenchQaAsync(["hardware", "stability", "keyboard"]);
        await WaitUntil(() => runner.WaitingFor == "keyboard");
        Assert.True(runner.IsRunning);
        Assert.Equal(1, crashRuns);

        // A fix made while the run waits: Re-run checks the item again beside the run.
        await runner.RerunAsync(["stability"]);
        Assert.Equal(2, crashRuns);
        Assert.True(runner.IsRunning);
        Assert.Equal("keyboard", runner.WaitingFor);
        Assert.False(runner.IsRecheckRunning);

        physicalQa.Update(s => s with { KeyboardOutcome = PhysicalCheckOutcome.Passed });
        await run.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.False(runner.IsRunning);
        Assert.Null(runner.WaitingFor);
        Assert.Equal(runner.TotalSteps, runner.CompletedSteps);
    }

    private static async Task WaitUntil(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (!condition())
        {
            if (DateTime.UtcNow > deadline) throw new TimeoutException();
            await Task.Delay(10);
        }
    }

    [Fact]
    public async Task BenchQaRunner_CountsProgressInSelectedItems_AndListsTheOnesThatCantRun()
    {
        var store = new ResultStore();
        IDiagnosticModule Quick(string slug) => new FakeModule(slug, _ => Task.FromResult(FakeModule.Ok(slug)));
        IDiagnosticModule OnDemand(string slug) => new OnDemandFakeModule(slug, _ => Task.FromResult(FakeModule.Ok(slug)));

        // No webcam or speaker-to-mic module on this PC, so those two selected items can't run.
        var diag = new DiagnosticsService(store, [
            Quick(ModuleSlugs.Osquery),
            Quick(ModuleSlugs.BatteryPower),
            OnDemand(ModuleSlugs.CpuStress),
            OnDemand(ModuleSlugs.DismScanHealth),
            OnDemand(ModuleSlugs.SfcVerifyOnly),
        ]);
        var runner = new BenchQaRunner(diag, store);
        var progress = new List<(int Done, int Total)>();
        runner.Changed += () => progress.Add((runner.CompletedItems, runner.RunItemIds.Count));

        await runner.RunIntakeAsync(["hardware", "battery", "cpu-stress", "integrity", "audio", "webcam", "keyboard"]);

        Assert.Equal(["hardware", "battery", "cpu-stress", "keyboard", "integrity"], runner.RunItemIds);
        Assert.Equal(["audio", "webcam"], runner.SkippedItemIds);
        Assert.Equal(runner.RunItemIds.Count, runner.CompletedItems);
        Assert.Equal(1.0, runner.ItemProgressFraction);
        // Progress only goes up, never past the items this run checks; integrity (DISM + SFC, two steps) counts once.
        Assert.All(progress, p => Assert.Equal(5, p.Total));
        Assert.Equal(progress.Select(p => p.Done).Order(), progress.Select(p => p.Done));
    }
}
