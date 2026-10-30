using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.History;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests;

public class RemediationTests
{
    [Fact]
    public async Task Group1_DriverAndWindowsUpdates_And_PnpUtil()
    {
        const string driverUpdateJson = """{"Count":2,"Installed":2,"Titles":["Intel Wi-Fi 6E AX211 23.40.0","Realtek Audio 6.0.9500"]}""";
        var launcher = new ScriptedLauncher((file, args) =>
        {
            if (file.Equals("pnputil.exe", StringComparison.OrdinalIgnoreCase))
                return ScriptedLauncher.Ok("Device restarted.");
            return ScriptedLauncher.Ok(driverUpdateJson);
        });
        var svc = new RemediationService(new SystemCommandRunner(launcher), new SessionContext(SessionMode.Local));

        // 1a. Check & install driver updates
        var drvRes = await svc.ExecuteAsync(new(RemediationKind.CheckAndInstallDriverUpdates, "Check & install driver updates"));
        Assert.True(drvRes.Success);
        Assert.Contains("Installed 2 of 2 driver update(s)", drvRes.Message);
        Assert.Contains("Intel Wi-Fi 6E AX211", drvRes.Message);

        // 1b. Restart a Code 43 device & Enable a Code 22 device
        var devRep = DeviceDriversModule.Build(
            [
                new("NVIDIA RTX 4070", "Display", "PCI\\VEN_10DE", 43, "Error"),
                new("Legacy COM1", "Ports", "ACPI\\PNP0501", 22, "Error"),
            ],
            []);
        var probCard = devRep.Cards.Single(c => c.Id == "problems");
        Assert.Contains(probCard.Actions!, a => a.Kind == RemediationKind.CheckAndInstallDriverUpdates);
        Assert.Contains(probCard.Actions!, a => a.Kind == RemediationKind.ScanHardwareChanges);

        var restartAction = Assert.Single(probCard.Rows[0].Actions!);
        Assert.Equal(RemediationKind.RestartDevice, restartAction.Kind);
        var enableAction = Assert.Single(probCard.Rows[1].Actions!);
        Assert.Equal(RemediationKind.EnableDevice, enableAction.Kind);

        var r1 = await svc.ExecuteAsync(restartAction);
        Assert.True(r1.Success);
        Assert.Equal("Restarted NVIDIA RTX 4070", r1.Message);

        var r2 = await svc.ExecuteAsync(enableAction);
        Assert.True(r2.Success);
        Assert.Equal("Enabled Legacy COM1", r2.Message);
    }

    [Fact]
    public async Task Group2_PowerPlan_FastStartup_And_ProtectedProcessGuard()
    {
        var launcher = new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""));
        var svc = new RemediationService(new SystemCommandRunner(launcher), new SessionContext(SessionMode.Local));

        // 2a. Power saver attaches Switch to Balanced plan
        var batRep = BatteryPowerModule.Build([], "Power saver");
        var planCard = batRep.Cards.Single(c => c.Id == "plan");
        var switchAct = Assert.Single(planCard.Actions!);
        Assert.Equal(RemediationKind.SetBalancedPowerPlan, switchAct.Kind);
        var switchRes = await svc.ExecuteAsync(switchAct);
        Assert.True(switchRes.Success);
        Assert.Contains("Balanced", switchRes.Message);

        // 2b. Uptime >= 14 days with Fast Startup attaches DisableFastStartup & ScheduleCleanRestart
        var hogsRep = ResourceHogsModule.Build(
            new SystemUptimeInfo(1_500_000, 17, 6, 0, FastStartupEnabled: true),
            [
                new("chrome.exe", 1000, 500_000_000, 10_000, 1_000),
                new("svchost.exe", 800, 200_000_000, 5_000, 500),
            ]);
        var upCard = hogsRep.Cards.Single(c => c.Id == "uptime");
        Assert.Contains(upCard.Actions!, a => a.Kind == RemediationKind.DisableFastStartup);
        Assert.Contains(upCard.Actions!, a => a.Kind == RemediationKind.ScheduleCleanRestart);

        var memCard = hogsRep.Cards.Single(c => c.Id == "memory");
        var chromeRow = memCard.Rows.Single(r => r.Values[0] == "chrome.exe");
        var svchostRow = memCard.Rows.Single(r => r.Values[0] == "svchost.exe");
        Assert.NotNull(chromeRow.Actions);
        Assert.Null(svchostRow.Actions); // Protected Windows process has no End Task button

        // Direct attempt to kill a protected process is blocked without calling launcher
        var callsBefore = launcher.Calls.Count;
        var blocked = await svc.ExecuteAsync(new(RemediationKind.EndProcessGroup, "End task", "lsass.exe", "lsass.exe"));
        Assert.False(blocked.Success);
        Assert.Contains("protected by Windows", blocked.Message);
        Assert.Equal(callsBefore, launcher.Calls.Count);

        // Ending chrome.exe succeeds
        var endChrome = await svc.ExecuteAsync(chromeRow.Actions!.Single());
        Assert.True(endChrome.Success);
        Assert.StartsWith("Closed chrome.exe", endChrome.Message);
    }

    [Fact]
    public async Task Group3_NetworkProxy_Dns_And_FlushRenew()
    {
        var launcher = new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""));
        var svc = new RemediationService(new SystemCommandRunner(launcher), new SessionContext(SessionMode.Remote));

        var wifiRep = WifiConfigModule.Build(
            null,
            wlanOk: true,
            new IpConfigSnapshot([new("Wi-Fi", "Intel Wi-Fi", "192.168.1.20", "192.168.1.1", "192.168.1.1")], ProxyEnabled: true, ProxyServer: "127.0.0.1:8888"));

        var ipCard = wifiRep.Cards.Single(c => c.Id == "ipdns");
        Assert.Contains(ipCard.Actions!, a => a.Kind == RemediationKind.DisableSystemProxy);
        Assert.Contains(ipCard.Actions!, a => a.Kind == RemediationKind.FlushDnsAndRenewIp);

        // Remote session plan warns about brief pause during IP renew
        var flushAct = ipCard.Actions!.Single(a => a.Kind == RemediationKind.FlushDnsAndRenewIp);
        var plan = svc.Plan(flushAct);
        Assert.Contains("Remote mode", plan.Warning);

        var proxyRes = await svc.ExecuteAsync(ipCard.Actions!.Single(a => a.Kind == RemediationKind.DisableSystemProxy));
        Assert.True(proxyRes.Success);
        Assert.Equal("Remote technician", svc.Recent.First().Actor);

        var rowActions = ipCard.Rows.Single().Actions!;
        Assert.Equal(2, rowActions.Count);
        var dnsRes = await svc.ExecuteAsync(rowActions.Single(a => a.Kind == RemediationKind.SetPublicDns));
        Assert.True(dnsRes.Success);
        Assert.Contains("1.1.1.1", dnsRes.Message);
    }

    [Fact]
    public async Task Group4_StorageCleanup_And_SsdOptimize()
    {
        const string cleanJson = """{"RemovedFiles":42,"FreedBytes":524288000}""";
        var launcher = new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(cleanJson));
        var svc = new RemediationService(new SystemCommandRunner(launcher), new SessionContext(SessionMode.Local));

        var drvRep = DriveHealthModule.Build(
            [new("Samsung SSD 980", "S1", "SSD", "NVMe", "Healthy", "OK", 1_000_000_000_000, 35, 2, 0, 0, 1000, "C")]);
        var card = Assert.Single(drvRep.Cards);
        Assert.Contains(card.Actions!, a => a.Kind == RemediationKind.CleanTempFiles);
        Assert.Contains(card.Actions!, a => a.Kind == RemediationKind.OptimizeSsd);

        var cleanRes = await svc.ExecuteAsync(card.Actions!.Single(a => a.Kind == RemediationKind.CleanTempFiles));
        Assert.True(cleanRes.Success);
        Assert.Contains("42 temporary file(s)", cleanRes.Message);
        Assert.Contains("500 MB freed", cleanRes.Message);
        Assert.Equal(524_288_000, cleanRes.FreedDiskBytes);
        Assert.Equal(42, cleanRes.RemovedFiles);

        var trimRes = await svc.ExecuteAsync(card.Actions!.Single(a => a.Kind == RemediationKind.OptimizeSsd));
        Assert.True(trimRes.Success);
        Assert.Contains("Optimized / Retrimmed Samsung SSD 980", trimRes.Message);
    }

    [Fact]
    public async Task SsdOptimize_RetrimsTheTargetDrive_NotAlwaysC()
    {
        var launcher = new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""));
        var svc = new RemediationService(new SystemCommandRunner(launcher), new SessionContext(SessionMode.Local));

        var res = await svc.ExecuteAsync(new(RemediationKind.OptimizeSsd, "Optimize / Retrim SSD", "D", "WD Blue SN580"));

        Assert.True(res.Success);
        var script = Assert.Single(launcher.Calls).Args[^1];
        Assert.Contains("-DriveLetter D", script);
        Assert.DoesNotContain("-DriveLetter C", script);
    }

    [Theory]
    [InlineData("msedgewebview2")]
    [InlineData("msedgewebview2.exe")]
    [InlineData("osqueryi")]
    [InlineData("MemTestHelper")]
    [InlineData("LsaIso")]
    public async Task EndTask_IsRefused_ForProcessesTheMemoryPageAlsoProtects(string process)
    {
        var launcher = new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""));
        var svc = new RemediationService(new SystemCommandRunner(launcher), new SessionContext(SessionMode.Local));
        var action = new AreaAction(RemediationKind.EndProcessGroup, "End task", process, process);

        Assert.False(svc.Plan(action).Allowed);
        var res = await svc.ExecuteAsync(action);
        Assert.False(res.Success);
        Assert.Empty(launcher.Calls);
    }

    [Fact]
    public void SsdOptimize_EachDiskTargetsItsOwnVolumes_AndDisksWithoutLettersGetNoButton()
    {
        var rep = DriveHealthModule.Build(
        [
            new("Samsung SSD 980", "S1", "SSD", "NVMe", "Healthy", "OK", 1_000_000_000_000, 35, 2, 0, 0, 1000, "C"),
            new("WD Blue SN580", "S2", "SSD", "NVMe", "Healthy", "OK", 2_000_000_000_000, 33, 1, 0, 0, 500, "DE"),
            new("Crucial MX500", "S3", "SSD", "SATA", "Healthy", "OK", 500_000_000_000, 30, 1, 0, 0, 100, ""),
        ]);
        Assert.Equal("C", rep.Cards[0].Actions!.Single(a => a.Kind == RemediationKind.OptimizeSsd).Target);
        Assert.Equal("DE", rep.Cards[1].Actions!.Single(a => a.Kind == RemediationKind.OptimizeSsd).Target);
        Assert.DoesNotContain(rep.Cards[2].Actions ?? [], a => a.Kind == RemediationKind.OptimizeSsd);
    }

    [Theory]
    [InlineData("C", "C")]
    [InlineData("d:", "D")]
    [InlineData("D,E", "DE")]
    [InlineData("", "")]
    [InlineData("C; Remove-Item", "")]
    public void DriveLetters_OnlyAcceptsLetters(string target, string expected) =>
        Assert.Equal(expected, RemediationService.DriveLetters(target));

    [Fact]
    public async Task SsdOptimize_WithNoValidLetter_IsRefusedAndRunsNothing()
    {
        var launcher = new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""));
        var svc = new RemediationService(new SystemCommandRunner(launcher), new SessionContext(SessionMode.Local));
        var res = await svc.ExecuteAsync(new(RemediationKind.OptimizeSsd, "Optimize / Retrim SSD", "C; Stop-Computer", "SSD"));
        Assert.False(res.Success);
        Assert.Empty(launcher.Calls);
    }

    [Fact]
    public async Task HistorySummary_AggregatesDiskReclaimed_MemorySaved_Fixes_And_DiagnosticRuns()
    {
        const string cleanJson = """{"RemovedFiles":18,"FreedBytes":1073741824}""";
        var launcher = new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(cleanJson));
        var remSvc = new RemediationService(new SystemCommandRunner(launcher), new SessionContext(SessionMode.Local));
        await remSvc.ExecuteAsync(new(RemediationKind.CleanTempFiles, "Clean temporary files"));

        var now = DateTimeOffset.UtcNow;
        var memRecord = new RemediationRecord(
            now.LocalDateTime,
            ServiceActor.Remote,
            RemediationKind.EndProcessGroup,
            "chrome.exe",
            true,
            "Closed chrome.exe (freed about 750 MB of RAM).",
            FreedMemoryBytes: 750L * 1024 * 1024);
        var formattedMemEvent = HistorySummary.FormatRemediationEvent(memRecord, "PC-1", "1.0.0");
        var parsedMemEntry = HistoryEventParser.Parse(formattedMemEvent, now);
        Assert.NotNull(parsedMemEntry);
        Assert.True(HistorySummary.IsFixEntry(parsedMemEntry!));

        var diagEntry1 = new HistoryEntry(now, "DriveHealth", "Drive health", "OK", "2 healthy drive(s)", 1.2, null, [], "PC-1", "1.0.0");
        var diagEntry2 = new HistoryEntry(now, "Crashes", "Crashes & unexpected restarts", "Warning", "1 BSOD", 0.8, null, [], "PC-1", "1.0.0");

        var summary = HistorySummary.Build([parsedMemEntry!, diagEntry1, diagEntry2], remSvc, null, null, HistoryRange.All, now);

        Assert.Equal(1_073_741_824L, summary.DiskReclaimedBytes);
        Assert.Equal(18, summary.TempFilesCleaned);
        Assert.Equal("1 GB", summary.DiskHeadline);
        Assert.Contains("18 temp file(s)", summary.DiskMeta);

        Assert.Equal(750L * 1024 * 1024, summary.MemorySavedBytes);
        Assert.Equal(1, summary.MemoryFixesCount);
        Assert.Equal("750 MB", summary.MemoryHeadline);

        Assert.Equal(2, summary.TotalFixesCount);
        Assert.Equal(2, summary.SuccessfulFixesCount);
        Assert.Equal(2, summary.Fixes.Count);

        Assert.Equal(2, summary.TotalRunsCount);
        Assert.Equal(1, summary.PassedRunsCount);
        Assert.Equal(1, summary.WarningRunsCount);
        Assert.Equal(0, summary.CriticalRunsCount);
    }

    [Fact]
    public async Task RemoteReboot_RegistersRunOnceWithSameSessionStream_AndLogsPostRebootResourceReductionInHistory()
    {
        var launcher = new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""));
        var runner = new SystemCommandRunner(launcher);
        var serverUri = new Uri("https://remoteblazor.pagetomovie.com:34544");
        var sessionId = Guid.Parse("bfdffa8b-70ac-4740-bdb1-c7f62a0b598f");
        var session = new SessionContext(SessionMode.Remote, serverUri, sessionId);
        var coordinator = new RebootResumeCoordinator(runner, executablePath: @"C:\App\RemotePCDiagnostics.Host.exe");
        var remSvc = new RemediationService(runner, session, rebootResume: coordinator);

        // 1. Even with 1 day uptime, high process memory (>= 6 GB) recommends a clean restart with pre-reboot baseline attached
        var preProcs = new List<ProcessResourceRow>
        {
            new("chrome.exe", 101, 5L * 1024 * 1024 * 1024, 50_000, 0),
            new("devenv.exe", 202, 3L * 1024 * 1024 * 1024, 40_000, 0),
        };
        var hogsRep = ResourceHogsModule.Build(new SystemUptimeInfo(90_000, 1, 1, 0, FastStartupEnabled: true), preProcs);
        var upCard = hogsRep.Cards.Single(c => c.Id == "uptime");
        var restartAction = upCard.Actions!.Single(a => a.Kind == RemediationKind.ScheduleCleanRestart);

        // 2. Remote technician triggers ScheduleCleanRestart
        var schedRes = await remSvc.ExecuteAsync(restartAction);
        Assert.True(schedRes.Success);
        Assert.Contains("8 GB across 2 processes", schedRes.Message);

        // Verify RunOnce command line keeps the exact same remote server and session GUID
        Assert.NotNull(coordinator.LastRegisteredCommandLine);
        Assert.Equal(
            "\"C:\\App\\RemotePCDiagnostics.Host.exe\" -u=https://remoteblazor.pagetomovie.com:34544 -i=bfdffa8b-70ac-4740-bdb1-c7f62a0b598f --post-reboot",
            coordinator.LastRegisteredCommandLine);
        Assert.Contains(launcher.Calls, c => c.File.EndsWith("reg.exe", StringComparison.OrdinalIgnoreCase) && c.Args.Contains(RebootResumeCoordinator.RunOnceValueName));

        // Verify SessionLaunchOptions.Resolve parses the RunOnce arguments back into the identical Remote session stream
        var relaunchOpts = SessionLaunchOptions.Resolve(
            ["-u=https://remoteblazor.pagetomovie.com:34544", $"-i={sessionId}", "--post-reboot"],
            _ => null);
        Assert.Equal(SessionMode.Remote, relaunchOpts.Mode);
        Assert.Equal(serverUri, relaunchOpts.ServerUri);
        Assert.Equal(sessionId, relaunchOpts.Id);
        Assert.True(relaunchOpts.PostReboot);

        // 3. Simulate post-reboot startup: uptime reset to 120s, memory dropped from 8 GB to 3 GB (5 GB freed), processes from 2 to 1
        var postBaseline = new ResourceBaselineSnapshot(
            UptimeSeconds: 120,
            UsedMemoryBytes: 3L * 1024 * 1024 * 1024,
            ProcessCount: 1,
            TopProcesses: "explorer.exe (120 MB)");
        var comparison = await coordinator.CompletePostRebootIfPendingAsync(
            remSvc,
            diagnostics: null,
            postRebootArgPresent: true,
            postBaselineOverride: postBaseline);

        Assert.NotNull(comparison);
        Assert.Equal(5L * 1024 * 1024 * 1024, comparison!.FreedMemoryBytes);
        Assert.Equal(1, comparison.ReducedProcesses);
        Assert.Contains("freed about 5 GB of RAM", comparison.SummaryMessage);
        Assert.Contains("1 fewer background processes", comparison.SummaryMessage);
        Assert.Null(coordinator.LoadPendingState()); // Pending state cleaned up after completion

        // 4. Verify HistorySummary logs the post-reboot memory reduction in System memory saved and Automated fixes
        var now = DateTimeOffset.UtcNow;
        var formattedRebootEvent = HistorySummary.FormatRemediationEvent(comparison.Record, "PC-1", "1.0.0");
        var parsedRebootEntry = HistoryEventParser.Parse(formattedRebootEvent, now);
        Assert.NotNull(parsedRebootEntry);

        var summary = HistorySummary.Build([parsedRebootEntry!], remediation: null, memory: null, services: null, HistoryRange.All, now);
        Assert.Equal(5L * 1024 * 1024 * 1024, summary.MemorySavedBytes);
        Assert.Equal("5 GB", summary.MemoryHeadline);
        Assert.Equal(1, summary.MemoryFixesCount);
        Assert.Single(summary.Fixes);
        Assert.Equal("+5 GB RAM", summary.Fixes[0].ImpactBadge);
        Assert.Equal("Remote technician", summary.Fixes[0].Actor);
    }
}
