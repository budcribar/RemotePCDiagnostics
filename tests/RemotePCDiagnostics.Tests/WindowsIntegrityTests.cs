using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Tests;

/// <summary>DISM ScanHealth and SFC /verifyonly: a scan that reaches no verdict is "Couldn't run" with the reason, never Critical (#68).</summary>
public class WindowsIntegrityTests
{
    private static async Task<DiagnosticResult> Run(IDiagnosticModule module) => await module.RefreshAsync(null);

    private static SfcVerifyOnlyModule Sfc(ProcessResult result) =>
        new(new SystemCommandRunner(new ScriptedLauncher((_, _) => result), isProcessElevated: () => true));

    private static DismScanHealthModule Dism(ProcessResult result) =>
        new(new SystemCommandRunner(new ScriptedLauncher((_, _) => result), isProcessElevated: () => true)) { FindImages = () => [] };

    [Fact]
    public async Task Sfc_Clean_IsOk()
    {
        var r = await Run(Sfc(new(0, "Verification 100% complete.\nWindows Resource Protection did not find any integrity violations.", "")));
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        Assert.Equal("OK", ResultEventLogger.Outcome(r));
    }

    [Fact]
    public async Task Sfc_Violations_IsWarning()
    {
        var r = await Run(Sfc(new(0, "Windows Resource Protection found integrity violations.", "")));
        Assert.Equal(DiagnosticStatus.Warning, r.Status);
        Assert.Equal("Warning", ResultEventLogger.Outcome(r));
    }

    [Theory]
    [InlineData("Another servicing or repair operation is currently running.\nWait for this to finish and run sfc again.", 0, "another servicing or repair operation")]
    [InlineData("There is a system repair pending which requires reboot to complete.  Restart Windows and run sfc again.", 0, "restart")]
    [InlineData("You must be an administrator running a console session in order to use the sfc utility.", 0, "administrator")]
    [InlineData("Windows Resource Protection could not start the repair service.", 0, "repair service")]
    [InlineData("Verification 100% complete.\nWindows Resource Protection could not perform the requested operation.", 0, "could not perform the scan")]
    [InlineData("", 0, "without any output")]
    [InlineData("Verification 100% complete.\nSomething unexpected.", 2, "Something unexpected.")]
    public async Task Sfc_NoVerdict_IsCouldNotRunWithReason(string output, int exitCode, string reason)
    {
        var r = await Run(Sfc(new(exitCode, output, "")));
        Assert.Equal(CouldNotRun.OutcomeText, ResultEventLogger.Outcome(r));
        Assert.NotEqual("Critical", ResultEventLogger.Outcome(r));
        Assert.Contains(reason, r.Message, StringComparison.OrdinalIgnoreCase);
        var report = Assert.IsType<AreaReport>(r.Payload);
        Assert.Equal(r.Message, report.CouldNotRunReason);
        Assert.Equal(RunEnd.CouldNotRun, report.RunEnd);
        Assert.Equal(AreaLevel.Warning, Assert.Single(report.Cards).Level);
        Assert.Null(report.Cards[0].Actions); // no repair offered when nothing showed corruption
    }

    [Fact]
    public async Task Sfc_DidNotReturn_IsCouldNotRun()
    {
        var r = await Run(Sfc(new(-1, "", "", TimedOut: true)));
        Assert.Equal(CouldNotRun.OutcomeText, ResultEventLogger.Outcome(r));
        Assert.Contains("did not start or did not finish", r.Message);
    }

    [Fact]
    public async Task Dism_Clean_IsOk()
    {
        var r = await Run(Dism(new(0, "No component store corruption detected.\nThe operation completed successfully.", "")));
        Assert.Equal("OK", ResultEventLogger.Outcome(r));
    }

    [Fact]
    public async Task Dism_Repairable_IsWarning()
    {
        var r = await Run(Dism(new(0, "The component store is repairable.\nThe operation completed successfully.", "")));
        Assert.Equal("Warning", ResultEventLogger.Outcome(r));
    }

    [Theory]
    [InlineData("Error: 1726\n\nThe remote procedure call failed.\n\nThe DISM log file can be found at C:\\Windows\\Logs\\DISM\\dism.log", 1726, "Error: 1726")]
    [InlineData("Error: 0x800f082f\n\nThe operation failed.", unchecked((int)0x800f082f), "waiting for a restart")]
    [InlineData("Error: 0x800700b7\n\nCannot create a file when that file already exists.", unchecked((int)0x800700b7), "another servicing")]
    [InlineData("Error: 740\n\nElevated permissions are required to run DISM.", 740, "administrator")]
    [InlineData("", 0, "without any output")]
    public async Task Dism_NoVerdict_IsCouldNotRunWithReason(string output, int exitCode, string reason)
    {
        var r = await Run(Dism(new(exitCode, output, "")));
        Assert.Equal(CouldNotRun.OutcomeText, ResultEventLogger.Outcome(r));
        Assert.Contains(reason, r.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Null(Assert.IsType<AreaReport>(r.Payload).Cards[0].Actions);
    }

    [Fact]
    public void Dism_ErrorReason_IncludesMessageNotLogPath() =>
        Assert.Equal("DISM stopped before it could report a result (Error: 1726). The remote procedure call failed. See the DISM log details below.",
            DismScanHealthModule.NoResultReason("Error: 1726\n\nThe remote procedure call failed.\n\nThe DISM log file can be found at C:\\x\\dism.log", 1726));

    [Fact]
    public void LastMessageLine_SkipsProgressAndCaps()
    {
        Assert.Equal("Done.", WindowsIntegrityModule.LastMessageLine("Start\r\nDone.\r\nVerification 100% complete."));
        Assert.Null(WindowsIntegrityModule.LastMessageLine("Verification 5% complete.\rVerification 100% complete."));
        Assert.Equal(201, WindowsIntegrityModule.LastMessageLine(new string('x', 500))!.Length);
    }

    [Fact]
    public void AreaReport_RunEnd()
    {
        Assert.Equal(RunEnd.Finished, new AreaReport([], "", DiagnosticStatus.Error).RunEnd);
        Assert.Equal(RunEnd.CouldNotRun, new AreaReport([], "", DiagnosticStatus.Error) { CouldNotRunReason = "x" }.RunEnd);
        Assert.Equal(RunEnd.Cancelled, new AreaReport([], "", DiagnosticStatus.Warning, Cancelled: true) { CouldNotRunReason = "x" }.RunEnd);
    }

    /// <summary>DISM and SFC both use the servicing stack: a second scan waits for the first instead of both failing.</summary>
    [Fact]
    public async Task Scans_RunOneAtATime()
    {
        var launcher = new GatedLauncher();
        var runner = new SystemCommandRunner(launcher, isProcessElevated: () => true);
        var dism = new DismScanHealthModule(runner) { FindImages = () => [] };
        var sfc = new SfcVerifyOnlyModule(runner);

        var dismRun = dism.RefreshAsync(null);
        await launcher.DismStarted.Task.WaitAsync(TimeSpan.FromSeconds(10));
        var sfcRun = sfc.RefreshAsync(null);
        await Task.Delay(200);
        Assert.False(launcher.SfcStarted.Task.IsCompleted);

        launcher.ReleaseDism.SetResult();
        Assert.Equal(DiagnosticStatus.Ok, (await dismRun.WaitAsync(TimeSpan.FromSeconds(10))).Status);
        Assert.Equal(DiagnosticStatus.Ok, (await sfcRun.WaitAsync(TimeSpan.FromSeconds(10))).Status);
        Assert.True(launcher.SfcStarted.Task.IsCompleted);
    }

    [Fact]
    public async Task WaitingScan_CanBeCancelled()
    {
        var launcher = new GatedLauncher();
        var runner = new SystemCommandRunner(launcher, isProcessElevated: () => true);
        var dism = new DismScanHealthModule(runner) { FindImages = () => [] };
        var sfc = new SfcVerifyOnlyModule(runner);

        var dismRun = dism.RefreshAsync(null);
        await launcher.DismStarted.Task.WaitAsync(TimeSpan.FromSeconds(10));
        var sfcRun = sfc.RefreshAsync(null);
        await Task.Delay(100);
        sfc.Cancel();
        var cancelled = await sfcRun.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.True(cancelled.Cancelled);
        Assert.False(launcher.SfcStarted.Task.IsCompleted);

        launcher.ReleaseDism.SetResult();
        await dismRun.WaitAsync(TimeSpan.FromSeconds(10));
    }

    /// <summary>Checks page: while DISM runs (from the page, the service workflow or an agent), "Run just this" on SFC is disabled and says why.</summary>
    [Fact]
    public async Task ChecksPage_BlocksTheOtherIntegrityScanWhileOneRuns()
    {
        var launcher = new GatedLauncher();
        var runner = new SystemCommandRunner(launcher, isProcessElevated: () => true);
        var dism = new DismScanHealthModule(runner) { FindImages = () => [] };
        var sfc = new SfcVerifyOnlyModule(runner);
        var other = new FakeModule("A", _ => Task.FromResult(FakeModule.Ok("A")));
        var store = new ResultStore();
        var svc = new DiagnosticsService(store, [dism, sfc, other]);
        var screen = new ChecksScreenState(svc, store);

        Assert.True(screen.CanRunSingle(sfc));
        Assert.Null(screen.BlockingIntegrityScan(sfc));

        var run = svc.RunAsync(dism.Name);
        await launcher.DismStarted.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.False(screen.CanRunSingle(sfc));
        Assert.Same(dism, screen.BlockingIntegrityScan(sfc));
        Assert.Null(screen.BlockingIntegrityScan(dism));
        Assert.Null(screen.BlockingIntegrityScan(other));
        Assert.True(screen.CanRunSingle(other));
        await screen.RunSingleAsync(sfc); // ignored while blocked
        Assert.False(launcher.SfcStarted.Task.IsCompleted);

        launcher.ReleaseDism.SetResult();
        await run.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.True(screen.CanRunSingle(sfc));
        Assert.Null(screen.BlockingIntegrityScan(sfc));
    }

    private sealed class GatedLauncher : IProcessLauncher
    {
        public TaskCompletionSource DismStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseDism { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource SfcStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct)
        {
            if (fileName.EndsWith("dism.exe", StringComparison.OrdinalIgnoreCase))
            {
                DismStarted.TrySetResult();
                await ReleaseDism.Task.WaitAsync(ct);
                return new(0, "No component store corruption detected.", "");
            }
            SfcStarted.TrySetResult();
            return new(0, "Windows Resource Protection did not find any integrity violations.", "");
        }
    }

    private static DismScanHealthModule Dism(ProcessResult result, IReadOnlyList<string> images) =>
        new(new SystemCommandRunner(new ScriptedLauncher((_, _) => result), isProcessElevated: () => true)) { FindImages = () => images };

    [Fact]
    public async Task Dism_Corrupt_NoImage_SaysHowToGetRepairFromImage()
    {
        var r = await Run(Dism(new(0, "The component store is repairable.\nThe operation completed successfully.", ""), []));
        var card = Assert.Single(Assert.IsType<AreaReport>(r.Payload).Cards);
        var row = Assert.Single(card.Rows, x => x.Values[0] == DismScanHealthModule.NoImageRowTitle);
        Assert.Contains("0x800F0915", row.Values[1]);
        var kinds = card.Actions!.Select(a => a.Kind).ToList();
        Assert.Contains(RemediationKind.CleanUpComponentStore, kinds);
        Assert.Contains(RemediationKind.RepairComponentStore, kinds);
        Assert.DoesNotContain(RemediationKind.RepairComponentStoreFromImage, kinds);
    }

    [Fact]
    public async Task Dism_Corrupt_WithImage_OffersRepairFromImageWithoutTheNote()
    {
        var r = await Run(Dism(new(0, "The component store is repairable.\nThe operation completed successfully.", ""), [@"D:\sources\install.wim"]));
        var card = Assert.Single(Assert.IsType<AreaReport>(r.Payload).Cards);
        Assert.DoesNotContain(card.Rows, x => x.Values[0] == DismScanHealthModule.NoImageRowTitle);
        Assert.Contains(card.Actions!, a => a.Kind == RemediationKind.RepairComponentStoreFromImage && a.Target == @"D:\sources\install.wim");
    }

    [Fact]
    public async Task Dism_Clean_HasNoImageNote()
    {
        var r = await Run(Dism(new(0, "No component store corruption detected.\nThe operation completed successfully.", ""), []));
        var card = Assert.Single(Assert.IsType<AreaReport>(r.Payload).Cards);
        Assert.DoesNotContain(card.Rows, x => x.Values[0] == DismScanHealthModule.NoImageRowTitle);
    }

    [Fact]
    public async Task Dism_ReportsPercentageProgress()
    {
        var launcher = new StreamingLauncher(
            ["[==== 20.0% ====]", "[=========== 60.5% ===========]", "[==========================100.0%==========================]"],
            new(0, "No component store corruption detected.\nThe operation completed successfully.", ""));
        var dism = new DismScanHealthModule(new SystemCommandRunner(launcher, isProcessElevated: () => true)) { FindImages = () => [] };
        var steps = new List<CheckProgress>();
        var progress = CheckProgressExtensions.Create(steps.Add);

        var r = await dism.RefreshAsync(progress);

        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        // Synchronous burst in <500ms emits initial 0%, first reading (20%), throttles intermediate 60.5%, and always emits 100%.
        Assert.Equal([(0, 100), (20, 100), (100, 100)], steps.Select(s => (s.Step, s.Total)).ToList());
        Assert.Contains(steps, s => s.Step == 20 && s.Message == "Scanning…");
    }

    [Fact]
    public void TryAcceptProgressPercent_ThrottlesTo500MsAndAlwaysEmitsFirstAnd100()
    {
        double last = -1;
        long lastTick = 0;

        Assert.True(WindowsIntegrityModule.TryAcceptProgressPercent("[==== 20.0% ====]", ref last, ref lastTick, out var p1, nowTickMs: 1000));
        Assert.Equal(20.0, p1);

        // Within 500ms window -> throttled
        Assert.False(WindowsIntegrityModule.TryAcceptProgressPercent("[==== 25.5% ====]", ref last, ref lastTick, out _, nowTickMs: 1200));

        // After 500ms window -> emitted
        Assert.True(WindowsIntegrityModule.TryAcceptProgressPercent("[=========== 60.5% ===========]", ref last, ref lastTick, out var p2, nowTickMs: 1500));
        Assert.Equal(60.5, p2);

        // Within 500ms window -> throttled
        Assert.False(WindowsIntegrityModule.TryAcceptProgressPercent("[=========== 80.0% ===========]", ref last, ref lastTick, out _, nowTickMs: 1700));

        // 100% is always emitted even within 500ms
        Assert.True(WindowsIntegrityModule.TryAcceptProgressPercent("[==========================100.0%==========================]", ref last, ref lastTick, out var p3, nowTickMs: 1750));
        Assert.Equal(100.0, p3);
    }

    [Fact]
    public async Task Sfc_ReportsPercentageProgress()
    {
        var nulPadded = string.Concat("Verification 42% complete.".Select(c => $"{c}\0"));
        var launcher = new StreamingLauncher(
            ["Beginning verification phase of system scan.", nulPadded, "Verification 100% complete."],
            new(0, "Windows Resource Protection did not find any integrity violations.", ""));
        var sfc = new SfcVerifyOnlyModule(new SystemCommandRunner(launcher, isProcessElevated: () => true));
        var steps = new List<CheckProgress>();
        var progress = CheckProgressExtensions.Create(steps.Add);

        var r = await sfc.RefreshAsync(progress);

        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        Assert.Equal([(0, 100), (42, 100), (100, 100)], steps.Select(s => (s.Step, s.Total)).ToList());
        Assert.Contains(steps, s => s.Step == 42 && s.Message == "Scanning…");
    }

    [Fact]
    public async Task Sfc_TrimsVerificationPercentLinesFromOutput()
    {
        var raw = string.Join("\r\n",
            "Beginning system scan.  This process will take some time.",
            "",
            "",
            "Beginning verification phase of system scan.",
            "Verification 0% complete.",
            "Verification 1% complete.",
            "Verification 50% complete.",
            "Verification 100% complete.",
            "",
            "Windows Resource Protection did not find any integrity violations.");
        var r = await Sfc(new(0, raw, "")).RefreshAsync(null);
        var rep = Assert.IsType<AreaReport>(r.Payload);
        var output = rep.Cards.Single().Rows.Single(row => row.Values[0] == "Output").Values[1];
        Assert.DoesNotContain("% complete", output);
        Assert.Contains("Beginning system scan.", output);
        Assert.Contains("Windows Resource Protection did not find any integrity violations.", output);
    }

    private sealed class StreamingLauncher(IReadOnlyList<string> lines, ProcessResult result) : IProcessLauncher
    {
        public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct) =>
            Task.FromResult(result);

        public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct, Action<string>? outputLine)
        {
            if (outputLine is not null)
                foreach (var line in lines) outputLine(line);
            return Task.FromResult(result);
        }
    }

    [Fact]
    public async Task AdminPipe_RunElevated_StreamsProgressWithoutBlockingOtherPipeRequests()
    {
        var pipeName = "rpcd-test-cmdjob-" + Guid.NewGuid().ToString("N");
        var firstLineSent = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseCommand = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var launcher = new BlockingStreamingLauncher(firstLineSent, releaseCommand);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var server = new RemotePCDiagnostics.Core.Session.AdminPipeServer(
            new RemotePCDiagnostics.Core.Session.AdminPipeServerOptions
            {
                PipeName = pipeName,
                ConnectTimeout = TimeSpan.FromSeconds(5),
                CustomClientVerifier = _ => (true, null),
            },
            launcher: launcher);

        var prevPoll = RemotePCDiagnostics.Core.Session.AdminPipeClient.CommandJobPollInterval;
        var prevDirect = RemotePCDiagnostics.Core.Session.AdminPipeServer.CommandJobDirectAnswer;
        RemotePCDiagnostics.Core.Session.AdminPipeClient.CommandJobPollInterval = TimeSpan.FromMilliseconds(25);
        RemotePCDiagnostics.Core.Session.AdminPipeServer.CommandJobDirectAnswer = TimeSpan.FromMilliseconds(25);
        try
        {
            var serverTask = server.RunSingleSessionAsync(cts.Token);
            using var client = await RemotePCDiagnostics.Core.Session.AdminPipeClient.ConnectAsync(pipeName, TimeSpan.FromSeconds(5), ct: cts.Token);

            var received = new List<string>();
            var gotLiveProgress = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var runTask = client.RunElevatedAsync(
                SystemCommandRunner.SystemTool("sfc.exe"),
                ["/verifyonly"],
                TimeSpan.FromMinutes(1),
                cts.Token,
                line =>
                {
                    received.Add(line);
                    if (line.Contains("42%")) gotLiveProgress.TrySetResult();
                });

            await firstLineSent.Task.WaitAsync(cts.Token);
            await gotLiveProgress.Task.WaitAsync(cts.Token);

            // Pipe must remain free while SFC is still running.
            var ping = await client.PingAsync(cts.Token);
            Assert.True(ping.Ok);
            Assert.False(runTask.IsCompleted);

            releaseCommand.SetResult();
            var pr = await runTask.WaitAsync(cts.Token);
            Assert.NotNull(pr);
            Assert.Equal(0, pr!.ExitCode);
            Assert.Contains(received, l => l.Contains("42%"));
            Assert.Contains(received, l => l.Contains("100%"));

            client.Dispose();
            await serverTask.WaitAsync(TimeSpan.FromSeconds(5));
        }
        finally
        {
            RemotePCDiagnostics.Core.Session.AdminPipeClient.CommandJobPollInterval = prevPoll;
            RemotePCDiagnostics.Core.Session.AdminPipeServer.CommandJobDirectAnswer = prevDirect;
        }
    }

    private sealed class BlockingStreamingLauncher(TaskCompletionSource firstLineSent, TaskCompletionSource release) : IProcessLauncher
    {
        public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct) =>
            RunAsync(fileName, arguments, timeout, ct, outputLine: null);

        public async Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct, Action<string>? outputLine)
        {
            outputLine?.Invoke("Verification 42% complete.");
            firstLineSent.TrySetResult();
            await release.Task.WaitAsync(ct);
            outputLine?.Invoke("Verification 100% complete.");
            return new(0, "Windows Resource Protection did not find any integrity violations.", "");
        }
    }
}
