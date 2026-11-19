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
}
