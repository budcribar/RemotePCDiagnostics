using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.History;
using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Tests;

/// <summary>Regression tests for issues found in code review (Oct 2026).</summary>
public class ReviewFixesTests
{
    private const long GB = MemorySizing.GB;

    // 1. Windows Update: a failed install must not be reported as success.
    [Theory]
    [InlineData(4)] // orcFailed
    [InlineData(5)] // orcAborted
    public async Task WindowsUpdate_InstallFailed_IsReportedAsFailure(int resultCode)
    {
        var json = $$"""{"Count":2,"Installed":0,"InstallResult":{{resultCode}},"Titles":["KB5031455","KB5032190"]}""";
        var launcher = new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(json));
        var svc = new RemediationService(new SystemCommandRunner(launcher), new SessionContext(SessionMode.Local));

        var res = await svc.ExecuteAsync(new(RemediationKind.CheckAndInstallWindowsUpdates, "Check & install Windows updates"));

        Assert.False(res.Success);
        Assert.Contains("2", res.Message);
        Assert.Contains("KB5031455", res.Message);
    }

    [Fact]
    public void WindowsUpdateScript_ReportsTheInstallResultCode() =>
        Assert.Contains("InstallResult", RemediationService.BuildWindowsUpdateScript(driversOnly: false));

    // 2. Memory test: BAD lines count as errors even if the helper dies before its next PROGRESS/DONE.
    [Fact]
    public async Task MemoryTest_BadWordsBeforeCrash_AreMemoryErrors()
    {
        var launcher = new FakeHelperLauncher(h =>
        {
            h.Send(new MemTestMessage.Progress(0, "Ones", 0.3, 0));
            h.Send(new MemTestMessage.BadWord(4096, ulong.MaxValue, 0xFFFFFFFFFFFFFFFE));
            h.Send(new MemTestMessage.BadWord(8192, ulong.MaxValue, 0xFFFFFFFFFFFFFFFB));
            h.Send(new MemTestMessage.BadWord(4096, ulong.MaxValue, 0xFFFFFFFFFFFFFFFE)); // same word again: still 2 spots
            h.Exit();
        });
        var sensors = new SequenceSensorProvider(_ => throw new PlatformNotSupportedException(), available: false);
        var opts = new MemoryTestOptions { Duration = TimeSpan.FromMinutes(1), SampleInterval = TimeSpan.FromSeconds(1), Grace = TimeSpan.FromSeconds(30) };

        var r = await new MemoryTest(new FakeMemoryInfo(16 * GB), launcher, sensors, new FakeStressClock()).RunAsync(opts);

        Assert.Equal(MemoryTestOutcome.MemoryErrors, r.Outcome);
        Assert.Equal(2, r.Errors);
    }

    // 3. Build-server allowlist: only bare "dotnet" (PATH) or the installed SDK location, never any folder's dotnet.exe.
    [Theory]
    [InlineData(@"C:\Users\Public\Downloads\dotnet.exe")]
    [InlineData(@"\\evil\share\dotnet.exe")]
    [InlineData(@"C:\Program Files\dotnet\..\..\Temp\dotnet.exe")]
    [InlineData(@".\dotnet.exe")]
    [InlineData(@"tools/dotnet")]
    public void BuildServerAllowlist_RejectsDotnetFromOtherFolders(string fileName) =>
        Assert.False(MemoryCommandAllowlist.IsAllowed(fileName, ["build-server", "shutdown"]));

    [Theory]
    [InlineData("dotnet")]
    [InlineData("dotnet.exe")]
    [InlineData(@"C:\Program Files\dotnet\dotnet.exe")]
    public void BuildServerAllowlist_AcceptsPathAndInstalledSdk(string fileName) =>
        Assert.True(MemoryCommandAllowlist.IsAllowed(fileName, ["build-server", "shutdown"]));

    // 4. History durations: round before splitting into units.
    [Theory]
    [InlineData(12.4, "12 s")]
    [InlineData(59.6, "1 min 0 s")]
    [InlineData(119.7, "2 min 0 s")]
    [InlineData(3599.6, "1 h 0 min")]
    [InlineData(5400.0, "1 h 30 min")]
    public void HistoryFormatDuration_RoundsConsistently(double seconds, string expected) =>
        Assert.Equal(expected, HistoryQuery.FormatDuration(seconds));
}
