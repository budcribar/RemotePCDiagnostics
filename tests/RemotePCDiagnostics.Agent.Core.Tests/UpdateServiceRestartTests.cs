using RemotePCDiagnostics.Agent.Core;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Agent.Core.Tests;

public class UpdateServiceRestartTests
{
    [Fact]
    public void Setup_task_script_records_the_exit_code_and_runs_as_SYSTEM()
    {
        var script = ScheduledSetup.BatchScript(
            @"C:\Program Files\Updates\Setup.exe",
            "/VERYSILENT /PRESERVEAGENT /LOG=\"C:\\ProgramData\\RemotePCDiagnostics\\Updates\\rpcd-setup.log\"",
            @"C:\Program Files\Updates\rpcd-setup-exit.txt");

        Assert.Contains("\"C:\\Program Files\\Updates\\Setup.exe\"", script, StringComparison.Ordinal);
        Assert.Contains("/PRESERVEAGENT", script, StringComparison.Ordinal);
        Assert.Contains("> \"C:\\Program Files\\Updates\\rpcd-setup-exit.txt\" echo %ERRORLEVEL%", script, StringComparison.Ordinal);
        Assert.True(ScheduledSetup.IsAscii(script));
        Assert.Equal(0, ScheduledSetup.ParseExitCode("0\r\n"));
        Assert.Equal(1056, ScheduledSetup.ParseExitCode(" 1056 "));
        Assert.Null(ScheduledSetup.ParseExitCode(""));
        Assert.Null(ScheduledSetup.ParseExitCode("still running"));

        var xml = ScheduledSetup.TaskXml(
            @"C:\Windows\System32\cmd.exe",
            "/d /c \"C:\\ProgramData\\RemotePCDiagnostics\\Updates\\rpcd-setup-run.cmd\"",
            @"C:\ProgramData\RemotePCDiagnostics\Updates");
        Assert.Contains("<UserId>S-1-5-18</UserId>", xml, StringComparison.Ordinal);
        Assert.Contains("<LogonType>ServiceAccount</LogonType>", xml, StringComparison.Ordinal);
        Assert.Contains("<Enabled>false</Enabled>", xml, StringComparison.Ordinal);
        Assert.Contains("<AllowStartOnDemand>true</AllowStartOnDemand>", xml, StringComparison.Ordinal);
        Assert.Contains("/d /c &quot;C:\\ProgramData\\RemotePCDiagnostics\\Updates\\rpcd-setup-run.cmd&quot;", xml, StringComparison.Ordinal);
        Assert.Contains(AgentLayout.SetupTaskName, "Remote PC Diagnostics Setup", StringComparison.Ordinal);
        Assert.DoesNotContain(AgentRemoval.ScheduledTaskNames, name => name == AgentLayout.SetupTaskName);
    }

    [Fact]
    public void Install_seals_a_finished_update_and_a_stopped_service_is_still_terminal()
    {
        var installing = new RpcdUpdateStatus
        {
            RequestId = "req-1052",
            Stage = RpcdUpdateStages.Installing,
            OldVersion = "1.2.0-ci.1043.1",
            NewVersion = "1.2.0-ci.1052.1",
            Percent = 100,
            Terminal = false,
            UpdatedUtc = DateTimeOffset.UtcNow.AddMinutes(-1),
            OwnerPid = 4242,
        };

        var running = RpcdUpdateSeal.Seal(installing, "1.2.0-ci.1052.1", serviceRunning: true, DateTimeOffset.UtcNow);
        Assert.Equal(RpcdUpdateStages.Succeeded, running.Stage);
        Assert.True(running.Terminal);
        Assert.Equal("1.2.0-ci.1043.1", running.OldVersion);

        var stopped = RpcdUpdateSeal.Seal(installing, "1.2.0-ci.1052.1", serviceRunning: false, DateTimeOffset.UtcNow);
        Assert.Equal(RpcdUpdateStages.Failed, stopped.Stage);
        Assert.True(stopped.Terminal);
        Assert.Contains(RpcdUpdateSeal.ServiceNotRunning, stopped.Error, StringComparison.Ordinal);

        var promoted = RpcdUpdateSeal.Seal(stopped, "1.2.0-ci.1052.1", serviceRunning: true, DateTimeOffset.UtcNow);
        Assert.Equal(RpcdUpdateStages.Succeeded, promoted.Stage);
        Assert.True(promoted.Terminal);
        Assert.Null(promoted.Error);

        var stillCopying = RpcdUpdateSeal.Seal(installing, "1.2.0-ci.1043.1", serviceRunning: false, DateTimeOffset.UtcNow);
        Assert.Equal(RpcdUpdateStages.Installing, stillCopying.Stage);
        Assert.False(stillCopying.Terminal);

        Assert.True(RpcdUpdateSeal.KeepSealedSuccess(running, installing with { Stage = RpcdUpdateStages.Failed, Terminal = true }));
        Assert.False(RpcdUpdateSeal.KeepSealedSuccess(running, running));
        Assert.False(RpcdUpdateSeal.KeepSealedSuccess(running, installing with { RequestId = "other", Stage = RpcdUpdateStages.Failed, Terminal = true }));
    }
}
