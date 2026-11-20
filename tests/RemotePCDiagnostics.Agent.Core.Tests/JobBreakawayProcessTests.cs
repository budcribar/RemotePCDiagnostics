using System.Diagnostics;
using RemotePCDiagnostics.Agent;
using Xunit;

namespace RemotePCDiagnostics.Agent.Core.Tests;

public class JobBreakawayProcessTests
{
    [Fact]
    public void Command_line_quotes_the_program_path_and_keeps_the_arguments_as_given()
    {
        var line = JobBreakawayProcess.BuildCommandLine(
            @"C:\ProgramData\RemotePCDiagnostics\Updates\RemotePCDiagnostics-Setup-1.2.0-win-x64.exe",
            "/VERYSILENT /SUPPRESSMSGBOXES \"/AGENTMSI=C:\\ProgramData\\RemotePCDiagnostics\\Updates\\Agent.msi\"");

        Assert.Equal(
            "\"C:\\ProgramData\\RemotePCDiagnostics\\Updates\\RemotePCDiagnostics-Setup-1.2.0-win-x64.exe\" /VERYSILENT /SUPPRESSMSGBOXES \"/AGENTMSI=C:\\ProgramData\\RemotePCDiagnostics\\Updates\\Agent.msi\"",
            line);
    }

    [Fact]
    public void Command_line_without_arguments_is_just_the_quoted_program()
    {
        Assert.Equal("\"C:\\a b\\setup.exe\"", JobBreakawayProcess.BuildCommandLine(@"C:\a b\setup.exe", ""));
    }

    [Fact]
    public void Breakaway_start_runs_the_program_on_Windows_and_declines_elsewhere()
    {
        var cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        var started = JobBreakawayProcess.TryStart(cmd, "/c exit 0", Path.GetTempPath(), out var process);
        if (!OperatingSystem.IsWindows())
        {
            Assert.False(started);
            return;
        }

        // A test runner not in a job, or in one that allows breakaway, starts it; one that forbids it gets false back.
        if (!started)
            return;
        process?.WaitForExit(10_000);
        Assert.True(process is null || process.HasExited);
    }
}
