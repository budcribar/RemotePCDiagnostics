using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Security;
using RemotePCDiagnostics.Core.Session;
using Xunit;

namespace RemotePCDiagnostics.Tests;

/// <summary>
/// The Security fixes, updates, clean-up, closing a program and the sign-in tasks run as the Agent's own scripts
/// (<see cref="AdminPipeFraming.OpAgentScript"/>): the app sends a name and arguments, and the Agent checks them and builds the PowerShell.
/// </summary>
public sealed class AgentScriptsPipeTests
{
    [Fact]
    public async Task The_agent_builds_the_script_itself_and_runs_it()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var launcher = new ScriptedLauncher((_, _) => ScriptedLauncher.Ok("was 0"));
        var (server, task, client) = await StartAsync(launcher, cts.Token);
        using (server)
        {
            await using (client)
            {
                var r = await client.RunAgentScriptAsync(AgentScripts.Of(AgentScripts.SecurityRead, SecurityFixes.Llmnr), TimeSpan.FromSeconds(30), cts.Token);
                Assert.Equal(0, r.ExitCode);
                Assert.Equal("was 0", r.StdOut);

                var update = await client.RunAgentScriptAsync(AgentScripts.Of(AgentScripts.InstallUpdate, "748279c7-4309-452c-8b30-e02ec52e498f"), TimeSpan.FromSeconds(30), cts.Token);
                Assert.Equal(0, update.ExitCode);
            }
            await task;
        }

        Assert.Equal(2, launcher.Calls.Count);
        Assert.All(launcher.Calls, c => Assert.EndsWith("powershell.exe", c.File, StringComparison.OrdinalIgnoreCase));
        Assert.Equal(SystemCommandRunner.PowerShellArgs(SecurityFixes.ReadScript(SecurityFixes.Llmnr)!), launcher.Calls[0].Args);
        Assert.Equal(SystemCommandRunner.PowerShellArgs(RemediationService.BuildInstallUpdateScript("748279c7-4309-452c-8b30-e02ec52e498f")!), launcher.Calls[1].Args);
    }

    public static TheoryData<string, string[]> Refused() => new()
    {
        { "run_powershell", ["Get-Process"] },                                         // not one of the Agent's scripts
        { AgentScripts.SecurityApply, ["Lsa"] },                                        // not a Security fix
        { AgentScripts.SecurityRestore, [SecurityFixes.Llmnr, "Remove-Item C:\\"] },   // not a value the app journaled
        { AgentScripts.OptimizeVolume, ["C; Format-Volume"] },
        { AgentScripts.InstallUpdate, ["KB1234'; iex"] },
        { AgentScripts.WindowsUpdate, ["everything"] },
        { AgentScripts.CleanTemp, ["C:\\Windows"] },
        { AgentScripts.StopProcess, ["lsass"] },                                        // protected
        { AgentScripts.StopProcess, ["*"] },
        { AgentScripts.ResumeTaskRegister, ["other", "PC\\ann", "--post-reboot"] },     // not a task this app creates
        { AgentScripts.ResumeTaskRegister, ["reboot", "PC\\ann';evil", "--post-reboot"] },
        { AgentScripts.ResumeTaskRegister, ["reboot", "PC\\ann", "--post-reboot", "-Command", "evil"] },
        { AgentScripts.ResumeTaskRegister, ["reboot", "PC\\ann", "-u=file:///C:/evil"] },
        { AgentScripts.ResumeTaskRemove, ["\\Microsoft\\Windows\\Defrag\\ScheduledDefrag"] },
    };

    [Theory]
    [MemberData(nameof(Refused))]
    public async Task The_agent_refuses_anything_it_does_not_build_itself(string name, string[] args)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var launcher = new ScriptedLauncher((_, _) => ScriptedLauncher.Ok(""));
        var (server, task, client) = await StartAsync(launcher, cts.Token);
        using (server)
        {
            await using (client)
            {
                var r = await client.RunAgentScriptAsync(AgentScripts.Of(name, args), TimeSpan.FromSeconds(30), cts.Token);
                Assert.Equal(SystemCommandRunner.AgentFailedExitCode, r.ExitCode);
                Assert.False(string.IsNullOrWhiteSpace(SystemCommandRunner.AgentFailure(r)));
            }
            await task;
        }
        Assert.Empty(launcher.Calls);
    }

    [Fact]
    public void The_workflow_task_runs_the_agent_launcher_until_the_workflow_removes_it()
    {
        var script = AgentScripts.Build(
            AgentScripts.Of(AgentScripts.ResumeTaskRegister, AgentScripts.WorkflowTask, @"PC\ann", "--post-reboot", SessionLaunchOptions.WorkflowArg),
            @"C:\Program Files\RemotePCDiagnostics\", out var refusal);
        Assert.Null(refusal);
        Assert.Contains(@"-Execute 'C:\Program Files\RemotePCDiagnostics\RemotePCDiagnostics.Agent.exe' -Argument '--launch --post-reboot --workflow'", script);
        Assert.Contains("-RunLevel Highest", script);
        Assert.DoesNotContain("EndBoundary", script);

        var remove = AgentScripts.Build(AgentScripts.Of(AgentScripts.ResumeTaskRemove, AgentScripts.WorkflowTask), null, out _);
        Assert.Equal(ResumeTaskScript.Remove(Core.Workflow.WorkflowService.ResumeTaskName), remove);
    }

    [Fact]
    public void Every_agent_script_passes_the_powershell_screen()
    {
        var requests = new[]
        {
            AgentScripts.Of(AgentScripts.OptimizeVolume, "CD"),
            AgentScripts.Of(AgentScripts.WindowsUpdate, "drivers"),
            AgentScripts.Of(AgentScripts.CleanTemp),
            AgentScripts.Of(AgentScripts.StopProcess, "chrome"),
            AgentScripts.Of(AgentScripts.ResumeTaskRegister, AgentScripts.RebootTask, @"PC\ann", "--post-reboot"),
            AgentScripts.Of(AgentScripts.ResumeTaskRemove, AgentScripts.RebootTask),
        }.Concat(SecurityFixes.All.SelectMany(f => new[] { AgentScripts.Of(AgentScripts.SecurityRead, f.Key), AgentScripts.Of(AgentScripts.SecurityApply, f.Key) }));

        foreach (var request in requests)
        {
            var script = AgentScripts.Build(request, @"C:\App", out var refusal);
            if (script is null && request.Name == AgentScripts.SecurityApply) continue; // a fix that only reads
            Assert.True(script is not null, $"{request.Name} {string.Join(' ', request.Args ?? [])}: {refusal}");
            Assert.Null(AdminCommandAllowlist.FindBlockedPowerShell(script));
        }
    }

    private static async Task<(AdminPipeServer, Task, AdminPipeClient)> StartAsync(IProcessLauncher launcher, CancellationToken ct)
    {
        var pipeName = $"rpd-test-{Guid.NewGuid():N}";
        var server = new AdminPipeServer(new AdminPipeServerOptions { PipeName = pipeName, ExpectedClientPid = Environment.ProcessId },
            launcher, appFolder: @"C:\App");
        var task = server.RunSingleSessionAsync(ct);
        var client = await AdminPipeClient.ConnectAsync(pipeName, TimeSpan.FromSeconds(10), ct);
        return (server, task, client);
    }
}
