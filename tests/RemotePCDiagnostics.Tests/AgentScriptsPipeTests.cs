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
        var plan = AgentScripts.Plan(
            AgentScripts.Of(AgentScripts.ResumeTaskRegister, AgentScripts.WorkflowTask, @"PC\ann", "--post-reboot", SessionLaunchOptions.WorkflowArg),
            @"C:\Program Files\RemotePCDiagnostics\", out var refusal);
        Assert.Null(refusal);
        var task = Assert.IsType<RegisterTaskAction>(plan!.Native);
        Assert.Equal(Core.Workflow.WorkflowService.ResumeTaskName, task.TaskName);
        var xml = System.Xml.Linq.XDocument.Parse(task.TaskXml);
        System.Xml.Linq.XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
        Assert.Equal(@"C:\Program Files\RemotePCDiagnostics\RemotePCDiagnostics.Agent.exe", xml.Descendants(ns + "Command").Single().Value);
        Assert.Equal("--launch --post-reboot --workflow", xml.Descendants(ns + "Arguments").Single().Value);
        Assert.Equal("HighestAvailable", xml.Descendants(ns + "RunLevel").Single().Value);
        Assert.Empty(xml.Descendants(ns + "EndBoundary"));

        var remove = AgentScripts.Plan(AgentScripts.Of(AgentScripts.ResumeTaskRemove, AgentScripts.WorkflowTask), null, out _);
        Assert.Equal(new RemoveTaskAction(Core.Workflow.WorkflowService.ResumeTaskName), remove!.Native);
    }

    [Fact]
    public void Every_agent_script_passes_the_powershell_screen()
    {
        var requests = new[]
        {
            AgentScripts.Of(AgentScripts.WindowsUpdate, "drivers"),
        }.Concat(SecurityFixes.All.SelectMany(f => new[] { AgentScripts.Of(AgentScripts.SecurityRead, f.Key), AgentScripts.Of(AgentScripts.SecurityApply, f.Key) }));

        foreach (var request in requests)
        {
            var script = AgentScripts.Build(request, @"C:\App", out var refusal);
            if (script is null && request.Name == AgentScripts.SecurityApply) continue; // a fix that only reads
            Assert.True(script is not null, $"{request.Name} {string.Join(' ', request.Args ?? [])}: {refusal}");
            Assert.Null(AdminCommandAllowlist.FindBlockedPowerShell(script));
        }
    }

    public static TheoryData<string, string[], AgentNativeAction> NativePlans() => new()
    {
        { AgentScripts.OptimizeVolume, ["CD"], new OptimizeVolumeAction("CD") },
        { AgentScripts.OptimizeVolume, ["c:"], new OptimizeVolumeAction("C") },
        { AgentScripts.CleanTemp, [], new CleanTempAction() },
        { AgentScripts.StopProcess, ["chrome"], new StopProcessAction("chrome") },
        { AgentScripts.ResumeTaskRemove, [AgentScripts.RebootTask], new RemoveTaskAction(RebootResumeCoordinator.ResumeTaskName) },
    };

    [Theory]
    [MemberData(nameof(NativePlans))]
    public void Simple_changes_are_made_in_CSharp_without_PowerShell(string name, string[] args, AgentNativeAction expected)
    {
        var plan = AgentScripts.Plan(AgentScripts.Of(name, args), @"C:\App", out var refusal);
        Assert.Null(refusal);
        Assert.Null(plan!.Script);
        Assert.Equal(expected, plan.Native);
        Assert.Null(AgentScripts.Build(AgentScripts.Of(name, args), @"C:\App", out var noScript));
        Assert.NotNull(noScript);
    }

    [Fact]
    public async Task The_agent_makes_a_native_change_through_its_ops_and_answers_with_their_result()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var launcher = new ScriptedLauncher((file, _) => file == "agent:StopProcess" ? ScriptedLauncher.Ok("""{"FreedMemoryBytes":1024}""") : ScriptedLauncher.Fail());
        var (server, task, client) = await StartAsync(launcher, cts.Token);
        using (server)
        {
            await using (client)
            {
                var r = await client.RunAgentScriptAsync(AgentScripts.Of(AgentScripts.StopProcess, "chrome"), TimeSpan.FromSeconds(30), cts.Token);
                Assert.Equal(0, r.ExitCode);
                Assert.Equal("""{"FreedMemoryBytes":1024}""", r.StdOut);
            }
            await task;
        }
        Assert.Empty(launcher.Calls); // no PowerShell
        Assert.Equal(new StopProcessAction("chrome"), Assert.Single(launcher.NativeCalls));
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

/// <summary>The pieces of the Agent's C# changes that don't need Windows: the sign-in task's XML and the temp file walk.</summary>
public sealed class AgentNativeOpsTests
{
    [Fact]
    public void Task_xml_escapes_values_and_matches_the_powershell_task()
    {
        var end = new DateTimeOffset(2026, 11, 21, 12, 0, 0, TimeSpan.Zero);
        var xml = ResumeTaskXml.Build(@"C:\A & B\Agent.exe", "--launch -u=https://x.example/?a=1&b=<2>", @"C:\A & B", @"PC\o'neil", end, highest: false);
        var doc = System.Xml.Linq.XDocument.Parse(xml);
        System.Xml.Linq.XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
        Assert.Equal(@"C:\A & B\Agent.exe", doc.Descendants(ns + "Command").Single().Value);
        Assert.Equal("--launch -u=https://x.example/?a=1&b=<2>", doc.Descendants(ns + "Arguments").Single().Value);
        Assert.Equal("LeastPrivilege", doc.Descendants(ns + "RunLevel").Single().Value);
        Assert.Equal("InteractiveToken", doc.Descendants(ns + "LogonType").Single().Value);
        Assert.Equal(@"PC\o'neil", doc.Descendants(ns + "LogonTrigger").Single().Element(ns + "UserId")!.Value);
        Assert.Equal("PT0S", doc.Descendants(ns + "ExecutionTimeLimit").Single().Value);
        Assert.Equal("false", doc.Descendants(ns + "DisallowStartIfOnBatteries").Single().Value);
        Assert.Equal("false", doc.Descendants(ns + "StopIfGoingOnBatteries").Single().Value);
        Assert.Equal(end.LocalDateTime.ToString("s", System.Globalization.CultureInfo.InvariantCulture), doc.Descendants(ns + "EndBoundary").Single().Value);
    }

    [Fact]
    public void Temp_cleaner_removes_only_old_files_and_does_not_follow_links()
    {
        var root = Path.Combine(Path.GetTempPath(), $"rpcd-clean-{Guid.NewGuid():N}");
        var outside = Path.Combine(Path.GetTempPath(), $"rpcd-outside-{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(Path.Combine(root, "sub"));
            Directory.CreateDirectory(outside);
            var old = Path.Combine(root, "sub", "old.tmp");
            var fresh = Path.Combine(root, "fresh.tmp");
            var keep = Path.Combine(outside, "keep.tmp");
            File.WriteAllBytes(old, new byte[100]);
            File.WriteAllBytes(fresh, new byte[50]);
            File.WriteAllBytes(keep, new byte[10]);
            File.SetLastWriteTime(old, DateTime.Now.AddDays(-3));
            File.SetLastWriteTime(keep, DateTime.Now.AddDays(-3));
            try { Directory.CreateSymbolicLink(Path.Combine(root, "link"), outside); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }

            var (files, bytes) = TempFileCleaner.Clean([root], DateTime.Now - TempFileCleaner.MinAge);

            Assert.Equal(1, files);
            Assert.Equal(100, bytes);
            Assert.False(File.Exists(old));
            Assert.True(File.Exists(fresh));
            Assert.True(File.Exists(keep));
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { }
            try { Directory.Delete(outside, true); } catch { }
        }
    }
}
