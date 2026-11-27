using RemotePCDiagnostics.Agent.Core;

namespace RemotePCDiagnostics.Agent.Core.Tests;

public class AgentInstancePolicyTests
{
    private const string CurrentExe = @"C:\Program Files\RemotePCDiagnosticsAgent\RemotePCDiagnostics.Agent.exe";
    private const string LegacyExe = @"C:\Program Files (x86)\RemotePCDiagnosticsAgent\RemotePCDiagnostics.Agent.exe";

    [Fact]
    public void A_second_instance_exits_zero_and_names_the_holder()
    {
        Assert.Equal(0, AgentInstancePolicy.ExitAlreadyRunning);
        Assert.Equal(@"Global\RemotePCDiagnostics.Agent", AgentInstancePolicy.MutexName);

        var report = AgentInstancePolicy.DescribeStartup(
            acquired: false,
            abandoned: false,
            claim: new AgentInstanceClaim(4242, "1.2.0-ci.1027.1", CurrentExe, "2026-11-21T02:00:00Z"),
            claimPidAlive: true,
            otherProcesses:
            [
                new AgentProcessSighting(4242, CurrentExe, "1.2.0-ci.1027.1"),
                new AgentProcessSighting(5150, LegacyExe, "1.2.0-ci.900.1"),
            ],
            services: [],
            currentImage: LegacyExe);

        Assert.False(report.Run);
        var line = Assert.Single(report.Lines);
        Assert.Contains("pid 4242", line, StringComparison.Ordinal);
        Assert.Contains("1.2.0-ci.1027.1", line, StringComparison.Ordinal);
        Assert.Contains(CurrentExe, line, StringComparison.Ordinal);
        Assert.Contains("pid 5150", line, StringComparison.Ordinal);
        Assert.Contains("1.2.0-ci.900.1", line, StringComparison.Ordinal);
        Assert.Contains("exiting without starting", line, StringComparison.Ordinal);
        Assert.DoesNotContain("pid 4242, version 1.2.0-ci.1027.1, path", line.Split("Also running")[1], StringComparison.Ordinal);
    }

    [Fact]
    public void The_winner_logs_a_live_process_and_a_legacy_service_as_stale()
    {
        var report = AgentInstancePolicy.DescribeStartup(
            acquired: true,
            abandoned: true,
            claim: new AgentInstanceClaim(100, "1.2.0-ci.100.1", LegacyExe, null),
            claimPidAlive: false,
            otherProcesses: [new AgentProcessSighting(200, LegacyExe, "1.2.0-ci.100.1")],
            services:
            [
                new AgentServiceRegistration(AgentLayout.ServiceName, "\"" + CurrentExe + "\" run", "Running"),
                new AgentServiceRegistration("Remote PC Diagnostics Agent", LegacyExe, "Running"),
            ],
            currentImage: CurrentExe);

        Assert.True(report.Run);
        Assert.Contains(report.Lines, line => line.Contains("process is gone", StringComparison.Ordinal) && line.Contains("pid 100", StringComparison.Ordinal));
        Assert.Contains(report.Lines, line => line.Contains("Stale agent process", StringComparison.Ordinal) && line.Contains("pid 200", StringComparison.Ordinal) && line.Contains("1.2.0-ci.100.1", StringComparison.Ordinal));
        Assert.Contains(report.Lines, line => line.Contains("Remote PC Diagnostics Agent", StringComparison.Ordinal) && line.Contains("still running", StringComparison.Ordinal));
        Assert.DoesNotContain(report.Lines, line => line.Contains("'" + AgentLayout.ServiceName + "'", StringComparison.Ordinal));
    }

    [Fact]
    public void A_stopped_legacy_service_is_still_logged_and_the_current_service_is_not()
    {
        var report = AgentInstancePolicy.DescribeStartup(
            acquired: true,
            abandoned: false,
            claim: null,
            claimPidAlive: false,
            otherProcesses: [],
            services:
            [
                new AgentServiceRegistration(AgentLayout.ServiceName, CurrentExe, "Stopped"),
                new AgentServiceRegistration("RemotePCDiagnostics.Agent", LegacyExe, "Stopped"),
            ],
            currentImage: CurrentExe);

        var line = Assert.Single(report.Lines);
        Assert.Contains("RemotePCDiagnostics.Agent", line, StringComparison.Ordinal);
        Assert.Contains("still registered", line, StringComparison.Ordinal);
        Assert.Contains(LegacyExe, line, StringComparison.Ordinal);
    }

    [Fact]
    public void Upgrade_stops_every_agent_service_before_it_deletes_the_old_names()
    {
        var services = new[]
        {
            new AgentServiceRegistration(AgentLayout.ServiceName, CurrentExe, "Running"),
            new AgentServiceRegistration("RemotePCDiagnostics.Agent", LegacyExe, "Running"),
            new AgentServiceRegistration("OldCopy", @"""C:\Tools\RemotePCDiagnostics.Agent.exe"" run", "Stopped"),
            new AgentServiceRegistration("WinDefend", @"C:\Program Files\Windows Defender\MsMpEng.exe", "Running"),
        };

        var plan = AgentInstancePolicy.BeforeStart(services);
        var waitAt = plan.ToList().FindIndex(action => action is WaitForInstanceMutexAction);
        var firstDelete = plan.ToList().FindIndex(action => action is DeleteServiceAction);
        Assert.True(waitAt > 0);
        Assert.True(firstDelete > waitAt);

        Assert.Contains(plan, action => action is StopServiceAction stop && stop.ServiceName == AgentLayout.ServiceName);
        Assert.Contains(plan, action => action is StopServiceAction stop && stop.ServiceName == "OldCopy");
        Assert.DoesNotContain(plan, action => action is StopServiceAction stop && stop.ServiceName == "WinDefend");
        Assert.DoesNotContain(plan, action => action is DeleteServiceAction delete && delete.ServiceName == AgentLayout.ServiceName);
        Assert.Contains(plan, action => action is DeleteServiceAction delete && delete.ServiceName == "RemotePCDiagnostics.Agent");
        Assert.Contains(plan, action => action is DeleteServiceAction delete && delete.ServiceName == "OldCopy");

        var currentStop = plan.ToList().FindIndex(action => action is StopServiceAction stop && stop.ServiceName == AgentLayout.ServiceName);
        var currentDisable = plan.ToList().FindIndex(action => action is DisableFailureRestartAction disable && disable.ServiceName == AgentLayout.ServiceName);
        Assert.True(currentDisable >= 0 && currentDisable < currentStop);

        var launchers = plan.ToList().FindIndex(action => action is RemoveStartupLaunchersAction);
        var terminate = plan.ToList().FindIndex(action => action is TerminateLeftoverProcessesAction);
        Assert.True(launchers > currentStop && terminate > launchers && waitAt > terminate);

        var ensure = Assert.IsType<EnsureServiceRecoveryAction>(plan[^1]);
        Assert.Equal(AgentLayout.ServiceName, ensure.ServiceName);
        Assert.True(plan.ToList().FindIndex(action => action is EnsureServiceRecoveryAction) > waitAt);
        var disableCurrent = Assert.Single(plan.OfType<DisableFailureRestartAction>(), action => action.ServiceName == AgentLayout.ServiceName);
        Assert.DoesNotContain(AgentServiceControl.ArgumentsFor(disableCurrent), arg => arg.Contains("start=", StringComparison.Ordinal));
        Assert.Contains(AgentServiceControl.ArgumentsFor(ensure), arg => arg.Contains("start= " + AgentServiceControl.AutomaticStartType, StringComparison.Ordinal));
        Assert.Contains(AgentServiceControl.ArgumentsFor(ensure), arg => arg.Contains(AgentServiceControl.FailureRestartActions, StringComparison.Ordinal));

        var sideBySide = AgentInstancePolicy.SideBySideInstallPaths(services, CurrentExe);
        Assert.Contains(LegacyExe, sideBySide);
        Assert.Contains(@"C:\Tools\RemotePCDiagnostics.Agent.exe", sideBySide);
        Assert.DoesNotContain(CurrentExe, sideBySide);
        Assert.Contains("RemotePCDiagnosticsAgent", AgentInstancePolicy.DescribeSideBySide(LegacyExe), StringComparison.Ordinal);
    }

    [Fact]
    public void Quoted_image_path_is_the_executable_and_the_claim_round_trips()
    {
        Assert.Equal(
            @"C:\Program Files\RemotePCDiagnosticsAgent\RemotePCDiagnostics.Agent.exe",
            AgentInstancePolicy.ExePathFromImage(@"""C:\Program Files\RemotePCDiagnosticsAgent\RemotePCDiagnostics.Agent.exe"" run"));
        Assert.True(AgentInstancePolicy.ImagePathLaunchesAgent(@"""C:\Agent\RemotePCDiagnostics.Agent.exe"" run"));
        Assert.False(AgentInstancePolicy.ServiceLaunchesAgent("Spooler", @"C:\Windows\System32\spoolsv.exe"));
        Assert.False(AgentInstancePolicy.ShouldDeleteService("Remote PC Diagnostics Agent", null)); // an old name alone isn't ours
        Assert.True(AgentInstancePolicy.ShouldDeleteService("OldCopy", @"""C:\Tools\RemotePCDiagnostics.Agent.exe"" run"));
        Assert.False(AgentInstancePolicy.ShouldDeleteService(AgentLayout.ServiceName, CurrentExe));

        var claim = new AgentInstanceClaim(7, "1.2.0-ci.1027.1", CurrentExe, "2026-11-21T02:36:00.0000000Z");
        var parsed = AgentInstanceClaim.Parse(AgentInstanceClaim.Format(claim));
        Assert.Equal(claim, parsed);
        Assert.Null(AgentInstanceClaim.Parse("version=only"));
        Assert.Null(AgentInstanceClaim.Parse(null));
    }

    [Fact]
    public void A_dying_holder_is_not_treated_as_a_second_instance()
    {
        Assert.False(AgentInstancePolicy.KillEntireProcessTree);
        var wait = AgentInstancePolicy.DyingHolderWait;
        var claim = new AgentInstanceClaim(50, "1.2.0-ci.1043.1", CurrentExe, null);
        var dying = new AgentProcessSighting(50, CurrentExe, "1.2.0-ci.1043.1");

        Assert.True(AgentInstancePolicy.ShouldWaitForDyingHolder(claim, claimPidAlive: false, [dying], TimeSpan.Zero, wait));
        Assert.True(AgentInstancePolicy.ShouldWaitForDyingHolder(claim, claimPidAlive: true, [dying], TimeSpan.FromSeconds(1), wait));
        Assert.True(AgentInstancePolicy.ShouldWaitForDyingHolder(null, false, [], TimeSpan.Zero, wait));
        Assert.False(AgentInstancePolicy.ShouldWaitForDyingHolder(claim, true, [dying], wait, wait));

        var waiting = AgentInstancePolicy.DescribeDyingHolder(claim, claimPidAlive: false);
        Assert.Contains("pid 50", waiting, StringComparison.Ordinal);
        Assert.Contains("Waiting", waiting, StringComparison.Ordinal);
        Assert.DoesNotContain("exiting without starting", waiting, StringComparison.Ordinal);
    }

    [Fact]
    public void Upgrade_does_not_kill_the_process_whose_job_contains_Setup()
    {
        const int self = 10;
        const int ancestor = 4;
        const int other = 77;

        Assert.False(AgentInstancePolicy.MayTerminateLeftover(0, self, [], inKillOnCloseJob: false, parentsKnown: true));
        Assert.False(AgentInstancePolicy.MayTerminateLeftover(self, self, [], inKillOnCloseJob: false, parentsKnown: true));
        Assert.False(AgentInstancePolicy.MayTerminateLeftover(ancestor, self, [ancestor], inKillOnCloseJob: true, parentsKnown: true));
        Assert.False(AgentInstancePolicy.MayTerminateLeftover(other, self, [], inKillOnCloseJob: true, parentsKnown: false));
        Assert.True(AgentInstancePolicy.MayTerminateLeftover(other, self, [ancestor], inKillOnCloseJob: false, parentsKnown: true));
        Assert.True(AgentInstancePolicy.MayTerminateLeftover(other, self, [ancestor], inKillOnCloseJob: true, parentsKnown: true));
    }

    [Fact]
    public void Failure_restart_is_cleared_without_turning_Automatic_off()
    {
        var cleared = AgentServiceControl.ArgumentsFor(new DisableFailureRestartAction("Remote PC Diagnostics Agent"));
        Assert.Equal(2, cleared.Count);
        Assert.DoesNotContain(cleared, arg => arg.Contains("start=", StringComparison.Ordinal));
        Assert.Contains(cleared, arg => arg.Contains(AgentServiceControl.ClearedFailureActions, StringComparison.Ordinal));
        Assert.Contains("\"Remote PC Diagnostics Agent\"", cleared[1], StringComparison.Ordinal);

        var restored = AgentServiceControl.ArgumentsFor(new EnsureServiceRecoveryAction(AgentLayout.ServiceName));
        Assert.Contains($"start= {AgentServiceControl.AutomaticStartType}", string.Join('\n', restored), StringComparison.Ordinal);
        Assert.DoesNotContain("delayed-auto", string.Join('\n', restored), StringComparison.Ordinal);
        Assert.DoesNotContain("start= disabled", string.Join('\n', restored), StringComparison.Ordinal);
        Assert.DoesNotContain(AgentLayout.SetupTaskName, AgentRemoval.ScheduledTaskNames);
    }
}
