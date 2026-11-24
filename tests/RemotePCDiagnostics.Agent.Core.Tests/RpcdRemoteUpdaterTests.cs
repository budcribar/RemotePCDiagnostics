using System.Net;
using RemotePCDiagnostics.Agent;
using RemotePCDiagnostics.Agent.Core;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Agent.Core.Tests;

/// <summary>
/// The agent service and an app's elevated helper each own an updater over the same staging folder. These check that they share state.
/// </summary>
public class RpcdRemoteUpdaterTests
{
    private static readonly RpcdUpdateRequest Approved = new("stable", null, Approved: true, ApprovedBy: "shop owner");

    [Theory]
    [InlineData(true, null)]
    [InlineData(true, "")]
    [InlineData(false, "Reported busy")]
    public void Hub_update_uses_agent_observed_host_state(bool hostRunning, string? reportedActivity)
    {
        var dir = TempDir();
        using var http = new HttpClient(new Stub(() => new HttpResponseMessage(HttpStatusCode.NotFound)));
        using var service = NewUpdater(dir, http, hostRunning: hostRunning);
        var status = service.Start(Approved with { BusyReason = reportedActivity },
            relaunch: null, trustCallerBusyReason: false);

        Assert.Equal(hostRunning ? RpcdUpdateStages.Refused : RpcdUpdateStages.Checking, status.Stage);
        if (hostRunning)
            Assert.Contains("Close Remote PC Diagnostics", status.Error);
    }


    [Fact]
    public async Task An_update_running_in_one_agent_process_refuses_one_in_the_other()
    {
        var dir = TempDir();
        var hold = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var http = new HttpClient(new Stub(() => hold.Task));
        using var helper = NewUpdater(dir, http);
        using var service = NewUpdater(dir, http);

        var first = helper.Start(Approved with { BusyReason = "" }, relaunch: null, trustCallerBusyReason: true);
        Assert.Equal(RpcdUpdateStages.Checking, first.Stage);

        var second = service.Start(Approved with { BusyReason = "" }, relaunch: null, trustCallerBusyReason: true);
        Assert.Equal(RpcdUpdateStages.Refused, second.Stage);
        Assert.Contains("already in progress", second.Error);

        // The service also reports the helper's update when polled.
        Assert.Equal(first.RequestId, service.Current(null)?.RequestId);

        hold.SetResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (helper.Current(first.RequestId) is { Terminal: false } && DateTime.UtcNow < deadline)
            await Task.Delay(50);
        Assert.Equal(RpcdUpdateStages.Failed, helper.Current(first.RequestId)?.Stage);
    }

    [Fact]
    public void Progress_payload_carries_the_installer_exit_code_and_log_only_when_set()
    {
        var failed = RpcdRemoteUpdater.ToProto(new RpcdUpdateStatus
        {
            RequestId = "f74a3e94dacc4484a728a01b8b049db6",
            Stage = RpcdUpdateStages.Failed,
            Terminal = true,
            Error = "The installer exited with code 1.",
            InstallerExitCode = 1,
            InstallerLog = "tail",
        });
        Assert.Equal(1, failed.InstallerExitCode);
        Assert.True(failed.HasInstallerExitCode);
        Assert.Equal("tail", failed.InstallerLog);

        var succeeded = RpcdRemoteUpdater.ToProto(new RpcdUpdateStatus { Stage = RpcdUpdateStages.Succeeded, Terminal = true });
        Assert.False(succeeded.HasInstallerExitCode);
        Assert.Equal("", succeeded.InstallerLog);
        Assert.Equal("", succeeded.OldAgentVersion);
        Assert.Equal("", succeeded.AgentVersion);

        var agentBehind = RpcdRemoteUpdater.ToProto(new RpcdUpdateStatus
        {
            Stage = RpcdUpdateStages.AgentNotUpdated,
            Terminal = true,
            OldVersion = "1.2.0-ci.991.1",
            NewVersion = "1.2.0-ci.996.1",
            OldAgentVersion = "1.2.0-ci.991.1",
            AgentVersion = "1.2.0-ci.991.1",
            Error = "RPCD 1.2.0-ci.996.1 is installed, but the agent service is 1.2.0-ci.991.1 instead of 1.2.0-ci.996.1.",
        });
        Assert.Equal(RpcdUpdateStages.AgentNotUpdated, agentBehind.Stage);
        Assert.True(agentBehind.Terminal);
        Assert.Equal("1.2.0-ci.991.1", agentBehind.OldAgentVersion);
        Assert.Equal("1.2.0-ci.991.1", agentBehind.AgentVersion);
        Assert.Equal("1.2.0-ci.996.1", agentBehind.NewVersion);

        var unchanged = RpcdRemoteUpdater.ToProto(new RpcdUpdateStatus { InstallerExitCode = 0, InstallerLog = "still the old build" });
        Assert.True(unchanged.HasInstallerExitCode);
        Assert.Equal(0, unchanged.InstallerExitCode);
    }

    [Fact]
    public void Relaunch_command_line_splits_back_into_restart_arguments()
    {
        var host = @"C:\Program Files\RemotePCDiagnostics\RemotePCDiagnostics.Host.exe";
        string[] args = ["-u=https://server.example.com:34544", "-i=748279c7-4309-452c-8b30-e02ec52e498f", "-g=acme", "--admin", "--restarted"];
        var line = WindowsCommandLine.Join([host, .. args]);

        Assert.Equal(args, RpcdRemoteUpdater.SplitRestartCommandLine(line, host));
        Assert.Null(RpcdRemoteUpdater.SplitRestartCommandLine(line + " --evil", host));
        Assert.Null(RpcdRemoteUpdater.SplitRestartCommandLine(line, @"C:\Other\RemotePCDiagnostics.Host.exe"));
    }

    [Fact]
    public void A_restarted_service_records_success_for_an_install_the_old_process_left_open()
    {
        var dir = TempDir();
        var version = AgentPaths.GetInstalledHostProductVersion();
        if (string.IsNullOrWhiteSpace(version))
            version = "1.2.0-ci.1052.1";
        var open = new RpcdUpdateStatus
        {
            RequestId = "req-restart",
            Stage = RpcdUpdateStages.Installing,
            OldVersion = "1.2.0-ci.1043.1",
            NewVersion = version,
            Percent = 100,
            Terminal = false,
            Detail = "Installing RPCD.",
            UpdatedUtc = DateTimeOffset.UtcNow.AddMinutes(-1),
            OwnerPid = 424242,
        };
        File.WriteAllText(Path.Combine(dir, RpcdUpdateSeal.FileName), open.ToJson());

        using var http = new HttpClient(new Stub(() => new HttpResponseMessage(HttpStatusCode.NotFound)));
        using var restarted = NewUpdater(dir, http, installedVersion: version);
        var current = restarted.Current(null);

        Assert.NotNull(current);
        Assert.Equal(RpcdUpdateStages.Succeeded, current.Stage);
        Assert.True(current.Terminal);
        Assert.Equal("1.2.0-ci.1043.1", current.OldVersion);
        var saved = RpcdUpdateStatus.Parse(File.ReadAllText(Path.Combine(dir, RpcdUpdateSeal.FileName)));
        Assert.Equal(RpcdUpdateStages.Succeeded, saved!.Stage);
        Assert.True(saved.Terminal);
    }

    [Fact]
    public void A_failed_setup_exit_finishes_an_install_whose_agent_is_gone()
    {
        // The elevated helper started Setup, and Setup closed the app, which ended the helper before Setup returned.
        var dir = TempDir();
        var open = new RpcdUpdateStatus
        {
            RequestId = "req-helper",
            Stage = RpcdUpdateStages.Installing,
            OldVersion = "1.2.0",
            NewVersion = "1.3.0",
            Percent = 100,
            Terminal = false,
            Detail = "Installing RPCD.",
            UpdatedUtc = DateTimeOffset.UtcNow.AddMinutes(-1),
            OwnerPid = 424242,
        };
        File.WriteAllText(Path.Combine(dir, RpcdUpdateSeal.FileName), open.ToJson());
        File.WriteAllText(Path.Combine(dir, ScheduledSetup.ExitCodeFileName), "5\r\n");

        using var http = new HttpClient(new Stub(() => new HttpResponseMessage(HttpStatusCode.NotFound)));
        using var service = NewUpdater(dir, http, installedVersion: "1.2.0");
        var current = service.Current("req-helper");

        Assert.NotNull(current);
        Assert.Equal(RpcdUpdateStages.Failed, current.Stage);
        Assert.True(current.Terminal);
        Assert.Equal(5, current.InstallerExitCode);
        Assert.Contains("code 5", current.Error);
        var saved = RpcdUpdateStatus.Parse(File.ReadAllText(Path.Combine(dir, RpcdUpdateSeal.FileName)));
        Assert.True(saved!.Terminal);
    }

    [Fact]
    public void A_zero_setup_exit_is_left_to_the_version_check()
    {
        var installing = new RpcdUpdateStatus
        {
            RequestId = "r",
            Stage = RpcdUpdateStages.Installing,
            OldVersion = "1.2.0",
            NewVersion = "1.3.0",
            UpdatedUtc = DateTimeOffset.UtcNow,
        };
        Assert.Same(installing, RpcdUpdateSeal.ApplySetupExit(installing, 0, "1.2.0", null, DateTimeOffset.UtcNow));
        Assert.Same(installing, RpcdUpdateSeal.ApplySetupExit(installing, null, "1.2.0", null, DateTimeOffset.UtcNow));
        var done = installing with { Stage = RpcdUpdateStages.Succeeded, Terminal = true };
        Assert.Same(done, RpcdUpdateSeal.ApplySetupExit(done, 5, "1.3.0", null, DateTimeOffset.UtcNow));
        var failed = RpcdUpdateSeal.ApplySetupExit(installing, 1, "1.2.0", "log tail", DateTimeOffset.UtcNow);
        Assert.Equal(RpcdUpdateStages.Failed, failed.Stage);
        Assert.Equal("log tail", failed.InstallerLog);
    }

    [Theory]
    [InlineData("Running", true)]
    [InlineData("Queued", true)]
    [InlineData("", true)]
    [InlineData(null, true)]
    [InlineData("Ready", false)]
    [InlineData("ready\r\n", false)]
    [InlineData("Disabled", false)]
    [InlineData("Missing", false)]
    public void The_setup_wait_stops_only_when_the_task_is_known_to_have_ended(string? state, bool mayRun) =>
        Assert.Equal(mayRun, ScheduledSetup.MayStillRun(state));

    [Fact]
    public void The_task_state_query_quotes_the_task_name()
    {
        var query = ScheduledSetup.StateQuery("Shop's Setup");
        Assert.Contains("-TaskName 'Shop''s Setup'", query);
        Assert.Contains("'Missing'", query);
    }

    private static RpcdRemoteUpdater NewUpdater(string dir, HttpClient http, string? installedVersion = null, bool hostRunning = false) => new(
        installedVersion: () => installedVersion ?? "1.2.0",
        hostRunning: () => hostRunning,
        relaunchArguments: () => null,
        log: null,
        http: http,
        stagingDirectory: dir);

    [Fact]
    public void Old_update_packages_are_deleted_and_recent_ones_kept()
    {
        var dir = TempDir();
        var now = DateTime.UtcNow;
        var old = Directory.CreateDirectory(Path.Combine(dir, Guid.NewGuid().ToString("N")));
        File.WriteAllText(Path.Combine(old.FullName, "RemotePCDiagnostics-Setup.exe"), "old");
        old.CreationTimeUtc = now - AgentSelfUpdater.PackageRetention - TimeSpan.FromMinutes(1);
        var running = Directory.CreateDirectory(Path.Combine(dir, Guid.NewGuid().ToString("N")));
        var other = Directory.CreateDirectory(Path.Combine(dir, "not-a-package"));
        other.CreationTimeUtc = old.CreationTimeUtc;
        var legacySetup = Path.Combine(dir, "RemotePCDiagnostics-Setup.exe");
        File.WriteAllText(legacySetup, "legacy");
        File.SetLastWriteTimeUtc(legacySetup, old.CreationTimeUtc);
        var status = Path.Combine(dir, "rpcd-update-status.json");
        File.WriteAllText(status, "{}");
        File.SetLastWriteTimeUtc(status, old.CreationTimeUtc);

        Assert.Equal(2, AgentSelfUpdater.DeleteOldPackages(dir, now));

        Assert.False(old.Exists && Directory.Exists(old.FullName));
        Assert.False(File.Exists(legacySetup));
        Assert.True(Directory.Exists(running.FullName));
        Assert.True(Directory.Exists(other.FullName));
        Assert.True(File.Exists(status));
    }

    [Fact]
    public void A_held_mutex_counts_as_a_running_host()
    {
        var name = "rpcd-test-" + Guid.NewGuid().ToString("N");
        Assert.False(RpcdRemoteUpdater.IsMutexHeld(name));
        using (new Mutex(initiallyOwned: true, name))
            Assert.True(RpcdRemoteUpdater.IsMutexHeld(name));
    }

    [Theory]
    [InlineData(true, true, true)]
    [InlineData(true, false, false)]
    [InlineData(false, true, false)]
    public void Relaunch_only_brings_back_a_session_whose_host_still_runs(bool running, bool alive, bool relaunched)
    {
        var dir = TempDir();
        var path = Path.Combine(dir, "active-session.json");
        File.WriteAllText(path, new ActiveSessionInfo(4242, running, Guid.NewGuid().ToString(), null, "Remote", DateTimeOffset.UtcNow).ToJson());

        var args = RpcdRemoteUpdater.RelaunchForActiveSession("https://server.example.com:34544", path, pid => alive && pid == 4242);

        Assert.Equal(relaunched, args is not null);
    }

    private static string TempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "rpcd-updater-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private sealed class Stub(Func<Task<HttpResponseMessage>> respond) : HttpMessageHandler
    {
        public Stub(Func<HttpResponseMessage> respond) : this(() => Task.FromResult(respond())) { }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            respond();
    }
}
