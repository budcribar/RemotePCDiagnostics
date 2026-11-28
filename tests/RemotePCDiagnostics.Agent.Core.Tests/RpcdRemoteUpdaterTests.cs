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

    [Fact]
    public void A_hub_update_is_refused_while_the_app_holds_the_update_lock()
    {
        var dir = TempDir();
        var name = "rpcd-test-" + Guid.NewGuid().ToString("N");
        using var http = new HttpClient(new Stub(() => new HttpResponseMessage(HttpStatusCode.NotFound)));
        using var service = NewUpdater(dir, http, lockName: name);
        var app = new UpdateBusyHold(() => UpdateBusyLock.TryHold(TimeSpan.Zero, name));

        using (app.Enter())
        {
            Assert.True(app.IsHeld);
            var refused = service.Start(Approved, relaunch: null);
            Assert.Equal(RpcdUpdateStages.Refused, refused.Stage);
            Assert.Equal(UpdateBusyLock.BusyMessage, refused.Error);
        }

        Assert.False(app.IsHeld);
        var started = service.Start(Approved, relaunch: null);
        Assert.Equal(RpcdUpdateStages.Checking, started.Stage);
    }

    [Fact]
    public void The_update_lock_is_shared_by_overlapping_work_and_given_back_by_the_last()
    {
        var name = "rpcd-test-" + Guid.NewGuid().ToString("N");
        var hold = new UpdateBusyHold(() => UpdateBusyLock.TryHold(TimeSpan.Zero, name));
        var check = hold.Enter();
        var undo = hold.Enter();
        check.Dispose();
        Assert.True(hold.IsHeld);
        Assert.Null(UpdateBusyLock.TryHold(TimeSpan.Zero, name));
        undo.Dispose();
        undo.Dispose();
        Assert.False(hold.IsHeld);
        using var agent = UpdateBusyLock.TryHold(TimeSpan.FromSeconds(1), name);
        Assert.NotNull(agent);
    }

    [Fact]
    public void A_missed_first_try_takes_the_update_lock_on_retry()
    {
        var name = "rpcd-test-" + Guid.NewGuid().ToString("N");
        var hold = new UpdateBusyHold(() => UpdateBusyLock.TryHold(TimeSpan.Zero, name));
        var other = UpdateBusyLock.TryHold(TimeSpan.Zero, name);
        Assert.NotNull(other);

        using (hold.Enter())
        {
            Assert.False(hold.IsHeld);
            hold.Retry();
            Assert.False(hold.IsHeld);
            other!.Dispose();
            SpinWait.SpinUntil(() => { hold.Retry(); return hold.IsHeld; }, TimeSpan.FromSeconds(5));
            Assert.True(hold.IsHeld);
        }

        Assert.False(hold.IsHeld);
        hold.Retry();
        Assert.False(hold.IsHeld);
    }

    [Fact]
    public async Task An_update_running_in_one_agent_process_refuses_one_in_the_other()
    {
        var dir = TempDir();
        var hold = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var http = new HttpClient(new Stub(() => hold.Task));
        using var helper = NewUpdater(dir, http);
        using var service = NewUpdater(dir, http);

        var first = helper.Start(Approved with { BusyReason = "" }, relaunch: null);
        Assert.Equal(RpcdUpdateStages.Checking, first.Stage);

        var second = service.Start(Approved with { BusyReason = "" }, relaunch: null);
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

    /// <param name="lockName">The update lock to use. Null gives each updater a lock that is always free.</param>
    private static RpcdRemoteUpdater NewUpdater(string dir, HttpClient http, string? installedVersion = null, string? lockName = null,
        TimeSpan? waitLimit = null, TimeSpan? waitHeartbeat = null) => new(
        installedVersion: () => installedVersion ?? "1.2.0",
        relaunchArguments: () => null,
        log: null,
        http: http,
        stagingDirectory: dir,
        holdUpdateLock: lockName is null ? () => new FreeLock() : () => UpdateBusyLock.TryHold(TimeSpan.FromMilliseconds(50), lockName),
        waitLimit: waitLimit,
        waitHeartbeat: waitHeartbeat);

    private static RpcdUpdateStatus WaitFor(RpcdRemoteUpdater updater, string requestId, Func<RpcdUpdateStatus, bool> done)
    {
        RpcdUpdateStatus? status = null;
        Assert.True(SpinWait.SpinUntil(() => (status = updater.Current(requestId)) is { } s && done(s), TimeSpan.FromSeconds(10)),
            $"status stayed {status?.Stage}");
        return status!;
    }

    [Fact]
    public void A_hub_update_waits_while_the_app_is_busy_and_starts_when_it_is_free()
    {
        var dir = TempDir();
        var name = "rpcd-test-" + Guid.NewGuid().ToString("N");
        var asked = 0;
        using var http = new HttpClient(new Stub(() => { Interlocked.Increment(ref asked); return new HttpResponseMessage(HttpStatusCode.NotFound); }));
        using var service = NewUpdater(dir, http, lockName: name);
        var app = new UpdateBusyHold(() => UpdateBusyLock.TryHold(TimeSpan.Zero, name));

        var check = app.Enter();
        var waiting = service.Start(Approved, relaunch: null, waitIfBusy: true);
        Assert.Equal(RpcdUpdateStages.Waiting, waiting.Stage);
        Assert.False(waiting.Terminal);
        Assert.Equal(RpcdUpdateStages.Waiting, service.Current(waiting.RequestId)!.Stage);
        Thread.Sleep(300);
        Assert.Equal(0, Volatile.Read(ref asked)); // nothing downloaded while busy

        // A second request is refused while the first one waits.
        var second = service.Start(Approved, relaunch: null, waitIfBusy: true);
        Assert.Equal(RpcdUpdateStages.Refused, second.Stage);
        Assert.Contains("already in progress", second.Error);

        check.Dispose();
        var after = WaitFor(service, waiting.RequestId, s => s.Stage != RpcdUpdateStages.Waiting && s.Stage != RpcdUpdateStages.Checking);
        Assert.Equal(RpcdUpdateStages.Failed, after.Stage); // the stub has no release, which proves the update went on past waiting
        Assert.True(Volatile.Read(ref asked) > 0);

        // Fixes may take the lock again once the update is done with it.
        Assert.True(SpinWait.SpinUntil(() => { using var h = app.TryEnter(); return h is not null; }, TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public void A_waiting_update_can_be_cancelled_and_never_installs()
    {
        var dir = TempDir();
        var name = "rpcd-test-" + Guid.NewGuid().ToString("N");
        var asked = 0;
        using var http = new HttpClient(new Stub(() => { Interlocked.Increment(ref asked); return new HttpResponseMessage(HttpStatusCode.NotFound); }));
        using var service = NewUpdater(dir, http, lockName: name);
        var app = new UpdateBusyHold(() => UpdateBusyLock.TryHold(TimeSpan.Zero, name));

        using (app.Enter())
        {
            var waiting = service.Start(Approved, relaunch: null, waitIfBusy: true);
            Assert.Null(service.Cancel("not-this-one"));
            var cancelled = service.Cancel(waiting.RequestId);
            Assert.NotNull(cancelled);
            Assert.Equal(RpcdUpdateStages.Cancelled, cancelled!.Stage);
            Assert.True(cancelled.Terminal);
        }

        Thread.Sleep(500);
        Assert.Equal(0, Volatile.Read(ref asked));
        Assert.True(SpinWait.SpinUntil(() => { using var h = app.TryEnter(); return h is not null; }, TimeSpan.FromSeconds(5)),
            "the cancelled update must not keep the lock");
        var next = service.Start(Approved, relaunch: null, waitIfBusy: true);
        Assert.NotEqual(RpcdUpdateStages.Refused, next.Stage);
    }

    [Fact]
    public void A_waiting_update_gives_up_after_the_wait_limit()
    {
        var dir = TempDir();
        var name = "rpcd-test-" + Guid.NewGuid().ToString("N");
        using var http = new HttpClient(new Stub(() => new HttpResponseMessage(HttpStatusCode.NotFound)));
        using var service = NewUpdater(dir, http, lockName: name, waitLimit: TimeSpan.FromMilliseconds(600), waitHeartbeat: TimeSpan.FromMilliseconds(100));
        var app = new UpdateBusyHold(() => UpdateBusyLock.TryHold(TimeSpan.Zero, name));

        using (app.Enter())
        {
            var waiting = service.Start(Approved, relaunch: null, waitIfBusy: true);
            var done = WaitFor(service, waiting.RequestId, s => s.Terminal);
            Assert.Equal(RpcdUpdateStages.Refused, done.Stage);
            Assert.Contains("still busy", done.Error);
        }
    }

    [Fact]
    public void The_app_s_own_update_request_still_refuses_while_busy()
    {
        var dir = TempDir();
        var name = "rpcd-test-" + Guid.NewGuid().ToString("N");
        using var http = new HttpClient(new Stub(() => new HttpResponseMessage(HttpStatusCode.NotFound)));
        using var service = NewUpdater(dir, http, lockName: name);
        var app = new UpdateBusyHold(() => UpdateBusyLock.TryHold(TimeSpan.Zero, name));
        using (app.Enter())
        {
            var refused = service.Start(Approved, relaunch: null);
            Assert.Equal(RpcdUpdateStages.Refused, refused.Stage);
        }
    }

    [Fact]
    public void Fixes_are_refused_while_an_update_holds_the_lock()
    {
        var name = "rpcd-test-" + Guid.NewGuid().ToString("N");
        var app = new UpdateBusyHold(() => UpdateBusyLock.TryHold(TimeSpan.Zero, name));
        using (UpdateBusyLock.TryHold(TimeSpan.Zero, name))
        {
            Assert.Null(app.TryEnter());
            Assert.False(app.IsHeld);
        }
        using var fix = app.TryEnter();
        Assert.NotNull(fix);
        using var overlapping = app.TryEnter(); // a second piece of work shares the hold
        Assert.NotNull(overlapping);
    }

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

    [Theory]
    [InlineData(true, true, true)]
    [InlineData(true, false, false)]
    [InlineData(false, true, false)]
    public void Relaunch_only_brings_back_a_session_whose_host_still_runs(bool running, bool alive, bool relaunched)
    {
        var dir = TempDir();
        var path = Path.Combine(dir, "active-session.json");
        File.WriteAllText(path, new ActiveSessionInfo(4242, running, Guid.NewGuid().ToString(), null, "Remote", DateTimeOffset.UtcNow).ToJson());

        var args = RpcdRemoteUpdater.RelaunchForActiveSession("https://server.example.com:34544", path, pid => alive && pid == 4242, DateTimeOffset.UtcNow);

        Assert.Equal(relaunched, args is not null);
    }

    [Theory]
    [InlineData(true, null, true)]       // the technician has control as the update starts
    [InlineData(false, -30, true)]       // their page left in control 30 s ago
    [InlineData(false, -600, false)]     // long ago
    [InlineData(false, null, false)]     // the person at the PC has control
    public void Relaunch_after_an_update_gives_control_back_to_the_technician_who_had_it(bool control, int? leftSecondsAgo, bool giveControl)
    {
        var now = DateTimeOffset.Parse("2026-11-28T15:40:00Z");
        var dir = TempDir();
        var path = Path.Combine(dir, "active-session.json");
        File.WriteAllText(path, new ActiveSessionInfo(4242, true, Guid.NewGuid().ToString(), "test-shop", "Remote", now.AddHours(-1),
            Admin: true, RemoteControl: control, RemoteLeftInControlUtc: leftSecondsAgo is { } s ? now.AddSeconds(s) : null).ToJson());

        var args = RpcdRemoteUpdater.RelaunchForActiveSession("https://server.example.com:34544", path, _ => true, now);

        Assert.NotNull(args);
        Assert.Equal(giveControl, args.Contains(SessionLaunchOptions.GiveControlArg));
        Assert.Equal(giveControl, SessionLaunchOptions.Parse(args).GiveControl);
    }

    private sealed class FreeLock : IDisposable
    {
        public void Dispose() { }
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
