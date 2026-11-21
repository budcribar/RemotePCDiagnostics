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
    public void Activity_reported_to_the_helper_lets_the_service_accept_a_hub_update()
    {
        var dir = TempDir();
        using var http = new HttpClient(new Stub(() => new HttpResponseMessage(HttpStatusCode.NotFound)));
        using var helper = NewUpdater(dir, http);
        using var service = NewUpdater(dir, http);

        // The app talks to its helper only. Without the shared report the service would say it could not confirm the PC is idle.
        helper.ReportActivity(null);
        var status = service.Start(Approved, relaunch: null, trustCallerBusyReason: false);

        Assert.Equal(RpcdUpdateStages.Checking, status.Stage);
    }

    [Fact]
    public void A_busy_report_to_the_helper_refuses_the_hub_update_on_the_service()
    {
        var dir = TempDir();
        using var http = new HttpClient(new Stub(() => new HttpResponseMessage(HttpStatusCode.NotFound)));
        using var helper = NewUpdater(dir, http);
        using var service = NewUpdater(dir, http);

        helper.ReportActivity("A fix is running.");
        var status = service.Start(Approved, relaunch: null, trustCallerBusyReason: false);

        Assert.Equal(RpcdUpdateStages.Refused, status.Stage);
        Assert.Equal("A fix is running.", status.Error);
    }

    [Fact]
    public void An_idle_session_activity_file_alone_does_not_start_a_hub_update()
    {
        // Any local process can write the session folder, so its "idle" must not be enough to start an update.
        var dir = TempDir();
        var sessionFile = Path.Combine(dir, "session", AgentLayout.UpdateActivityFileName);
        using var http = new HttpClient(new Stub(() => new HttpResponseMessage(HttpStatusCode.NotFound)));
        using var service = NewUpdater(dir, http, sessionFile, TimeSpan.Zero);

        Assert.Null(RpcdActivityReport.TryWrite(sessionFile, null, DateTimeOffset.UtcNow));
        var status = service.Start(Approved, relaunch: null, trustCallerBusyReason: false);

        Assert.Equal(RpcdUpdateStages.Refused, status.Stage);
        Assert.Equal(RpcdUpdateSession.ActivityUnconfirmed, status.Error);
    }

    [Fact]
    public void A_busy_session_activity_file_refuses_even_after_an_older_idle_pipe_report()
    {
        var dir = TempDir();
        var sessionFile = Path.Combine(dir, "session", AgentLayout.UpdateActivityFileName);
        using var http = new HttpClient(new Stub(() => new HttpResponseMessage(HttpStatusCode.NotFound)));
        using var helper = NewUpdater(dir, http, sessionFile);
        using var service = NewUpdater(dir, http, sessionFile, TimeSpan.Zero);

        helper.ReportActivity(null);
        Assert.Null(RpcdActivityReport.TryWrite(sessionFile, "A check is running.", DateTimeOffset.UtcNow.AddSeconds(1)));
        var status = service.Start(Approved, relaunch: null, trustCallerBusyReason: false);

        Assert.Equal(RpcdUpdateStages.Refused, status.Stage);
        Assert.Equal("A check is running.", status.Error);
    }

    [Fact]
    public void Trusted_report_ignores_an_idle_session_copy_and_keeps_a_newer_busy_one()
    {
        var now = DateTimeOffset.UtcNow;
        var securedIdle = new RpcdActivityReport(null, now);
        Assert.Same(securedIdle, RpcdActivityReport.Trusted(securedIdle, new RpcdActivityReport(null, now.AddSeconds(5))));
        Assert.Null(RpcdActivityReport.Trusted(null, new RpcdActivityReport(null, now)));
        var busy = new RpcdActivityReport("A fix is running.", now.AddSeconds(5));
        Assert.Same(busy, RpcdActivityReport.Trusted(securedIdle, busy));
        Assert.Same(securedIdle, RpcdActivityReport.Trusted(securedIdle, busy with { At = now.AddSeconds(-5) }));
    }

    [Fact]
    public void A_missing_activity_file_is_logged_and_named_in_the_refusal_detail()
    {
        var dir = TempDir();
        var log = new List<string>();
        using var http = new HttpClient(new Stub(() => new HttpResponseMessage(HttpStatusCode.NotFound)));
        using var service = NewUpdater(dir, http, Path.Combine(dir, "missing-activity.json"), TimeSpan.Zero, log);

        var status = service.Start(Approved, relaunch: null, trustCallerBusyReason: false);

        Assert.Equal(RpcdUpdateStages.Refused, status.Stage);
        Assert.Equal(RpcdUpdateSession.ActivityUnconfirmed, status.Error);
        Assert.Contains(RpcdUpdateSession.ProbeNoReport, status.Detail);
        Assert.Contains(log, line => line.StartsWith("[rpcd-update] ", StringComparison.Ordinal) && line.Contains(RpcdUpdateSession.ProbeNoReport, StringComparison.Ordinal));
    }

    [Fact]
    public async Task The_probe_waits_for_the_pipe_activity_report()
    {
        var dir = TempDir();
        using var http = new HttpClient(new Stub(() => new HttpResponseMessage(HttpStatusCode.NotFound)));
        using var helper = NewUpdater(dir, http);
        using var service = NewUpdater(dir, http, probe: TimeSpan.FromSeconds(3));
        var write = Task.Run(async () =>
        {
            await Task.Delay(400);
            helper.ReportActivity(null);
        });

        var status = service.Start(Approved, relaunch: null, trustCallerBusyReason: false);
        await write;

        Assert.Equal(RpcdUpdateStages.Checking, status.Stage);
    }

    [Fact]
    public void An_unreadable_activity_file_is_named_in_the_refusal_detail()
    {
        var dir = TempDir();
        var sessionFile = Path.Combine(dir, "session-activity.json");
        File.WriteAllText(sessionFile, "{}");
        using var held = new FileStream(sessionFile, FileMode.Open, FileAccess.Read, FileShare.None);
        var log = new List<string>();
        using var http = new HttpClient(new Stub(() => new HttpResponseMessage(HttpStatusCode.NotFound)));
        using var service = NewUpdater(dir, http, sessionFile, TimeSpan.Zero, log);

        var status = service.Start(Approved, relaunch: null, trustCallerBusyReason: false);

        Assert.Equal(RpcdUpdateStages.Refused, status.Stage);
        Assert.Contains("could not read", status.Detail);
        Assert.Contains(log, line => line.Contains("could not read", StringComparison.Ordinal));
        held.Dispose();
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

    private static RpcdRemoteUpdater NewUpdater(string dir, HttpClient http, string? sessionActivityPath = null, TimeSpan? probe = null, List<string>? log = null, string? installedVersion = null) => new(
        installedVersion: () => installedVersion ?? "1.2.0",
        hostRunning: () => true,
        relaunchArguments: () => null,
        log: log is null ? null : log.Add,
        http: http,
        stagingDirectory: dir,
        sessionActivityPath: sessionActivityPath ?? Path.Combine(dir, "session-activity.json"),
        activityProbeTimeout: probe ?? TimeSpan.Zero);

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
