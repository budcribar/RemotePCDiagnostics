using System.Net;
using System.Security.Cryptography;
using System.Text;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Tests;

public class RpcdRemoteUpdateTests
{
    private const string OldVersion = "1.2.0-ci.991.1";
    private const string NewVersion = "1.2.0-ci.996.1";
    private const string ExeName = "RemotePCDiagnostics-Setup-1.2.0-win-x64.exe";
    private const string ExeUrl = "https://github.com/budcribar/RemotePCDiagnostics/releases/download/prerelease/" + ExeName;

    [Fact]
    public void Approval_is_required_and_a_label_is_not_approval()
    {
        var session = new RpcdUpdateSession();
        var started = session.TryBegin(new RpcdUpdateRequest("prerelease", null, Approved: false, ApprovedBy: "shop owner"), hostRunning: false, trustCallerBusyReason: false, DateTimeOffset.UtcNow, out var status);

        Assert.False(started);
        Assert.Equal(RpcdUpdateStages.Refused, status.Stage);
        Assert.True(status.Terminal);
        Assert.Equal(RpcdUpdateSession.ApprovalRequired, status.Error);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("beta")]
    [InlineData("stable ")]
    public void Channel_must_be_stable_or_prerelease(string? channel)
    {
        if (channel == "stable ")
        {
            var ok = new RpcdUpdateSession();
            Assert.True(ok.TryBegin(new RpcdUpdateRequest(channel, null, true), false, true, DateTimeOffset.UtcNow, out var accepted));
            Assert.Equal("stable", accepted.Channel);
            return;
        }

        var session = new RpcdUpdateSession();
        var started = session.TryBegin(new RpcdUpdateRequest(channel, null, true), false, true, DateTimeOffset.UtcNow, out var status);
        Assert.False(started);
        Assert.Equal("Channel must be stable or prerelease.", status.Error);
    }

    [Fact]
    public void Busy_work_refuses_before_any_download()
    {
        var session = new RpcdUpdateSession();
        var calls = 0;
        using var http = new HttpClient(new Stub(_ => { calls++; return new HttpResponseMessage(HttpStatusCode.OK); }));
        var reason = "A check is running (DriveHealth). Wait until it finishes before updating Remote PC Diagnostics.";

        var started = session.TryBegin(
            new RpcdUpdateRequest("prerelease", NewVersion, true, BusyReason: reason),
            hostRunning: true,
            trustCallerBusyReason: true,
            DateTimeOffset.UtcNow,
            out var status);

        Assert.False(started);
        Assert.Equal(RpcdUpdateStages.Refused, status.Stage);
        Assert.Contains("DriveHealth", status.Error);
        Assert.Equal(0, calls);
    }

    [Fact]
    public void Hub_command_cannot_claim_the_pc_is_idle_while_the_app_is_open()
    {
        var session = new RpcdUpdateSession();
        var started = session.TryBegin(new RpcdUpdateRequest("prerelease", null, true), hostRunning: true, trustCallerBusyReason: false, DateTimeOffset.UtcNow, out var status);

        Assert.False(started);
        Assert.Equal(RpcdUpdateSession.ActivityUnconfirmed, status.Error);
    }

    [Fact]
    public void A_fresh_idle_report_lets_a_hub_command_continue()
    {
        var now = DateTimeOffset.UtcNow;
        var session = new RpcdUpdateSession();
        session.ReportActivity(null, now);

        Assert.True(session.TryBegin(new RpcdUpdateRequest("stable", null, true), hostRunning: true, trustCallerBusyReason: false, now, out var status));
        Assert.Equal(RpcdUpdateStages.Checking, status.Stage);
        Assert.False(status.Terminal);
    }

    [Fact]
    public void A_second_update_is_refused_without_replacing_the_one_in_progress()
    {
        var session = new RpcdUpdateSession();
        Assert.True(session.TryBegin(new RpcdUpdateRequest("prerelease", null, true), false, true, DateTimeOffset.UtcNow, out var first));
        var started = session.TryBegin(new RpcdUpdateRequest("stable", null, true), false, true, DateTimeOffset.UtcNow, out var second);

        Assert.False(started);
        Assert.Equal("An RPCD update is already in progress.", second.Error);
        Assert.Equal(first.RequestId, session.Current(null, OldVersion, DateTimeOffset.UtcNow)!.RequestId);
        Assert.Equal(RpcdUpdateStages.Checking, session.Current(null, OldVersion, DateTimeOffset.UtcNow)!.Stage);
    }

    [Fact]
    public void Requests_at_the_same_moment_start_only_one_update()
    {
        var session = new RpcdUpdateSession();
        var now = DateTimeOffset.UtcNow;
        var started = 0;
        Parallel.For(0, 32, i =>
        {
            if (session.TryBegin(new RpcdUpdateRequest("stable", null, true, BusyReason: ""), false, true, now, out _))
                Interlocked.Increment(ref started);
        });
        Assert.Equal(1, started);
    }

    [Fact]
    public void An_update_another_agent_process_saved_refuses_a_second_one()
    {
        var now = DateTimeOffset.UtcNow;
        var session = new RpcdUpdateSession(ownerPid: 1);
        session.Adopt(new RpcdUpdateStatus
        {
            RequestId = "other",
            Stage = RpcdUpdateStages.Downloading,
            Terminal = false,
            UpdatedUtc = now.AddSeconds(-10),
            OwnerPid = 2,
        });

        Assert.False(session.TryBegin(new RpcdUpdateRequest("stable", null, true, BusyReason: ""), false, true, now, out var status));
        Assert.Equal(RpcdUpdateStages.Refused, status.Stage);
        Assert.Contains("already in progress", status.Error);
        Assert.Equal("other", session.Current(null, null, now)!.RequestId);
    }

    [Fact]
    public void An_older_saved_status_does_not_replace_a_newer_one()
    {
        var now = DateTimeOffset.UtcNow;
        var session = new RpcdUpdateSession();
        Assert.True(session.TryBegin(new RpcdUpdateRequest("stable", null, true, BusyReason: ""), false, true, now, out var mine));
        session.Adopt(new RpcdUpdateStatus { RequestId = "stale", Stage = RpcdUpdateStages.Failed, Terminal = true, UpdatedUtc = now.AddMinutes(-5) });
        Assert.Equal(mine.RequestId, session.Current(null, null, now)!.RequestId);
        Assert.Equal(Environment.ProcessId, mine.OwnerPid);
    }

    [Fact]
    public void An_older_activity_report_does_not_hide_a_newer_busy_one()
    {
        var now = DateTimeOffset.UtcNow;
        var session = new RpcdUpdateSession();
        session.ReportActivity("A check is running (Sensors).", now);
        session.ReportActivity(null, now.AddSeconds(-20));
        Assert.Equal("A check is running (Sensors).", session.ActivityBlock(hostRunning: true, now));
    }

    [Fact]
    public async Task Already_up_to_date_does_not_download_or_install()
    {
        var installer = new Installer();
        var session = await RunAsync(OldVersion, releaseVersion: OldVersion, explicitVersion: null, installer, readBack: OldVersion);

        Assert.Equal(0, installer.Calls);
        var status = session.Current(null, OldVersion, DateTimeOffset.UtcNow);
        Assert.Equal(RpcdUpdateStages.AlreadyUpToDate, status!.Stage);
        Assert.True(status.Terminal);
        Assert.Contains(OldVersion, status.Error);
        Assert.Equal(OldVersion, status.OldVersion);
        Assert.Equal(OldVersion, status.NewVersion);
    }

    [Fact]
    public async Task An_older_explicit_version_is_not_the_current_release()
    {
        var installer = new Installer();
        var session = await RunAsync(OldVersion, releaseVersion: NewVersion, explicitVersion: "1.2.0-ci.991.1", installer, readBack: OldVersion);

        Assert.Equal(0, installer.Calls);
        var status = session.Current(null, OldVersion, DateTimeOffset.UtcNow);
        Assert.Equal(RpcdUpdateStages.Failed, status!.Stage);
        Assert.Contains("not the current prerelease release", status.Error);
    }

    [Fact]
    public async Task Missing_checksum_refuses_the_release()
    {
        var installer = new Installer();
        var session = await RunAsync(OldVersion, NewVersion, null, installer, OldVersion, includeSha: false);

        Assert.Equal(0, installer.Calls);
        Assert.Contains("SHA-256", session.Current(null, OldVersion, DateTimeOffset.UtcNow)!.Error);
    }

    [Fact]
    public async Task Checksum_mismatch_leaves_the_old_version_and_no_partial_file()
    {
        var dir = TempDir();
        var installer = new Installer();
        try
        {
            var session = await RunAsync(OldVersion, NewVersion, NewVersion, installer, OldVersion, directory: dir, badHash: true);
            Assert.Equal(0, installer.Calls);
            Assert.Contains("SHA-256", session.Current(null, OldVersion, DateTimeOffset.UtcNow)!.Error);
            Assert.Empty(Directory.Exists(dir) ? Directory.GetFiles(dir, "*.part") : []);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { }
        }
    }

    [Fact]
    public async Task Untrusted_installer_url_is_refused()
    {
        var installer = new Installer();
        var session = await RunAsync(OldVersion, NewVersion, null, installer, OldVersion, exeUrl: "https://evil.example.com/setup.exe");
        Assert.Equal(0, installer.Calls);
        Assert.Contains("official GitHub release", session.Current(null, OldVersion, DateTimeOffset.UtcNow)!.Error);
    }

    [Fact]
    public async Task TestShop_bundle_is_not_installed()
    {
        var installer = new Installer();
        var session = await RunAsync(OldVersion, NewVersion, null, installer, OldVersion, testShopOnly: true);
        Assert.Equal(0, installer.Calls);
        Assert.Contains("TestShop", session.Current(null, OldVersion, DateTimeOffset.UtcNow)!.Error);
    }

    [Fact]
    public async Task Successful_update_verifies_the_hash_preserves_agent_settings_and_returns_both_versions()
    {
        var installer = new Installer { ExitCode = 0 };
        var session = await RunAsync(OldVersion, NewVersion, "v" + NewVersion, installer, readBack: NewVersion);

        Assert.Equal(1, installer.Calls);
        Assert.Contains("/VERYSILENT", installer.Arguments);
        Assert.Contains("/PRESERVEAGENT", installer.Arguments);
        Assert.DoesNotContain("AGENTMSI", installer.Arguments);
        Assert.Contains("/RELAUNCHARGS=", installer.Arguments);

        var status = session.Current(null, NewVersion, DateTimeOffset.UtcNow);
        Assert.Equal(RpcdUpdateStages.Succeeded, status!.Stage);
        Assert.True(status.Terminal);
        Assert.Equal(OldVersion, status.OldVersion);
        Assert.Equal(NewVersion, status.NewVersion);
        Assert.Null(status.Error);
    }

    [Fact]
    public async Task Installer_failure_reports_the_exit_code_and_leaves_the_old_version()
    {
        var installer = new Installer { ExitCode = 5 };
        var session = await RunAsync(OldVersion, NewVersion, null, installer, readBack: OldVersion);
        var status = session.Current(null, OldVersion, DateTimeOffset.UtcNow);
        Assert.Equal(RpcdUpdateStages.Failed, status!.Stage);
        Assert.Contains("exited with code 5", status.Error);
        Assert.Contains(OldVersion, status.Error);
        Assert.Equal(OldVersion, status.OldVersion);
    }

    [Fact]
    public async Task A_zero_exit_that_does_not_change_the_version_is_a_failure()
    {
        var installer = new Installer { ExitCode = 0 };
        var session = await RunAsync(OldVersion, NewVersion, null, installer, readBack: OldVersion);
        var status = session.Current(null, OldVersion, DateTimeOffset.UtcNow);
        Assert.Equal(RpcdUpdateStages.Failed, status!.Stage);
        Assert.Contains("still " + OldVersion, status.Error);
    }

    [Fact]
    public void Reconcile_marks_success_when_the_installed_version_caught_up()
    {
        var started = DateTimeOffset.UtcNow.AddMinutes(-2);
        var status = new RpcdUpdateStatus
        {
            RequestId = "req",
            Stage = RpcdUpdateStages.Installing,
            OldVersion = OldVersion,
            NewVersion = NewVersion,
            UpdatedUtc = started,
        };
        var done = RpcdGitHubRelease.Reconcile(status, NewVersion, DateTimeOffset.UtcNow, RpcdUpdateSession.InstallGiveUp);
        Assert.Equal(RpcdUpdateStages.Succeeded, done.Stage);
        Assert.Equal(OldVersion, done.OldVersion);
        Assert.Equal(NewVersion, done.NewVersion);
    }

    [Fact]
    public void Reconcile_marks_failure_when_the_install_never_finishes()
    {
        var status = new RpcdUpdateStatus
        {
            RequestId = "req",
            Stage = RpcdUpdateStages.Installing,
            OldVersion = OldVersion,
            NewVersion = NewVersion,
            UpdatedUtc = DateTimeOffset.UtcNow.AddMinutes(-30),
        };
        var done = RpcdGitHubRelease.Reconcile(status, OldVersion, DateTimeOffset.UtcNow, RpcdUpdateSession.InstallGiveUp);
        Assert.Equal(RpcdUpdateStages.Failed, done.Stage);
        Assert.Contains("still " + OldVersion, done.Error);
    }

    [Fact]
    public void Build_version_is_read_from_the_release_notes()
    {
        Assert.Equal(NewVersion, RpcdGitHubRelease.ParseBuildVersion("Build version: `1.2.0-ci.996.1`\nmore"));
        Assert.Null(RpcdGitHubRelease.ParseBuildVersion("no version here"));
    }

    [Fact]
    public void Activity_block_names_a_check_a_fix_the_workflow_and_a_stress_test()
    {
        Assert.Null(AgentExports.UpdateBlockReason(new AgentExports.ActivitySnapshot([])));

        var check = AgentExports.UpdateBlockReason(new AgentExports.ActivitySnapshot(
            [new AgentExports.RunningCheck("DriveHealth", "Drives", null, null)]));
        Assert.Contains("check is running (DriveHealth)", check);

        var stress = AgentExports.UpdateBlockReason(new AgentExports.ActivitySnapshot([],
            StressSuite: new StressSuiteProgress(StressSuiteMode.Short, 1, 3, "CPU", [], Finished: false, null)));
        Assert.Contains("stress test is running", stress);

        var workflow = AgentExports.UpdateBlockReason(new AgentExports.ActivitySnapshot([],
            Workflow: new AgentExports.WorkflowActivity(WorkflowStage.Applying, true, "Applying fixes")));
        Assert.Contains("service workflow is running", workflow);

        var fix = AgentExports.UpdateBlockReason(new AgentExports.ActivitySnapshot([],
            Fix: new FixRun(new AreaAction(RemediationKind.ScheduleCleanRestart, "Restart"), "Restart", "Storage", DateTimeOffset.UtcNow)));
        Assert.Contains("fix is running", fix);
    }

    private static async Task<RpcdUpdateSession> RunAsync(
        string installed,
        string releaseVersion,
        string? explicitVersion,
        Installer installer,
        string readBack,
        bool includeSha = true,
        bool badHash = false,
        bool testShopOnly = false,
        string? exeUrl = null,
        string? directory = null)
    {
        var payload = Encoding.UTF8.GetBytes("official-installer");
        var hash = badHash ? new string('a', 64) : Convert.ToHexStringLower(SHA256.HashData(payload));
        var body = ReleaseJson(releaseVersion, includeSha, testShopOnly, exeUrl, hash);
        using var http = new HttpClient(new Stub(req =>
        {
            var url = req.RequestUri!.AbsoluteUri;
            if (url.Contains("/releases/", StringComparison.Ordinal) && !url.EndsWith(".exe", StringComparison.Ordinal) && !url.EndsWith(".sha256", StringComparison.Ordinal))
            {
                if (url.Contains("/releases/tags/prerelease", StringComparison.Ordinal) || url.EndsWith("/releases/latest", StringComparison.Ordinal))
                    return Json(body);
                return new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new StringContent("{\"message\":\"Not Found\"}") };
            }
            if (url.EndsWith(".sha256", StringComparison.Ordinal))
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(hash + "  " + ExeName + "\n") };
            if (url == (exeUrl ?? ExeUrl))
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(payload) };
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));

        var session = new RpcdUpdateSession();
        var now = DateTimeOffset.UtcNow;
        Assert.True(session.TryBegin(new RpcdUpdateRequest("prerelease", explicitVersion, true), false, true, now, out _));
        await session.ExecuteAsync(new RpcdUpdateRequest("prerelease", explicitVersion, true), new RpcdUpdateRun
        {
            Http = http,
            InstalledVersion = installed,
            ReadInstalledVersion = () => readBack,
            StagingDirectory = directory ?? TempDir(),
            RelaunchArguments = ["-u=https://server.example.com:34544", "-i=748279c7-4309-452c-8b30-e02ec52e498f", "--restarted"],
            RunInstaller = (install, _) =>
            {
                installer.Calls++;
                installer.Arguments = install.Arguments;
                return Task.FromResult(installer.ExitCode);
            },
            UtcNow = now,
        }, CancellationToken.None);
        return session;
    }

    private static string ReleaseJson(string version, bool includeSha, bool testShopOnly, string? exeUrl, string hash)
    {
        var name = testShopOnly ? "RemotePCDiagnostics-TestShop-Setup-1.2.0-win-x64.exe" : ExeName;
        var url = exeUrl ?? "https://github.com/budcribar/RemotePCDiagnostics/releases/download/prerelease/" + name;
        var assets = new StringBuilder();
        assets.Append("{\"name\":\"").Append(name).Append("\",\"browser_download_url\":\"").Append(url).Append("\"}");
        if (includeSha && !testShopOnly)
            assets.Append(",{\"name\":\"").Append(name).Append(".sha256\",\"browser_download_url\":\"").Append(url).Append(".sha256\"}");
        _ = hash;
        return "{\"tag_name\":\"prerelease\",\"prerelease\":true,\"html_url\":\"https://github.com/budcribar/RemotePCDiagnostics/releases/tag/prerelease\",\"body\":\"Build version: `"
            + version + "`\\n\",\"assets\":[" + assets + "]}";
    }

    private static string TempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), "rpcd-update-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static HttpResponseMessage Json(string body) =>
        new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private sealed class Installer
    {
        public int Calls { get; set; }
        public int ExitCode { get; set; }
        public string? Arguments { get; set; }
    }

    private sealed class Stub(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(respond(request));
    }
}
