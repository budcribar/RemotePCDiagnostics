using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
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
        Assert.Contains(RpcdUpdateSession.ProbeNoReport, status.Detail);
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
        Assert.Contains("/FORCECLOSEAPPLICATIONS", installer.Arguments);
        Assert.Contains("/LOG=\"", installer.Arguments);
        Assert.Contains(RpcdSetupLog.FileName, installer.Arguments);
        Assert.DoesNotContain("AGENTMSI", installer.Arguments);
        Assert.False(session.Current(null, NewVersion, DateTimeOffset.UtcNow)!.UpdateAgent);
        Assert.Contains("/RELAUNCHARGS=", installer.Arguments);

        var status = session.Current(null, NewVersion, DateTimeOffset.UtcNow);
        Assert.Equal(RpcdUpdateStages.Succeeded, status!.Stage);
        Assert.True(status.Terminal);
        Assert.Equal(OldVersion, status.OldVersion);
        Assert.Equal(NewVersion, status.NewVersion);
        Assert.Null(status.Error);
        Assert.Null(status.InstallerExitCode);
        Assert.Null(status.InstallerLog);
    }

    [Fact]
    public async Task An_installed_agent_is_updated_from_the_verified_release_msi()
    {
        var installer = new Installer { ExitCode = 0 };
        var session = await RunAsync(
            OldVersion, NewVersion, null, installer, readBack: NewVersion,
            agentInstalled: true, agentBefore: OldVersion, agentAfter: NewVersion, includeAgentMsi: true);

        Assert.Equal(1, installer.Calls);
        Assert.Contains("/PRESERVEAGENT", installer.Arguments);
        Assert.Contains("/AGENTMSI=", installer.Arguments);
        Assert.Contains("RemotePCDiagnostics.Agent-" + NewVersion + "-win-x64.msi", installer.Arguments);
        Assert.DoesNotContain("ENROLLMENT_KEY", installer.Arguments);
        Assert.DoesNotContain("SERVER_URL", installer.Arguments);
        Assert.DoesNotContain("--key=", installer.Arguments);

        var status = session.Current(null, NewVersion, DateTimeOffset.UtcNow, NewVersion);
        Assert.Equal(RpcdUpdateStages.Succeeded, status!.Stage);
        Assert.True(status.UpdateAgent);
        Assert.Equal(OldVersion, status.OldAgentVersion);
        Assert.Equal(NewVersion, status.AgentVersion);
        Assert.Equal(NewVersion, status.NewVersion);
    }

    [Fact]
    public async Task A_missing_agent_msi_fails_before_setup_when_the_service_is_installed()
    {
        var installer = new Installer();
        var session = await RunAsync(OldVersion, NewVersion, null, installer, OldVersion, agentInstalled: true, agentBefore: OldVersion);

        Assert.Equal(0, installer.Calls);
        var status = session.Current(null, OldVersion, DateTimeOffset.UtcNow, OldVersion);
        Assert.Equal(RpcdUpdateStages.Failed, status!.Stage);
        Assert.True(status.Terminal);
        Assert.Contains(RpcdGitHubRelease.AgentMsiMissing, status.Error);
        Assert.NotEqual(RpcdUpdateStages.Succeeded, status.Stage);
    }

    [Fact]
    public async Task An_agent_msi_checksum_mismatch_does_not_start_setup()
    {
        var installer = new Installer();
        var session = await RunAsync(
            OldVersion, NewVersion, null, installer, OldVersion,
            agentInstalled: true, agentBefore: OldVersion, includeAgentMsi: true, badAgentHash: true);

        Assert.Equal(0, installer.Calls);
        var status = session.Current(null, OldVersion, DateTimeOffset.UtcNow, OldVersion);
        Assert.Equal(RpcdUpdateStages.Failed, status!.Stage);
        Assert.Contains("Agent MSI", status.Error);
        Assert.Contains("SHA-256", status.Error);
    }

    [Fact]
    public async Task Success_requires_the_agent_service_version_when_one_is_installed()
    {
        var installer = new Installer { ExitCode = 0 };
        var session = await RunAsync(
            OldVersion, NewVersion, null, installer, readBack: NewVersion,
            agentInstalled: true, agentBefore: OldVersion, agentAfter: OldVersion, includeAgentMsi: true);

        Assert.Equal(1, installer.Calls);
        var status = session.Current(null, NewVersion, DateTimeOffset.UtcNow, OldVersion);
        Assert.Equal(RpcdUpdateStages.AgentNotUpdated, status!.Stage);
        Assert.True(status.Terminal);
        Assert.NotEqual(RpcdUpdateStages.Succeeded, status.Stage);
        Assert.Equal(NewVersion, status.NewVersion);
        Assert.Equal(OldVersion, status.OldAgentVersion);
        Assert.Equal(OldVersion, status.AgentVersion);
        Assert.Contains(NewVersion, status.Error);
        Assert.Contains(OldVersion, status.Error);
        Assert.Equal(0, status.InstallerExitCode);
    }

    [Fact]
    public async Task An_app_that_is_current_still_updates_when_the_agent_is_behind()
    {
        var installer = new Installer { ExitCode = 0 };
        var session = await RunAsync(
            NewVersion, NewVersion, null, installer, readBack: NewVersion,
            agentInstalled: true, agentBefore: OldVersion, agentAfter: NewVersion, includeAgentMsi: true);

        Assert.Equal(1, installer.Calls);
        Assert.Contains("/AGENTMSI=", installer.Arguments);
        Assert.Equal(RpcdUpdateStages.Succeeded, session.Current(null, NewVersion, DateTimeOffset.UtcNow, NewVersion)!.Stage);
    }

    [Fact]
    public async Task A_newer_app_is_not_downgraded_to_refresh_an_older_agent()
    {
        var installer = new Installer();
        var newer = "1.2.0-ci.997.1";
        var session = await RunAsync(
            newer, NewVersion, null, installer, readBack: newer,
            agentInstalled: true, agentBefore: OldVersion, includeAgentMsi: true);

        Assert.Equal(0, installer.Calls);
        var status = session.Current(null, newer, DateTimeOffset.UtcNow, OldVersion);
        Assert.Equal(RpcdUpdateStages.AlreadyUpToDate, status!.Stage);
        Assert.Contains("newer than the published", status.Error);
    }

    [Fact]
    public void Release_parse_selects_the_base_version_agent_msi_from_the_same_release()
    {
        var setup = "RemotePCDiagnostics-Setup-1.2.0-win-x64.exe";
        var msi = "RemotePCDiagnostics.Agent-1.2.0-win-x64.msi";
        var root = "https://github.com/budcribar/RemotePCDiagnostics/releases/download/prerelease/";
        var json = "{\"tag_name\":\"prerelease\",\"body\":\"Build version: `" + NewVersion + "`\\n\",\"assets\":["
            + Asset(setup, root + setup) + ","
            + Asset(setup + ".sha256", root + setup + ".sha256") + ","
            + Asset(msi, root + msi) + ","
            + Asset(msi + ".sha256", root + msi + ".sha256") + ","
            + Asset("RemotePCDiagnostics-TestShop-Setup-1.2.0-win-x64.exe", root + "RemotePCDiagnostics-TestShop-Setup-1.2.0-win-x64.exe")
            + "]}";

        var parsed = RpcdGitHubRelease.Parse(json, null);
        Assert.Null(parsed.Error);
        Assert.Equal(NewVersion, parsed.Choice!.Version);
        Assert.Equal(root + msi, parsed.Choice.AgentMsiUrl);
        Assert.Equal(root + msi + ".sha256", parsed.Choice.AgentMsiSha256Url);
        Assert.Null(parsed.Choice.AgentMsiError);
    }

    [Fact]
    public void Release_parse_reports_a_missing_agent_msi_checksum()
    {
        var setup = "RemotePCDiagnostics-Setup-1.2.0-win-x64.exe";
        var msi = "RemotePCDiagnostics.Agent-1.2.0-win-x64.msi";
        var root = "https://github.com/budcribar/RemotePCDiagnostics/releases/download/prerelease/";
        var json = "{\"tag_name\":\"prerelease\",\"body\":\"Build version: `" + NewVersion + "`\\n\",\"assets\":["
            + Asset(setup, root + setup) + ","
            + Asset(setup + ".sha256", root + setup + ".sha256") + ","
            + Asset(msi, root + msi)
            + "]}";

        var parsed = RpcdGitHubRelease.Parse(json, null);
        Assert.Null(parsed.Error);
        Assert.Null(parsed.Choice!.AgentMsiUrl);
        Assert.Equal(RpcdGitHubRelease.AgentMsiChecksumMissing, parsed.Choice.AgentMsiError);
    }

    [Fact]
    public void Release_parse_selects_arm64_assets_on_arm64_and_x64_assets_on_x64()
    {
        var x64Setup = "RemotePCDiagnostics-Setup-1.2.0-win-x64.exe";
        var arm64Setup = "RemotePCDiagnostics-Setup-1.2.0-win-arm64.exe";
        var x64Msi = "RemotePCDiagnostics.Agent-1.2.0-win-x64.msi";
        var arm64Msi = "RemotePCDiagnostics.Agent-1.2.0-win-arm64.msi";
        var root = "https://github.com/budcribar/RemotePCDiagnostics/releases/download/prerelease/";
        var json = "{\"tag_name\":\"prerelease\",\"body\":\"Build version: `" + NewVersion + "`\\n\",\"assets\":["
            + Asset(x64Setup, root + x64Setup) + ","
            + Asset(x64Setup + ".sha256", root + x64Setup + ".sha256") + ","
            + Asset(arm64Setup, root + arm64Setup) + ","
            + Asset(arm64Setup + ".sha256", root + arm64Setup + ".sha256") + ","
            + Asset(x64Msi, root + x64Msi) + ","
            + Asset(x64Msi + ".sha256", root + x64Msi + ".sha256") + ","
            + Asset(arm64Msi, root + arm64Msi) + ","
            + Asset(arm64Msi + ".sha256", root + arm64Msi + ".sha256")
            + "]}";

        var arm = RpcdGitHubRelease.Parse(json, null, System.Runtime.InteropServices.Architecture.Arm64);
        Assert.Null(arm.Error);
        Assert.Equal(root + arm64Setup, arm.Choice!.InstallerUrl);
        Assert.Equal(root + arm64Setup + ".sha256", arm.Choice.InstallerSha256Url);
        Assert.Equal(root + arm64Msi, arm.Choice.AgentMsiUrl);
        Assert.Equal(root + arm64Msi + ".sha256", arm.Choice.AgentMsiSha256Url);
        Assert.Equal("1.2.0", arm.Choice.FilenameVersion);

        var x64 = RpcdGitHubRelease.Parse(json, null, System.Runtime.InteropServices.Architecture.X64);
        Assert.Null(x64.Error);
        Assert.Equal(root + x64Setup, x64.Choice!.InstallerUrl);
        Assert.Equal(root + x64Msi, x64.Choice.AgentMsiUrl);
    }

    [Fact]
    public void Release_parse_falls_back_to_x64_on_arm64_when_arm64_assets_are_absent()
    {
        var x64Setup = "RemotePCDiagnostics-Setup-1.2.0-win-x64.exe";
        var x64Msi = "RemotePCDiagnostics.Agent-1.2.0-win-x64.msi";
        var root = "https://github.com/budcribar/RemotePCDiagnostics/releases/download/v1.2.0/";
        var json = "{\"tag_name\":\"v1.2.0\",\"assets\":["
            + Asset(x64Setup, root + x64Setup) + ","
            + Asset(x64Setup + ".sha256", root + x64Setup + ".sha256") + ","
            + Asset(x64Msi, root + x64Msi) + ","
            + Asset(x64Msi + ".sha256", root + x64Msi + ".sha256")
            + "]}";

        var arm = RpcdGitHubRelease.Parse(json, null, System.Runtime.InteropServices.Architecture.Arm64);
        Assert.Null(arm.Error);
        Assert.Equal(root + x64Setup, arm.Choice!.InstallerUrl);
        Assert.Equal(root + x64Msi, arm.Choice.AgentMsiUrl);
    }

    [Fact]
    public void Release_feed_channel_resolves_arm64_downloads_with_x64_fallback()
    {
        var withArm = new AppUpdateInstaller.ReleaseFeedChannel(
            "1.2.0", "https://example/rel",
            "https://example/x64.exe", "https://example/x64.exe.sha256",
            "https://example/x64.msi", "https://example/x64.msi.sha256",
            "https://example/arm64.exe", "https://example/arm64.exe.sha256",
            "https://example/arm64.msi", "https://example/arm64.msi.sha256");

        var armPick = withArm.ResolveDownloads(System.Runtime.InteropServices.Architecture.Arm64);
        Assert.Equal("https://example/arm64.exe", armPick.InstallerUrl);
        Assert.Equal("https://example/arm64.exe.sha256", armPick.InstallerSha256Url);
        Assert.Equal("https://example/arm64.msi", armPick.AgentMsiUrl);
        Assert.Equal("https://example/arm64.msi.sha256", armPick.AgentMsiSha256Url);

        var x64Pick = withArm.ResolveDownloads(System.Runtime.InteropServices.Architecture.X64);
        Assert.Equal("https://example/x64.exe", x64Pick.InstallerUrl);
        Assert.Equal("https://example/x64.msi", x64Pick.AgentMsiUrl);

        var x64Only = new AppUpdateInstaller.ReleaseFeedChannel(
            "1.2.0", "https://example/rel",
            "https://example/x64.exe", "https://example/x64.exe.sha256",
            "https://example/x64.msi", "https://example/x64.msi.sha256");
        var fallback = x64Only.ResolveDownloads(System.Runtime.InteropServices.Architecture.Arm64);
        Assert.Equal("https://example/x64.exe", fallback.InstallerUrl);
        Assert.Equal("https://example/x64.msi", fallback.AgentMsiUrl);
    }

    [Fact]
    public void Reconcile_does_not_succeed_when_the_agent_service_is_still_old()
    {
        var now = DateTimeOffset.UtcNow;
        var status = new RpcdUpdateStatus
        {
            RequestId = "req",
            Stage = RpcdUpdateStages.Installing,
            OldVersion = OldVersion,
            NewVersion = NewVersion,
            UpdateAgent = true,
            OldAgentVersion = OldVersion,
            UpdatedUtc = now.AddMinutes(-2),
        };

        var waiting = RpcdGitHubRelease.Reconcile(status, NewVersion, now, RpcdUpdateSession.InstallGiveUp, OldVersion);
        Assert.Equal(RpcdUpdateStages.Installing, waiting.Stage);
        Assert.False(waiting.Terminal);

        var late = RpcdGitHubRelease.Reconcile(status with { UpdatedUtc = now.AddMinutes(-30) }, NewVersion, now, RpcdUpdateSession.InstallGiveUp, OldVersion);
        Assert.Equal(RpcdUpdateStages.AgentNotUpdated, late.Stage);
        Assert.True(late.Terminal);
        Assert.Equal(NewVersion, late.NewVersion);
        Assert.Equal(OldVersion, late.AgentVersion);
        Assert.Contains(NewVersion, late.Error);
        Assert.Contains(OldVersion, late.Error);

        var done = RpcdUpdateSeal.Seal(status, NewVersion, serviceRunning: true, now, NewVersion);
        Assert.Equal(RpcdUpdateStages.Succeeded, done.Stage);
        Assert.Equal(NewVersion, done.AgentVersion);

        var afterSetup = RpcdUpdateSeal.ApplyZeroExitAgentCheck(status, 0, NewVersion, OldVersion, now);
        Assert.Equal(RpcdUpdateStages.AgentNotUpdated, afterSetup.Stage);
        Assert.True(afterSetup.Terminal);
        Assert.Equal(0, afterSetup.InstallerExitCode);
        Assert.Equal(NewVersion, afterSetup.NewVersion);
        Assert.Equal(OldVersion, afterSetup.AgentVersion);
        Assert.Same(status, RpcdUpdateSeal.ApplyZeroExitAgentCheck(status, null, NewVersion, OldVersion, now));
    }

    [Fact]
    public async Task Installer_failure_reports_the_exit_code_and_leaves_the_old_version()
    {
        var installer = new Installer { ExitCode = 5 };
        var session = await RunAsync(OldVersion, NewVersion, null, installer, readBack: OldVersion);
        var status = session.Current(null, OldVersion, DateTimeOffset.UtcNow);
        Assert.Equal(RpcdUpdateStages.Failed, status!.Stage);
        Assert.Contains("exited with code 5", status.Error);
        Assert.Contains(InnoSetupExitCodes.Describe(5), status.Error);
        Assert.Contains(OldVersion, status.Error);
        Assert.Equal(OldVersion, status.OldVersion);
        Assert.Equal(5, status.InstallerExitCode);
    }

    [Fact]
    public async Task Installer_failure_keeps_the_masked_log_tail_and_the_exit_code()
    {
        var lines = new string[RpcdSetupLog.TailLines + 25];
        for (var i = 0; i < lines.Length; i++)
            lines[i] = $"line {i}";
        lines[^1] = @"User profile C:\Users\budcribar\AppData\Local\Temp\is-1.tmp and shop@example.com --key=super-secret";
        var installer = new Installer { ExitCode = 1, Log = string.Join('\n', lines) };

        var session = await RunAsync(OldVersion, NewVersion, null, installer, readBack: OldVersion);
        var status = session.Current(null, OldVersion, DateTimeOffset.UtcNow);

        Assert.Equal(1, status!.InstallerExitCode);
        Assert.Contains("failed to initialize", status.Error, StringComparison.OrdinalIgnoreCase);
        Assert.NotNull(status.InstallerLog);
        Assert.Equal("line 25", status.InstallerLog.Split('\n')[0]);
        Assert.Contains(@"C:\Users\<user>\AppData", status.InstallerLog);
        Assert.DoesNotContain("budcribar", status.InstallerLog);
        Assert.Contains("<email>", status.InstallerLog);
        Assert.DoesNotContain("shop@example.com", status.InstallerLog);
        Assert.Contains("--key=<redacted>", status.InstallerLog);
        Assert.DoesNotContain("super-secret", status.InstallerLog);

        var roundTrip = RpcdUpdateStatus.Parse(status.ToJson());
        Assert.Equal(status.InstallerExitCode, roundTrip!.InstallerExitCode);
        Assert.Equal(status.InstallerLog, roundTrip.InstallerLog);
    }

    [Fact]
    public async Task A_zero_exit_that_does_not_change_the_version_keeps_the_log()
    {
        var installer = new Installer { ExitCode = 0, Log = "Setup finished without copying." };
        var session = await RunAsync(OldVersion, NewVersion, null, installer, readBack: OldVersion);
        var status = session.Current(null, OldVersion, DateTimeOffset.UtcNow);
        Assert.Equal(0, status!.InstallerExitCode);
        Assert.Equal("Setup finished without copying.", status.InstallerLog);
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

    [Theory]
    [InlineData(0, "finished")]
    [InlineData(1, "initialize")]
    [InlineData(2, "cancelled before")]
    [InlineData(3, "memory")]
    [InlineData(4, "copying")]
    [InlineData(5, "Abort")]
    [InlineData(6, "debugger")]
    [InlineData(7, "Preparing to Install")]
    [InlineData(8, "/NORESTART")]
    [InlineData(-1, "did not start")]
    public void Inno_exit_codes_map_to_a_sentence(int code, string phrase)
    {
        var text = InnoSetupExitCodes.Describe(code);
        Assert.Contains(phrase, text, StringComparison.OrdinalIgnoreCase);
        Assert.NotEqual(InnoSetupExitCodes.Describe(99), text);
    }

    [Fact]
    public void Setup_log_switch_quotes_the_path_and_refuses_a_quote_inside_it()
    {
        Assert.Equal(@"/LOG=""C:\ProgramData\RemotePCDiagnostics\Updates\rpcd-setup.log""",
            RpcdSetupLog.LogSwitch(@"C:\ProgramData\RemotePCDiagnostics\Updates\rpcd-setup.log"));
        Assert.Null(RpcdSetupLog.LogSwitch(@"C:\ProgramData\Remote""PC\rpcd-setup.log"));
        Assert.Null(RpcdSetupLog.LogSwitch(null));
    }

    [Fact]
    public void Only_the_agent_service_closes_the_host_before_setup()
    {
        Assert.True(RpcdSetupLog.CanCloseHostBeforeSetup(0));
        Assert.False(RpcdSetupLog.CanCloseHostBeforeSetup(1));
        Assert.False(RpcdSetupLog.CanCloseHostBeforeSetup(-1));
    }

    [Fact]
    public void Log_tail_masks_a_long_path_prefix_and_keeps_the_end()
    {
        var text = new string('x', RpcdSetupLog.MaxChars + 50) + "\n" + @"\\?\C:\Users\Ada Lovelace\Desktop\notes.txt";
        var tail = RpcdSetupLog.Tail(text);
        Assert.NotNull(tail);
        Assert.True(tail.Length <= RpcdSetupLog.MaxChars);
        Assert.Contains(@"C:\Users\<user>\Desktop\notes.txt", tail);
        Assert.DoesNotContain("Ada Lovelace", tail);
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
        Assert.Contains("service workflow is running (Applying)", workflow);

        var fix = AgentExports.UpdateBlockReason(new AgentExports.ActivitySnapshot([],
            Fix: new FixRun(new AreaAction(RemediationKind.ScheduleCleanRestart, "Restart"), "Restart", "Storage", DateTimeOffset.UtcNow)));
        Assert.Contains("fix is running", fix);
    }

    public static IEnumerable<object[]> EveryWorkflowStage() =>
        Enum.GetValues<WorkflowStage>().Select(stage => new object[] { stage });

    [Theory]
    [MemberData(nameof(EveryWorkflowStage))]
    public void Update_guard_and_activity_list_agree_on_each_stage(WorkflowStage stage)
    {
        var active = WorkflowState.IsActiveStage(stage);
        var snapshot = new AgentExports.ActivitySnapshot([],
            Workflow: new AgentExports.WorkflowActivity(stage, Busy: false, Status: null));

        var reason = AgentExports.UpdateBlockReason(snapshot);
        using var doc = JsonDocument.Parse(AgentExports.Activity(snapshot));
        var listed = doc.RootElement.TryGetProperty("workflow", out var workflow);

        if (active)
        {
            Assert.NotNull(reason);
            Assert.Contains($"service workflow is running ({stage})", reason);
            Assert.True(listed);
            Assert.Equal(stage.ToString(), workflow.GetProperty("stage").GetString());
        }
        else
        {
            Assert.Null(reason);
            Assert.False(listed);
        }
    }

    [Fact]
    public void A_parked_review_allows_the_update_even_when_marked_busy()
    {
        var reason = AgentExports.UpdateBlockReason(new AgentExports.ActivitySnapshot([],
            Workflow: new AgentExports.WorkflowActivity(WorkflowStage.Review, Busy: true, Status: "Waiting")));
        Assert.Null(reason);
    }

    [Fact]
    public void A_missing_activity_report_names_the_probe_in_the_refusal_detail()
    {
        var now = DateTimeOffset.Parse("2026-11-20T17:06:00Z");
        var session = new RpcdUpdateSession();
        var started = session.TryBegin(new RpcdUpdateRequest("prerelease", null, true), hostRunning: true, trustCallerBusyReason: false, now, out var status);

        Assert.False(started);
        Assert.Equal(RpcdUpdateSession.ActivityUnconfirmed, status.Error);
        Assert.Contains(RpcdUpdateSession.ProbeNoReport, status.Detail);
    }

    [Fact]
    public void A_stale_activity_report_names_its_age()
    {
        var now = DateTimeOffset.Parse("2026-11-20T17:06:00Z");
        var session = new RpcdUpdateSession();
        session.ReportActivity(null, now.AddMinutes(-5));

        Assert.Contains("300 seconds old", session.ActivityDiagnosis(now));
        Assert.False(session.TryBegin(new RpcdUpdateRequest("prerelease", null, true), true, false, now, out var status));
        Assert.Contains("300 seconds old", status.Detail);
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
        string? directory = null,
        bool agentInstalled = false,
        string? agentBefore = null,
        string? agentAfter = null,
        bool includeAgentMsi = false,
        bool badAgentHash = false)
    {
        var payload = Encoding.UTF8.GetBytes("official-installer");
        var hash = badHash ? new string('a', 64) : Convert.ToHexStringLower(SHA256.HashData(payload));
        var msiPayload = Encoding.UTF8.GetBytes("official-agent-msi");
        var msiHash = badAgentHash ? new string('b', 64) : Convert.ToHexStringLower(SHA256.HashData(msiPayload));
        var msiName = "RemotePCDiagnostics.Agent-" + releaseVersion + "-win-x64.msi";
        var body = ReleaseJson(releaseVersion, includeSha, testShopOnly, exeUrl, hash, includeAgentMsi, msiName);
        using var http = new HttpClient(new Stub(req =>
        {
            var url = req.RequestUri!.AbsoluteUri;
            if (url.Contains("/releases/", StringComparison.Ordinal)
                && !url.EndsWith(".exe", StringComparison.Ordinal)
                && !url.EndsWith(".sha256", StringComparison.Ordinal)
                && !url.EndsWith(".msi", StringComparison.Ordinal))
            {
                if (url.Contains("/releases/tags/prerelease", StringComparison.Ordinal) || url.EndsWith("/releases/latest", StringComparison.Ordinal))
                    return Json(body);
                return new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new StringContent("{\"message\":\"Not Found\"}") };
            }
            if (url.EndsWith(".msi.sha256", StringComparison.Ordinal))
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(msiHash + "  " + msiName + "\n") };
            if (url.EndsWith(".sha256", StringComparison.Ordinal))
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(hash + "  " + ExeName + "\n") };
            if (url.EndsWith(".msi", StringComparison.Ordinal))
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(msiPayload) };
            if (url == (exeUrl ?? ExeUrl))
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(payload) };
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));

        var session = new RpcdUpdateSession();
        var now = DateTimeOffset.UtcNow;
        var staging = directory ?? TempDir();
        var agentUpdated = false;
        Assert.True(session.TryBegin(new RpcdUpdateRequest("prerelease", explicitVersion, true), false, true, now, out _));
        await session.ExecuteAsync(new RpcdUpdateRequest("prerelease", explicitVersion, true), new RpcdUpdateRun
        {
            Http = http,
            InstalledVersion = installed,
            ReadInstalledVersion = () => readBack,
            StagingDirectory = staging,
            RelaunchArguments = ["-u=https://server.example.com:34544", "-i=748279c7-4309-452c-8b30-e02ec52e498f", "--restarted"],
            IsPersistentAgentInstalled = () => agentInstalled,
            ReadInstalledAgentVersion = () => agentUpdated ? agentAfter : agentBefore,
            RunInstaller = (install, _) =>
            {
                installer.Calls++;
                installer.Arguments = install.Arguments;
                agentUpdated = true;
                if (installer.Log is not null)
                    File.WriteAllText(Path.Combine(staging, RpcdSetupLog.FileName), installer.Log);
                return Task.FromResult(installer.ExitCode);
            },
            UtcNow = now,
        }, CancellationToken.None);
        return session;
    }

    private static string ReleaseJson(string version, bool includeSha, bool testShopOnly, string? exeUrl, string hash, bool includeAgentMsi = false, string? msiName = null)
    {
        var name = testShopOnly ? "RemotePCDiagnostics-TestShop-Setup-1.2.0-win-x64.exe" : ExeName;
        var url = exeUrl ?? "https://github.com/budcribar/RemotePCDiagnostics/releases/download/prerelease/" + name;
        var assets = new StringBuilder();
        assets.Append(Asset(name, url));
        if (includeSha && !testShopOnly)
            assets.Append(',').Append(Asset(name + ".sha256", url + ".sha256"));
        if (includeAgentMsi && !testShopOnly && msiName is not null)
        {
            var msiUrl = "https://github.com/budcribar/RemotePCDiagnostics/releases/download/prerelease/" + msiName;
            assets.Append(',').Append(Asset(msiName, msiUrl));
            assets.Append(',').Append(Asset(msiName + ".sha256", msiUrl + ".sha256"));
        }
        _ = hash;
        return "{\"tag_name\":\"prerelease\",\"prerelease\":true,\"html_url\":\"https://github.com/budcribar/RemotePCDiagnostics/releases/tag/prerelease\",\"body\":\"Build version: `"
            + version + "`\\n\",\"assets\":[" + assets + "]}";
    }

    private static string Asset(string name, string url) =>
        "{\"name\":\"" + name + "\",\"browser_download_url\":\"" + url + "\"}";

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
        public string? Log { get; set; }
    }

    private sealed class Stub(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(respond(request));
    }
}
