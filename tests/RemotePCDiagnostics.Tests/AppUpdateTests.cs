using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Session;
using Xunit;

namespace RemotePCDiagnostics.Tests;

public class AppUpdateTests
{
    [Theory]
    [InlineData("1.2.0-ci.786.1", AppUpdateChannel.Prerelease)]
    [InlineData("1.2.0-ci.786.1+48ceabf", AppUpdateChannel.Prerelease)]
    [InlineData("1.2.0", AppUpdateChannel.Stable)]
    [InlineData("1.2.0-local", AppUpdateChannel.Stable)]
    [InlineData(null, AppUpdateChannel.Stable)]
    public void Ci_builds_default_to_prerelease_channel_and_releases_default_to_stable(string? installed, AppUpdateChannel expected) =>
        Assert.Equal(expected, AppVersionComparer.DefaultChannelFor(installed));

    [Theory]
    [InlineData("1.3.0", "1.2.0", true)]
    [InlineData("1.2.0-ci.800.1", "1.2.0-ci.724.1", true)]
    [InlineData("1.2.0-ci.724.1", "1.2.0-ci.724.1", false)]
    [InlineData("1.2.0-ci.700.1", "1.2.0-ci.724.1", false)]
    [InlineData("1.2.0-ci.800.1", "1.2.0", null)]
    [InlineData(null, "1.2.0", null)]
    public void Version_comparison_handles_semver_and_ci_builds(string? candidate, string? installed, bool? expected) =>
        Assert.Equal(expected, AppVersionComparer.IsNewer(candidate, installed));

    [Theory]
    [InlineData("https://github.com/budcribar/RemotePCDiagnostics/releases/download/v1.3.0/RemotePCDiagnostics-Setup-1.3.0-win-x64.exe", true)]
    [InlineData("https://github.com/attacker/evil/releases/download/v1.3.0/setup.exe", false)]
    [InlineData("https://objects.githubusercontent.com/github-production-release-asset/123", false)]
    [InlineData("http://github.com/budcribar/RemotePCDiagnostics/releases/download/v1.3.0/setup.exe", false)]
    [InlineData("https://evil.example.com/setup.exe", false)]
    [InlineData("not-a-url", false)]
    public void Trusted_download_url_allows_only_official_rpcd_github_releases(string url, bool expected) =>
        Assert.Equal(expected, AppVersionComparer.IsTrustedDownloadUrl(url));

    [Theory]
    [InlineData("https://objects.githubusercontent.com/github-production-release-asset/123?sig=abc", true)]
    [InlineData("https://release-assets.githubusercontent.com/asset/123", true)]
    [InlineData("https://github.com/budcribar/RemotePCDiagnostics/releases/download/v1.3.0/setup.exe", true)]
    [InlineData("https://github.com/attacker/repo/releases/download/v1.0/malware.exe", false)]
    [InlineData("https://evil.example.com/setup.exe", false)]
    public void Allowed_redirect_url_permits_only_github_release_asset_hosts(string url, bool expected) =>
        Assert.Equal(expected, AppVersionComparer.IsAllowedRedirectUrl(new Uri(url)));

    [Fact]
    public void AdminCommandAllowlist_blocks_sc_schtasks_arbitrary_reg_and_unsafe_powershell()
    {
        Assert.False(AdminCommandAllowlist.TryResolveSystemTool("sc.exe", out _));
        Assert.False(AdminCommandAllowlist.TryResolveSystemTool("schtasks.exe", out _));

        // Never reg.exe or powershell.exe: registry changes are typed ops, admin PowerShell is one of the Agent's own scripts.
        Assert.False(AdminCommandAllowlist.TryResolveSystemTool("reg.exe", out _));
        Assert.False(AdminCommandAllowlist.TryResolveSystemTool(SystemCommandRunner.PowerShell, out _));

        // wevtutil.exe only reads events
        Assert.True(AdminCommandAllowlist.TryValidateArguments("wevtutil.exe", WindowsEventLog.Arguments("System", "*", 5), out _));
        Assert.False(AdminCommandAllowlist.TryValidateArguments("wevtutil.exe", ["cl", "Security"], out _));
        Assert.False(AdminCommandAllowlist.TryValidateArguments("wevtutil.exe", ["qe", "Security", "/sq:true"], out _));

        // shutdown.exe allows /r, /g, /a only
        Assert.True(AdminCommandAllowlist.TryValidateArguments("shutdown.exe", ["/r", "/t", "60"], out _));
        Assert.False(AdminCommandAllowlist.TryValidateArguments("shutdown.exe", ["/s", "/t", "0"], out _));

    }

    [Fact]
    public void LaunchRules_validate_pins_server_url_to_configured_server()
    {
        var sessionId = Guid.NewGuid().ToString("D");
        Assert.Null(RemotePCDiagnostics.Agent.Core.LaunchRules.Validate(
            sessionId, "https://server.remoteblazorwebview.com:34544", out _, out _, "https://server.remoteblazorwebview.com:34544"));
        Assert.NotNull(RemotePCDiagnostics.Agent.Core.LaunchRules.Validate(
            sessionId, "https://evil.example.com:34544", out _, out _, "https://server.remoteblazorwebview.com:34544"));
        Assert.NotNull(RemotePCDiagnostics.Agent.Core.LaunchRules.Validate(
            sessionId, "https://server.remoteblazorwebview.com:9999", out _, out _, "https://server.remoteblazorwebview.com:34544"));
    }

    [Fact]
    public async Task Download_and_verify_checks_sha256_and_rejects_mismatch()
    {
        var payload = Encoding.UTF8.GetBytes("fake-installer-binary");
        var validHash = Convert.ToHexStringLower(SHA256.HashData(payload));
        var badHash = new string('0', 64);

        const string exeUrl = "https://github.com/budcribar/RemotePCDiagnostics/releases/download/v1.3.0/RemotePCDiagnostics-Setup-1.3.0-win-x64.exe";
        const string shaUrl = exeUrl + ".sha256";

        var currentHash = validHash;
        using var http = new HttpClient(new StubHandler(req =>
        {
            if (req.RequestUri!.AbsoluteUri == exeUrl)
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(payload) };
            if (req.RequestUri.AbsoluteUri == shaUrl)
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent($"{currentHash}  RemotePCDiagnostics-Setup-1.3.0-win-x64.exe\n") };
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));

        var dir = Path.Combine(Path.GetTempPath(), $"rpcd-update-test-{Guid.NewGuid():N}");
        try
        {
            var path = await AppUpdateInstaller.DownloadAndVerifyAsync(http, exeUrl, shaUrl, dir, null, default);
            Assert.True(File.Exists(path));
            Assert.Equal(payload, await File.ReadAllBytesAsync(path));

            currentHash = badHash;
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                AppUpdateInstaller.DownloadAndVerifyAsync(http, exeUrl, shaUrl, dir, null, default));
            Assert.False(File.Exists(path + ".part"));
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task Download_and_verify_refuses_an_installer_without_a_checksum()
    {
        const string exeUrl = "https://github.com/budcribar/RemotePCDiagnostics/releases/download/v1.3.0/RemotePCDiagnostics-Setup-1.3.0-win-x64.exe";
        var requests = 0;
        using var http = new HttpClient(new StubHandler(_ =>
        {
            requests++;
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent([1, 2, 3]) };
        }));

        var dir = Path.Combine(Path.GetTempPath(), $"rpcd-update-test-{Guid.NewGuid():N}");
        try
        {
            foreach (var sha in new[] { null, "", "  " })
            {
                var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                    AppUpdateInstaller.DownloadAndVerifyAsync(http, exeUrl, sha, dir, null, default));
                Assert.Equal(AppUpdateInstaller.MissingChecksumMessage, ex.Message);
            }
            Assert.Equal(0, requests);
            Assert.False(Directory.Exists(dir) && Directory.EnumerateFiles(dir).Any());
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task Optional_agent_msi_without_a_checksum_is_skipped_not_installed()
    {
        const string msiUrl = "https://github.com/budcribar/RemotePCDiagnostics/releases/download/v1.3.0/RemotePCDiagnostics.Agent-1.3.0-win-x64.msi";
        var requests = 0;
        using var http = new HttpClient(new StubHandler(_ =>
        {
            requests++;
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent([1, 2, 3]) };
        }));

        var dir = Path.Combine(Path.GetTempPath(), $"rpcd-update-test-{Guid.NewGuid():N}");
        try
        {
            string? skipped = null;
            var path = await AppUpdateInstaller.DownloadAgentMsiAsync(
                http, msiUrl, sha256Url: null, dir, required: false, progress: null, onSkipped: m => skipped = m, default);
            Assert.Null(path);
            Assert.NotNull(skipped);
            Assert.Equal(0, requests);

            await Assert.ThrowsAsync<InvalidOperationException>(() => AppUpdateInstaller.DownloadAgentMsiAsync(
                http, msiUrl, sha256Url: null, dir, required: true, progress: null, onSkipped: null, default));
            Assert.Equal(0, requests);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task Store_backend_handles_check_and_install_for_packaged_apps()
    {
        var store = new FakeStoreBackend(isPackaged: true, updateAvailable: true, canSilent: true);
        using var service = new AppUpdateService("1.2.0", storeBackend: store);

        var info = await service.CheckForUpdateAsync(force: true);
        Assert.True(info.UpdateAvailable);
        Assert.Equal(AppInstallKind.MicrosoftStore, info.InstallKind);
        Assert.True(info.CanInstallSilently);
        Assert.NotNull(service.LastCheck);
        Assert.True(service.LastCheck.UpdateAvailable);
        Assert.Equal("Microsoft Store update", service.LastCheck.LatestVersion);
        Assert.Null(service.LastCheck.Error);

        var result = await service.InstallUpdateAsync();
        Assert.True(result.Ok);
        Assert.True(result.Restarting);
        Assert.Equal(1, store.InstallCalls);
    }

    [Fact]
    public async Task Standalone_install_delegates_to_elevated_agent_bridge_when_connected()
    {
        const string feedUrl = "https://admin.remoteblazorwebview.com/api/rpcd/latest";
        using var http = new HttpClient(new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(new
            {
                stable = new
                {
                    version = "1.3.0-ci.800.1",
                    releaseUrl = "https://github.com/budcribar/RemotePCDiagnostics/releases/tag/v1.3.0",
                    installerUrl = "https://github.com/budcribar/RemotePCDiagnostics/releases/download/v1.3.0/RemotePCDiagnostics-Setup-1.3.0-win-x64.exe",
                    installerSha256Url = "https://github.com/budcribar/RemotePCDiagnostics/releases/download/v1.3.0/RemotePCDiagnostics-Setup-1.3.0-win-x64.exe.sha256",
                },
            }), Encoding.UTF8, "application/json"),
        }));

        var bridge = new FakeBridge();
        var exitRequested = false;
        using var service = new AppUpdateService(
            installedVersion: "1.2.0-ci.700.1",
            feedUrl: feedUrl,
            getElevatedBridge: () => bridge,
            onExitForUpdate: () => exitRequested = true,
            httpClient: http,
            getRelaunchArguments: () => ["-u=https://server.example.com:34544", "-i=748279c7-4309-452c-8b30-e02ec52e498f", "--restarted"]);

        var info = await service.CheckForUpdateAsync(force: true);
        Assert.True(info.UpdateAvailable);
        Assert.Equal(AppInstallKind.Standalone, info.InstallKind);
        Assert.True(info.CanInstallSilently);
        Assert.Equal("1.3.0-ci.800.1", info.LatestVersion);

        var result = await service.InstallUpdateAsync();
        Assert.True(result.Ok);
        Assert.True(result.Restarting);
        Assert.True(exitRequested);
        Assert.Equal(AppUpdateChannel.Stable, bridge.LastChannel);
        // The helper gets the app's restart command line, so Setup can bring the remote session back after the update.
        Assert.Equal(["-u=https://server.example.com:34544", "-i=748279c7-4309-452c-8b30-e02ec52e498f", "--restarted"], bridge.LastRelaunchArguments);
    }

    [Fact]
    public void Setup_arguments_carry_the_agent_msi_and_the_relaunch_command_line()
    {
        var args = AppUpdateInstaller.BuildSetupArguments(
            verySilent: true,
            @"C:\ProgramData\RemotePCDiagnostics\Updates\RemotePCDiagnostics.Agent-1.2.0-win-x64.msi",
            ["-u=https://server.example.com:34544", "-i=748279c7-4309-452c-8b30-e02ec52e498f", "-g=test-shop", "--voice", "--restarted"]);

        Assert.Equal(
            "/VERYSILENT /SUPPRESSMSGBOXES /CLOSEAPPLICATIONS /NORESTART "
            + "\"/AGENTMSI=C:\\ProgramData\\RemotePCDiagnostics\\Updates\\RemotePCDiagnostics.Agent-1.2.0-win-x64.msi\" "
            + "\"/RELAUNCHARGS=-u=https://server.example.com:34544 -i=748279c7-4309-452c-8b30-e02ec52e498f -g=test-shop --voice --restarted\"",
            args);
    }

    [Fact]
    public void Setup_arguments_leave_out_what_was_not_given()
    {
        Assert.Equal("/SILENT /SUPPRESSMSGBOXES /CLOSEAPPLICATIONS /NORESTART", AppUpdateInstaller.BuildSetupArguments(false, null, null));
        Assert.Equal("/SILENT /SUPPRESSMSGBOXES /CLOSEAPPLICATIONS /NORESTART", AppUpdateInstaller.BuildSetupArguments(false, "C:\\a\"b.msi", ["-i=\"x\""]));
    }

    [Fact]
    public void Restart_arguments_pass_the_relaunch_check()
    {
        var args = SessionLaunchOptions.RestartArguments(new Uri("https://server.example.com:34544/"), Guid.NewGuid(), unattended: true, voice: true, group: "test-shop", admin: false);
        Assert.True(SessionLaunchOptions.IsRestartCommandLine(args));
        Assert.True(SessionLaunchOptions.IsRestartCommandLine([SessionLaunchOptions.RestartedArg]));
    }

    [Theory]
    [InlineData("--undo-all")]
    [InlineData("-u=file:///C:/evil")]
    [InlineData("-i=not-a-guid")]
    [InlineData("-i=00000000-0000-0000-0000-000000000000")]
    [InlineData("-g=two words")]
    [InlineData("-g=")]
    [InlineData("--restarted\" /evil")]
    public void Relaunch_check_rejects_anything_else(string arg) =>
        Assert.False(SessionLaunchOptions.IsRestartCommandLine(["-u=https://server.example.com:34544", arg]));

    [Fact]
    public async Task Failed_update_check_records_a_fixed_error_and_not_the_exception()
    {
        using var http = new HttpClient(new StubHandler(_ =>
            throw new HttpRequestException("https://secret.example/feed?key=rpd_live_SECRET")));
        using var service = new AppUpdateService("1.2.0", httpClient: http);

        var info = await service.CheckForUpdateAsync(force: true);

        Assert.False(info.UpdateAvailable);
        Assert.NotNull(service.LastCheck);
        Assert.False(service.LastCheck.UpdateAvailable);
        Assert.Null(service.LastCheck.LatestVersion);
        Assert.Equal("Update check failed.", service.LastCheck.Error);
        Assert.DoesNotContain("secret", service.LastCheck.Error, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("rpd_live", service.LastCheck.Error, StringComparison.OrdinalIgnoreCase);
    }

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(respond(request));
    }

    private sealed class FakeStoreBackend(bool isPackaged, bool updateAvailable, bool canSilent) : IStoreUpdateBackend
    {
        public int InstallCalls { get; private set; }
        public bool IsPackagedStoreApp => isPackaged;

        public Task<StoreUpdateCheckResult> CheckForUpdateAsync(CancellationToken ct = default) =>
            Task.FromResult(new StoreUpdateCheckResult(updateAvailable, canSilent, "Microsoft Store update"));

        public Task<AppUpdateResult> DownloadAndInstallAsync(Action<AppUpdateProgress>? progress = null, CancellationToken ct = default)
        {
            InstallCalls++;
            progress?.Invoke(new AppUpdateProgress("downloading", 100, "Done"));
            return Task.FromResult(new AppUpdateResult(true, Restarting: true, Message: "Microsoft Store update installed."));
        }
    }

    private sealed class FakeBridge : IElevatedCommandBridge
    {
        public bool IsConnected => true;
        public AppUpdateChannel? LastChannel { get; private set; }

        public Task<ProcessResult?> RunElevatedAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct, Action<string>? outputLine = null) =>
            Task.FromResult<ProcessResult?>(null);

        public Task<SensorSnapshot?> ReadSensorsAsync(CancellationToken ct = default) =>
            Task.FromResult<SensorSnapshot?>(null);

        public Task<IReadOnlyList<DriveHealth>?> ReadDrivesAsync(CancellationToken ct = default) =>
            Task.FromResult<IReadOnlyList<DriveHealth>?>(null);

        public IReadOnlyList<string>? LastRelaunchArguments { get; private set; }

        public Task<AppUpdateResult?> SelfUpdateAsync(AppUpdateChannel channel, IReadOnlyList<string>? relaunchArguments = null, CancellationToken ct = default)
        {
            LastChannel = channel;
            LastRelaunchArguments = relaunchArguments;
            return Task.FromResult<AppUpdateResult?>(new AppUpdateResult(true, Restarting: true, Message: "Agent updating."));
        }
    }
}
