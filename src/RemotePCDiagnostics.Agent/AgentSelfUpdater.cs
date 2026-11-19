using System.Diagnostics;
using Microsoft.Extensions.Logging;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Logging;

namespace RemotePCDiagnostics.Agent;

/// <summary>
/// Performs zero-UAC elevated RPCD (and optional persistent Agent service) self-updates on behalf of
/// <c>RemotePCDiagnostics.Host</c>. Only downloads from the trusted release feed and verifies SHA-256 checksums
/// in an admin-writable <c>%ProgramData%</c> staging folder before launching Inno Setup silently.
/// </summary>
internal static class AgentSelfUpdater
{
    public static async Task<AppUpdateResult> RunAsync(
        AppUpdateChannel channel,
        IReadOnlyList<string>? relaunchArguments,
        ILogger log,
        CancellationToken ct)
    {
        var installed = AgentPaths.GetInstalledOrCachedAppVersion();
        var feedUrl = AppUpdateInstaller.ResolveFeedUrl();
        log.Info($"[agent-update] Checking {feedUrl} for channel={channel} (installed={installed}).");

        using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(3) };
        var feed = await AppUpdateInstaller.FetchFeedAsync(http, feedUrl, ct).ConfigureAwait(false);
        var selected = channel == AppUpdateChannel.Prerelease ? feed?.Prerelease : feed?.Stable;
        if (selected is null || string.IsNullOrWhiteSpace(selected.InstallerUrl))
            return new AppUpdateResult(false, Error: "No RPCD installer was found in the release feed.");

        if (!string.IsNullOrWhiteSpace(installed) && AppVersionComparer.IsNewer(selected.Version, installed) == false)
            return new AppUpdateResult(false, Error: $"RPCD {installed} is already up to date.");

        var stagingDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "RemotePCDiagnostics",
            "Updates");

        string installerPath;
        try
        {
            installerPath = await AppUpdateInstaller.DownloadAndVerifyAsync(
                http,
                selected.InstallerUrl,
                selected.InstallerSha256Url,
                stagingDir,
                progress: null,
                ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.Warn($"[agent-update] Download/verification failed: {ex.Message}");
            return new AppUpdateResult(false, Error: ex.Message);
        }

        string? msiPath = null;
        if (!string.IsNullOrWhiteSpace(selected.AgentMsiUrl)
            && File.Exists(AgentPaths.DefaultInstalledAgentExe()))
        {
            try
            {
                msiPath = await AppUpdateInstaller.DownloadAndVerifyAsync(
                    http,
                    selected.AgentMsiUrl,
                    selected.AgentMsiSha256Url,
                    stagingDir,
                    progress: null,
                    ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Desktop update can still proceed even if the optional Agent MSI download fails.
                log.Warn($"[agent-update] Agent MSI download/verification skipped: {ex.Message}");
            }
        }

        // Setup closes the app, and this helper (a child of the app) ends with it, so nothing may be left for this process
        // to do after Setup starts. Setup itself runs the Agent MSI and starts the app again (installer/RemotePCDiagnostics.iss).
        IReadOnlyList<string>? relaunch = null;
        if (relaunchArguments is { Count: > 0 })
        {
            if (SessionLaunchOptions.IsRestartCommandLine(relaunchArguments))
                relaunch = relaunchArguments;
            else
                log.Warn("[agent-update] Ignoring a relaunch command line that is not a session restart; the app will not be started again.");
        }

        try
        {
            var arguments = AppUpdateInstaller.BuildSetupArguments(verySilent: true, msiPath, relaunch);
            log.Info($"[agent-update] Launching silent installer '{installerPath}' (agent MSI: {msiPath ?? "none"}; relaunch: {(relaunch is null ? "no" : "yes")}).");
            var psi = new ProcessStartInfo
            {
                FileName = installerPath,
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = stagingDir,
            };
            var proc = Process.Start(psi);
            if (proc is null)
                return new AppUpdateResult(false, Error: "Failed to start the RPCD installer.");

            return new AppUpdateResult(
                Ok: true,
                Restarting: true,
                Message: $"Installing RPCD {selected.Version ?? "update"} silently. The session will reconnect shortly.");
        }
        catch (Exception ex)
        {
            log.Warn($"[agent-update] Failed to launch installer: {ex.Message}");
            return new AppUpdateResult(false, Error: ex.Message);
        }
    }
}
