using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Logging;

namespace RemotePCDiagnostics.Agent;

/// <summary>
/// Performs zero-UAC elevated RPCD (and optional persistent Agent service) self-updates on behalf of
/// <c>RemotePCDiagnostics.Host</c>. Only downloads from the trusted release feed and verifies SHA-256 checksums
/// in an admin-only <c>%ProgramData%</c> staging folder before launching Inno Setup silently.
/// </summary>
internal static class AgentSelfUpdater
{
    public static async Task<AppUpdateResult> RunAsync(
        AppUpdateChannel channel,
        ILogger log,
        CancellationToken ct)
    {
        var installed = AgentPaths.GetInstalledOrCachedAppVersion();
#if DEBUG
        var feedUrl = AppUpdateInstaller.ResolveFeedUrl(allowEnvOverride: true);
#else
        var feedUrl = AppUpdateInstaller.DefaultFeedUrl;
#endif
        log.Info($"[agent-update] Checking {feedUrl} for channel={channel} (installed={installed}).");

        using var http = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false })
        {
            Timeout = TimeSpan.FromMinutes(3),
        };
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

        try
        {
            PrepareSecuredStagingDirectory(stagingDir);
        }
        catch (Exception ex)
        {
            log.Warn($"[agent-update] Could not secure staging directory: {ex.Message}");
            return new AppUpdateResult(false, Error: "Could not prepare a secure update staging directory.");
        }

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

        try
        {
            log.Info($"[agent-update] Launching silent installer '{installerPath}'.");
            var psi = new ProcessStartInfo
            {
                FileName = installerPath,
                Arguments = "/VERYSILENT /SUPPRESSMSGBOXES /CLOSEAPPLICATIONS /RESTARTAPPLICATIONS /NORESTART",
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = stagingDir,
            };
            var proc = Process.Start(psi);
            if (proc is null)
                return new AppUpdateResult(false, Error: "Failed to start the RPCD installer.");

            if (!string.IsNullOrWhiteSpace(msiPath))
            {
                var msiexecPath = Path.Combine(Environment.SystemDirectory, "msiexec.exe");
                if (!File.Exists(msiexecPath))
                    msiexecPath = "msiexec.exe";
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await proc.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
                        if (proc.ExitCode == 0)
                        {
                            log.Info($"[agent-update] Launching silent Agent MSI upgrade '{msiPath}'.");
                            Process.Start(new ProcessStartInfo
                            {
                                FileName = msiexecPath,
                                Arguments = $"/i \"{msiPath}\" /qn /norestart",
                                UseShellExecute = false,
                                CreateNoWindow = true,
                                WorkingDirectory = stagingDir,
                            });
                        }
                    }
                    catch (Exception ex)
                    {
                        log.Warn($"[agent-update] Agent MSI follow-up failed: {ex.Message}");
                    }
                });
            }

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

    private static void PrepareSecuredStagingDirectory(string stagingDir)
    {
        var dirInfo = Directory.CreateDirectory(stagingDir);
        if ((dirInfo.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Staging directory must not be a symlink or junction.");

        if (!OperatingSystem.IsWindows())
            return;

        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        const InheritanceFlags all = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

        var security = new DirectorySecurity();
        security.SetOwner(admins);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl, all, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, all, PropagationFlags.None, AccessControlType.Allow));
        dirInfo.SetAccessControl(security);
    }
}
