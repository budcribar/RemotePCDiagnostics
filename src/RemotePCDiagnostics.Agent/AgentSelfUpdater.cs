using System.Diagnostics;
using Microsoft.Extensions.Logging;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Agent.Core;
using RemotePCDiagnostics.Logging;

namespace RemotePCDiagnostics.Agent;

/// <summary>
/// Performs zero-UAC elevated RPCD (and optional persistent Agent service) self-updates on behalf of
/// <c>RemotePCDiagnostics.Host</c>. Only downloads from the trusted release feed and verifies SHA-256 checksums
/// in an admin-only <c>%ProgramData%</c> staging folder before launching Inno Setup silently.
/// </summary>
internal static class AgentSelfUpdater
{
    /// <summary>Admin-only folder for downloaded installers (and <see cref="PendingAppRelaunch"/>'s request).</summary>
    public static string StagingDirectory() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "RemotePCDiagnostics",
        "Updates");

    public static async Task<AppUpdateResult> RunAsync(
        AppUpdateChannel channel,
        IReadOnlyList<string>? relaunchArguments,
        ILogger log,
        CancellationToken ct,
        Action<Process, string>? relaunchFromService = null)
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

        var stagingDir = StagingDirectory();

        try
        {
            PrepareStaging(stagingDir);
        }
        catch (Exception ex)
        {
            log.Warn($"[agent-update] Could not secure staging directory: {ex.Message}");
            return new AppUpdateResult(false, Error: "Could not prepare a secure update staging directory.");
        }

        var packageDir = Path.Combine(stagingDir, Guid.NewGuid().ToString("N"));
        string installerPath;
        try
        {
            installerPath = await AppUpdateInstaller.DownloadAndVerifyAsync(
                http,
                selected.InstallerUrl,
                selected.InstallerSha256Url,
                packageDir,
                progress: null,
                ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.Warn($"[agent-update] Download/verification failed: {ex.Message}");
            return new AppUpdateResult(false, Error: ex.Message);
        }

        string? msiPath = null;
        if (File.Exists(AgentPaths.DefaultInstalledAgentExe()))
        {
            // A failed MSI check does not block the desktop update. Remote update_rpcd uses the same helper with required: true.
            msiPath = await AppUpdateInstaller.DownloadAgentMsiAsync(
                http,
                selected.AgentMsiUrl,
                selected.AgentMsiSha256Url,
                packageDir,
                required: false,
                progress: null,
                onSkipped: message => log.Warn($"[agent-update] Agent MSI download/verification skipped: {message}"),
                ct).ConfigureAwait(false);
        }

        // Setup closes the app, and this helper (a child of the app) ends with it, so nothing may be left for this process
        // to do after Setup starts. Setup itself runs the Agent MSI and starts the app again (installer/RemotePCDiagnostics.iss).
        IReadOnlyList<string>? relaunch = null;
        IReadOnlyList<string>? serviceRelaunch = null;
        if (relaunchArguments is { Count: > 0 })
        {
            if (!SessionLaunchOptions.IsRestartCommandLine(relaunchArguments))
                log.Warn("[agent-update] Ignoring a relaunch command line that is not a session restart; the app will not be started again.");
            else if (OperatingSystem.IsWindows() && Process.GetCurrentProcess().SessionId == 0)
            {
                // The agent service (SYSTEM, Session 0) ran this update for an unattended session. Setup would start the app on
                // Session 0's desktop, where nobody sees it, so the service starts it in the user's session instead (PendingAppRelaunch).
                if (relaunchFromService is not null)
                    serviceRelaunch = relaunchArguments;
                else
                    log.Info("[agent-update] Running in the service session: the app will not be started again.");
            }
            else
                relaunch = relaunchArguments;
        }

        if (serviceRelaunch is not null)
        {
            try { PendingAppRelaunch.Save(stagingDir, serviceRelaunch); }
            catch (Exception ex)
            {
                log.Warn($"[agent-update] Could not save the relaunch request: {ex.Message}");
                serviceRelaunch = null;
            }
        }

        try
        {
            var arguments = AppUpdateInstaller.BuildSetupArguments(verySilent: true, msiPath, relaunch);
            log.Info($"[agent-update] Launching silent installer '{installerPath}' (agent MSI: {msiPath ?? "none"}; relaunch: {(relaunch is not null ? "by Setup" : serviceRelaunch is not null ? "by the agent service" : "no")}).");
            var proc = StartInstaller(installerPath, arguments, stagingDir, log, out var started);
            if (!started)
                return new AppUpdateResult(false, Error: "Failed to start the RPCD installer.");

            if (serviceRelaunch is not null && proc is not null)
                relaunchFromService!(proc, stagingDir);

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

    /// <summary>
    /// Starts a verified Setup and waits for it. Returns the process exit code, or -1 when Setup did not start.
    /// From the agent service, Setup is started outside the service job. That job kills child processes when the
    /// service exits, and the upgrade Setup runs stops this service.
    /// </summary>
    internal static async Task<int> StartAndWaitAsync(
        string installerPath,
        string arguments,
        string stagingDir,
        Action<string>? log,
        CancellationToken ct)
    {
        try
        {
            return await WaitForSetupAsync(installerPath, arguments, stagingDir, log, ct).ConfigureAwait(false);
        }
        finally
        {
            // The caller cleared failure restart before this. Put Automatic and the actions back whether Setup
            // finished or never started. Starting the process is Setup's post-install step: this process may
            // still hold the instance mutex, and a start from here would exit 0 as a second instance.
            AgentServiceRecovery.ApplyAutomatic(log);
        }
    }

    private static async Task<int> WaitForSetupAsync(
        string installerPath,
        string arguments,
        string stagingDir,
        Action<string>? log,
        CancellationToken ct)
    {
        if (OperatingSystem.IsWindows() && JobBreakawayProcess.IsInJob())
        {
            // The elevated helper is in the app's kill-on-close job, and Setup closes the app, so this process usually dies
            // before Setup returns. Setup runs under a cmd script that leaves its exit code in the staging folder, and the
            // next agent process to read the status turns a failed exit into a final failure (RpcdUpdateSeal.ApplySetupExit).
            var exitPath = Path.Combine(stagingDir, ScheduledSetup.ExitCodeFileName);
            var batchPath = Path.Combine(stagingDir, ScheduledSetup.BatchFileName);
            var batch = ScheduledSetup.BatchScript(installerPath, arguments, exitPath);
            var wrapped = false;
            if (ScheduledSetup.IsAscii(batch))
            {
                try
                {
                    if (File.Exists(exitPath))
                        File.Delete(exitPath);
                    await File.WriteAllTextAsync(batchPath, batch, System.Text.Encoding.ASCII).ConfigureAwait(false);
                    wrapped = true;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    log?.Invoke($"[rpcd-update] Could not write Setup's exit-code script, starting Setup directly: {ex.Message}");
                }
            }

            var cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
            var started = wrapped
                ? JobBreakawayProcess.TryStart(cmd, "/d /c " + WindowsCommandLine.Quote(batchPath), stagingDir, out var detached)
                : JobBreakawayProcess.TryStart(installerPath, arguments, stagingDir, out detached);
            if (started)
            {
                if (detached is null)
                    return -1;
                using (detached)
                {
                    await detached.WaitForExitAsync(ct).ConfigureAwait(false);
                    if (!wrapped)
                        return detached.ExitCode;
                    var code = ReadSetupExit(exitPath);
                    TryDelete(exitPath);
                    TryDelete(batchPath);
                    return code ?? -1;
                }
            }

            log?.Invoke("[rpcd-update] This process is in a job that does not allow breakaway. Starting Setup as a scheduled task so stopping the service does not stop Setup.");
            if (ScheduledSetupLaunch.TryStart(installerPath, arguments, stagingDir, log, out var wait) && wait is not null)
            {
                using (wait)
                    return await wait.WaitAsync(ct).ConfigureAwait(false);
            }

            log?.Invoke("[rpcd-update] Could not start Setup outside the service job. A child Setup ends when this service ends.");
        }

        Process? proc;
        try
        {
            proc = StartInstaller(installerPath, arguments, stagingDir, new CallbackLogger(log), out var started);
            if (!started || proc is null)
                return -1;
        }
        catch (Exception ex)
        {
            log?.Invoke($"[rpcd-update] Failed to start the installer: {ex.Message}");
            return -1;
        }

        using (proc)
        {
            await proc.WaitForExitAsync(ct).ConfigureAwait(false);
            return proc.ExitCode;
        }
    }

    internal static void PrepareStaging(string stagingDir)
    {
        if (!OperatingSystem.IsWindows() ||
            !ProtectedStateFolder.Ensure(Path.GetDirectoryName(stagingDir)!, stagingDir, null))
            throw new InvalidOperationException("Could not secure update staging for Administrators and SYSTEM.");
        DeleteOldPackages(stagingDir, DateTime.UtcNow);
    }

    /// <summary>How old a downloaded package folder must be before it is deleted. An update that is still running is younger.</summary>
    internal static readonly TimeSpan PackageRetention = TimeSpan.FromHours(6);

    /// <summary>
    /// Deletes the per-update package folders (named by a GUID) older than <see cref="PackageRetention"/>, so each update's
    /// Setup and Agent MSI do not stay in ProgramData. A folder that is still in use is left for the next update.
    /// </summary>
    internal static int DeleteOldPackages(string stagingDir, DateTime utcNow, Action<string>? log = null)
    {
        var deleted = 0;
        if (!Directory.Exists(stagingDir))
            return 0;
        foreach (var dir in new DirectoryInfo(stagingDir).EnumerateDirectories())
        {
            if (!Guid.TryParseExact(dir.Name, "N", out _) || (dir.Attributes & FileAttributes.ReparsePoint) != 0)
                continue;
            if (utcNow - dir.CreationTimeUtc < PackageRetention)
                continue;
            try
            {
                dir.Delete(recursive: true);
                deleted++;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                log?.Invoke($"[agent-update] Could not delete old update package {dir.Name}: {ex.Message}");
            }
        }
        // Builds before per-update folders downloaded Setup and the MSI straight into the staging folder.
        foreach (var file in new DirectoryInfo(stagingDir).EnumerateFiles())
        {
            var ext = file.Extension;
            if (!(ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) || ext.Equals(".msi", StringComparison.OrdinalIgnoreCase)
                    || ext.Equals(".part", StringComparison.OrdinalIgnoreCase)) || utcNow - file.LastWriteTimeUtc < PackageRetention)
                continue;
            try
            {
                file.Delete();
                deleted++;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                log?.Invoke($"[agent-update] Could not delete old update file {file.Name}: {ex.Message}");
            }
        }
        return deleted;
    }

    /// <summary>The exit code Setup's cmd script wrote, or null when it has not written one.</summary>
    internal static int? ReadSetupExit(string exitPath)
    {
        try
        {
            return File.Exists(exitPath) ? ScheduledSetup.ParseExitCode(File.ReadAllText(exitPath)) : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
                File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // The next update clears it before starting Setup.
        }
    }

    private sealed class CallbackLogger(Action<string>? log) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => log is not null;
        public void Log<TState>(Microsoft.Extensions.Logging.LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            log?.Invoke(formatter(state, exception));
    }

    /// <summary>
    /// Starts Setup so that it outlives this process. In the elevated helper, this process is in a kill-on-close job that the
    /// Host holds, and Setup closes the Host: a Setup started inside that job is ended with it, before it installs anything,
    /// and the PC stays on the old build (see <see cref="JobBreakawayProcess"/>).
    /// </summary>
    private static Process? StartInstaller(string installerPath, string arguments, string stagingDir, ILogger log, out bool started)
    {
        if (JobBreakawayProcess.IsInJob())
        {
            if (JobBreakawayProcess.TryStart(installerPath, arguments, stagingDir, out var detached))
            {
                started = true;
                return detached;
            }
            log.Warn("[agent-update] Windows did not let Setup leave this process's job; Setup may be stopped when the app closes.");
        }

        var proc = Process.Start(new ProcessStartInfo
        {
            FileName = installerPath,
            Arguments = arguments,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = stagingDir,
        });
        started = proc is not null;
        return proc;
    }
}
