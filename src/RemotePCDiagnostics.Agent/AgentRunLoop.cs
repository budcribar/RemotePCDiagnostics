using RemotePCDiagnostics.Agent.Core;

namespace RemotePCDiagnostics.Agent;

/// <summary>The service and <c>run</c> share one loop: the relay stream, the badge file, and the desktop-install watch.</summary>
internal static class AgentRunLoop
{
    /// <summary>The installed app's folder (osquery is in it), or null when the app isn't installed.</summary>
    private static string? AppFolder()
    {
        try { return Path.GetDirectoryName(AgentPaths.TryFindLocalInstalledHostExe() ?? AgentPaths.TryFindStoreHostExe()); }
        catch { return null; }
    }

    public static async Task RunAsync(AgentConfig config, Action<string>? log, CancellationToken ct)
    {
        // Created before anything else, so the service sets the update lock's permissions before an app can make it.
        using var updateLock = AgentUpdateLock.Create(log);
        using var updater = new RpcdRemoteUpdater(
            installedVersion: AgentPaths.GetUpdateInstalledVersion,
            relaunchArguments: () => RpcdRemoteUpdater.RelaunchForActiveSession(config.Server),
            log: log,
            configuredServer: () => config.Server);
        using var platform = new WindowsAgentPlatform(config.Server, log, updater);
        // Takes %ProgramData%\RemotePCDiagnostics back and clears links or files someone else put in it, before anything is written there.
        if (OperatingSystem.IsWindows() && string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(AgentLayout.ConfigPathEnvVar)))
            try { ProtectedStateFolder.Ensure(null); } catch { }
        try { AgentPaths.EnsureSessionsDirectory(); } catch { }
        // A drive self-test that was running when the PC restarted or the Agent stopped: put its power settings back.
        if (OperatingSystem.IsWindows()) RemotePCDiagnostics.Core.Storage.AgentDriveSelfTestHost.RecoverAtStart(RemotePCDiagnostics.Core.Logging.AppLoggerFactory.From(log).CreateLogger("DriveSelfTest"));
        // An in-app update may have replaced this service mid-way (Setup's Agent MSI step): bring the session's app back.
        try { platform.ResumePendingRelaunch(); } catch { }
        var publisher = new AgentStatusPublisher();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var removing = 0;
        // Scheduled metrics (persistent agents only): the fleet admin's schedule, a capped outbox in the protected state folder.
        AgentMetrics? metrics = null;
        if (config.AgentLifetime != AgentLifetime.Session && OperatingSystem.IsWindows())
        {
            try
            {
                var metricsLog = RemotePCDiagnostics.Core.Logging.AppLoggerFactory.From(log).CreateLogger("AgentMetrics");
                // The sensor driver is opened for the one reading and closed again, not held for the life of the service.
                async Task<RemotePCDiagnostics.Core.Sensors.SensorSnapshot?> ReadSensorsAsync(CancellationToken token)
                {
                    using var provider = AgentAdminHost.CreateWindowsSensorProvider(metricsLog, out var reader);
                    return reader is null ? null : await reader(token).ConfigureAwait(false);
                }
                metrics = new AgentMetrics(config.MachineId, RemotePCDiagnostics.Core.ProtectedState.Folder(),
                    () => new RemotePCDiagnostics.Core.Metrics.CoreMetricsProbes(AppFolder(), ReadSensorsAsync, metricsLog),
                    AgentMetrics.EventLogHistory(log), AgentPaths.GetInstalledOrCachedAppVersion, log: log);
            }
            catch (Exception ex) { log?.Invoke($"Scheduled metrics unavailable: {ex.Message}"); }
        }
        // Alerts (persistent agents only): event watchers and level readings, an outbox in the protected state folder.
        AgentAlerts? alerts = null;
        if (config.AgentLifetime != AgentLifetime.Session && OperatingSystem.IsWindows())
        {
            try { alerts = new AgentAlerts(RemotePCDiagnostics.Core.ProtectedState.Folder(), AgentPaths.GetInstalledOrCachedAppVersion, log: log); }
            catch (Exception ex) { log?.Invoke($"Alerts unavailable: {ex.Message}"); }
        }
        var worker = new AgentHubWorker(config, platform, new AgentSessionOptions
        {
            Metrics = metrics,
            Alerts = alerts,
            Log = log,
            LinkChanged = (connected, group) => publisher.Publish(connected, group),
            ReleaseAnnounced = (stable, prerelease) => publisher.PublishRelease(stable, prerelease),
            UpdateRpcd = updater.HandleHubAsync,
            ReadUpdateRpcd = requestId => updater.ToProgress(requestId),
            CancelUpdateRpcd = requestId => updater.Cancel(requestId),
            SaveAgentToken = assigned =>
            {
                config.AgentToken = assigned;
                AgentPaths.WriteSecuredConfig(config);
            },
        });
        var localPipe = platform.RunLocalHostPipeAsync(linked.Token);
        var watch = DesktopInstallWatch.RunAsync(linked.Token, log, () =>
        {
            Interlocked.Exchange(ref removing, 1);
            try { linked.Cancel(); } catch { }
        });
        try
        {
            await worker.RunLoopAsync(linked.Token).ConfigureAwait(false);
        }
        finally
        {
            // Self-removal starts uninstall in another process, which deletes the status file. Do not recreate it.
            if (Volatile.Read(ref removing) == 0)
                publisher.Publish(false, null);
            try { await linked.CancelAsync().ConfigureAwait(false); } catch { }
            try { await localPipe.ConfigureAwait(false); }
            catch (OperationCanceledException) { }
            try { await watch.ConfigureAwait(false); }
            catch (OperationCanceledException) { }
        }
    }
}
