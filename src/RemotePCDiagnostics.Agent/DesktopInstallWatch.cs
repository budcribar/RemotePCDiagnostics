using RemotePCDiagnostics.Agent.Core;

namespace RemotePCDiagnostics.Agent;

/// <summary>
/// MSIX cannot run code on uninstall. After this service has seen the Setup exe, the Inno uninstall key, or the
/// Store package, two later polls that confirm all of those are gone (and the desktop app is not running) start
/// <c>RemotePCDiagnostics.Agent.exe uninstall</c> in another process. A fleet agent that only cached the app never
/// sets the seen flag and stays installed.
/// </summary>
internal static class DesktopInstallWatch
{
    public static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(60);

    public static async Task RunAsync(CancellationToken ct, Action<string>? log, Action onRemovalStarted)
    {
        var seen = AgentPaths.ReadHostWatch().HostEverSeen;
        var streak = 0;
        using var timer = new PeriodicTimer(PollInterval);
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var observation = DesktopInstallProbe.Observe();
                if (observation.ConfirmedPresent && !seen)
                {
                    seen = true;
                    try { AgentPaths.WriteHostWatch(new AgentHostWatchState { HostEverSeen = true }); }
                    catch { /* The next poll tries again. */ }
                }
                streak = AgentSelfRemoval.NextAbsentStreak(streak, observation);
                if (AgentSelfRemoval.ShouldRemove(seen, streak, observation))
                {
                    log?.Invoke("Remote PC Diagnostics is no longer installed. Removing the agent.");
                    if (AgentServiceInstaller.TryBeginSelfRemoval(log))
                    {
                        onRemovalStarted();
                        return;
                    }
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                log?.Invoke("Desktop install check failed: " + ex.Message);
            }

            try
            {
                if (!await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
                    return;
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }
}
