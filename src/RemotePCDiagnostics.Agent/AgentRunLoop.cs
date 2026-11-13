using RemotePCDiagnostics.Agent.Core;

namespace RemotePCDiagnostics.Agent;

/// <summary>The service and <c>run</c> share one loop: the relay stream, the badge file, and the desktop-install watch.</summary>
internal static class AgentRunLoop
{
    public static async Task RunAsync(AgentConfig config, Action<string>? log, CancellationToken ct)
    {
        using var platform = new WindowsAgentPlatform();
        var publisher = new AgentStatusPublisher();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var removing = 0;
        var worker = new AgentHubWorker(config, platform, new AgentSessionOptions
        {
            Log = log,
            LinkChanged = (connected, group) => publisher.Publish(connected, group),
        });
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
            try { linked.Cancel(); } catch { }
            try { await watch.ConfigureAwait(false); }
            catch (OperationCanceledException) { }
        }
    }
}
