using RemotePCDiagnostics.Agent.Core;

namespace RemotePCDiagnostics.Agent;

/// <summary>
/// Puts the agent service back to Automatic with failure restart, or clears failure restart while it is being replaced.
/// Never switches the start type away from Automatic. A remote update used to set <c>start= disabled</c> and then die
/// with the service process, which left the new build installed and the service stopped.
/// </summary>
internal static class AgentServiceRecovery
{
    public static void ClearFailureRestart(Action<string>? log)
    {
        if (!OperatingSystem.IsWindows())
            return;
        Run(AgentServiceControl.ClearFailureFlag(AgentPaths.ServiceName), log);
        Run(AgentServiceControl.ClearFailureRestart(AgentPaths.ServiceName), log);
    }

    public static void ApplyAutomatic(Action<string>? log)
    {
        if (!OperatingSystem.IsWindows())
            return;
        foreach (var args in AgentServiceControl.ArgumentsFor(new EnsureServiceRecoveryAction(AgentPaths.ServiceName)))
            Run(args, log);
    }

    private static void Run(string arguments, Action<string>? log)
    {
        try
        {
            var (code, output) = AgentServiceInstaller.RunSc(arguments);
            var line = string.IsNullOrWhiteSpace(output) ? $"sc {arguments} -> {code}" : $"sc {arguments} -> {code} {output}";
            log?.Invoke(line);
        }
        catch (Exception ex)
        {
            log?.Invoke($"sc {arguments} did not run: {ex.Message}");
        }
    }
}
