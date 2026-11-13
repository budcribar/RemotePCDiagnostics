using System.ServiceProcess;
using RemotePCDiagnostics.Agent.Core;

namespace RemotePCDiagnostics.Host;

/// <summary>The top-bar agent badge. Service Control Manager is asked only when the default agent executable is missing.</summary>
public static class AgentModeHost
{
    public static AgentModeMonitor CreateMonitor()
    {
        var reader = new AgentModeReader(AgentLayout.DefaultAgentExe(), AgentLayout.StatusPath(), IsServiceInstalled);
        return new AgentModeMonitor(reader.Read);
    }

    private static bool IsServiceInstalled()
    {
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            using var controller = new ServiceController(AgentLayout.ServiceName);
            _ = controller.Status;
            return true;
        }
        catch
        {
            return false;
        }
    }
}
