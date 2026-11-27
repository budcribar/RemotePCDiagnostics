using System.Diagnostics;
using RemotePCDiagnostics.Agent.Core;

namespace RemotePCDiagnostics.Agent;

/// <summary>Deletes the agent's install folder once the uninstalling process (which runs from it) has exited.</summary>
internal static class AgentInstallDirectoryCleanup
{
    public static void ScheduleInstallDirectoryDelete(string installDir)
    {
        if (!OperatingSystem.IsWindows() || !AgentRemoval.IsAgentInstallDirectory(installDir))
            return;
        var cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        if (!File.Exists(cmd))
            cmd = "cmd.exe";
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = cmd,
                Arguments = AgentRemoval.DelayedDirectoryDeleteArguments(installDir),
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            });
        }
        catch
        {
            // The service and the key are already gone. A leftover folder can be deleted by hand.
        }
    }
}
