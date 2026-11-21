using System.ServiceProcess;
using RemotePCDiagnostics.Agent.Core;

namespace RemotePCDiagnostics.Agent;

/// <summary>
/// Stops every agent service and startup launcher before a new one is started.
/// An <c>sc delete</c> while the old process is still running drops it from the Service Control Manager
/// and the following <c>sc start</c> launches a second version beside it. Legacy names, a Run key, and a
/// scheduled task are the other way two copies stay installed: <c>install</c> used to register only
/// <see cref="AgentLayout.ServiceName"/> and remove those launchers only on uninstall.
/// </summary>
internal static class AgentUpgradeQuiesce
{
    public static void PrepareForInstall(Action<string>? log)
    {
        if (!OperatingSystem.IsWindows())
            return;

        var services = AgentMachineSnapshot.ReadServices();
        var target = AgentPaths.DefaultInstalledAgentExe();
        foreach (var path in AgentInstancePolicy.SideBySideInstallPaths(services, target))
            AgentSingleInstance.Log(AgentInstancePolicy.DescribeSideBySide(path), log);

        try
        {
            foreach (var action in AgentInstancePolicy.BeforeStart(services))
                Execute(action, log);
        }
        finally
        {
            // Failure recovery stays cleared until the caller sets it immediately before start.
            // The start type is put back so a failed install can start the existing service again.
            AgentServiceInstaller.RunSc($"config {AgentPaths.ServiceName} start= auto");
        }
    }

    /// <summary>Stops and deletes agent services other than the current name. Used by uninstall as well as upgrade.</summary>
    public static void RemoveLegacyServices(Action<string>? log)
    {
        if (!OperatingSystem.IsWindows())
            return;

        foreach (var service in AgentMachineSnapshot.ReadServices())
        {
            if (!AgentInstancePolicy.ShouldDeleteService(service.Name, service.ImagePath)) continue;
            var name = Quote(service.Name);
            AgentServiceInstaller.RunSc($"config {name} start= disabled");
            AgentServiceInstaller.RunSc($"failure {name} reset= 0 actions= \"\"");
            StopService(service.Name, log);
            var (code, output) = AgentServiceInstaller.RunSc($"delete {Quote(service.Name)}");
            var line = code == 0
                ? $"Stopped and removed Windows Service '{service.Name}'."
                : $"Could not remove Windows Service '{service.Name}' ({code}): {output}";
            AgentSingleInstance.Log(AgentInstancePolicy.LogPrefix + " " + line, log);
        }
    }

    private static void Execute(AgentUpgradeAction action, Action<string>? log)
    {
        switch (action)
        {
            case DisableFailureRestartAction disable:
                AgentServiceInstaller.RunSc($"config {Quote(disable.ServiceName)} start= disabled");
                AgentServiceInstaller.RunSc($"failure {Quote(disable.ServiceName)} reset= 0 actions= \"\"");
                AgentSingleInstance.Log($"{AgentInstancePolicy.LogPrefix} Failure restart disabled for '{disable.ServiceName}' while it is replaced.", log);
                break;
            case StopServiceAction stop:
                StopService(stop.ServiceName, log);
                break;
            case RemoveStartupLaunchersAction:
                foreach (var line in AgentStartupCleanup.RemoveAll())
                    AgentSingleInstance.Log(AgentInstancePolicy.LogPrefix + " " + line, log);
                break;
            case TerminateLeftoverProcessesAction:
                EndLeftoverProcesses(log);
                break;
            case WaitForInstanceMutexAction:
                if (!AgentSingleInstance.WaitUntilFree(TimeSpan.FromSeconds(15), log))
                    throw new InvalidOperationException($"{AgentInstancePolicy.MutexName} is still held. The new agent service was not started.");
                break;
            case DeleteServiceAction delete:
                var (code, output) = AgentServiceInstaller.RunSc($"delete {Quote(delete.ServiceName)}");
                AgentSingleInstance.Log(
                    code == 0
                        ? $"{AgentInstancePolicy.LogPrefix} Removed service '{delete.ServiceName}'."
                        : $"{AgentInstancePolicy.LogPrefix} Could not remove service '{delete.ServiceName}' ({code}): {output}",
                    log);
                break;
        }
    }

    private static void StopService(string name, Action<string>? log)
    {
        try
        {
            using var controller = new ServiceController(name);
            if (controller.Status is not (ServiceControllerStatus.Stopped or ServiceControllerStatus.StopPending))
            {
                AgentSingleInstance.Log($"{AgentInstancePolicy.LogPrefix} Stopping service '{name}'.", log);
                controller.Stop();
            }
            controller.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(20));
            AgentSingleInstance.Log($"{AgentInstancePolicy.LogPrefix} Service '{name}' has stopped.", log);
        }
        catch (InvalidOperationException)
        {
            AgentSingleInstance.Log($"{AgentInstancePolicy.LogPrefix} Service '{name}' is not installed.", log);
        }
        catch (Exception ex)
        {
            AgentSingleInstance.Log($"{AgentInstancePolicy.LogPrefix} Service '{name}' did not stop yet: {ex.Message}", log);
        }
    }

    private static void EndLeftoverProcesses(Action<string>? log)
    {
        foreach (var process in AgentMachineSnapshot.OtherProcesses())
        {
            try
            {
                using var live = System.Diagnostics.Process.GetProcessById(process.Pid);
                AgentSingleInstance.Log(
                    $"{AgentInstancePolicy.LogPrefix} Ending leftover agent process pid {process.Pid}, version {AgentInstancePolicy.Shown(process.Version)}, path {AgentInstancePolicy.Shown(process.Path)}.",
                    log);
                // Not the process tree: Setup may be a child of the agent that launched this upgrade.
                live.Kill(entireProcessTree: false);
                live.WaitForExit(10_000);
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                AgentSingleInstance.Log($"{AgentInstancePolicy.LogPrefix} Leftover agent process pid {process.Pid} was not ended ({ex.Message}).", log);
            }
        }

        var still = AgentMachineSnapshot.OtherProcesses();
        if (still.Count > 0)
        {
            var pids = string.Join(", ", still.Select(static process => process.Pid.ToString(System.Globalization.CultureInfo.InvariantCulture)));
            throw new InvalidOperationException($"An agent process is still running (pid {pids}). The new agent service was not started.");
        }
    }

    private static string Quote(string name) =>
        name.IndexOfAny([' ', '\t', '"']) < 0 ? name : "\"" + name.Replace("\"", "", StringComparison.Ordinal) + "\"";
}
