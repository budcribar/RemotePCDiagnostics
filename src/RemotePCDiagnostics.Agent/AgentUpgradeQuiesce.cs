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
            // Failure restart was cleared so a stop during the copy does not launch a second copy.
            // Automatic and the restart actions are put back here even when a later step throws.
            // The start type is never switched off: a killed installer used to leave it that way.
            AgentServiceRecovery.ApplyAutomatic(line => AgentSingleInstance.Log(line, log));
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
            // Legacy names are deleted, so they must not restart while the delete is in progress.
            // The current service is not in this list and is never set off Automatic.
            AgentServiceInstaller.RunSc($"config {name} start= disabled");
            AgentServiceInstaller.RunSc(AgentServiceControl.ClearFailureRestart(service.Name));
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
                foreach (var args in AgentServiceControl.ArgumentsFor(disable))
                    AgentServiceInstaller.RunSc(args);
                AgentSingleInstance.Log($"{AgentInstancePolicy.LogPrefix} Failure restart disabled for '{disable.ServiceName}' while it is replaced. Startup stays Automatic.", log);
                break;
            case EnsureServiceRecoveryAction ensure:
                foreach (var args in AgentServiceControl.ArgumentsFor(ensure))
                    AgentServiceInstaller.RunSc(args);
                AgentSingleInstance.Log($"{AgentInstancePolicy.LogPrefix} '{ensure.ServiceName}' is Automatic and failure restart is on.", log);
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
        var parentsKnown = ProcessLineage.TryParentChain(Environment.ProcessId, out var parents);
        var inJob = JobBreakawayProcess.IsInJob();
        IReadOnlyList<int> protectedIds = parentsKnown ? parents : [];
        foreach (var process in AgentMachineSnapshot.OtherProcesses())
        {
            if (!AgentInstancePolicy.MayTerminateLeftover(process.Pid, Environment.ProcessId, protectedIds, inJob, parentsKnown))
            {
                AgentSingleInstance.Log(
                    $"{AgentInstancePolicy.LogPrefix} Leaving agent process pid {process.Pid} running. Ending it would end Setup before the new service starts.",
                    log);
                continue;
            }

            try
            {
                using var live = System.Diagnostics.Process.GetProcessById(process.Pid);
                AgentSingleInstance.Log(
                    $"{AgentInstancePolicy.LogPrefix} Ending leftover agent process pid {process.Pid}, version {AgentInstancePolicy.Shown(process.Version)}, path {AgentInstancePolicy.Shown(process.Path)}.",
                    log);
                live.Kill(entireProcessTree: AgentInstancePolicy.KillEntireProcessTree);
                live.WaitForExit(10_000);
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                AgentSingleInstance.Log($"{AgentInstancePolicy.LogPrefix} Leftover agent process pid {process.Pid} was not ended ({ex.Message}).", log);
            }
        }

        var still = AgentMachineSnapshot.OtherProcesses()
            .Where(process => AgentInstancePolicy.MayTerminateLeftover(process.Pid, Environment.ProcessId, protectedIds, inJob, parentsKnown))
            .ToList();
        if (still.Count > 0)
        {
            var pids = string.Join(", ", still.Select(static process => process.Pid.ToString(System.Globalization.CultureInfo.InvariantCulture)));
            throw new InvalidOperationException($"An agent process is still running (pid {pids}). The new agent service was not started.");
        }
    }

    private static string Quote(string name) =>
        name.IndexOfAny([' ', '\t', '"']) < 0 ? name : "\"" + name.Replace("\"", "", StringComparison.Ordinal) + "\"";
}
