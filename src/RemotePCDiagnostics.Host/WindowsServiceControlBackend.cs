using System.ServiceProcess;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// <see cref="IServiceControlBackend"/>: states and dependents are read here with ServiceController; starting and stopping need
/// administrator rights, so the Agent does them (<paramref name="admin"/>, over the admin pipe). The app never runs as administrator.
/// </summary>
public sealed class WindowsServiceControlBackend(IAdminSettingsBackend admin) : IServiceControlBackend
{
    public ServiceState GetState(string name)
    {
        try
        {
            using var sc = new ServiceController(name);
            return Map(sc.Status);
        }
        catch (InvalidOperationException) { return ServiceState.NotFound; }
    }

    public bool IsDriver(string name)
    {
        try
        {
            using var sc = new ServiceController(name);
            return (sc.ServiceType & (ServiceType.KernelDriver | ServiceType.FileSystemDriver | ServiceType.Adapter | ServiceType.RecognizerDriver)) != 0;
        }
        catch (InvalidOperationException) { return false; }
    }

    public IReadOnlyList<DependentService> GetRunningDependents(string name)
    {
        using var sc = new ServiceController(name);
        var result = new List<DependentService>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void Walk(ServiceController s)
        {
            var deps = s.DependentServices;
            try
            {
                foreach (var d in deps)
                {
                    if (!seen.Add(d.ServiceName)) continue;
                    if (d.Status != ServiceControllerStatus.Stopped) result.Add(new(d.ServiceName, d.DisplayName));
                    Walk(d);
                }
            }
            finally
            {
                foreach (var d in deps) d.Dispose();
            }
        }
        Walk(sc);
        return result;
    }

    public void Start(string name)
    {
        if (GetState(name) is ServiceState.Running or ServiceState.StartPending) return;
        admin.StartService(name);
    }

    public void Stop(string name)
    {
        if (GetState(name) is ServiceState.Stopped or ServiceState.StopPending) return;
        admin.StopService(name);
    }

    public async Task<bool> WaitForStateAsync(string name, ServiceState target, TimeSpan timeout, CancellationToken ct)
    {
        using var sc = new ServiceController(name);
        var deadline = DateTime.UtcNow + timeout;
        while (true)
        {
            sc.Refresh();
            if (Map(sc.Status) == target) return true;
            if (DateTime.UtcNow >= deadline) return false;
            await Task.Delay(250, ct).ConfigureAwait(false);
        }
    }

    private static ServiceState Map(ServiceControllerStatus s) => s switch
    {
        ServiceControllerStatus.Running => ServiceState.Running,
        ServiceControllerStatus.Stopped => ServiceState.Stopped,
        ServiceControllerStatus.StartPending => ServiceState.StartPending,
        ServiceControllerStatus.StopPending => ServiceState.StopPending,
        ServiceControllerStatus.Paused => ServiceState.Paused,
        ServiceControllerStatus.PausePending => ServiceState.PausePending,
        ServiceControllerStatus.ContinuePending => ServiceState.ContinuePending,
        _ => ServiceState.Unknown,
    };
}
