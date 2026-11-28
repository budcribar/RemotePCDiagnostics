using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Storage;

namespace RemotePCDiagnostics.Modules.DiskSurfaceScan;

/// <summary>Disk surface scan: the disk list from Storage WMI, the reads by the Agent (<c>disk_read_scan</c>), with its mode and map above the report.</summary>
public sealed class DiskSurfaceScanPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new DiskSurfaceScanModule(
            sp.GetRequiredService<IWmiSource>(),
            sp.GetService<IDiskScanSource>() ?? new AgentDiskScanSource(sp.GetRequiredService<SystemCommandRunner>()),
            context.Log), ModuleIds.DiskSurfaceScan, typeof(DiskSurfaceScanDetails));
}
