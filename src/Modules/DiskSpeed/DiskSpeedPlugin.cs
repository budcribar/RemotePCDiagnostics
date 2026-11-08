using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Modules.DiskSpeed;

/// <summary>Disk speed test, with its own page.</summary>
public sealed class DiskSpeedPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new DiskSpeedModule(new PhysicalDiskTestFileSystem(sp.LoggerFor<PhysicalDiskTestFileSystem>()),
            sp.GetRequiredService<ISensorProvider>(), sp.LoggerFor<DiskSpeedModule>()), ModuleIds.DiskSpeed, typeof(DiskSpeedPage));
}

