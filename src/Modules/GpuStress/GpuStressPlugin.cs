using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Modules.GpuStress;

/// <summary>Graphics (GPU) stress test, with its own page. Direct3D comes from the app (IGpuDeviceFactory).</summary>
public sealed class GpuStressPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new GpuStressModule(sp.GetRequiredService<IGpuDeviceFactory>(), sp.GetRequiredService<ISensorProvider>(), sp.LoggerFor<GpuStressModule>()),
            ModuleIds.GpuStress, typeof(GpuStressPage));
}

