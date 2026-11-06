using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Modules.GpuStress;

/// <summary>Graphics (GPU) stress test, with its own page. Direct3D comes from the app (IGpuDeviceFactory).</summary>
public sealed class GpuStressPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context)
    {
        services.AddSingleton<IDiagnosticModule>(sp => new GpuStressModule(sp.GetRequiredService<IGpuDeviceFactory>(), sp.GetRequiredService<ISensorProvider>(), sp.LoggerFor<GpuStressModule>()));
        context.SetDetailsComponent(ModuleIds.GpuStress, typeof(GpuStressPage));
    }
}
