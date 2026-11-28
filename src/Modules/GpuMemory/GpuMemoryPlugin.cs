using RemotePCDiagnostics.Core.GpuMemory;
using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Modules.GpuMemory;

/// <summary>Graphics memory (VRAM) test. The graphics chips come from the app (IGpuMemorySource: Direct3D 11 in the Host).</summary>
public sealed class GpuMemoryPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new GpuMemoryModule(
            sp.GetService<IGpuMemorySource>() ?? new NoGpuMemorySource(),
            sp.GetService<ISensorProvider>(),
            sp.LoggerFor<GpuMemoryModule>()));
}
