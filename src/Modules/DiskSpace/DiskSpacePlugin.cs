using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Modules.DiskSpace;

/// <summary>Large-file and largest-folder finder.</summary>
public sealed class DiskSpacePlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => sp.GetService<DiskSpaceModule>() ?? new DiskSpaceModule(sp.GetService<ILogger>()));
}
