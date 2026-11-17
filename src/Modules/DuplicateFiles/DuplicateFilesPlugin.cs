using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Modules.DuplicateFiles;

/// <summary>Duplicate file finder.</summary>
public sealed class DuplicateFilesPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => sp.GetService<DuplicateFilesModule>() ?? new DuplicateFilesModule(sp.GetService<ILogger>()));
}
