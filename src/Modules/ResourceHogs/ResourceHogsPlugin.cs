using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Modules.ResourceHogs;

public sealed class ResourceHogsPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new ResourceHogsModule(sp.GetRequiredService<OsqueryRunner>(), sp.GetRequiredService<SystemCommandRunner>()));
}

