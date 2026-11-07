using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Modules.Services;

/// <summary>Services. Needs administrator.</summary>
public sealed class ServicesPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context)
    {
        // The app's own instance when there is one (memory suggestions share it); a new one in the module host.
        services.AddSingleton<IDiagnosticModule>(sp => sp.GetService<ServicesModule>() ?? new ServicesModule(sp.GetRequiredService<OsqueryRunner>()));
    }
}
