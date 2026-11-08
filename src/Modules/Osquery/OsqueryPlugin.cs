using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Modules.Osquery;

/// <summary>Hardware inventory (osquery), with its own page.</summary>
public sealed class OsqueryPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new OsqueryModule(sp.GetRequiredService<OsqueryRunner>()),
            ModuleIds.Osquery, typeof(OsqueryPage));
}

