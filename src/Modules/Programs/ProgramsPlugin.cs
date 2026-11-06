using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Modules.Programs;

public sealed class ProgramsPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddSingleton<IDiagnosticModule>(sp => new ProgramsModule(sp.GetRequiredService<OsqueryRunner>()));
}
