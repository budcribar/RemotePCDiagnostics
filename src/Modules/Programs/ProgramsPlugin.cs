using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Modules.Programs;

/// <summary>Programs &amp; updates. Runs out of process (module.json outOfProcess), with its own search UI framed on the module page.</summary>
public sealed class ProgramsPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context)
    {
        services.AddSingleton<IDiagnosticModule>(sp => new ProgramsModule(sp.GetRequiredService<OsqueryRunner>()));
        context.SetDetailsComponent(ModuleIds.Programs, typeof(ProgramsDetails));
    }
}
