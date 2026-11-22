using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Modules.Programs;

/// <summary>Programs &amp; updates. Runs out of process (module.json outOfProcess), with its own search UI framed on the module page.</summary>
public sealed class ProgramsPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new ProgramsModule(sp.GetRequiredService<IProgramsSource>(), commands: sp.GetService<SystemCommandRunner>(), log: context.Log),
            ModuleIds.Programs, typeof(ProgramsDetails));
}

