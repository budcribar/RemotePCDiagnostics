using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Modules.ChargerReplug;

/// <summary>The charger unplug and replug test. Its controls are on the Interactive tests page; the power state is GetSystemPowerStatus.</summary>
public sealed class ChargerReplugPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new ChargerReplugModule(sp.GetService<IPowerLineSource>() ?? new WindowsPowerLineSource(), sp.LoggerFor<ChargerReplugModule>()),
            ModuleIds.ChargerReplug);
}
