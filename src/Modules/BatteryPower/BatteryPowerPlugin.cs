using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Modules.BatteryPower;

/// <summary>Battery &amp; power plan. Runs out of process (module.json outOfProcess), with its own battery gauge framed on the module page.</summary>
public sealed class BatteryPowerPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new BatteryPowerModule(sp.GetRequiredService<OsqueryRunner>(), sp.GetRequiredService<SystemCommandRunner>()),
            ModuleIds.BatteryPower, typeof(BatteryDetails));
}

