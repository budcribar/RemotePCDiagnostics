using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Modules.BatteryPower;

/// <summary>Battery &amp; power plan. Runs out of process (module.json outOfProcess), with its own battery gauge framed on the module page.</summary>
public sealed class BatteryPowerPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context)
    {
        services.AddSingleton<IDiagnosticModule>(sp => new BatteryPowerModule(sp.GetRequiredService<OsqueryRunner>(), sp.GetRequiredService<SystemCommandRunner>()));
        context.SetDetailsComponent(ModuleIds.BatteryPower, typeof(BatteryDetails));
    }
}
