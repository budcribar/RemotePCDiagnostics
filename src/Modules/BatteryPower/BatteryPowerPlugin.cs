using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Modules.BatteryPower;

/// <summary>Battery &amp; power plan. Runs out of process (module.json outOfProcess), with its own battery gauge framed on the module page.</summary>
public sealed class BatteryPowerPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new BatteryPowerModule(sp.GetRequiredService<IBatteryPowerSource>(), context.Log),
            ModuleIds.BatteryPower, typeof(BatteryDetails));
}

