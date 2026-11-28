using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Battery;
using RemotePCDiagnostics.Core.DataSources;

namespace RemotePCDiagnostics.Modules.BatteryDrain;

/// <summary>Battery drain & runtime test: readings from WMI, the load in the app, the power settings and the shutdown by the Agent
/// (<c>battery_drain_power</c>). Its choices and live readings are on the Checks page (BatteryDrainPanel).</summary>
public sealed class BatteryDrainPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new BatteryDrainModule(
            sp.GetService<IBatteryDrainReadings>() ?? new WmiBatteryDrainReadings(sp.GetRequiredService<IWmiSource>()),
            sp.GetService<IBatteryDrainAgent>() ?? new AgentBatteryDrainSource(sp.GetRequiredService<SystemCommandRunner>()),
            sp.GetService<IBatteryDrainLoad>() ?? new ThreadBatteryDrainLoad(context.Log),
            sp.GetService<IBatteryDrainLogStore>() ?? new FileBatteryDrainLogStore(log: context.Log),
            context.Log));
}
