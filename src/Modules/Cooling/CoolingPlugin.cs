using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Cooling;
using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Modules.Cooling;

/// <summary>The cooling test: the Temperatures &amp; fans sensors and CPU load over time, full CPU load, and the Agent's thermal modes.</summary>
public sealed class CoolingPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new CoolingTestModule(
            sp.GetService<ICoolingSource>() ?? new CoolingSource(sp.GetRequiredService<ISensorProvider>(), new WindowsCpuLoadSource(),
                sp.GetService<SystemCommandRunner>(), sp.LoggerFor<CoolingTestModule>()),
            new CpuCoolingLoad(),
            PcMaker.Read,
            sp.LoggerFor<CoolingTestModule>()), ModuleIds.Cooling, typeof(CoolingDetails));
}
