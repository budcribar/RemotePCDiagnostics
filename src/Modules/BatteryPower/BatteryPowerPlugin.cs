using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Modules.BatteryPower;

public sealed class BatteryPowerPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddSingleton<IDiagnosticModule>(sp => new BatteryPowerModule(sp.GetRequiredService<OsqueryRunner>(), sp.GetRequiredService<SystemCommandRunner>()));
}
