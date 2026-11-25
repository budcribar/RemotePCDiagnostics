using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Modules.WindowsMaintenance;

/// <summary>Read-only Windows maintenance check (clock &amp; time sync, hosts file, restore points, Delivery Optimization).</summary>
public sealed class WindowsMaintenancePlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new WindowsMaintenanceModule(
            sp.GetService<SystemCommandRunner>(),
            sp.GetService<IRegistrySource>(),
            sp.GetService<IWmiSource>(),
            sp.GetService<IElevatedCommandBridge>()),
            ModuleIds.WindowsMaintenance);
}
