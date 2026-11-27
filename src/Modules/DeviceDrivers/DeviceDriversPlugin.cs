using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Modules.DeviceDrivers;

public sealed class DeviceDriversPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new DeviceDriversModule(sp.GetRequiredService<IDeviceDriverSource>(), sp.GetService<SystemCommandRunner>(), context.Log,
            sp.GetService<RemotePCDiagnostics.Core.Drivers.VendorDriverUpdates>()));
}
