using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.DeviceSensors;

namespace RemotePCDiagnostics.Modules.DeviceSensors;

/// <summary>Motion, light &amp; presence sensors. In user mode (the module host) the sensors come from the app (<c>devicesensors.state</c>),
/// and Device Manager through the app to the Agent (<c>wmi.query</c>).</summary>
public sealed class DeviceSensorsPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new DeviceSensorsModule(
            sp.GetService<IDeviceSensorSource>() ?? new WindowsDeviceSensorSource(context.Log),
            sp.GetRequiredService<IWmiSource>(),
            context.Log));
}
