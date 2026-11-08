using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Modules.Sensors;

/// <summary>Temperatures &amp; fans (LibreHardwareMonitor), with its own page. In the app it reads the sensors itself; in user mode (the
/// module host) it asks the app for them (<c>sensors.read</c>), since fans and some storage sensors need administrator rights.</summary>
public sealed class SensorsPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new LibreHardwareMonitorModule(
            sp.GetService<RemotePCDiagnostics.Core.Plugins.IHostQueries>() is { } host ? new RemotePCDiagnostics.Core.Plugins.HostSensorProvider(host) : sp.GetRequiredService<ISensorProvider>()),
            ModuleIds.Sensors, typeof(LibreHardwareMonitorPage));
}

