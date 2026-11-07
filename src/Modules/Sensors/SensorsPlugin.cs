using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Modules.Sensors;

/// <summary>Temperatures &amp; fans (LibreHardwareMonitor), with its own page. Needs administrator.</summary>
public sealed class SensorsPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context)
    {
        services.AddSingleton<IDiagnosticModule>(sp => new LibreHardwareMonitorModule(sp.GetRequiredService<ISensorProvider>()));
        context.SetDetailsComponent(ModuleIds.Sensors, typeof(LibreHardwareMonitorPage));
    }
}
