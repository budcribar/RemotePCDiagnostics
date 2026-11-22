using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Modules.Crashes;

/// <summary>Crashes &amp; unexpected restarts. The dump files and the graphics drivers are read with WMI through the Agent. In user mode (the
/// module host) the event logs and the reviewed list come from the app (<c>eventlog.query</c>, <c>events.reviewed</c>), and WMI goes
/// through the app to the Agent (<c>wmi.query</c>).</summary>
public sealed class CrashesPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new CrashesModule(sp.GetRequiredService<SystemCommandRunner>(), includeSystemCrashes: true,
            dumps: sp.GetService<ICrashDumpSource>(), drivers: sp.GetService<IDeviceDriverSource>(),
            host: sp.GetService<RemotePCDiagnostics.Core.Plugins.IHostQueries>()));
}

