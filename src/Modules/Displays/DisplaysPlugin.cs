using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Display;

namespace RemotePCDiagnostics.Modules.Displays;

/// <summary>Displays &amp; video outputs. In user mode (the module host) the display configuration and the System log come from the app
/// (<c>display.state</c>, <c>eventlog.query</c>), and the BIOS settings through the app to the Agent (<c>wmi.query</c>).</summary>
public sealed class DisplaysPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new DisplaysModule(
            sp.GetService<IDisplaySource>() ?? new WindowsDisplaySource(context.Log),
            sp.GetRequiredService<SystemCommandRunner>(),
            sp.GetRequiredService<IWmiSource>(),
            sp.GetRequiredService<IRegistrySource>(),
            sp.GetService<IHostQueries>(),
            context.Log));
}
