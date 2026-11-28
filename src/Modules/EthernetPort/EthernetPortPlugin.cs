using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;

namespace RemotePCDiagnostics.Modules.EthernetPort;

/// <summary>The Ethernet port test. Its controls are on the Interactive tests page. The ports come from WMI (through the Agent when it is
/// connected); the link, the pings and the loopback frames are the app's own, without administrator rights (the app supplies
/// <see cref="IEthernetPortIo"/>, so the module runs in the app, where the page hands it the picked port).</summary>
public sealed class EthernetPortPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new EthernetPortModule(
            sp.GetService<INicHardwareSource>() ?? new WmiNicHardwareSource(sp.GetRequiredService<IWmiSource>()),
            sp.GetRequiredService<IEthernetPortIo>(), new NicLinkProbe(), sp.LoggerFor<EthernetPortModule>()), ModuleIds.EthernetPort);
}
