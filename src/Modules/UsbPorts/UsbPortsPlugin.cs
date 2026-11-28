using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Usb;

namespace RemotePCDiagnostics.Modules.UsbPorts;

/// <summary>USB ports &amp; devices. In user mode (the module host) the USB tree and the System log come from the app (<c>usb.tree</c>,
/// <c>eventlog.query</c>), and the BIOS settings through the app to the Agent (<c>wmi.query</c>).</summary>
public sealed class UsbPortsPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new UsbPortsModule(
            sp.GetService<IUsbTreeSource>() ?? new WindowsUsbTreeSource(context.Log),
            sp.GetRequiredService<SystemCommandRunner>(),
            sp.GetRequiredService<IWmiSource>(),
            sp.GetRequiredService<IRegistrySource>(),
            sp.GetService<IHostQueries>(),
            context.Log));
}
