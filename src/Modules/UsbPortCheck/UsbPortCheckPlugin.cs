using RemotePCDiagnostics.Core.Usb;

namespace RemotePCDiagnostics.Modules.UsbPortCheck;

/// <summary>The interactive USB port check. Its controls are on the Interactive tests page; the USB tree comes from the app.</summary>
public sealed class UsbPortCheckPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new UsbPortCheckModule(sp.GetRequiredService<IUsbTreeSource>(),
            sp.LoggerFor<UsbPortCheckModule>()), ModuleIds.UsbPortCheck);
}
