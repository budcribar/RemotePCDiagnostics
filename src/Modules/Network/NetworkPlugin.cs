using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Modules.Network;

/// <summary>Network &amp; Wi-Fi. Adapters and IP configuration come from <see cref="INetworkSource"/>; in user mode (the module host) its WMI
/// queries go through the app (<c>wmi.query</c>).</summary>
public sealed class NetworkPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new NetworkModule(sp.GetRequiredService<INetworkSource>(), sp.GetRequiredService<SystemCommandRunner>(),
            includeWifiAndIpConfig: true, log: context.Log,
            radio: sp.GetService<IWifiRadioSource>() ?? new WlanRadioSource(context.Log)));
}
