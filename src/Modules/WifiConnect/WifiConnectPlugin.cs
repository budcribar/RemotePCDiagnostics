using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Modules.WifiConnect;

/// <summary>The Wi-Fi connect test. Its controls are on the Interactive tests page; Wi-Fi is the WLAN API, in the app without administrator rights
/// (the app supplies <see cref="IWifiConnector"/>, so the module runs in the app).</summary>
public sealed class WifiConnectPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp =>
        {
            var module = new WifiConnectModule(sp.GetService<IWifiRadioSource>() ?? new WlanRadioSource(sp.LoggerFor<WifiConnectModule>()),
                sp.GetRequiredService<IWifiConnector>(), new WifiRestoreMarker(), sp.LoggerFor<WifiConnectModule>());
            // A test the app didn't finish (it crashed or the PC shut down mid-test) left the PC on the test's network: go back now.
            _ = module.RestorePendingAsync(CancellationToken.None);
            return module;
        }, ModuleIds.WifiConnect);
}
