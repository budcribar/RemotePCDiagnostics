using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Modules.Services;

/// <summary>Services. In user mode (the module host) its WMI queries go through the app (<c>wmi.query</c>).</summary>
public sealed class ServicesPlugin : IModulePlugin
{
    // The app's own instance when there is one (memory suggestions share it); a new one in the module host.
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => sp.GetService<ServicesModule>() ?? new ServicesModule(sp.GetRequiredService<IServiceSource>(), context.Log));
}
