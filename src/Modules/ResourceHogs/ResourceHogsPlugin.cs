using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Modules.ResourceHogs;

/// <summary>Resource hogs & uptime. In user mode (the module host) its WMI queries go through the app (<c>wmi.query</c>).</summary>
public sealed class ResourceHogsPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new ResourceHogsModule(sp.GetRequiredService<IResourceHogsSource>(), log: context.Log));
}
