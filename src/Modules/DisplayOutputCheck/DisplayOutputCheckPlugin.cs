using RemotePCDiagnostics.Core.Display;

namespace RemotePCDiagnostics.Modules.DisplayOutputCheck;

/// <summary>The interactive video output check. Its controls are on the Interactive tests page; the display configuration comes from the app.</summary>
public sealed class DisplayOutputCheckPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new DisplayOutputCheckModule(sp.GetRequiredService<IDisplaySource>(),
            sp.LoggerFor<DisplayOutputCheckModule>()), ModuleIds.DisplayOutputCheck);
}
