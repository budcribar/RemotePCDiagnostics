using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Security;

namespace RemotePCDiagnostics.Modules.SecurityEssentials;

/// <summary>Security essentials. In user mode (the module host) its WMI queries go through the app (<c>wmi.query</c>).</summary>
public sealed class SecurityEssentialsPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new SecurityEssentialsModule(sp.GetRequiredService<ISecurityEssentialsSource>(), context.Log));
}
