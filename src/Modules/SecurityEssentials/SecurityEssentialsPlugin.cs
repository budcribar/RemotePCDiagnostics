using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Security;

namespace RemotePCDiagnostics.Modules.SecurityEssentials;

/// <summary>Security essentials. In user mode (the module host) its WMI queries go through the app (<c>wmi.query</c>).</summary>
public sealed class SecurityEssentialsPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp =>
        {
            // The setting fixes run in the Agent; without one the summary doesn't count them as fixable here.
            var elevation = sp.GetService<RemotePCDiagnostics.Core.Session.IElevationContext>();
            return new SecurityEssentialsModule(sp.GetRequiredService<ISecurityEssentialsSource>(), context.Log,
                elevation is null ? null : () => elevation.HasAdminCapabilities);
        });
}
