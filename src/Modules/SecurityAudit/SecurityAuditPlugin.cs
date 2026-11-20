using RemotePCDiagnostics.Core.Security;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Modules.SecurityAudit;

/// <summary>
/// Security audit (bundled HardeningKitty, read-only), with its own page. Needs administrator: when the app isn't elevated, the audit
/// runs in the elevated helper or the agent service. At the PC, with neither running, Start asks Windows to start the helper first.
/// </summary>
public sealed class SecurityAuditPlugin : IModulePlugin
{
    // On-demand only (Start button on its page): excluded from Run All (IncludeInRunAll=false) and not auto-run.
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp =>
        {
            var elevation = sp.GetService<IElevationContext>();
            return new SecurityAuditModule(new SecurityAuditOptions
            {
                Log = context.Log,
                ElevatedBridge = sp.GetService<IElevatedCommandBridge>(),
                IsAdministrator = elevation is null ? null : () => elevation.IsProcessElevated,
                // Windows' permission prompt shows only at the PC, so a remote session never raises it.
                RequestElevation = elevation is null || context.Session.Mode != SessionMode.Local ? null
                    : async ct => (await elevation.EnableAdminModeAsync(ct).ConfigureAwait(false)).Success && elevation.IsAdminHelperConnected,
            });
        }, RemotePCDiagnostics.Core.ModuleIds.SecurityAudit, typeof(SecurityAuditPage));
}
