using RemotePCDiagnostics.Core.Security;

namespace RemotePCDiagnostics.Modules.SecurityAudit;

/// <summary>Security audit (bundled HardeningKitty, read-only), with its own page. Needs administrator.</summary>
public sealed class SecurityAuditPlugin : IModulePlugin
{
    // On-demand only (Start button on its page): excluded from Run All (IncludeInRunAll=false) and not auto-run.
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, new SecurityAuditModule(new SecurityAuditOptions { Log = context.Log }), typeof(SecurityAuditPage));
}

