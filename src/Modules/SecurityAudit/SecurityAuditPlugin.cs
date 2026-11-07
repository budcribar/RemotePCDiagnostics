using RemotePCDiagnostics.Core.Security;

namespace RemotePCDiagnostics.Modules.SecurityAudit;

/// <summary>Security audit (bundled HardeningKitty, read-only), with its own page. Needs administrator.</summary>
public sealed class SecurityAuditPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context)
    {
        // On-demand only (Start button on its page): excluded from Run All (IncludeInRunAll=false) and not auto-run.
        services.AddSingleton<IDiagnosticModule>(new SecurityAuditModule(new SecurityAuditOptions { Log = context.Log }));
        context.SetDetailsComponent(ModuleIds.SecurityAudit, typeof(SecurityAuditPage));
    }
}
