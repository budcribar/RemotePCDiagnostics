using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Modules.DriveHealth;

/// <summary>Drive health (SMART, reliability counters, retrim). In user mode (the module host) the reads that need administrator
/// rights come from the app (<c>storage.drives</c>, <c>storage.retrims</c>, <c>osquery.select</c>).</summary>
public sealed class DriveHealthPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context)
    {
        services.AddSingleton<IDiagnosticModule>(sp =>
        {
            var host = sp.GetService<RemotePCDiagnostics.Core.Plugins.IHostQueries>();
            var retrims = host is not null ? new RemotePCDiagnostics.Core.Plugins.HostRetrimHistory(host)
                : sp.GetService<IRetrimHistory>() ?? new RetrimHistory(new RetrimLog(RetrimLog.DefaultPath()));
            return new DriveHealthModule(sp.GetRequiredService<SystemCommandRunner>(), sp.GetRequiredService<OsqueryRunner>(), retrims, host: host);
        });
    }
}
