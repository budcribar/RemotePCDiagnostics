using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Modules.DriveHealth;

/// <summary>Drive health (SMART, reliability counters, retrim). Needs administrator.</summary>
public sealed class DriveHealthPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context)
    {
        // Out of process the module host has no Windows Defrag events reader: the retrim history then comes from the app's own record only.
        services.AddSingleton<IDiagnosticModule>(sp => new DriveHealthModule(sp.GetRequiredService<SystemCommandRunner>(), sp.GetRequiredService<OsqueryRunner>(),
            sp.GetService<IRetrimHistory>() ?? new RetrimHistory(new RetrimLog(RetrimLog.DefaultPath()))));
    }
}
