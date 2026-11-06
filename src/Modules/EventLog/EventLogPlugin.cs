using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Modules.EventLog;

public sealed class EventLogPlugin : IModulePlugin
{
    // Crash events are the Crashes module's.
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddSingleton<IDiagnosticModule>(sp => new EventLogModule(sp.GetRequiredService<SystemCommandRunner>(), excludeCrashEvents: true));
}
