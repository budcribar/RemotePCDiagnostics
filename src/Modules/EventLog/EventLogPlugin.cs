using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Modules.EventLog;

public sealed class EventLogPlugin : IModulePlugin
{
    // Crash events are the Crashes module's. In user mode (the module host) the event logs and the reviewed list come from the app
    // (eventlog.query, events.reviewed).
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddSingleton<IDiagnosticModule>(sp => new EventLogModule(sp.GetRequiredService<SystemCommandRunner>(), excludeCrashEvents: true,
            host: sp.GetService<RemotePCDiagnostics.Core.Plugins.IHostQueries>()));
}
