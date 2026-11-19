using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Modules.Crashes;

/// <summary>Crashes &amp; unexpected restarts. In user mode (the module host) the event logs, the admin-only minidump folder and the
/// reviewed list come from the app (<c>eventlog.query</c>, <c>crashes.minidumps</c>, <c>events.reviewed</c>), and for the graphics card the
/// live kernel dumps and the graphics drivers (<c>crashes.livekernelreports</c>, <c>osquery.select</c>).</summary>
public sealed class CrashesPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new CrashesModule(sp.GetRequiredService<SystemCommandRunner>(), includeSystemCrashes: true,
            host: sp.GetService<RemotePCDiagnostics.Core.Plugins.IHostQueries>(), osquery: sp.GetService<RemotePCDiagnostics.Core.Osquery.OsqueryRunner>()));
}

