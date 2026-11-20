using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Modules.SleepWake;

/// <summary>Sleep, wake &amp; standby drain. In user mode the System log comes from the app (<c>eventlog.query</c>).</summary>
public sealed class SleepWakePlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new SleepWakeModule(sp.GetRequiredService<SystemCommandRunner>(),
            host: sp.GetService<RemotePCDiagnostics.Core.Plugins.IHostQueries>()));
}
