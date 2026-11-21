using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Modules.WakeReadiness;

/// <summary>Wake readiness. Reads powercfg and the adapter's advanced properties. It changes nothing.</summary>
public sealed class WakeReadinessPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new WakeReadinessModule(sp.GetRequiredService<SystemCommandRunner>()));
}
