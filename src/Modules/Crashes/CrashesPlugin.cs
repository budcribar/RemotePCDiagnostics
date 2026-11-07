using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Modules.Crashes;

/// <summary>Crashes &amp; unexpected restarts (the minidump folder is admin-only). Needs administrator.</summary>
public sealed class CrashesPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context)
    {
        services.AddSingleton<IDiagnosticModule>(sp => new CrashesModule(sp.GetRequiredService<SystemCommandRunner>(), includeSystemCrashes: true));
    }
}
