using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Modules.DismScanHealth;

/// <summary>DISM /ScanHealth (on demand). Needs administrator.</summary>
public sealed class DismScanHealthPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context)
    {
        services.AddSingleton<IDiagnosticModule>(sp => new DismScanHealthModule(sp.GetRequiredService<SystemCommandRunner>()));
    }
}
