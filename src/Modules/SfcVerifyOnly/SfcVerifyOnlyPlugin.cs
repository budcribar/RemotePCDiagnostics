using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Modules.SfcVerifyOnly;

/// <summary>SFC /verifyonly (on demand). Needs administrator.</summary>
public sealed class SfcVerifyOnlyPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context)
    {
        services.AddSingleton<IDiagnosticModule>(sp => new SfcVerifyOnlyModule(sp.GetRequiredService<SystemCommandRunner>()));
    }
}
