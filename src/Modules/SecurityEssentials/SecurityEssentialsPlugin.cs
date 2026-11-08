using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Security;

namespace RemotePCDiagnostics.Modules.SecurityEssentials;

public sealed class SecurityEssentialsPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new SecurityEssentialsModule(sp.GetRequiredService<SystemCommandRunner>()));
}

