using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Storage;

namespace RemotePCDiagnostics.Modules.DriveSelfTest;

/// <summary>The drives' own short and extended self-tests, run through the Agent.</summary>
public sealed class DriveSelfTestPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new DriveSelfTestModule(
            sp.GetService<IDriveSelfTestSource>() ?? new AgentDriveSelfTestSource(sp.GetRequiredService<SystemCommandRunner>()),
            AgentShopPillState.NoAgent(sp),
            sp.LoggerFor<DriveSelfTestModule>()));
}
