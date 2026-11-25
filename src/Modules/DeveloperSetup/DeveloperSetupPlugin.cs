using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Benchmarks;

namespace RemotePCDiagnostics.Modules.DeveloperSetup;

/// <summary>Fast read-only Developer setup check (toolchains, free space, Defender exclusions, Dev Drive, power plan).</summary>
public sealed class DeveloperSetupPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new DeveloperSetupModule(
            sp.GetService<IDeveloperEnvironmentProbe>(),
            sp.GetService<SystemCommandRunner>(),
            sp.GetService<RemotePCDiagnostics.Core.DataSources.IRegistrySource>()),
            ModuleIds.DeveloperSetup);
}
