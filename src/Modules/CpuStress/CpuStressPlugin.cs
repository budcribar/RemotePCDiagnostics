using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Modules.CpuStress;

/// <summary>CPU stress test, with its own page. On demand only: not auto-run and not in Run All; runs when Start is pressed on its page.</summary>
public sealed class CpuStressPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new CpuStressModule(sp.GetRequiredService<ISensorProvider>(), sp.LoggerFor<CpuStressModule>(), ecFan: sp.GetRequiredService<IEcFanSource>()),
            ModuleIds.CpuStress, typeof(CpuStressPage));
}

