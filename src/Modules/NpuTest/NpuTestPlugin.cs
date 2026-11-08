using RemotePCDiagnostics.Core.Npu;

namespace RemotePCDiagnostics.Modules.NpuTest;

/// <summary>NPU (AI accelerator) test, with its own page. The NPU comes from the app (INpuIo).</summary>
public sealed class NpuTestPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new NpuTestModule(sp.GetRequiredService<INpuIo>(), sp.LoggerFor<NpuTestModule>()),
            ModuleIds.NpuTest, typeof(NpuTestPage));
}

