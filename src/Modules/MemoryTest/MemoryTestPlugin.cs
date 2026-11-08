using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Modules.MemoryTest;

/// <summary>Memory test (RemotePCDiagnostics.MemTest.exe next to the app's exe), with its own page.</summary>
public sealed class MemoryTestPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new MemoryTestModule(new SystemMemoryInfo(), new ProcessMemTestHelperLauncher(log: sp.LoggerFor<ProcessMemTestHelperLauncher>()),
            sp.GetRequiredService<ISensorProvider>(), new MdschedLauncher(sp.LoggerFor<MdschedLauncher>()), sp.LoggerFor<MemoryTestModule>()),
            ModuleIds.MemoryTest, typeof(MemoryTestPage));
}

