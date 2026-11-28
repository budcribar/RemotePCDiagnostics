using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Modules.MemoryTest;

/// <summary>Memory test (RemotePCDiagnostics.MemTest.exe next to the app's exe), with its own page, and the Windows boot memory test.</summary>
public sealed class MemoryTestPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new MemoryTestModule(new SystemMemoryInfo(), new ProcessMemTestHelperLauncher(log: sp.LoggerFor<ProcessMemTestHelperLauncher>()),
            sp.GetRequiredService<ISensorProvider>(), new MdschedLauncher(sp.LoggerFor<MdschedLauncher>()), sp.LoggerFor<MemoryTestModule>(),
            offline: Offline(sp)),
            ModuleIds.MemoryTest, typeof(MemoryTestPage));

    private static OfflineMemoryDiagnostic? Offline(IServiceProvider sp)
    {
        if (sp.GetService<SystemCommandRunner>() is not { } commands) return null;
        var source = sp.GetService<IMemoryDiagnosticSource>() ?? new AgentMemoryDiagnosticSource(commands);
        return new OfflineMemoryDiagnostic(source, new WindowsEventLog(commands), () => sp.GetService<RemediationService>(), sp.LoggerFor<OfflineMemoryDiagnostic>());
    }
}
