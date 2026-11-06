using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.UI.Pages;

namespace RemotePCDiagnostics.UI;

/// <summary>The details UI of each built-in module, registered in the catalog the same way a plugin registers its own.</summary>
public static class BuiltInModuleUi
{
    public static IReadOnlyDictionary<Guid, Type> Components { get; } = new Dictionary<Guid, Type>
    {
        [ModuleIds.Sensors] = typeof(LibreHardwareMonitorPage),
        [ModuleIds.CpuStress] = typeof(CpuStressPage),
        [ModuleIds.MemoryTest] = typeof(MemoryTestPage),
        [ModuleIds.DiskSpeed] = typeof(DiskSpeedPage),
        [ModuleIds.GpuStress] = typeof(GpuStressPage),
        [ModuleIds.NetworkTest] = typeof(NetworkTestPage),
        [ModuleIds.SecurityAudit] = typeof(SecurityAuditPage),
        [ModuleIds.SpeakerToMic] = typeof(SpeakerToMicPage),
        [ModuleIds.MicToSpeaker] = typeof(MicToSpeakerPage),
        [ModuleIds.Webcam] = typeof(WebcamTestPage),
        [ModuleIds.NpuTest] = typeof(NpuTestPage),
    };

    public static void Register(ModuleCatalog catalog)
    {
        foreach (var (id, type) in Components) catalog.SetDetailsComponent(id, type);
    }
}
