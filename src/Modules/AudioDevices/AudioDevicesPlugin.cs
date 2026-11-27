using RemotePCDiagnostics.Core.Audio;

namespace RemotePCDiagnostics.Modules.AudioDevices;

/// <summary>The per-device sound test. Its controls are on the Interactive tests page; audio devices come from the app (IAudioIo).</summary>
public sealed class AudioDevicesPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new AudioDevicesModule(sp.GetRequiredService<IAudioIo>(), sp.LoggerFor<AudioDevicesModule>(), sp.GetService<IAudioStateSource>()),
            ModuleIds.AudioDevices);
}
