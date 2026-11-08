using RemotePCDiagnostics.Core.Audio;

namespace RemotePCDiagnostics.Modules.MicToSpeaker;

/// <summary>Microphone to speaker test, with its own page. Audio devices come from the app (IAudioIo).</summary>
public sealed class MicToSpeakerPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new MicToSpeakerModule(sp.GetRequiredService<IAudioIo>(), sp.LoggerFor<MicToSpeakerModule>()),
            ModuleIds.MicToSpeaker, typeof(MicToSpeakerPage));
}

