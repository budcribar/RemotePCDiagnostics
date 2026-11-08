using RemotePCDiagnostics.Core.Audio;

namespace RemotePCDiagnostics.Modules.SpeakerToMic;

/// <summary>Speaker to microphone test, with its own page. Audio devices come from the app (IAudioIo).</summary>
public sealed class SpeakerToMicPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new SpeakerToMicModule(sp.GetRequiredService<IAudioIo>(), sp.LoggerFor<SpeakerToMicModule>()),
            ModuleIds.SpeakerToMic, typeof(SpeakerToMicPage));
}

