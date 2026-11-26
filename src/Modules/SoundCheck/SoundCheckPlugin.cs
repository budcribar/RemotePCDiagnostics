using RemotePCDiagnostics.Core.Audio;

namespace RemotePCDiagnostics.Modules.SoundCheck;

/// <summary>The left/right test sound. Its controls are on the Interactive tests page; audio devices come from the app (IAudioIo).</summary>
public sealed class SoundCheckPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new SoundCheckModule(sp.GetRequiredService<IAudioIo>(), sp.LoggerFor<SoundCheckModule>(), sp.GetService<IAudioStateSource>()),
            ModuleIds.SoundCheck);
}
