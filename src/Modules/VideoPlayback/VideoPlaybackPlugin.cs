using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.VideoPlayback;

namespace RemotePCDiagnostics.Modules.VideoPlayback;

/// <summary>Video playback test. The clip, the decoders and the counters come from the app (IVideoPlaybackSource: Media Foundation in the Host).</summary>
public sealed class VideoPlaybackPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new VideoPlaybackModule(
            sp.GetService<IVideoPlaybackSource>() ?? new NoVideoPlaybackSource(),
            sp.GetService<ISensorProvider>(),
            sp.LoggerFor<VideoPlaybackModule>()));
}
