using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Audio;
using RemotePCDiagnostics.Core.DataSources;

namespace RemotePCDiagnostics.Modules.Sound;

/// <summary>Sound. In user mode (the module host) audio devices come from the app (<c>audio.state</c>) and WMI through the app (<c>wmi.query</c>).</summary>
public sealed class SoundPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new SoundModule(
            sp.GetService<IAudioStateSource>() ?? new NullAudioStateSource(),
            sp.GetRequiredService<IServiceSource>(),
            sp.GetRequiredService<IDeviceDriverSource>(),
            sp.GetRequiredService<IWmiSource>(),
            sp.GetRequiredService<IRegistrySource>(),
            context.Log));
}
