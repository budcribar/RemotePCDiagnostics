using RemotePCDiagnostics.Core.Webcam;

namespace RemotePCDiagnostics.Modules.Webcam;

/// <summary>Webcam test, with its own page. Cameras come from the app (IWebcamIo). Frames are analysed in memory only.</summary>
public sealed class WebcamPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context) =>
        services.AddModule(context, sp => new WebcamTestModule(sp.GetRequiredService<IWebcamIo>(), sp.LoggerFor<WebcamTestModule>()),
            ModuleIds.Webcam, typeof(WebcamTestPage));
}

