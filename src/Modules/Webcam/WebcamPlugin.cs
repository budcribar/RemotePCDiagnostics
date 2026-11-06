using RemotePCDiagnostics.Core.Webcam;

namespace RemotePCDiagnostics.Modules.Webcam;

/// <summary>Webcam test, with its own page. Cameras come from the app (IWebcamIo). Frames are analysed in memory only.</summary>
public sealed class WebcamPlugin : IModulePlugin
{
    public void Register(IServiceCollection services, IPluginContext context)
    {
        services.AddSingleton<IDiagnosticModule>(sp => new WebcamTestModule(sp.GetRequiredService<IWebcamIo>(), sp.LoggerFor<WebcamTestModule>()));
        context.SetDetailsComponent(ModuleIds.Webcam, typeof(WebcamTestPage));
    }
}
