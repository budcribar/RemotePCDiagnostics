using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using PeakSWC.RemoteBlazorWebView;
using PeakSWC.RemoteWebView;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Host;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        // Local (default) or Remote. Remote when started with -u=<server uri> (RemoteBlazorWebViewTutorial convention)
        // or REMOTEPC_MODE=Remote (+ optional REMOTEPC_SERVER_URL, default https://remoteblazor.pagetomovie.com:34544).
        // See Properties/launchSettings.json for the "Local" and "Remote (Railway)" Visual Studio profiles.
        var launch = SessionLaunchOptions.Resolve(Environment.GetCommandLineArgs().Skip(1), Environment.GetEnvironmentVariable);
        var mode = launch.Mode;

        var services = new ServiceCollection();
        services.AddRemoteWpfBlazorWebView();
        services.AddSingleton<ISessionContext>(new SessionContext(mode, launch.ServerUri));
        services.AddSingleton<ResultStore>();
        services.AddSingleton<OsqueryRunner>(_ => new OsqueryRunner());
        services.AddSingleton<IDiagnosticModule, OsqueryModule>();
        services.AddSingleton<DiagnosticsService>();
        Resources.Add("services", services.BuildServiceProvider());

        InitializeComponent();
        App.Log($"MainWindow initialized, mode={mode} server={launch.ServerUri}");

        // CI/diagnostics: pass WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS (e.g. --remote-debugging-port=9222) explicitly
        // and log WebView2 startup so failures show up in host.log.
        RemoteBlazorWebView.BlazorWebViewInitializing += (_, e) =>
        {
            var extra = Environment.GetEnvironmentVariable("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS");
            if (!string.IsNullOrWhiteSpace(extra))
            {
                e.EnvironmentOptions ??= new Microsoft.Web.WebView2.Core.CoreWebView2EnvironmentOptions();
                e.EnvironmentOptions.AdditionalBrowserArguments = extra;
            }
            App.Log($"BlazorWebViewInitializing args='{extra}'");
        };
        RemoteBlazorWebView.BlazorWebViewInitialized += (_, e) =>
            App.Log($"BlazorWebViewInitialized browserVersion={e.WebView.CoreWebView2?.Environment.BrowserVersionString}");

        if (launch.ServerUri is not null)
        {
            // Per RemoteBlazorWebViewTutorial (WpfApp): set Id and ServerUri; the control registers with the
            // RemoteWebViewService and raises ReadyToConnect with the technician URL <server>/app/<id>.
            RemoteBlazorWebView.Id = launch.Id; // Guid.Empty = new id each run; fixed via -i=<guid> or REMOTEPC_ID
            RemoteBlazorWebView.ServerUri = launch.ServerUri;
            RemoteBlazorWebView.ReadyToConnect += (s, e) =>
                (s as IBlazorWebView)?.NavigateToString($"<a href='{e.Url}app/{e.Id}' target='_blank'>{e.Url}app/{e.Id}</a>");
            // TODO: consent prompt + audit log before accepting a remote session (see README Safety section).
        }
    }
}
