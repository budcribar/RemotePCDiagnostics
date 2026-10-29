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
        // Remote mode when started with -u=<server uri> (same convention as RemoteBlazorWebViewTutorial).
        var serverArg = Environment.GetCommandLineArgs().FirstOrDefault(a => a.StartsWith("-u=", StringComparison.OrdinalIgnoreCase));
        var mode = serverArg is null ? SessionMode.Local : SessionMode.Remote;

        var services = new ServiceCollection();
        services.AddRemoteWpfBlazorWebView();
        services.AddSingleton<ISessionContext>(new SessionContext(mode));
        services.AddSingleton<ResultStore>();
        services.AddSingleton<OsqueryRunner>(_ => new OsqueryRunner());
        services.AddSingleton<IDiagnosticModule, OsqueryModule>();
        services.AddSingleton<DiagnosticsService>();
        Resources.Add("services", services.BuildServiceProvider());

        InitializeComponent();
        App.Log($"MainWindow initialized, mode={mode}");

        if (serverArg is not null)
        {
            // Per ConvertToRemoteBlazor.md in budcribar/RemoteBlazorWebViewTutorial.
            // TODO: confirm whether these must be set before InitializeComponent/first render in v10, and add -i=<guid> parsing for a fixed Id.
            RemoteBlazorWebView.Id = Guid.Empty; // new id each run
            RemoteBlazorWebView.ServerUri = new Uri(serverArg[3..]);
            RemoteBlazorWebView.ReadyToConnect += (s, e) =>
                (s as IBlazorWebView)?.NavigateToString($"<a href='{e.Url}app/{e.Id}' target='_blank'>{e.Url}app/{e.Id}</a>");
            // TODO: consent prompt + audit log before accepting a remote session (see README Safety section).
        }
    }
}
