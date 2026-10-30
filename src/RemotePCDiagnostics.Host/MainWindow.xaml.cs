using System.Diagnostics;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Extensions.DependencyInjection;
using PeakSWC.RemoteBlazorWebView;
using PeakSWC.RemoteWebView;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Security;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Stress;
using RemotePCDiagnostics.Host.Sensors;

namespace RemotePCDiagnostics.Host;

public partial class MainWindow : Window
{
    private const string HostPage = @"wwwroot\index.html";
    private Uri? _serverUri;
    private Uri? _technicianUrl;
    private DispatcherTimer? _readyTimer;
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
        services.AddSingleton<OsqueryRunner>(_ => new OsqueryRunner(options: new OsqueryOptions { Log = App.Log }));
        services.AddSingleton<IDiagnosticModule, OsqueryModule>();
        services.AddSingleton<ISensorProvider, LhmSensorProvider>();
        services.AddSingleton<IDiagnosticModule, LibreHardwareMonitorModule>();
        // On demand only: not auto-run and excluded from Run All; runs when the user presses Start on its page.
        services.AddSingleton<IDiagnosticModule>(sp => new CpuStressModule(sp.GetRequiredService<ISensorProvider>(), App.Log));
        services.AddSingleton<IDiagnosticModule>(sp => new DiskSpeedModule(new PhysicalDiskTestFileSystem(App.Log), sp.GetRequiredService<ISensorProvider>(), App.Log));
        services.AddSingleton<IDiagnosticModule>(sp => new MemoryTestModule(new SystemMemoryInfo(), new ProcessMemTestHelperLauncher(log: App.Log),
            sp.GetRequiredService<ISensorProvider>(), new MdschedLauncher(App.Log), App.Log));
        services.AddSingleton(new SystemCommandRunner(log: App.Log));
        services.AddSingleton<IDiagnosticModule>(sp =>
        {
            var settings = NetworkTestSettings.FromEnvironment(Environment.GetEnvironmentVariable);
            return new NetworkTestModule(new SystemPinger(), new SystemGatewayResolver(), new HttpSpeedTester(settings, log: App.Log),
                new SystemAdapterCounters(sp.GetRequiredService<SystemCommandRunner>()), sp.GetRequiredService<ISensorProvider>(), settings, App.Log);
        });
        services.AddSingleton<IDiagnosticModule>(sp => new GpuStressModule(new RemotePCDiagnostics.Host.Gpu.D3D11GpuDeviceFactory(App.Log), sp.GetRequiredService<ISensorProvider>(), App.Log));
        services.AddSingleton<IDiagnosticModule, DriveHealthModule>();
        services.AddSingleton<ServicesModule>();
        services.AddSingleton<IDiagnosticModule>(sp => sp.GetRequiredService<ServicesModule>());
        services.AddSingleton(sp => new ServiceActionService(new WindowsServiceControlBackend(), sp.GetRequiredService<ISessionContext>(), App.Log));
        services.AddSingleton<IDiagnosticModule, ProgramsModule>(sp => new ProgramsModule(sp.GetRequiredService<OsqueryRunner>()));
        services.AddSingleton<IDiagnosticModule, NetworkModule>(sp => new NetworkModule(sp.GetRequiredService<OsqueryRunner>(), sp.GetRequiredService<SystemCommandRunner>()));
        services.AddSingleton<IDiagnosticModule, EventLogModule>();
        services.AddSingleton<IDiagnosticModule, CrashesModule>();
        // On-demand only (Start button on its page): not in AutoRun below and excluded from Run All (IncludeInRunAll=false).
        services.AddSingleton<IDiagnosticModule>(new SecurityAuditModule(new SecurityAuditOptions { Log = App.Log }));
        services.AddSingleton<DiagnosticsService>();
        var provider = services.BuildServiceProvider();
        Resources.Add("services", provider);
        // Tell the person at this PC when a remote technician starts/stops/restarts a service (non-blocking).
        provider.GetRequiredService<ServiceActionService>().ActionCompleted += rec =>
        {
            if (rec.Actor != ServiceActor.Remote) return;
            Dispatcher.BeginInvoke(() => MessageBox.Show(this, $"The remote technician used the Services page: {rec.Message.TrimEnd('.')}.", "Remote PC Diagnostics", MessageBoxButton.OK, MessageBoxImage.Information));
        };

        // Auto-run the hardware inventory in the background on launch (host side, Local and Remote alike).
        // Results flow through ResultStore to the Dashboard / Hardware inventory page. Disable with REMOTEPC_AUTORUN=0.
        AutoRun.Start(provider.GetRequiredService<DiagnosticsService>(), Environment.GetEnvironmentVariable, App.Log, "Osquery", LibreHardwareMonitorModule.ModuleName,
            DriveHealthModule.ModuleName, ServicesModule.ModuleName, ProgramsModule.ModuleName, NetworkModule.ModuleName, EventLogModule.ModuleName, CrashesModule.ModuleName);

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
            StartRemote(launch.ServerUri, launch.Id);
        else
            RemoteBlazorWebView.HostPage = HostPage; // Local: unchanged behavior (HostPage moved from XAML to code)
    }

    /// <summary>
    /// Remote mode, matching RemoteBlazorWebViewTutorial (WpfApp): subscribe ReadyToConnect/Connected/Disconnected and set
    /// Id + ServerUri BEFORE HostPage (setting HostPage starts the control; ServerUri/GrpcBaseUri/Id set afterwards are rejected).
    /// </summary>
    private void StartRemote(Uri serverUri, Guid id)
    {
        _serverUri = serverUri;
        RemotePanel.Visibility = Visibility.Visible;
        SetRemoteState(RemoteSessionState.Connecting);

        RemoteBlazorWebView.ReadyToConnect += (s, e) =>
        {
            _readyTimer?.Stop();
            _technicianUrl = RemoteLinkInfo.BuildTechnicianUrl(e.Url ?? serverUri, e.Id);
            App.Log($"ReadyToConnect url={e.Url} id={e.Id} link={_technicianUrl}");
            RemoteLinkText.Text = _technicianUrl.ToString();
            RemoteHyperlink.NavigateUri = _technicianUrl;
            RemoteLinkRow.Visibility = Visibility.Visible;
            SetRemoteState(RemoteSessionState.Ready);
            // Fallback: same link inside the web view, as the tutorial does (overlay is primary).
            try { (s as IBlazorWebView)?.NavigateToString($"<a href='{_technicianUrl}' target='_blank'>{_technicianUrl}</a>"); }
            catch (Exception ex) { App.Log($"NavigateToString fallback failed: {ex}"); }
        };
        RemoteBlazorWebView.Connected += (_, e) =>
        {
            App.Log($"Remote Connected id={e.Id} ip={e.IpAddress} user={e.User}");
            SetRemoteState(RemoteSessionState.TechnicianConnected);
        };
        RemoteBlazorWebView.Disconnected += (_, e) =>
        {
            App.Log($"Remote Disconnected id={e.Id} url={e.Url} error={e.Exception}");
            SetRemoteState(_technicianUrl is null ? RemoteSessionState.Unreachable : RemoteSessionState.Disconnected);
        };
        RemoteBlazorWebView.Refreshed += (_, e) => App.Log($"Remote Refreshed {e}");

        _readyTimer = new DispatcherTimer { Interval = RemoteLinkInfo.ReadyTimeout };
        _readyTimer.Tick += (_, _) =>
        {
            _readyTimer.Stop();
            if (_technicianUrl is null)
            {
                App.Log($"No ReadyToConnect after {RemoteLinkInfo.ReadyTimeout.TotalSeconds}s (server={serverUri})");
                SetRemoteState(RemoteSessionState.Unreachable);
            }
        };

        try
        {
            RemoteBlazorWebView.Id = id; // Guid.Empty = new id each run; fixed via -i=<guid> or REMOTEPC_ID
            RemoteBlazorWebView.ServerUri = serverUri;
            RemoteBlazorWebView.HostPage = HostPage; // must be last (starts the control)
            _readyTimer.Start();
        }
        catch (Exception ex)
        {
            App.Log($"Remote start failed: {ex}");
            SetRemoteState(RemoteSessionState.Unreachable);
        }
        // TODO: consent prompt + audit log before accepting a remote session (see README Safety section).
    }

    private void SetRemoteState(RemoteSessionState state)
    {
        if (_serverUri is null) return;
        RemoteStatusText.Text = RemoteLinkInfo.StatusText(state, _serverUri);
        RemoteStatusText.Foreground = new SolidColorBrush(RemoteLinkInfo.IsWarning(state) ? Color.FromRgb(0xFF, 0xC8, 0x57) : Color.FromRgb(0xD0, 0xD5, 0xDD));
    }

    private void RemoteHyperlink_RequestNavigate(object sender, System.Windows.Navigation.RequestNavigateEventArgs e)
    {
        try { Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true }); }
        catch (Exception ex) { App.Log($"Open link failed: {ex}"); }
        e.Handled = true;
    }

    private void CopyLinkButton_Click(object sender, RoutedEventArgs e)
    {
        if (_technicianUrl is null) return;
        try { Clipboard.SetText(_technicianUrl.ToString()); CopyLinkButton.Content = "Copied"; }
        catch (Exception ex) { App.Log($"Copy link failed: {ex}"); }
    }
}
