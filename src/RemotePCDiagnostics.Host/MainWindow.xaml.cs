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
    private readonly ServiceProvider _provider;
    private Uri? _serverUri;
    private Uri? _technicianUrl;
    private Guid _sessionId;
    private bool _mirror;
    private bool _reverseMirror;
    private bool _restarting;
    private Microsoft.Web.WebView2.Wpf.WebView2? _controlWebView; // --reverse-mirror: a plain WebView2 that shows the controlling /app page locally
    private DispatcherTimer? _readyTimer;
    private DispatcherTimer? _copyResetTimer;
    public MainWindow()
    {
        // Local (default) or Remote. Remote when started with -u=<server uri> (RemoteBlazorWebViewTutorial convention)
        // or REMOTEPC_MODE=Remote (+ optional REMOTEPC_SERVER_URL, default https://remoteblazorwebview.com:34544).
        // See Properties/launchSettings.json for the Visual Studio profiles ("Remote (Railway, mirror)" is the default; "Remote (Railway, reverse mirror demo)", "Remote (Railway)", "Local").
        var pendingReboot = RebootResumeCoordinator.TryReadPendingStateFile();
        var launch = SessionLaunchOptions.Resolve(Environment.GetCommandLineArgs().Skip(1), Environment.GetEnvironmentVariable, pendingReboot);
        var mode = launch.Mode;

        var sessionCtx = new SessionContext(mode, launch.ServerUri, launch.Id, launch.Mirror, launch.ReverseMirror);
        var services = new ServiceCollection().AddRemotePCDiagnosticsHost(sessionCtx, App.Log, App.Event);
        var provider = _provider = services.BuildServiceProvider();
        Resources.Add("services", provider);
        Closed += (_, _) => { try { provider.GetService<IEcFanSource>()?.Dispose(); } catch { } }; // release the PawnIO EC module handle
        provider.GetRequiredService<DiagnosticsService>().Log = App.Log;
        provider.GetRequiredService<ChecksScreenState>(); // start tracking results (run mode labels, last completed) from launch
        // One Windows Event Log entry per finished test (every module and run path), see ResultEventLogger.
        var diag = provider.GetRequiredService<DiagnosticsService>();
        var eventContext = new RemotePCDiagnostics.Core.Logging.ResultEventContext(
            n => diag.Catalog.DisplayName(n),
            () => _machine.Value, RemotePCDiagnostics.Core.AppBuildInfo.Version);
        _ = new RemotePCDiagnostics.Core.Logging.ResultEventLogger(provider.GetRequiredService<ResultStore>(), App.Events, _ => diag.CurrentSuiteLabel, context: eventContext);
        _ = Task.Run(() => App.Event(RemotePCDiagnostics.Core.Logging.LogEventIds.AppStart, RemotePCDiagnostics.Core.Logging.LogLevel.Information, AppStartText(mode.ToString())));
        // Tell the person at this PC when a remote technician starts/stops/restarts a service (non-blocking).
        provider.GetRequiredService<ServiceActionService>().ActionCompleted += rec =>
        {

            _ = Task.Run(() => App.Event(RemotePCDiagnostics.Core.Logging.LogEventIds.TestResult, rec.Success ? RemotePCDiagnostics.Core.Logging.LogLevel.Information : RemotePCDiagnostics.Core.Logging.LogLevel.Warning, RemotePCDiagnostics.Core.History.HistorySummary.FormatServiceEvent(rec, _machine.Value, eventContext.AppVersion)));
            if (rec.Actor == ServiceActor.Remote) Dispatcher.BeginInvoke(() => MessageBox.Show(this, $"The remote technician used the Services page: {rec.Message.TrimEnd('.')}.", "Remote PC Diagnostics", MessageBoxButton.OK, MessageBoxImage.Information));
        };
        provider.GetRequiredService<RemediationService>().ActionCompleted += rec =>
        {

            _ = Task.Run(() => App.Event(RemotePCDiagnostics.Core.Logging.LogEventIds.TestResult, rec.Success ? RemotePCDiagnostics.Core.Logging.LogLevel.Information : RemotePCDiagnostics.Core.Logging.LogLevel.Warning, RemotePCDiagnostics.Core.History.HistorySummary.FormatRemediationEvent(rec, _machine.Value, eventContext.AppVersion)));
            if (rec.Actor == ServiceActor.Remote) Dispatcher.BeginInvoke(() => MessageBox.Show(this, $"The remote technician ran an automated fix: {rec.Message.TrimEnd('.')}.", "Remote PC Diagnostics", MessageBoxButton.OK, MessageBoxImage.Information));
        };

        // Auto-run the hardware inventory in the background on launch (host side, Local and Remote alike).
        // Results flow through ResultStore to the Dashboard / Hardware inventory page. Disable with REMOTEPC_AUTORUN=0.
        AutoRun.Start(provider.GetRequiredService<DiagnosticsService>(), Environment.GetEnvironmentVariable, App.Log, ModuleSlugs.Osquery, LibreHardwareMonitorModule.ModuleName);


        _ = Task.Run(async () => { try { await provider.GetRequiredService<RebootResumeCoordinator>().CompletePostRebootIfPendingAsync(provider.GetRequiredService<RemediationService>(), provider.GetRequiredService<DiagnosticsService>(), launch.PostReboot); } catch (Exception ex) { App.Log($"Post-reboot check failed: {ex.Message}"); } });

        // A service workflow waiting for this restart carries on by itself.
        _ = Task.Run(async () => { try { await provider.GetRequiredService<RemotePCDiagnostics.Core.Workflow.WorkflowService>().ResumeAsync(); } catch (Exception ex) { App.Log($"Workflow resume failed: {ex.Message}"); } });
        // An "after" benchmark requested before a restart runs by itself once start-up has settled.
        _ = Task.Run(async () => { try { await provider.GetRequiredService<RemotePCDiagnostics.Core.Benchmarks.BenchmarkService>().ResumeAfterRestartAsync(); } catch (Exception ex) { App.Log($"Benchmark resume failed: {ex.Message}"); } });

        var webViewDataDir = ResolveWebViewUserDataFolder();
        Environment.SetEnvironmentVariable("WEBVIEW2_USER_DATA_FOLDER", webViewDataDir);

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
            e.UserDataFolder = webViewDataDir;
            App.Log($"BlazorWebViewInitializing userDataFolder='{webViewDataDir}' args='{extra}'");
        };
        RemoteBlazorWebView.BlazorWebViewInitialized += (_, e) =>
            App.Log($"BlazorWebViewInitialized browserVersion={e.WebView.CoreWebView2?.Environment.BrowserVersionString}");

        if (launch.ServerUri is not null)
            StartRemote(launch.ServerUri, sessionCtx.SessionId, launch.Mirror, launch.ReverseMirror);
        else
            RemoteBlazorWebView.HostPage = HostPage; // Local: unchanged behavior (HostPage moved from XAML to code)
    }

    /// <summary>
    /// Remote mode, matching RemoteBlazorWebViewTutorial (WpfApp): subscribe ReadyToConnect/Connected/Disconnected and set
    /// Id + ServerUri BEFORE HostPage (setting HostPage starts the control; ServerUri/GrpcBaseUri/Id set afterwards are rejected).
    /// </summary>
    private void StartRemote(Uri serverUri, Guid id, bool mirror, bool reverseMirror = false)
    {
        _serverUri = serverUri;
        _mirror = mirror;
        _reverseMirror = reverseMirror;
        // Reverse-mirror demo: keep the top card hidden so the window looks like Local; a small "Remote" bubble carries the link instead.
        RemotePanel.Visibility = reverseMirror ? Visibility.Collapsed : Visibility.Visible;
        SetRemoteState(RemoteSessionState.Connecting);

        RemoteBlazorWebView.ReadyToConnect += (s, e) => Dispatcher.BeginInvoke(() =>
        {
            _readyTimer?.Stop();
            if (_provider.GetService<ISessionContext>() is SessionContext sc && e.Id != Guid.Empty) sc.SessionId = e.Id;
            if (e.Id != Guid.Empty) _sessionId = e.Id;
            // Demo (--reverse-mirror): the shared link is the read-only mirror page; this window opens the controlling /app page itself.
            _technicianUrl = RemoteLinkInfo.BuildShareUrl(e.Url ?? serverUri, e.Id, _reverseMirror);
            App.Log($"ReadyToConnect url={e.Url} id={e.Id} link={_technicianUrl} reverseMirror={_reverseMirror}");
            RemoteLinkText.Text = _technicianUrl.ToString();
            RemoteHyperlink.NavigateUri = _technicianUrl;
            RemoteLinkRow.Visibility = Visibility.Visible;
            SetRemoteState(RemoteSessionState.Ready);
            if (_reverseMirror)
            {
                // Tutorial "Reversing The Mirror" pattern: a plain WebView2 (no Blazor external-link handling, which otherwise opens
                // /app in the system browser) shows the controlling /app page locally; the Blazor control hosts the app + mirrors.
                ShowLocalController(RemoteLinkInfo.BuildTechnicianUrl(e.Url ?? serverUri, e.Id));
                RemoteBubble.Visibility = Visibility.Visible; // small bubble carries the view-only link; no top card
                return;
            }
            // The app runs in the technician's browser; this window only needs to say so (the link is in the panel above, not repeated).
            try { (s as IBlazorWebView)?.NavigateToString(RemoteLinkInfo.LocalPlaceholderHtml); }
            catch (Exception ex) { App.Log($"NavigateToString placeholder failed: {ex}"); }
        });
        RemoteBlazorWebView.Connected += (_, e) => Dispatcher.BeginInvoke(() =>
        {

            App.Log($"Remote Connected id={e.Id} ip={e.IpAddress} user={e.User} mirror={_mirror} reverseMirror={_reverseMirror}");
            SetRemoteState(RemoteSessionState.TechnicianConnected);
            if (_mirror)
            {
                var activeId = e.Id != Guid.Empty ? e.Id : (_sessionId != Guid.Empty ? _sessionId : id);
                var mirrorUrl = RemoteLinkInfo.BuildMirrorUrl(e.Url ?? serverUri, activeId);
                App.Log($"Navigating local WebView to mirror={mirrorUrl}");
                try { RemoteBlazorWebView.WebView.CoreWebView2?.Navigate(mirrorUrl.ToString()); }
                catch (Exception ex) { App.Log($"Mirror navigate failed: {ex}"); }
            }
        });
        RemoteBlazorWebView.Disconnected += (_, e) => Dispatcher.BeginInvoke(() =>
        {
            App.Log($"Remote Disconnected id={e.Id} url={e.Url} error={e.Exception}");
            SetRemoteState(_technicianUrl is null ? RemoteSessionState.Unreachable : RemoteSessionState.Disconnected);
        });
        // The technician refreshed the browser (or pressed Restart on the "Locked" page): the server drops this client, so
        // start a fresh copy on the same session id and close this one (RemoteBlazorWebViewTutorial does the same with Restart()).
        RemoteBlazorWebView.Refreshed += (_, e) => Dispatcher.BeginInvoke(() =>
        {
            App.Log($"Remote Refreshed {e}");
            if (_restarting) return;
            var id = _sessionId != Guid.Empty ? _sessionId : RemoteBlazorWebView.Id;
            var exe = Environment.ProcessPath;
            if (id == Guid.Empty || exe is null) { App.Log("Refreshed: no session id or executable path, can't restart"); return; }
            try
            {
                var psi = new System.Diagnostics.ProcessStartInfo(exe) { UseShellExecute = false, WorkingDirectory = AppContext.BaseDirectory };
                foreach (var a in SessionLaunchOptions.RestartArguments(serverUri, id, _mirror, _reverseMirror)) psi.ArgumentList.Add(a);
                System.Diagnostics.Process.Start(psi);
                _restarting = true;
                App.Log($"Refreshed: started a new copy for session {id}; closing this one");
                System.Windows.Application.Current.Shutdown();
            }
            catch (Exception ex) { App.Log($"Refreshed: restart failed: {ex.Message}"); }
        });

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
            RemoteBlazorWebView.EnableMirrors = mirror || reverseMirror; // the read-only /mirror page needs this in both directions
            if (reverseMirror)
            {
                // The admin Clients list renders each client's own card markup. In reverse mode the local window controls /app, so point
                // that card at the read-only /mirror page (set Markup before HostPage; the library keeps a non-empty Markup as given).
                try { RemoteBlazorWebView.Markup = RemoteLinkInfo.ToMirrorMarkup(RemoteWebView.GenMarkup(serverUri, id)); }
                catch (Exception ex) { App.Log($"Reverse mirror markup failed: {ex}"); }
            }
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

    /// <summary>
    /// --reverse-mirror (tutorial "Reversing The Mirror"): put a plain WebView2 over the Blazor view and point it at the controlling
    /// /app page, so the person here drives the app in this window while watchers open the read-only /mirror link. A plain WebView2 has
    /// none of the Blazor control's "open off-origin links in the system browser" behavior, so /app loads in-window instead of Chrome.
    /// </summary>
    private void ShowLocalController(Uri appUrl)
    {
        try
        {
            if (_controlWebView is null)
            {
                _controlWebView = new Microsoft.Web.WebView2.Wpf.WebView2
                {
                    CreationProperties = new Microsoft.Web.WebView2.Wpf.CoreWebView2CreationProperties { UserDataFolder = ResolveWebViewUserDataFolder() }
                };
                System.Windows.Controls.Grid.SetRow(_controlWebView, 1);
                System.Windows.Controls.Panel.SetZIndex(_controlWebView, 5); // above the Blazor view (0), below the panel (10)
                RootGrid.Children.Add(_controlWebView);
            }
            App.Log($"Reverse mirror: showing the local controller at {appUrl}");
            _controlWebView.Source = appUrl;
            _controlWebView.Visibility = Visibility.Visible;
        }
        catch (Exception ex) { App.Log($"Reverse mirror: couldn't show the local controller: {ex}"); }
    }

    private static string ResolveWebViewUserDataFolder()
    {
        var custom = Environment.GetEnvironmentVariable("REMOTEPC_WEBVIEW_USER_DATA_FOLDER");
        var candidates = new[]
        {
            custom,
            System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "RemotePCDiagnostics", "WebView2"),
            System.IO.Path.Combine(System.IO.Path.GetTempPath(), "RemotePCDiagnostics", "WebView2")
        };
        foreach (var dir in candidates)
        {
            if (string.IsNullOrWhiteSpace(dir)) continue;
            try
            {
                var info = System.IO.Directory.CreateDirectory(dir);
                try
                {
                    var acl = System.IO.FileSystemAclExtensions.GetAccessControl(info);
                    var flags = System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit;
                    var usersSid = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinUsersSid, null);
                    var authSid = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.AuthenticatedUserSid, null);
                    acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(usersSid, System.Security.AccessControl.FileSystemRights.Modify, flags, System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
                    acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(authSid, System.Security.AccessControl.FileSystemRights.Modify, flags, System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
                    System.IO.FileSystemAclExtensions.SetAccessControl(info, acl);
                }
                catch { }
                var probe = System.IO.Path.Combine(dir, ".write-probe");
                System.IO.File.WriteAllText(probe, "ok");
                System.IO.File.Delete(probe);
                return dir;
            }
            catch { }
        }
        return System.IO.Path.Combine(System.IO.Path.GetTempPath(), "RemotePCDiagnostics", "WebView2");
    }

    private void SetRemoteState(RemoteSessionState state)
    {
        if (_serverUri is null) return;
        // Reverse-mirror demo looks like Local; only pop the card up if the server can't be reached, so errors aren't hidden.
        if (_reverseMirror) RemotePanel.Visibility = RemoteLinkInfo.IsWarning(state) ? Visibility.Visible : Visibility.Collapsed;
        RemoteStatusText.Text = RemoteLinkInfo.StatusText(state, _serverUri, _mirror, _reverseMirror);
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
        try
        {
            Clipboard.SetText(_technicianUrl.ToString());
            CopyLinkButton.Content = "Copied";
            _copyResetTimer?.Stop();
            _copyResetTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            _copyResetTimer.Tick += (_, _) => { _copyResetTimer.Stop(); CopyLinkButton.Content = "Copy link"; };
            _copyResetTimer.Start();
        }
        catch (Exception ex) { App.Log($"Copy link failed: {ex}"); }
    }

    private void RemoteBubble_Click(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (_technicianUrl is null) return;
        try
        {
            Clipboard.SetText(_technicianUrl.ToString());
            RemoteBubbleText.Text = "Link copied";
            _copyResetTimer?.Stop();
            _copyResetTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            _copyResetTimer.Tick += (_, _) => { _copyResetTimer.Stop(); RemoteBubbleText.Text = "Remote"; };
            _copyResetTimer.Start();
        }
        catch (Exception ex) { App.Log($"Copy link (bubble) failed: {ex}"); }
    }

    /// <summary>App start event text: version, machine model, admin, mode (no server URL or session id).</summary>
    private static string AppStartText(string mode)
    {
        string model = "unknown";
        try
        {
            using var q = new System.Management.ManagementObjectSearcher("SELECT Manufacturer, Model FROM Win32_ComputerSystem");
            foreach (var o in q.Get()) using (o) model = $"{o["Manufacturer"]} {o["Model"]}".Trim();
            using var p = new System.Management.ManagementObjectSearcher("SELECT Name FROM Win32_ComputerSystemProduct");
            foreach (var o in p.Get()) using (o) model += $" ({o["Name"]})";
        }
        catch (Exception ex) { model = $"unknown ({ex.GetType().Name})"; }
        bool admin = false;
        try { using var id = System.Security.Principal.WindowsIdentity.GetCurrent(); admin = new System.Security.Principal.WindowsPrincipal(id).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator); } catch { }
        var version = RemotePCDiagnostics.Core.AppBuildInfo.Version;
        return $"Remote PC Diagnostics started.{Environment.NewLine}Version: {version}{Environment.NewLine}Machine: {model}{Environment.NewLine}Running as administrator: {(admin ? "yes" : "no")}{Environment.NewLine}Mode: {mode}{Environment.NewLine}OS: {Environment.OSVersion.VersionString}";
    }

    protected override void OnClosed(EventArgs e)
    {
        base.OnClosed(e); // raise Closed first so handlers (EC fan release) run before the provider is disposed
        _readyTimer?.Stop();
        _copyResetTimer?.Stop();
        try
        {
            _provider.GetService<DiagnosticsService>()?.CancelStressSuite();
            foreach (var m in _provider.GetServices<IDiagnosticModule>())
            {
                if (m is IStressSuiteModule sm) sm.Stop();
                else if (m is SecurityAuditModule sa) sa.Cancel();
                else if (m is RemotePCDiagnostics.Core.Audio.IAudioTestModule am) am.Cancel();
                else if (m is RemotePCDiagnostics.Core.Webcam.IWebcamTestModule wm) wm.Cancel();
                else if (m is RemotePCDiagnostics.Core.Npu.INpuTestModule nm) nm.Cancel();
            }
            _provider.Dispose();
        }
        catch (Exception ex) { App.Log($"Shutdown cleanup failed: {ex.Message}"); }
    }

    private static readonly Lazy<string> _machine = new(() =>
    {
        var model = "";
        try
        {
            using var q = new System.Management.ManagementObjectSearcher("SELECT Manufacturer, Model FROM Win32_ComputerSystem");
            foreach (var o in q.Get()) using (o) model = $"{o["Manufacturer"]} {o["Model"]}".Trim();
        }
        catch { }
        return model.Length > 0 ? $"{Environment.MachineName} ({model})" : Environment.MachineName;
    });

}
