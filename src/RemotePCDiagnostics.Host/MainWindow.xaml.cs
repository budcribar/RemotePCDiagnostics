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

// The remote session is set up by RemoteBlazorWebView's source generator: [RemoteBlazor] generates InitializeRemoteBlazor(), which
// sets the server, the session id, mirrors and voice, opens the app's own page in this window as the owner (shared control), and
// restarts the app on the same session when a browser asks for it, including when this window is not responding.
[RemoteBlazor(nameof(RemoteBlazorWebView), ShareControl = true, RestartOnRefresh = true)]
public partial class MainWindow : Window
{
    private static readonly ILogger Logger = HostServices.For<MainWindow>(App.Loggers);
    private const string HostPage = @"wwwroot\index.html";
    private readonly ServiceProvider _provider;
    private readonly string? _group;
    private Uri? _serverUri;
    private Uri? _remoteUserUrl;
    private DispatcherTimer? _readyTimer;
    private readonly SessionAudit _audit = new(App.Audit);
    public MainWindow()
    {
        // Keep the UI dispatcher above Normal and BelowNormal stressor threads so progress renders and Stop clicks stay responsive under full load.
        try { Thread.CurrentThread.Priority = ThreadPriority.AboveNormal; } catch { }

        // Local (default) or Remote. Remote when started with -u=<server uri> (RemoteBlazorWebViewTutorial convention)
        // or REMOTEPC_MODE=Remote (+ optional REMOTEPC_SERVER_URL, default https://remoteblazorwebview.com:34544).
        // See Properties/launchSettings.json for the Visual Studio profiles: "Remote" (default), "Remote + voice" and "Local". A remote session is shared: the app shows in this window and control moves between the user and the remote user.
        var pendingReboot = RebootResumeCoordinator.TryReadPendingStateFile();
        var launch = SessionLaunchOptions.Resolve(Environment.GetCommandLineArgs().Skip(1), Environment.GetEnvironmentVariable, pendingReboot);
        var mode = launch.Mode;
        _group = launch.Group;

        var sessionCtx = new SessionContext(mode, launch.ServerUri, launch.Id, launch.Unattended, launch.Voice, launch.Group);
        var services = new ServiceCollection().AddRemotePCDiagnosticsHost(sessionCtx, App.Log, App.Event, loggers: App.Loggers);
        var provider = _provider = services.BuildServiceProvider();
        provider.GetService<DesktopSessionRelauncher>()?.BindWindowClose(() => Dispatcher.BeginInvoke(Close));
        Resources.Add("services", provider);
        Closed += (_, _) => { try { provider.GetService<IEcFanSource>()?.Dispose(); } catch { } }; // release the PawnIO EC module handle
        provider.GetRequiredService<ChecksScreenState>(); // start tracking results (run mode labels, last completed) from launch
        // One Windows Event Log entry per finished test (every module and run path), see ResultEventLogger.
        var diag = provider.GetRequiredService<DiagnosticsService>();
        var eventContext = new RemotePCDiagnostics.Core.Logging.ResultEventContext(
            n => diag.Catalog.DisplayName(n),
            () => _machine.Value, RemotePCDiagnostics.Core.AppBuildInfo.Version,
            n => RemotePCDiagnostics.Core.History.HistoryIds.For(n, diag.Catalog));
        _ = new RemotePCDiagnostics.Core.Logging.ResultEventLogger(provider.GetRequiredService<ResultStore>(), App.Events, _ => diag.CurrentSuiteLabel, context: eventContext);
        _ = Task.Run(() => App.Event(RemotePCDiagnostics.Core.Logging.LogEventIds.AppStart, RemotePCDiagnostics.Core.Logging.LogLevel.Information, AppStartText(mode.ToString())));
        // Tell the person at this PC when a remote user starts/stops/restarts a service (non-blocking).
        provider.GetRequiredService<ServiceActionService>().ActionCompleted += rec =>
        {

            _ = Task.Run(() => App.Event(RemotePCDiagnostics.Core.Logging.LogEventIds.TestResult, rec.Success ? RemotePCDiagnostics.Core.Logging.LogLevel.Information : RemotePCDiagnostics.Core.Logging.LogLevel.Warning, RemotePCDiagnostics.Core.History.HistorySummary.FormatServiceEvent(rec, _machine.Value, eventContext.AppVersion)));
            if (rec.Actor == ServiceActor.Remote) Dispatcher.BeginInvoke(() => MessageBox.Show(this, $"A remote user used the Services page: {rec.Message.TrimEnd('.')}.", "Remote PC Diagnostics", MessageBoxButton.OK, MessageBoxImage.Information));
        };
        provider.GetRequiredService<RemediationService>().ActionCompleted += rec =>
        {

            _ = Task.Run(() => App.Event(RemotePCDiagnostics.Core.Logging.LogEventIds.TestResult, rec.Success ? RemotePCDiagnostics.Core.Logging.LogLevel.Information : RemotePCDiagnostics.Core.Logging.LogLevel.Warning, RemotePCDiagnostics.Core.History.HistorySummary.FormatRemediationEvent(rec, _machine.Value, eventContext.AppVersion)));
            if (rec.Actor == ServiceActor.Remote) Dispatcher.BeginInvoke(() => MessageBox.Show(this, $"A remote user ran an automated fix: {rec.Message.TrimEnd('.')}.", "Remote PC Diagnostics", MessageBoxButton.OK, MessageBoxImage.Information));
        };

        // Auto-run the hardware inventory in the background on launch (host side, Local and Remote alike).
        // Results flow through ResultStore to the Dashboard / Hardware inventory page. Disable with REMOTEPC_AUTORUN=0.
        AutoRun.Start(provider.GetRequiredService<DiagnosticsService>(), Environment.GetEnvironmentVariable, App.Loggers.CreateLogger(typeof(AutoRun).FullName!), ModuleSlugs.Osquery, LibreHardwareMonitorModule.ModuleName, ModuleSlugs.DriveHealth);


        _ = Task.Run(async () => { try { await provider.GetRequiredService<RebootResumeCoordinator>().CompletePostRebootIfPendingAsync(provider.GetRequiredService<RemediationService>(), provider.GetRequiredService<DiagnosticsService>()); } catch (Exception ex) { Logger.Warn($"Post-reboot check failed: {ex.Message}"); } });

        // A service workflow waiting for this restart carries on by itself.
        _ = Task.Run(async () => { try { await provider.GetRequiredService<RemotePCDiagnostics.Core.Workflow.WorkflowService>().ResumeAsync(); } catch (Exception ex) { Logger.Warn($"Workflow resume failed: {ex.Message}"); } });
        // An "after" benchmark requested before a restart runs by itself once start-up has settled.
        _ = Task.Run(async () => { try { await provider.GetRequiredService<RemotePCDiagnostics.Core.Benchmarks.BenchmarkService>().ResumeAfterRestartAsync(); } catch (Exception ex) { Logger.Warn($"Benchmark resume failed: {ex.Message}"); } });

        InitializeComponent();
        Logger.Info($"MainWindow initialized, mode={mode} server={launch.ServerUri} group={launch.Group}");

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
            Logger.Info($"BlazorWebViewInitializing args='{extra}'");
        };
        RemoteBlazorWebView.BlazorWebViewInitialized += (_, e) =>
        {
            Logger.Info($"BlazorWebViewInitialized browserVersion={e.WebView.CoreWebView2?.Environment.BrowserVersionString}");
            // Remote: this window shows the relay's page for the session. Reloading it (F5, Ctrl+R) makes the relay treat the
            // session as refreshed, which restarts the app. Nothing here needs a reload, so ignore it; find, zoom and the
            // other browser keys keep working.
            if (e.WebView.CoreWebView2 is { } core)
                core.NavigationStarting += (_, n) =>
                {
                    if (_serverUri is null || n.NavigationKind != Microsoft.Web.WebView2.Core.CoreWebView2NavigationKind.Reload) return;
                    n.Cancel = true;
                    Logger.Info("Ignored a page reload in the remote session window");
                };
        };

        // Local when there is no server. The values come from SessionLaunchOptions (command line, environment, saved reboot state),
        // so they are handed to the generated code instead of letting it read the command line itself.
        bool remote;
        try
        {
            // Group MUST be set before InitializeRemoteBlazor / HostPage (setting Group after HostPage throws ArgumentException).
            if (launch.Mode == SessionMode.Remote && !string.IsNullOrWhiteSpace(launch.Group))
                RemoteBlazorWebView.Group = launch.Group;

            remote = InitializeRemoteBlazor(new RemoteBlazorStartup
            {
                ServerUri = launch.ServerUri,
                Id = sessionCtx.SessionId, // Guid.Empty in Local; in Remote a fixed id (-i=<guid>, REMOTEPC_ID) or a new one
                Unattended = launch.Unattended,
                Voice = launch.Voice,
                // The copy started on a restart: same server, session, and shop group, same unattended/voice, marked --restarted so it waits
                // for this copy to exit. Called on the UI thread, or on a background thread when this window is not responding.
                RestartArguments = (server, id) =>
                {
                    Logger.Info($"Restart requested from a browser: starting a new copy for session {id} (group={launch.Group}); this one closes");
                    return SessionLaunchOptions.RestartArguments(server, id, launch.Unattended, launch.Voice, launch.Group);
                },
            });
        }
        catch (Exception ex)
        {
            Logger.Error($"Remote start failed: {ex}");
            _serverUri = launch.ServerUri;
            provider.GetService<RemoteSessionHealth>()?.ReportFailure(RemoteSessionState.Unreachable, ex.Message);
            SetRemoteState(RemoteSessionState.Unreachable, ex.Message);
            return;
        }
        if (remote) WatchRemoteSession(launch.ServerUri!, sessionCtx.SessionId, launch.Unattended);
        // Last: setting HostPage starts the control, and the server, group and id must be set before it (which is why it is not in the XAML).
        RemoteBlazorWebView.HostPage = HostPage;
    }

    /// <summary>
    /// What this app adds around the generated remote setup: the session id for the rest of the app, the log, the "can't reach
    /// the relay" notice, and the admin site's client card. Call after InitializeRemoteBlazor() and before HostPage is set.
    /// </summary>
    private void WatchRemoteSession(Uri serverUri, Guid id, bool unattended)
    {
        _serverUri = serverUri;
        // Status, give/take control, Copy link and Restart are in the app's header (RemoteBlazorWebView's session bar), in this
        // window and in the remote user's browser.
        SetRemoteState(RemoteSessionState.Connecting);

        RemoteBlazorWebView.ReadyToConnect += (_, e) => Dispatcher.BeginInvoke(() =>
        {
            _readyTimer?.Stop();
            if (_provider.GetService<ISessionContext>() is SessionContext sc && e.Id != Guid.Empty) sc.SessionId = e.Id;
            // The link to share is the read-only /mirror page: this window holds the app's own page, and the remote user is
            // handed control from the session bar.
            _remoteUserUrl = RemoteLinkInfo.BuildMirrorUrl(e.Url ?? serverUri, e.Id != Guid.Empty ? e.Id : id);
            Logger.Info($"ReadyToConnect url={e.Url} id={e.Id} link={_remoteUserUrl}");
            _provider.GetService<RemoteSessionHealth>()?.ReportReady();
            SetRemoteState(RemoteSessionState.Ready);
            _audit.Started(unattended);
        });
        // The audit trail (the app's own event log): who joined, each time control moved, who left. Consent is the person at
        // this PC sharing the link and giving control (supervised), or the unattended setting chosen when it was set up.
        RemoteBlazorWebView.ParticipantsChanged += (_, e) =>
        {
            _audit.Update([.. e.Participants.Select(p => new SessionParticipant(p.ClientId, p.IsOwner, p.HasControl, p.UserName))]);
            _provider.GetService<RemoteUsers>()?.Set(e.Participants.Count(p => !p.IsOwner)); // the top bar's badge
        };
        RemoteBlazorWebView.Connected += (_, e) => Dispatcher.BeginInvoke(() =>
        {
            Logger.Info($"Remote Connected id={e.Id} ip={e.IpAddress} user={e.User}");
            _provider.GetService<RemoteSessionHealth>()?.ReportConnected();
            SetRemoteState(RemoteSessionState.RemoteUserConnected);
        });
        RemoteBlazorWebView.Disconnected += (_, e) => Dispatcher.BeginInvoke(() =>
        {
            Logger.Info($"Remote Disconnected id={e.Id} url={e.Url} error={e.Exception}");
            _audit.Ended(e.Exception?.Message ?? "");
            _provider.GetService<RemoteUsers>()?.Set(0);
            var nextState = _remoteUserUrl is null ? RemoteSessionState.Unreachable : RemoteSessionState.Disconnected;
            _provider.GetService<RemoteSessionHealth>()?.ReportFailure(nextState, e.Exception?.Message);
            SetRemoteState(nextState, e.Exception?.Message);
        });

        _readyTimer = new DispatcherTimer { Interval = RemoteLinkInfo.ReadyTimeout };
        _readyTimer.Tick += (_, _) =>
        {
            _readyTimer.Stop();
            if (_remoteUserUrl is null)
            {
                Logger.Warn($"No ReadyToConnect after {RemoteLinkInfo.ReadyTimeout.TotalSeconds}s (server={serverUri})");
                _provider.GetService<RemoteSessionHealth>()?.ReportFailure(RemoteSessionState.Unreachable, null);
                SetRemoteState(RemoteSessionState.Unreachable);
            }
        };

        // The admin Clients list renders each client's own card markup. This window holds /app, so point that card at the
        // read-only /mirror page (set Markup before HostPage; the library keeps a non-empty Markup as given).
        try { RemoteBlazorWebView.Markup = RemoteLinkInfo.ToMirrorMarkup(RemoteWebView.GenMarkup(serverUri, id)); }
        catch (Exception ex) { Logger.Error($"Client card markup failed: {ex}"); }
        _readyTimer.Start();
    }

    private void SetRemoteState(RemoteSessionState state, string? errorDetail = null)
    {
        if (_serverUri is null) return;
        Logger.Info($"Remote session state: {state}");
        // Once the app's page is up its header carries the status. Before that, the one thing to say here is that the
        // relay can't be reached (a later ReadyToConnect replaces this page).
        if (!RemoteLinkInfo.IsWarning(state)) return;
        if (!string.IsNullOrWhiteSpace(_group) && state == RemoteSessionState.Unreachable)
        {
            var issue = RemoteSessionHealth.ClassifyError(errorDetail, state);
            try { RemoteBlazorWebView.NavigateToString(RemoteSessionHealth.BuildShopRelayDeniedHtml(_serverUri, _group, issue)); }
            catch (Exception ex) { Logger.Error($"Showing the shop relay notice failed: {ex}"); }

            // Disambiguate generic client CreateFailed errors into GroupInactive (404) vs SessionLimitReached (active shop).
            if (issue is RemoteRelayIssueKind.CreateFailedOrDenied or RemoteRelayIssueKind.RelayUnreachable
                && _provider.GetService<RemotePCDiagnostics.Core.Workflow.ShopRelayClient>() is { } relayClient)
            {
                var uri = _serverUri;
                var grp = _group;
                _ = Task.Run(async () =>
                {
                    try
                    {
                        var brandingResult = await relayClient.FetchBrandingAsync(uri, grp).ConfigureAwait(false);
                        var refined = brandingResult switch
                        {
                            RemotePCDiagnostics.Core.Workflow.ShopRelayBrandingResult.NotFoundOrInactive => RemoteRelayIssueKind.GroupInactive,
                            RemotePCDiagnostics.Core.Workflow.ShopRelayBrandingResult.Found when issue == RemoteRelayIssueKind.CreateFailedOrDenied => RemoteRelayIssueKind.SessionLimitReached,
                            _ => issue,
                        };
                        if (refined == issue || _remoteUserUrl is not null) return;
                        _provider.GetService<RemoteSessionHealth>()?.ReportFailure(state, refined == RemoteRelayIssueKind.GroupInactive ? "group_inactive" : "session_limit_reached");
                        _ = Dispatcher.BeginInvoke(() =>
                        {
                            if (_remoteUserUrl is not null) return;
                            try { RemoteBlazorWebView.NavigateToString(RemoteSessionHealth.BuildShopRelayDeniedHtml(uri, grp, refined)); }
                            catch { }
                        });
                    }
                    catch { }
                });
            }
            return;
        }
        try { RemoteBlazorWebView.NavigateToString(RemoteLinkInfo.UnreachableHtml(_serverUri)); }
        catch (Exception ex) { Logger.Error($"Showing the unreachable notice failed: {ex}"); }
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
        _audit.Ended("The app was closed");
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
        catch (Exception ex) { Logger.Warn($"Shutdown cleanup failed: {ex.Message}"); }
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
