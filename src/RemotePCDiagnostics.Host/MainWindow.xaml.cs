using System.Diagnostics;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Extensions.DependencyInjection;
using PeakSWC.RemoteBlazorWebView;
using PeakSWC.RemoteWebView;
using RemotePCDiagnostics.Agent.Core;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Security;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Stress;

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
    /// <summary>What this window last wrote to the active session file (Remote, once the relay assigned the id).</summary>
    private volatile ActiveSessionInfo? _activeSession;
    private readonly SystemAwake _awake = new();
    public MainWindow()
    {
        StartupProfiler.Mark("MainWindow.ctor:Start");
        // Keep the UI dispatcher above Normal and BelowNormal stressor threads so progress renders and Stop clicks stay responsive under full load.
        try { Thread.CurrentThread.Priority = ThreadPriority.AboveNormal; } catch { }

        // Local (default) or Remote. Remote when started with -u=<server uri> (RemoteBlazorWebViewTutorial convention)
        // or REMOTEPC_MODE=Remote (+ optional REMOTEPC_SERVER_URL, default https://remoteblazorwebview.com:34544).
        // See Properties/launchSettings.json for the Visual Studio profiles: "Remote Admin" (default), "Remote Admin + voice", "Remote Admin (unattended)", "Local Admin", and "Local User". A remote session is shared: the app shows in this window and control moves between the user and the remote user.
        var pendingReboot = RebootResumeCoordinator.TryReadPendingStateFile();
        var launch = SessionLaunchOptions.Resolve(Environment.GetCommandLineArgs().Skip(1), Environment.GetEnvironmentVariable, pendingReboot);
        var mode = launch.Mode;
        _group = launch.Group;
        // --no-window: a remote session that runs with its window hidden (copies started again under the session inherit it).
        StartsHidden = NoWindowStart.Applies(Environment.GetCommandLineArgs().Skip(1), Environment.GetEnvironmentVariable, mode);
        if (StartsHidden) Environment.SetEnvironmentVariable(NoWindowStart.Variable, "1");
        else if (NoWindowStart.Requested(Environment.GetCommandLineArgs().Skip(1), Environment.GetEnvironmentVariable))
        {
            Logger.Info("No-window start ignored: only a remote session can run without a window.");
            Environment.SetEnvironmentVariable(NoWindowStart.Variable, null);
        }
        // A copy started to reconnect carries on from the previous one (when it began, how many tries). Read it once and take it
        // out of this process's environment, so other copies this one starts (a restart from a browser, Local Mode) begin afresh.
        if (mode == SessionMode.Remote)
            _reconnect = ReconnectCarry.FromEnvironment(Environment.GetEnvironmentVariable, DateTimeOffset.UtcNow);
        Environment.SetEnvironmentVariable(ReconnectCarry.SinceEnvVar, null);
        Environment.SetEnvironmentVariable(ReconnectCarry.AttemptEnvVar, null);
        // The Agent gives the copy it starts its admin pipe on the command line. Copies this one starts again under the same
        // session (a reconnect, a restart from a browser) inherit it through the environment, so they reach the Agent's pipe
        // (which follows them) instead of starting an elevated helper of their own with a UAC prompt nobody may be there to answer.
        if (ElevationService.TryResolveInitialPipeName() is { } agentPipe)
            Environment.SetEnvironmentVariable(ElevationService.AdminPipeEnvVar, agentPipe);

        var sessionCtx = new SessionContext(mode, launch.ServerUri, launch.Id, launch.Unattended, launch.Voice, launch.Group, launch.Admin);
        ActiveSessionInfo.TryWrite(new ActiveSessionInfo(
            Process.GetCurrentProcess().Id,
            Running: true,
            SessionId: sessionCtx.Mode == SessionMode.Remote ? sessionCtx.SessionId.ToString() : null,
            Group: launch.Group,
            Mode: launch.Mode.ToString(),
            StartedUtc: DateTimeOffset.UtcNow,
            Unattended: launch.Unattended,
            Voice: launch.Voice,
            Admin: launch.Admin));
        StartupProfiler.Mark("AddRemotePCDiagnosticsHost:Start");
        var services = new ServiceCollection().AddRemotePCDiagnosticsHost(sessionCtx, App.Log, App.Event, loggers: App.Loggers);
        StartupProfiler.Mark("AddRemotePCDiagnosticsHost:Done");
        var provider = _provider = services.BuildServiceProvider();
        StartupProfiler.Mark("BuildServiceProvider:Done");
        var diag = provider.GetRequiredService<DiagnosticsService>();
        provider.GetService<DesktopSessionRelauncher>()?.BindWindowClose(() => Dispatcher.BeginInvoke(Close));
        var elevation = provider.GetService<ElevationService>();
        if (elevation is not null)
        {
            void OnElevationChanged()
            {
                if (elevation.IsAdminHelperConnected)
                {
                    // Admin-only setup (state folder, Event Log source, history updates) first, then the workflow, benchmark and check
                    // settings the Agent keeps in that folder: an app started before the Agent connected read nothing, so read it now and carry on.
                    _ = Task.Run(async () =>
                    {
                        await App.PrepareMachineThroughAgentAsync(elevation).ConfigureAwait(false);
                        // Side by side: either can run for a while once it resumes.
                        await Task.WhenAll(Task.Run(async () =>
                        {
                            try
                            {
                                var workflow = provider.GetRequiredService<RemotePCDiagnostics.Core.Workflow.WorkflowService>();
                                if (workflow.Reload()) await workflow.ResumeAsync().ConfigureAwait(false);
                            }
                            catch (Exception ex) { Logger.Warn($"Workflow resume after the Agent connected failed: {ex.Message}"); }
                        }), Task.Run(async () =>
                        {
                            try
                            {
                                var benchmarks = provider.GetRequiredService<RemotePCDiagnostics.Core.Benchmarks.BenchmarkService>();
                                if (benchmarks.Reload()) await benchmarks.ResumeAfterRestartAsync().ConfigureAwait(false);
                            }
                            catch (Exception ex) { Logger.Warn($"Benchmark state reload through the Agent failed: {ex.Message}"); }
                        }), Task.Run(() =>
                        {
                            try { provider.GetRequiredService<RemotePCDiagnostics.Core.Checks.CheckSettingsService>().Reload(); }
                            catch (Exception ex) { Logger.Warn($"Check settings reload through the Agent failed: {ex.Message}"); }
                        })).ConfigureAwait(false);
                    });
                    if (provider.GetService<ISensorProvider>() is LhmSensorProvider lhm)
                    {
                        lhm.Reset();
                    }
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            // Hardware details first: the Dashboard header needs them, and a read made before the Agent connected failed.
                            await AutoRun.ReadHardwareInventoryAsync(diag, provider.GetRequiredService<ResultStore>(),
                                App.Loggers.CreateLogger(typeof(AutoRun).FullName!), rereadFailed: true).ConfigureAwait(false);
                            // Temperatures wait until someone runs the checks (Bud, Nov 28): only a reading someone already asked for is
                            // read again, now with the Agent's rights.
                            if (provider.GetRequiredService<ResultStore>().Get(LibreHardwareMonitorModule.ModuleName).Status == DiagnosticStatus.NotRun
                                && !diag.IsRunning(LibreHardwareMonitorModule.ModuleName)) return;
                            while (diag.IsRunning(LibreHardwareMonitorModule.ModuleName))
                            {
                                await Task.Delay(250).ConfigureAwait(false);
                            }
                            await diag.RunAsync(LibreHardwareMonitorModule.ModuleName).ConfigureAwait(false);
                        }
                        catch (Exception ex)
                        {
                            Logger.Warn($"Sensors refresh on elevation failed: {ex.Message}");
                        }
                    });
                }
            }
            elevation.Changed += OnElevationChanged;
            if (elevation.IsAdminHelperConnected) OnElevationChanged(); // connected before this subscribed
        }
        Resources.Add("services", provider);
        var fullscreenService = provider.GetService<IFullscreenService>();
        if (fullscreenService is not null)
        {
            _screens = provider.GetService<RemotePCDiagnostics.Core.Display.IScreenControl>() as WindowsScreenControl;
            fullscreenService.FullscreenChanged += enable =>
            {
                var target = fullscreenService.ScreenId;
                Dispatcher.BeginInvoke(() => SetFullscreen(enable, target));
            };
        }
        Closed += (_, _) => { try { provider.GetService<IEcFanSource>()?.Dispose(); } catch { } }; // release the PawnIO EC module handle
        provider.GetRequiredService<ChecksScreenState>(); // start tracking results (run mode labels, last completed) from launch
        // One Windows Event Log entry per finished test (every module and run path), see ResultEventLogger.
        var eventContext = new RemotePCDiagnostics.Core.Logging.ResultEventContext(
            n => diag.Catalog.DisplayName(n),
            () => _machine.Value, RemotePCDiagnostics.Core.AppBuildInfo.Version,
            n => RemotePCDiagnostics.Core.History.HistoryIds.For(n, diag.Catalog));
        _ = new RemotePCDiagnostics.Core.Logging.ResultEventLogger(provider.GetRequiredService<ResultStore>(), App.Events, _ => diag.CurrentSuiteLabel, context: eventContext);
        _ = Task.Run(() => App.Event(RemotePCDiagnostics.Core.Logging.LogEventIds.AppStart, RemotePCDiagnostics.Core.Logging.LogLevel.Information, AppStartText(mode.ToString())));
        // Log when a remote user starts/stops/restarts a service or runs an automated fix (no modal MessageBox that could stack on an unattended PC).
        provider.GetRequiredService<ServiceActionService>().ActionCompleted += rec =>
        {
            _ = Task.Run(() => App.Event(RemotePCDiagnostics.Core.Logging.LogEventIds.TestResult, rec.Success ? RemotePCDiagnostics.Core.Logging.LogLevel.Information : RemotePCDiagnostics.Core.Logging.LogLevel.Warning, RemotePCDiagnostics.Core.History.HistorySummary.FormatServiceEvent(rec, _machine.Value, eventContext.AppVersion)));
            if (rec.Actor == ServiceActor.Remote) App.Log($"Remote user used the Services page: {rec.Message.TrimEnd('.')}.");
        };
        provider.GetRequiredService<RemediationService>().ActionCompleted += rec =>
        {
            _ = Task.Run(() => App.Event(RemotePCDiagnostics.Core.Logging.LogEventIds.TestResult, rec.Success ? RemotePCDiagnostics.Core.Logging.LogLevel.Information : RemotePCDiagnostics.Core.Logging.LogLevel.Warning, RemotePCDiagnostics.Core.History.HistorySummary.FormatRemediationEvent(rec, _machine.Value, eventContext.AppVersion)));
            if (rec.Actor == ServiceActor.Remote && !RebootResumeCoordinator.IsPostRebootComparison(rec)) App.Log($"Remote user ran an automated fix: {rec.Message.TrimEnd('.')}.");
        };

        // The hardware inventory is the exception: the Dashboard header (model, processor, memory) shows it, so read it right away
        // instead of leaving the header on "Querying hardware…" until someone runs the checks.
        // It goes through the Agent, so it waits for the Agent's pipe (up to 30 s) instead of failing before it is up.
        // The Store edition may have no Agent at all: then it reads without one at once.
#if RPCD_STORE
        Func<bool>? noAgent = AgentShopPillState.NoAgent(provider);
#else
        Func<bool>? noAgent = null;
#endif
        _ = AutoRun.ReadHardwareInventoryAsync(diag, provider.GetRequiredService<ResultStore>(), App.Loggers.CreateLogger(typeof(AutoRun).FullName!),
            elevation is null ? null : () => elevation.IsAdminHelperConnected, noAgent, TimeSpan.FromSeconds(30));

        // Checks don't run by themselves on launch: they run when the person, a remote user or an AI agent asks. REMOTEPC_AUTORUN=1
        // brings back the old launch-time run (development and demos); StartEnabledChecksAsync returns at once when it is off.
        if (StartupOptimizations.DeferAutoRun)
        {
            _ = Task.Run(async () =>
            {
                await Task.Delay(2000).ConfigureAwait(false);
                await AutoRun.StartEnabledChecksAsync(
                    provider.GetRequiredService<DiagnosticsService>(),
                    provider.GetService<RemotePCDiagnostics.Core.Checks.CheckSettingsService>(),
                    Environment.GetEnvironmentVariable,
                    App.Loggers.CreateLogger(typeof(AutoRun).FullName!),
                    slowChecksDelay: TimeSpan.FromSeconds(15)).ConfigureAwait(false);
            });
        }
        else
        {
            _ = AutoRun.StartEnabledChecksAsync(
                provider.GetRequiredService<DiagnosticsService>(),
                provider.GetService<RemotePCDiagnostics.Core.Checks.CheckSettingsService>(),
                Environment.GetEnvironmentVariable,
                App.Loggers.CreateLogger(typeof(AutoRun).FullName!),
                slowChecksDelay: TimeSpan.FromSeconds(15));
        }
        StartupProfiler.Mark("AutoRunDispatched");

        if (StartupOptimizations.DeferResumes)
        {
            _ = Task.Run(async () =>
            {
                await Task.Delay(2500).ConfigureAwait(false);
                try { await provider.GetRequiredService<RebootResumeCoordinator>().CompletePostRebootIfPendingAsync(provider.GetRequiredService<RemediationService>(), provider.GetRequiredService<DiagnosticsService>()); } catch (Exception ex) { Logger.Warn($"Post-reboot check failed: {ex.Message}"); }
                try { await provider.GetRequiredService<RemotePCDiagnostics.Core.Workflow.WorkflowService>().ResumeAsync(); } catch (Exception ex) { Logger.Warn($"Workflow resume failed: {ex.Message}"); }
                try { await provider.GetRequiredService<RemotePCDiagnostics.Core.Benchmarks.BenchmarkService>().ResumeAfterRestartAsync(); } catch (Exception ex) { Logger.Warn($"Benchmark resume failed: {ex.Message}"); }
            });
        }
        else
        {
            _ = Task.Run(async () => { try { await provider.GetRequiredService<RebootResumeCoordinator>().CompletePostRebootIfPendingAsync(provider.GetRequiredService<RemediationService>(), provider.GetRequiredService<DiagnosticsService>()); } catch (Exception ex) { Logger.Warn($"Post-reboot check failed: {ex.Message}"); } });
            _ = Task.Run(async () => { try { await provider.GetRequiredService<RemotePCDiagnostics.Core.Workflow.WorkflowService>().ResumeAsync(); } catch (Exception ex) { Logger.Warn($"Workflow resume failed: {ex.Message}"); } });
            _ = Task.Run(async () => { try { await provider.GetRequiredService<RemotePCDiagnostics.Core.Benchmarks.BenchmarkService>().ResumeAfterRestartAsync(); } catch (Exception ex) { Logger.Warn($"Benchmark resume failed: {ex.Message}"); } });
        }

        InitializeComponent();
        Logger.Info($"MainWindow initialized, mode={mode} server={launch.ServerUri} group={launch.Group}");

        // CI/diagnostics: pass WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS (e.g. --remote-debugging-port=9222) explicitly
        // and log WebView2 startup so failures show up in host.log.
        RemoteBlazorWebView.BlazorWebViewInitializing += (_, e) =>
        {
            var extra = Environment.GetEnvironmentVariable("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS");
            if (StartupOptimizations.WebViewFlags)
            {
                var perfFlags = "--disable-features=Translate,OptimizationHints,MediaRouter,CalculateNativeWinOcclusion --disable-background-networking --disable-component-update";
                extra = string.IsNullOrWhiteSpace(extra) ? perfFlags : $"{extra} {perfFlags}";
            }
            if (!string.IsNullOrWhiteSpace(extra))
            {
                e.EnvironmentOptions ??= new Microsoft.Web.WebView2.Core.CoreWebView2EnvironmentOptions();
                e.EnvironmentOptions.AdditionalBrowserArguments = extra;
            }
            Logger.Info($"BlazorWebViewInitializing args='{extra}'");
            StartupProfiler.Mark("BlazorWebViewInitializing");
        };
        RemoteBlazorWebView.BlazorWebViewInitialized += (_, e) =>
        {
            StartupProfiler.Mark("BlazorWebViewInitialized");
            if (_hideWhenReady) Dispatcher.BeginInvoke(HideForNoWindow);
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
                // Unattended sessions give the remote user control as soon as they join. A copy restarted while the remote user had
                // control (--give-control) does the same, so the technician who pressed Restart gets control back when their page
                // rejoins; the session stays supervised otherwise (the audit and the session info still say so).
                Unattended = launch.Unattended || launch.GiveControl,
                Voice = launch.Voice,
                // The copy started on a restart: same server, session, and shop group, same unattended/voice, marked --restarted so it waits
                // for this copy to exit. Called on the UI thread, or on a background thread when this window is not responding.
                RestartArguments = (server, id) =>
                {
                    var giveControl = _audit.RemoteUserHadControl;
                    Logger.Info($"Restart requested from a browser: starting a new copy for session {id} (group={launch.Group}, remoteHadControl={giveControl}); this one closes");
                    return SessionLaunchOptions.RestartArguments(server, id, launch.Unattended, launch.Voice, launch.Group, launch.Admin, giveControl);
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
        StartupProfiler.Mark("HostPageAssigned");
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
            StopReconnectTimer();
            _reconnect = null;
            HideNativeFallbackCard();
            if (_provider.GetService<ISessionContext>() is SessionContext sc && e.Id != Guid.Empty)
            {
                sc.SessionId = e.Id;
                sc.RemoteControlSource = () => _audit.RemoteUserHadControl;
                _activeSession = new ActiveSessionInfo(
                    Process.GetCurrentProcess().Id,
                    Running: true,
                    SessionId: e.Id.ToString(),
                    Group: _group,
                    Mode: SessionMode.Remote.ToString(),
                    StartedUtc: DateTimeOffset.UtcNow,
                    Unattended: sc.Unattended,
                    Voice: sc.Voice,
                    Admin: sc.Admin,
                    RemoteControl: _audit.RemoteUserHasControl,
                    RemoteLeftInControlUtc: _audit.RemoteLeftInControlUtc);
                ActiveSessionInfo.TryWrite(_activeSession);
            }
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
            // The Agent reads who has control from the session file when Admin starts an update, so the relaunched app hands
            // control back to the technician.
            if (_activeSession is { } active)
            {
                var updated = active with { RemoteControl = _audit.RemoteUserHasControl, RemoteLeftInControlUtc = _audit.RemoteLeftInControlUtc };
                if (updated != active && ActiveSessionInfo.TryWrite(updated)) _activeSession = updated;
            }
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
            // A copy started to reconnect that can't reach the relay yet is still reconnecting, not a session that never started.
            var nextState = _remoteUserUrl is null && _reconnect is null ? RemoteSessionState.Unreachable : RemoteSessionState.Disconnected;
            _provider.GetService<RemoteSessionHealth>()?.ReportFailure(nextState, e.Exception?.Message);
            SetRemoteState(nextState, e.Exception?.Message);
            if (nextState == RemoteSessionState.Disconnected)
            {
                StartAutoReconnect();
            }
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

    private UIElement? _fallbackCard;
    private DispatcherTimer? _reconnectTimer;
    private ReconnectCarry? _reconnect;
    private int _reconnectCountdownSeconds;
    private bool _isAutoReconnecting;
    private System.Windows.Controls.TextBlock? _reconnectCountdownTextBlock;
    private static readonly System.Net.Http.HttpClient RelayProbe = new() { Timeout = TimeSpan.FromSeconds(5) };

    private void StopReconnectTimer()
    {
        _reconnectTimer?.Stop();
        _reconnectTimer = null;
        _isAutoReconnecting = false;
        if (_reconnectCountdownTextBlock is not null)
            _reconnectCountdownTextBlock.Text = string.Empty;
    }

    private void StartAutoReconnect()
    {
        if (_isAutoReconnecting) return; // a startup failure and the Disconnected event that follows it both get here
        StopReconnectTimer();
        _reconnect ??= ReconnectCarry.Start(DateTimeOffset.UtcNow);
        ScheduleNextReconnect();
    }

    /// <summary>
    /// Waits, then starts a new copy under the same session id once the relay answers. While the relay can't be reached (Wi-Fi
    /// still off after a wake, a relay redeploy, the relay still holding the old connection) this copy keeps waiting, longer
    /// each time, rather than handing over to a copy that would fail too. It gives up after <see cref="ReconnectCarry.Window"/>.
    /// </summary>
    private void ScheduleNextReconnect()
    {
        var reconnect = _reconnect ??= ReconnectCarry.Start(DateTimeOffset.UtcNow);
        if (reconnect.Expired(DateTimeOffset.UtcNow))
        {
            Logger.Warn($"Auto-reconnect gave up after {ReconnectCarry.Window.TotalMinutes:0} minutes ({reconnect.Attempt} tries). Releasing active session.");
            _isAutoReconnecting = false;
            ActiveSessionInfo.TryDelete(expectedProcessId: Environment.ProcessId);
            if (_provider.GetService<ISessionContext>()?.Unattended == true)
            {
                Logger.Info("Unattended session could not reconnect to relay; closing window cleanly.");
                Close();
                return;
            }
            if (_reconnectCountdownTextBlock is not null)
            {
                _reconnectCountdownTextBlock.Text = "Could not reconnect automatically. Click Reconnect to retry, or switch to Local Mode.";
            }
            return;
        }

        _isAutoReconnecting = true;
        var delay = reconnect.NextDelay();
        _reconnectCountdownSeconds = (int)Math.Ceiling(delay.TotalSeconds);
        Logger.Info($"Scheduling auto-reconnect try {reconnect.Attempt + 1} in {_reconnectCountdownSeconds}s (reconnecting since {reconnect.Since:O}).");

        UpdateReconnectCountdownText();

        _reconnectTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _reconnectTimer.Tick += (_, _) =>
        {
            _reconnectCountdownSeconds--;
            UpdateReconnectCountdownText();
            if (_reconnectCountdownSeconds <= 0)
            {
                _reconnectTimer.Stop();
                _ = ReconnectWhenRelayAnswersAsync();
            }
        };
        _reconnectTimer.Start();
    }

    private async Task ReconnectWhenRelayAnswersAsync()
    {
        var reconnect = (_reconnect ?? ReconnectCarry.Start(DateTimeOffset.UtcNow)).Next();
        _reconnect = reconnect;
        if (_serverUri is not null && !await RelayAnswersAsync(_serverUri).ConfigureAwait(true))
        {
            Logger.Info($"Auto-reconnect try {reconnect.Attempt}: relay {RemoteLinkInfo.HostAndPort(_serverUri)} not reachable yet; waiting.");
            if (_isAutoReconnecting) ScheduleNextReconnect();
            return;
        }
        if (!_isAutoReconnecting) return; // stopped (Exit, Local Mode, a manual retry) while the relay was being checked
        Logger.Info($"Executing auto-reconnect try {reconnect.Attempt} under current session id.");
        RelaunchSelf(keepRemoteArgs: true, reconnect);
    }

    /// <summary>True when the relay answers HTTP at all (any status): the network is back and the relay is up.</summary>
    private static async Task<bool> RelayAnswersAsync(Uri serverUri)
    {
        try
        {
            using var response = await RelayProbe.GetAsync(serverUri, System.Net.Http.HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
            return true;
        }
        catch (Exception ex)
        {
            Logger.Info($"Relay check failed: {ex.GetType().Name}: {ex.Message}");
            return false;
        }
    }

    private void UpdateReconnectCountdownText()
    {
        if (_reconnectCountdownTextBlock is not null)
        {
            _reconnectCountdownTextBlock.Text = _isAutoReconnecting
                ? _reconnectCountdownSeconds > 0
                    ? $"Reconnecting in {_reconnectCountdownSeconds}s (try {(_reconnect?.Attempt ?? 0) + 1})..."
                    : "Checking the relay..."
                : string.Empty;
        }
    }

    /// <summary>
    /// Handles synchronous exceptions thrown by <c>RemoteWebView.Client()</c> on the WPF UI thread during <c>Loaded</c>
    /// (for example when the relay times out or rejects <c>CreateWebView</c>) so the window stays open with a clear notice.
    /// </summary>
    public bool TryHandleRemoteStartupException(Exception ex)
    {
        if (_serverUri is null || _remoteUserUrl is not null) return false;
        var text = ex.ToString();
        var isRemoteStartup = text.Contains("PeakSWC.RemoteWebView", StringComparison.Ordinal)
            || text.Contains("PeakSWC.RemoteBlazorWebView", StringComparison.Ordinal)
            || text.Contains("Grpc.", StringComparison.Ordinal)
            || text.Contains("Timeout waiting for server to start", StringComparison.OrdinalIgnoreCase)
            || text.Contains("WebView Create failed", StringComparison.OrdinalIgnoreCase);
        if (!isRemoteStartup) return false;

        _readyTimer?.Stop();
        Logger.Error($"Remote startup failed on UI dispatcher: {ex.Message}");
        if (_reconnect is not null)
        {
            // This copy was started to reconnect: keep trying (a relay that is still coming back, or still holds the old connection).
            _provider.GetService<RemoteSessionHealth>()?.ReportFailure(RemoteSessionState.Disconnected, ex.Message);
            SetRemoteState(RemoteSessionState.Disconnected, ex.Message);
            StartAutoReconnect();
            return true;
        }
        _provider.GetService<RemoteSessionHealth>()?.ReportFailure(RemoteSessionState.Unreachable, ex.Message);
        SetRemoteState(RemoteSessionState.Unreachable, ex.Message);
        return true;
    }

    /// <summary>Keeps the PC from sleeping on its idle timer while an unattended session is starting or up (see <see cref="KeepAwakePolicy"/>).</summary>
    private void KeepAwakeFor(RemoteSessionState state)
    {
        try
        {
            var hold = KeepAwakePolicy.ShouldHold(_provider.GetService<ISessionContext>()?.Unattended ?? false, state);
            if (_awake.Set(hold, "Remote PC Diagnostics: an unattended remote session is running"))
                Logger.Info(hold ? "Keeping the PC awake while the unattended session is up" : "No longer keeping the PC awake");
            else if (hold && !_awake.Held)
                Logger.Warn("Couldn't ask Windows to keep the PC awake; it may go to sleep during the unattended session");
        }
        catch (Exception ex) { Logger.Warn($"Keep-awake request failed: {ex.Message}"); }
    }

    private void SetRemoteState(RemoteSessionState state, string? errorDetail = null)
    {
        if (_serverUri is null) return;
        Logger.Info($"Remote session state: {state}");
        KeepAwakeFor(state);
        // Once the app's page is up its header carries the status. Before that, the one thing to say here is that the
        // relay can't be reached (a later ReadyToConnect replaces this page).
        if (!RemoteLinkInfo.IsWarning(state)) return;
        var issue = RemoteSessionHealth.ClassifyError(errorDetail, state);
        if (state == RemoteSessionState.Disconnected)
        {
            ShowNativeFallbackCard(_serverUri, _group, issue);
            return;
        }
        if (!string.IsNullOrWhiteSpace(_group) && state == RemoteSessionState.Unreachable)
        {
            ShowRelayNotice(RemoteSessionHealth.BuildShopRelayDeniedHtml(_serverUri, _group, issue), _serverUri, _group, issue);

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
                            ShowRelayNotice(RemoteSessionHealth.BuildShopRelayDeniedHtml(uri, grp, refined), uri, grp, refined);
                        });
                    }
                    catch { }
                });
            }
            return;
        }
        var defaultHtml = issue != RemoteRelayIssueKind.RelayUnreachable
            ? RemoteSessionHealth.BuildShopRelayDeniedHtml(_serverUri, "default", issue)
            : RemoteLinkInfo.UnreachableHtml(_serverUri);
        ShowRelayNotice(defaultHtml, _serverUri, _group, issue);
    }

    private void ShowRelayNotice(string html, Uri serverUri, string? groupSlug, RemoteRelayIssueKind issue)
    {
        try
        {
            RemoteBlazorWebView.NavigateToString(html);
            return;
        }
        catch (Exception ex)
        {
            Logger.Warn($"WebView notice unavailable ({ex.GetType().Name}); showing native fallback card");
        }
        ShowNativeFallbackCard(serverUri, groupSlug, issue);
    }

    private void HideNativeFallbackCard()
    {
        if (_fallbackCard is null) return;
        RootGrid.Children.Remove(_fallbackCard);
        _fallbackCard = null;
        _reconnectCountdownTextBlock = null;
        RemoteBlazorWebView.Visibility = Visibility.Visible;
    }

    private void ShowNativeFallbackCard(Uri serverUri, string? groupSlug, RemoteRelayIssueKind issue)
    {
        HideNativeFallbackCard();
        var server = RemoteLinkInfo.HostAndPort(serverUri);
        var groupLabel = string.IsNullOrWhiteSpace(groupSlug) ? "default" : groupSlug;
        var (headline, explanation) = issue switch
        {
            RemoteRelayIssueKind.GroupInactive => (
                $"Shop code \"{groupLabel}\" is not active",
                "This repair shop code was not found on the relay or its subscription/trial is currently inactive."),
            RemoteRelayIssueKind.SessionLimitReached => (
                $"Shop \"{groupLabel}\" is at its active session limit",
                "All concurrent remote support slots for this plan are currently in use. Close an idle session or try again shortly."),
            RemoteRelayIssueKind.CreateFailedOrDenied => (
                "Could not start remote session on the relay",
                $"The relay ({server}) declined the session request for group \"{groupLabel}\". Verify the shop code or open in Local Mode."),
            RemoteRelayIssueKind.Disconnected => (
                "Disconnected from relay server",
                $"The connection to relay {server} was lost. Reconnecting automatically with backoff, or click Reconnect to retry now."),
            _ => (
                $"Can't reach relay {server}",
                $"Remote PC Diagnostics could not connect to {server}. Check your internet connection, retry, or open in Local Mode."),
        };

        var stack = new System.Windows.Controls.StackPanel { MaxWidth = 560 };
        stack.Children.Add(new System.Windows.Controls.TextBlock
        {
            Text = headline,
            FontSize = 18,
            FontWeight = FontWeights.SemiBold,
            Foreground = new SolidColorBrush(Color.FromRgb(0xFB, 0xBF, 0x24)),
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 10),
        });
        stack.Children.Add(new System.Windows.Controls.TextBlock
        {
            Text = explanation,
            FontSize = 14,
            Foreground = new SolidColorBrush(Color.FromRgb(0x9F, 0xB0, 0xC0)),
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 14),
        });
        stack.Children.Add(new System.Windows.Controls.TextBlock
        {
            Text = $"Relay: {server}  ·  Group: {groupLabel}",
            FontSize = 12.5,
            Foreground = new SolidColorBrush(Color.FromRgb(0xCB, 0xD5, 0xE1)),
            Margin = new Thickness(0, 0, 0, 18),
        });

        if (issue == RemoteRelayIssueKind.Disconnected)
        {
            _reconnectCountdownTextBlock = new System.Windows.Controls.TextBlock
            {
                FontSize = 13,
                Foreground = new SolidColorBrush(Color.FromRgb(0x60, 0xA5, 0xFA)),
                Margin = new Thickness(0, 0, 0, 14),
                TextWrapping = TextWrapping.Wrap,
            };
            UpdateReconnectCountdownText();
            stack.Children.Add(_reconnectCountdownTextBlock);
        }

        var actions = new System.Windows.Controls.WrapPanel();
        var retryBtn = new System.Windows.Controls.Button
        {
            Content = issue == RemoteRelayIssueKind.Disconnected ? "Reconnect" : "Retry remote session",
            Padding = new Thickness(14, 7, 14, 7),
            Margin = new Thickness(0, 0, 10, 0),
        };
        retryBtn.Click += (_, _) => { StopReconnectTimer(); RelaunchSelf(keepRemoteArgs: true); };

        var localBtn = new System.Windows.Controls.Button
        {
            Content = "Open in Local Mode",
            Padding = new Thickness(14, 7, 14, 7),
            Margin = new Thickness(0, 0, 10, 0),
        };
        localBtn.Click += (_, _) => { StopReconnectTimer(); RelaunchSelf(keepRemoteArgs: false); };

        actions.Children.Add(retryBtn);
        actions.Children.Add(localBtn);

        if (issue == RemoteRelayIssueKind.Disconnected)
        {
            var exitBtn = new System.Windows.Controls.Button
            {
                Content = "Exit",
                Padding = new Thickness(14, 7, 14, 7),
            };
            exitBtn.Click += (_, _) => { StopReconnectTimer(); Close(); };
            actions.Children.Add(exitBtn);
        }

        stack.Children.Add(actions);

        var card = new System.Windows.Controls.Border
        {
            Background = new SolidColorBrush(Color.FromRgb(0x16, 0x1C, 0x23)),
            BorderBrush = new SolidColorBrush(Color.FromRgb(0x3B, 0x2E, 0x14)),
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(10),
            Padding = new Thickness(28, 24, 28, 24),
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(24),
            Child = stack,
        };
        var host = new System.Windows.Controls.Grid
        {
            Background = new SolidColorBrush(Color.FromRgb(0x0F, 0x14, 0x19)),
        };
        host.Children.Add(card);
        System.Windows.Controls.Grid.SetRow(host, 1);
        RemoteBlazorWebView.Visibility = Visibility.Collapsed;
        RootGrid.Children.Add(host);
        _fallbackCard = host;
    }

    private void RelaunchSelf(bool keepRemoteArgs, ReconnectCarry? reconnect = null)
    {
        var exe = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(exe)) return;
        try
        {
            var session = _provider.GetService<ISessionContext>();
            var sessionId = session?.SessionId is { } sid && sid != Guid.Empty ? sid : Guid.NewGuid();
            IReadOnlyList<string> args = keepRemoteArgs && _serverUri is not null
                ? SessionLaunchOptions.RestartArguments(_serverUri, sessionId, session?.Unattended ?? false, session?.Voice ?? false, _group, session?.Admin, _audit.RemoteUserHadControl)
                : ["--restarted"];
            var psi = new ProcessStartInfo(exe) { UseShellExecute = false, WorkingDirectory = AppContext.BaseDirectory };
            foreach (var arg in args) psi.ArgumentList.Add(arg);
            if (reconnect is not null && keepRemoteArgs) reconnect.WriteTo(psi.Environment);
            else ReconnectCarry.ClearIn(psi.Environment);
            // Local Mode is a session of its own: it must not reach for the Agent pipe of the remote session it replaces.
            if (!keepRemoteArgs) psi.Environment.Remove(ElevationService.AdminPipeEnvVar);
            Process.Start(psi);
            Close();
        }
        catch (Exception ex) { Logger.Error($"Relaunch failed: {ex.Message}"); }
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
        _tray?.Dispose();
        try { _awake.Dispose(); } catch { }
        ActiveSessionInfo.TryDelete(expectedProcessId: Environment.ProcessId);
        _readyTimer?.Stop();
        StopReconnectTimer();
        _audit.Ended("The app was closed");

        var cleanupTask = Task.Run(() =>
        {
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
        });

        if (!cleanupTask.Wait(TimeSpan.FromSeconds(2.5)))
        {
            Logger.Warn("Shutdown cleanup timed out after 2.5s; forcing process termination");
        }

        ActiveSessionInfo.TryDelete(expectedProcessId: Environment.ProcessId);
        App.ReleaseInstance();
        Environment.Exit(0);
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

    /// <summary>
    /// Another launch of the app (desktop icon, Start menu) asked this copy to show itself: shows the window if it was hidden, restores it
    /// maximized if it was minimized or in a normal size, and brings it in front of other windows. The launching copy has already allowed
    /// this process to take the foreground; if Windows still refuses focus, a Topmost toggle at least raises the window above the others.
    /// A full-screen window keeps its full-screen layout.
    /// </summary>
    public void BringToFront()
    {
        App.Log($"Second launch: bringing the window to the front (state={WindowState}, visible={IsVisible})");
        if (StartsHidden) ShowAfterNoWindow();
        if (!IsVisible) Show();
        if (!_isFullscreen) WindowState = WindowState.Maximized;
        Activate();
        var hwnd = new System.Windows.Interop.WindowInteropHelper(this).Handle;
        if (hwnd != IntPtr.Zero && !SetForegroundWindow(hwnd))
        {
            Topmost = true;
            Topmost = false;
        }
        Focus();
    }

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    private bool _hideWhenReady;
    private NoWindowTrayIcon? _tray;

    /// <summary>True when this copy started with <c>--no-window</c> in a remote session (see <see cref="NoWindowStart"/>).</summary>
    public bool StartsHidden { get; private set; }

    /// <summary>The longest the window stays off-screen before it is hidden, if the WebView never reports that it started.</summary>
    private static readonly TimeSpan NoWindowHideDeadline = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Starts the window without showing it to the person: off-screen, without focus or a taskbar button, then hidden once the
    /// WebView has started. WPF builds the BlazorWebView (which opens the remote session) only for a window that has been shown,
    /// so a window that is never shown would never connect. The remote user's page doesn't need this window to be visible.
    /// </summary>
    public void ShowHidden()
    {
        App.Log("No-window start: the session runs with its window hidden.");
        _hideWhenReady = true;
        ShowInTaskbar = false;
        ShowActivated = false;
        WindowStartupLocation = WindowStartupLocation.Manual;
        WindowState = WindowState.Normal;
        Left = -32000;
        Top = -32000;
        Show();
        try { _tray = new NoWindowTrayIcon(BringToFront); }
        catch (Exception ex) { App.Log($"No-window start: the tray icon could not be shown ({ex.Message})."); }
        var deadline = new DispatcherTimer { Interval = NoWindowHideDeadline };
        deadline.Tick += (_, _) => { deadline.Stop(); HideForNoWindow(); };
        deadline.Start();
    }

    private void HideForNoWindow()
    {
        if (!_hideWhenReady) return;
        _hideWhenReady = false;
        Hide();
        App.Log("No-window start: window hidden.");
    }

    /// <summary>The person opened the app while it ran hidden (a second launch, or the tray icon): it becomes an ordinary window, and later restarts show it too.</summary>
    private void ShowAfterNoWindow()
    {
        StartsHidden = false;
        _tray?.Dispose();
        _tray = null;
        _hideWhenReady = false;
        Environment.SetEnvironmentVariable(NoWindowStart.Variable, null);
        ShowInTaskbar = true;
        ShowActivated = true;
        var area = SystemParameters.WorkArea;
        Left = area.Left + Math.Max(0, (area.Width - Width) / 2);
        Top = area.Top + Math.Max(0, (area.Height - Height) / 2);
        App.Log("No-window start: the person opened the app, so the window is shown.");
    }

    private WindowStyle _savedStyle = WindowStyle.SingleBorderWindow;
    private WindowState _savedState = WindowState.Normal;
    private ResizeMode _savedResize = ResizeMode.CanResize;
    private Rect _savedBounds = Rect.Empty;
    private bool _isFullscreen;
    private string? _fullscreenScreen;
    private bool _movedForFullscreen;
    private WindowsScreenControl? _screens;

    /// <summary>
    /// Borderless full screen, on <paramref name="screenId"/> when given (the display test moves through each monitor), else on the
    /// screen the window is on. Leaving full screen puts the window back where it was.
    /// </summary>
    private void SetFullscreen(bool enable, string? screenId = null)
    {
        if (enable == _isFullscreen && (!enable || string.Equals(screenId, _fullscreenScreen, StringComparison.OrdinalIgnoreCase))) return;
        if (enable)
        {
            RemotePCDiagnostics.Core.Display.ScreenInfo? screen = null;
            if (screenId is not null)
            {
                screen = _screens?.Find(screenId);
                if (screen is null)
                {
                    Logger.Warn($"Fullscreen requested for screen '{screenId}', but that monitor is no longer connected.");
                    return;
                }
            }
            if (!_isFullscreen)
            {
                _savedStyle = WindowStyle;
                _savedState = WindowState;
                _savedResize = ResizeMode;
                _savedBounds = RestoreBounds;
                _movedForFullscreen = false;
            }
            _isFullscreen = true;
            _fullscreenScreen = screenId;

            WindowStyle = WindowStyle.None;
            ResizeMode = ResizeMode.NoResize;
            WindowState = WindowState.Normal;
            if (screen is not null)
            {
                // Physical pixels: place the (normal) window on that monitor, then maximize it there.
                var hwnd = new System.Windows.Interop.WindowInteropHelper(this).Handle;
                if (hwnd != IntPtr.Zero && SetWindowPos(hwnd, IntPtr.Zero, screen.X, screen.Y, Math.Max(1, screen.Width), Math.Max(1, screen.Height),
                        SWP_NOZORDER))
                    _movedForFullscreen = true;
            }
            WindowState = WindowState.Maximized;
        }
        else
        {
            _isFullscreen = false;
            _fullscreenScreen = null;
            WindowStyle = _savedStyle;
            ResizeMode = _savedResize;
            if (_movedForFullscreen && !_savedBounds.IsEmpty)
            {
                WindowState = WindowState.Normal;
                Left = _savedBounds.Left;
                Top = _savedBounds.Top;
                Width = _savedBounds.Width;
                Height = _savedBounds.Height;
            }
            _movedForFullscreen = false;
            WindowState = _savedState;
        }
    }

    private const uint SWP_NOZORDER = 0x0004;

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int x, int y, int cx, int cy, uint uFlags);
}
