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
    private bool _restarting;
    private DispatcherTimer? _readyTimer;
    private DispatcherTimer? _copyResetTimer;
    public MainWindow()
    {
        // Local (default) or Remote. Remote when started with -u=<server uri> (RemoteBlazorWebViewTutorial convention)
        // or REMOTEPC_MODE=Remote (+ optional REMOTEPC_SERVER_URL, default https://remoteblazorwebview.com:34544).
        // See Properties/launchSettings.json for the "Local" and "Remote (Railway)" Visual Studio profiles.
        var pendingReboot = RebootResumeCoordinator.TryReadPendingStateFile();
        var launch = SessionLaunchOptions.Resolve(Environment.GetCommandLineArgs().Skip(1), Environment.GetEnvironmentVariable, pendingReboot);
        var mode = launch.Mode;

        var services = new ServiceCollection();
        services.AddRemoteWpfBlazorWebView();
        var sessionCtx = new SessionContext(mode, launch.ServerUri, launch.Id);
        services.AddSingleton<ISessionContext>(sessionCtx);
        services.AddSingleton<ResultStore>();
        services.AddSingleton<OsqueryRunner>(_ => new OsqueryRunner(options: new OsqueryOptions { Log = App.Log }));
        services.AddSingleton<IDiagnosticModule, OsqueryModule>();
        // Read-only EC fan diagnostic, active only on Lenovo IdeaPad 1 15ALC7 (82R4) with PawnIO installed.
        services.AddSingleton<IEcFanSource>(_ => LenovoEcFanSource.Create(App.Log));
        services.AddSingleton<ISensorProvider, LhmSensorProvider>();
        services.AddSingleton<IDiagnosticModule, LibreHardwareMonitorModule>();
        // On demand only: not auto-run and excluded from Run All; runs when the user presses Start on its page.
        services.AddSingleton<IDiagnosticModule>(sp => new CpuStressModule(sp.GetRequiredService<ISensorProvider>(), App.Log, ecFan: sp.GetRequiredService<IEcFanSource>()));
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
        // Last retrim per SSD volume: Windows' Defrag event 258 plus this app's own record (retrim.json), so Drive health only offers it when needed.
        services.AddSingleton(_ => new RetrimLog(RetrimLog.DefaultPath(), App.Log));
        services.AddSingleton<IRetrimHistory>(sp => new RetrimHistory(sp.GetRequiredService<RetrimLog>(), new WindowsRetrimEvents(App.Log), App.Log));
        services.AddSingleton<IDiagnosticModule>(sp => new DriveHealthModule(sp.GetRequiredService<SystemCommandRunner>(), sp.GetRequiredService<OsqueryRunner>(), sp.GetRequiredService<IRetrimHistory>()));
        services.AddSingleton<ServicesModule>();
        services.AddSingleton<IDiagnosticModule>(sp => sp.GetRequiredService<ServicesModule>());
        // Reversible changes (with their "before" values) for "Undo all changes" / --undo-all; survives restarts.
        services.AddSingleton<RemotePCDiagnostics.Core.Changes.IChangeJournal>(_ => new RemotePCDiagnostics.Core.Changes.FileChangeJournal(RemotePCDiagnostics.Core.Changes.FileChangeJournal.DefaultPath(), App.Log));
        services.AddSingleton(sp => new ServiceActionService(new WindowsServiceControlBackend(), sp.GetRequiredService<ISessionContext>(), App.Log,
            journal: sp.GetRequiredService<RemotePCDiagnostics.Core.Changes.IChangeJournal>()));
        services.AddSingleton(sp => new RebootResumeCoordinator(sp.GetRequiredService<SystemCommandRunner>(), sp.GetRequiredService<OsqueryRunner>(), RebootResumeCoordinator.DefaultStateFilePath(), log: App.Log));
        services.AddSingleton(sp => new RemediationService(sp.GetRequiredService<SystemCommandRunner>(), sp.GetRequiredService<ISessionContext>(), App.Log, sp.GetRequiredService<RebootResumeCoordinator>(),
            sp.GetRequiredService<RemotePCDiagnostics.Core.Changes.IChangeJournal>(), sp.GetRequiredService<RetrimLog>()));
        services.AddSingleton(sp => App.CreateUndoService(sp.GetRequiredService<RemotePCDiagnostics.Core.Changes.IChangeJournal>(), sp.GetRequiredService<SystemCommandRunner>(),
            new WindowsMemorySystem(sp.GetRequiredService<OsqueryRunner>(), App.Log)));
        services.AddSingleton<IDiagnosticModule, ProgramsModule>(sp => new ProgramsModule(sp.GetRequiredService<OsqueryRunner>()));
        services.AddSingleton<IDiagnosticModule, NetworkModule>(sp => new NetworkModule(sp.GetRequiredService<OsqueryRunner>(), sp.GetRequiredService<SystemCommandRunner>(), includeWifiAndIpConfig: true));
        services.AddSingleton<IDiagnosticModule>(sp => new EventLogModule(sp.GetRequiredService<SystemCommandRunner>(), excludeCrashEvents: true));
        services.AddSingleton<IDiagnosticModule>(sp => new CrashesModule(sp.GetRequiredService<SystemCommandRunner>(), includeSystemCrashes: true));
        services.AddSingleton<IDiagnosticModule>(sp => new ResourceHogsModule(sp.GetRequiredService<OsqueryRunner>(), sp.GetRequiredService<SystemCommandRunner>()));
        services.AddSingleton<IDiagnosticModule>(sp => new DeviceDriversModule(sp.GetRequiredService<OsqueryRunner>(), sp.GetRequiredService<SystemCommandRunner>()));

        services.AddSingleton<IDiagnosticModule>(sp => new BatteryPowerModule(sp.GetRequiredService<OsqueryRunner>(), sp.GetRequiredService<SystemCommandRunner>()));

        // On-demand only (Start button on its page): not in AutoRun below and excluded from Run All (IncludeInRunAll=false).
        services.AddSingleton<IDiagnosticModule>(new SecurityAuditModule(new SecurityAuditOptions { Log = App.Log }));
        // Audio tests (speaker→mic, mic→speaker): on-demand only, own pages, not part of Run All or the stress run.
        services.AddSingleton<RemotePCDiagnostics.Core.Audio.IAudioIo>(_ => new WasapiAudioIo(App.Log));
        services.AddSingleton<IDiagnosticModule>(sp => new RemotePCDiagnostics.Core.Audio.SpeakerToMicModule(sp.GetRequiredService<RemotePCDiagnostics.Core.Audio.IAudioIo>(), App.Log));
        services.AddSingleton<IDiagnosticModule>(sp => new RemotePCDiagnostics.Core.Audio.MicToSpeakerModule(sp.GetRequiredService<RemotePCDiagnostics.Core.Audio.IAudioIo>(), App.Log));
        // Webcam test: on-demand only, own page, not part of Run All or the stress run. Frames are analysed in memory only.
        services.AddSingleton<IDiagnosticModule>(new RemotePCDiagnostics.Core.Webcam.WebcamTestModule(new MediaCaptureWebcamIo(App.Log), App.Log));
        // NPU test: on-demand only, own page, not part of Run All or the stress run.
        services.AddSingleton<RemotePCDiagnostics.Core.Npu.INpuIo>(_ => new WindowsNpuIo(App.Log));
        services.AddSingleton<IDiagnosticModule>(sp => new RemotePCDiagnostics.Core.Npu.NpuTestModule(sp.GetRequiredService<RemotePCDiagnostics.Core.Npu.INpuIo>(), App.Log));
        services.AddSingleton<DiagnosticsService>();
        services.AddSingleton(new RemotePCDiagnostics.Core.Preferences.PreferencesService(
            new RemotePCDiagnostics.Core.Preferences.FilePreferencesStore(RemotePCDiagnostics.Core.Preferences.FilePreferencesStore.DefaultPath(), App.Log)));
        services.AddSingleton(sp => new ChecksScreenState(sp.GetRequiredService<DiagnosticsService>(), sp.GetRequiredService<ResultStore>(),
            sp.GetRequiredService<RemotePCDiagnostics.Core.Preferences.PreferencesService>()));
        services.AddSingleton(sp => new RemotePCDiagnostics.Core.Memory.MemorySuggestionService(
            new WindowsMemorySystem(sp.GetRequiredService<OsqueryRunner>(), App.Log), sp.GetRequiredService<ServicesModule>(), sp.GetRequiredService<ServiceActionService>(),
            sp.GetRequiredService<ISessionContext>(), (level, text) => App.Event(RemotePCDiagnostics.Core.Logging.LogEventIds.MemorySuggestion, level, text), App.Log,
            remediation: sp.GetRequiredService<RemediationService>(), journal: sp.GetRequiredService<RemotePCDiagnostics.Core.Changes.IChangeJournal>()));
        // Before/after performance benchmarks (state saved so the "before" survives a restart; event 1500).
        services.AddSingleton(sp => new RemotePCDiagnostics.Core.Benchmarks.BenchmarkService(
            new RemotePCDiagnostics.Core.Benchmarks.BenchmarkRunner(new WindowsBenchmarkProbes(sp.GetRequiredService<SystemCommandRunner>(), sp.GetRequiredService<ISensorProvider>(), App.Log), App.Log),
            new RemotePCDiagnostics.Core.Benchmarks.FileBenchmarkStore(RemotePCDiagnostics.Core.Benchmarks.FileBenchmarkStore.DefaultPath(), App.Log),
            sp.GetRequiredService<RemediationService>(), sp.GetRequiredService<ISessionContext>(),
            (level, text) => App.Event(RemotePCDiagnostics.Core.Logging.LogEventIds.Benchmark, level, text), App.Log));
        // Service workflow: checks → tech review → restart → before benchmark → fixes → restart → after benchmark → report.
        services.AddSingleton(sp => new RemotePCDiagnostics.Core.Workflow.WorkflowService(
            sp.GetRequiredService<DiagnosticsService>(), sp.GetRequiredService<ResultStore>(), sp.GetRequiredService<RemediationService>(),
            sp.GetRequiredService<RemotePCDiagnostics.Core.Benchmarks.BenchmarkService>(),
            new WindowsWorkflowSystem(sp.GetRequiredService<SystemCommandRunner>(), sp.GetRequiredService<ISessionContext>(), App.Log),
            new RemotePCDiagnostics.Core.Workflow.FileWorkflowStore(RemotePCDiagnostics.Core.Workflow.FileWorkflowStore.DefaultPath(), App.Log),
            sp.GetRequiredService<RemotePCDiagnostics.Core.Memory.MemorySuggestionService>(), sp.GetRequiredService<ISessionContext>(),
            (level, text) => App.Event(RemotePCDiagnostics.Core.Logging.LogEventIds.Workflow, level, text), App.Log,
            journal: sp.GetRequiredService<RemotePCDiagnostics.Core.Changes.IChangeJournal>(),
            prefs: sp.GetRequiredService<RemotePCDiagnostics.Core.Preferences.PreferencesService>()));
        // History page reads past results (event 1100) back from the Windows Event Log.
        services.AddSingleton<RemotePCDiagnostics.Core.History.IHistoryStore>(_ => EventLogHistorySource.Create(App.Log));
        var provider = _provider = services.BuildServiceProvider();
        Resources.Add("services", provider);
        Closed += (_, _) => { try { provider.GetService<IEcFanSource>()?.Dispose(); } catch { } }; // release the PawnIO EC module handle
        provider.GetRequiredService<DiagnosticsService>().Log = App.Log;
        provider.GetRequiredService<ChecksScreenState>(); // start tracking results (run mode labels, last completed) from launch
        // One Windows Event Log entry per finished test (every module and run path), see ResultEventLogger.
        var diag = provider.GetRequiredService<DiagnosticsService>();
        var eventContext = new RemotePCDiagnostics.Core.Logging.ResultEventContext(
            n => diag.Modules.FirstOrDefault(m => string.Equals(m.Name, n, StringComparison.OrdinalIgnoreCase))?.DisplayName ?? n,
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
        AutoRun.Start(provider.GetRequiredService<DiagnosticsService>(), Environment.GetEnvironmentVariable, App.Log, "Osquery", LibreHardwareMonitorModule.ModuleName,
            DriveHealthModule.ModuleName, ServicesModule.ModuleName, ProgramsModule.ModuleName, NetworkModule.ModuleName, EventLogModule.ModuleName, CrashesModule.ModuleName,
            ResourceHogsModule.ModuleName, DeviceDriversModule.ModuleName, BatteryPowerModule.ModuleName);
        _ = Task.Run(async () => { try { await provider.GetRequiredService<RebootResumeCoordinator>().CompletePostRebootIfPendingAsync(provider.GetRequiredService<RemediationService>(), provider.GetRequiredService<DiagnosticsService>(), launch.PostReboot); } catch (Exception ex) { App.Log($"Post-reboot check failed: {ex.Message}"); } });

        // A service workflow waiting for this restart carries on by itself.
        _ = Task.Run(async () => { try { await provider.GetRequiredService<RemotePCDiagnostics.Core.Workflow.WorkflowService>().ResumeAsync(); } catch (Exception ex) { App.Log($"Workflow resume failed: {ex.Message}"); } });
        // An "after" benchmark requested before a restart runs by itself once start-up has settled.
        _ = Task.Run(async () => { try { await provider.GetRequiredService<RemotePCDiagnostics.Core.Benchmarks.BenchmarkService>().ResumeAfterRestartAsync(); } catch (Exception ex) { App.Log($"Benchmark resume failed: {ex.Message}"); } });

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
            StartRemote(launch.ServerUri, sessionCtx.SessionId);
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

        RemoteBlazorWebView.ReadyToConnect += (s, e) => Dispatcher.BeginInvoke(() =>
        {
            _readyTimer?.Stop();
            if (_provider.GetService<ISessionContext>() is SessionContext sc && e.Id != Guid.Empty) sc.SessionId = e.Id;
            if (e.Id != Guid.Empty) _sessionId = e.Id;
            _technicianUrl = RemoteLinkInfo.BuildTechnicianUrl(e.Url ?? serverUri, e.Id);
            App.Log($"ReadyToConnect url={e.Url} id={e.Id} link={_technicianUrl}");
            RemoteLinkText.Text = _technicianUrl.ToString();
            RemoteHyperlink.NavigateUri = _technicianUrl;
            RemoteLinkRow.Visibility = Visibility.Visible;
            SetRemoteState(RemoteSessionState.Ready);
            // The app runs in the technician's browser; this window only needs to say so (the link is in the panel above, not repeated).
            try { (s as IBlazorWebView)?.NavigateToString(RemoteLinkInfo.LocalPlaceholderHtml); }
            catch (Exception ex) { App.Log($"NavigateToString placeholder failed: {ex}"); }
        });
        RemoteBlazorWebView.Connected += (_, e) => Dispatcher.BeginInvoke(() =>
        {
            App.Log($"Remote Connected id={e.Id} ip={e.IpAddress} user={e.User}");
            SetRemoteState(RemoteSessionState.TechnicianConnected);
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
                foreach (var a in SessionLaunchOptions.RestartArguments(serverUri, id)) psi.ArgumentList.Add(a);
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
