using Microsoft.Extensions.DependencyInjection;
using PeakSWC.RemoteBlazorWebView;
using PeakSWC.RemoteWebView;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Bios;
using RemotePCDiagnostics.Core.Checks;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Plugins;
using RemotePCDiagnostics.ModuleUi;
using RemotePCDiagnostics.Core.Security;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// The app's composition root: every module, service and Windows adapter the window and the Blazor pages use.
/// Kept out of <see cref="MainWindow"/> so a test can build the same container (ValidateOnBuild) and resolve everything.
/// </summary>
public static class HostServices
{
    /// <summary>Registers RemoteBlazorWebView and everything the app needs. <paramref name="log"/> is the file log line writer, used for ILogger lines only when <paramref name="loggers"/> is null
    /// (<see cref="App.Log"/>); <paramref name="logEvent"/> writes a Windows Event Log entry (<see cref="App.Event"/>).
    /// <paramref name="modulesFolder"/> overrides where module DLLs are loaded from (tests pass an empty folder so the PC's installed modules don't matter).
    /// <paramref name="loggers"/> backs every class's ILogger (<see cref="App.Loggers"/>), one category per class.
    /// <paramref name="bundledModulesFolder"/> overrides where the modules that ship with the app are loaded from (default builtin-modules\ next to the exe).
    /// <paramref name="checksFolder"/> overrides where custom JSON checks are loaded from.</summary>
    public static IServiceCollection AddRemotePCDiagnosticsHost(this IServiceCollection services, SessionContext session,
        Action<string> log, Action<int, RemotePCDiagnostics.Core.Logging.LogLevel, string> logEvent, string? modulesFolder = null,
        Microsoft.Extensions.Logging.ILoggerFactory? loggers = null, string? bundledModulesFolder = null, string? checksFolder = null)
    {
        services.AddRemoteWpfBlazorWebView();
        // ILogger<T> over the app's file and Event Log sinks (after the WebView's own logging registration, so this one wins).
        var loggerFactory = loggers ?? RemotePCDiagnostics.Core.Logging.AppLoggerFactory.From(log);
        services.AddSingleton(loggerFactory);
        services.AddSingleton(typeof(Microsoft.Extensions.Logging.ILogger<>), typeof(Microsoft.Extensions.Logging.Logger<>));
        ILogger L<T>() => For<T>(loggerFactory); // each class logs under its own category
        services.AddSingleton<ISessionContext>(session);
        services.AddSingleton<ElevationService>(sp => new ElevationService(sp.GetRequiredService<ISessionContext>(), L<ElevationService>()));
        services.AddSingleton<IElevationContext>(sp => sp.GetRequiredService<ElevationService>());
        services.AddSingleton<IElevatedCommandBridge>(sp => sp.GetRequiredService<ElevationService>());
        // Startup apps, services, hibernation, Fast Startup and DNS changes that need administrator rights: made by the Agent.
        services.AddSingleton<IAdminSettingsBackend>(sp => new AgentAdminSettings(sp.GetRequiredService<IElevatedCommandBridge>()));
        // HKLM policy values, extension blocklists, the page file and Defender exclusions: made by the Agent too.
        services.AddSingleton<IMachineTweaks>(sp => new AgentMachineTweaks(sp.GetRequiredService<IElevatedCommandBridge>(), L<AgentMachineTweaks>()));
        services.AddSingleton<RemoteUsers>(); // the top bar's "N Remote Users" badge
        services.AddSingleton(_ => AgentModeHost.CreateMonitor()); // Local only / agent link, separate from the session badge
        if (session.Mode == SessionMode.Local) services.AddSingleton<ICopilotHandoff, CopilotHandoff>();
        services.AddSingleton<ResultStore>();
        // WMI is read by the Agent, never by the app (it has the rights some classes need).
        services.AddSingleton<RemotePCDiagnostics.Core.DataSources.IWmiSource>(sp => new RemotePCDiagnostics.Core.DataSources.AgentWmiSource(sp.GetRequiredService<IElevatedCommandBridge>()));
        // The registry keys checks read need no administrator rights, so the app reads them itself.
        services.AddSingleton<RemotePCDiagnostics.Core.DataSources.IRegistrySource>(_ => new RemotePCDiagnostics.Core.DataSources.SystemRegistrySource(L<RemotePCDiagnostics.Core.DataSources.SystemRegistrySource>()));
        services.AddSingleton<RemotePCDiagnostics.Core.DataSources.IPackageSource>(_ => new RemotePCDiagnostics.Host.Platform.SystemPackageSource(L<RemotePCDiagnostics.Host.Platform.SystemPackageSource>()));
        services.AddReaders();
#if RPCD_STORE
        // The Store edition may have no Agent: then it reads as a standard user, with the legacy readers.
        services.AddSingleton<OsqueryRunner>(_ => new OsqueryRunner(options: new OsqueryOptions { Log = L<OsqueryRunner>() }));
        RemotePCDiagnostics.Legacy.LegacyReaders.AddLegacyFallbacks(services);
#endif
        // Read-only EC fan diagnostic, active only on Lenovo IdeaPad 1 15ALC7 (82R4) with PawnIO installed.
        services.AddSingleton<IEcFanSource>(_ => LenovoEcFanSource.Create(loggerFactory.CreateLogger(typeof(LenovoEcFanSource).FullName!)));
        services.AddSingleton<ISensorProvider>(sp => new LhmSensorProvider(
            sp.GetRequiredService<IEcFanSource>(),
            sp.GetService<IElevatedCommandBridge>(),
            L<LhmSensorProvider>(),
            isLocalProcessElevated: () => false));
        services.AddSingleton(sp => new SystemCommandRunner(
            log: L<SystemCommandRunner>(),
            elevatedBridge: sp.GetRequiredService<IElevatedCommandBridge>(),
            isProcessElevated: () => false));
        // One Windows memory/startup adapter for the whole app (undo and memory suggestions share it).
        services.AddSingleton<IMemorySystem>(sp => new WindowsMemorySystem(L<WindowsMemorySystem>(), sp.GetRequiredService<IAdminSettingsBackend>(),
            sp.GetRequiredService<IMachineTweaks>(), sp.GetRequiredService<IElevatedCommandBridge>()));
        // Its role interfaces resolve to the same instance, so a consumer can take only the part it uses.
        services.AddSingleton<RemotePCDiagnostics.Core.Optimizations.IMemoryProbe>(sp => sp.GetRequiredService<IMemorySystem>());
        services.AddSingleton<RemotePCDiagnostics.Core.Optimizations.IAppControl>(sp => sp.GetRequiredService<IMemorySystem>());
        services.AddSingleton<RemotePCDiagnostics.Core.Optimizations.IServiceConfig>(sp => sp.GetRequiredService<IMemorySystem>());
        services.AddSingleton<RemotePCDiagnostics.Core.Optimizations.IBrowserSettings>(sp => sp.GetRequiredService<IMemorySystem>());
        services.AddSingleton<RemotePCDiagnostics.Core.Optimizations.IRegistryTweaks>(sp => sp.GetRequiredService<IMemorySystem>());
        services.AddSingleton<RemotePCDiagnostics.Core.Optimizations.IPowerConfig>(sp => sp.GetRequiredService<IMemorySystem>());
        services.AddSingleton<RemotePCDiagnostics.Core.Optimizations.IStorageCleanupSystem>(sp => sp.GetRequiredService<IMemorySystem>());
        services.AddSingleton<RemotePCDiagnostics.Core.Optimizations.IDefenderConfig>(sp => sp.GetRequiredService<IMemorySystem>());
        services.AddSingleton<RemotePCDiagnostics.Core.Optimizations.IAppManagementSystem>(sp => sp.GetRequiredService<IMemorySystem>());
        // Last retrim per SSD volume: Windows' Defrag event 258 plus this app's own record (retrim.json), so Drive health only offers it when needed.
        services.AddSingleton(_ => new RetrimLog(RetrimLog.DefaultPath(), L<RetrimLog>()));
        services.AddSingleton<IRetrimHistory>(sp => new RetrimHistory(sp.GetRequiredService<RetrimLog>(), new WindowsRetrimEvents(L<WindowsRetrimEvents>()), L<RetrimHistory>()));
        services.AddSingleton<RemotePCDiagnostics.Core.Areas.IDriveHealthHistoryStore>(_ => new RemotePCDiagnostics.Core.Areas.DriveHealthHistoryStore(RemotePCDiagnostics.Core.Areas.DriveHealthHistoryStore.DefaultPath(), L<RemotePCDiagnostics.Core.Areas.DriveHealthHistoryStore>()));
        services.AddSingleton(sp => new ServicesModule(sp.GetRequiredService<IServiceSource>(), L<ServicesModule>()));
        // Reversible changes (with their "before" values) for "Undo all changes" / --undo-all; survives restarts.
        // The app isn't elevated, so the Agent reads and saves it (the state folder is for administrators only).
        services.AddSingleton<RemotePCDiagnostics.Core.Changes.IChangeJournal>(sp => new RemotePCDiagnostics.Core.Changes.AgentChangeJournal(
            sp.GetRequiredService<IElevatedCommandBridge>(), sp.GetService<IElevationContext>(), RemotePCDiagnostics.Core.Changes.FileChangeJournal.DefaultPath(),
            L<RemotePCDiagnostics.Core.Changes.AgentChangeJournal>()));
        services.AddSingleton(sp => new ServiceActionService(new WindowsServiceControlBackend(sp.GetRequiredService<IAdminSettingsBackend>()), sp.GetRequiredService<ISessionContext>(), L<ServiceActionService>(),
            journal: sp.GetRequiredService<RemotePCDiagnostics.Core.Changes.IChangeJournal>()));
        services.AddSingleton(sp => new RebootResumeCoordinator(sp.GetRequiredService<SystemCommandRunner>(), RebootResumeCoordinator.DefaultStateFilePath(), log: L<RebootResumeCoordinator>()));
        // Registry and WMI settings the fixes and undo change (Fast Startup and adapter DNS through the Agent, the signed-in user's proxy here).
        services.AddSingleton<ISystemSettings>(sp => new WindowsSystemSettings(L<WindowsSystemSettings>(), sp.GetRequiredService<IAdminSettingsBackend>()));
        services.AddSingleton(sp => new RemediationService(sp.GetRequiredService<SystemCommandRunner>(), sp.GetRequiredService<ISessionContext>(), L<RemediationService>(), sp.GetRequiredService<RebootResumeCoordinator>(),
            sp.GetRequiredService<RemotePCDiagnostics.Core.Changes.IChangeJournal>(), sp.GetRequiredService<RetrimLog>(), sp.GetRequiredService<ISystemSettings>()));
        services.AddSingleton(sp => CreateUndoService(sp.GetRequiredService<RemotePCDiagnostics.Core.Changes.IChangeJournal>(), sp.GetRequiredService<SystemCommandRunner>(),
            sp.GetRequiredService<IMemorySystem>(), sp.GetRequiredService<IAdminSettingsBackend>(), L<UndoService>(), logEvent));
        // Audio tests (speaker→mic, mic→speaker): on-demand only, own pages, not part of Run All or the stress run.
        services.AddSingleton<RemotePCDiagnostics.Core.Audio.IAudioIo>(_ => new WasapiAudioIo(L<WasapiAudioIo>()));
        // NPU test: on-demand only, own page, not part of Run All or the stress run.
        services.AddSingleton<RemotePCDiagnostics.Core.Npu.INpuIo>(_ => new WindowsNpuIo(L<WindowsNpuIo>()));
        // GPU stress test: Direct3D 11 compute devices.
        services.AddSingleton<IGpuDeviceFactory>(_ => new RemotePCDiagnostics.Host.Gpu.D3D11GpuDeviceFactory(L<RemotePCDiagnostics.Host.Gpu.D3D11GpuDeviceFactory>()));
        // Webcam test: cameras through Windows MediaCapture (a preview window only at the PC itself).
        services.AddSingleton<RemotePCDiagnostics.Core.Webcam.IWebcamIo>(_ => new MediaCaptureWebcamIo(L<MediaCaptureWebcamIo>(), showPreview: session.Mode == SessionMode.Local));
        // Vendor-independent BIOS update orchestrator, probes, and all 9 built-in vendor providers (additional providers register via AddBiosUpdateProvider<T>).
        services.AddBiosUpdates();
        services.AddBuiltInBiosUpdateProviders();
        // Every built-in module goes through the same registration path a plugin uses.
        var plugins = new PluginRegistrar(session, HostVersion(), L<PluginRegistrar>());
        services.AddSingleton(plugins);
        plugins.Register(services, new BuiltInModulesPlugin(), BuiltInModulesPlugin.Id, ModuleSource.BuiltIn);
        var effectiveModulesFolder = modulesFolder ?? ModuleLoaderOptions.DefaultModulesFolder();
        ModuleProcessModeSetting.PurgeLegacySetting(effectiveModulesFolder);
        services.AddSingleton(LoadModulePlugins(services, plugins, logEvent, loggerFactory, new ModuleLoaderOptions
        {
            HostVersion = HostVersion(),
            ModulesFolder = effectiveModulesFolder,
            BundledFolder = bundledModulesFolder ?? ModuleLoaderOptions.DefaultBundledFolder(),
            ChecksFolder = checksFolder ?? (modulesFolder is not null ? System.IO.Path.Combine(modulesFolder, "checks") : null),
            // Only the person at the PC can turn unsigned modules on (a marker in the admin-only modules folder); never in a remote session.
            AllowUnsigned = session.Mode == SessionMode.Local && UnsignedModulesSetting.IsOn(modulesFolder),
            // All test modules run in-process in user mode (privileged actions run via Agent helper).
            ProcessModes = new ModuleProcessModeSetting { All = ModuleProcessMode.InProcess },
        }));
        // Modules' own UIs that run in the module UI host, framed on the module page: through a relay in the app in Local mode, through
        // the session's relay in Remote mode (modules that ship with the app only).
        if (session.Mode == SessionMode.Local || session.ServerUri is not null)
            services.AddSingleton<IModuleUiFrames>(sp =>
            {
                var frames = new ModuleUiFrames(L<ModuleUiFrames>(), remoteRelay: session.Mode == SessionMode.Remote ? session.ServerUri : null);
                EventHandler onExit = (_, _) => frames.Dispose(); // the UI processes never outlive the app
                AppDomain.CurrentDomain.ProcessExit += onExit;
                frames.OnDisposed = () => AppDomain.CurrentDomain.ProcessExit -= onExit;
                return frames;
            });
        services.AddSingleton(sp => new CheckSettingsService(
            new AgentCheckSettingsStore(sp.GetRequiredService<IElevatedCommandBridge>(), L<AgentCheckSettingsStore>())));
        services.AddSingleton(sp =>
        {
            sp.GetService<HostQueryBackendSlot>()?.Bind(sp);
            var diag = new DiagnosticsService(sp.GetRequiredService<ResultStore>(), sp.GetServices<IDiagnosticModule>(),
                checks: sp.GetRequiredService<CheckSettingsService>());
            diag.Log = L<DiagnosticsService>();
            sp.GetRequiredService<PluginRegistrar>().ApplyTo(diag.Catalog); // where each module came from, its details UI
            diag.RejectDependencyCycles(); // now that plugin DependsOn / RunAfter are known
            return diag;
        });
        services.AddSingleton(new RemotePCDiagnostics.Core.Preferences.PreferencesService(
            new RemotePCDiagnostics.Core.Preferences.FilePreferencesStore(RemotePCDiagnostics.Core.Preferences.FilePreferencesStore.DefaultPath(), L<RemotePCDiagnostics.Core.Preferences.FilePreferencesStore>())));
        services.AddSingleton(sp => new ChecksScreenState(sp.GetRequiredService<DiagnosticsService>(), sp.GetRequiredService<ResultStore>(),
            sp.GetRequiredService<RemotePCDiagnostics.Core.Preferences.PreferencesService>(),
            sp.GetRequiredService<RemotePCDiagnostics.Core.Optimizations.MemorySuggestionService>()));
        services.AddSingleton(sp => new RemotePCDiagnostics.Core.Optimizations.MemorySuggestionService(
            sp.GetRequiredService<IMemorySystem>(), sp.GetRequiredService<ServicesModule>(), sp.GetRequiredService<ServiceActionService>(),
            sp.GetRequiredService<ISessionContext>(), (level, text) => logEvent(RemotePCDiagnostics.Core.Logging.LogEventIds.MemorySuggestion, level, text), L<RemotePCDiagnostics.Core.Optimizations.MemorySuggestionService>(),
            remediation: sp.GetRequiredService<RemediationService>(), journal: sp.GetRequiredService<RemotePCDiagnostics.Core.Changes.IChangeJournal>()));
        // Developer setup check & developer clean-build benchmarks (Phase 1 & 2).
        services.AddSingleton<RemotePCDiagnostics.Core.Benchmarks.IDeveloperSampleStore>(sp => new AgentDeveloperSampleStore(
            sp.GetRequiredService<IElevatedCommandBridge>(), L<AgentDeveloperSampleStore>()));
        services.AddSingleton<RemotePCDiagnostics.Core.Benchmarks.IDeveloperEnvironmentProbe>(sp =>
        {
            var probesForCond = new WindowsBenchmarkProbes(sp.GetRequiredService<SystemCommandRunner>(), sp.GetRequiredService<ISensorProvider>(), L<WindowsBenchmarkProbes>());
            return new WindowsDeveloperEnvironmentProbe(
                sp.GetRequiredService<SystemCommandRunner>(),
                sp.GetRequiredService<IMachineTweaks>(),
                sp.GetRequiredService<IElevatedCommandBridge>(),
                probesForCond.ReadConditions,
                L<WindowsDeveloperEnvironmentProbe>());
        });
        services.AddSingleton(sp => new RemotePCDiagnostics.Core.Benchmarks.DeveloperBuildRunner(
            sp.GetRequiredService<RemotePCDiagnostics.Core.Benchmarks.IDeveloperEnvironmentProbe>(),
            machineTweaks: sp.GetRequiredService<IMachineTweaks>(),
            sampleStore: sp.GetRequiredService<RemotePCDiagnostics.Core.Benchmarks.IDeveloperSampleStore>(),
            log: L<RemotePCDiagnostics.Core.Benchmarks.DeveloperBuildRunner>()));
        // Before/after performance benchmarks (state saved so the "before" survives a restart; event 1500).
        services.AddSingleton(sp => new RemotePCDiagnostics.Core.Benchmarks.BenchmarkService(
            new RemotePCDiagnostics.Core.Benchmarks.BenchmarkRunner(
                new WindowsBenchmarkProbes(sp.GetRequiredService<SystemCommandRunner>(), sp.GetRequiredService<ISensorProvider>(), L<WindowsBenchmarkProbes>(), sp.GetRequiredService<RemotePCDiagnostics.Core.Benchmarks.DeveloperBuildRunner>()),
                L<RemotePCDiagnostics.Core.Benchmarks.BenchmarkRunner>()),
            new AgentBenchmarkStore(sp.GetRequiredService<IElevatedCommandBridge>(), L<AgentBenchmarkStore>()),
            sp.GetRequiredService<RemediationService>(), sp.GetRequiredService<ISessionContext>(),
            (level, text) => logEvent(RemotePCDiagnostics.Core.Logging.LogEventIds.Benchmark, level, text), L<RemotePCDiagnostics.Core.Benchmarks.BenchmarkService>(),
            devRunner: sp.GetRequiredService<RemotePCDiagnostics.Core.Benchmarks.DeveloperBuildRunner>(),
            devEnv: sp.GetRequiredService<RemotePCDiagnostics.Core.Benchmarks.IDeveloperEnvironmentProbe>()));
        // Service workflow: checks → tech review → restart → before benchmark → fixes → restart → after benchmark → report.
        services.AddSingleton(sp => new RemotePCDiagnostics.Core.Workflow.WorkflowService(
            sp.GetRequiredService<DiagnosticsService>(), sp.GetRequiredService<ResultStore>(), sp.GetRequiredService<RemediationService>(),
            sp.GetRequiredService<RemotePCDiagnostics.Core.Benchmarks.BenchmarkService>(),
            new WindowsWorkflowSystem(sp.GetRequiredService<SystemCommandRunner>(), sp.GetRequiredService<ISessionContext>(), L<WindowsWorkflowSystem>(), sp.GetRequiredService<IElevatedCommandBridge>()),
            new AgentWorkflowStore(sp.GetRequiredService<IElevatedCommandBridge>(), L<AgentWorkflowStore>()),
            sp.GetRequiredService<RemotePCDiagnostics.Core.Optimizations.MemorySuggestionService>(), sp.GetRequiredService<ISessionContext>(),
            (level, text) => logEvent(RemotePCDiagnostics.Core.Logging.LogEventIds.Workflow, level, text), L<RemotePCDiagnostics.Core.Workflow.WorkflowService>(),
            journal: sp.GetRequiredService<RemotePCDiagnostics.Core.Changes.IChangeJournal>(),
            prefs: sp.GetRequiredService<RemotePCDiagnostics.Core.Preferences.PreferencesService>()));
        services.AddSingleton<RemotePCDiagnostics.Core.Workflow.PhysicalBenchQaService>();
        services.AddSingleton(sp => new RemotePCDiagnostics.Core.Workflow.BenchQaRunner(
            sp.GetRequiredService<DiagnosticsService>(),
            sp.GetRequiredService<ResultStore>(),
            sp.GetService<RemotePCDiagnostics.Core.Workflow.WorkflowService>(),
            sp.GetService<RemotePCDiagnostics.Core.Preferences.PreferencesService>(),
            sp.GetService<RemotePCDiagnostics.Core.Workflow.PhysicalBenchQaService>(),
            L<RemotePCDiagnostics.Core.Workflow.BenchQaRunner>()));
        services.AddSingleton(_ => new RemotePCDiagnostics.Core.Workflow.ShopRelayClient(log: L<RemotePCDiagnostics.Core.Workflow.ShopRelayClient>()));
        services.AddSingleton<RemoteSessionHealth>();
        services.AddSingleton(sp => new DesktopSessionRelauncher(sp.GetRequiredService<ISessionContext>(), L<DesktopSessionRelauncher>()));
        services.AddSingleton<ISessionRelauncher>(sp => sp.GetRequiredService<DesktopSessionRelauncher>());
        services.AddSingleton<IFullscreenService, FullscreenService>();
        services.AddSingleton<IStoreUpdateBackend>(_ => new StoreAppUpdateBackend(L<StoreAppUpdateBackend>()));
        services.AddSingleton<IAppUpdateService>(sp => new AppUpdateService(
            installedVersion: AppBuildInfo.Version,
            channel: AppVersionComparer.DefaultChannelFor(AppBuildInfo.Version),
            storeBackend: sp.GetService<IStoreUpdateBackend>(),
            getElevatedBridge: () => sp.GetService<IElevatedCommandBridge>(),
            onExitForUpdate: () =>
            {
                try
                {
                    System.Windows.Application.Current?.Dispatcher.BeginInvoke(() => System.Windows.Application.Current.Shutdown());
                }
                catch { }
            },
            log: L<AppUpdateService>(),
            // Setup starts the app again with this once the update is installed: the same relay, session id and group, so the
            // remote user's page reconnects instead of waiting for a session that never comes back.
            getRelaunchArguments: () => session.Mode == SessionMode.Remote && session.ServerUri is not null && session.SessionId != Guid.Empty
                ? SessionLaunchOptions.RestartArguments(session.ServerUri, session.SessionId, session.Unattended, session.Voice, session.Group, session.Admin)
                : [SessionLaunchOptions.RestartedArg]));
        // Uploads each finished benchmark pass to the shop's comparison. MainLayout injects it, so it listens from the first page on.
        services.AddSingleton(sp => new RemotePCDiagnostics.UI.BenchmarkUploader(
            sp.GetRequiredService<RemotePCDiagnostics.Core.Benchmarks.BenchmarkService>(),
            sp.GetRequiredService<RemotePCDiagnostics.UI.AppServices>(),
            sp.GetRequiredService<ISessionContext>()));
        // The optional host services pages may use (instead of injecting IServiceProvider).
        services.AddSingleton(sp => new RemotePCDiagnostics.UI.AppServices(sp.GetService<RemediationService>(), sp.GetService<ServiceActionService>(),
            sp.GetService<RemotePCDiagnostics.Core.Optimizations.MemorySuggestionService>(), sp.GetService<RemotePCDiagnostics.Core.Areas.ICopilotHandoff>(),
            sp.GetService<RemotePCDiagnostics.Core.Preferences.PreferencesService>(), sp.GetService<RemotePCDiagnostics.Core.Workflow.WorkflowService>(),
            sp.GetService<PluginRegistrar>(), sp.GetService<IModuleUiFrames>(),
            new SupportDiagnostics(new RemotePCDiagnostics.Core.Osquery.SystemProcessLauncher()),
            sp.GetService<RemotePCDiagnostics.Core.Workflow.PhysicalBenchQaService>(),
            sp.GetService<RemotePCDiagnostics.Core.Workflow.BenchQaRunner>(),
            sp.GetService<RemotePCDiagnostics.Core.Workflow.ShopRelayClient>(),
            sp.GetService<ISessionRelauncher>(),
            sp.GetService<RemoteSessionHealth>(),
            sp.GetService<IElevationContext>(),
            sp.GetService<IFullscreenService>(),
            sp.GetService<IAppUpdateService>(),
            sp.GetService<SystemCommandRunner>(),
            sp.GetService<CheckSettingsService>(),
            sp.GetService<IBiosUpdateService>()));
        // History page reads past results (event 1100) back from the Windows Event Log.
        services.AddSingleton<RemotePCDiagnostics.Core.History.IHistoryStore>(_ => EventLogHistorySource.Create(loggerFactory.CreateLogger(typeof(EventLogHistorySource).FullName!)));
        return services;
    }

    /// <summary>Discovers, verifies and registers module plugins. Never throws: a broken modules folder leaves only the built-ins.</summary>
    public static ModuleLoader LoadModulePlugins(IServiceCollection services, PluginRegistrar plugins,
        Action<int, RemotePCDiagnostics.Core.Logging.LogLevel, string> logEvent, Microsoft.Extensions.Logging.ILoggerFactory loggers,
        ModuleLoaderOptions? options = null)
    {
        var log = For<ModuleLoader>(loggers);
        // Host queries: what a module in user mode asks the app for. The answers come from the app's own services, so they bind when the
        // container builds the diagnostics service (HostQueryBackendSlot.Bind). The Agent's connection binds then too: it runs the modules
        // that need administrator.
        var backend = new HostQueryBackendSlot();
        var launcher = new RestrictedModuleHostLauncher(For<RestrictedModuleHostLauncher>(loggers), agent: () => backend.Agent);
        services.AddSingleton(backend);
        var hostQueries = new HostQueryServer(() => backend.Value, For<HostQueryServer>(loggers));
        var loader = new ModuleLoader(options ?? new ModuleLoaderOptions { HostVersion = HostVersion() }, plugins, log,
            um => PerDeviceModuleProxy.For(new UserModeModuleProxy(um, launcher, For<UserModeModuleProxy>(loggers), hostQueries)));
        var before = plugins.Records.Count;
        try { loader.LoadBundled(services); }
        catch (Exception ex) { log.Error($"Modules: loading the built-in module DLLs failed: {ex.GetType().Name}: {ex.Message}"); }
        try { loader.LoadAll(services); }
        catch (Exception ex) { log.Error($"Modules: loading plugins failed: {ex.GetType().Name}: {ex.Message}"); }
#if RPCD_STORE
        // Checks written as data run osquery SQL, and only the Store edition ships osquery.
        LoadJsonChecks(services, plugins, For<RemotePCDiagnostics.Core.Checks.JsonCheckModule>(loggers), options?.ChecksFolder);
#endif
        foreach (var r in plugins.Records.Skip(before))
        {
            if (r.Source == ModuleSource.BuiltIn && r.State == PluginState.Loaded) continue; // shipped with the app: only a failure is news
            var text = $"Module plugin: {r.PluginId}{Environment.NewLine}Module id: {r.ModuleId}{Environment.NewLine}Version: {r.Version}{Environment.NewLine}" +
                $"Signature: {r.Signature}{Environment.NewLine}State: {r.State}{(r.Reason is null ? "" : Environment.NewLine + "Reason: " + r.Reason)}{Environment.NewLine}Path: {r.Path}";
            try { logEvent(RemotePCDiagnostics.Core.Logging.LogEventIds.ModulePlugin,
                r.State == PluginState.Loaded || r.UserMode ? RemotePCDiagnostics.Core.Logging.LogLevel.Information : RemotePCDiagnostics.Core.Logging.LogLevel.Warning, text); }
            catch { }
        }
        return loader;
    }

    /// <summary>Whether this edition loads checks written as data (only the Store edition, which ships osquery).</summary>
    public static readonly bool LoadsJsonChecks =
#if RPCD_STORE
        true;
#else
        false;
#endif

    /// <summary>Checks written as data (%ProgramFiles%\RemotePCDiagnostics\checks\*.json): read-only osquery, no code, so they run unsigned.
/// Store edition only: the Setup edition doesn't ship osquery and ignores the folder.</summary>
    public static void LoadJsonChecks(IServiceCollection services, PluginRegistrar plugins, ILogger? log, string? folder = null)
    {
        try
        {
            var ids = BuiltInModules.Descriptors.ToDictionary(d => d.Id, d => d.Slug);
            var slugs = new HashSet<string>(BuiltInModules.Descriptors.Select(d => d.Slug), StringComparer.OrdinalIgnoreCase);
            foreach (var r in plugins.Records) { if (r.ModuleId is { } id) ids[id] = r.PluginId; slugs.Add(r.PluginId); }
            var problems = new List<(string File, string Problem)>();
            foreach (var c in RemotePCDiagnostics.Core.Checks.JsonCheckModule.LoadFolder(folder ?? RemotePCDiagnostics.Core.Checks.JsonCheckModule.DefaultFolder(), ids, slugs, problems))
            {
                var record = new PluginRecord(c.Slug, ModuleSource.Plugin, PluginState.Loaded)
                    { ModuleId = c.Id, DisplayName = c.DisplayName, Signature = "Check (no code)", Version = "check" };
                plugins.Register(services, new RemotePCDiagnostics.Core.Checks.JsonCheckPlugin(c, log), c.Slug, ModuleSource.Plugin, c.Id, record, c.ToDescriptor());
            }
            foreach (var (file, problem) in problems)
                plugins.RecordDisabled(new PluginRecord(System.IO.Path.GetFileNameWithoutExtension(file), ModuleSource.Plugin, PluginState.Disabled, problem) { Path = file, Signature = "Check (no code)" });
        }
        catch (Exception ex) { log.Warn($"Checks: loading JSON checks failed: {ex.Message}"); }
    }

    /// <summary>A logger whose category is the type's full name (shown as its short name on each line).</summary>
    public static ILogger For<T>(Microsoft.Extensions.Logging.ILoggerFactory loggers) => loggers.CreateLogger(typeof(T).FullName ?? typeof(T).Name);

    /// <summary>The app's version as a <see cref="Version"/> (for a plugin's minHost check).</summary>
    public static Version HostVersion() => Version.TryParse(AppBuildInfo.Release, out var v) ? v : new Version(0, 0);

    /// <summary>The undo service, shared by the window (via the container) and the headless --undo-all run.</summary>
    public static UndoService CreateUndoService(IChangeJournal journal, SystemCommandRunner commands, IMemorySystem memory, IAdminSettingsBackend admin,
        ILogger? log, Action<int, RemotePCDiagnostics.Core.Logging.LogLevel, string> logEvent) =>
        new(journal, commands, memory, new WindowsServiceControlBackend(admin), (level, text) => logEvent(RemotePCDiagnostics.Core.Logging.LogEventIds.Undo, level, text), log,
            new WindowsSystemSettings(log, admin));
}

/// <summary>The app's services that answer host queries (<see cref="HostQueryServer"/>), bound once the container exists.</summary>
public sealed class HostQueryBackendSlot
{
    public HostQueryBackend? Value { get; private set; }

    /// <summary>The Agent's connection (Admin Repair Mode or the agent service), for the module host it runs.</summary>
    public RemotePCDiagnostics.Core.Session.IElevatedCommandBridge? Agent { get; private set; }

    public void Bind(IServiceProvider sp)
    {
        Agent ??= sp.GetService<RemotePCDiagnostics.Core.Session.IElevatedCommandBridge>();
        Value ??= new HostQueryBackend
        {
            Sensors = sp.GetService<ISensorProvider>(), Commands = sp.GetService<SystemCommandRunner>(),
            Retrims = sp.GetService<IRetrimHistory>(), Drives = sp.GetService<IDriveSource>(),
            Wmi = sp.GetService<RemotePCDiagnostics.Core.DataSources.IWmiSource>(),
            Packages = sp.GetService<RemotePCDiagnostics.Core.DataSources.IPackageSource>(),
        };
    }
}
