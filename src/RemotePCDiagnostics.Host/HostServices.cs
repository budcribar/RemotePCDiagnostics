using Microsoft.Extensions.DependencyInjection;
using PeakSWC.RemoteBlazorWebView;
using PeakSWC.RemoteWebView;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Plugins;
using RemotePCDiagnostics.ModuleUi;
using RemotePCDiagnostics.Core.Security;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Stress;
using RemotePCDiagnostics.Host.Sensors;

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
    /// <paramref name="bundledModulesFolder"/> overrides where the modules that ship with the app are loaded from (default builtin-modules\ next to the exe).</summary>
    public static IServiceCollection AddRemotePCDiagnosticsHost(this IServiceCollection services, SessionContext session,
        Action<string> log, Action<int, RemotePCDiagnostics.Core.Logging.LogLevel, string> logEvent, string? modulesFolder = null,
        Microsoft.Extensions.Logging.ILoggerFactory? loggers = null, string? bundledModulesFolder = null)
    {
        services.AddRemoteWpfBlazorWebView();
        // ILogger<T> over the app's file and Event Log sinks (after the WebView's own logging registration, so this one wins).
        var loggerFactory = loggers ?? RemotePCDiagnostics.Core.Logging.AppLoggerFactory.From(log);
        services.AddSingleton(loggerFactory);
        services.AddSingleton(typeof(Microsoft.Extensions.Logging.ILogger<>), typeof(Microsoft.Extensions.Logging.Logger<>));
        ILogger L<T>() => For<T>(loggerFactory); // each class logs under its own category
        services.AddSingleton<ISessionContext>(session);
        if (session.Mode == SessionMode.Local) services.AddSingleton<ICopilotHandoff, CopilotHandoff>();
        services.AddSingleton<ResultStore>();
        services.AddSingleton<OsqueryRunner>(_ => new OsqueryRunner(options: new OsqueryOptions { Log = L<OsqueryRunner>() }));
        // Read-only EC fan diagnostic, active only on Lenovo IdeaPad 1 15ALC7 (82R4) with PawnIO installed.
        services.AddSingleton<IEcFanSource>(_ => LenovoEcFanSource.Create(loggerFactory.CreateLogger(typeof(LenovoEcFanSource).FullName!)));
        services.AddSingleton<ISensorProvider, LhmSensorProvider>();
        services.AddSingleton(new SystemCommandRunner(log: L<SystemCommandRunner>()));
        // One Windows memory/startup adapter for the whole app (undo and memory suggestions share it).
        services.AddSingleton<IMemorySystem>(sp => new WindowsMemorySystem(sp.GetRequiredService<OsqueryRunner>(), L<WindowsMemorySystem>()));
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
        services.AddSingleton<ServicesModule>();
        // Reversible changes (with their "before" values) for "Undo all changes" / --undo-all; survives restarts.
        services.AddSingleton<RemotePCDiagnostics.Core.Changes.IChangeJournal>(_ => new RemotePCDiagnostics.Core.Changes.FileChangeJournal(RemotePCDiagnostics.Core.Changes.FileChangeJournal.DefaultPath(), L<RemotePCDiagnostics.Core.Changes.FileChangeJournal>()));
        services.AddSingleton(sp => new ServiceActionService(new WindowsServiceControlBackend(), sp.GetRequiredService<ISessionContext>(), L<ServiceActionService>(),
            journal: sp.GetRequiredService<RemotePCDiagnostics.Core.Changes.IChangeJournal>()));
        services.AddSingleton(sp => new RebootResumeCoordinator(sp.GetRequiredService<SystemCommandRunner>(), sp.GetRequiredService<OsqueryRunner>(), RebootResumeCoordinator.DefaultStateFilePath(), log: L<RebootResumeCoordinator>()));
        // Registry and WMI settings the fixes and undo change in process (Fast Startup, the signed-in user's proxy, adapter DNS).
        services.AddSingleton<ISystemSettings>(_ => new WindowsSystemSettings(L<WindowsSystemSettings>()));
        services.AddSingleton(sp => new RemediationService(sp.GetRequiredService<SystemCommandRunner>(), sp.GetRequiredService<ISessionContext>(), L<RemediationService>(), sp.GetRequiredService<RebootResumeCoordinator>(),
            sp.GetRequiredService<RemotePCDiagnostics.Core.Changes.IChangeJournal>(), sp.GetRequiredService<RetrimLog>(), sp.GetRequiredService<ISystemSettings>()));
        services.AddSingleton(sp => CreateUndoService(sp.GetRequiredService<RemotePCDiagnostics.Core.Changes.IChangeJournal>(), sp.GetRequiredService<SystemCommandRunner>(),
            sp.GetRequiredService<IMemorySystem>(), L<UndoService>(), logEvent));
        // Audio tests (speaker→mic, mic→speaker): on-demand only, own pages, not part of Run All or the stress run.
        services.AddSingleton<RemotePCDiagnostics.Core.Audio.IAudioIo>(_ => new WasapiAudioIo(L<WasapiAudioIo>()));
        // NPU test: on-demand only, own page, not part of Run All or the stress run.
        services.AddSingleton<RemotePCDiagnostics.Core.Npu.INpuIo>(_ => new WindowsNpuIo(L<WindowsNpuIo>()));
        // GPU stress test: Direct3D 11 compute devices.
        services.AddSingleton<IGpuDeviceFactory>(_ => new RemotePCDiagnostics.Host.Gpu.D3D11GpuDeviceFactory(L<RemotePCDiagnostics.Host.Gpu.D3D11GpuDeviceFactory>()));
        // Webcam test: cameras through Windows MediaCapture (a preview window only at the PC itself).
        services.AddSingleton<RemotePCDiagnostics.Core.Webcam.IWebcamIo>(_ => new MediaCaptureWebcamIo(L<MediaCaptureWebcamIo>(), showPreview: session.Mode == SessionMode.Local));
        // Every built-in module goes through the same registration path a plugin uses.
        var plugins = new PluginRegistrar(session, HostVersion(), L<PluginRegistrar>());
        services.AddSingleton(plugins);
        plugins.Register(services, new BuiltInModulesPlugin(), BuiltInModulesPlugin.Id, ModuleSource.BuiltIn);
        // The modules that ship with the app (builtin-modules\ next to the exe, in-process), then module DLLs from
        // %ProgramFiles%\RemotePCDiagnostics\modules (signed ones load in-process; unsigned ones never do).
        services.AddSingleton(LoadModulePlugins(services, plugins, logEvent, loggerFactory, new ModuleLoaderOptions
        {
            HostVersion = HostVersion(),
            ModulesFolder = modulesFolder ?? ModuleLoaderOptions.DefaultModulesFolder(),
            BundledFolder = bundledModulesFolder ?? ModuleLoaderOptions.DefaultBundledFolder(),
            // Only the person at the PC can turn unsigned modules on (a marker in the admin-only modules folder); never in a remote session.
            AllowUnsigned = session.Mode == SessionMode.Local && UnsignedModulesSetting.IsOn(),
            // In or out of process for each module that ships with the app (About page; process-mode.json in the same admin-only folder).
            ProcessModes = ModuleProcessModeSetting.Read(modulesFolder ?? ModuleLoaderOptions.DefaultModulesFolder()),
        }));
        // Unsigned modules' own UIs, framed on the module page (Local only, like unsigned modules themselves).
        if (session.Mode == SessionMode.Local)
            services.AddSingleton<IModuleUiFrames>(sp =>
            {
                var frames = new ModuleUiFrames(L<ModuleUiFrames>());
                AppDomain.CurrentDomain.ProcessExit += (_, _) => frames.Dispose(); // the UI processes never outlive the app
                return frames;
            });
        services.AddSingleton(sp =>
        {
            var diag = new DiagnosticsService(sp.GetRequiredService<ResultStore>(), sp.GetServices<IDiagnosticModule>());
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
        // Before/after performance benchmarks (state saved so the "before" survives a restart; event 1500).
        services.AddSingleton(sp => new RemotePCDiagnostics.Core.Benchmarks.BenchmarkService(
            new RemotePCDiagnostics.Core.Benchmarks.BenchmarkRunner(new WindowsBenchmarkProbes(sp.GetRequiredService<SystemCommandRunner>(), sp.GetRequiredService<ISensorProvider>(), L<WindowsBenchmarkProbes>()), L<RemotePCDiagnostics.Core.Benchmarks.BenchmarkRunner>()),
            new RemotePCDiagnostics.Core.Benchmarks.FileBenchmarkStore(RemotePCDiagnostics.Core.Benchmarks.FileBenchmarkStore.DefaultPath(), L<RemotePCDiagnostics.Core.Benchmarks.FileBenchmarkStore>()),
            sp.GetRequiredService<RemediationService>(), sp.GetRequiredService<ISessionContext>(),
            (level, text) => logEvent(RemotePCDiagnostics.Core.Logging.LogEventIds.Benchmark, level, text), L<RemotePCDiagnostics.Core.Benchmarks.BenchmarkService>()));
        // Service workflow: checks → tech review → restart → before benchmark → fixes → restart → after benchmark → report.
        services.AddSingleton(sp => new RemotePCDiagnostics.Core.Workflow.WorkflowService(
            sp.GetRequiredService<DiagnosticsService>(), sp.GetRequiredService<ResultStore>(), sp.GetRequiredService<RemediationService>(),
            sp.GetRequiredService<RemotePCDiagnostics.Core.Benchmarks.BenchmarkService>(),
            new WindowsWorkflowSystem(sp.GetRequiredService<SystemCommandRunner>(), sp.GetRequiredService<ISessionContext>(), L<WindowsWorkflowSystem>()),
            new RemotePCDiagnostics.Core.Workflow.FileWorkflowStore(RemotePCDiagnostics.Core.Workflow.FileWorkflowStore.DefaultPath(), L<RemotePCDiagnostics.Core.Workflow.FileWorkflowStore>()),
            sp.GetRequiredService<RemotePCDiagnostics.Core.Optimizations.MemorySuggestionService>(), sp.GetRequiredService<ISessionContext>(),
            (level, text) => logEvent(RemotePCDiagnostics.Core.Logging.LogEventIds.Workflow, level, text), L<RemotePCDiagnostics.Core.Workflow.WorkflowService>(),
            journal: sp.GetRequiredService<RemotePCDiagnostics.Core.Changes.IChangeJournal>(),
            prefs: sp.GetRequiredService<RemotePCDiagnostics.Core.Preferences.PreferencesService>()));
        // The optional host services pages may use (instead of injecting IServiceProvider).
        services.AddSingleton(sp => new RemotePCDiagnostics.UI.AppServices(sp.GetService<RemediationService>(), sp.GetService<ServiceActionService>(),
            sp.GetService<RemotePCDiagnostics.Core.Optimizations.MemorySuggestionService>(), sp.GetService<RemotePCDiagnostics.Core.Areas.ICopilotHandoff>(),
            sp.GetService<RemotePCDiagnostics.Core.Preferences.PreferencesService>(), sp.GetService<RemotePCDiagnostics.Core.Workflow.WorkflowService>(),
            sp.GetService<PluginRegistrar>(), sp.GetService<IModuleUiFrames>()));
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
        var launcher = new RestrictedModuleHostLauncher(For<RestrictedModuleHostLauncher>(loggers));
        var loader = new ModuleLoader(options ?? new ModuleLoaderOptions { HostVersion = HostVersion() }, plugins, log,
            um => new UserModeModuleProxy(um, launcher, For<UserModeModuleProxy>(loggers)));
        var before = plugins.Records.Count;
        try { loader.LoadBundled(services); }
        catch (Exception ex) { log.Error($"Modules: loading the built-in module DLLs failed: {ex.GetType().Name}: {ex.Message}"); }
        try { loader.LoadAll(services); }
        catch (Exception ex) { log.Error($"Modules: loading plugins failed: {ex.GetType().Name}: {ex.Message}"); }
        LoadJsonChecks(services, plugins, For<RemotePCDiagnostics.Core.Checks.JsonCheckModule>(loggers));
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

    /// <summary>Checks written as data (%ProgramFiles%\RemotePCDiagnostics\checks\*.json): read-only osquery, no code, so they run unsigned.</summary>
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
    public static UndoService CreateUndoService(IChangeJournal journal, SystemCommandRunner commands, IMemorySystem memory,
        ILogger? log, Action<int, RemotePCDiagnostics.Core.Logging.LogLevel, string> logEvent) =>
        new(journal, commands, memory, new WindowsServiceControlBackend(), (level, text) => logEvent(RemotePCDiagnostics.Core.Logging.LogEventIds.Undo, level, text), log,
            new WindowsSystemSettings(log));
}
