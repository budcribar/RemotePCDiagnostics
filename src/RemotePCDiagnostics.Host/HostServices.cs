using Microsoft.Extensions.DependencyInjection;
using PeakSWC.RemoteBlazorWebView;
using PeakSWC.RemoteWebView;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Memory;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Plugins;
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
    /// <summary>Registers RemoteBlazorWebView and everything the app needs. <paramref name="log"/> is the file log line writer
    /// (<see cref="App.Log"/>); <paramref name="logEvent"/> writes a Windows Event Log entry (<see cref="App.Event"/>).</summary>
    public static IServiceCollection AddRemotePCDiagnosticsHost(this IServiceCollection services, SessionContext session,
        Action<string> log, Action<int, RemotePCDiagnostics.Core.Logging.LogLevel, string> logEvent)
    {
        services.AddRemoteWpfBlazorWebView();
        services.AddSingleton<ISessionContext>(session);
        if (session.Mode == SessionMode.Local) services.AddSingleton<ICopilotHandoff, CopilotHandoff>();
        services.AddSingleton<ResultStore>();
        services.AddSingleton<OsqueryRunner>(_ => new OsqueryRunner(options: new OsqueryOptions { Log = log }));
        // Read-only EC fan diagnostic, active only on Lenovo IdeaPad 1 15ALC7 (82R4) with PawnIO installed.
        services.AddSingleton<IEcFanSource>(_ => LenovoEcFanSource.Create(log));
        services.AddSingleton<ISensorProvider, LhmSensorProvider>();
        services.AddSingleton(new SystemCommandRunner(log: log));
        // One Windows memory/startup adapter for the whole app (undo and memory suggestions share it).
        services.AddSingleton<IMemorySystem>(sp => new WindowsMemorySystem(sp.GetRequiredService<OsqueryRunner>(), log));
        // Last retrim per SSD volume: Windows' Defrag event 258 plus this app's own record (retrim.json), so Drive health only offers it when needed.
        services.AddSingleton(_ => new RetrimLog(RetrimLog.DefaultPath(), log));
        services.AddSingleton<IRetrimHistory>(sp => new RetrimHistory(sp.GetRequiredService<RetrimLog>(), new WindowsRetrimEvents(log), log));
        services.AddSingleton<ServicesModule>();
        // Reversible changes (with their "before" values) for "Undo all changes" / --undo-all; survives restarts.
        services.AddSingleton<RemotePCDiagnostics.Core.Changes.IChangeJournal>(_ => new RemotePCDiagnostics.Core.Changes.FileChangeJournal(RemotePCDiagnostics.Core.Changes.FileChangeJournal.DefaultPath(), log));
        services.AddSingleton(sp => new ServiceActionService(new WindowsServiceControlBackend(), sp.GetRequiredService<ISessionContext>(), log,
            journal: sp.GetRequiredService<RemotePCDiagnostics.Core.Changes.IChangeJournal>()));
        services.AddSingleton(sp => new RebootResumeCoordinator(sp.GetRequiredService<SystemCommandRunner>(), sp.GetRequiredService<OsqueryRunner>(), RebootResumeCoordinator.DefaultStateFilePath(), log: log));
        services.AddSingleton(sp => new RemediationService(sp.GetRequiredService<SystemCommandRunner>(), sp.GetRequiredService<ISessionContext>(), log, sp.GetRequiredService<RebootResumeCoordinator>(),
            sp.GetRequiredService<RemotePCDiagnostics.Core.Changes.IChangeJournal>(), sp.GetRequiredService<RetrimLog>()));
        services.AddSingleton(sp => CreateUndoService(sp.GetRequiredService<RemotePCDiagnostics.Core.Changes.IChangeJournal>(), sp.GetRequiredService<SystemCommandRunner>(),
            sp.GetRequiredService<IMemorySystem>(), log, logEvent));
        // Audio tests (speaker→mic, mic→speaker): on-demand only, own pages, not part of Run All or the stress run.
        services.AddSingleton<RemotePCDiagnostics.Core.Audio.IAudioIo>(_ => new WasapiAudioIo(log));
        // NPU test: on-demand only, own page, not part of Run All or the stress run.
        services.AddSingleton<RemotePCDiagnostics.Core.Npu.INpuIo>(_ => new WindowsNpuIo(log));
        // Every built-in module goes through the same registration path a plugin uses.
        var plugins = new PluginRegistrar(session, HostVersion(), log);
        services.AddSingleton(plugins);
        plugins.Register(services, new BuiltInModulesPlugin(log), BuiltInModulesPlugin.Id, ModuleSource.BuiltIn);
        // Module DLLs from %ProgramFiles%\RemotePCDiagnostics\modules (signed ones load in-process; unsigned ones never do).
        services.AddSingleton(LoadModulePlugins(services, plugins, log, logEvent, new ModuleLoaderOptions
        {
            HostVersion = HostVersion(),
            // Only the person at the PC can turn unsigned modules on (a marker in the admin-only modules folder); never in a remote session.
            AllowUnsigned = session.Mode == SessionMode.Local && UnsignedModulesSetting.IsOn(),
        }));
        // Unsigned modules' own UIs, framed on the module page (Local only, like unsigned modules themselves).
        if (session.Mode == SessionMode.Local)
            services.AddSingleton<IModuleUiFrames>(_ =>
            {
                var frames = new ModuleUiFrames(log);
                AppDomain.CurrentDomain.ProcessExit += (_, _) => frames.Dispose(); // the UI processes never outlive the app
                return frames;
            });
        services.AddSingleton(sp =>
        {
            var diag = new DiagnosticsService(sp.GetRequiredService<ResultStore>(), sp.GetServices<IDiagnosticModule>());
            diag.Log = log;
            sp.GetRequiredService<PluginRegistrar>().ApplyTo(diag.Catalog); // where each module came from, its details UI
            diag.RejectDependencyCycles(); // now that plugin DependsOn / RunAfter are known
            return diag;
        });
        services.AddSingleton(new RemotePCDiagnostics.Core.Preferences.PreferencesService(
            new RemotePCDiagnostics.Core.Preferences.FilePreferencesStore(RemotePCDiagnostics.Core.Preferences.FilePreferencesStore.DefaultPath(), log)));
        services.AddSingleton(sp => new ChecksScreenState(sp.GetRequiredService<DiagnosticsService>(), sp.GetRequiredService<ResultStore>(),
            sp.GetRequiredService<RemotePCDiagnostics.Core.Preferences.PreferencesService>(),
            sp.GetRequiredService<RemotePCDiagnostics.Core.Memory.MemorySuggestionService>()));
        services.AddSingleton(sp => new RemotePCDiagnostics.Core.Memory.MemorySuggestionService(
            sp.GetRequiredService<IMemorySystem>(), sp.GetRequiredService<ServicesModule>(), sp.GetRequiredService<ServiceActionService>(),
            sp.GetRequiredService<ISessionContext>(), (level, text) => logEvent(RemotePCDiagnostics.Core.Logging.LogEventIds.MemorySuggestion, level, text), log,
            remediation: sp.GetRequiredService<RemediationService>(), journal: sp.GetRequiredService<RemotePCDiagnostics.Core.Changes.IChangeJournal>()));
        // Before/after performance benchmarks (state saved so the "before" survives a restart; event 1500).
        services.AddSingleton(sp => new RemotePCDiagnostics.Core.Benchmarks.BenchmarkService(
            new RemotePCDiagnostics.Core.Benchmarks.BenchmarkRunner(new WindowsBenchmarkProbes(sp.GetRequiredService<SystemCommandRunner>(), sp.GetRequiredService<ISensorProvider>(), log), log),
            new RemotePCDiagnostics.Core.Benchmarks.FileBenchmarkStore(RemotePCDiagnostics.Core.Benchmarks.FileBenchmarkStore.DefaultPath(), log),
            sp.GetRequiredService<RemediationService>(), sp.GetRequiredService<ISessionContext>(),
            (level, text) => logEvent(RemotePCDiagnostics.Core.Logging.LogEventIds.Benchmark, level, text), log));
        // Service workflow: checks → tech review → restart → before benchmark → fixes → restart → after benchmark → report.
        services.AddSingleton(sp => new RemotePCDiagnostics.Core.Workflow.WorkflowService(
            sp.GetRequiredService<DiagnosticsService>(), sp.GetRequiredService<ResultStore>(), sp.GetRequiredService<RemediationService>(),
            sp.GetRequiredService<RemotePCDiagnostics.Core.Benchmarks.BenchmarkService>(),
            new WindowsWorkflowSystem(sp.GetRequiredService<SystemCommandRunner>(), sp.GetRequiredService<ISessionContext>(), log),
            new RemotePCDiagnostics.Core.Workflow.FileWorkflowStore(RemotePCDiagnostics.Core.Workflow.FileWorkflowStore.DefaultPath(), log),
            sp.GetRequiredService<RemotePCDiagnostics.Core.Memory.MemorySuggestionService>(), sp.GetRequiredService<ISessionContext>(),
            (level, text) => logEvent(RemotePCDiagnostics.Core.Logging.LogEventIds.Workflow, level, text), log,
            journal: sp.GetRequiredService<RemotePCDiagnostics.Core.Changes.IChangeJournal>(),
            prefs: sp.GetRequiredService<RemotePCDiagnostics.Core.Preferences.PreferencesService>()));
        // The optional host services pages may use (instead of injecting IServiceProvider).
        services.AddSingleton(sp => new RemotePCDiagnostics.UI.AppServices(sp.GetService<RemediationService>(), sp.GetService<ServiceActionService>(),
            sp.GetService<RemotePCDiagnostics.Core.Memory.MemorySuggestionService>(), sp.GetService<RemotePCDiagnostics.Core.Areas.ICopilotHandoff>(),
            sp.GetService<RemotePCDiagnostics.Core.Preferences.PreferencesService>(), sp.GetService<RemotePCDiagnostics.Core.Workflow.WorkflowService>(),
            sp.GetService<PluginRegistrar>()));
        // History page reads past results (event 1100) back from the Windows Event Log.
        services.AddSingleton<RemotePCDiagnostics.Core.History.IHistoryStore>(_ => EventLogHistorySource.Create(log));
        return services;
    }

    /// <summary>Discovers, verifies and registers module plugins. Never throws: a broken modules folder leaves only the built-ins.</summary>
    public static ModuleLoader LoadModulePlugins(IServiceCollection services, PluginRegistrar plugins, Action<string> log,
        Action<int, RemotePCDiagnostics.Core.Logging.LogLevel, string> logEvent, ModuleLoaderOptions? options = null)
    {
        var launcher = new RestrictedModuleHostLauncher(log);
        var loader = new ModuleLoader(options ?? new ModuleLoaderOptions { HostVersion = HostVersion() }, plugins, log,
            um => new UserModeModuleProxy(um, launcher, log));
        var before = plugins.Records.Count;
        try { loader.LoadAll(services); }
        catch (Exception ex) { log($"Modules: loading plugins failed: {ex.GetType().Name}: {ex.Message}"); }
        LoadJsonChecks(services, plugins, log);
        foreach (var r in plugins.Records.Skip(before))
        {
            var text = $"Module plugin: {r.PluginId}{Environment.NewLine}Module id: {r.ModuleId}{Environment.NewLine}Version: {r.Version}{Environment.NewLine}" +
                $"Signature: {r.Signature}{Environment.NewLine}State: {r.State}{(r.Reason is null ? "" : Environment.NewLine + "Reason: " + r.Reason)}{Environment.NewLine}Path: {r.Path}";
            try { logEvent(RemotePCDiagnostics.Core.Logging.LogEventIds.ModulePlugin,
                r.State == PluginState.Loaded || r.UserMode ? RemotePCDiagnostics.Core.Logging.LogLevel.Information : RemotePCDiagnostics.Core.Logging.LogLevel.Warning, text); }
            catch { }
        }
        return loader;
    }

    /// <summary>Checks written as data (%ProgramFiles%\RemotePCDiagnostics\checks\*.json): read-only osquery, no code, so they run unsigned.</summary>
    public static void LoadJsonChecks(IServiceCollection services, PluginRegistrar plugins, Action<string> log, string? folder = null)
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
        catch (Exception ex) { log($"Checks: loading JSON checks failed: {ex.Message}"); }
    }

    /// <summary>The app's version as a <see cref="Version"/> (for a plugin's minHost check).</summary>
    public static Version HostVersion() => Version.TryParse(AppBuildInfo.Release, out var v) ? v : new Version(0, 0);

    /// <summary>The undo service, shared by the window (via the container) and the headless --undo-all run.</summary>
    public static UndoService CreateUndoService(IChangeJournal journal, SystemCommandRunner commands, IMemorySystem memory,
        Action<string> log, Action<int, RemotePCDiagnostics.Core.Logging.LogLevel, string> logEvent) =>
        new(journal, commands, memory, new WindowsServiceControlBackend(), (level, text) => logEvent(RemotePCDiagnostics.Core.Logging.LogEventIds.Undo, level, text), log);
}
