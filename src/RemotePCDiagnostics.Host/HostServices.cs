using Microsoft.Extensions.DependencyInjection;
using PeakSWC.RemoteBlazorWebView;
using PeakSWC.RemoteWebView;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Memory;
using RemotePCDiagnostics.Core.Osquery;
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
        services.AddSingleton<IDiagnosticModule, OsqueryModule>();
        // Read-only EC fan diagnostic, active only on Lenovo IdeaPad 1 15ALC7 (82R4) with PawnIO installed.
        services.AddSingleton<IEcFanSource>(_ => LenovoEcFanSource.Create(log));
        services.AddSingleton<ISensorProvider, LhmSensorProvider>();
        services.AddSingleton<IDiagnosticModule, LibreHardwareMonitorModule>();
        // On demand only: not auto-run and excluded from Run All; runs when the user presses Start on its page.
        services.AddSingleton<IDiagnosticModule>(sp => new CpuStressModule(sp.GetRequiredService<ISensorProvider>(), log, ecFan: sp.GetRequiredService<IEcFanSource>()));
        services.AddSingleton<IDiagnosticModule>(sp => new DiskSpeedModule(new PhysicalDiskTestFileSystem(log), sp.GetRequiredService<ISensorProvider>(), log));
        services.AddSingleton<IDiagnosticModule>(sp => new MemoryTestModule(new SystemMemoryInfo(), new ProcessMemTestHelperLauncher(log: log),
            sp.GetRequiredService<ISensorProvider>(), new MdschedLauncher(log), log));
        services.AddSingleton(new SystemCommandRunner(log: log));
        // One Windows memory/startup adapter for the whole app (undo and memory suggestions share it).
        services.AddSingleton<IMemorySystem>(sp => new WindowsMemorySystem(sp.GetRequiredService<OsqueryRunner>(), log));
        services.AddSingleton<IDiagnosticModule>(sp =>
        {
            var settings = NetworkTestSettings.FromEnvironment(Environment.GetEnvironmentVariable);
            return new NetworkTestModule(new SystemPinger(), new SystemGatewayResolver(), new HttpSpeedTester(settings, log: log),
                new SystemAdapterCounters(sp.GetRequiredService<SystemCommandRunner>()), sp.GetRequiredService<ISensorProvider>(), settings, log);
        });
        services.AddSingleton<IDiagnosticModule>(sp => new GpuStressModule(new RemotePCDiagnostics.Host.Gpu.D3D11GpuDeviceFactory(log), sp.GetRequiredService<ISensorProvider>(), log));
        // Last retrim per SSD volume: Windows' Defrag event 258 plus this app's own record (retrim.json), so Drive health only offers it when needed.
        services.AddSingleton(_ => new RetrimLog(RetrimLog.DefaultPath(), log));
        services.AddSingleton<IRetrimHistory>(sp => new RetrimHistory(sp.GetRequiredService<RetrimLog>(), new WindowsRetrimEvents(log), log));
        services.AddSingleton<IDiagnosticModule>(sp => new DriveHealthModule(sp.GetRequiredService<SystemCommandRunner>(), sp.GetRequiredService<OsqueryRunner>(), sp.GetRequiredService<IRetrimHistory>()));
        services.AddSingleton<ServicesModule>();
        services.AddSingleton<IDiagnosticModule>(sp => sp.GetRequiredService<ServicesModule>());
        // Reversible changes (with their "before" values) for "Undo all changes" / --undo-all; survives restarts.
        services.AddSingleton<RemotePCDiagnostics.Core.Changes.IChangeJournal>(_ => new RemotePCDiagnostics.Core.Changes.FileChangeJournal(RemotePCDiagnostics.Core.Changes.FileChangeJournal.DefaultPath(), log));
        services.AddSingleton(sp => new ServiceActionService(new WindowsServiceControlBackend(), sp.GetRequiredService<ISessionContext>(), log,
            journal: sp.GetRequiredService<RemotePCDiagnostics.Core.Changes.IChangeJournal>()));
        services.AddSingleton(sp => new RebootResumeCoordinator(sp.GetRequiredService<SystemCommandRunner>(), sp.GetRequiredService<OsqueryRunner>(), RebootResumeCoordinator.DefaultStateFilePath(), log: log));
        services.AddSingleton(sp => new RemediationService(sp.GetRequiredService<SystemCommandRunner>(), sp.GetRequiredService<ISessionContext>(), log, sp.GetRequiredService<RebootResumeCoordinator>(),
            sp.GetRequiredService<RemotePCDiagnostics.Core.Changes.IChangeJournal>(), sp.GetRequiredService<RetrimLog>()));
        services.AddSingleton(sp => CreateUndoService(sp.GetRequiredService<RemotePCDiagnostics.Core.Changes.IChangeJournal>(), sp.GetRequiredService<SystemCommandRunner>(),
            sp.GetRequiredService<IMemorySystem>(), log, logEvent));
        services.AddSingleton<IDiagnosticModule, ProgramsModule>(sp => new ProgramsModule(sp.GetRequiredService<OsqueryRunner>()));
        services.AddSingleton<IDiagnosticModule, NetworkModule>(sp => new NetworkModule(sp.GetRequiredService<OsqueryRunner>(), sp.GetRequiredService<SystemCommandRunner>(), includeWifiAndIpConfig: true));
        services.AddSingleton<IDiagnosticModule>(sp => new EventLogModule(sp.GetRequiredService<SystemCommandRunner>(), excludeCrashEvents: true));
        services.AddSingleton<IDiagnosticModule>(sp => new CrashesModule(sp.GetRequiredService<SystemCommandRunner>(), includeSystemCrashes: true));
        services.AddSingleton<IDiagnosticModule>(sp => new ResourceHogsModule(sp.GetRequiredService<OsqueryRunner>(), sp.GetRequiredService<SystemCommandRunner>()));
        services.AddSingleton<IDiagnosticModule>(sp => new DeviceDriversModule(sp.GetRequiredService<OsqueryRunner>(), sp.GetRequiredService<SystemCommandRunner>()));
        services.AddSingleton<IDiagnosticModule>(sp => new DismScanHealthModule(sp.GetRequiredService<SystemCommandRunner>()));
        services.AddSingleton<IDiagnosticModule>(sp => new SfcVerifyOnlyModule(sp.GetRequiredService<SystemCommandRunner>()));

        services.AddSingleton<IDiagnosticModule>(sp => new BatteryPowerModule(sp.GetRequiredService<OsqueryRunner>(), sp.GetRequiredService<SystemCommandRunner>()));

        // On-demand only (Start button on its page): not in AutoRun below and excluded from Run All (IncludeInRunAll=false).
        services.AddSingleton<IDiagnosticModule>(new SecurityAuditModule(new SecurityAuditOptions { Log = log }));
        // Audio tests (speaker→mic, mic→speaker): on-demand only, own pages, not part of Run All or the stress run.
        services.AddSingleton<RemotePCDiagnostics.Core.Audio.IAudioIo>(_ => new WasapiAudioIo(log));
        services.AddSingleton<IDiagnosticModule>(sp => new RemotePCDiagnostics.Core.Audio.SpeakerToMicModule(sp.GetRequiredService<RemotePCDiagnostics.Core.Audio.IAudioIo>(), log));
        services.AddSingleton<IDiagnosticModule>(sp => new RemotePCDiagnostics.Core.Audio.MicToSpeakerModule(sp.GetRequiredService<RemotePCDiagnostics.Core.Audio.IAudioIo>(), log));
        // Webcam test: on-demand only, own page, not part of Run All or the stress run. Frames are analysed in memory only.
        services.AddSingleton<IDiagnosticModule>(new RemotePCDiagnostics.Core.Webcam.WebcamTestModule(new MediaCaptureWebcamIo(log, showPreview: session.Mode == SessionMode.Local), log));
        // NPU test: on-demand only, own page, not part of Run All or the stress run.
        services.AddSingleton<RemotePCDiagnostics.Core.Npu.INpuIo>(_ => new WindowsNpuIo(log));
        services.AddSingleton<IDiagnosticModule>(sp => new RemotePCDiagnostics.Core.Npu.NpuTestModule(sp.GetRequiredService<RemotePCDiagnostics.Core.Npu.INpuIo>(), log));
        services.AddSingleton(sp =>
        {
            var diag = new DiagnosticsService(sp.GetRequiredService<ResultStore>(), sp.GetServices<IDiagnosticModule>());
            RemotePCDiagnostics.UI.BuiltInModuleUi.Register(diag.Catalog); // each built-in module's own details UI
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
            sp.GetService<RemotePCDiagnostics.Core.Preferences.PreferencesService>(), sp.GetService<RemotePCDiagnostics.Core.Workflow.WorkflowService>()));
        // History page reads past results (event 1100) back from the Windows Event Log.
        services.AddSingleton<RemotePCDiagnostics.Core.History.IHistoryStore>(_ => EventLogHistorySource.Create(log));
        return services;
    }

    /// <summary>The undo service, shared by the window (via the container) and the headless --undo-all run.</summary>
    public static UndoService CreateUndoService(IChangeJournal journal, SystemCommandRunner commands, IMemorySystem memory,
        Action<string> log, Action<int, RemotePCDiagnostics.Core.Logging.LogLevel, string> logEvent) =>
        new(journal, commands, memory, new WindowsServiceControlBackend(), (level, text) => logEvent(RemotePCDiagnostics.Core.Logging.LogEventIds.Undo, level, text), log);
}
