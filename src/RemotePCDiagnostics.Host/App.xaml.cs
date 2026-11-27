using System.IO;
using System.Security.Principal;
using System.Windows;
using RemotePCDiagnostics.Agent.Core;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Logging;

namespace RemotePCDiagnostics.Host;

public partial class App : Application
{
    private static readonly Lazy<EventLogSink> _events = new(() => new EventLogSink(LogFileOnly));

    /// <summary>Windows Event Log (the app's own log, source RemotePCDiagnostics); never throws or blocks.</summary>
    public static ILogSink Events => _events.Value;

    /// <summary>Writes a session audit entry (events 2000-2006) to the event log and the same text to the file log. Never throws or blocks.</summary>
    public static void Audit(LogEntry entry)
    {
        LogFileOnly($"[audit {entry.EventId}] {entry.Message.Replace(Environment.NewLine, " | ")}");
        try { Events.Write(entry); } catch { }
    }

    /// <summary>File log: on by default at %LOCALAPPDATA%\RemotePCDiagnostics\logs\RemotePCDiagnostics.log (rolls at 5 MB, keeps 5 older files).
    /// Setting RPD_LOG_FILE sends it to that path instead, without rolling (CI).</summary>
    private static readonly Lazy<RollingFileLog> _file = new(() =>
        Environment.GetEnvironmentVariable("RPD_LOG_FILE") is { Length: > 0 } p ? new RollingFileLog(p, long.MaxValue) : new RollingFileLog(RollingFileLog.DefaultPath()));
    private static readonly EventLogGate _gate = new();

    /// <summary>Where the log file is written.</summary>
    public static string LogFilePath => _file.Value.Path;

    /// <summary>Writes the line to the log file. Selected lines (fan diagnostic, sensor driver, stress suite, crashes) also go to the Windows Event Log,
    /// and so does any other line that reads as a warning or error (rate-limited, so a repeating problem can't flood it).</summary>
    public static void Log(string message)
    {
        LogFileOnly(message);
        try
        {
            if (LogText.Route(message) is { } e) { Events.Write(e); return; }
            var level = LogLevels.Classify(message);
            if (level != LogLevel.Information && _gate.Allow(message))
                Events.Write(new LogEntry(level == LogLevel.Error ? LogEventIds.Error : LogEventIds.AppWarning, level, message));
        }
        catch { }
    }

    /// <summary>Writes an event (and the same text to the file log).</summary>
    public static void Event(int id, LogLevel level, string message)
    {
        LogFileOnly($"[event {id}] {message.Replace(Environment.NewLine, " | ")}");
        try { Events.Write(new LogEntry(id, level, message)); } catch { }
    }

    /// <summary>
    /// ILogger&lt;T&gt; for the app (registered by <see cref="HostServices"/>): each line carries its level and category, so warnings and
    /// errors reach the Event Log (rate-limited) without guessing from the wording.
    /// </summary>
    public static Microsoft.Extensions.Logging.ILoggerFactory Loggers { get; } = new AppLoggerFactory(Write);

    /// <summary>Writes an ILogger line: file log with level and category; warnings and errors also to the Event Log.</summary>
    public static void Write(LogLevel level, string category, string message)
    {
        var line = $"[{AppLoggerFactory.ShortName(category)}] {message}";
        LogFileOnly(level == LogLevel.Information ? line : $"{level.ToString().ToUpperInvariant()} {line}");
        try
        {
            if (LogText.Route(message) is { } e) { Events.Write(e with { Message = line }); return; }
            if (level != LogLevel.Information && _gate.Allow(line))
                Events.Write(new LogEntry(level == LogLevel.Error ? LogEventIds.Error : LogEventIds.AppWarning, level, line));
        }
        catch { }
    }

    private static void LogFileOnly(string message) =>
        _file.Value.Write($"{DateTimeOffset.Now:O} [{RemotePCDiagnostics.Core.AppBuildInfo.LogStamp}] {message}");

    /// <summary>Process exit codes (also used by --undo-all).</summary>
    public const int ExitOk = 0, ExitUndoPartial = 1, ExitAlreadyRunning = 2, ExitNotAdmin = 5; // 5: --undo-all couldn't start the Agent
    private const string InstanceMutexName = @"Global\RemotePCDiagnostics.Host";
    private static Mutex? _instance;

    private static bool TryAcquireInstanceMutex(string[] args, out bool unauthorized)
    {
        unauthorized = false;
        var first = false;
        try
        {
            _instance = new Mutex(true, InstanceMutexName, out first);
        }
        catch (UnauthorizedAccessException)
        {
            unauthorized = true;
            return false;
        }
        // Restarted after the remote user's browser refreshed or elevated relaunch: the old copy is shutting down, so wait for it.
        if (!first && RemotePCDiagnostics.Core.Session.SessionLaunchOptions.IsRestarted(args))
        {
            Log("Restarted: waiting for the previous copy to exit");
            try { first = _instance.WaitOne(RemotePCDiagnostics.Core.Session.SessionLaunchOptions.RestartWait); }
            catch (AbandonedMutexException) { first = true; } // the old copy ended without releasing it: we own it now
        }
        if (!first)
        {
            _instance.Dispose();
            _instance = null;
        }
        return first;
    }

    public static bool IsAdministrator() =>
        RemotePCDiagnostics.Core.Session.ElevationService.DetectProcessElevated();

    public static UndoService CreateUndoService(IChangeJournal journal, SystemCommandRunner commands, RemotePCDiagnostics.Core.Optimizations.IMemorySystem memory,
        RemotePCDiagnostics.Core.Session.IAdminSettingsBackend admin) =>
        HostServices.CreateUndoService(journal, commands, memory, admin, HostServices.For<UndoService>(Loggers), Event);

    protected override void OnStartup(StartupEventArgs e)
    {
        StartupProfiler.LogAction = LogFileOnly;
        if (e.Args.Contains("--benchmark-startup")) StartupProfiler.IsEnabled = true;
        if (e.Args.Contains("--benchmark-exit")) Environment.SetEnvironmentVariable("RPD_BENCHMARK_EXIT", "1");
        StartupProfiler.Mark("App.OnStartup");

        // Packaging check: no window, machine scans, journal changes or instance mutex.
        if (e.Args.Contains("--verify-package"))
        {
            var code = PackageVerifier.Run(AppContext.BaseDirectory, LogFileOnly);
            var modulesMissing = BuiltInModulesPlugin.MissingModuleDlls(RemotePCDiagnostics.Core.Plugins.ModuleLoaderOptions.DefaultBundledFolder())
                .Select(slug => $"{RemotePCDiagnostics.Core.Plugins.ModuleLoaderOptions.BundledFolderName}/ (module {slug})").ToArray();
            if (modulesMissing.Length > 0)
            {
                LogFileOnly($"Package check 'bundled modules' failed. Expected every built-in module DLL. Found missing: {string.Join(", ", modulesMissing)}.");
                code = 1;
            }
            Shutdown(code == 0 ? ExitOk : 1);
            return;
        }
        var isAdmin = IsAdministrator();
        Log($"Startup build={RemotePCDiagnostics.Core.AppBuildInfo.Version} pid={Environment.ProcessId} elevated={isAdmin} args={string.Join(' ', e.Args)}");
        DispatcherUnhandledException += (_, ex) =>
        {
            Log($"Unhandled: {ex.Exception}");
            if (Current?.MainWindow is RemotePCDiagnostics.Host.MainWindow mw && mw.TryHandleRemoteStartupException(ex.Exception))
                ex.Handled = true;
        };
        AppDomain.CurrentDomain.UnhandledException += (_, ex) => Log($"Fatal: {ex.ExceptionObject}");
        base.OnStartup(e);

        // Headless --undo-all runs un-elevated like the rest of the app: the Agent reads the undo journal and does the admin work.
        var isUndoAll = e.Args.Any(a => a.Equals("--undo-all", StringComparison.OrdinalIgnoreCase));

        // One instance per PC (local window and remote session share it); --undo-all also waits its turn.
        // If an elevated instance already holds Global\RemotePCDiagnostics.Host with an admin-only DACL, opening the mutex from a standard user throws UnauthorizedAccessException.
        if (!TryAcquireInstanceMutex(e.Args, out var unauthorized))
        {
            Log(unauthorized
                ? "Another (elevated) instance already owns the instance mutex: exiting"
                : "Another instance is already running: exiting");
            if (!isUndoAll) TryActivateExistingWindow();
            Shutdown(ExitAlreadyRunning);
            return;
        }

        if (e.Args.Any(a => a.Equals("--undo-all", StringComparison.OrdinalIgnoreCase)))
        {
            Shutdown(RunUndoAll(restart: e.Args.Any(a => a.Equals("--restart", StringComparison.OrdinalIgnoreCase))));
            return;
        }

        // A later launch (desktop icon, Start menu) exits at once; it signals this copy to come to the front instead.
        InstanceActivation.Listen(() => Dispatcher.BeginInvoke(() => (MainWindow as RemotePCDiagnostics.Host.MainWindow)?.BringToFront()));
        var window = new RemotePCDiagnostics.Host.MainWindow();
        MainWindow = window;
        StartupProfiler.Mark("MainWindowCreated");
        if (window.StartsHidden) window.ShowHidden();
        else window.Show();
        StartupProfiler.Mark("MainWindowShown");
    }

    private static int _machineSetupDone;

    /// <summary>
    /// The administrator-only setup the app needs, done by the Agent once it is connected: securing the state folder and registering
    /// the Event Log source. Asked again on the next connection until it is all done.
    /// </summary>
    public static async Task PrepareMachineThroughAgentAsync(RemotePCDiagnostics.Core.Session.IElevatedCommandBridge agent)
    {
        if (Volatile.Read(ref _machineSetupDone) != 0) return;
        RemotePCDiagnostics.Core.Session.MachineSetupResult? setup;
        try { setup = await agent.PrepareMachineAsync().ConfigureAwait(false); }
        catch (Exception ex) { Log($"Machine setup through the Agent failed: {ex.Message}"); return; }
        if (setup is null) return;
        Log($"Machine setup (Agent): state folder secured={setup.StateFolderSecured}, event source={setup.EventSourceReady}");
        if (setup.EventSourceReady && _events.IsValueCreated) _events.Value.SourceRegistered();
        if (!setup.StateFolderSecured)
            Event(LogEventIds.Error, LogLevel.Error, $"Remote PC Diagnostics couldn't make {ProtectedState.Folder()} administrator-only. " +
                "Undo, the service workflow and restart resume keep working, but a program without administrator rights may be able to change what they do.");
        if (setup.Done) Volatile.Write(ref _machineSetupDone, 1);
    }

    /// <summary>
    /// --undo-all: reverts every journaled change without opening the window, logs the result (Event Log 1600 and the file
    /// log), and exits 0 when everything was undone, 1 otherwise. --restart restarts the PC afterwards (10 s) so Fast Startup and
    /// page file changes finish reverting. Saved benchmark results are kept.
    /// The app stays un-elevated: it starts the Agent (one UAC prompt, for the Agent), which reads the journal from the
    /// administrator-only state folder, takes undone changes off it and runs the admin commands. Exits 5 when the Agent didn't start.
    /// </summary>
    private static int RunUndoAll(bool restart)
    {
        try
        {
            using var agent = new ElevationService(new SessionContext(SessionMode.Local), HostServices.For<ElevationService>(Loggers));
            var started = Task.Run(() => agent.EnableAdminModeAsync()).GetAwaiter().GetResult();
            var journal = agent.IsAdminHelperConnected
                ? Task.Run(() => AgentChangeJournal.LoadAsync(agent, HostServices.For<AgentChangeJournal>(Loggers))).GetAwaiter().GetResult()
                : null;
            if (journal is null)
            {
                var why = !agent.IsAdminHelperConnected
                    ? (started.Cancelled ? "Administrator approval for the Agent was cancelled." : started.Message)
                    : "The Agent on this PC can't read the undo list. Update Remote PC Diagnostics, then try again.";
                Log("--undo-all: nothing undone. " + why);
                MessageBox.Show($"Remote PC Diagnostics didn't undo any changes. {why}\n\nUndoing changes needs the Agent, which asks for administrator approval when it starts. Run --undo-all again and approve the prompt.",
                    "Remote PC Diagnostics", MessageBoxButton.OK, MessageBoxImage.Warning);
                return ExitNotAdmin;
            }
            var commands = new SystemCommandRunner(log: HostServices.For<SystemCommandRunner>(Loggers), elevatedBridge: agent, isProcessElevated: () => false);
            var admin = new AgentAdminSettings(agent);
            var machine = new AgentMachineTweaks(agent, HostServices.For<AgentMachineTweaks>(Loggers));
            var undo = CreateUndoService(journal, commands, new WindowsMemorySystem(HostServices.For<WindowsMemorySystem>(Loggers), admin, machine), admin);
            var result = Task.Run(() => undo.UndoAllAsync("Command line (--undo-all)")).GetAwaiter().GetResult();
            Log("--undo-all: " + result.Summary);
            foreach (var i in result.Items) Log($"--undo-all: {(i.Success ? "OK" : i.Skipped ? "LEFT AS IS (permanent)" : "FAILED")} {i.Change.Kind} '{i.Change.Target}': {i.Message}");
            if (restart)
            {
                Log("--undo-all: restarting in 10 seconds");
                Task.Run(() => commands.RunAsync(SystemCommandRunner.SystemTool("shutdown.exe"), ["/r", "/t", "10", "/c", "Remote PC Diagnostics: restarting to finish undoing changes."], CancellationToken.None)).GetAwaiter().GetResult();
            }
            return result.Failed == 0 ? ExitOk : ExitUndoPartial;
        }
        catch (Exception ex) { Log("--undo-all failed: " + ex); return ExitUndoPartial; }
    }

    /// <summary>Asks the running copy to restore, maximize and come to the front. Falls back to doing it from here for a running copy too old to listen,
    /// which Windows' foreground lock often turns into a flashing taskbar button.</summary>
    private static void TryActivateExistingWindow()
    {
        if (InstanceActivation.SignalRunningCopy())
        {
            Log("Asked the running copy to come to the front");
            return;
        }
        try
        {
            using var current = System.Diagnostics.Process.GetCurrentProcess();
            foreach (var proc in System.Diagnostics.Process.GetProcessesByName(current.ProcessName))
            {
                using (proc)
                {
                    if (proc.Id == current.Id || proc.MainWindowHandle == IntPtr.Zero) continue;
                    ShowWindowAsync(proc.MainWindowHandle, SwMaximize);
                    SetForegroundWindow(proc.MainWindowHandle);
                    return;
                }
            }
        }
        catch { }
    }

    private const int SwMaximize = 3;

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);

    public static void ReleaseInstance()
    {
        InstanceActivation.Stop();
        try { _instance?.ReleaseMutex(); _instance?.Dispose(); _instance = null; } catch { }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        ActiveSessionInfo.TryDelete(expectedProcessId: Environment.ProcessId);
        Log($"Exit code={e.ApplicationExitCode}");
        Event(LogEventIds.AppExit, LogLevel.Information, $"Remote PC Diagnostics exited (code {e.ApplicationExitCode}).");
        try { _events.Value.Flush(TimeSpan.FromSeconds(1)); _events.Value.Dispose(); } catch { }
        ReleaseInstance();
        base.OnExit(e);
    }
}
