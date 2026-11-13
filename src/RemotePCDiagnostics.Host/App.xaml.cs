using System.IO;
using System.Security.Principal;
using System.Windows;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
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
    public const int ExitOk = 0, ExitUndoPartial = 1, ExitAlreadyRunning = 2, ExitNotAdmin = 5;
    private const string InstanceMutexName = @"Global\RemotePCDiagnostics.Host";
    private static Mutex? _instance;

    public static bool IsAdministrator() =>
        RemotePCDiagnostics.Core.Session.ElevationService.DetectProcessElevated();

    public static UndoService CreateUndoService(IChangeJournal journal, SystemCommandRunner commands, RemotePCDiagnostics.Core.Optimizations.IMemorySystem memory) =>
        HostServices.CreateUndoService(journal, commands, memory, HostServices.For<UndoService>(Loggers), Event);

    protected override void OnStartup(StartupEventArgs e)
    {
        // Packaging check: no window, machine scans, journal changes or instance mutex.
        if (e.Args.Contains("--verify-package"))
        {
            var required = new List<string>
            {
                "tools/osquery/osqueryi.exe", "tools/HardeningKitty/HardeningKitty.psd1",
                "tools/HardeningKitty/HardeningKitty.psm1", "RemotePCDiagnostics.MemTest.exe",
                "RemotePCDiagnostics.ModuleHost.exe", "RemotePCDiagnostics.Admin.exe",
                "moduleui/RemotePCDiagnostics.ModuleUiHost.exe",
                "wwwroot/index.html",
            };
            foreach (var stem in new[] { "RemotePCDiagnostics.MemTest", "RemotePCDiagnostics.ModuleHost", "RemotePCDiagnostics.Admin", "moduleui/RemotePCDiagnostics.ModuleUiHost" })
            {
                if (File.Exists(Path.Combine(AppContext.BaseDirectory, stem + ".dll")))
                    required.Add(stem + ".runtimeconfig.json");
            }
            var missing = required.Where(p => !File.Exists(Path.Combine(AppContext.BaseDirectory, p)))
                .Concat(BuiltInModulesPlugin.MissingModuleDlls(RemotePCDiagnostics.Core.Plugins.ModuleLoaderOptions.DefaultBundledFolder())
                    .Select(slug => $"{RemotePCDiagnostics.Core.Plugins.ModuleLoaderOptions.BundledFolderName}/ (module {slug})")).ToArray();
            LogFileOnly($"Package base: {AppContext.BaseDirectory}; missing: {string.Join(", ", missing)}");
            var valid = missing.Length == 0;
            if (valid)
            {
                try
                {
                    var start = new System.Diagnostics.ProcessStartInfo(Path.Combine(AppContext.BaseDirectory, "RemotePCDiagnostics.MemTest.exe"), "--bytes 1048576 --seconds 1")
                    { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true };
                    using var helper = System.Diagnostics.Process.Start(start)!;
                    var output = helper.StandardOutput.ReadToEndAsync();
                    if (!helper.WaitForExit(15000)) { helper.Kill(); valid = false; }
                    else
                    {
                        var done = output.GetAwaiter().GetResult().Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
                            .Select(RemotePCDiagnostics.Core.Stress.MemTestMessage.Parse)
                            .OfType<RemotePCDiagnostics.Core.Stress.MemTestMessage.Done>()
                            .LastOrDefault();
                        valid = helper.ExitCode == 0 && done is { Bytes: 1048576, Passes: > 0, Errors: 0 };
                    }
                }
                catch (Exception ex) { LogFileOnly($"Package helper failed: {ex.Message}"); valid = false; }
            }
            if (valid)
            {
                try
                {
                    var adminStart = new System.Diagnostics.ProcessStartInfo(Path.Combine(AppContext.BaseDirectory, "RemotePCDiagnostics.Admin.exe"), "--self-check")
                    { UseShellExecute = false, CreateNoWindow = true };
                    using var adminHelper = System.Diagnostics.Process.Start(adminStart)!;
                    if (!adminHelper.WaitForExit(10000)) { adminHelper.Kill(); valid = false; }
                    else valid = adminHelper.ExitCode == 0;
                }
                catch (Exception ex) { LogFileOnly($"Admin helper self-check failed: {ex.Message}"); valid = false; }
            }
            Shutdown(valid ? ExitOk : 1);
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

        var isUndoAll = e.Args.Any(a => a.Equals("--undo-all", StringComparison.OrdinalIgnoreCase));

        // Headless --undo-all reverts system-wide changes in ProgramData and requires Administrator privileges.
        if (isUndoAll && !isAdmin)
        {
            Log("--undo-all invoked without administrator rights: requesting elevation");
            if (!TryElevate(e.Args))
            {
                MessageBox.Show(
                    "Reverting system-wide changes (--undo-all) requires administrator privileges.",
                    "Administrator Privileges Required",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
            Shutdown(ExitNotAdmin);
            return;
        }

        // One instance per PC (local window and remote session share it); --undo-all also waits its turn.
        // If an elevated instance already holds Global\RemotePCDiagnostics.Host with an admin-only DACL, opening the mutex from a standard user throws UnauthorizedAccessException.
        var first = false;
        try
        {
            _instance = new Mutex(true, InstanceMutexName, out first);
        }
        catch (UnauthorizedAccessException)
        {
            Log("Another (elevated) instance already owns the instance mutex: exiting");
            if (!isUndoAll) TryActivateExistingWindow();
            Shutdown(ExitAlreadyRunning);
            return;
        }
        // Restarted after the remote user's browser refreshed or elevated relaunch: the old copy is shutting down, so wait for it.
        if (!first && RemotePCDiagnostics.Core.Session.SessionLaunchOptions.IsRestarted(e.Args))
        {
            Log("Restarted: waiting for the previous copy to exit");
            try { first = _instance.WaitOne(RemotePCDiagnostics.Core.Session.SessionLaunchOptions.RestartWait); }
            catch (AbandonedMutexException) { first = true; } // the old copy ended without releasing it: we own it now
        }
        if (!first)
        {
            Log("Another instance is already running: exiting");
            if (!isUndoAll) TryActivateExistingWindow();
            _instance.Dispose();
            _instance = null;
            Shutdown(ExitAlreadyRunning);
            return;
        }

        if (isAdmin)
        {
            // Before anything reads the undo journal, workflow or resume state: secure their folder and move them out of %LOCALAPPDATA%.
            SecureProtectedState();
        }

        if (e.Args.Any(a => a.Equals("--undo-all", StringComparison.OrdinalIgnoreCase)))
        {
            Shutdown(RunUndoAll(restart: e.Args.Any(a => a.Equals("--restart", StringComparison.OrdinalIgnoreCase))));
            return;
        }

        if (isAdmin)
        {
            // One-time history update (event log format 3) before anything else writes events; the marker makes it a no-op afterwards.
            RunStartupMigrations();
        }

        MainWindow = new RemotePCDiagnostics.Host.MainWindow();
        MainWindow.Show();
    }

    private static void SecureProtectedState()
    {
        if (!ProtectedStateFolder.Ensure(Loggers.CreateLogger(typeof(ProtectedStateFolder).FullName!)))
        {
            Event(LogEventIds.Error, LogLevel.Error, $"Remote PC Diagnostics couldn't make {ProtectedState.Folder()} administrator-only. " +
                "Undo, the service workflow and restart resume keep working, but a program without administrator rights may be able to change what they do.");
            return;
        }
        try
        {
            var outcome = new RemotePCDiagnostics.Core.Migrations.ProtectedStateMigration(ProtectedState.LegacyFolder(), ProtectedState.Folder(),
                new RemotePCDiagnostics.Core.Migrations.MigrationMarkers(RemotePCDiagnostics.Core.Migrations.MigrationMarkers.DefaultPath()), HostServices.For<RemotePCDiagnostics.Core.Migrations.ProtectedStateMigration>(Loggers)).Run();
            if (outcome != RemotePCDiagnostics.Core.Migrations.MigrationOutcome.AlreadyDone) Log($"State move to {ProtectedState.Folder()}: {outcome}");
        }
        catch (Exception ex) { Log($"State move to {ProtectedState.Folder()} failed: {ex.Message}"); }
    }

    private static void RunStartupMigrations()
    {
        try
        {
            var outcome = new RemotePCDiagnostics.Core.Migrations.EventLogV3Migration(new WindowsEventLogMigrationIo(HostServices.For<WindowsEventLogMigrationIo>(Loggers)),
                new RemotePCDiagnostics.Core.Migrations.MigrationMarkers(RemotePCDiagnostics.Core.Migrations.MigrationMarkers.DefaultPath()),
                RemotePCDiagnostics.Core.Migrations.EventLogV3Migration.DefaultWorkDir(), HostServices.For<RemotePCDiagnostics.Core.Migrations.EventLogV3Migration>(Loggers)).Run();
            if (outcome != RemotePCDiagnostics.Core.Migrations.MigrationOutcome.AlreadyDone) Log($"History update (event log format 3): {outcome}");
        }
        catch (Exception ex) { Log($"History update (event log format 3) failed: {ex.Message}"); }
        try
        {
            var outcome = new RemotePCDiagnostics.Core.Migrations.EventLogMoveMigration(new WindowsEventLogMoveIo(),
                new RemotePCDiagnostics.Core.Migrations.MigrationMarkers(RemotePCDiagnostics.Core.Migrations.MigrationMarkers.DefaultPath()),
                RemotePCDiagnostics.Core.Migrations.EventLogV3Migration.DefaultWorkDir(), HostServices.For<RemotePCDiagnostics.Core.Migrations.EventLogMoveMigration>(Loggers)).Run();
            if (outcome != RemotePCDiagnostics.Core.Migrations.MigrationOutcome.AlreadyDone) Log($"Event log move to the {EventLogSink.OwnLogName} log: {outcome}");
        }
        catch (Exception ex) { Log($"Event log move failed: {ex.Message}"); }
    }

    /// <summary>
    /// --undo-all: reverts every journaled change without opening the window, logs the result (Event Log 1600 and the file
    /// log), and exits 0 when everything was undone, 1 otherwise. --restart restarts the PC afterwards (10 s) so Fast Startup and
    /// page file changes finish reverting. Saved benchmark results are kept.
    /// </summary>
    private static int RunUndoAll(bool restart)
    {
        try
        {
            var commands = new SystemCommandRunner(log: HostServices.For<SystemCommandRunner>(Loggers));
            var undo = CreateUndoService(new FileChangeJournal(FileChangeJournal.DefaultPath(), HostServices.For<FileChangeJournal>(Loggers)), commands,
                new WindowsMemorySystem(null, HostServices.For<WindowsMemorySystem>(Loggers)));
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

    private static bool TryElevate(string[] args)
    {
        if (args.Any(a => a.Equals("--elevated", StringComparison.OrdinalIgnoreCase))) return false;
        var exe = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(exe)) return false;
        try
        {
            var quotedArgs = string.Join(" ", args.Append("--elevated").Select(a => a.Contains(' ') ? $"\"{a}\"" : a));
            var psi = new System.Diagnostics.ProcessStartInfo(exe, quotedArgs)
            {
                UseShellExecute = true,
                Verb = "runas",
                WorkingDirectory = AppContext.BaseDirectory
            };
            System.Diagnostics.Process.Start(psi);
            return true;
        }
        catch (Exception ex)
        {
            Log($"Elevation declined or failed: {ex.Message}");
            return false;
        }
    }

    private static void TryActivateExistingWindow()
    {
        try
        {
            using var current = System.Diagnostics.Process.GetCurrentProcess();
            foreach (var proc in System.Diagnostics.Process.GetProcessesByName(current.ProcessName))
            {
                using (proc)
                {
                    if (proc.Id == current.Id || proc.MainWindowHandle == IntPtr.Zero) continue;
                    ShowWindowAsync(proc.MainWindowHandle, SwRestore);
                    SetForegroundWindow(proc.MainWindowHandle);
                    return;
                }
            }
        }
        catch { }
    }

    private const int SwRestore = 9;

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);

    protected override void OnExit(ExitEventArgs e)
    {
        Log($"Exit code={e.ApplicationExitCode}");
        Event(LogEventIds.AppExit, LogLevel.Information, $"Remote PC Diagnostics exited (code {e.ApplicationExitCode}).");
        try { _events.Value.Flush(TimeSpan.FromSeconds(1)); _events.Value.Dispose(); } catch { }
        try { _instance?.ReleaseMutex(); _instance?.Dispose(); } catch { }
        base.OnExit(e);
    }
}
