using System.IO;
using System.Security.Principal;
using System.Windows;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Logging;

namespace RemotePCDiagnostics.Host;

public partial class App : Application
{
    private static readonly Lazy<EventLogSink> _events = new(() => new EventLogSink(LogFileOnly));

    /// <summary>Windows Event Log (Application, source RemotePCDiagnostics); never throws or blocks.</summary>
    public static ILogSink Events => _events.Value;

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

    private static void LogFileOnly(string message) =>
        _file.Value.Write($"{DateTimeOffset.Now:O} [{RemotePCDiagnostics.Core.AppBuildInfo.LogStamp}] {message}");

    /// <summary>Process exit codes (also used by --undo-all).</summary>
    public const int ExitOk = 0, ExitUndoPartial = 1, ExitAlreadyRunning = 2, ExitNotAdmin = 5;
    private const string InstanceMutexName = @"Global\RemotePCDiagnostics.Host";
    private static Mutex? _instance;

    public static bool IsAdministrator()
    {
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static UndoService CreateUndoService(IChangeJournal journal, SystemCommandRunner commands, RemotePCDiagnostics.Core.Memory.IMemorySystem memory) =>
        HostServices.CreateUndoService(journal, commands, memory, Log, Event);

    protected override void OnStartup(StartupEventArgs e)
    {
        // Packaging check: no window, machine scans, journal changes or instance mutex.
        if (e.Args.Contains("--verify-package"))
        {
            var required = new[] { "tools/osquery/osqueryi.exe", "tools/HardeningKitty/HardeningKitty.psd1",
                "tools/HardeningKitty/HardeningKitty.psm1", "RemotePCDiagnostics.MemTest.exe",
                "RemotePCDiagnostics.MemTest.runtimeconfig.json", "wwwroot/index.html" };
            var missing = required.Where(p => !File.Exists(Path.Combine(AppContext.BaseDirectory, p))).ToArray();
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
                    else valid = helper.ExitCode == 0 && output.GetAwaiter().GetResult().Contains("MT DONE 1048576 ");
                }
                catch (Exception ex) { LogFileOnly($"Package helper failed: {ex.Message}"); valid = false; }
            }
            Shutdown(valid ? ExitOk : 1);
            return;
        }
        Log($"Startup build={RemotePCDiagnostics.Core.AppBuildInfo.Version} pid={Environment.ProcessId} args={string.Join(' ', e.Args)}");
        DispatcherUnhandledException += (_, ex) => Log($"Unhandled: {ex.Exception}");
        AppDomain.CurrentDomain.UnhandledException += (_, ex) => Log($"Fatal: {ex.ExceptionObject}");
        base.OnStartup(e);

        // Everything this app does needs administrator rights: without them, leave right away (app and --undo-all alike).
        if (!IsAdministrator())
        {
            Log("Not running as administrator: requesting elevation before loading WebView");
            if (!TryElevate(e.Args))
            {
                MessageBox.Show(
                    "Remote PC Diagnostics requires administrator privileges to run.",
                    "Administrator Privileges Required",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
            Shutdown(ExitNotAdmin);
            return;
        }

        // One instance per PC (local window and remote session share it); --undo-all also waits its turn.
        _instance = new Mutex(true, InstanceMutexName, out var first);
        // Restarted after the technician's browser refreshed: the old copy is shutting down, so wait for it.
        if (!first && RemotePCDiagnostics.Core.Session.SessionLaunchOptions.IsRestarted(e.Args))
        {
            Log("Restarted: waiting for the previous copy to exit");
            try { first = _instance.WaitOne(RemotePCDiagnostics.Core.Session.SessionLaunchOptions.RestartWait); }
            catch (AbandonedMutexException) { first = true; } // the old copy ended without releasing it: we own it now
        }
        if (!first) { Log("Another instance is already running: exiting"); _instance.Dispose(); _instance = null; Shutdown(ExitAlreadyRunning); return; }

        if (e.Args.Any(a => a.Equals("--undo-all", StringComparison.OrdinalIgnoreCase)))
        {
            Shutdown(RunUndoAll(restart: e.Args.Any(a => a.Equals("--restart", StringComparison.OrdinalIgnoreCase))));
            return;
        }

        MainWindow = new RemotePCDiagnostics.Host.MainWindow();
        MainWindow.Show();
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
            var commands = new SystemCommandRunner(log: Log);
            var undo = CreateUndoService(new FileChangeJournal(FileChangeJournal.DefaultPath(), Log), commands, new WindowsMemorySystem(null, Log));
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

    protected override void OnExit(ExitEventArgs e)
    {
        Log($"Exit code={e.ApplicationExitCode}");
        Event(LogEventIds.AppExit, LogLevel.Information, $"Remote PC Diagnostics exited (code {e.ApplicationExitCode}).");
        try { _events.Value.Flush(TimeSpan.FromSeconds(1)); _events.Value.Dispose(); } catch { }
        try { _instance?.ReleaseMutex(); _instance?.Dispose(); } catch { }
        base.OnExit(e);
    }
}
