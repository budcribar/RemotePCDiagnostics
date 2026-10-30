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

    /// <summary>Optional file log, enabled by setting RPD_LOG_FILE (used by CI). Selected lines (fan diagnostic,
    /// sensor driver, stress suite, crashes) also go to the Windows Event Log.</summary>
    public static void Log(string message)
    {
        LogFileOnly(message);
        try { if (LogText.Route(message) is { } e) Events.Write(e); } catch { }
    }

    /// <summary>Writes an event (and the same text to the file log).</summary>
    public static void Event(int id, LogLevel level, string message)
    {
        LogFileOnly($"[event {id}] {message.Replace(Environment.NewLine, " | ")}");
        try { Events.Write(new LogEntry(id, level, message)); } catch { }
    }

    private static readonly object _fileGate = new();
    private static void LogFileOnly(string message)
    {
        var path = Environment.GetEnvironmentVariable("RPD_LOG_FILE");
        if (string.IsNullOrEmpty(path)) return;
        try { lock (_fileGate) File.AppendAllText(path, $"{DateTimeOffset.Now:O} {message}{Environment.NewLine}"); } catch { }
    }

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
        new(journal, commands, memory, new WindowsServiceControlBackend(), (level, text) => Event(LogEventIds.Undo, level, text), Log);

    protected override void OnStartup(StartupEventArgs e)
    {
        Log($"Startup pid={Environment.ProcessId} args={string.Join(' ', e.Args)}");
        DispatcherUnhandledException += (_, ex) => Log($"Unhandled: {ex.Exception}");
        AppDomain.CurrentDomain.UnhandledException += (_, ex) => Log($"Fatal: {ex.ExceptionObject}");
        base.OnStartup(e);

        // Everything this app does needs administrator rights: without them, leave right away (app and --undo-all alike).
        if (!IsAdministrator()) { Log("Not running as administrator: exiting"); Shutdown(ExitNotAdmin); return; }

        // One instance per PC (local window and remote session share it); --undo-all also waits its turn.
        _instance = new Mutex(true, InstanceMutexName, out var first);
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
            foreach (var i in result.Items) Log($"--undo-all: {(i.Success ? "OK" : "FAILED")} {i.Change.Kind} '{i.Change.Target}': {i.Message}");
            if (restart)
            {
                Log("--undo-all: restarting in 10 seconds");
                Task.Run(() => commands.RunAsync(SystemCommandRunner.SystemTool("shutdown.exe"), ["/r", "/t", "10", "/c", "Remote PC Diagnostics: restarting to finish undoing changes."], CancellationToken.None)).GetAwaiter().GetResult();
            }
            return result.Failed == 0 ? ExitOk : ExitUndoPartial;
        }
        catch (Exception ex) { Log("--undo-all failed: " + ex); return ExitUndoPartial; }
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
