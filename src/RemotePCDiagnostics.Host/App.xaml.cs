using System.IO;
using System.Windows;
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

    protected override void OnStartup(StartupEventArgs e)
    {
        Log($"Startup pid={Environment.ProcessId} args={string.Join(' ', e.Args)}");
        DispatcherUnhandledException += (_, ex) => Log($"Unhandled: {ex.Exception}");
        AppDomain.CurrentDomain.UnhandledException += (_, ex) => Log($"Fatal: {ex.ExceptionObject}");
        base.OnStartup(e);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        Log($"Exit code={e.ApplicationExitCode}");
        Event(LogEventIds.AppExit, LogLevel.Information, $"Remote PC Diagnostics exited (code {e.ApplicationExitCode}).");
        try { _events.Value.Flush(TimeSpan.FromSeconds(1)); _events.Value.Dispose(); } catch { }
        base.OnExit(e);
    }
}
