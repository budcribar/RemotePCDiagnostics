using System.IO;
using System.Windows;

namespace RemotePCDiagnostics.Host;

public partial class App : Application
{
    /// <summary>Optional file log, enabled by setting RPD_LOG_FILE (used by CI).</summary>
    public static void Log(string message)
    {
        var path = Environment.GetEnvironmentVariable("RPD_LOG_FILE");
        if (string.IsNullOrEmpty(path)) return;
        try { File.AppendAllText(path, $"{DateTimeOffset.Now:O} {message}{Environment.NewLine}"); } catch { }
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
        base.OnExit(e);
    }
}
