using System.IO;
using PeakSWC.RemoteBlazorWebView.RemoteComponents;
using PeakSWC.RemoteBlazorWebView.Wpf;
using RemotePCDiagnostics.Core.Plugins;
using RemotePCDiagnostics.ModuleUi;

namespace RemotePCDiagnostics.ModuleUiHost;

/// <summary>
/// RemotePCDiagnostics.ModuleUiHost "&lt;module.dll&gt;" &lt;relay uri&gt; &lt;relay grpc uri&gt; &lt;id&gt; "&lt;data folder&gt;" [app pid]
/// Loads one unsigned module and renders its details UI as a remote component (RemoteComponentHost): a RemoteBlazorWebView client of the
/// app's relay, which serves it to the module page's sandboxed frame at &lt;relay uri&gt;/&lt;id&gt;. Runs with the token the app gave it:
/// no administrator, Medium integrity. Exits when the frame is reloaded or closed (the app starts a fresh copy each time the module page
/// opens), or when the app or its relay goes away. Its stdin carries the IModuleUi values from the module page's ModuleUiFrame (the
/// module's latest result in the app), which the details UI gets as the ModuleDetails.LastResult cascading value.
/// </summary>
public static class Program
{
    public const int ExitOk = RemoteComponentHost.ExitOk, ExitFailed = RemoteComponentHost.ExitFailed, ExitUsage = 2, ExitNoUi = 3;

    internal static UserModePlugin.Loaded? Ui { get; private set; }
    private static string? _logPath;

    [STAThread]
    public static int Main(string[] args)
    {
        if (args.Length < 5 || !Uri.TryCreate(args[1], UriKind.Absolute, out var relay) || !Uri.TryCreate(args[2], UriKind.Absolute, out var grpc)
            || !Guid.TryParse(args[3], out var id))
        {
            Console.Error.WriteLine("usage: RemotePCDiagnostics.ModuleUiHost <module.dll> <relay uri> <relay grpc uri> <id> <data folder> [app pid]");
            return ExitUsage;
        }
        try
        {
            Directory.CreateDirectory(args[4]);
            _logPath = Path.Combine(args[4], "module-ui.log");
            // This exe is in moduleui\ under the app's folder: the app's helpers (osquery) resolve from the folder above.
            var appDirectory = Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory)) ?? AppContext.BaseDirectory;
            Ui = UserModePlugin.Load(args[0], RemotePCDiagnostics.Logging.LineLogger.From(Log), appDirectory);
            Log($"start pid={Environment.ProcessId} module={Ui.Manifest.Slug} relay={relay} id={id}");
            if (Ui.DetailsComponent is null) { Log("the module sets no details UI"); return ExitNoUi; }

            return RemoteComponentHost.Run(new RemoteComponentHostOptions
            {
                ServerUri = relay,
                GrpcBaseUri = grpc,
                Id = id,
                RootComponent = typeof(ModuleUiRoot),
                // This process runs with a restricted, Medium-integrity token and can't open the elevated app's process handle.
                ParentProcessId = args.Length > 5 && int.TryParse(args[5], out var appPid) ? appPid : null,
                // WebView2 needs a user data folder this token can write; the default is next to the exe, under Program Files.
                WebViewDataFolder = Path.Combine(args[4], "webview2"),
                Title = Ui.Manifest.DisplayName,
                Log = Log,
                ConfigureServices = (services, connection) => services.AddRemoteComponentReceiver<ModuleUiReceiver>(connection),
            });
        }
        catch (Exception ex) { Log("failed: " + ex); return ExitFailed; }
    }

    private static readonly object LogGate = new();
    internal static void Log(string line)
    {
        try { lock (LogGate) File.AppendAllText(_logPath!, $"{DateTimeOffset.Now:O} {line}{Environment.NewLine}"); } catch { }
    }
}
