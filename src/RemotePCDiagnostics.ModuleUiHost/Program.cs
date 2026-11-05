using System.Diagnostics;
using System.IO;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using PeakSWC.RemoteBlazorWebView;
using PeakSWC.RemoteBlazorWebView.Wpf;
using RemotePCDiagnostics.Core.Plugins;

namespace RemotePCDiagnostics.ModuleUiHost;

/// <summary>
/// RemotePCDiagnostics.ModuleUiHost "&lt;module.dll&gt;" &lt;relay uri&gt; &lt;relay grpc uri&gt; &lt;id&gt; "&lt;data folder&gt;" [app pid]
/// Loads one unsigned module and renders its details UI as a RemoteBlazorWebView client of the app's relay, which serves it to the module
/// page's sandboxed frame at &lt;relay uri&gt;/&lt;id&gt;. Runs with the token the app gave it: no administrator, Medium integrity. Exits
/// when the frame is reloaded (the app starts a fresh copy each time the module page opens), or when the app or its relay goes away.
/// </summary>
public static class Program
{
    public const int ExitOk = 0, ExitFailed = 1, ExitUsage = 2, ExitNoUi = 3;

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
            Ui = UserModePlugin.Load(args[0], Log);
            Log($"start pid={Environment.ProcessId} module={Ui.Manifest.Slug} relay={relay} id={id}");
            if (Ui.DetailsComponent is null) { Log("the module sets no details UI"); return ExitNoUi; }

            // WebView2 needs a user data folder this token can write; the default is next to the exe, under Program Files.
            var webViewData = Path.Combine(args[4], "webview2");
            Directory.CreateDirectory(webViewData);
            Environment.SetEnvironmentVariable("WEBVIEW2_USER_DATA_FOLDER", webViewData);

            var app = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
            app.DispatcherUnhandledException += (_, e) => { Log("crash: " + e.Exception); e.Handled = true; app.Shutdown(ExitFailed); };
            if (args.Length > 5 && int.TryParse(args[5], out var appPid)) ExitWithApp(app, appPid);

            var services = new ServiceCollection();
            services.AddRemoteWpfBlazorWebView();
            var webView = new BlazorWebView { Services = services.BuildServiceProvider(), ServerUri = relay, GrpcBaseUri = grpc, Id = id };
            webView.RootComponents.Add(new RootComponent { Selector = "#app", ComponentType = typeof(ModuleUiRoot) });
            webView.Connected += (_, e) => Log($"frame connected from {e.IpAddress}");
            webView.Disconnected += (_, e) => { Log($"disconnected: {e.Exception?.Message}"); app.Dispatcher.BeginInvoke(() => app.Shutdown(ExitOk)); };
            webView.Refreshed += (_, _) => { Log("frame reloaded"); app.Dispatcher.BeginInvoke(() => app.Shutdown(ExitOk)); };
            // Setting HostPage starts the control, so it goes last.
            webView.HostPage = @"wwwroot\index.html";

            // The window only owns the control; people see the module page's frame. It must not be minimized: the WebView2 composition
            // control creates a D3D9 device from it when it loads, which fails for a minimized window. So: normal, off screen, hidden
            // from the taskbar, never activated.
            var window = new Window
            {
                Title = Ui.Manifest.DisplayName, Width = 800, Height = 600, Content = webView,
                WindowStartupLocation = WindowStartupLocation.Manual, Left = -32000, Top = -32000, ShowInTaskbar = false, ShowActivated = false,
            };
            window.Show();
            return app.Run();
        }
        catch (Exception ex) { Log("failed: " + ex); return ExitFailed; }
    }

    /// <summary>Ends this process when the app ends, even if it never got to close the relay. This process runs with a restricted,
    /// Medium-integrity token and can't open the elevated app's process handle (so no WaitForExit); it polls the process list instead,
    /// which needs no handle.</summary>
    private static void ExitWithApp(Application app, int appPid)
    {
        _ = Task.Run(async () =>
        {
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(2));
            while (await timer.WaitForNextTickAsync())
            {
                bool running;
                try { running = IsRunning(appPid); }
                catch (Exception ex) { Log($"can't watch the app (pid {appPid}): {ex.Message}"); return; }
                if (running) continue;
                Log("the app exited");
                await app.Dispatcher.BeginInvoke(() => app.Shutdown(ExitOk));
                return;
            }
        });
    }

    private static bool IsRunning(int pid)
    {
        var found = false;
        foreach (var p in Process.GetProcesses())
            using (p)
                if (p.Id == pid) found = true;
        return found;
    }

    private static readonly object LogGate = new();
    internal static void Log(string line)
    {
        try { lock (LogGate) File.AppendAllText(_logPath!, $"{DateTimeOffset.Now:O} {line}{Environment.NewLine}"); } catch { }
    }
}
