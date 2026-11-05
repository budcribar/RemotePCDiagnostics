using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using PeakSWC.RemoteBlazorWebView;
using PeakSWC.RemoteBlazorWebView.Wpf;
using PeakSWC.RemoteWebView;
using RemotePCDiagnostics.Host;

namespace UnsignedUiSpike.Shell;

/// <summary>
/// Spike for the plan's open question: can an unsigned module's RemoteBlazorWebView UI run in a restricted-token, Medium-integrity
/// process and be framed by the app over the embedded relay, with a postMessage channel? Three frames:
///   open    - relay without a frame-ancestors lock, sandbox="allow-scripts allow-forms" (opaque origin)
///   locked  - relay with FrameAncestors = the shell's origin, same sandbox (opaque origin, so the relay sees Origin: null)
///   samesrc - locked relay, sandbox adds allow-same-origin (the frame keeps the relay's own origin, still cross-origin to the shell)
/// Usage: UnsignedUiSpike.Shell.exe [--unrestricted] [--frame-ancestor &lt;origin&gt;]
/// Results: %LOCALAPPDATA%\RemotePCDiagnostics\spike\results-*.json (Save button, and on exit), module logs next to it.
/// </summary>
public static class Program
{
    [STAThread]
    public static void Main(string[] args)
    {
        Spike.Restricted = !args.Contains("--unrestricted");
        var ancestorArg = Array.IndexOf(args, "--frame-ancestor");
        // A WPF BlazorWebView on .NET 8+ serves its page from https://0.0.0.1 (0.0.0.0 only with the AppHostAddressAlways0000 switch);
        // the page reports its real origin, which the results record.
        var frameAncestor = ancestorArg >= 0 && ancestorArg + 1 < args.Length ? args[ancestorArg + 1] : "https://0.0.0.1";
        Directory.CreateDirectory(Spike.Folder);

        var app = new Application();
        app.DispatcherUnhandledException += (_, e) => { Spike.Record("shell", "crash", e.Exception.ToString()); MessageBox.Show(e.Exception.ToString(), "Spike error"); e.Handled = true; };

        var sw = Stopwatch.StartNew();
        var open = RemoteWebViewServer.StartAsync(new RemoteWebViewServerOptions()).GetAwaiter().GetResult();
        Spike.Record("shell", "relay-open", $"{open.BaseUri} grpc={open.GrpcUri} in {sw.ElapsedMilliseconds} ms");
        sw.Restart();
        var locked = RemoteWebViewServer.StartAsync(new RemoteWebViewServerOptions { FrameAncestors = [frameAncestor] }).GetAwaiter().GetResult();
        Spike.Record("shell", "relay-locked", $"{locked.BaseUri} grpc={locked.GrpcUri} frame-ancestors={frameAncestor} in {sw.ElapsedMilliseconds} ms");

        Spike.Frames.Add(Spike.Start("open", "open relay, opaque origin", open, "allow-scripts allow-forms"));
        Spike.Frames.Add(Spike.Start("locked", "locked relay, opaque origin", locked, "allow-scripts allow-forms"));
        Spike.Frames.Add(Spike.Start("samesrc", "locked relay, allow-same-origin", locked, "allow-scripts allow-forms allow-same-origin"));

        var services = new ServiceCollection();
        services.AddRemoteBlazorWebViewDeveloperTools(); // F12 in the shell opens DevTools, including the frames' consoles
        services.AddRemoteWpfBlazorWebView();
        // Local mode, like the app: no ServerUri. Setting HostPage starts the control, so it goes last.
        var webView = new BlazorWebView { Services = services.BuildServiceProvider() };
        webView.RootComponents.Add(new RootComponent { Selector = "#app", ComponentType = typeof(ShellPage) });
        webView.HostPage = @"wwwroot\index.html";
        var window = new Window { Title = "Unsigned module UI spike", Width = 1100, Height = 1000, Content = webView };
        window.Closed += (_, _) =>
        {
            foreach (var f in Spike.Frames) { try { if (!f.Process.HasExited) f.Process.Kill(); } catch { } }
            Spike.Save();
            // StopAsync can hang while frames still hold gRPC streams; don't let it block exit.
            Task.WaitAny([Task.Run(() => open.StopAsync()), Task.Run(() => locked.StopAsync())], TimeSpan.FromSeconds(3));
            Environment.Exit(0);
        };
        app.Run(window);
    }
}

public sealed record SpikeFrame(string Key, string Title, string Sandbox, string Src, Process Process, Guid Id, DateTimeOffset StartedAt);

public static class Spike
{
    public static string Folder { get; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RemotePCDiagnostics", "spike");
    public static bool Restricted { get; set; } = true;
    public static string ShellOrigin { get; set; } = "?";
    public static List<SpikeFrame> Frames { get; } = [];
    private static readonly ConcurrentQueue<object> Events = new();

    public static SpikeFrame Start(string key, string title, EmbeddedRemoteWebViewServer relay, string sandbox)
    {
        var id = Guid.NewGuid();
        var data = Path.Combine(Folder, "modulehost", key);
        Directory.CreateDirectory(data);
        var exe = Path.Combine(AppContext.BaseDirectory, "moduleui", "UnsignedUiSpike.ModuleUi.exe");
        var arguments = $"\"{relay.BaseUri}\" \"{relay.GrpcUri}\" {id} \"{data}\"";
        Process p;
        try
        {
            p = Restricted ? RestrictedModuleHostLauncher.StartRestrictedGui(exe, arguments, Path.GetDirectoryName(exe)!)
                : Process.Start(new ProcessStartInfo(exe, arguments) { UseShellExecute = false, WorkingDirectory = Path.GetDirectoryName(exe)! })!;
            Record(key, "launched", $"pid={p.Id} restricted={Restricted} data={data}");
        }
        catch (Exception ex)
        {
            Record(key, "launch-failed", ex.ToString());
            throw;
        }
        return new SpikeFrame(key, title, sandbox, new Uri(relay.BaseUri, $"{id}").ToString(), p, id, DateTimeOffset.Now);
    }

    public static void Record(string frame, string kind, string detail)
    {
        var started = Frames.FirstOrDefault(f => f.Key == frame)?.StartedAt;
        Events.Enqueue(new { at = DateTimeOffset.Now, msSinceLaunch = started is { } s ? (long?)(DateTimeOffset.Now - s).TotalMilliseconds : null, frame, kind, detail });
    }

    public static string Save()
    {
        var path = Path.Combine(Folder, $"results-{DateTime.Now:yyyyMMdd-HHmmss}.json");
        var frames = Frames.Select(f => new
        {
            f.Key, f.Title, f.Sandbox, f.Src, pid = f.Process.Id,
            exited = Exited(f.Process), exitCode = ExitCode(f.Process),
            moduleLog = Path.Combine(Folder, "modulehost", f.Key, "module-ui.log"),
        });
        File.WriteAllText(path, JsonSerializer.Serialize(new { ShellOrigin, Restricted, frames, events = Events.ToArray() }, new JsonSerializerOptions { WriteIndented = true }));
        return path;
    }

    private static bool Exited(Process p) { try { return p.HasExited; } catch { return true; } }

    // A process from GetProcessById (the restricted launch) has no exit code; read it through the OS handle instead.
    private static int? ExitCode(Process p)
    {
        try { return p.HasExited && GetExitCodeProcess(p.Handle, out var code) ? (int)code : null; } catch { return null; }
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);
}
