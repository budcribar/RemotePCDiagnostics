using System.IO;
using System.Security.Principal;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using PeakSWC.RemoteBlazorWebView;
using PeakSWC.RemoteBlazorWebView.Wpf;

namespace UnsignedUiSpike.ModuleUi;

/// <summary>Usage: UnsignedUiSpike.ModuleUi.exe &lt;relay base uri&gt; &lt;relay grpc uri&gt; &lt;session id&gt; &lt;data folder&gt;</summary>
public static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        if (args.Length < 4) { MessageBox.Show("usage: <base uri> <grpc uri> <id> <data folder>"); return 2; }
        var (baseUri, grpcUri, id, data) = (new Uri(args[0]), new Uri(args[1]), Guid.Parse(args[2]), args[3]);
        SpikeLog.Path = System.IO.Path.Combine(data, "module-ui.log");
        try
        {
            // WebView2 under a restricted token needs a user data folder this token can write (the default is next to the exe).
            Directory.CreateDirectory(System.IO.Path.Combine(data, "webview2"));
            Environment.SetEnvironmentVariable("WEBVIEW2_USER_DATA_FOLDER", System.IO.Path.Combine(data, "webview2"));
            SpikeLog.Write($"start pid={Environment.ProcessId} integrity={Token.Integrity} admin={Token.IsAdmin} relay={baseUri} grpc={grpcUri} id={id}");

            var app = new Application();
            app.DispatcherUnhandledException += (_, e) => { SpikeLog.Write("crash: " + e.Exception); e.Handled = true; app.Shutdown(1); };
            var services = new ServiceCollection();
            services.AddRemoteWpfBlazorWebView();
            var webView = new BlazorWebView { Services = services.BuildServiceProvider(), ServerUri = baseUri, GrpcBaseUri = grpcUri, Id = id };
            webView.RootComponents.Add(new RootComponent { Selector = "#app", ComponentType = typeof(SpikePanel) });
            webView.HostPage = @"wwwroot\index.html";
            webView.Connected += (_, e) => SpikeLog.Write($"browser connected from {e.IpAddress}");
            webView.Disconnected += (_, e) => SpikeLog.Write($"disconnected: {e.Exception?.Message}");
            // The window is only the control's owner; the UI people use is the iframe in the shell. It must not be minimized: the
            // WebView2 composition control creates a D3D9 device from it on load, which throws NotImplementedException for a minimized
            // window. So it stays Normal, off screen, out of the taskbar and never activated.
            var window = new Window
            {
                Title = "Unsigned module host (spike)", Width = 600, Height = 400, Content = webView,
                WindowStartupLocation = WindowStartupLocation.Manual, Left = -32000, Top = -32000, ShowInTaskbar = false, ShowActivated = false,
            };
            return app.Run(window);
        }
        catch (Exception ex) { SpikeLog.Write("failed: " + ex); return 1; }
    }
}

public static class Token
{
    public static bool IsAdmin => new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);

    /// <summary>Low / Medium / High / System from the token's integrity level (TokenIntegrityLevel).</summary>
    public static string Integrity
    {
        get
        {
            try
            {
                var token = WindowsIdentity.GetCurrent().Token;
                GetTokenInformation(token, 25, IntPtr.Zero, 0, out var size);
                var buffer = System.Runtime.InteropServices.Marshal.AllocHGlobal(size);
                try
                {
                    if (!GetTokenInformation(token, 25, buffer, size, out _)) return "unknown";
                    var sid = new SecurityIdentifier(System.Runtime.InteropServices.Marshal.ReadIntPtr(buffer));
                    return sid.Value switch { "S-1-16-4096" => "Low", "S-1-16-8192" => "Medium", "S-1-16-8448" => "Medium+", "S-1-16-12288" => "High", "S-1-16-16384" => "System", var v => v };
                }
                finally { System.Runtime.InteropServices.Marshal.FreeHGlobal(buffer); }
            }
            catch (Exception ex) { return "unknown (" + ex.Message + ")"; }
        }
    }

    [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr token, int infoClass, IntPtr info, int length, out int returnLength);
}

public static class SpikeLog
{
    public static string? Path { get; set; }
    private static readonly object Gate = new();
    public static void Write(string line) { try { lock (Gate) File.AppendAllText(Path!, $"{DateTimeOffset.Now:O} {line}{Environment.NewLine}"); } catch { } }
}
