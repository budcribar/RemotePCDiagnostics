using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using PeakSWC.RemoteBlazorWebView.RemoteComponents;
using PeakSWC.RemoteWebView;
using RemotePCDiagnostics.Core.Plugins;
using RemotePCDiagnostics.ModuleUi;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// Local mode: serves unsigned modules' own UIs to the module page. On first use it starts a relay inside the app (loopback only, framed
/// only by the app's page, accepting the opaque origin of a sandboxed frame), then for each module page it starts the module's UI host
/// (moduleui\RemotePCDiagnostics.ModuleUiHost.exe) with the restricted token, as a client of that relay under a fresh id. The session it
/// returns holds the UI host's stdin, over which the module page's ModuleUiFrame sends the module's latest result (the IModuleUi contract).
/// </summary>
public sealed class ModuleUiFrames(Microsoft.Extensions.Logging.ILogger? log = null, string? directory = null) : IModuleUiFrames, IDisposable
{
    public const string HostName = "RemotePCDiagnostics.ModuleUiHost";

    /// <summary>The origin of the app's own page in Local mode (BlazorWebView on .NET 8 and later). Only it may frame the relay's pages.</summary>
    public const string AppOrigin = "https://0.0.0.1";

    private readonly SemaphoreSlim _relayGate = new(1, 1);
    private EmbeddedRemoteWebViewServer? _relay;
    private readonly ConcurrentDictionary<Guid, Running> _running = new();

    /// <summary>One module's UI process and the app's end of its stdin.</summary>
    private sealed class Running(Process process, RemoteComponentConnection connection)
    {
        public Process Process => process;
        public RemoteComponentConnection Connection => connection;

        public void Stop()
        {
            connection.Dispose();
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch { }
            try { process.Dispose(); } catch { }
        }
    }
    private int _disposed;

    public async Task<RemoteComponentSession> OpenAsync(UserModeModule module, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        var relay = await RelayAsync(cancellationToken).ConfigureAwait(false);
        var dir = Path.Combine(directory ?? AppContext.BaseDirectory, "moduleui");
        var exe = Path.Combine(dir, HostName + ".exe");
        var id = Guid.NewGuid();
        var data = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RemotePCDiagnostics", "moduleui",
            module.Manifest.Slug);
        var arguments = $"\"{module.Path}\" {relay.BaseUri} {relay.GrpcUri} {id} \"{data}\" {Environment.ProcessId}";

        // One UI process per module: the page opening again starts a fresh one (the relay treats a reload as a restart).
        if (_running.TryRemove(module.Manifest.Id, out var previous)) previous.Stop();
        var (process, input) = RestrictedModuleHostLauncher.StartRestrictedGuiWithInput(exe, arguments, dir);
        // The contract has no callbacks, so nothing is read back from the process.
        var running = new Running(process, new RemoteComponentConnection(null, input));
        _running.AddOrUpdate(module.Manifest.Id, running, (_, prev) => { prev.Stop(); return running; });
        if (_disposed != 0 && _running.TryRemove(module.Manifest.Id, out var raced)) { raced.Stop(); ObjectDisposedException.ThrowIf(true, this); }
        if (log is not null) Microsoft.Extensions.Logging.LoggerExtensions.LogInformation(log, "Module UI [{Slug}]: started pid={Pid} (restricted token, Medium integrity), log {Log}",
            module.Manifest.Slug, process.Id, data + "\\module-ui.log");
        // The relay's /{id} page waits for the UI process to connect, so the frame can load right away.
        return new RemoteComponentSession(new Uri(relay.BaseUri, id.ToString()), running.Connection, () =>
        {
            // The frame went away (the page closed or navigated): stop its process, unless a newer page already replaced it.
            _running.TryRemove(new KeyValuePair<Guid, Running>(module.Manifest.Id, running));
            running.Stop();
            return ValueTask.CompletedTask;
        });
    }

    private async Task<EmbeddedRemoteWebViewServer> RelayAsync(CancellationToken cancellationToken)
    {
        if (_relay is { } r) return r;
        await _relayGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_relay is null)
            {
                _relay = await RemoteWebViewServer.StartAsync(new RemoteWebViewServerOptions
                {
                    FrameAncestors = [AppOrigin],
                    AllowOpaqueOrigin = true, // the module page frames these pages without allow-same-origin
                }, cancellationToken).ConfigureAwait(false);
                if (log is not null) Microsoft.Extensions.Logging.LoggerExtensions.LogInformation(log, "Module UI relay: {Relay} (gRPC {Grpc})", _relay.BaseUri, _relay.GrpcUri);
            }
            return _relay;
        }
        finally { _relayGate.Release(); }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        foreach (var r in _running.Values) r.Stop();
        _running.Clear();
        if (_relay is { } relay)
        {
            // Don't let a stuck stream hold up the app's exit.
            try { Task.Run(() => relay.StopAsync()).Wait(TimeSpan.FromSeconds(3)); } catch { }
        }
    }
}
