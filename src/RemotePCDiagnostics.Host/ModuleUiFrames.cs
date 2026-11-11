using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using PeakSWC.RemoteBlazorWebView.RemoteComponents;
using PeakSWC.RemoteWebView;
using RemotePCDiagnostics.Core.Plugins;
using RemotePCDiagnostics.ModuleUi;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// Serves modules' own UIs to the module page. In Local mode, on first use it starts a relay inside the app (loopback only, framed
/// only by the app's page, accepting the opaque origin of a sandboxed frame). In Remote mode (<paramref name="remoteRelay"/>) it uses the
/// session's own relay instead, where the remote browser already is, and only for modules that ship with the app (unsigned modules never
/// load in a remote session). A mirror of the session frames the same UI read-only (RemoteComponentSession.MirrorSource). Then for each
/// module page it starts the module's UI host
/// (moduleui\RemotePCDiagnostics.ModuleUiHost.exe) with the restricted token, as a client of that relay under a fresh id. The session it
/// returns holds the UI host's stdin, over which the module page's ModuleUiFrame sends the module's latest result (the IModuleUi contract).
/// </summary>
public sealed class ModuleUiFrames(Microsoft.Extensions.Logging.ILogger? log = null, string? directory = null, Uri? remoteRelay = null) : IModuleUiFrames, IDisposable
{
    public const string HostName = "RemotePCDiagnostics.ModuleUiHost";

    /// <summary>The origin of the app's own page in Local mode (BlazorWebView on .NET 8 and later). Only it may frame the relay's pages.</summary>
    public const string AppOrigin = "https://0.0.0.1";

    /// <summary>Remote mode: the session's relay (its gRPC endpoint is the same address).</summary>
    public Uri? RemoteRelay => remoteRelay;

    /// <summary>Local mode frames any module's UI; Remote mode only those of modules that ship with the app.</summary>
    public bool CanOpen(UserModeModule module) => remoteRelay is null || module.Bundled;

    /// <summary>The address the UI host connects to and the address of its page, for frame <paramref name="id"/> on <paramref name="relay"/>.</summary>
    public static (Uri Base, Uri Grpc, Uri Page) Addresses(Uri relay, Uri? grpc, Guid id)
    {
        var baseUri = relay.AbsoluteUri.EndsWith('/') ? relay : new Uri(relay.AbsoluteUri + "/");
        return (baseUri, grpc ?? baseUri, new Uri(baseUri, id.ToString()));
    }

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
    internal Action? OnDisposed { get; set; }

    public async Task<RemoteComponentSession> OpenAsync(UserModeModule module, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        if (!CanOpen(module)) throw new InvalidOperationException("only modules that ship with the app can show their own UI in a remote session");
        Uri relayBase, relayGrpc;
        if (remoteRelay is not null) (relayBase, relayGrpc) = (remoteRelay, remoteRelay);
        else { var local = await RelayAsync(cancellationToken).ConfigureAwait(false); (relayBase, relayGrpc) = (local.BaseUri, local.GrpcUri); }
        var dir = Path.Combine(directory ?? AppContext.BaseDirectory, "moduleui");
        var exe = Path.Combine(dir, HostName + ".exe");
        var id = Guid.NewGuid();
        var (baseUri, grpcUri, page) = Addresses(relayBase, relayGrpc, id);
        var data = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RemotePCDiagnostics", "moduleui",
            module.Manifest.Slug);
        var arguments = $"\"{module.Path}\" {baseUri} {grpcUri} {id} \"{data}\" {Environment.ProcessId}";

        // One UI process per module: the page opening again starts a fresh one (the relay treats a reload as a restart).
        if (_running.TryRemove(module.Manifest.Id, out var previous)) previous.Stop();
        var (process, input) = RestrictedModuleHostLauncher.StartRestrictedGuiWithInput(exe, arguments, dir, unsigned: !module.Bundled);
        // The contract has no callbacks, so nothing is read back from the process.
        var running = new Running(process, new RemoteComponentConnection(null, input));
        _running.AddOrUpdate(module.Manifest.Id, running, (_, prev) => { prev.Stop(); return running; });
        if (_disposed != 0 && _running.TryRemove(module.Manifest.Id, out var raced)) { raced.Stop(); ObjectDisposedException.ThrowIf(true, this); }
        if (log is not null) Microsoft.Extensions.Logging.LoggerExtensions.LogInformation(log, "Module UI [{Slug}]: started pid={Pid} (restricted token, Medium integrity{Unsigned}) on {Relay}, log {Log}",
            module.Manifest.Slug, process.Id, module.Bundled ? "" : ", no INTERACTIVE or Event Log Readers", baseUri, data + "\\module-ui.log");
        // The relay's /{id} page waits for the UI process to connect, so the frame can load right away.
        return new RemoteComponentSession(page, running.Connection, () =>
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
        OnDisposed?.Invoke();
        OnDisposed = null;
        foreach (var r in _running.Values) r.Stop();
        _running.Clear();
        if (_relay is { } relay)
        {
            // Don't let a stuck stream hold up the app's exit.
            try { Task.Run(() => relay.StopAsync()).Wait(TimeSpan.FromSeconds(3)); } catch { }
        }
    }
}
