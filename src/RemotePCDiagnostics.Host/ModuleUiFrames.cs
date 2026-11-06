using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using PeakSWC.RemoteWebView;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Plugins;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// Local mode: serves unsigned modules' own UIs to the module page. On first use it starts a relay inside the app (loopback only, framed
/// only by the app's page, accepting the opaque origin of a sandboxed frame), then for each module page it starts the module's UI host
/// (moduleui\RemotePCDiagnostics.ModuleUiHost.exe) with the restricted token, as a client of that relay under a fresh id. The UI host's
/// stdin gets the module's latest result from <paramref name="results"/> when it starts and after every run (<see cref="ModuleUiState"/>),
/// so the module's details UI shows the app's run, not a blank state of its own.
/// </summary>
public sealed class ModuleUiFrames : IModuleUiFrames, IDisposable
{
    private readonly Microsoft.Extensions.Logging.ILogger? log;
    private readonly string? directory;
    private readonly ResultStore? results;

    public ModuleUiFrames(Microsoft.Extensions.Logging.ILogger? log = null, string? directory = null, ResultStore? results = null)
    {
        this.log = log;
        this.directory = directory;
        this.results = results;
        if (results is not null) results.Changed += OnResult;
    }

    public const string HostName = "RemotePCDiagnostics.ModuleUiHost";

    /// <summary>The origin of the app's own page in Local mode (BlazorWebView on .NET 8 and later). Only it may frame the relay's pages.</summary>
    public const string AppOrigin = "https://0.0.0.1";

    private readonly SemaphoreSlim _relayGate = new(1, 1);
    private EmbeddedRemoteWebViewServer? _relay;
    private readonly ConcurrentDictionary<Guid, Running> _running = new();

    /// <summary>One module's UI process and the app's end of its stdin.</summary>
    private sealed class Running(Process process, StreamWriter input, string moduleName)
    {
        public Process Process => process;
        public string ModuleName => moduleName;
        private readonly object _gate = new();

        /// <summary>Sends one line; false when the process has gone away.</summary>
        public bool Send(string line)
        {
            lock (_gate)
            {
                try { input.WriteLine(line); return true; }
                catch (Exception ex) when (ex is IOException or ObjectDisposedException) { return false; }
            }
        }

        public void Stop()
        {
            lock (_gate) { try { input.Dispose(); } catch { } }
            ModuleUiFrames.Stop(process);
        }
    }
    private int _disposed;

    public async Task<Uri> OpenAsync(UserModeModule module, CancellationToken cancellationToken = default)
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
        var running = new Running(process, input, module.Manifest.Slug);
        _running.AddOrUpdate(module.Manifest.Id, running, (_, prev) => { prev.Stop(); return running; });
        if (_disposed != 0 && _running.TryRemove(module.Manifest.Id, out var raced)) { raced.Stop(); ObjectDisposedException.ThrowIf(true, this); }
        // The module's last run, before the UI renders (the host reads its stdin from the start).
        if (results is not null) running.Send(ModuleUiState.ToLine(results.Get(module.Manifest.Slug)));
        if (log is not null) Microsoft.Extensions.Logging.LoggerExtensions.LogInformation(log, "Module UI [{Slug}]: started pid={Pid} (restricted token, Medium integrity), log {Log}",
            module.Manifest.Slug, process.Id, data + "\\module-ui.log");
        // The relay's /{id} page waits for the UI process to connect, so the frame can load right away.
        return new Uri(relay.BaseUri, id.ToString());
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

    /// <summary>A run finished (or a result was stored): pass it to that module's UI process, if one is open.</summary>
    private void OnResult(object? sender, DiagnosticResult result)
    {
        foreach (var (id, running) in _running)
        {
            if (!string.Equals(running.ModuleName, result.ModuleName, StringComparison.OrdinalIgnoreCase)) continue;
            if (!running.Send(ModuleUiState.ToLine(result)) && _running.TryRemove(new KeyValuePair<Guid, Running>(id, running))) running.Stop();
        }
    }

    private static void Stop(Process p)
    {
        try { if (!p.HasExited) p.Kill(entireProcessTree: true); } catch { }
        try { p.Dispose(); } catch { }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        if (results is not null) results.Changed -= OnResult;
        foreach (var r in _running.Values) r.Stop();
        _running.Clear();
        if (_relay is { } relay)
        {
            // Don't let a stuck stream hold up the app's exit.
            try { Task.Run(() => relay.StopAsync()).Wait(TimeSpan.FromSeconds(3)); } catch { }
        }
    }
}
