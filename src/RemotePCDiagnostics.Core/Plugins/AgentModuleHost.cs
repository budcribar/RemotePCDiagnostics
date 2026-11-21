using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Text;

namespace RemotePCDiagnostics.Core.Plugins;

/// <summary>
/// The Agent's end of a module that ships with the app and needs administrator, run out of process: the Agent (the elevated helper or
/// the agent service) starts RemotePCDiagnostics.ModuleHost from the app's folder with its own rights, and relays the module host's lines
/// to the app over a pipe that only the app can open. The app never runs as administrator, so it never starts this host itself.
/// The Agent runs only the modules it finds in the app's own builtin-modules folder (under Program Files, which standard users can't
/// write) whose module.json says they need administrator; a line for any other module is answered with an error and never reaches the host.
/// </summary>
/// <param name="appFolder">The app's install folder: RemotePCDiagnostics.ModuleHost and builtin-modules\ are in it.</param>
/// <param name="start">Starts the module host for "--shared" or one module DLL (tests); by default from <paramref name="appFolder"/>.</param>
public sealed class AgentModuleHost(string appFolder, ILogger? log = null, Func<string, IModuleHostConnection>? start = null)
{
    public const string Shared = "--shared";
    public const string NotAllowed = "The Agent runs only the modules that ship with the app and need administrator.";

    private readonly ConcurrentDictionary<string, bool> _allowed = new(StringComparer.OrdinalIgnoreCase);

    public string BundledFolder { get; } = Path.GetFullPath(Path.Combine(appFolder, ModuleLoaderOptions.BundledFolderName));

    /// <summary>Starts the module host: <see cref="Shared"/>, or one module that <see cref="IsAllowed"/>.</summary>
    public IModuleHostConnection Start(string module)
    {
        if (module != Shared && !IsAllowed(module)) throw new UnauthorizedAccessException(NotAllowed);
        if (start is not null) return start(module);
        var label = module == Shared ? "agent" : Path.GetFileNameWithoutExtension(module);
        return new ProcessModuleHostLauncher(appFolder, log).Start(module, label);
    }

    /// <summary>
    /// True for a DLL directly in the app's builtin-modules folder that carries the id and slug of a module the app knows and says it
    /// needs administrator (its module.json, read without running any of its code). Remembered per path.
    /// </summary>
    public bool IsAllowed(string? module)
    {
        if (string.IsNullOrWhiteSpace(module) || module == Shared) return false;
        string full;
        try { full = Path.GetFullPath(module); }
        catch { return false; }
        return _allowed.GetOrAdd(full, Check);
    }

    private bool Check(string full)
    {
        try
        {
            if (!string.Equals(Path.GetDirectoryName(full), BundledFolder.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), StringComparison.OrdinalIgnoreCase)
                || !string.Equals(Path.GetExtension(full), ".dll", StringComparison.OrdinalIgnoreCase) || !File.Exists(full))
                return false;
            var (manifest, _) = ModuleManifest.ReadFromAssembly(File.ReadAllBytes(full));
            return manifest.NeedsAdmin && BuiltInModules.Descriptors.Any(d => d.Id == manifest.Id && string.Equals(d.Slug, manifest.Slug, StringComparison.Ordinal));
        }
        catch (Exception ex)
        {
            log.Warn($"[agent-module-host] {full}: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Relays lines between the app (<paramref name="app"/>, the pipe it connected to) and the module host until either side ends; then
    /// ends the other. In a shared host every line from the app must name a module that <see cref="IsAllowed"/> (or be the host's own
    /// "exit"); any other gets an error back and is dropped.
    /// </summary>
    public async Task RelayAsync(Stream app, IModuleHostConnection host, bool shared, CancellationToken ct)
    {
        var reader = new StreamReader(app, new UTF8Encoding(false), detectEncodingFromByteOrderMarks: false, leaveOpen: true);
        var writer = new StreamWriter(app, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = false };
        var writeGate = new SemaphoreSlim(1, 1);
        async Task ToAppAsync(string line)
        {
            await writeGate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                await writer.WriteLineAsync(line.AsMemory(), ct).ConfigureAwait(false);
                await writer.FlushAsync(ct).ConfigureAwait(false);
            }
            finally { writeGate.Release(); }
        }

        using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var fromApp = Task.Run(async () =>
        {
            while (await reader.ReadLineAsync(stop.Token).ConfigureAwait(false) is { } line)
            {
                if (shared && ModuleHostMessage.Parse(line) is { } m && !(string.IsNullOrEmpty(m.Module) ? m.Type == "exit" : IsAllowed(m.Module)))
                {
                    log.Warn($"[agent-module-host] Refused a '{m.Type}' line for '{m.Module}'.");
                    if (!string.IsNullOrEmpty(m.Module))
                        await ToAppAsync(new ModuleHostMessage { Type = "error", Module = m.Module, Message = NotAllowed }.ToLine()).ConfigureAwait(false);
                    continue;
                }
                await host.WriteLineAsync(line, stop.Token).ConfigureAwait(false);
            }
        }, CancellationToken.None);
        var fromHost = Task.Run(async () =>
        {
            while (await host.ReadLineAsync(stop.Token).ConfigureAwait(false) is { } line)
                await ToAppAsync(line).ConfigureAwait(false);
        }, CancellationToken.None);

        var first = await Task.WhenAny(fromApp, fromHost).ConfigureAwait(false);
        if (first.Exception?.GetBaseException() is { } failed and not OperationCanceledException)
            log.Info($"[agent-module-host] Relay ended: {failed.Message}");
        // The app closed its end: closing the host's stdin ends it. The host ended: closing the pipe tells the app.
        try { host.Dispose(); } catch { }
        try { app.Dispose(); } catch { }
        stop.Cancel();
        try { await Task.WhenAll(fromApp, fromHost).ConfigureAwait(false); } catch { }
        writeGate.Dispose();
    }
}

/// <summary>The app's end of a module host the Agent runs (<see cref="AgentModuleHost"/>): its lines over the pipe the Agent opened.</summary>
public sealed class PipeModuleHostConnection(PipeStream pipe) : IModuleHostConnection
{
    private readonly StreamReader _reader = new(pipe, new UTF8Encoding(false), detectEncodingFromByteOrderMarks: false, leaveOpen: true);
    private readonly StreamWriter _writer = new(pipe, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = false };
    private int _disposed;

    public async Task WriteLineAsync(string line, CancellationToken ct)
    {
        await _writer.WriteLineAsync(line.AsMemory(), ct).ConfigureAwait(false);
        await _writer.FlushAsync(ct).ConfigureAwait(false);
    }

    public Task<string?> ReadLineAsync(CancellationToken ct) => _reader.ReadLineAsync(ct).AsTask();

    public bool HasExited => Volatile.Read(ref _disposed) != 0 || !pipe.IsConnected;

    /// <summary>Closing the pipe makes the Agent end the module host.</summary>
    public void Kill() => Dispose();

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        try { pipe.Dispose(); } catch { }
        try { _reader.Dispose(); _writer.Dispose(); } catch { }
    }
}
