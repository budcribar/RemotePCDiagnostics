using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Plugins;

/// <summary>
/// The line protocol between the app and RemotePCDiagnostics.ModuleHost (one JSON object per line over the helper's stdin and stdout, which
/// only the app holds). App to host: availability, refresh, stop, exit, answer, call. Host to app: ready, availability, progress, result,
/// error, query (a host query, <see cref="IHostQueries"/>, which the app answers with the same <see cref="Id"/>), return (the answer to a
/// call, <see cref="ModulePageCalls"/>, with the call's <see cref="Id"/>).
/// </summary>
public sealed record ModuleHostMessage
{
    public string Type { get; init; } = "";
    public bool? Available { get; init; }
    public string? Reason { get; init; }
    public string? Message { get; init; }
    public int? Step { get; init; }
    public int? Total { get; init; }
    public DiagnosticStatus? Status { get; init; }
    public bool? Cancelled { get; init; }
    public AreaReport? Report { get; init; }
    /// <summary>When the result was produced (results sent to a module's UI host).</summary>
    public DateTimeOffset? When { get; init; }
    /// <summary>A result's payload when it isn't an <see cref="AreaReport"/> (one of <see cref="ModuleHostPayloads.Types"/>), and its type.</summary>
    public JsonElement? Payload { get; init; }
    public string? PayloadType { get; init; }

    /// <summary>Host queries: the query's id (chosen by the module host), capability and arguments; the answer's outcome and value.</summary>
    public int? Id { get; init; }
    public string? Capability { get; init; }
    public JsonElement? Args { get; init; }
    public bool? Ok { get; init; }
    public string? Error { get; init; }
    public JsonElement? Value { get; init; }

    /// <summary>A call from the module's page (<see cref="ModulePageCalls"/>): its name; the arguments go in <see cref="Args"/>.</summary>
    public string? Name { get; init; }
    /// <summary>On a result: what the module's page needs from the module besides its report, by <see cref="ModulePageCalls"/> name
    /// (the services behind the rows, the card that can look up freeze evidence).</summary>
    public Dictionary<string, JsonElement>? PageData { get; init; }

    /// <summary>When several bundled modules share one module host (--shared), the module DLL path this message belongs to.</summary>
    public string? Module { get; init; }

    /// <summary>A per-device module (<see cref="ModuleManifest.PerDevice"/>): the device a refresh runs against; the devices "detection"
    /// found (with <see cref="Reason"/> when the module doesn't apply).</summary>
    public ModuleInstance? Instance { get; init; }
    public List<ModuleInstance>? Instances { get; init; }

    public static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        NumberHandling = JsonNumberHandling.AllowNamedFloatingPointLiterals, Converters = { new JsonStringEnumConverter() },
    };

    public string ToLine() => JsonSerializer.Serialize(this, Json);
    public static ModuleHostMessage? Parse(string? line)
    {
        if (string.IsNullOrWhiteSpace(line)) return null;
        try { return JsonSerializer.Deserialize<ModuleHostMessage>(line, Json); } catch (JsonException) { return null; }
    }
}

/// <summary>
/// Result payloads other than <see cref="AreaReport"/> that a module that ships with the app may send back from the module host, so its
/// page gets the same result in either process. A type not listed here arrives as no payload.
/// </summary>
public static class ModuleHostPayloads
{
    public static readonly IReadOnlyList<Type> Types =
        [typeof(Sensors.SensorReport), typeof(Security.SecurityAuditReport), typeof(Osquery.HardwareInventory), typeof(double)];

    public static (JsonElement Payload, string Type)? Write(object? payload) =>
        payload is not null && Types.Contains(payload.GetType())
            ? (JsonSerializer.SerializeToElement(payload, payload.GetType(), ModuleHostMessage.Json), payload.GetType().FullName!)
            : null;

    /// <summary>The result with its typed payload, or null when the type isn't one of <see cref="Types"/> or doesn't read.</summary>
    public static DiagnosticResult? Read(string name, DiagnosticStatus status, string message, JsonElement payload, string type)
    {
        var t = Types.FirstOrDefault(x => x.FullName == type);
        if (t is null) return null;
        try
        {
            var value = payload.Deserialize(t, ModuleHostMessage.Json);
            return (DiagnosticResult?)Activator.CreateInstance(typeof(DiagnosticResult<>).MakeGenericType(t), name, status, message, DateTimeOffset.Now, value);
        }
        catch (JsonException) { return null; }
    }
}

/// <summary>Where unsigned modules may run: the marker file in the admin-only modules folder, so only an elevated app at the PC can turn
/// it on (a standard user, a remote session or a module can't).</summary>
public static class UnsignedModulesSetting
{
    public const string MarkerName = "allow-unsigned";
    public static string MarkerPath(string? modulesFolder = null) => Path.Combine(modulesFolder ?? ModuleLoaderOptions.DefaultModulesFolder(), MarkerName);
    public static bool IsOn(string? modulesFolder = null) { try { return File.Exists(MarkerPath(modulesFolder)); } catch { return false; } }

    /// <summary>Turns unsigned modules on or off (takes effect at the next start). Throws when the folder isn't writable (not elevated).</summary>
    public static void Set(bool on, string? modulesFolder = null)
    {
        var path = MarkerPath(modulesFolder);
        if (on)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, "Unsigned modules run in user mode (RemotePCDiagnostics.ModuleHost, restricted token).");
        }
        else if (File.Exists(path)) File.Delete(path);
    }
}

/// <summary>A running module host: its stdin and stdout.</summary>
public interface IModuleHostConnection : IDisposable
{
    Task WriteLineAsync(string line, CancellationToken ct);
    Task<string?> ReadLineAsync(CancellationToken ct);
    bool HasExited { get; }
    void Kill();
}

/// <summary>Starts the module host for one module (the Windows host uses a restricted, Medium-integrity token).</summary>
public interface IModuleHostLauncher
{
    IModuleHostConnection Start(UserModeModule module);
}

/// <summary>
/// Multiplexes bundled out-of-process modules of the same token level (user-mode vs elevated) onto a single shared
/// <c>RemotePCDiagnostics.ModuleHost --shared</c> process so running all checks in parallel starts one module host instead of a dozen.
/// Unsigned third-party plugins are never shared: each gets its own process.
/// </summary>
public sealed class SharedBundledHost(Func<UserModeModule, IModuleHostConnection> startRaw)
{
    private readonly Group _userMode = new(startRaw);
    private readonly Group _elevated = new(startRaw);

    public IModuleHostConnection Start(UserModeModule module) =>
        !module.Bundled ? startRaw(module) : (module.Elevated ? _elevated : _userMode).Open(module);

    private sealed class Group(Func<UserModeModule, IModuleHostConnection> startRaw)
    {
        private readonly object _gate = new();
        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, VirtualConnection> _active = new(StringComparer.OrdinalIgnoreCase);
        private IModuleHostConnection? _raw;
        private Task _writeTail = Task.CompletedTask;

        private Task EnqueueWriteLocked(IModuleHostConnection raw, string line, CancellationToken ct)
        {
            var previous = _writeTail;
            var current = RunWriteAsync(previous, raw, line, ct);
            _writeTail = WaitQuietlyAsync(previous, current);
            return current;
        }

        private static async Task RunWriteAsync(Task previous, IModuleHostConnection raw, string line, CancellationToken ct)
        {
            await previous.WaitAsync(ct).ConfigureAwait(false);
            await raw.WriteLineAsync(line, ct).ConfigureAwait(false);
        }

        private static async Task WaitQuietlyAsync(Task previous, Task current)
        {
            try { await previous.ConfigureAwait(false); } catch { }
            try { await current.ConfigureAwait(false); } catch { }
        }

        public IModuleHostConnection Open(UserModeModule module)
        {
            VirtualConnection[] stale = [];
            VirtualConnection? replaced = null;
            IModuleHostConnection? deadRaw = null;
            VirtualConnection vc;
            lock (_gate)
            {
                if (_raw is null || _raw.HasExited)
                {
                    stale = [.. _active.Values];
                    _active.Clear();
                    deadRaw = _raw;
                    _writeTail = Task.CompletedTask;
                    _raw = startRaw(module with { Path = "--shared" });
                    var captured = _raw;
                    _ = Task.Run(() => ReadLoopAsync(captured));
                }
                vc = new VirtualConnection(this, _raw, module.Path);
                if (_active.TryRemove(module.Path, out replaced) && !_raw.HasExited)
                {
                    _ = EnqueueWriteLocked(_raw, new ModuleHostMessage { Type = "exit", Module = module.Path }.ToLine(), CancellationToken.None);
                }
                _active[module.Path] = vc;
            }
            foreach (var s in stale) s.CompleteInbox();
            replaced?.CompleteInbox();
            if (deadRaw is not null)
            {
                try { deadRaw.Dispose(); } catch { }
            }
            return vc;
        }

        private async Task ReadLoopAsync(IModuleHostConnection raw)
        {
            try
            {
                while (await raw.ReadLineAsync(CancellationToken.None).ConfigureAwait(false) is { } line)
                {
                    var m = ModuleHostMessage.Parse(line);
                    if (m?.Module is { Length: > 0 } mod && _active.TryGetValue(mod, out var vc) && ReferenceEquals(vc.Raw, raw))
                        vc.Deliver(line);
                }
            }
            catch { }
            finally
            {
                VirtualConnection[] victims;
                lock (_gate)
                {
                    victims = _active.Where(kv => ReferenceEquals(kv.Value.Raw, raw))
                        .Where(kv => _active.TryRemove(kv))
                        .Select(kv => kv.Value)
                        .ToArray();
                    if (ReferenceEquals(_raw, raw))
                    {
                        _raw = null;
                        _writeTail = Task.CompletedTask;
                    }
                }
                foreach (var vc in victims) vc.CompleteInbox();
            }
        }

        public Task WriteRawAsync(IModuleHostConnection raw, string line, CancellationToken ct)
        {
            lock (_gate) return EnqueueWriteLocked(raw, line, ct);
        }

        public void Kill(IModuleHostConnection raw)
        {
            VirtualConnection[] victims;
            lock (_gate)
            {
                victims = _active.Where(kv => ReferenceEquals(kv.Value.Raw, raw))
                    .Where(kv => _active.TryRemove(kv))
                    .Select(kv => kv.Value)
                    .ToArray();
                if (ReferenceEquals(_raw, raw))
                {
                    _raw = null;
                    _writeTail = Task.CompletedTask;
                }
            }
            foreach (var vc in victims) vc.CompleteInbox();
            raw.Kill();
        }

        public void CloseVirtual(VirtualConnection vc, IModuleHostConnection raw, string modulePath)
        {
            IModuleHostConnection? toDispose = null;
            lock (_gate)
            {
                var removed = _active.TryRemove(new KeyValuePair<string, VirtualConnection>(modulePath, vc));
                if (!removed) return;
                if (ReferenceEquals(_raw, raw) && _active.IsEmpty)
                {
                    toDispose = _raw;
                    _raw = null;
                    _writeTail = Task.CompletedTask;
                }
                else if (ReferenceEquals(_raw, raw) && !raw.HasExited)
                {
                    _ = EnqueueWriteLocked(raw, new ModuleHostMessage { Type = "exit", Module = modulePath }.ToLine(), CancellationToken.None);
                }
            }
            if (toDispose is not null)
            {
                try { toDispose.Dispose(); } catch { }
            }
        }
    }

    private sealed class VirtualConnection(Group group, IModuleHostConnection raw, string modulePath) : IModuleHostConnection
    {
        private readonly System.Threading.Channels.Channel<string> _inbox = System.Threading.Channels.Channel.CreateUnbounded<string>();
        private int _disposed;

        internal IModuleHostConnection Raw => raw;
        public void Deliver(string line) => _inbox.Writer.TryWrite(line);
        public void CompleteInbox() => _inbox.Writer.TryComplete();

        public async Task WriteLineAsync(string line, CancellationToken ct)
        {
            var m = ModuleHostMessage.Parse(line);
            if (m is not null) line = (m with { Module = modulePath }).ToLine();
            await group.WriteRawAsync(raw, line, ct).ConfigureAwait(false);
        }

        public async Task<string?> ReadLineAsync(CancellationToken ct)
        {
            try { return await _inbox.Reader.ReadAsync(ct).ConfigureAwait(false); }
            catch (System.Threading.Channels.ChannelClosedException) { return null; }
        }

        public bool HasExited => Volatile.Read(ref _disposed) != 0 || raw.HasExited;
        public void Kill() => group.Kill(raw);

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            CompleteInbox();
            group.CloseVirtual(this, raw, modulePath);
        }
    }
}

/// <summary>Starts RemotePCDiagnostics.ModuleHost from the app folder with the current token (tests; the Windows host restricts it).</summary>
public sealed class ProcessModuleHostLauncher : IModuleHostLauncher
{
    public const string HostName = "RemotePCDiagnostics.ModuleHost";
    private readonly string? _directory;
    private readonly ILogger? _log;
    private readonly SharedBundledHost _shared;

    public ProcessModuleHostLauncher(string? directory = null, ILogger? log = null)
    {
        _directory = directory;
        _log = log;
        _shared = new SharedBundledHost(StartRaw);
    }

    public static (string File, string Args) Command(string directory, UserModeModule module)
    {
        var exe = Path.Combine(directory, HostName + (OperatingSystem.IsWindows() ? ".exe" : ""));
        var dll = Path.Combine(directory, HostName + ".dll");
        var args = module.Path == "--shared" ? "--shared" : $"\"{module.Path}\"";
        return File.Exists(exe) ? (exe, args) : File.Exists(dll) ? ("dotnet", $"\"{dll}\" {args}") : throw new FileNotFoundException("Module host not found", exe);
    }

    public IModuleHostConnection Start(UserModeModule module) => _shared.Start(module);

    public IModuleHostConnection StartRaw(UserModeModule module)
    {
        var (file, args) = Command(_directory ?? AppContext.BaseDirectory, module);
        var psi = new ProcessStartInfo(file, args)
        {
            UseShellExecute = false, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true,
        };
        var p = Process.Start(psi) ?? throw new InvalidOperationException("Module host did not start");
        p.ErrorDataReceived += (_, e) => { if (e.Data is { Length: > 0 }) _log.Info($"Module host [{module.Manifest.Slug}]: {e.Data}"); };
        p.BeginErrorReadLine();
        return new Connection(p);
    }

    private sealed class Connection(Process p) : IModuleHostConnection
    {
        public Process Process => p;
        public async Task WriteLineAsync(string line, CancellationToken ct) { await p.StandardInput.WriteLineAsync(line.AsMemory(), ct).ConfigureAwait(false); await p.StandardInput.FlushAsync(ct).ConfigureAwait(false); }
        public Task<string?> ReadLineAsync(CancellationToken ct) => p.StandardOutput.ReadLineAsync(ct).AsTask();
        public bool HasExited { get { try { return p.HasExited; } catch { return true; } } }
        public void Kill() { try { if (!p.HasExited) p.Kill(entireProcessTree: true); } catch { } }
        public void Dispose()
        {
            try { p.StandardInput.Close(); } catch { } // closing stdin ends the host
            try { if (!p.WaitForExit(2000)) Kill(); } catch { Kill(); }
            p.Dispose();
        }
    }
}

/// <summary>Marks a module whose code runs out of process in user mode (the module page shows the "Unsigned module" banner).</summary>
public interface IUserModeModule : IDiagnosticModule
{
    UserModeModule Source { get; }

    /// <summary>Asks the module host to stop the run in progress (what the module's own Cancel does in process); nothing when none is.</summary>
    void Stop();
}

/// <summary>
/// Stands in for an out-of-process module inside the app: the descriptor comes from its manifest (or the app's own, for a module that ships
/// with the app), the work happens in the module host. An unsigned module's report is shown with every one-click action removed, because
/// those run elevated in the app.
/// </summary>
public sealed class UserModeModuleProxy(UserModeModule module, IModuleHostLauncher launcher, ILogger? log = null, HostQueryServer? hostQueries = null)
    : IUserModeModule, IModuleFeatures, IDisposable
{
    private readonly SemaphoreSlim _write = new(1, 1);

    private async Task WriteAsync(IModuleHostConnection conn, ModuleHostMessage m, CancellationToken ct)
    {
        await _write.WaitAsync(ct).ConfigureAwait(false);
        try { await conn.WriteLineAsync(m.ToLine(), ct).ConfigureAwait(false); }
        finally { _write.Release(); }
    }

    /// <summary>How many host queries of this module the app answers at once; more wait their turn.</summary>
    public const int MaxConcurrentQueries = 4;

    private readonly SemaphoreSlim _queries = new(MaxConcurrentQueries, MaxConcurrentQueries);

    /// <summary>
    /// The module asked the app for a reading (a host query): answer it in the background, so a slow query (osquery, a drive read) doesn't
    /// hold up the module's other queries, its progress or its answer to "stop". A query still running when the request is cancelled or
    /// done is answered "cancelled", so the module is never left waiting on the app.
    /// </summary>
    private void Answer(IModuleHostConnection conn, ModuleHostMessage query, Queries queries) =>
        queries.Track(Task.Run(() => AnswerAsync(conn, query, queries.Token)));

    private async Task AnswerAsync(IModuleHostConnection conn, ModuleHostMessage query, CancellationToken ct)
    {
        ModuleHostMessage answer;
        try
        {
            await _queries.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                answer = hostQueries is null
                    ? new ModuleHostMessage { Type = "answer", Id = query.Id, Ok = false, Error = "notAllowed", Reason = "this app answers no host queries" }
                    : await hostQueries.AnswerAsync(module, query, ct).ConfigureAwait(false);
            }
            finally { _queries.Release(); }
        }
        catch (OperationCanceledException)
        {
            answer = new ModuleHostMessage { Type = "answer", Id = query.Id, Ok = false, Error = "cancelled", Reason = "the run was stopped" };
        }
        catch (Exception ex)
        {
            answer = new ModuleHostMessage { Type = "answer", Id = query.Id, Ok = false, Error = "failed", Reason = ex.Message };
        }
        try { await WriteAsync(conn, answer, CancellationToken.None).ConfigureAwait(false); }
        catch (Exception ex) { log.Info($"Module host [{Name}]: answer {query.Id} not sent: {ex.Message}"); } // the host has gone
    }

    /// <summary>The host queries of one request (an availability check or a run): cancelled together when the request is stopped or ends.</summary>
    private sealed class Queries(CancellationToken outer) : IDisposable
    {
        private readonly CancellationTokenSource _cts = CancellationTokenSource.CreateLinkedTokenSource(outer);
        private readonly List<Task> _running = [];
        public CancellationToken Token => _cts.Token;
        public void Track(Task t) { lock (_running) { _running.RemoveAll(r => r.IsCompleted); _running.Add(t); } }
        public void Cancel() { try { _cts.Cancel(); } catch (ObjectDisposedException) { } }
        public void Dispose()
        {
            Cancel();
            Task[] left;
            lock (_running) left = [.. _running];
            // The token source goes once the last answer is written.
            _ = Task.WhenAll(left).ContinueWith(_ => _cts.Dispose(), TaskScheduler.Default);
        }
    }

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly object _connGate = new();
    private IModuleHostConnection? _conn;

    public UserModeModule Source => module;
    public Guid Id => module.Manifest.Id;
    public string Name => module.Manifest.Slug;
    public string DisplayName => module.Descriptor.DisplayName;
    public bool IncludeInRunAll => module.Descriptor.Kind == ModuleKind.Check; // the app's own descriptor for a module that ships with it
    public event EventHandler<DiagnosticResult>? Updated;

    /// <summary>How long the host gets to answer an availability check, and to stop after being asked.</summary>
    public TimeSpan AnswerTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>How long the host waits after a request before it exits (a run's availability check and the run share one host), unless
    /// the module's manifest keeps it running.</summary>
    public TimeSpan IdleExit { get; init; } = TimeSpan.FromSeconds(2);

    private Timer? _idle;
    private bool _disposed;

    /// <summary>True while a module host is running for this module.</summary>
    public bool IsHostRunning { get { lock (_connGate) return _conn is { HasExited: false }; } }

    /// <summary>A request finished: unless the manifest keeps the host running, it exits once nothing new arrives for <see cref="IdleExit"/>.</summary>
    private void Idle()
    {
        if (module.Manifest.KeepAlive) return;
        lock (_connGate)
        {
            if (_disposed) return;
            _idle?.Dispose();
            _idle = new Timer(_ =>
            {
                if (!_gate.Wait(0)) return; // a new request is running; it schedules its own exit
                try { log.Info($"Module host [{Name}]: done, exiting"); Reset(); }
                finally { _gate.Release(); }
            }, null, IdleExit, Timeout.InfiniteTimeSpan);
        }
    }

    private void Busy() { lock (_connGate) { _idle?.Dispose(); _idle = null; } }

    public async Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        Busy();
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(AnswerTimeout);
            var conn = Connect();
            using var queries = new Queries(timeout.Token);
            await WriteAsync(conn, new ModuleHostMessage { Type = "availability" }, timeout.Token).ConfigureAwait(false);
            while (true)
            {
                var m = Read(await conn.ReadLineAsync(timeout.Token).ConfigureAwait(false) ?? throw Exited());
                if (m?.Type == "query") { Answer(conn, m, queries); continue; }
                if (m?.Type == "availability") return m.Available == true ? ModuleAvailability.Available : ModuleAvailability.Unavailable(m.Reason ?? "Unavailable");
                if (m?.Type == "error") return ModuleAvailability.Unavailable(m.Message ?? "The module host failed");
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex) { Reset(); return ModuleAvailability.Unavailable($"The module host didn't answer: {ex.Message}"); }
        finally { _gate.Release(); Idle(); }
    }

    public Task<DiagnosticResult> RefreshAsync(IProgress<string>? progress, CancellationToken cancellationToken = default) =>
        RefreshCoreAsync(null, progress, cancellationToken);

    /// <summary>A per-device module (<see cref="ModuleManifest.PerDevice"/>): runs it against one device in the module host.</summary>
    public Task<DiagnosticResult> RefreshAsync(ModuleInstance instance, IProgress<string>? progress, CancellationToken cancellationToken = default) =>
        RefreshCoreAsync(instance, progress, cancellationToken);

    /// <summary>A per-device module (<see cref="ModuleManifest.PerDevice"/>): the devices it runs against, found in the module host.
    /// Never throws: a host that can't answer makes the module not apply, with the reason.</summary>
    public async Task<ModuleDetection> DetectAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        Busy();
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(CallTimeout); // a drive list can take as long as a run's first read
            var conn = Connect();
            using var queries = new Queries(timeout.Token);
            await WriteAsync(conn, new ModuleHostMessage { Type = "detect" }, timeout.Token).ConfigureAwait(false);
            while (true)
            {
                var m = Read(await conn.ReadLineAsync(timeout.Token).ConfigureAwait(false) ?? throw Exited());
                if (m?.Type == "query") { Answer(conn, m, queries); continue; }
                if (m?.Type == "detection")
                    return m.Reason is { } reason ? ModuleDetection.NotApplicable(reason) : ModuleDetection.For(m.Instances ?? []);
                if (m?.Type == "error") return ModuleDetection.NotApplicable(m.Message ?? "The module host failed");
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex) { Reset(); return ModuleDetection.NotApplicable($"The module host didn't answer: {ex.Message}"); }
        finally { _gate.Release(); Idle(); }
    }

    private async Task<DiagnosticResult> RefreshCoreAsync(ModuleInstance? instance, IProgress<string>? progress, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        Busy();
        try
        {
            var conn = Connect();
            lock (_connGate) _refreshing = conn;
            await WriteAsync(conn, new ModuleHostMessage { Type = "refresh", Instance = instance }, CancellationToken.None).ConfigureAwait(false);
            using var queries = new Queries(CancellationToken.None);
            using var stopping = cancellationToken.Register(() =>
            {
                queries.Cancel(); // queries still running are answered "cancelled" right away
                try { _ = WriteAsync(conn, new ModuleHostMessage { Type = "stop" }, CancellationToken.None); } catch { }
            });
            // After a cancel the module gets one AnswerTimeout to answer "stop"; past that the host is reset.
            async Task<string?> GraceReadAsync()
            {
                using var grace = new CancellationTokenSource(AnswerTimeout);
                try { return await conn.ReadLineAsync(grace.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) { Reset(); throw new OperationCanceledException(cancellationToken); }
            }
            while (true)
            {
                string? line;
                if (cancellationToken.IsCancellationRequested) line = await GraceReadAsync().ConfigureAwait(false);
                else
                {
                    try { line = await conn.ReadLineAsync(cancellationToken).ConfigureAwait(false); }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { line = await GraceReadAsync().ConfigureAwait(false); }
                }
                var m = Read(line ?? throw Exited());
                switch (m?.Type)
                {
                    case "query":
                        // Answered even while stopping ("cancelled" then), so the module isn't left waiting on the app.
                        Answer(conn, m, queries);
                        break;
                    case "progress":
                        if (m.Total is > 1) progress.ReportStep(m.Step ?? 0, m.Total.Value, m.Message ?? "");
                        else if (m.Message is { Length: > 0 }) progress?.Report(m.Message);
                        break;
                    case "updated":
                    {
                        var updatedReport = m.Report is { } ur ? (module.Bundled ? ur : WithoutActions(ur)) : null;
                        DiagnosticResult updatedResult;
                        if (updatedReport is null && module.Bundled && m.Payload is { } up && m.PayloadType is { } ut
                            && ModuleHostPayloads.Read(Name, m.Status ?? DiagnosticStatus.Running, m.Message ?? "", up, ut) is { } typedUpdate)
                            updatedResult = typedUpdate;
                        else if (updatedReport is not null)
                            updatedResult = new DiagnosticResult<AreaReport>(Name, m.Status ?? DiagnosticStatus.Running, m.Message ?? "", m.When ?? DateTimeOffset.Now, updatedReport);
                        else
                            updatedResult = new DiagnosticResult(Name, m.Status ?? DiagnosticStatus.Running, m.Message ?? "", m.When ?? DateTimeOffset.Now);
                        if (m.When is { } when) updatedResult = updatedResult with { Timestamp = when };
                        var inst = m.Instance ?? instance;
                        if (inst is not null) updatedResult = updatedResult with { InstanceKey = inst.Key, InstanceLabel = inst.Label };
                        Updated?.Invoke(this, updatedResult with { Cancelled = m.Cancelled == true });
                        break;
                    }
                    case "result":
                        // What the page needs besides the report: only from a module that ships with the app (it decides which rows get
                        // the app's Start/Stop buttons). A run without any keeps the last.
                        if (module.Bundled && m.PageData is { } pageData) SetPageData(pageData);
                        // One-click fixes run elevated in the app: only a module that ships with the app may offer them.
                        var report = m.Report is { } r ? (module.Bundled ? r : WithoutActions(r)) : null;
                        // Another payload type only from a module that ships with the app (its own page reads it).
                        if (report is null && module.Bundled && m.Payload is { } payload && m.PayloadType is { } type
                            && ModuleHostPayloads.Read(Name, m.Status ?? DiagnosticStatus.Error, m.Message ?? "", payload, type) is { } typed)
                            return typed with { Cancelled = m.Cancelled == true || cancellationToken.IsCancellationRequested };
                        return new DiagnosticResult<AreaReport>(Name, m.Status ?? DiagnosticStatus.Error, m.Message ?? "", DateTimeOffset.Now, report)
                            { Cancelled = m.Cancelled == true || cancellationToken.IsCancellationRequested };
                    case "error":
                        return CouldNotRun.Result(Name, m.Message ?? "The module failed");
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            Reset();
            log.Info($"Module host [{Name}]: {ex.Message}");
            return CouldNotRun.Result(Name, $"The module host stopped: {ex.Message}");
        }
        finally
        {
            lock (_connGate) _refreshing = null;
            _gate.Release();
            Idle();
        }
    }

    private IModuleHostConnection? _refreshing;

    public void Stop()
    {
        IModuleHostConnection? conn;
        lock (_connGate) conn = _refreshing;
        if (conn is null) return;
        log.Info($"Module host [{Name}]: asked to stop");
        _ = WriteAsync(conn, new ModuleHostMessage { Type = "stop" }, CancellationToken.None).ContinueWith(_ => { }, TaskScheduler.Default);
    }

    /// <summary>How long a call from the module's page (<see cref="CallAsync"/>) may take; past that the host is reset.</summary>
    public TimeSpan CallTimeout { get; init; } = TimeSpan.FromMinutes(3);

    private int _lastCallId;

    /// <summary>
    /// Runs call <paramref name="name"/> on the module in the module host (<see cref="ModulePageCalls"/>), starting the host if it isn't
    /// running, and answering the module's host queries meanwhile. Waits for a run in progress. Only for a module that ships with the app.
    /// Throws <see cref="ModuleCallException"/> when the host can't answer.
    /// </summary>
    public async Task<JsonElement?> CallAsync(string name, JsonElement? args, CancellationToken cancellationToken = default)
    {
        if (!module.Bundled) throw new ModuleCallException("notAllowed", "only modules that ship with the app take calls from their page");
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        Busy();
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(CallTimeout);
            var conn = Connect();
            var id = Interlocked.Increment(ref _lastCallId);
            using var queries = new Queries(timeout.Token);
            log.Info($"Module host [{Name}]: call {id} {name}");
            await WriteAsync(conn, new ModuleHostMessage { Type = "call", Id = id, Name = name, Args = args }, timeout.Token).ConfigureAwait(false);
            while (true)
            {
                var m = Read(await conn.ReadLineAsync(timeout.Token).ConfigureAwait(false) ?? throw Exited());
                switch (m)
                {
                    case { Type: "query" }: Answer(conn, m, queries); break;
                    case { Type: "return" } when m.Id == id:
                        return m.Ok == true ? m.Value : throw new ModuleCallException(m.Error ?? "failed", m.Reason ?? "the module couldn't answer");
                    case { Type: "error" }: throw new ModuleCallException("failed", m.Message ?? "the module host failed");
                }
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            Reset();
            throw new ModuleCallException("timeout", $"the module didn't answer within {CallTimeout.TotalSeconds:0} s");
        }
        catch (IOException ex)
        {
            Reset();
            throw new ModuleCallException("failed", ex.Message);
        }
        finally { _gate.Release(); Idle(); }
    }

    private readonly object _pageGate = new();
    private IReadOnlyDictionary<string, ServiceInfo>? _serviceRows;
    private string? _hangCard;
    private AreaPanels _panels;
    private (HashSet<string> Keys, object? Report)? _combined;

    private void SetPageData(Dictionary<string, JsonElement> data)
    {
        lock (_pageGate)
        {
            _serviceRows = ModulePageCalls.ReadServiceRows(data);
            _hangCard = ModulePageCalls.ReadHangCard(data);
            _panels = ModulePageCalls.ReadPanels(data);
            if (ModulePageCalls.ReadCombined(data) is { } combined) _combined = combined;
        }
    }

    /// <summary>What the module's page asks of the module, served from its last run's page data and calls to the module host.</summary>
    public T? Feature<T>() where T : class
    {
        if (!module.Bundled) return null;
        lock (_pageGate)
        {
            if (typeof(T) == typeof(IServiceRows) && _serviceRows is { } rows) return new ServiceRowsFeature(rows) as T;
            if (typeof(T) == typeof(IHangEvidenceSource) && _hangCard is { } card) return new HangEvidenceFeature(this, card) as T;
            if (typeof(T) == typeof(IHasAreaPanels) && _panels != AreaPanels.None) return new PanelsFeature(_panels) as T;
        }
        return null;
    }

    /// <summary>
    /// A per-device module's one report of all devices (<see cref="IInstanceSummary.Combine"/>): the module host's own combination when
    /// it covers the same devices, which it does after a normal run; otherwise the devices' reports one after another.
    /// </summary>
    public object? Combine(IReadOnlyList<DiagnosticResult> instanceResults)
    {
        var keys = instanceResults.Select(r => r.InstanceKey).OfType<string>().ToHashSet(StringComparer.OrdinalIgnoreCase);
        lock (_pageGate)
            if (_combined is { } c && c.Keys.SetEquals(keys)) return c.Report;
        if (instanceResults.Count == 1) return instanceResults[0].Payload;
        var reports = instanceResults.Select(r => r.Payload).OfType<AreaReport>().ToList();
        if (reports.Count == 0) return null;
        static int Severity(DiagnosticStatus s) => s switch { DiagnosticStatus.Error => 3, DiagnosticStatus.Warning => 2, DiagnosticStatus.Ok => 1, _ => 0 };
        return new AreaReport([.. reports.SelectMany(r => r.Cards)], string.Join(" · ", reports.Select(r => r.Summary).Where(t => t.Length > 0).Distinct()),
            reports.Select(r => r.Status).OrderByDescending(Severity).First(), reports.Select(r => r.Notice).FirstOrDefault(n => n is not null));
    }

    private sealed class PanelsFeature(AreaPanels panels) : IHasAreaPanels
    {
        public AreaPanels Panels => panels;
    }

    private sealed class ServiceRowsFeature(IReadOnlyDictionary<string, ServiceInfo> rows) : IServiceRows
    {
        public IReadOnlyDictionary<string, ServiceInfo> Latest => rows; // the same dictionary until the next run, as in process
    }

    private sealed class HangEvidenceFeature(UserModeModuleProxy proxy, string cardId) : IHangEvidenceSource
    {
        public string HangCardId => cardId;

        public async Task<string> FindHangEvidenceAsync(IReadOnlyList<HangOccurrence> occurrences, CancellationToken ct)
        {
            try
            {
                var value = await proxy.CallAsync(ModulePageCalls.HangEvidence, JsonSerializer.SerializeToElement(occurrences, ModuleHostMessage.Json), ct)
                    .ConfigureAwait(false);
                return value is { ValueKind: JsonValueKind.String } v ? v.GetString() ?? "" : "";
            }
            catch (ModuleCallException ex) { return $"Couldn't look up the related events: {ex.Message}"; }
        }
    }

    /// <summary>A line from the module host; one that isn't a message, and each query, is logged (a dropped query would leave the module
    /// waiting).</summary>
    private ModuleHostMessage? Read(string line)
    {
        var m = ModuleHostMessage.Parse(line);
        if (m is null && !string.IsNullOrWhiteSpace(line)) log.Info($"Module host [{Name}]: unreadable line ({line.Length} chars) ignored");
        else if (m?.Type == "query") log.Info($"Module host [{Name}]: query {m.Id} {m.Capability} received");
        return m;
    }

    /// <summary>One-click actions run elevated in the app, so an unsigned module never gets to offer them.</summary>
    public static AreaReport WithoutActions(AreaReport r)
    {
        static AreaCard Card(AreaCard c) => c with { Actions = null, Rows = (c.Rows ?? []).Select(row => row with { Actions = null, DumpPath = null }).ToList() };
        return r with { Cards = (r.Cards ?? []).Select(Card).ToList(), ReviewedCards = r.ReviewedCards?.Select(Card).ToList() };
    }

    private IModuleHostConnection Connect()
    {
        lock (_connGate)
        {
            if (_conn is { HasExited: false } c) return c;
            _conn?.Dispose();
            _conn = launcher.Start(module);
            log.Info($"Module host [{Name}]: started for {module.Path}");
            return _conn;
        }
    }

    /// <summary>Ends the module host (closing its stdin).</summary>
    public void Dispose()
    {
        lock (_connGate)
        {
            if (_disposed) return;
            _disposed = true;
            _idle?.Dispose();
            _idle = null;
        }
        Reset();
    }

    private void Reset() { lock (_connGate) { _conn?.Dispose(); _conn = null; } }
    private static IOException Exited() => new("the module host exited");
}

/// <summary>
/// The app's stand-in for a module that ships with the app and runs once per device (<see cref="ModuleManifest.PerDevice"/>, Drive
/// health), out of process: the devices are detected and each one is run in the module host, so the module keeps one result per device
/// and its page one card per device, as in process.
/// </summary>
public sealed class PerDeviceModuleProxy(UserModeModuleProxy inner) : IPerDeviceModule, IInstanceSummary, IUserModeModule, IModuleFeatures, IDisposable
{
    public UserModeModuleProxy Inner => inner;
    public UserModeModule Source => inner.Source;
    public Guid Id => inner.Id;
    public string Name => inner.Name;
    public string DisplayName => inner.DisplayName;
    public bool IncludeInRunAll => inner.IncludeInRunAll;
    public event EventHandler<DiagnosticResult>? Updated { add => inner.Updated += value; remove => inner.Updated -= value; }
    public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken = default) => inner.CheckAvailabilityAsync(cancellationToken);
    public Task<DiagnosticResult> RefreshAsync(IProgress<string>? progress, CancellationToken cancellationToken = default) => inner.RefreshAsync(progress, cancellationToken);
    public Task<DiagnosticResult> RefreshAsync(ModuleInstance instance, IProgress<string>? progress, CancellationToken ct = default) => inner.RefreshAsync(instance, progress, ct);
    public Task<ModuleDetection> DetectAsync(CancellationToken ct = default) => inner.DetectAsync(ct);
    public object? Combine(IReadOnlyList<DiagnosticResult> instanceResults) => inner.Combine(instanceResults);
    public void Stop() => inner.Stop();
    public T? Feature<T>() where T : class => inner.Feature<T>();
    public void Dispose() => inner.Dispose();

    /// <summary>The stand-in for <paramref name="module"/>: per device when its manifest says so and it ships with the app.</summary>
    public static IDiagnosticModule For(UserModeModuleProxy proxy) =>
        proxy.Source is { Bundled: true, Manifest.PerDevice: true } ? new PerDeviceModuleProxy(proxy) : proxy;
}
