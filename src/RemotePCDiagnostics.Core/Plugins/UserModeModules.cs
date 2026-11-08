using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Plugins;

/// <summary>
/// The line protocol between the app and RemotePCDiagnostics.ModuleHost (one JSON object per line over the helper's stdin and stdout, which
/// only the app holds). App to host: availability, refresh, stop, exit, answer. Host to app: ready, availability, progress, result, error,
/// query (a host query, <see cref="IHostQueries"/>, which the app answers with the same <see cref="Id"/>).
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
    public static readonly IReadOnlyList<Type> Types = [typeof(Sensors.SensorReport)];

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

/// <summary>Starts RemotePCDiagnostics.ModuleHost from the app folder with the current token (tests; the Windows host restricts it).</summary>
public sealed class ProcessModuleHostLauncher(string? directory = null, ILogger? log = null) : IModuleHostLauncher
{
    public const string HostName = "RemotePCDiagnostics.ModuleHost";

    public static (string File, string Args) Command(string directory, UserModeModule module)
    {
        var exe = Path.Combine(directory, HostName + (OperatingSystem.IsWindows() ? ".exe" : ""));
        var dll = Path.Combine(directory, HostName + ".dll");
        var args = $"\"{module.Path}\"";
        return File.Exists(exe) ? (exe, args) : File.Exists(dll) ? ("dotnet", $"\"{dll}\" {args}") : throw new FileNotFoundException("Module host not found", exe);
    }

    public IModuleHostConnection Start(UserModeModule module)
    {
        var (file, args) = Command(directory ?? AppContext.BaseDirectory, module);
        var psi = new ProcessStartInfo(file, args)
        {
            UseShellExecute = false, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true,
        };
        var p = Process.Start(psi) ?? throw new InvalidOperationException("Module host did not start");
        p.ErrorDataReceived += (_, e) => { if (e.Data is { Length: > 0 }) log.Info($"Module host [{module.Manifest.Slug}]: {e.Data}"); };
        p.BeginErrorReadLine();
        return new Connection(p);
    }

    private sealed class Connection(Process p) : IModuleHostConnection
    {
        public async Task WriteLineAsync(string line, CancellationToken ct) { await p.StandardInput.WriteLineAsync(line.AsMemory(), ct).ConfigureAwait(false); await p.StandardInput.FlushAsync(ct).ConfigureAwait(false); }
        public Task<string?> ReadLineAsync(CancellationToken ct) => p.StandardOutput.ReadLineAsync(ct).AsTask();
        public bool HasExited { get { try { return p.HasExited; } catch { return true; } } }
        public void Kill() { try { if (!p.HasExited) p.Kill(entireProcessTree: true); } catch { } }
        public void Dispose() { try { Kill(); } finally { p.Dispose(); } }
    }
}

/// <summary>Marks a module whose code runs out of process in user mode (the module page shows the "Unsigned module" banner).</summary>
public interface IUserModeModule : IDiagnosticModule
{
    UserModeModule Source { get; }
}

/// <summary>
/// Stands in for an out-of-process module inside the app: the descriptor comes from its manifest (or the app's own, for a module that ships
/// with the app), the work happens in the module host. An unsigned module's report is shown with every one-click action removed, because
/// those run elevated in the app.
/// </summary>
public sealed class UserModeModuleProxy(UserModeModule module, IModuleHostLauncher launcher, ILogger? log = null, HostQueryServer? hostQueries = null)
    : IUserModeModule, IDisposable
{
    private readonly SemaphoreSlim _write = new(1, 1);

    private async Task WriteAsync(IModuleHostConnection conn, ModuleHostMessage m, CancellationToken ct)
    {
        await _write.WaitAsync(ct).ConfigureAwait(false);
        try { await conn.WriteLineAsync(m.ToLine(), ct).ConfigureAwait(false); }
        finally { _write.Release(); }
    }

    /// <summary>The module asked the app for a reading (a host query): answer it, or refuse it when this app answers none.</summary>
    private async Task AnswerAsync(IModuleHostConnection conn, ModuleHostMessage query, CancellationToken ct)
    {
        var answer = hostQueries is null
            ? new ModuleHostMessage { Type = "answer", Id = query.Id, Ok = false, Error = "notAllowed", Reason = "this app answers no host queries" }
            : await hostQueries.AnswerAsync(module, query, ct).ConfigureAwait(false);
        await WriteAsync(conn, answer, CancellationToken.None).ConfigureAwait(false);
    }

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly object _connGate = new();
    private IModuleHostConnection? _conn;

    public UserModeModule Source => module;
    public Guid Id => module.Manifest.Id;
    public string Name => module.Manifest.Slug;
    public string DisplayName => module.Descriptor.DisplayName;
    public bool IncludeInRunAll => module.Descriptor.Kind == ModuleKind.Check; // the app's own descriptor for a module that ships with it
    public event EventHandler<DiagnosticResult>? Updated { add { } remove { } }

    /// <summary>How long the host gets to answer an availability check, and to stop after being asked.</summary>
    public TimeSpan AnswerTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>How long the host waits after a request before it exits (a run's availability check and the run share one host), unless
    /// the module's manifest keeps it running.</summary>
    public TimeSpan IdleExit { get; init; } = TimeSpan.FromSeconds(2);

    private Timer? _idle;

    /// <summary>True while a module host is running for this module.</summary>
    public bool IsHostRunning { get { lock (_connGate) return _conn is { HasExited: false }; } }

    /// <summary>A request finished: unless the manifest keeps the host running, it exits once nothing new arrives for <see cref="IdleExit"/>.</summary>
    private void Idle()
    {
        if (module.Manifest.KeepAlive) return;
        lock (_connGate)
        {
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
            await WriteAsync(conn, new ModuleHostMessage { Type = "availability" }, timeout.Token).ConfigureAwait(false);
            while (true)
            {
                var m = Read(await conn.ReadLineAsync(timeout.Token).ConfigureAwait(false) ?? throw Exited());
                if (m?.Type == "query") { await AnswerAsync(conn, m, timeout.Token).ConfigureAwait(false); continue; }
                if (m?.Type == "availability") return m.Available == true ? ModuleAvailability.Available : ModuleAvailability.Unavailable(m.Reason ?? "Unavailable");
                if (m?.Type == "error") return ModuleAvailability.Unavailable(m.Message ?? "The module host failed");
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex) { Reset(); return ModuleAvailability.Unavailable($"The module host didn't answer: {ex.Message}"); }
        finally { _gate.Release(); Idle(); }
    }

    public async Task<DiagnosticResult> RefreshAsync(IProgress<string>? progress, CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        Busy();
        try
        {
            var conn = Connect();
            await WriteAsync(conn, new ModuleHostMessage { Type = "refresh" }, CancellationToken.None).ConfigureAwait(false);
            using var stopping = cancellationToken.Register(() => { try { _ = WriteAsync(conn, new ModuleHostMessage { Type = "stop" }, CancellationToken.None); } catch { } });
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
                        // Answered even while stopping, so the module isn't left waiting on the app.
                        await AnswerAsync(conn, m, CancellationToken.None).ConfigureAwait(false);
                        break;
                    case "progress":
                        if (m.Total is > 1) progress.ReportStep(m.Step ?? 0, m.Total.Value, m.Message ?? "");
                        else if (m.Message is { Length: > 0 }) progress?.Report(m.Message);
                        break;
                    case "result":
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
        finally { _gate.Release(); Idle(); }
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
    public void Dispose() { Busy(); Reset(); }

    private void Reset() { lock (_connGate) { _conn?.Dispose(); _conn = null; } }
    private static IOException Exited() => new("the module host exited");
}
