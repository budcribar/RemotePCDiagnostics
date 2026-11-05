using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Plugins;

/// <summary>
/// The line protocol between the app and RemotePCDiagnostics.ModuleHost (one JSON object per line over the helper's stdin and stdout, which
/// only the app holds). App to host: availability, refresh, stop, exit. Host to app: ready, availability, progress, result, error.
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

    public static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
    };

    public string ToLine() => JsonSerializer.Serialize(this, Json);
    public static ModuleHostMessage? Parse(string? line)
    {
        if (string.IsNullOrWhiteSpace(line)) return null;
        try { return JsonSerializer.Deserialize<ModuleHostMessage>(line, Json); } catch (JsonException) { return null; }
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
public sealed class ProcessModuleHostLauncher(string? directory = null, Action<string>? log = null) : IModuleHostLauncher
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
        p.ErrorDataReceived += (_, e) => { if (e.Data is { Length: > 0 }) log?.Invoke($"Module host [{module.Manifest.Slug}]: {e.Data}"); };
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
/// Stands in for an unsigned module inside the app: the descriptor comes from its manifest, the work happens in the module host. Its
/// report is shown in the generic view with every one-click action removed, because those run elevated in the app.
/// </summary>
public sealed class UserModeModuleProxy(UserModeModule module, IModuleHostLauncher launcher, Action<string>? log = null) : IUserModeModule, IDisposable
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly object _connGate = new();
    private IModuleHostConnection? _conn;

    public UserModeModule Source => module;
    public Guid Id => module.Manifest.Id;
    public string Name => module.Manifest.Slug;
    public string DisplayName => module.Descriptor.DisplayName;
    public bool IncludeInRunAll => module.Manifest.Kind == ModuleKind.Check;
    public event EventHandler<DiagnosticResult>? Updated { add { } remove { } }

    /// <summary>How long the host gets to answer an availability check, and to stop after being asked.</summary>
    public TimeSpan AnswerTimeout { get; init; } = TimeSpan.FromSeconds(30);

    public async Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(AnswerTimeout);
            var conn = Connect();
            await conn.WriteLineAsync(new ModuleHostMessage { Type = "availability" }.ToLine(), timeout.Token).ConfigureAwait(false);
            while (true)
            {
                var m = ModuleHostMessage.Parse(await conn.ReadLineAsync(timeout.Token).ConfigureAwait(false) ?? throw Exited());
                if (m?.Type == "availability") return m.Available == true ? ModuleAvailability.Available : ModuleAvailability.Unavailable(m.Reason ?? "Unavailable");
                if (m?.Type == "error") return ModuleAvailability.Unavailable(m.Message ?? "The module host failed");
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex) { Reset(); return ModuleAvailability.Unavailable($"The module host didn't answer: {ex.Message}"); }
        finally { _gate.Release(); }
    }

    public async Task<DiagnosticResult> RefreshAsync(IProgress<string>? progress, CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var conn = Connect();
            await conn.WriteLineAsync(new ModuleHostMessage { Type = "refresh" }.ToLine(), CancellationToken.None).ConfigureAwait(false);
            using var stopping = cancellationToken.Register(() => _ = conn.WriteLineAsync(new ModuleHostMessage { Type = "stop" }.ToLine(), CancellationToken.None));
            while (true)
            {
                string? line;
                if (cancellationToken.IsCancellationRequested)
                {
                    using var grace = new CancellationTokenSource(AnswerTimeout);
                    try { line = await conn.ReadLineAsync(grace.Token).ConfigureAwait(false); }
                    catch (OperationCanceledException) { Reset(); throw new OperationCanceledException(cancellationToken); }
                }
                else line = await conn.ReadLineAsync(CancellationToken.None).ConfigureAwait(false);
                var m = ModuleHostMessage.Parse(line ?? throw Exited());
                switch (m?.Type)
                {
                    case "progress":
                        if (m.Total is > 1) progress.ReportStep(m.Step ?? 0, m.Total.Value, m.Message ?? "");
                        else if (m.Message is { Length: > 0 }) progress?.Report(m.Message);
                        break;
                    case "result":
                        var report = m.Report is { } r ? WithoutActions(r) : null;
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
            log?.Invoke($"Module host [{Name}]: {ex.Message}");
            return CouldNotRun.Result(Name, $"The module host stopped: {ex.Message}");
        }
        finally { _gate.Release(); }
    }

    /// <summary>One-click actions run elevated in the app, so an unsigned module never gets to offer them.</summary>
    public static AreaReport WithoutActions(AreaReport r)
    {
        static AreaCard Card(AreaCard c) => c with { Actions = null, Rows = c.Rows.Select(row => row with { Actions = null }).ToList() };
        return r with { Cards = r.Cards.Select(Card).ToList(), ReviewedCards = r.ReviewedCards?.Select(Card).ToList() };
    }

    private IModuleHostConnection Connect()
    {
        lock (_connGate)
        {
            if (_conn is { HasExited: false } c) return c;
            _conn?.Dispose();
            _conn = launcher.Start(module);
            log?.Invoke($"Module host [{Name}]: started for {module.Path}");
            return _conn;
        }
    }

    /// <summary>Ends the module host (closing its stdin).</summary>
    public void Dispose() => Reset();

    private void Reset() { lock (_connGate) { _conn?.Dispose(); _conn = null; } }
    private static IOException Exited() => new("the module host exited");
}
