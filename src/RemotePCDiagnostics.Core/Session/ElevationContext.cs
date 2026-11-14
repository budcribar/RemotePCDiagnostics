using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Core.Session;

public sealed record ElevationResult(
    bool Success,
    bool Cancelled,
    string Message);

public sealed record AdminHelperStartRequest(
    string HelperExecutablePath,
    string PipeName,
    int ParentPid,
    string? ClientSid);

/// <summary>
/// Tracks whether <c>RemotePCDiagnostics.Host</c> launched elevated or in Microsoft Store <c>asInvoker</c> standard-user mode,
/// and manages the on-demand <c>RemotePCDiagnostics.Agent</c> Named-Pipe elevated repair helper or full elevated Host relaunch.
/// </summary>
public interface IElevationContext
{
    bool IsProcessElevated { get; }
    bool IsAdminHelperConnected { get; }
    bool HasAdminCapabilities => IsProcessElevated || IsAdminHelperConnected;

    event Action? Changed;

    Task<ElevationResult> EnableAdminModeAsync(CancellationToken ct = default);
    Task<ElevationResult> RelaunchElevatedAsync(CancellationToken ct = default);
}

public sealed class ElevationService : IElevationContext, IElevatedCommandBridge, IDisposable
{
    public const string SimulateStandardUserEnvVar = "RPD_SIMULATE_STANDARD_USER";
    public const string AdminHelperExeName = "RemotePCDiagnostics.Agent.exe";
    public const string AdminPipeEnvVar = "RPD_ADMIN_PIPE";
    public const string AdminPipeArgPrefix = "--admin-pipe=";
    private const int ErrorCancelled = 1223; // ERROR_CANCELLED when user declines UAC prompt

    private readonly ISessionContext _session;
    private readonly ILogger? _log;
    private readonly string _baseDirectory;
    private readonly Func<bool> _isProcessElevated;
    private readonly Func<AdminHelperStartRequest, CancellationToken, Task<AdminPipeClient>>? _customConnector;
    private readonly Func<IReadOnlyList<string>, CancellationToken, Task<ElevationResult>>? _customRelauncher;
    private readonly SemaphoreSlim _enableGate = new(1, 1);
    private readonly object _stateLock = new();

    private AdminPipeClient? _client;
    private Process? _helperProcess;
    private Action? _closeCurrentWindow;
    private int _disposed;

    public event Action? Changed;

    public ElevationService(
        ISessionContext session,
        ILogger? log = null,
        string? baseDirectory = null,
        Func<bool>? isProcessElevated = null,
        Func<AdminHelperStartRequest, CancellationToken, Task<AdminPipeClient>>? customConnector = null,
        Func<IReadOnlyList<string>, CancellationToken, Task<ElevationResult>>? customRelauncher = null,
        string? initialPipeName = null)
    {
        _session = session ?? throw new ArgumentNullException(nameof(session));
        _log = log;
        _baseDirectory = !string.IsNullOrWhiteSpace(baseDirectory) ? baseDirectory : AppContext.BaseDirectory;
        _isProcessElevated = isProcessElevated ?? DetectProcessElevated;
        _customConnector = customConnector;
        _customRelauncher = customRelauncher;

        var initialPipe = !string.IsNullOrWhiteSpace(initialPipeName)
            ? initialPipeName
            : TryResolveInitialPipeName();
        if (!string.IsNullOrEmpty(initialPipe))
        {
            _ = Task.Run(async () =>
            {
                try
                {
                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                    await TryConnectPipeAsync(initialPipe, TimeSpan.FromSeconds(8), cts.Token).ConfigureAwait(false);
                }
                catch { }
            });
        }
    }

    public bool IsProcessElevated => _isProcessElevated();

    public bool IsAdminHelperConnected
    {
        get
        {
            lock (_stateLock)
                return _client is { IsConnected: true };
        }
    }

    public bool HasAdminCapabilities => IsProcessElevated || IsAdminHelperConnected;

    bool IElevatedCommandBridge.IsConnected => IsAdminHelperConnected;

    public void BindWindowClose(Action closeWindow) => _closeCurrentWindow = closeWindow;

    public static bool IsSimulateStandardUser()
    {
        var raw = Environment.GetEnvironmentVariable(SimulateStandardUserEnvVar)?.Trim();
        return string.Equals(raw, "1", StringComparison.OrdinalIgnoreCase)
            || string.Equals(raw, "true", StringComparison.OrdinalIgnoreCase);
    }

    public static bool DetectProcessElevated()
    {
        if (IsSimulateStandardUser())
            return false;

        if (OperatingSystem.IsWindows())
        {
            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                // Fall back to runtime privilege probe below.
            }
        }

        return Environment.IsPrivilegedProcess;
    }

    /// <summary>
    /// Builds the command-line arguments used to relaunch <c>RemotePCDiagnostics.Host.exe</c> elevated while preserving
    /// any active remote relay URL, session ID, shop group, unattended, and voice flags.
    /// </summary>
    public static IReadOnlyList<string> BuildRelaunchArguments(ISessionContext session)
    {
        ArgumentNullException.ThrowIfNull(session);
        var args = new List<string>();
        if (session.Mode == SessionMode.Remote && session.ServerUri is not null)
            args.Add($"-u={session.ServerUri.AbsoluteUri.TrimEnd('/')}");
        if (session.SessionId != Guid.Empty)
            args.Add($"-i={session.SessionId:D}");
        if (SessionLaunchOptions.NormalizeGroup(session.Group) is { } group)
            args.Add($"-g={group}");
        if (session.Unattended)
            args.Add(SessionLaunchOptions.UnattendedArg);
        if (session.Voice)
            args.Add(SessionLaunchOptions.VoiceArg);
        args.Add(SessionLaunchOptions.RestartedArg);
        return args;
    }

    public async Task<ElevationResult> EnableAdminModeAsync(CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (IsProcessElevated)
            return new ElevationResult(true, false, "Already running with Administrator privileges.");
        if (IsAdminHelperConnected)
            return new ElevationResult(true, false, "Admin Repair Mode is already active.");

        await _enableGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (IsAdminHelperConnected)
                return new ElevationResult(true, false, "Admin Repair Mode is already active.");

            var pipeName = $"rpd-admin-{Guid.NewGuid():N}";
            var helperExe = Path.Combine(_baseDirectory, AdminHelperExeName);
            var clientSid = TryGetCurrentUserSid();
            var request = new AdminHelperStartRequest(helperExe, pipeName, Environment.ProcessId, clientSid);

            AdminPipeClient client;
            Process? spawned = null;

            if (_customConnector is not null)
            {
                client = await _customConnector(request, ct).ConfigureAwait(false);
            }
            else
            {
                if (!File.Exists(helperExe))
                {
                    var msg = $"Admin repair helper executable was not found at '{helperExe}'.";
                    _log.Warn($"[elevation] {msg}");
                    return new ElevationResult(false, false, msg);
                }

                try
                {
                    spawned = StartAdminHelperProcess(request);
                }
                catch (Win32Exception ex) when (ex.NativeErrorCode == ErrorCancelled)
                {
                    _log.Info("[elevation] User cancelled the UAC prompt for Admin Repair Mode.");
                    return new ElevationResult(
                        Success: false,
                        Cancelled: true,
                        Message: "Administrator approval was cancelled. Standard User diagnostics remain available.");
                }
                catch (Exception ex)
                {
                    _log.Warn($"[elevation] Failed to launch Admin helper: {ex.Message}");
                    return new ElevationResult(false, false, $"Could not start Admin Repair Mode: {ex.Message}");
                }

                try
                {
                    client = await AdminPipeClient.ConnectAsync(pipeName, TimeSpan.FromSeconds(20), ct, _log).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    TryTerminateHelper(spawned);
                    throw;
                }
                catch (Exception ex)
                {
                    TryTerminateHelper(spawned);
                    _log.Warn($"[elevation] Failed to connect to Admin helper pipe '{pipeName}': {ex.Message}");
                    return new ElevationResult(false, false, $"Admin Repair Mode helper did not connect: {ex.Message}");
                }
            }

            AdminPipeClient? previous;
            Process? previousProc;
            lock (_stateLock)
            {
                previous = _client;
                previousProc = _helperProcess;
                _client = client;
                _helperProcess = spawned;
            }

            previous?.Dispose();
            TryTerminateHelper(previousProc);

            client.Disconnected += OnHelperDisconnected;
            _log.Info($"[elevation] Admin Repair Mode connected (helperPid={client.HelperPid}, elevated={client.HelperIsElevated}).");
            NotifyChanged();
            return new ElevationResult(true, false, "Admin Repair Mode enabled. Deep system repairs are unlocked.");
        }
        finally
        {
            _enableGate.Release();
        }
    }

    public async Task<ElevationResult> RelaunchElevatedAsync(CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (IsProcessElevated)
            return new ElevationResult(true, false, "Already running as Administrator.");

        var args = BuildRelaunchArguments(_session);
        if (_customRelauncher is not null)
            return await _customRelauncher(args, ct).ConfigureAwait(false);

        var preview = $"RemotePCDiagnostics.Host.exe {string.Join(' ', args)}";
        if (_closeCurrentWindow is not { } closeWindow
            || Environment.ProcessPath is not { Length: > 0 } exePath
            || !File.Exists(exePath))
        {
            _log.Info($"[elevation] Preview/headless relaunch requested: {preview}");
            return new ElevationResult(
                Success: true,
                Cancelled: false,
                Message: $"Configured elevated relaunch ({preview}).");
        }

        try
        {
            var argLine = string.Join(' ', args.Select(QuoteIfNeeded));
            var psi = IsSimulateStandardUser()
                ? new ProcessStartInfo(exePath, argLine)
                {
                    UseShellExecute = false,
                    WorkingDirectory = Path.GetDirectoryName(exePath) ?? _baseDirectory,
                }
                : new ProcessStartInfo(exePath, argLine)
                {
                    UseShellExecute = true,
                    Verb = "runas",
                    WorkingDirectory = Path.GetDirectoryName(exePath) ?? _baseDirectory,
                };

            Process.Start(psi);
            _log.Info($"[elevation] Started elevated Host copy: {exePath} {argLine}");
            closeWindow();
            return new ElevationResult(true, false, "Relaunching Remote PC Diagnostics as Administrator…");
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == ErrorCancelled)
        {
            _log.Info("[elevation] User cancelled UAC prompt for full Host relaunch.");
            return new ElevationResult(false, Cancelled: true, "Administrator relaunch was cancelled.");
        }
        catch (Exception ex)
        {
            _log.Warn($"[elevation] Failed to relaunch Host elevated: {ex.Message}");
            return new ElevationResult(false, false, $"Could not relaunch as Administrator: {ex.Message}");
        }
    }

    public async Task<ProcessResult?> RunElevatedAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        TimeSpan timeout,
        CancellationToken ct,
        Action<string>? outputLine = null)
    {
        AdminPipeClient? client;
        lock (_stateLock)
            client = _client;

        if (client is not { IsConnected: true })
            return null;

        return await client.RunElevatedAsync(fileName, arguments, timeout, ct, outputLine).ConfigureAwait(false);
    }

    public async Task<SensorSnapshot?> ReadSensorsAsync(CancellationToken ct = default)
    {
        AdminPipeClient? client;
        lock (_stateLock)
            client = _client;

        if (client is not { IsConnected: true })
            return null;

        return await client.ReadSensorsAsync(ct).ConfigureAwait(false);
    }

    public static string? TryResolveInitialPipeName(IReadOnlyList<string>? args = null)
    {
        if (args is not null)
        {
            foreach (var a in args)
            {
                if (a.StartsWith(AdminPipeArgPrefix, StringComparison.OrdinalIgnoreCase))
                    return a[AdminPipeArgPrefix.Length..].Trim();
            }
        }
        var fromEnv = Environment.GetEnvironmentVariable(AdminPipeEnvVar)?.Trim();
        return !string.IsNullOrEmpty(fromEnv) ? fromEnv : null;
    }

    public async Task<bool> TryConnectPipeAsync(string pipeName, TimeSpan timeout, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(pipeName)) return false;
        try
        {
            var client = await AdminPipeClient.ConnectAsync(pipeName, timeout, ct, _log).ConfigureAwait(false);
            AdminPipeClient? previous;
            lock (_stateLock)
            {
                previous = _client;
                _client = client;
            }
            previous?.Dispose();
            client.Disconnected += OnHelperDisconnected;
            _log?.Info($"[elevation] Connected to initial admin pipe '{pipeName}' (helperPid={client.HelperPid}, elevated={client.HelperIsElevated}).");
            NotifyChanged();
            return true;
        }
        catch (Exception ex)
        {
            _log?.Warn($"[elevation] Could not connect to initial admin pipe '{pipeName}': {ex.Message}");
            return false;
        }
    }

    private Process? StartAdminHelperProcess(AdminHelperStartRequest request)
    {
        var argParts = new List<string>
        {
            "--mode=helper",
            $"--parent-pid={request.ParentPid}",
            $"--pipe={request.PipeName}",
        };
        if (!string.IsNullOrWhiteSpace(request.ClientSid))
            argParts.Add($"--client-sid={request.ClientSid}");

        var workingDir = Path.GetDirectoryName(request.HelperExecutablePath) ?? _baseDirectory;
        if (IsSimulateStandardUser() || !OperatingSystem.IsWindows())
        {
            var psi = new ProcessStartInfo(request.HelperExecutablePath)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = workingDir,
            };
            foreach (var part in argParts)
                psi.ArgumentList.Add(part);
            return Process.Start(psi);
        }

        var shellPsi = new ProcessStartInfo(request.HelperExecutablePath, string.Join(' ', argParts.Select(QuoteIfNeeded)))
        {
            UseShellExecute = true,
            Verb = "runas",
            WindowStyle = ProcessWindowStyle.Hidden,
            WorkingDirectory = workingDir,
        };
        return Process.Start(shellPsi);
    }

    private void OnHelperDisconnected()
    {
        _log.Info("[elevation] Admin Repair Mode helper disconnected.");
        NotifyChanged();
    }

    private void NotifyChanged()
    {
        try { Changed?.Invoke(); } catch { }
    }

    private static string? TryGetCurrentUserSid()
    {
        if (!OperatingSystem.IsWindows())
            return null;
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return identity.User?.Value;
        }
        catch
        {
            return null;
        }
    }

    private static string QuoteIfNeeded(string arg) =>
        arg.Contains(' ') || arg.Contains('"')
            ? $"\"{arg.Replace("\"", "\\\"")}\""
            : arg;

    private static void TryTerminateHelper(Process? proc)
    {
        if (proc is null) return;
        try
        {
            if (!proc.HasExited)
                proc.Kill(entireProcessTree: true);
        }
        catch { }
        finally
        {
            try { proc.Dispose(); } catch { }
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;

        AdminPipeClient? client;
        Process? proc;
        lock (_stateLock)
        {
            client = _client;
            proc = _helperProcess;
            _client = null;
            _helperProcess = null;
        }

        if (client is not null)
        {
            client.Disconnected -= OnHelperDisconnected;
            client.Dispose();
        }
        TryTerminateHelper(proc);
        _enableGate.Dispose();
    }
}
