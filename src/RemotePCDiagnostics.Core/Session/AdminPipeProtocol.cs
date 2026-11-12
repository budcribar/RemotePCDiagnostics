using System.Buffers.Binary;
using System.Collections.Frozen;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32.SafeHandles;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Session;

/// <summary>
/// Bridges allowlisted system repair commands from an un-elevated <c>RemotePCDiagnostics.Host</c> process
/// to the connected <c>RemotePCDiagnostics.Admin</c> Named-Pipe helper when Admin Repair Mode is enabled.
/// </summary>
public interface IElevatedCommandBridge
{
    bool IsConnected { get; }

    Task<ProcessResult?> RunElevatedAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        TimeSpan timeout,
        CancellationToken ct,
        Action<string>? outputLine = null);
}

public static class AdminCommandAllowlist
{
    private static readonly FrozenDictionary<string, string> CanonicalRelativePaths =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["sfc.exe"] = "sfc.exe",
            ["dism.exe"] = "dism.exe",
            ["ipconfig.exe"] = "ipconfig.exe",
            ["netsh.exe"] = "netsh.exe",
            ["defrag.exe"] = "defrag.exe",
            ["powercfg.exe"] = "powercfg.exe",
            ["sc.exe"] = "sc.exe",
            ["wevtutil.exe"] = "wevtutil.exe",
            ["pnputil.exe"] = "pnputil.exe",
            ["reg.exe"] = "reg.exe",
            ["schtasks.exe"] = "schtasks.exe",
            ["shutdown.exe"] = "shutdown.exe",
            ["tpmtool.exe"] = "tpmtool.exe",
            ["dsregcmd.exe"] = "dsregcmd.exe",
            ["w32tm.exe"] = "w32tm.exe",
            ["powershell.exe"] = Path.Combine("WindowsPowerShell", "v1.0", "powershell.exe"),
        }.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

    public static IReadOnlyCollection<string> AllowedExecutableNames => CanonicalRelativePaths.Keys;

    /// <summary>
    /// Validates that <paramref name="requestedFileName"/> names an allowlisted Windows system repair tool and resolves its
    /// canonical path strictly under <see cref="Environment.SystemDirectory"/>. Rooted paths pointing outside the system directory
    /// are rejected so a caller can never execute an arbitrary binary with a spoofed leaf name.
    /// </summary>
    public static bool TryResolveSystemTool(string? requestedFileName, out string resolvedPath)
    {
        resolvedPath = "";
        if (string.IsNullOrWhiteSpace(requestedFileName))
            return false;

        var trimmed = requestedFileName.Trim();
        var leaf = Path.GetFileName(trimmed);
        if (string.IsNullOrEmpty(leaf) || !CanonicalRelativePaths.TryGetValue(leaf, out var canonicalRel))
            return false;

        var systemDir = Environment.SystemDirectory;
        var canonicalFull = string.IsNullOrEmpty(systemDir)
            ? canonicalRel
            : Path.Combine(systemDir, canonicalRel);

        // If caller passed an explicit directory path, require it to match the canonical system path.
        var hasDirectory = trimmed.Contains(Path.DirectorySeparatorChar) || trimmed.Contains(Path.AltDirectorySeparatorChar);
        if (hasDirectory && !string.IsNullOrEmpty(systemDir))
        {
            try
            {
                var requestedFull = Path.GetFullPath(trimmed);
                var expectedFull = Path.GetFullPath(canonicalFull);
                if (!string.Equals(requestedFull, expectedFull, StringComparison.OrdinalIgnoreCase))
                    return false;
            }
            catch
            {
                return false;
            }
        }

        resolvedPath = canonicalFull;
        return true;
    }
}

public sealed record AdminPipeRequest(
    [property: JsonPropertyName("op")] string Op,
    [property: JsonPropertyName("fileName")] string? FileName = null,
    [property: JsonPropertyName("arguments")] IReadOnlyList<string>? Arguments = null,
    [property: JsonPropertyName("timeoutMs")] int TimeoutMs = 60_000);

public sealed record AdminPipeResponse(
    [property: JsonPropertyName("ok")] bool Ok,
    [property: JsonPropertyName("allowed")] bool Allowed = true,
    [property: JsonPropertyName("elevated")] bool Elevated = false,
    [property: JsonPropertyName("helperPid")] int HelperPid = 0,
    [property: JsonPropertyName("exitCode")] int ExitCode = -1,
    [property: JsonPropertyName("stdOut")] string StdOut = "",
    [property: JsonPropertyName("stdErr")] string StdErr = "",
    [property: JsonPropertyName("timedOut")] bool TimedOut = false,
    [property: JsonPropertyName("error")] string? Error = null);

/// <summary>
/// Length-prefixed (4-byte little-endian int32 + UTF-8 JSON) framing over Named Pipes with zero third-party dependencies.
/// </summary>
public static class AdminPipeFraming
{
    public const int MaxFrameBytes = 16 * 1024 * 1024; // 16 MB cap against malformed/unbounded frames
    public const string OpPing = "ping";
    public const string OpRunCommand = "run_command";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static async Task WriteFrameAsync<T>(Stream stream, T payload, CancellationToken ct)
    {
        var jsonBytes = JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions);
        if (jsonBytes.Length == 0 || jsonBytes.Length > MaxFrameBytes)
            throw new InvalidDataException($"Frame size {jsonBytes.Length} is out of bounds (1..{MaxFrameBytes}).");

        var header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, jsonBytes.Length);
        await stream.WriteAsync(header, ct).ConfigureAwait(false);
        await stream.WriteAsync(jsonBytes, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    public static async Task<T?> ReadFrameAsync<T>(Stream stream, CancellationToken ct)
    {
        var header = new byte[4];
        var readHeader = await ReadExactOrEofAsync(stream, header, ct).ConfigureAwait(false);
        if (readHeader == 0)
            return default; // Clean EOF

        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length <= 0 || length > MaxFrameBytes)
            throw new InvalidDataException($"Invalid pipe frame length: {length}.");

        var body = new byte[length];
        await ReadExactAsync(stream, body, ct).ConfigureAwait(false);
        return JsonSerializer.Deserialize<T>(body, JsonOptions);
    }

    private static async Task<int> ReadExactOrEofAsync(Stream stream, byte[] buffer, CancellationToken ct)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(offset, buffer.Length - offset), ct).ConfigureAwait(false);
            if (n == 0)
            {
                if (offset == 0) return 0;
                throw new EndOfStreamException("Unexpected EOF while reading frame header.");
            }
            offset += n;
        }
        return offset;
    }

    private static async Task ReadExactAsync(Stream stream, byte[] buffer, CancellationToken ct)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(offset, buffer.Length - offset), ct).ConfigureAwait(false);
            if (n == 0)
                throw new EndOfStreamException("Unexpected EOF while reading frame body.");
            offset += n;
        }
    }
}

/// <summary>
/// Client end of the Named-Pipe elevated helper connection used by <see cref="ElevationService"/> and <see cref="SystemCommandRunner"/>.
/// </summary>
public sealed class AdminPipeClient : IElevatedCommandBridge, IAsyncDisposable, IDisposable
{
    private readonly NamedPipeClientStream _pipe;
    private readonly SemaphoreSlim _requestLock = new(1, 1);
    private readonly ILogger? _log;
    private int _disposed;

    public event Action? Disconnected;

    public string PipeName { get; }
    public int HelperPid { get; private set; }
    public bool HelperIsElevated { get; private set; }

    public bool IsConnected => Volatile.Read(ref _disposed) == 0 && _pipe.IsConnected;

    private AdminPipeClient(string pipeName, NamedPipeClientStream pipe, ILogger? log)
    {
        PipeName = pipeName;
        _pipe = pipe;
        _log = log;
    }

    public static async Task<AdminPipeClient> ConnectAsync(
        string pipeName,
        TimeSpan connectTimeout,
        CancellationToken ct,
        ILogger? log = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pipeName);
        var pipe = new NamedPipeClientStream(
            serverName: ".",
            pipeName: pipeName,
            direction: PipeDirection.InOut,
            options: PipeOptions.Asynchronous);

        try
        {
            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            connectCts.CancelAfter(connectTimeout);
            await pipe.ConnectAsync(connectCts.Token).ConfigureAwait(false);

            var client = new AdminPipeClient(pipeName, pipe, log);
            var ping = await client.PingAsync(connectCts.Token).ConfigureAwait(false);
            if (!ping.Ok)
            {
                client.Dispose();
                throw new IOException(ping.Error ?? "Elevated helper rejected the connection.");
            }
            client.HelperPid = ping.HelperPid;
            client.HelperIsElevated = ping.Elevated;
            return client;
        }
        catch
        {
            pipe.Dispose();
            throw;
        }
    }

    public async Task<AdminPipeResponse> PingAsync(CancellationToken ct = default) =>
        await SendAsync(new AdminPipeRequest(AdminPipeFraming.OpPing), ct).ConfigureAwait(false);

    public async Task<AdminPipeResponse> RunCommandAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        TimeSpan timeout,
        CancellationToken ct = default)
    {
        var timeoutMs = (int)Math.Clamp(timeout.TotalMilliseconds, 1_000, 3_600_000);
        return await SendAsync(
            new AdminPipeRequest(AdminPipeFraming.OpRunCommand, fileName, arguments, timeoutMs),
            ct).ConfigureAwait(false);
    }

    public async Task<ProcessResult?> RunElevatedAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        TimeSpan timeout,
        CancellationToken ct,
        Action<string>? outputLine = null)
    {
        var response = await RunCommandAsync(fileName, arguments, timeout, ct).ConfigureAwait(false);
        if (!response.Allowed)
        {
            _log.Warn($"[admin-pipe] Rejected non-allowlisted command '{fileName}': {response.Error}");
            return null;
        }
        if (!response.Ok && response.Error is not null && response.ExitCode < 0 && !response.TimedOut)
        {
            _log.Warn($"[admin-pipe] Command '{Path.GetFileName(fileName)}' failed in helper: {response.Error}");
            return null;
        }

        if (outputLine is not null && !string.IsNullOrEmpty(response.StdOut))
        {
            foreach (var line in response.StdOut.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
            {
                try { outputLine(line); } catch { }
            }
        }

        return new ProcessResult(response.ExitCode, response.StdOut, response.StdErr, response.TimedOut);
    }

    private async Task<AdminPipeResponse> SendAsync(AdminPipeRequest request, CancellationToken ct)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        await _requestLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (!_pipe.IsConnected)
                throw new IOException("Admin helper named pipe is disconnected.");

            await AdminPipeFraming.WriteFrameAsync(_pipe, request, ct).ConfigureAwait(false);
            var response = await AdminPipeFraming.ReadFrameAsync<AdminPipeResponse>(_pipe, ct).ConfigureAwait(false);
            if (response is null)
                throw new IOException("Admin helper closed the named pipe connection.");
            return response;
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
            Dispose();
            throw;
        }
        finally
        {
            _requestLock.Release();
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;
        try { _pipe.Dispose(); } catch { }
        try { Disconnected?.Invoke(); } catch { }
    }

    public ValueTask DisposeAsync()
    {
        Dispose();
        return ValueTask.CompletedTask;
    }
}

public sealed record AdminPipeServerOptions
{
    public required string PipeName { get; init; }
    public int? ExpectedClientPid { get; init; }
    public string? ExpectedClientExePath { get; init; }
    public string? AllowedClientSid { get; init; }
    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(30);
    public Func<NamedPipeServerStream, (bool Allowed, string? Reason)>? CustomClientVerifier { get; init; }
}

/// <summary>
/// Server end of the Named-Pipe elevated helper. Enforces strict Windows PipeSecurity ACLs (Administrators, SYSTEM, and the
/// launching user SID; denies Network SID), verifies the connected client's PID and executable image path via Win32 APIs, and
/// executes only <see cref="AdminCommandAllowlist"/> system repair tools.
/// </summary>
public sealed class AdminPipeServer(
    AdminPipeServerOptions options,
    IProcessLauncher? launcher = null,
    ILogger? log = null) : IAsyncDisposable, IDisposable
{
    private readonly IProcessLauncher _launcher = launcher ?? new SystemProcessLauncher();
    private NamedPipeServerStream? _server;
    private int _disposed;

    public async Task RunSingleSessionAsync(CancellationToken ct)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        using var server = CreateSecuredServerStream(options);
        _server = server;

        using (var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            connectCts.CancelAfter(options.ConnectTimeout);
            await server.WaitForConnectionAsync(connectCts.Token).ConfigureAwait(false);
        }

        var (verified, reason) = VerifyConnectedClient(server, options);
        if (!verified)
        {
            log.Warn($"[admin-pipe-server] Rejected client connection on '{options.PipeName}': {reason}");
            try { server.Disconnect(); } catch { }
            return;
        }

        log.Info($"[admin-pipe-server] Verified client connected on '{options.PipeName}'.");

        while (server.IsConnected && !ct.IsCancellationRequested)
        {
            AdminPipeRequest? request;
            try
            {
                request = await AdminPipeFraming.ReadFrameAsync<AdminPipeRequest>(server, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException)
            {
                log.Warn($"[admin-pipe-server] Pipe read ended: {ex.Message}");
                break;
            }

            if (request is null)
                break; // Client closed pipe cleanly

            var response = await HandleRequestAsync(request, ct).ConfigureAwait(false);
            try
            {
                await AdminPipeFraming.WriteFrameAsync(server, response, ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException)
            {
                log.Warn($"[admin-pipe-server] Pipe write ended: {ex.Message}");
                break;
            }
        }
    }

    private async Task<AdminPipeResponse> HandleRequestAsync(AdminPipeRequest request, CancellationToken ct)
    {
        if (string.Equals(request.Op, AdminPipeFraming.OpPing, StringComparison.OrdinalIgnoreCase))
        {
            return new AdminPipeResponse(
                Ok: true,
                Allowed: true,
                Elevated: Environment.IsPrivilegedProcess,
                HelperPid: Environment.ProcessId,
                ExitCode: 0);
        }

        if (string.Equals(request.Op, AdminPipeFraming.OpRunCommand, StringComparison.OrdinalIgnoreCase))
        {
            if (!AdminCommandAllowlist.TryResolveSystemTool(request.FileName, out var resolvedTool))
            {
                return new AdminPipeResponse(
                    Ok: false,
                    Allowed: false,
                    Elevated: Environment.IsPrivilegedProcess,
                    HelperPid: Environment.ProcessId,
                    ExitCode: -1,
                    Error: $"Executable '{request.FileName}' is not on the elevated repair allowlist.");
            }

            var args = request.Arguments ?? [];
            var timeout = TimeSpan.FromMilliseconds(Math.Clamp(request.TimeoutMs, 1_000, 3_600_000));
            try
            {
                var pr = await _launcher.RunAsync(resolvedTool, args, timeout, ct).ConfigureAwait(false);
                return new AdminPipeResponse(
                    Ok: !pr.TimedOut,
                    Allowed: true,
                    Elevated: Environment.IsPrivilegedProcess,
                    HelperPid: Environment.ProcessId,
                    ExitCode: pr.ExitCode,
                    StdOut: pr.StdOut,
                    StdErr: pr.StdErr,
                    TimedOut: pr.TimedOut,
                    Error: pr.TimedOut ? "Command timed out." : null);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                return new AdminPipeResponse(
                    Ok: false,
                    Allowed: true,
                    Elevated: Environment.IsPrivilegedProcess,
                    HelperPid: Environment.ProcessId,
                    ExitCode: -1,
                    Error: ex.Message);
            }
        }

        return new AdminPipeResponse(
            Ok: false,
            Allowed: false,
            Elevated: Environment.IsPrivilegedProcess,
            HelperPid: Environment.ProcessId,
            ExitCode: -1,
            Error: $"Unknown operation '{request.Op}'.");
    }

    private static NamedPipeServerStream CreateSecuredServerStream(AdminPipeServerOptions options)
    {
        const PipeOptions pipeOpts = PipeOptions.Asynchronous | PipeOptions.FirstPipeInstance;
        if (!OperatingSystem.IsWindows())
        {
            return new NamedPipeServerStream(
                options.PipeName,
                PipeDirection.InOut,
                maxNumberOfServerInstances: 1,
                PipeTransmissionMode.Byte,
                pipeOpts);
        }

        var security = new PipeSecurity();
        var adminsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var anonymousSid = new SecurityIdentifier(WellKnownSidType.AnonymousSid, null);

        security.AddAccessRule(new PipeAccessRule(adminsSid, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(systemSid, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(anonymousSid, PipeAccessRights.FullControl, AccessControlType.Deny));

        using (var currentIdentity = WindowsIdentity.GetCurrent())
        {
            if (currentIdentity.User is { } currentUserSid)
                security.AddAccessRule(new PipeAccessRule(currentUserSid, PipeAccessRights.FullControl, AccessControlType.Allow));
        }

        if (!string.IsNullOrWhiteSpace(options.AllowedClientSid))
        {
            try
            {
                var clientSid = new SecurityIdentifier(options.AllowedClientSid);
                security.AddAccessRule(new PipeAccessRule(clientSid, PipeAccessRights.ReadWrite, AccessControlType.Allow));
            }
            catch
            {
                // Ignore malformed SID; client PID + path check still guards access.
            }
        }

        return NamedPipeServerStreamAcl.Create(
            options.PipeName,
            PipeDirection.InOut,
            maxNumberOfServerInstances: 1,
            PipeTransmissionMode.Byte,
            pipeOpts,
            inBufferSize: 65536,
            outBufferSize: 65536,
            security);
    }

    private static (bool Allowed, string? Reason) VerifyConnectedClient(
        NamedPipeServerStream server,
        AdminPipeServerOptions options)
    {
        if (options.CustomClientVerifier is { } custom)
            return custom(server);

        if (!OperatingSystem.IsWindows())
            return (true, null);

        if (IsRemoteNamedPipeClient(server.SafePipeHandle))
            return (false, "Remote network named-pipe clients are prohibited.");

        if (options.ExpectedClientPid is null && string.IsNullOrWhiteSpace(options.ExpectedClientExePath))
            return (true, null);

        if (!GetNamedPipeClientProcessId(server.SafePipeHandle, out var clientPidU32) || clientPidU32 == 0)
            return (false, $"GetNamedPipeClientProcessId failed (Win32 error {Marshal.GetLastWin32Error()}).");

        var clientPid = (int)clientPidU32;
        if (options.ExpectedClientPid is { } expectedPid && clientPid != expectedPid)
            return (false, $"Client PID {clientPid} did not match expected parent PID {expectedPid}.");

        if (!string.IsNullOrWhiteSpace(options.ExpectedClientExePath))
        {
            var actualExe = TryQueryProcessImagePath(clientPidU32);
            if (string.IsNullOrWhiteSpace(actualExe))
                return (false, $"Could not query executable path for client PID {clientPid}.");

            var expectedFull = Path.GetFullPath(options.ExpectedClientExePath);
            var actualFull = Path.GetFullPath(actualExe);
            if (!string.Equals(actualFull, expectedFull, StringComparison.OrdinalIgnoreCase))
                return (false, $"Client executable '{actualFull}' did not match expected '{expectedFull}'.");
        }

        var helperPfn = TryQueryProcessPackageFamilyName((uint)Environment.ProcessId);
        if (!string.IsNullOrWhiteSpace(helperPfn))
        {
            var clientPfn = TryQueryProcessPackageFamilyName(clientPidU32);
            if (!string.Equals(helperPfn, clientPfn, StringComparison.OrdinalIgnoreCase))
                return (false, $"Client MSIX package identity '{clientPfn ?? "<none>"}' did not match '{helperPfn}'.");
        }

        return (true, null);
    }

    private static bool IsRemoteNamedPipeClient(SafePipeHandle pipeHandle)
    {
        var sb = new StringBuilder(256);
        return GetNamedPipeClientComputerNameW(pipeHandle, sb, (uint)sb.Capacity);
    }

    private static string? TryQueryProcessPackageFamilyName(uint processId)
    {
        if (!OperatingSystem.IsWindows())
            return null;

        var hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
        if (hProcess == IntPtr.Zero)
            return null;
        try
        {
            var length = 130u;
            var sb = new StringBuilder((int)length);
            var rc = GetPackageFamilyName(hProcess, ref length, sb);
            return rc == 0 && length > 0 ? sb.ToString() : null;
        }
        catch
        {
            return null;
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }

    public static string? TryQueryProcessImagePath(uint processId)
    {
        if (!OperatingSystem.IsWindows())
            return null;

        var hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
        if (hProcess == IntPtr.Zero)
            return null;
        try
        {
            var capacity = 1024;
            var sb = new StringBuilder(capacity);
            var size = (uint)capacity;
            if (!QueryFullProcessImageNameW(hProcess, 0, sb, ref size))
                return null;
            return sb.ToString(0, (int)size);
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;
        try { _server?.Dispose(); } catch { }
    }

    public ValueTask DisposeAsync()
    {
        Dispose();
        return ValueTask.CompletedTask;
    }

    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle Pipe, out uint ClientProcessId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool GetNamedPipeClientComputerNameW(SafePipeHandle Pipe, StringBuilder ClientComputerName, uint ClientComputerNameLength);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetPackageFamilyName(IntPtr hProcess, ref uint packageFamilyNameLength, StringBuilder packageFamilyName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageNameW(IntPtr hProcess, uint dwFlags, StringBuilder lpExeName, ref uint lpdwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);
}
