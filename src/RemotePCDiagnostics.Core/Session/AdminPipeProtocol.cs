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
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Security;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Core.Session;

/// <summary>
/// Bridges allowlisted system repair commands from an un-elevated <c>RemotePCDiagnostics.Host</c> process
/// to the connected <c>RemotePCDiagnostics.Agent</c> Named-Pipe helper when Admin Repair Mode is enabled.
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

    Task<SensorSnapshot?> ReadSensorsAsync(CancellationToken ct = default);
    Task<IReadOnlyList<DriveHealth>?> ReadDrivesAsync(CancellationToken ct = default);
    /// <summary>
    /// Has the elevated helper install the latest RPCD silently. <paramref name="relaunchArguments"/> is the app's command
    /// line for Setup to start it with afterwards (<see cref="SessionLaunchOptions.RestartArguments"/>), or null for none.
    /// </summary>
    Task<AppUpdateResult?> SelfUpdateAsync(AppUpdateChannel channel, IReadOnlyList<string>? relaunchArguments = null, CancellationToken ct = default) =>
        Task.FromResult<AppUpdateResult?>(null);

    /// <summary>
    /// Has the elevated helper run the security audit with administrator rights, with the HardeningKitty installed next to it. Null when
    /// it can't (not connected, or a helper from before this existed); throws <see cref="OperationCanceledException"/> when cancelled.
    /// </summary>
    Task<SecurityAuditRun?> RunSecurityAuditAsync(TimeSpan timeout, CancellationToken ct = default) =>
        Task.FromResult<SecurityAuditRun?>(null);

    /// <summary>
    /// The workflow's automatic sign-in, done by the Agent (it writes HKLM and an LSA secret). Each throws
    /// <see cref="InvalidOperationException"/> with the Agent's reason when it can't, and <see cref="NotSupportedException"/> when the
    /// Agent is from before this existed.
    /// </summary>
    Task<bool> ValidateCredentialsAsync(string user, string domain, string password, CancellationToken ct = default) =>
        throw new NotSupportedException("The Agent can't check sign-in passwords.");
    Task<AutoLogonBackup> EnableAutoLogonAsync(string user, string domain, string password, int logons, CancellationToken ct = default) =>
        throw new NotSupportedException("The Agent can't turn on automatic sign-in.");
    Task DisableAutoLogonAsync(AutoLogonBackup? backup, CancellationToken ct = default) =>
        throw new NotSupportedException("The Agent can't turn off automatic sign-in.");

    /// <summary>
    /// A system setting the fixes and undo change with administrator rights (<see cref="IAdminSettingsBackend"/>), made by the Agent.
    /// Throws <see cref="InvalidOperationException"/> with the Agent's reason when it can't, and <see cref="AdminRequiredException"/> when the
    /// Agent isn't connected or is from before this existed.
    /// </summary>
    Task ChangeSystemSettingAsync(AdminPipeSetting setting, CancellationToken ct = default) =>
        throw new AdminRequiredException("The Agent isn't connected. " + ElevationService.AdminRepairHint);

    /// <summary>
    /// A machine-wide change (<see cref="IMachineTweaks"/>: HKLM policy values, extension blocklists, the page file, Defender exclusions),
    /// made by the Agent. The response's <see cref="AdminPipeResponse.StdOut"/> carries what the change reads back. Throws
    /// <see cref="AdminRequiredException"/> when the Agent isn't connected or is from before this existed.
    /// </summary>
    Task<AdminPipeResponse> MachineTweakAsync(AdminPipeTweak tweak, CancellationToken ct = default) =>
        throw new AdminRequiredException("The Agent isn't connected. " + ElevationService.AdminRepairHint);

    /// <summary>
    /// Runs one of the Agent's own scripts (<see cref="AgentScripts"/>): the app sends the name and arguments, never PowerShell. A script
    /// the Agent refuses comes back with <see cref="SystemCommandRunner.AgentFailedExitCode"/> and the reason in StdErr. Throws
    /// <see cref="AdminRequiredException"/> when the Agent isn't connected or is from before this existed.
    /// </summary>
    Task<ProcessResult> RunAgentScriptAsync(AdminPipeScript script, TimeSpan timeout, CancellationToken ct, Action<string>? outputLine = null) =>
        throw new AdminRequiredException("The Agent isn't connected. " + ElevationService.AdminRepairHint);

    /// <summary>
    /// The undo journal (%ProgramData%\RemotePCDiagnostics\state\changes.json, which only administrators can open), read by the
    /// Agent. Null when it can't (not connected, or an Agent from before this existed).
    /// </summary>
    Task<IReadOnlyList<ChangeRecord>?> ReadChangeJournalAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<ChangeRecord>?>(null);
    /// <summary>Has the Agent take one undone change off the journal. False when it couldn't.</summary>
    Task<bool> RemoveJournalChangeAsync(Guid id, CancellationToken ct = default) => Task.FromResult(false);
    /// <summary>
    /// Has the Agent record a change the app just made in the undo journal. False when it couldn't (not connected, or an Agent from
    /// before this existed); the app keeps the record and tries again when the Agent connects.
    /// </summary>
    Task<bool> AddJournalChangeAsync(ChangeRecord change, CancellationToken ct = default) => Task.FromResult(false);

    /// <summary>
    /// One of the state files the Agent keeps for the app (<see cref="ProtectedStateFiles.AgentManaged"/>) in the state folder only
    /// administrators can open. <see cref="AgentStateRead.Ok"/> is false when the Agent couldn't read it (not connected, or too old);
    /// a file that isn't there is Ok with no JSON.
    /// </summary>
    Task<AgentStateRead> ReadStateFileAsync(string name, CancellationToken ct = default) => Task.FromResult(AgentStateRead.Failed);
    /// <summary>Has the Agent save one of those files (null JSON deletes it). False when it couldn't.</summary>
    Task<bool> WriteStateFileAsync(string name, string? json, CancellationToken ct = default) => Task.FromResult(false);
}

/// <summary>A state file as the Agent read it: <paramref name="Ok"/> false when it couldn't; <paramref name="Json"/> null when there's no file.</summary>
public sealed record AgentStateRead(bool Ok, string? Json)
{
    public static readonly AgentStateRead Failed = new(false, null);
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
            ["wevtutil.exe"] = "wevtutil.exe",
            ["pnputil.exe"] = "pnputil.exe",
            ["shutdown.exe"] = "shutdown.exe",
            ["tpmtool.exe"] = "tpmtool.exe",
            ["dsregcmd.exe"] = "dsregcmd.exe",
            ["w32tm.exe"] = "w32tm.exe",
            // Never powershell.exe or reg.exe: the Agent doesn't run scripts or registry edits the app wrote. Admin PowerShell is one of
            // the Agent's own scripts (AgentScripts, op agent_script); registry changes are typed ops (system_setting, machine_tweak).
        }.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

    // What an elevated script from the app never needs: downloading, decoding or compiling code, running a string as code,
    // starting another shell, and adding accounts. Matched after PowerShellScreen.Normalize, so splitting a name with
    // quotes, '+' or backticks ('Inv'+'oke-Expression', I`EX) does not get it past this list.
    private static readonly string[] BlockedPowerShellNames =
    [
        // Downloads
        "invoke-webrequest", "invoke-restmethod", "net.webclient", "webclient", "downloadstring", "downloadfile", "downloaddata",
        "openread", "start-bitstransfer", "system.net.http", "net.sockets", "net.webrequest",
        // Code from strings, encodings and the runtime
        "invoke-expression", "frombase64string", "-encodedcommand", "add-type", "reflection.assembly", "[char]", "[scriptblock]",
        "scriptblock]::create", "executioncontext", "invokecommand", "invokescript", "invoke-command", "start-job", "&(", "&$",
        // Tools that download or run code for you (WindowsUpdate.ps1 needs Start-Process for UsoClient.exe, and PowerShell runs
        // any program by its path anyway, so starting programs as such is not screened)
        "new-service", "certutil", "mshta", "rundll32", "regsvr32", "bitsadmin",
        // Accounts
        "new-localuser", "add-localgroupmember",
    ];

    /// <summary>Aliases and program names that are blocked as whole words only, because they are short.</summary>
    private static readonly HashSet<string> BlockedPowerShellWords = new(StringComparer.Ordinal)
    {
        "iex", "iwr", "irm", "icm", "sajb", "curl", "wget", "powershell", "powershell.exe", "pwsh", "pwsh.exe", "cmd", "cmd.exe",
        "wscript", "cscript", "-enc", "-ec",
    };

    /// <summary>Phrases with a space in them, matched with runs of whitespace collapsed to one space.</summary>
    private static readonly string[] BlockedPowerShellPhrases = ["net user", "net localgroup", "net1 user", "net1 localgroup"];

    /// <summary>
    /// The first blocked thing in <paramref name="script"/>, or null when there is none. This screens the scripts the elevated
    /// helper runs for the app; it is defence in depth on top of the helper checking that its caller is the app itself.
    /// </summary>
    public static string? FindBlockedPowerShell(string? script)
    {
        var (spaced, compact) = NormalizePowerShell(script ?? "");
        foreach (var name in BlockedPowerShellNames)
            if (compact.Contains(name, StringComparison.Ordinal)) return name;
        foreach (var phrase in BlockedPowerShellPhrases)
            if (spaced.Contains(phrase, StringComparison.Ordinal)) return phrase;
        foreach (var word in spaced.Split(PowerShellWordBreaks, StringSplitOptions.RemoveEmptyEntries))
        {
            if (BlockedPowerShellWords.Contains(word)) return word;
            // "C:\Windows\System32\cmd.exe" or "...\certutil.exe": the program name is the last path segment.
            var slash = word.LastIndexOfAny(['\\', '/']);
            if (slash >= 0 && BlockedPowerShellWords.Contains(word[(slash + 1)..])) return word[(slash + 1)..];
        }
        return null;
    }

    private static readonly char[] PowerShellWordBreaks = [' ', ';', '|', '(', ')', '{', '}', '[', ']', ',', '=', '&', '@', '$', '<', '>', '!'];

    /// <summary>
    /// Lowercase, without backticks, quotes or '+', so names split up as strings come back together. <c>spaced</c> keeps one
    /// space between words; <c>compact</c> has no whitespace at all.
    /// </summary>
    private static (string Spaced, string Compact) NormalizePowerShell(string script)
    {
        var spaced = new System.Text.StringBuilder(script.Length);
        var compact = new System.Text.StringBuilder(script.Length);
        var lastWasSpace = true;
        foreach (var raw in script)
        {
            if (raw is '`' or '\'' or '"' or '+' or '\u2018' or '\u2019' or '\u201C' or '\u201D')
                continue;
            if (char.IsWhiteSpace(raw))
            {
                if (!lastWasSpace) spaced.Append(' ');
                lastWasSpace = true;
                continue;
            }
            var c = char.ToLowerInvariant(raw);
            spaced.Append(c);
            compact.Append(c);
            lastWasSpace = false;
        }
        return (spaced.ToString(), compact.ToString());
    }

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

    /// <summary>
    /// Enforces argument constraints on high-risk allowlisted tools (<c>shutdown.exe</c>, <c>wevtutil.exe</c>)
    /// so an un-elevated caller cannot abuse them for arbitrary persistence, registry hijacking, or payload staging.
    /// </summary>
    public static bool TryValidateArguments(string? requestedFileName, IReadOnlyList<string>? arguments, out string? error)
    {
        error = null;
        var leaf = Path.GetFileName(requestedFileName?.Trim() ?? "");
        var args = arguments ?? [];

        if (string.Equals(leaf, "wevtutil.exe", StringComparison.OrdinalIgnoreCase))
        {
            // Only reading events (qe): clearing, exporting or changing a log isn't something the app asks the Agent to do.
            if (args.Count < 2 || !string.Equals(args[0].Trim(), "qe", StringComparison.OrdinalIgnoreCase)
                || args.Skip(1).Any(x => x.StartsWith("/sq", StringComparison.OrdinalIgnoreCase) || x.StartsWith("/lf:true", StringComparison.OrdinalIgnoreCase)))
            {
                error = "wevtutil.exe is restricted to reading events (qe).";
                return false;
            }
            return true;
        }

        if (string.Equals(leaf, "shutdown.exe", StringComparison.OrdinalIgnoreCase))
        {
            if (args.Count == 0 || args[0].Trim() is not ("/r" or "/g" or "/a" or "-r" or "-g" or "-a"))
            {
                error = "shutdown.exe is restricted to /r, /g, and /a.";
                return false;
            }
            return true;
        }

        return true;
    }
}

public sealed record AdminPipeRequest(
    [property: JsonPropertyName("op")] string Op,
    [property: JsonPropertyName("fileName")] string? FileName = null,
    [property: JsonPropertyName("arguments")] IReadOnlyList<string>? Arguments = null,
    [property: JsonPropertyName("timeoutMs")] int TimeoutMs = 60_000,
    [property: JsonPropertyName("channel")] string? Channel = null,
    [property: JsonPropertyName("autoLogon")] AdminPipeAutoLogon? AutoLogon = null,
    [property: JsonPropertyName("setting")] AdminPipeSetting? Setting = null,
    [property: JsonPropertyName("tweak")] AdminPipeTweak? Tweak = null,
    [property: JsonPropertyName("script")] AdminPipeScript? Script = null,
    [property: JsonPropertyName("changeId")] Guid? ChangeId = null,
    [property: JsonPropertyName("change")] ChangeRecord? Change = null,
    [property: JsonPropertyName("stateName")] string? StateName = null,
    [property: JsonPropertyName("stateJson")] string? StateJson = null);

/// <summary>The automatic sign-in requests' arguments. The password is sent only to check it and to turn sign-in on.</summary>
public sealed record AdminPipeAutoLogon(
    [property: JsonPropertyName("user")] string? User = null,
    [property: JsonPropertyName("domain")] string? Domain = null,
    [property: JsonPropertyName("password")] string? Password = null,
    [property: JsonPropertyName("logons")] int Logons = 0,
    [property: JsonPropertyName("backup")] AutoLogonBackup? Backup = null);

public sealed record AdminPipeResponse(
    [property: JsonPropertyName("ok")] bool Ok,
    [property: JsonPropertyName("allowed")] bool Allowed = true,
    [property: JsonPropertyName("elevated")] bool Elevated = false,
    [property: JsonPropertyName("helperPid")] int HelperPid = 0,
    [property: JsonPropertyName("exitCode")] int ExitCode = -1,
    [property: JsonPropertyName("stdOut")] string StdOut = "",
    [property: JsonPropertyName("stdErr")] string StdErr = "",
    [property: JsonPropertyName("timedOut")] bool TimedOut = false,
    [property: JsonPropertyName("error")] string? Error = null,
    [property: JsonPropertyName("sensors")] SensorSnapshot? Sensors = null,
    [property: JsonPropertyName("drives")] IReadOnlyList<DriveHealth>? Drives = null,
    [property: JsonPropertyName("updateResult")] AppUpdateResult? UpdateResult = null,
    [property: JsonPropertyName("report")] string? Report = null,
    [property: JsonPropertyName("cancelled")] bool Cancelled = false,
    [property: JsonPropertyName("autoLogonBackup")] AutoLogonBackup? AutoLogonBackup = null,
    [property: JsonPropertyName("changes")] IReadOnlyList<ChangeRecord>? Changes = null,
    [property: JsonPropertyName("stateJson")] string? StateJson = null);

/// <summary>
/// Length-prefixed (4-byte little-endian int32 + UTF-8 JSON) framing over Named Pipes with zero third-party dependencies.
/// </summary>
public static class AdminPipeFraming
{
    public const int MaxFrameBytes = 16 * 1024 * 1024; // 16 MB cap against malformed/unbounded frames
    public const string OpPing = "ping";
    public const string OpRunCommand = "run_command";
    public const string OpReadSensors = "read_sensors";
    public const string OpReadDrives = "read_drives";
    public const string OpSelfUpdate = "self_update";
    /// <summary>Runs the security audit elevated; the response carries the report CSV. The only request the client can cancel.</summary>
    public const string OpSecurityAudit = "security_audit";
    /// <summary>Sent while a <see cref="OpSecurityAudit"/> request runs: stops it. It gets no response of its own.</summary>
    public const string OpCancel = "cancel";
    public const string OpValidateCredentials = "validate_credentials";
    public const string OpEnableAutoLogon = "enable_autologon";
    public const string OpDisableAutoLogon = "disable_autologon";
    /// <summary>One <see cref="AdminPipeSetting"/> change (startup apps, services, hibernation, Fast Startup, DNS).</summary>
    public const string OpSystemSetting = "system_setting";
    /// <summary>The undo journal, which only administrators can open: read it, and take an undone change off it.</summary>
    public const string OpJournalList = "journal_list";
    public const string OpJournalRemove = "journal_remove";
    /// <summary>One <see cref="AdminPipeTweak"/> change (HKLM policy values, extension blocklists, page file, Defender exclusions).</summary>
    public const string OpMachineTweak = "machine_tweak";
    /// <summary>One <see cref="AdminPipeScript"/>: the Agent builds and runs that script (Security fixes, updates, clean-up, sign-in tasks).</summary>
    public const string OpAgentScript = "agent_script";
    /// <summary>Records a change the app just made in the undo journal.</summary>
    public const string OpJournalAdd = "journal_add";
    /// <summary>The workflow and benchmark state files in the state folder: read one, or save it (no JSON deletes it).</summary>
    public const string OpStateRead = "state_read";
    public const string OpStateWrite = "state_write";

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

    public async Task<SensorSnapshot?> ReadSensorsAsync(CancellationToken ct = default)
    {
        var response = await SendAsync(new AdminPipeRequest(AdminPipeFraming.OpReadSensors), ct).ConfigureAwait(false);
        if (!response.Ok || response.Sensors is null)
        {
            _log?.Warn($"[admin-pipe] ReadSensors failed: {response.Error ?? "no data"}");
            return null;
        }
        return response.Sensors;
    }

    public async Task<IReadOnlyList<DriveHealth>?> ReadDrivesAsync(CancellationToken ct = default)
    {
        var response = await SendAsync(new AdminPipeRequest(AdminPipeFraming.OpReadDrives), ct).ConfigureAwait(false);
        if (!response.Ok || response.Drives is null)
        {
            _log?.Warn($"[admin-pipe] ReadDrives failed: {response.Error ?? "no data"}");
            return null;
        }
        return response.Drives;
    }

    public async Task<AppUpdateResult?> SelfUpdateAsync(AppUpdateChannel channel, IReadOnlyList<string>? relaunchArguments = null, CancellationToken ct = default)
    {
        var channelName = channel == AppUpdateChannel.Prerelease ? "prerelease" : "stable";
        var response = await SendAsync(
            new AdminPipeRequest(AdminPipeFraming.OpSelfUpdate, Arguments: relaunchArguments, Channel: channelName, TimeoutMs: 300_000),
            ct).ConfigureAwait(false);
        if (response.UpdateResult is not null)
            return response.UpdateResult;
        return new AppUpdateResult(response.Ok, Error: response.Error);
    }

    public async Task<bool> ValidateCredentialsAsync(string user, string domain, string password, CancellationToken ct = default)
    {
        var r = await SendAsync(new AdminPipeRequest(AdminPipeFraming.OpValidateCredentials, AutoLogon: new(user, domain, password)), ct).ConfigureAwait(false);
        ThrowIfRefused(r);
        return r.Ok;
    }

    public async Task<AutoLogonBackup> EnableAutoLogonAsync(string user, string domain, string password, int logons, CancellationToken ct = default)
    {
        var r = await SendAsync(new AdminPipeRequest(AdminPipeFraming.OpEnableAutoLogon, AutoLogon: new(user, domain, password, logons)), ct).ConfigureAwait(false);
        ThrowIfRefused(r);
        if (!r.Ok || r.AutoLogonBackup is null) throw new InvalidOperationException(r.Error ?? "The Agent didn't turn on automatic sign-in.");
        return r.AutoLogonBackup;
    }

    public async Task DisableAutoLogonAsync(AutoLogonBackup? backup, CancellationToken ct = default)
    {
        var r = await SendAsync(new AdminPipeRequest(AdminPipeFraming.OpDisableAutoLogon, AutoLogon: new(Backup: backup)), ct).ConfigureAwait(false);
        ThrowIfRefused(r);
        if (!r.Ok) throw new InvalidOperationException(r.Error ?? "The Agent didn't turn off automatic sign-in.");
    }

    public async Task<IReadOnlyList<ChangeRecord>?> ReadChangeJournalAsync(CancellationToken ct = default)
    {
        var r = await SendAsync(new AdminPipeRequest(AdminPipeFraming.OpJournalList), ct).ConfigureAwait(false);
        if (!r.Ok) _log.Warn($"[admin-pipe] Reading the undo journal failed: {r.Error}");
        return r.Ok ? r.Changes ?? [] : null;
    }

    public async Task<bool> RemoveJournalChangeAsync(Guid id, CancellationToken ct = default)
    {
        var r = await SendAsync(new AdminPipeRequest(AdminPipeFraming.OpJournalRemove, ChangeId: id), ct).ConfigureAwait(false);
        if (!r.Ok) _log.Warn($"[admin-pipe] Removing {id} from the undo journal failed: {r.Error}");
        return r.Ok;
    }

    public async Task<bool> AddJournalChangeAsync(ChangeRecord change, CancellationToken ct = default)
    {
        var r = await SendAsync(new AdminPipeRequest(AdminPipeFraming.OpJournalAdd, Change: change), ct).ConfigureAwait(false);
        if (!r.Ok) _log.Warn($"[admin-pipe] Recording {change.Kind} '{change.Target}' in the undo journal failed: {r.Error}");
        return r.Ok;
    }

    public async Task<AgentStateRead> ReadStateFileAsync(string name, CancellationToken ct = default)
    {
        var r = await SendAsync(new AdminPipeRequest(AdminPipeFraming.OpStateRead, StateName: name), ct).ConfigureAwait(false);
        if (!r.Ok) _log.Warn($"[admin-pipe] Reading {name} failed: {r.Error}");
        return r.Ok ? new AgentStateRead(true, r.StateJson) : AgentStateRead.Failed;
    }

    public async Task<bool> WriteStateFileAsync(string name, string? json, CancellationToken ct = default)
    {
        var r = await SendAsync(new AdminPipeRequest(AdminPipeFraming.OpStateWrite, StateName: name, StateJson: json), ct).ConfigureAwait(false);
        if (!r.Ok) _log.Warn($"[admin-pipe] Saving {name} failed: {r.Error}");
        return r.Ok;
    }

    public async Task ChangeSystemSettingAsync(AdminPipeSetting setting, CancellationToken ct = default)
    {
        var r = await SendAsync(new AdminPipeRequest(AdminPipeFraming.OpSystemSetting, Setting: setting), ct).ConfigureAwait(false);
        // Not allowed = an Agent from before this existed ("Unknown operation"): it has to be updated before it can make these changes.
        // (A change the Agent refuses or that fails comes back allowed, with the reason.)
        if (!r.Allowed)
            throw new AdminRequiredException("The Agent on this PC can't change this setting yet. Update Remote PC Diagnostics, then try again.");
        if (!r.Ok) throw new InvalidOperationException(r.Error ?? "The Agent didn't make the change.");
    }

    public async Task<AdminPipeResponse> MachineTweakAsync(AdminPipeTweak tweak, CancellationToken ct = default)
    {
        var r = await SendAsync(new AdminPipeRequest(AdminPipeFraming.OpMachineTweak, Tweak: tweak, TimeoutMs: 180_000), ct).ConfigureAwait(false);
        // Not allowed = an Agent from before this existed ("Unknown operation"). A refused or failed change comes back allowed, with the reason.
        if (!r.Allowed)
            throw new AdminRequiredException("The Agent on this PC can't make this change yet. Update Remote PC Diagnostics, then try again.");
        return r;
    }

    public async Task<ProcessResult> RunAgentScriptAsync(AdminPipeScript script, TimeSpan timeout, CancellationToken ct, Action<string>? outputLine = null)
    {
        var timeoutMs = (int)Math.Clamp(timeout.TotalMilliseconds, 1_000, 3_600_000);
        var r = await SendAsync(new AdminPipeRequest(AdminPipeFraming.OpAgentScript, TimeoutMs: timeoutMs, Script: script), ct).ConfigureAwait(false);
        // Not allowed = an Agent from before this existed ("Unknown operation"). A script it refuses comes back allowed, with the reason.
        if (!r.Allowed)
            throw new AdminRequiredException("The Agent on this PC can't make this change yet. Update Remote PC Diagnostics, then try again.");
        if (r.ExitCode < 0 && !r.TimedOut && r.Error is not null)
        {
            _log.Warn($"[admin-pipe] Agent script '{script.Name}' not run: {r.Error}");
            return new ProcessResult(SystemCommandRunner.AgentFailedExitCode, "", r.Error);
        }
        if (outputLine is not null && !string.IsNullOrEmpty(r.StdOut))
            foreach (var line in r.StdOut.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
                try { outputLine(line); } catch { }
        return new ProcessResult(r.ExitCode, r.StdOut, r.StdErr, r.TimedOut);
    }

    /// <summary>An Agent from before a request existed answers "Unknown operation" (not allowed).</summary>
    private static void ThrowIfRefused(AdminPipeResponse r)
    {
        if (!r.Allowed) throw new NotSupportedException(r.Error ?? "The Agent doesn't support this request.");
    }

    /// <summary>How long after cancelling the client waits for the helper to answer the cancelled request before dropping the pipe.</summary>
    public static TimeSpan CancelGrace { get; set; } = TimeSpan.FromSeconds(20);

    public async Task<SecurityAuditRun?> RunSecurityAuditAsync(TimeSpan timeout, CancellationToken ct = default)
    {
        var timeoutMs = (int)Math.Clamp(timeout.TotalMilliseconds, 1_000, 3_600_000);
        var response = await SendCancellableAsync(new AdminPipeRequest(AdminPipeFraming.OpSecurityAudit, TimeoutMs: timeoutMs),
            TimeSpan.FromMilliseconds(timeoutMs) + TimeSpan.FromMinutes(1), ct).ConfigureAwait(false);
        if (response is null) return null;
        if (response.Cancelled) throw new OperationCanceledException(ct);
        if (!response.Allowed || (!response.Ok && !response.TimedOut))
        {
            _log?.Warn($"[admin-pipe] Security audit not run in helper: {response.Error ?? "no report"}");
            return null;
        }
        return new SecurityAuditRun(new ProcessResult(response.ExitCode, response.StdOut, response.StdErr, response.TimedOut), response.Report);
    }

    /// <summary>
    /// Sends a request the caller can cancel while it runs: on cancellation it sends <see cref="AdminPipeFraming.OpCancel"/> and waits
    /// (up to <see cref="CancelGrace"/>) for the request's own answer, so the next request doesn't read a stale one, then throws. Null when
    /// the helper doesn't answer within <paramref name="wait"/> (the pipe is dropped).
    /// </summary>
    private async Task<AdminPipeResponse?> SendCancellableAsync(AdminPipeRequest request, TimeSpan wait, CancellationToken ct)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        await _requestLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (!_pipe.IsConnected)
                throw new IOException("Admin helper named pipe is disconnected.");
            await AdminPipeFraming.WriteFrameAsync(_pipe, request, ct).ConfigureAwait(false);
            // Read without the caller's token: cancelling a pipe read mid-frame would leave half a frame behind. Dispose ends it.
            var read = AdminPipeFraming.ReadFrameAsync<AdminPipeResponse>(_pipe, CancellationToken.None);
            try
            {
                return await read.WaitAsync(wait, ct).ConfigureAwait(false)
                    ?? throw new IOException("Admin helper closed the named pipe connection.");
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                try
                {
                    await AdminPipeFraming.WriteFrameAsync(_pipe, new AdminPipeRequest(AdminPipeFraming.OpCancel), CancellationToken.None).ConfigureAwait(false);
                    await read.WaitAsync(CancelGrace).ConfigureAwait(false);
                }
                catch
                {
                    _log?.Warn($"[admin-pipe] Helper didn't answer the cancelled '{request.Op}' in time; dropping the pipe.");
                    Dispose();
                }
                throw;
            }
            catch (TimeoutException)
            {
                _log?.Warn($"[admin-pipe] Helper didn't answer '{request.Op}' within {wait}; dropping the pipe.");
                Dispose();
                return null;
            }
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
    public required string PipeName { get; set; }
    public int? ExpectedClientPid { get; set; }
    public string? ExpectedClientExePath { get; set; }
    public string? AllowedClientSid { get; set; }
    public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(30);
    public Func<NamedPipeServerStream, (bool Allowed, string? Reason)>? CustomClientVerifier { get; set; }
}

/// <summary>
/// Server end of the Named-Pipe elevated helper. Enforces strict Windows PipeSecurity ACLs (Administrators, SYSTEM, and the
/// launching user SID; denies Network SID), verifies the connected client's PID and executable image path via Win32 APIs, and
/// executes only <see cref="AdminCommandAllowlist"/> system repair tools.
/// </summary>
public sealed class AdminPipeServer(
    AdminPipeServerOptions options,
    IProcessLauncher? launcher = null,
    Func<CancellationToken, Task<SensorSnapshot?>>? sensorReader = null,
    ILogger? log = null,
    Func<AppUpdateChannel, IReadOnlyList<string>?, CancellationToken, Task<AppUpdateResult>>? selfUpdater = null,
    Func<TimeSpan, CancellationToken, Task<SecurityAuditRun>>? securityAuditor = null,
    IAutoLogonBackend? autoLogon = null,
    IAdminSettingsBackend? adminSettings = null,
    IMachineTweaks? machineTweaks = null,
    DefenderPaths? defenderPaths = null,
    string? appFolder = null,
    Func<IChangeJournal>? changeJournal = null,
    string? stateFolder = null) : IAsyncDisposable, IDisposable
{
    public AdminPipeServer(
        AdminPipeServerOptions options,
        IProcessLauncher? launcher,
        ILogger? log) : this(options, launcher, (Func<CancellationToken, Task<SensorSnapshot?>>?)null, log) { }

    public AdminPipeServer(
        AdminPipeServerOptions options,
        IProcessLauncher? launcher,
        Func<SensorSnapshot?>? syncSensorReader,
        ILogger? log = null) : this(options, launcher, syncSensorReader is null ? null : _ => Task.FromResult(syncSensorReader()), log) { }

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

        // A request read while a cancellable one ran (the client sends only a cancel then, so this is rare).
        Task<AdminPipeRequest?>? pendingRead = null;
        while (server.IsConnected && !ct.IsCancellationRequested)
        {
            AdminPipeRequest? request;
            try
            {
                request = await (pendingRead ?? AdminPipeFraming.ReadFrameAsync<AdminPipeRequest>(server, ct)).ConfigureAwait(false);
                pendingRead = null;
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
            if (string.Equals(request.Op, AdminPipeFraming.OpCancel, StringComparison.OrdinalIgnoreCase))
                continue; // Nothing is running to stop (the request finished first); a cancel gets no response.

            AdminPipeResponse response;
            if (string.Equals(request.Op, AdminPipeFraming.OpSecurityAudit, StringComparison.OrdinalIgnoreCase))
                (response, pendingRead) = await HandleCancellableAsync(server, request, ct).ConfigureAwait(false);
            else
                response = await HandleRequestAsync(request, ct).ConfigureAwait(false);
            try
            {
                await AdminPipeFraming.WriteFrameAsync(server, response, ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException)
            {
                log.Warn($"[admin-pipe-server] Pipe write ended: {ex.Message}");
                break;
            }
        }
    }

    /// <summary>
    /// Runs a request while reading the pipe for a <see cref="AdminPipeFraming.OpCancel"/>, which stops it. Returns its response and the
    /// read still open (or one that already brought the next request, or the client closing), for the loop to carry on with.
    /// </summary>
    private async Task<(AdminPipeResponse Response, Task<AdminPipeRequest?> Next)> HandleCancellableAsync(
        NamedPipeServerStream server, AdminPipeRequest request, CancellationToken ct)
    {
        using var runCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var work = HandleRequestAsync(request, runCts.Token);
        var next = AdminPipeFraming.ReadFrameAsync<AdminPipeRequest>(server, ct);
        while (true)
        {
            if (await Task.WhenAny(work, next).ConfigureAwait(false) == work)
                return (await work.ConfigureAwait(false), next);
            AdminPipeRequest? arrived;
            try { arrived = await next.ConfigureAwait(false); }
            catch
            {
                // The client went away (or the helper is stopping): stop the run, and let the loop see the failed read.
                runCts.Cancel();
                return (await work.ConfigureAwait(false), next);
            }
            if (arrived is null)
            {
                runCts.Cancel();
                return (await work.ConfigureAwait(false), next);
            }
            if (!string.Equals(arrived.Op, AdminPipeFraming.OpCancel, StringComparison.OrdinalIgnoreCase))
                return (await work.ConfigureAwait(false), next); // Handled after this one's response, in order.
            log.Info($"[admin-pipe-server] Cancelling '{request.Op}' at the client's request.");
            runCts.Cancel();
            next = AdminPipeFraming.ReadFrameAsync<AdminPipeRequest>(server, ct);
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
            if (!AdminCommandAllowlist.TryValidateArguments(request.FileName, args, out var argError))
            {
                return new AdminPipeResponse(
                    Ok: false,
                    Allowed: false,
                    Elevated: Environment.IsPrivilegedProcess,
                    HelperPid: Environment.ProcessId,
                    ExitCode: -1,
                    Error: argError ?? "Command arguments are not permitted by the elevated repair allowlist.");
            }
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

        if (string.Equals(request.Op, AdminPipeFraming.OpReadSensors, StringComparison.OrdinalIgnoreCase))
        {
            if (sensorReader is null)
            {
                return new AdminPipeResponse(
                    Ok: false,
                    Allowed: true,
                    Elevated: Environment.IsPrivilegedProcess,
                    HelperPid: Environment.ProcessId,
                    Error: "Sensor provider is not configured in admin helper.");
            }

            try
            {
                var snapshot = await sensorReader(ct).ConfigureAwait(false);
                return new AdminPipeResponse(
                    Ok: snapshot is not null,
                    Allowed: true,
                    Elevated: Environment.IsPrivilegedProcess,
                    HelperPid: Environment.ProcessId,
                    ExitCode: 0,
                    Sensors: snapshot);
            }
            catch (Exception ex)
            {
                return new AdminPipeResponse(
                    Ok: false,
                    Allowed: true,
                    Elevated: Environment.IsPrivilegedProcess,
                    HelperPid: Environment.ProcessId,
                    ExitCode: -1,
                    Error: $"Failed to read sensors: {ex.Message}");
            }
        }

        if (string.Equals(request.Op, AdminPipeFraming.OpReadDrives, StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var drives = Platform.WindowsStorageDriveReader.ReadDrives();
                return new AdminPipeResponse(
                    Ok: true,
                    Allowed: true,
                    Elevated: Environment.IsPrivilegedProcess,
                    HelperPid: Environment.ProcessId,
                    ExitCode: 0,
                    Drives: drives);
            }
            catch (Exception ex)
            {
                return new AdminPipeResponse(
                    Ok: false,
                    Allowed: true,
                    Elevated: Environment.IsPrivilegedProcess,
                    HelperPid: Environment.ProcessId,
                    ExitCode: -1,
                    Error: $"Failed to read drives: {ex.Message}");
            }
        }

        if (string.Equals(request.Op, AdminPipeFraming.OpSelfUpdate, StringComparison.OrdinalIgnoreCase))
        {
            if (selfUpdater is null)
            {
                return new AdminPipeResponse(
                    Ok: false,
                    Allowed: false,
                    Elevated: Environment.IsPrivilegedProcess,
                    HelperPid: Environment.ProcessId,
                    ExitCode: -1,
                    Error: "Self-update is not supported by this elevated helper.");
            }

            var channel = string.Equals(request.Channel, "prerelease", StringComparison.OrdinalIgnoreCase)
                ? AppUpdateChannel.Prerelease
                : AppUpdateChannel.Stable;
            try
            {
                var result = await selfUpdater(channel, request.Arguments, ct).ConfigureAwait(false);
                return new AdminPipeResponse(
                    Ok: result.Ok,
                    Allowed: true,
                    Elevated: Environment.IsPrivilegedProcess,
                    HelperPid: Environment.ProcessId,
                    ExitCode: result.Ok ? 0 : 1,
                    Error: result.Error,
                    UpdateResult: result);
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
                    Error: $"Self-update failed: {ex.Message}");
            }
        }

        if (string.Equals(request.Op, AdminPipeFraming.OpSecurityAudit, StringComparison.OrdinalIgnoreCase))
            return await RunSecurityAuditAsync(request, ct).ConfigureAwait(false);

        if (request.Op is AdminPipeFraming.OpValidateCredentials or AdminPipeFraming.OpEnableAutoLogon or AdminPipeFraming.OpDisableAutoLogon)
            return await Task.Run(() => HandleAutoLogon(request), ct).ConfigureAwait(false);

        if (string.Equals(request.Op, AdminPipeFraming.OpSystemSetting, StringComparison.OrdinalIgnoreCase))
            return await Task.Run(() => HandleSystemSetting(request), ct).ConfigureAwait(false);

        if (request.Op is AdminPipeFraming.OpJournalList or AdminPipeFraming.OpJournalRemove or AdminPipeFraming.OpJournalAdd)
            return await Task.Run(() => HandleJournal(request), ct).ConfigureAwait(false);

        if (string.Equals(request.Op, AdminPipeFraming.OpMachineTweak, StringComparison.OrdinalIgnoreCase))
            return await Task.Run(() => HandleMachineTweakAsync(request, ct), ct).ConfigureAwait(false);

        if (string.Equals(request.Op, AdminPipeFraming.OpAgentScript, StringComparison.OrdinalIgnoreCase))
            return await HandleAgentScriptAsync(request, ct).ConfigureAwait(false);

        if (request.Op is AdminPipeFraming.OpStateRead or AdminPipeFraming.OpStateWrite)
            return await Task.Run(() => HandleStateFile(request), ct).ConfigureAwait(false);

        return new AdminPipeResponse(
            Ok: false,
            Allowed: false,
            Elevated: Environment.IsPrivilegedProcess,
            HelperPid: Environment.ProcessId,
            ExitCode: -1,
            Error: $"Unknown operation '{request.Op}'.");
    }

    /// <summary>The maximum sign-ins automatic sign-in may be turned on for (the workflow needs two).</summary>
    public const int MaxAutoLogons = 5;

    private AdminPipeResponse HandleAutoLogon(AdminPipeRequest request)
    {
        AdminPipeResponse Answer(bool ok, string? error = null, bool allowed = true, AutoLogonBackup? backup = null) => new(
            Ok: ok, Allowed: allowed, Elevated: Environment.IsPrivilegedProcess, HelperPid: Environment.ProcessId, ExitCode: ok ? 0 : -1,
            Error: error, AutoLogonBackup: backup);

        if (autoLogon is null) return Answer(false, "Automatic sign-in is not supported by this elevated helper.", allowed: false);
        var a = request.AutoLogon ?? new AdminPipeAutoLogon();
        try
        {
            switch (request.Op)
            {
                case AdminPipeFraming.OpValidateCredentials:
                    if (string.IsNullOrWhiteSpace(a.User) || a.Password is null) return Answer(false, "A user name and password are required.");
                    return Answer(autoLogon.Validate(a.User, a.Domain ?? "", a.Password));
                case AdminPipeFraming.OpEnableAutoLogon:
                    if (string.IsNullOrWhiteSpace(a.User) || a.Password is null) return Answer(false, "A user name and password are required.");
                    if (a.Logons is < 1 or > MaxAutoLogons) return Answer(false, $"Automatic sign-in is limited to 1 to {MaxAutoLogons} sign-ins.");
                    var backup = autoLogon.Enable(a.User, a.Domain ?? "", a.Password, a.Logons);
                    log.Info($"[admin-pipe-server] Automatic sign-in turned on for {a.Domain}\\{a.User} ({a.Logons} sign-ins).");
                    return Answer(true, backup: backup);
                default:
                    // Only Winlogon's own values come back: AutoAdminLogon is "0" or "1", nothing else is written.
                    if (a.Backup is { AutoAdminLogon: not (null or "0" or "1") })
                        return Answer(false, "The saved sign-in settings aren't valid.");
                    autoLogon.Disable(a.Backup);
                    log.Info("[admin-pipe-server] Automatic sign-in turned off and the previous settings restored.");
                    return Answer(true);
            }
        }
        catch (Exception ex)
        {
            log.Warn($"[admin-pipe-server] {request.Op} failed: {ex.Message}");
            return Answer(false, ex.Message);
        }
    }

    /// <summary>
    /// The undo journal for an app that isn't elevated: it reads the records, adds the changes it makes and takes off the ones it
    /// undid. Only the verified app can connect, and an undo runs in the app, which reaches administrator rights only through this
    /// pipe's own checked requests (allowlisted commands and values), so a record adds nothing the app couldn't already ask for.
    /// </summary>
    private AdminPipeResponse HandleJournal(AdminPipeRequest request)
    {
        AdminPipeResponse Answer(bool ok, string? error = null, bool allowed = true, IReadOnlyList<ChangeRecord>? changes = null) => new(
            Ok: ok, Allowed: allowed, Elevated: Environment.IsPrivilegedProcess, HelperPid: Environment.ProcessId, ExitCode: ok ? 0 : -1,
            Error: error, Changes: changes);

        if (changeJournal is null) return Answer(false, "The undo journal is not supported by this elevated helper.", allowed: false);
        try
        {
            // Opened for each request: the app or another Agent may have changed the file since the last one.
            var journal = changeJournal();
            if (request.Op == AdminPipeFraming.OpJournalList) return Answer(true, changes: journal.All);
            if (request.Op == AdminPipeFraming.OpJournalAdd)
            {
                if (ProtectedStateFiles.InvalidChange(request.Change) is { } bad) return Answer(false, bad);
                journal.Add(request.Change!);
                log.Info($"[admin-pipe-server] Recorded {request.Change!.Kind} '{request.Change.Target}' in the undo journal.");
                return Answer(true);
            }
            if (request.ChangeId is not { } id || id == Guid.Empty) return Answer(false, "Which change to remove wasn't given.");
            if (journal.All.All(c => c.Id != id)) return Answer(true); // already gone
            journal.Remove(id);
            log.Info($"[admin-pipe-server] Undone change {id} taken off the undo journal.");
            return Answer(true);
        }
        catch (Exception ex)
        {
            log.Warn($"[admin-pipe-server] {request.Op} failed: {ex.Message}");
            return Answer(false, ex.Message);
        }
    }

    /// <summary>The installed app's folder (the Agent's own): where the sign-in tasks run the Agent launcher from.</summary>
    private string AppFolder => appFolder ?? AppContext.BaseDirectory;

    private async Task<AdminPipeResponse> HandleAgentScriptAsync(AdminPipeRequest request, CancellationToken ct)
    {
        AdminPipeResponse Refused(string error) => new(
            Ok: false, Allowed: true, Elevated: Environment.IsPrivilegedProcess, HelperPid: Environment.ProcessId, ExitCode: -1, Error: error);

        if (request.Script is not { Name.Length: > 0 } script) return Refused("No script was named.");
        var what = $"{script.Name} {string.Join(' ', script.Args ?? [])}";
        if (AgentScripts.Build(script, AppFolder, out var refusal) is not { } ps)
        {
            log.Warn($"[admin-pipe-server] Agent script '{what}' refused: {refusal}");
            return Refused(refusal ?? "That change isn't allowed.");
        }
        // The script is this app's own code; the screen is a second check that nothing in it downloads or runs other code.
        if (AdminCommandAllowlist.FindBlockedPowerShell(ps) is { } blocked)
        {
            log.Warn($"[admin-pipe-server] Agent script '{what}' blocked: contains '{blocked}'.");
            return Refused($"The script contains '{blocked}', which the Agent doesn't run.");
        }
        var timeout = TimeSpan.FromMilliseconds(Math.Clamp(request.TimeoutMs, 1_000, 3_600_000));
        try
        {
            var pr = await _launcher.RunAsync(SystemCommandRunner.PowerShell, SystemCommandRunner.PowerShellArgs(ps), timeout, ct).ConfigureAwait(false);
            log.Info($"[admin-pipe-server] Agent script '{what}' exit={pr.ExitCode} timedOut={pr.TimedOut}.");
            return new AdminPipeResponse(
                Ok: !pr.TimedOut, Allowed: true, Elevated: Environment.IsPrivilegedProcess, HelperPid: Environment.ProcessId,
                ExitCode: pr.ExitCode, StdOut: pr.StdOut, StdErr: pr.StdErr, TimedOut: pr.TimedOut,
                Error: pr.TimedOut ? "The change timed out." : null);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            log.Warn($"[admin-pipe-server] Agent script '{what}' failed to start: {ex.Message}");
            return Refused("PowerShell didn't start: " + ex.Message);
        }
    }

    private async Task<AdminPipeResponse> HandleMachineTweakAsync(AdminPipeRequest request, CancellationToken ct)
    {
        AdminPipeResponse Answer(bool ok, string? text = null, string? error = null, bool allowed = true) => new(
            Ok: ok, Allowed: allowed, Elevated: Environment.IsPrivilegedProcess, HelperPid: Environment.ProcessId, ExitCode: ok ? 0 : -1,
            StdOut: text ?? "", Error: error);

        if (machineTweaks is null) return Answer(false, error: "Machine-wide changes are not supported by this elevated helper.", allowed: false);
        if (request.Tweak is not { } t) return Answer(false, error: "No change was sent.");
        var what = t.Target ?? t.Name ?? $"{t.Folders?.Count ?? 0} folder(s), {t.Processes?.Count ?? 0} program(s)";
        try
        {
            if (MachineTweakRules.Refusal(t, defenderPaths) is { } refusal)
            {
                log.Warn($"[admin-pipe-server] {t.Action} '{what}' refused: {refusal}");
                return Answer(false, error: refusal);
            }
            var (ok, text) = await MachineTweakRules.ApplyAsync(machineTweaks, t, ct).ConfigureAwait(false);
            log.Info($"[admin-pipe-server] {t.Action} '{what}' {(ok ? "done" : "not done")}.");
            return ok ? Answer(true, text) : Answer(false, error: text ?? "Windows didn't allow the change.");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            log.Warn($"[admin-pipe-server] {t.Action} '{what}' failed: {ex.Message}");
            return Answer(false, error: ex.Message);
        }
    }

    /// <summary>The workflow and benchmark state for an app that isn't elevated, by fixed file name only, checked before it's saved.</summary>
    private AdminPipeResponse HandleStateFile(AdminPipeRequest request)
    {
        AdminPipeResponse Answer(bool ok, string? error = null, bool allowed = true, string? json = null) => new(
            Ok: ok, Allowed: allowed, Elevated: Environment.IsPrivilegedProcess, HelperPid: Environment.ProcessId, ExitCode: ok ? 0 : -1,
            Error: error, StateJson: json);

        if (string.IsNullOrEmpty(stateFolder)) return Answer(false, "State files are not supported by this elevated helper.", allowed: false);
        if (!ProtectedStateFiles.IsAgentManaged(request.StateName)) return Answer(false, $"'{request.StateName}' isn't a state file the Agent keeps.", allowed: false);
        var path = Path.Combine(stateFolder, request.StateName!);
        try
        {
            if (request.Op == AdminPipeFraming.OpStateRead)
                return Answer(true, json: File.Exists(path) ? File.ReadAllText(path) : null);

            if (request.StateJson is null)
            {
                if (File.Exists(path)) File.Delete(path);
                return Answer(true);
            }
            if (ProtectedStateFiles.InvalidState(request.StateName!, request.StateJson) is { } bad) return Answer(false, bad);
            // Never creates the folder: it must already be the secured one (only administrators can open it).
            if (!Directory.Exists(stateFolder)) return Answer(false, "The state folder isn't set up yet.");
            var tmp = path + ".tmp";
            File.WriteAllText(tmp, request.StateJson);
            File.Move(tmp, path, overwrite: true);
            return Answer(true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            log.Warn($"[admin-pipe-server] {request.Op} {request.StateName} failed: {ex.Message}");
            return Answer(false, ex.Message);
        }
    }

    private AdminPipeResponse HandleSystemSetting(AdminPipeRequest request)
    {
        AdminPipeResponse Answer(bool ok, string? error = null, bool allowed = true) => new(
            Ok: ok, Allowed: allowed, Elevated: Environment.IsPrivilegedProcess, HelperPid: Environment.ProcessId, ExitCode: ok ? 0 : -1, Error: error);

        if (adminSettings is null) return Answer(false, "System settings are not supported by this elevated helper.", allowed: false);
        if (request.Setting is not { } s) return Answer(false, "No setting was sent.");
        try
        {
            if (AdminSettingsRules.Refusal(s, adminSettings.IsDriver) is { } refusal)
            {
                log.Warn($"[admin-pipe-server] {s.Action} '{s.Target ?? s.Name}' refused: {refusal}");
                return Answer(false, refusal);
            }
            AdminSettingsRules.Apply(adminSettings, s);
            log.Info($"[admin-pipe-server] {s.Action} '{s.Target ?? s.Name}' done.");
            return Answer(true);
        }
        catch (Exception ex)
        {
            log.Warn($"[admin-pipe-server] {s.Action} '{s.Target ?? s.Name}' failed: {ex.Message}");
            return Answer(false, ex.Message);
        }
    }

    private async Task<AdminPipeResponse> RunSecurityAuditAsync(AdminPipeRequest request, CancellationToken ct)
    {
        AdminPipeResponse Fail(string error, bool allowed = true, bool cancelled = false) => new(
            Ok: false, Allowed: allowed, Elevated: Environment.IsPrivilegedProcess, HelperPid: Environment.ProcessId, ExitCode: -1,
            Error: error, Cancelled: cancelled);

        if (securityAuditor is null)
            return Fail("The security audit is not supported by this elevated helper.", allowed: false);
        try
        {
            var run = await securityAuditor(TimeSpan.FromMilliseconds(Math.Clamp(request.TimeoutMs, 1_000, 3_600_000)), ct).ConfigureAwait(false);
            return new AdminPipeResponse(
                Ok: !run.Process.TimedOut && run.ReportCsv is not null,
                Allowed: true,
                Elevated: Environment.IsPrivilegedProcess,
                HelperPid: Environment.ProcessId,
                ExitCode: run.Process.ExitCode,
                StdOut: run.Process.StdOut,
                StdErr: run.Process.StdErr,
                TimedOut: run.Process.TimedOut,
                Error: run.Process.TimedOut ? "The audit timed out." : run.ReportCsv is null ? "The audit wrote no report." : null,
                Report: run.ReportCsv);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return Fail("The audit was cancelled.", cancelled: true);
        }
        catch (Exception ex)
        {
            log.Warn($"[admin-pipe-server] Security audit failed: {ex.Message}");
            return Fail($"Security audit failed: {ex.Message}");
        }
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
