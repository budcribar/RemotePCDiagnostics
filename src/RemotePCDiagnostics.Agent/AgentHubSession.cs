using System.Diagnostics;
using Grpc.Core;
using Grpc.Net.Client;
using PeakSWC.RemoteWebView.Agent;
using RemotePCDiagnostics.Agent.Core;

namespace RemotePCDiagnostics.Agent;

public interface IAgentLaunchedProcess : IDisposable
{
    bool HasExited { get; }
    uint ExitCode { get; }
    Task WaitForExitAsync(CancellationToken ct);
    void Kill();
}

public interface IAgentPlatform
{
    string MachineName { get; }
    string GetOsVersion();
    string GetActiveSignedInUser();
    string GetAgentVersion();
    string GetCachedOrInstalledAppVersion();
    /// <summary>When Windows last started, so Admin can drop the hardware inventory it kept from before. Null when unknown.</summary>
    DateTimeOffset? GetBootTime() => null;
    Task<ConsentOutcome> RequestConsentAsync(string requester, int timeoutSeconds, CancellationToken ct);
    Task<(string? ExePath, string? Error)> ResolveHostExecutableAsync(
        Func<LaunchStage, string, int, Task> reportStageAsync,
        CancellationToken ct);
    (IAgentLaunchedProcess? Process, string? Error) StartHostProcess(string hostExePath, string fullCommandLine);
    Task<bool?> CheckRelaySessionConnectedAsync(string statusUrl, CancellationToken ct);
    Task RemoveSelfAfterSessionAsync();
}

/// <summary>Works out when Windows started from the current time and the milliseconds since boot.</summary>
public static class BootTime
{
    /// <summary>Rounded to the second, so the value is the same on every reconnect within one boot. Null for a nonsensical tick count.</summary>
    public static DateTimeOffset? From(DateTimeOffset utcNow, long millisecondsSinceBoot)
    {
        if (millisecondsSinceBoot < 0)
            return null;
        var booted = utcNow.ToUniversalTime() - TimeSpan.FromMilliseconds(millisecondsSinceBoot);
        return new DateTimeOffset(booted.UtcTicks - booted.UtcTicks % TimeSpan.TicksPerSecond, TimeSpan.Zero);
    }
}

public sealed class AgentSessionOptions
{
    public TimeSpan HeartbeatInterval { get; init; } = TimeSpan.FromSeconds(30);
    /// <summary>A fixed time between status polls (tests). Unset: <see cref="LaunchRules.PollInterval"/>, often at first and then less so.</summary>
    public TimeSpan? StatusPollInterval { get; init; }
    public int ConsentTimeoutSeconds { get; init; } = AgentCommandLine.DefaultConsentTimeoutSeconds;
    public Action<string>? Log { get; init; }
    /// <summary>
    /// Relay link opened, refreshed, or dropped. <c>group</c> is the shop slug when one is known.
    /// Called from the connection tasks; must not throw (exceptions are ignored).
    /// </summary>
    public Action<bool, string?>? LinkChanged { get; init; }
    /// <summary>
    /// Relay pushed a new RPCD release version hint (stable, prerelease). Must not throw.
    /// </summary>
    public Action<string?, string?>? ReleaseAnnounced { get; init; }

    /// <summary>
    /// Install an official RPCD release. The callback reports progress, including the terminal snapshot.
    /// Null when this process has no updater: the hub answers with a failed progress and installs nothing.
    /// </summary>
    public Func<UpdateRpcdCommand, Func<UpdateRpcdProgress, CancellationToken, Task>, CancellationToken, Task>? UpdateRpcd { get; init; }

    /// <summary>The latest update progress, or the one named by request id. Null when this process has no updater.</summary>
    public Func<string, UpdateRpcdProgress?>? ReadUpdateRpcd { get; init; }

    /// <summary>Persists a per-agent token assigned by the relay on first enrollment (writes secured agent.json).</summary>
    public Action<string>? SaveAgentToken { get; init; }

    /// <summary>The scheduled metrics pass and its outbox (null: this agent runs none, as in tests and session-lifetime agents).</summary>
    public AgentMetrics? Metrics { get; init; }
}

/// <summary>
/// Production Windows implementation of <see cref="IAgentPlatform"/> backed by <see cref="Win32Session"/> and <see cref="AgentPaths"/>.
/// </summary>
internal sealed class WindowsAgentPlatform(string? configuredServer = null, Action<string>? log = null, RpcdRemoteUpdater? updater = null) : IAgentPlatform, IDisposable
{
    /// <summary>The agent log line format (<c>RemotePCDiagnostics.Agent.log</c>), so the session pipe's lines land next to the agent's.</summary>
    private void Log(string message) => log?.Invoke($"{DateTimeOffset.Now:O} [agent] {message}");

    private readonly HttpClient _http = new(new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
    })
    {
        Timeout = TimeSpan.FromMinutes(10),
    };

    private readonly HttpClient _statusHttp = new(new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
    })
    {
        Timeout = TimeSpan.FromSeconds(5),
    };

    public string MachineName => Environment.MachineName;
    public string GetOsVersion() => Win32Session.GetOsVersionText();
    public string GetActiveSignedInUser() => Win32Session.GetActiveSignedInUser();
    public string GetAgentVersion() => AgentPaths.GetAgentVersion();
    public string GetCachedOrInstalledAppVersion() => AgentPaths.GetInstalledOrCachedAppVersion();

    /// <summary>
    /// Now minus the tick count (GetTickCount64, which counts sleep and hibernation too). A Restart resets it; a shutdown with
    /// Fast Startup on resumes the same kernel session and keeps it.
    /// </summary>
    public DateTimeOffset? GetBootTime() => BootTime.From(DateTimeOffset.UtcNow, Environment.TickCount64);

    public async Task<ConsentOutcome> RequestConsentAsync(string requester, int timeoutSeconds, CancellationToken ct)
    {
        var agentExe = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(agentExe) || !File.Exists(agentExe))
            return ConsentOutcome.Failed;

        var cmdLine = LaunchRules.ConsentCommandLine(agentExe, requester, timeoutSeconds);
        var workDir = Path.GetDirectoryName(agentExe) ?? AppContext.BaseDirectory;
        var (proc, error) = Win32Session.StartInActiveUserSession(
            agentExe,
            cmdLine,
            workDir,
            preferElevatedToken: false,
            createNoWindow: true);

        if (proc is null || error is not null)
            return ConsentOutcome.Failed;

        using (proc)
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds + 15));
            try
            {
                await proc.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);
                return ConsentPolicy.FromExitCode(proc.ExitCode);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                return ConsentOutcome.TimedOut;
            }
            catch (OperationCanceledException)
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                throw;
            }
        }
    }

    public Task<(string? ExePath, string? Error)> ResolveHostExecutableAsync(
        Func<LaunchStage, string, int, Task> reportStageAsync,
        CancellationToken ct) =>
        AgentPaths.ResolveOrDownloadHostAsync(_http, reportStageAsync, ct);

    public (IAgentLaunchedProcess? Process, string? Error) StartHostProcess(string hostExePath, string fullCommandLine)
    {
        var workDir = Path.GetDirectoryName(hostExePath) ?? AppContext.BaseDirectory;
        var pipeName = $"rpd-admin-{Guid.NewGuid():N}";
        var cmdWithPipe = $"{fullCommandLine} {RemotePCDiagnostics.Core.Session.ElevationService.AdminPipeArgPrefix}{pipeName}";

        // F7: Launch WPF + WebView2 Host un-elevated (asInvoker) and bridge allowlisted elevated repairs/updates over AdminPipeServer.
        var (proc, err) = Win32Session.StartInActiveUserSession(
            hostExePath,
            cmdWithPipe,
            workDir,
            preferElevatedToken: false,
            createNoWindow: false);

        if (proc is null)
            return (null, err ?? "Failed to start Remote PC Diagnostics.");

        var pipeCts = new CancellationTokenSource();
        // Elevated repairs and updates asked for by an unattended session's app go to the agent log, like the rest of the agent.
        var pipeLog = RemotePCDiagnostics.Core.Logging.AppLoggerFactory.From(Log).CreateLogger("AgentSessionPipe");
        var serverOptions = new RemotePCDiagnostics.Core.Session.AdminPipeServerOptions
        {
            PipeName = pipeName,
            ExpectedClientPid = proc.Id,
            ExpectedClientExePath = hostExePath,
            AllowedClientSid = Win32Session.GetActiveUserSid(),
            ConnectTimeout = TimeSpan.FromSeconds(60),
        };
        var pipeServer = CreatePipeServer(serverOptions, workDir, pipeLog, out var sensorProvider);
        updater?.Bind(serverOptions);

        var launched = new SystemLaunchedProcess(proc, pipeCts, pipeServer, hostExePath,
            RestartedCopy.SessionIdFrom(fullCommandLine), serverOptions, Log);

        _ = Task.Run(async () =>
        {
            try
            {
                // The host keeps this pipe name for the life of the process, and a copy it starts again under the same session
                // (a reconnect, a restart) inherits it. When the connection drops, listen again for whichever copy is current
                // instead of leaving the app holding a client that will never reconnect.
                while (!pipeCts.IsCancellationRequested && !launched.HasExited)
                {
                    try
                    {
                        await pipeServer.RunSingleSessionAsync(pipeCts.Token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (pipeCts.IsCancellationRequested)
                    {
                        break;
                    }
                    catch (Exception ex)
                    {
                        Log($"[rpcd-update] Admin pipe session ended ({ex.Message}). Listening again.");
                    }
                    if (pipeCts.IsCancellationRequested || launched.HasExited)
                        break;
                    Log("[rpcd-update] Admin pipe dropped. Listening again for the app.");
                    try { await Task.Delay(TimeSpan.FromSeconds(1), pipeCts.Token).ConfigureAwait(false); }
                    catch (OperationCanceledException) { break; }
                }
            }
            catch (OperationCanceledException) { }
            finally
            {
                pipeServer.Dispose();
                sensorProvider?.Dispose();
            }
        });

        return (launched, null);
    }

    /// <summary>
    /// Listens on the well-known local service pipe so a user-mode Host launched from the Desktop/Start Menu connects
    /// to the persistent Agent service with zero UAC prompt. Only the installed Host executable is allowed to connect.
    /// </summary>
    public async Task RunLocalHostPipeAsync(CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows())
            return;

        var pipeLog = RemotePCDiagnostics.Core.Logging.AppLoggerFactory.From(Log).CreateLogger("AgentLocalPipe");
        while (!ct.IsCancellationRequested)
        {
            var hostExe = AgentPaths.TryFindLocalInstalledHostExe();
            if (string.IsNullOrWhiteSpace(hostExe))
            {
                try { await Task.Delay(TimeSpan.FromSeconds(5), ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }
                continue;
            }

            var workDir = Path.GetDirectoryName(hostExe) ?? AppContext.BaseDirectory;
            var serverOptions = new RemotePCDiagnostics.Core.Session.AdminPipeServerOptions
            {
                PipeName = RemotePCDiagnostics.Core.Session.ElevationService.ServiceAdminPipeName,
                ExpectedClientExePath = hostExe,
                AllowInteractiveUsers = true,
                // Only the active console user session may use the always-on service pipe (blocks disconnected/background sessions).
                RequireActiveConsoleSession = true,
                // The client is a user-owned process: a standard user only gets reads, an administrator gets repairs.
                RestrictStandardUsers = true,
                ConnectTimeout = Timeout.InfiniteTimeSpan,
            };
            using var pipeServer = CreatePipeServer(serverOptions, workDir, pipeLog, out var sensorProvider);
            using (sensorProvider)
            {
                updater?.Bind(serverOptions);
                try
                {
                    await pipeServer.RunUntilCancelledAsync(ct).ConfigureAwait(false);
                    return;
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception ex)
                {
                    Log($"[local-pipe] Service admin pipe stopped ({ex.Message}); retrying in 5 s.");
                }
            }

            try { await Task.Delay(TimeSpan.FromSeconds(5), ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }
        }
    }

    private RemotePCDiagnostics.Core.Session.AdminPipeServer CreatePipeServer(
        RemotePCDiagnostics.Core.Session.AdminPipeServerOptions serverOptions,
        string workDir,
        Microsoft.Extensions.Logging.ILogger pipeLog,
        out IDisposable? sensorProvider)
    {
        // The app reads temperatures and fans through this pipe, as it does through the elevated helper.
        sensorProvider = null;
        Func<CancellationToken, Task<RemotePCDiagnostics.Core.Sensors.SensorSnapshot?>>? sensorReader = null;
        if (OperatingSystem.IsWindows())
            sensorProvider = AgentAdminHost.CreateWindowsSensorProvider(pipeLog, out sensorReader);
        var launcher = new RemotePCDiagnostics.Core.Osquery.SystemProcessLauncher();
        return new RemotePCDiagnostics.Core.Session.AdminPipeServer(
            serverOptions,
            launcher,
            log: pipeLog,
            sensorReader: sensorReader,
            selfUpdater: (channel, relaunchArgs, token) => AgentSelfUpdater.RunAsync(channel, relaunchArgs, pipeLog, token, RelaunchAfterSetup),
            // The app's own install folder holds the HardeningKitty it ships.
            securityAuditor: RemotePCDiagnostics.Core.Security.SecurityAuditModule.ElevatedRunner(workDir, pipeLog),
            moduleHost: new RemotePCDiagnostics.Core.Plugins.AgentModuleHost(workDir, pipeLog),
            adminSettings: OperatingSystem.IsWindows() ? new RemotePCDiagnostics.Core.Session.WindowsAdminSettings(pipeLog) : null,
            machineTweaks: OperatingSystem.IsWindows() ? new RemotePCDiagnostics.Core.Session.WindowsMachineTweaks(pipeLog) : null,
            // The app isn't elevated: this service keeps its undo journal and its workflow and benchmark state.
            changeJournal: () => new RemotePCDiagnostics.Core.Changes.FileChangeJournal(RemotePCDiagnostics.Core.Changes.FileChangeJournal.DefaultPath(), pipeLog),
            stateFolder: RemotePCDiagnostics.Core.ProtectedState.Folder(),
            machineSetup: AgentMachineSetup.ForService(pipeLog),
            biosOperations: new RemotePCDiagnostics.Core.Session.AgentBiosOperations(launcher, log: pipeLog));
    }

    /// <summary>
    /// After an update this service ran for an unattended session: once Setup exits, start the app again in the user's session.
    /// If Setup's Agent MSI step stops this service first, the new service does it when it starts (<see cref="ResumePendingRelaunch"/>).
    /// </summary>
    private void RelaunchAfterSetup(Process setup, string stagingDir)
    {
        _ = Task.Run(async () =>
        {
            try
            {
                using (setup)
                    await setup.WaitForExitAsync().ConfigureAwait(false);
                ResumePendingRelaunch(stagingDir);
            }
            catch (Exception ex)
            {
                Log($"[update-relaunch] Waiting for Setup failed: {ex.Message}");
            }
        });
    }

    /// <summary>Starts the app for a pending post-update relaunch request, if there is one (see <see cref="PendingAppRelaunch"/>).</summary>
    public void ResumePendingRelaunch(string? stagingDir = null) =>
        PendingAppRelaunch.TryResume(
            stagingDir ?? AgentSelfUpdater.StagingDirectory(),
            configuredServer,
            (hostExe, cmdLine) =>
            {
                var (proc, error) = StartHostProcess(hostExe, cmdLine);
                // The pipe server lives as long as the app; nothing else tracks this copy of the app.
                return proc is null ? error ?? "Failed to start Remote PC Diagnostics." : null;
            },
            Log);

    public async Task<bool?> CheckRelaySessionConnectedAsync(string statusUrl, CancellationToken ct)
    {
        try
        {
            using var resp = await _statusHttp.GetAsync(statusUrl, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
                return null;
            var body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            return LaunchRules.ParseStatus(body);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return null;
        }
    }

    public Task RemoveSelfAfterSessionAsync()
    {
        AgentServiceInstaller.CleanupPerSessionAgentBestEffort();
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        _http.Dispose();
        _statusHttp.Dispose();
    }

    /// <summary>
    /// The app the Agent started, followed across the copies it starts of itself. The app reconnects to the relay (and restarts
    /// when a browser asks) by starting a new copy under the same session id with --restarted and then closing; that copy is the
    /// same session. When the current copy exits, a child of it running the same exe with that session id and --restarted
    /// becomes the current one: the admin pipe accepts it, Kill closes it, and the session only ends when the last copy exits.
    /// </summary>
    private sealed class SystemLaunchedProcess(
        Process process,
        CancellationTokenSource? pipeCts = null,
        RemotePCDiagnostics.Core.Session.AdminPipeServer? pipeServer = null,
        string? hostExePath = null,
        string? sessionId = null,
        RemotePCDiagnostics.Core.Session.AdminPipeServerOptions? pipeOptions = null,
        Action<string>? log = null) : IAgentLaunchedProcess
    {
        private readonly object _gate = new();
        private Process _current = process;
        private readonly List<Process> _previous = [];

        public bool HasExited
        {
            get
            {
                lock (_gate)
                {
                    if (!Exited(_current)) return false;
                    // Checked without waiting: the pipe loop and the launch loop look often.
                    return !TryFollowSuccessorNoLock();
                }
            }
        }

        public uint ExitCode
        {
            get
            {
                lock (_gate)
                {
                    try { return unchecked((uint)_current.ExitCode); }
                    catch { return 1; }
                }
            }
        }

        public async Task WaitForExitAsync(CancellationToken ct)
        {
            while (true)
            {
                Process current;
                lock (_gate) current = _current;
                await current.WaitForExitAsync(ct).ConfigureAwait(false);

                // The new copy is started before the old one closes, so it is normally there at once; allow a moment.
                var deadline = DateTime.UtcNow + RestartedCopy.SuccessorWait;
                var followed = false;
                while (true)
                {
                    lock (_gate)
                    {
                        if (!ReferenceEquals(_current, current) || TryFollowSuccessorNoLock())
                        {
                            followed = true;
                            break;
                        }
                    }
                    if (DateTime.UtcNow >= deadline) break;
                    await Task.Delay(TimeSpan.FromMilliseconds(250), ct).ConfigureAwait(false);
                }
                if (!followed) return;
            }
        }

        public void Kill()
        {
            lock (_gate)
            {
                try { _current.Kill(entireProcessTree: true); } catch { }
            }
        }

        public void Dispose()
        {
            try { pipeCts?.Cancel(); } catch { }
            pipeCts?.Dispose();
            try { pipeServer?.Dispose(); } catch { }
            lock (_gate)
            {
                _current.Dispose();
                foreach (var p in _previous) p.Dispose();
                _previous.Clear();
            }
        }

        private static bool Exited(Process p)
        {
            try { return p.HasExited; }
            catch { return true; }
        }

        /// <summary>Moves to the exited copy's restarted child, if there is one. Caller holds <see cref="_gate"/>.</summary>
        private bool TryFollowSuccessorNoLock()
        {
            if (!OperatingSystem.IsWindows() || string.IsNullOrEmpty(hostExePath) || string.IsNullOrEmpty(sessionId))
                return false;
            int parentId;
            try { parentId = _current.Id; }
            catch { return false; }

            var next = FindRestartedChild(parentId, hostExePath, sessionId);
            if (next is null) return false;

            _previous.Add(_current);
            _current = next;
            if (pipeOptions is not null)
                pipeOptions.ExpectedClientPid = next.Id; // the pipe now accepts the new copy, and only it
            log?.Invoke($"The app restarted itself for session {sessionId} (pid {parentId} -> {next.Id}); following the new copy.");
            return true;
        }

        [System.Runtime.Versioning.SupportedOSPlatform("windows")]
        private static Process? FindRestartedChild(int parentId, string hostExePath, string sessionId)
        {
            try
            {
                var expected = Path.GetFullPath(hostExePath);
                using var searcher = new System.Management.ManagementObjectSearcher(
                    $"SELECT ProcessId, ExecutablePath, CommandLine FROM Win32_Process WHERE ParentProcessId = {parentId}");
                foreach (var o in searcher.Get())
                {
                    using (o)
                    {
                        var path = o["ExecutablePath"] as string;
                        if (string.IsNullOrEmpty(path) ||
                            !string.Equals(Path.GetFullPath(path), expected, StringComparison.OrdinalIgnoreCase))
                            continue;
                        if (!RestartedCopy.IsRestartOf(o["CommandLine"] as string, sessionId))
                            continue;
                        if (o["ProcessId"] is not uint pid) continue;
                        try
                        {
                            var child = Process.GetProcessById((int)pid);
                            if (!child.HasExited) return child;
                            child.Dispose();
                        }
                        catch (ArgumentException) { } // it has already gone
                    }
                }
            }
            catch (Exception) { }
            return null;
        }
    }
}

/// <summary>
/// Manages the outbound <c>AgentHub.Connect</c> bidirectional stream, exponential <see cref="Backoff"/> reconnection loop,
/// 30-second heartbeats, consent enforcement, and <c>LaunchCommand</c> / <c>CancelCommand</c> execution.
/// </summary>
public sealed class AgentHubWorker(
    AgentConfig config,
    IAgentPlatform platform,
    AgentSessionOptions? options = null)
{
    private readonly AgentSessionOptions _options = options ?? new AgentSessionOptions();
    private readonly object _stateGate = new();
    private string? _activeRequestId;
    private CancellationTokenSource? _activeLaunchCts;
    private bool _sessionRunning;
    private string _runningSessionId = "";
    private string? _shopGroup = AgentLayout.NormalizeShopGroup(config.Group);
    private bool _linkAnnounced;
    private volatile bool _stopAfterSingleSession;

    // A session that reached READY outlives the Connect stream that launched it: the relay keeps a READY launch through a
    // disconnect, so after a reconnect an end request (CancelCommand) for it must still close the app, and its "ended" stage
    // must still reach the relay. These point at whichever stream is current.
    private Func<AgentMessage, CancellationToken, Task>? _currentWrite;
    private CancellationTokenSource? _currentStreamCts;
    private LaunchProgress? _undeliveredEnd;

    /// <summary>
    /// Runs the persistent reconnection loop against <see cref="AgentConfig.Server"/> until <paramref name="stoppingToken"/> is cancelled
    /// (or until a <see cref="AgentLifetime.Session"/> agent finishes one session).
    /// </summary>
    public async Task RunLoopAsync(CancellationToken stoppingToken)
    {
        var backoff = new Backoff();
        // Passes run on their schedule whether or not the relay is reachable; their runs wait in the outbox.
        using var metricsCts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        var metricsLoop = _options.Metrics?.RunAsync(IsBusyForMetrics, metricsCts.Token) ?? Task.CompletedTask;

        while (!stoppingToken.IsCancellationRequested && !_stopAfterSingleSession)
        {
            var startedAt = Stopwatch.GetTimestamp();
            try
            {
                using var channel = GrpcChannel.ForAddress(config.Server, new GrpcChannelOptions
                {
                    HttpHandler = new SocketsHttpHandler
                    {
                        KeepAlivePingDelay = TimeSpan.FromSeconds(30),
                        KeepAlivePingTimeout = TimeSpan.FromSeconds(15),
                        EnableMultipleHttp2Connections = true,
                    },
                });

                var client = new AgentHub.AgentHubClient(channel);
                Log($"Connecting to AgentHub at {config.Server} (machine={config.MachineId}, consent={config.Consent}, lifetime={config.Lifetime})...");
                await RunSingleConnectionAsync(client, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested || _stopAfterSingleSession)
            {
                break;
            }
            catch (RpcException rpcEx)
            {
                Log($"AgentHub stream ended ({rpcEx.StatusCode}: {rpcEx.Status.Detail}).");
            }
            catch (Exception ex)
            {
                Log($"AgentHub connection error: {ex.Message}");
            }

            if (stoppingToken.IsCancellationRequested || _stopAfterSingleSession)
                break;

            var lasted = Stopwatch.GetElapsedTime(startedAt);
            backoff.ConnectionEnded(lasted);
            var delay = backoff.Next();
            Log($"Reconnecting in {delay.TotalSeconds:0} s...");
            try
            {
                await Task.Delay(delay, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
        await metricsCts.CancelAsync().ConfigureAwait(false);
        try { await metricsLoop.ConfigureAwait(false); } catch { }
    }

    /// <summary>The app (or a session) is running: a scheduled pass waits, so it never competes with a technician's checks.</summary>
    private bool IsBusyForMetrics()
    {
        bool running; string id;
        lock (_stateGate) { running = _sessionRunning; id = _runningSessionId; }
        try { return ResolveSessionStatus(running, id).Running; }
        catch { return running; }
    }

    /// <summary>
    /// Executes a single <c>AgentHub.Connect</c> bidirectional gRPC session (used directly in unit tests and by <see cref="RunLoopAsync"/>).
    /// </summary>
    public async Task RunSingleConnectionAsync(AgentHub.AgentHubClient client, CancellationToken ct)
    {
        using var streamCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var token = streamCts.Token;
        using var writeGate = new SemaphoreSlim(1, 1);

        using var call = client.Connect(cancellationToken: token);

        async Task WriteMessageAsync(AgentMessage msg, CancellationToken writeCt)
        {
            await writeGate.WaitAsync(writeCt).ConfigureAwait(false);
            try
            {
                writeCt.ThrowIfCancellationRequested();
                await call.RequestStream.WriteAsync(msg).ConfigureAwait(false);
            }
            finally
            {
                writeGate.Release();
            }
        }

        var hello = new AgentHello
        {
            MachineId = config.MachineId,
            EnrollmentKey = config.Key ?? "",
            AgentToken = config.AgentToken ?? "",
            MachineName = platform.MachineName,
            OsVersion = platform.GetOsVersion(),
            SignedInUser = platform.GetActiveSignedInUser(),
            AgentVersion = platform.GetAgentVersion(),
            CachedAppVersion = platform.GetCachedOrInstalledAppVersion(),
            ConsentCeiling = config.ConsentCeiling == ConsentCeiling.Unattended
                ? ConsentMode.ConsentUnattendedAllowed
                : ConsentMode.ConsentAlwaysAsk,
            Lifetime = config.AgentLifetime == AgentLifetime.Session
                ? Lifetime.RemoveAfterSession
                : Lifetime.Persistent,
            MetricsScheduleRevision = _options.Metrics?.ScheduleRevision ?? 0,
        };
        if (platform.GetBootTime() is { } booted)
            hello.BootTime = Google.Protobuf.WellKnownTypes.Timestamp.FromDateTimeOffset(booted);

        await WriteMessageAsync(new AgentMessage { Hello = hello }, token).ConfigureAwait(false);
        Log($"Sent AgentHello (machine={hello.MachineName}, user='{hello.SignedInUser}', version={hello.AgentVersion}).");
        AnnounceLink(true);
        TriggerHardwareSyncOnConnect(hello.MachineName, token);

        LaunchProgress? undelivered;
        lock (_stateGate)
        {
            _currentWrite = WriteMessageAsync;
            _currentStreamCts = streamCts;
            undelivered = _undeliveredEnd;
            _undeliveredEnd = null;
        }
        if (undelivered is not null)
        {
            // The app of a READY session closed while no stream was up: tell the relay now, so it stops holding the launch.
            try { await WriteMessageAsync(new AgentMessage { Progress = undelivered }, token).ConfigureAwait(false); }
            catch { lock (_stateGate) _undeliveredEnd ??= undelivered; }
        }

        // A READY session is still running on this new stream: say so again. A relay that restarted (a redeploy) has forgotten
        // the launch, and without it an end request finds nothing to close ("not started through the agent"). A relay that
        // kept it just stores the same stage again.
        LaunchProgress? stillRunning = null;
        lock (_stateGate)
        {
            if (_sessionRunning && !string.IsNullOrEmpty(_activeRequestId) && !string.IsNullOrEmpty(_runningSessionId))
            {
                stillRunning = new LaunchProgress
                {
                    RequestId = _activeRequestId,
                    SessionId = _runningSessionId,
                    Stage = LaunchStage.StageReady,
                    Detail = "Remote PC Diagnostics is still running",
                    Percent = 100,
                };
            }
        }
        if (stillRunning is not null)
        {
            try { await WriteMessageAsync(new AgentMessage { Progress = stillRunning }, token).ConfigureAwait(false); }
            catch { /* the next connection says it again */ }
        }

        var heartbeatTask = PumpHeartbeatsAsync(WriteMessageAsync, token);
        _options.Metrics?.Attach(WriteMessageAsync);
        Task? activeLaunchTask = null;

        try
        {
            while (await call.ResponseStream.MoveNext(token).ConfigureAwait(false))
            {
                var command = call.ResponseStream.Current;
                switch (command.BodyCase)
                {
                    case HubCommand.BodyOneofCase.Launch:
                        activeLaunchTask = HandleLaunchCommand(command.Launch, WriteMessageAsync, streamCts, ct);
                        break;

                    case HubCommand.BodyOneofCase.Cancel:
                        HandleCancelCommand(command.Cancel);
                        break;

                    case HubCommand.BodyOneofCase.ReleaseAvailable:
                        try
                        {
                            _options.ReleaseAnnounced?.Invoke(
                                command.ReleaseAvailable.StableVersion,
                                command.ReleaseAvailable.PrereleaseVersion);
                        }
                        catch { }
                        break;

                    case HubCommand.BodyOneofCase.UpdateRpcd:
                        _ = HandleUpdateRpcdAsync(command.UpdateRpcd, WriteMessageAsync, token);
                        break;

                    case HubCommand.BodyOneofCase.UpdateRpcdStatus:
                        _ = HandleUpdateRpcdStatusAsync(command.UpdateRpcdStatus, WriteMessageAsync, token);
                        break;

                    case HubCommand.BodyOneofCase.MetricsSchedule:
                        _options.Metrics?.ApplySchedule(command.MetricsSchedule);
                        break;

                    case HubCommand.BodyOneofCase.MetricsAck:
                        _options.Metrics?.Acknowledge(command.MetricsAck.ThroughSeq);
                        break;

                    case HubCommand.BodyOneofCase.CollectMetrics:
                        if (_options.Metrics?.CollectNow() == false)
                            Log("Collect metrics: a pass was asked for a moment ago; ignored.");
                        break;

                    case HubCommand.BodyOneofCase.AssignAgentToken:
                        var assigned = command.AssignAgentToken?.AgentToken?.Trim();
                        if (!string.IsNullOrEmpty(assigned))
                        {
                            config.AgentToken = assigned;
                            try
                            {
                                _options.SaveAgentToken?.Invoke(assigned);
                                Log("Saved per-agent credential for this computer.");
                            }
                            catch (Exception ex)
                            {
                                Log($"Failed to persist per-agent credential: {ex.Message}");
                            }
                        }
                        break;
                }
            }
        }
        finally
        {
            bool wasCurrent;
            lock (_stateGate)
            {
                wasCurrent = ReferenceEquals(_currentStreamCts, streamCts);
                if (wasCurrent)
                {
                    _currentWrite = null;
                    _currentStreamCts = null;
                }
            }
            if (wasCurrent)
                _options.Metrics?.Attach(null);
            await streamCts.CancelAsync().ConfigureAwait(false);
            try { await heartbeatTask.ConfigureAwait(false); } catch { }
            // Completes when the launch ends, or once it reached READY and no longer depends on this stream.
            if (activeLaunchTask is not null)
            {
                try { await activeLaunchTask.ConfigureAwait(false); } catch { }
            }
            // After the launch task, so a late "connected" from a launch that already started cannot stick.
            AnnounceLink(false);
            try { await call.RequestStream.CompleteAsync().ConfigureAwait(false); } catch { }
        }
    }

    private async Task PumpHeartbeatsAsync(
        Func<AgentMessage, CancellationToken, Task> writeAsync,
        CancellationToken ct)
    {
        using var timer = new PeriodicTimer(_options.HeartbeatInterval);
        try
        {
            while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
            {
                bool internalRunning;
                string internalSessionId;
                lock (_stateGate)
                {
                    internalRunning = _sessionRunning;
                    internalSessionId = _runningSessionId;
                }

                var (running, sessionId) = ResolveSessionStatus(internalRunning, internalSessionId);

                var hb = new Heartbeat
                {
                    SignedInUser = platform.GetActiveSignedInUser(),
                    SessionRunning = running,
                    SessionId = sessionId,
                    CachedAppVersion = platform.GetCachedOrInstalledAppVersion(),
                    MetricsScheduleRevision = _options.Metrics?.ScheduleRevision ?? 0,
                };
                await writeAsync(new AgentMessage { Heartbeat = hb }, ct).ConfigureAwait(false);
                AnnounceLink(true);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Normal stream shutdown.
        }
    }

    internal static (bool Running, string SessionId) ResolveSessionStatus(
        bool internalRunning,
        string internalSessionId,
        string? activeSessionPath = null,
        Func<int, (bool Alive, string Name)>? processChecker = null,
        Func<bool>? hostProcessRunningChecker = null,
        Action<string>? fileDeleter = null)
    {
        var running = internalRunning;
        var sessionId = internalSessionId ?? "";
        var sessionPath = activeSessionPath;
        if (sessionPath is null)
        {
            sessionPath = AgentLayout.ActiveSessionPath();
            if (!File.Exists(sessionPath) && File.Exists(AgentLayout.LegacyActiveSessionPath()))
            {
                sessionPath = AgentLayout.LegacyActiveSessionPath();
            }
        }

        if (File.Exists(sessionPath))
        {
            ActiveSessionInfo? info = null;
            try
            {
                var json = File.ReadAllText(sessionPath);
                info = ActiveSessionInfo.Parse(json);
            }
            catch { }

            var processAlive = false;
            if (info is not null && info.ProcessId > 0)
            {
                if (processChecker is not null)
                {
                    try
                    {
                        var (alive, name) = processChecker(info.ProcessId);
                        processAlive = alive && name.Contains("RemotePCDiagnostics.Host", StringComparison.OrdinalIgnoreCase);
                    }
                    catch
                    {
                        processAlive = false;
                    }
                }
                else
                {
                    try
                    {
                        using var proc = Process.GetProcessById(info.ProcessId);
                        if (!proc.HasExited && proc.ProcessName.Contains("RemotePCDiagnostics.Host", StringComparison.OrdinalIgnoreCase))
                        {
                            // The process existing is the test. This service runs in session 0 and cannot see windows on the
                            // person's desktop (MainWindowHandle is always zero from here), so "no window" says nothing.
                            // A closed app ends itself: the Host exits after a bounded cleanup.
                            processAlive = true;
                        }
                    }
                    catch
                    {
                        processAlive = false;
                    }
                }
            }

            if (processAlive)
            {
                running = true;
                if (!string.IsNullOrEmpty(info?.SessionId))
                {
                    sessionId = info.SessionId;
                }
                else if (string.IsNullOrEmpty(sessionId))
                {
                    sessionId = info?.SessionId ?? "";
                }
            }
            else
            {
                try
                {
                    if (fileDeleter is not null)
                    {
                        fileDeleter(sessionPath);
                    }
                    else if (File.Exists(sessionPath))
                    {
                        File.Delete(sessionPath);
                    }
                }
                catch { }
            }
        }

        var isHostRunning = hostProcessRunningChecker is not null
            ? hostProcessRunningChecker()
            : DesktopInstallProbe.HostProcessRunning();

        if (isHostRunning)
        {
            running = true;
        }

        return (running, sessionId);
    }

    private Task HandleLaunchCommand(
        LaunchCommand launch,
        Func<AgentMessage, CancellationToken, Task> writeAsync,
        CancellationTokenSource streamCts,
        CancellationToken stoppingToken)
    {
        CancellationTokenSource launchCts;
        lock (_stateGate)
        {
            if (_sessionRunning || _activeRequestId is not null)
            {
                return ReportProgressSafeAsync(
                    writeAsync,
                    launch.RequestId,
                    launch.SessionId,
                    LaunchStage.StageFailed,
                    "A Remote PC Diagnostics session is already running on this computer.",
                    0,
                    streamCts.Token);
            }

            _activeRequestId = launch.RequestId;
            launchCts = CancellationTokenSource.CreateLinkedTokenSource(streamCts.Token);
            _activeLaunchCts = launchCts;
        }

        var detached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var run = Task.Run(async () =>
        {
            try
            {
                await ExecuteLaunchCoreAsync(launch, writeAsync, launchCts, streamCts, stoppingToken, detached).ConfigureAwait(false);
            }
            finally
            {
                lock (_stateGate)
                {
                    if (string.Equals(_activeRequestId, launch.RequestId, StringComparison.OrdinalIgnoreCase))
                    {
                        _activeRequestId = null;
                        _activeLaunchCts = null;
                    }
                }
                launchCts.Dispose();
                detached.TrySetResult();
            }
        }, CancellationToken.None);
        return Task.WhenAny(run, detached.Task);
    }

    private void HandleCancelCommand(CancelCommand cancel)
    {
        if (string.IsNullOrWhiteSpace(cancel.RequestId))
            return;

        CancellationTokenSource? toCancel = null;
        lock (_stateGate)
        {
            if (string.Equals(_activeRequestId, cancel.RequestId, StringComparison.OrdinalIgnoreCase))
            {
                toCancel = _activeLaunchCts;
            }
        }

        if (toCancel is not null)
        {
            Log($"Cancelling launch request {cancel.RequestId}.");
            try { toCancel.Cancel(); } catch { }
        }
    }

    private async Task ExecuteLaunchCoreAsync(
        LaunchCommand launch,
        Func<AgentMessage, CancellationToken, Task> writeAsync,
        CancellationTokenSource launchCts,
        CancellationTokenSource streamCts,
        CancellationToken stoppingToken,
        TaskCompletionSource detached)
    {
        var launchCt = launchCts.Token;
        RememberGroup(launch.Group);
        AnnounceLink(true);

        await ReportProgressSafeAsync(
            writeAsync,
            launch.RequestId,
            launch.SessionId,
            LaunchStage.StageQueued,
            "Preparing Remote PC Diagnostics...",
            0,
            streamCts.Token).ConfigureAwait(false);

        var validationError = LaunchRules.Validate(launch.SessionId, launch.ServerUrl, out var sessionGuid, out var serverUrl, config.Server);
        if (validationError is not null)
        {
            await ReportProgressSafeAsync(writeAsync, launch.RequestId, launch.SessionId, LaunchStage.StageFailed, validationError, 0, streamCts.Token).ConfigureAwait(false);
            return;
        }

        var sessionIdStr = sessionGuid.ToString("D");

        var signedInUser = platform.GetActiveSignedInUser();
        if (string.IsNullOrWhiteSpace(signedInUser))
        {
            await ReportProgressSafeAsync(writeAsync, launch.RequestId, sessionIdStr, LaunchStage.StageFailed, "Nobody is signed in at this computer", 0, streamCts.Token).ConfigureAwait(false);
            return;
        }

        try
        {
            if (ConsentPolicy.MustAsk(config.ConsentCeiling, launch.RequireConsent))
            {
                await ReportProgressSafeAsync(
                    writeAsync,
                    launch.RequestId,
                    sessionIdStr,
                    LaunchStage.StageWaitingForConsent,
                    $"Waiting for {signedInUser} to allow the session...",
                    0,
                    launchCt).ConfigureAwait(false);

                var outcome = await platform.RequestConsentAsync(launch.Requester, _options.ConsentTimeoutSeconds, launchCt).ConfigureAwait(false);
                switch (outcome)
                {
                    case ConsentOutcome.Allowed:
                        break;
                    case ConsentOutcome.Declined:
                        await ReportProgressSafeAsync(writeAsync, launch.RequestId, sessionIdStr, LaunchStage.StageDeclined, "The person at the computer declined the session", 0, streamCts.Token).ConfigureAwait(false);
                        return;
                    case ConsentOutcome.TimedOut:
                        await ReportProgressSafeAsync(writeAsync, launch.RequestId, sessionIdStr, LaunchStage.StageConsentTimedOut, "No answer within the consent time limit", 0, streamCts.Token).ConfigureAwait(false);
                        return;
                    default:
                        await ReportProgressSafeAsync(writeAsync, launch.RequestId, sessionIdStr, LaunchStage.StageFailed, "Could not display the consent prompt on the user's desktop", 0, streamCts.Token).ConfigureAwait(false);
                        return;
                }
            }

            var (hostExePath, resolveError) = await platform.ResolveHostExecutableAsync(
                (stage, detail, pct) => ReportProgressSafeAsync(writeAsync, launch.RequestId, sessionIdStr, stage, detail, pct, launchCt),
                launchCt).ConfigureAwait(false);

            if (string.IsNullOrWhiteSpace(hostExePath) || resolveError is not null)
            {
                await ReportProgressSafeAsync(
                    writeAsync,
                    launch.RequestId,
                    sessionIdStr,
                    LaunchStage.StageFailed,
                    resolveError ?? "Could not find RemotePCDiagnostics.Host.exe.",
                    0,
                    streamCts.Token).ConfigureAwait(false);
                return;
            }

            var appCmdLine = LaunchRules.AppCommandLine(hostExePath, serverUrl, sessionGuid, launch.Group, launch.Hidden);
            await ReportProgressSafeAsync(writeAsync, launch.RequestId, sessionIdStr, LaunchStage.StageStarting, launch.Hidden ? "Starting Remote PC Diagnostics with no window..." : "Starting Remote PC Diagnostics...", 0, launchCt).ConfigureAwait(false);

            var (proc, startError) = platform.StartHostProcess(hostExePath, appCmdLine);
            if (proc is null || startError is not null)
            {
                await ReportProgressSafeAsync(
                    writeAsync,
                    launch.RequestId,
                    sessionIdStr,
                    LaunchStage.StageFailed,
                    startError ?? "Failed to start Remote PC Diagnostics.",
                    0,
                    streamCts.Token).ConfigureAwait(false);
                return;
            }

            using (proc)
            {
                var statusUrl = LaunchRules.StatusUrl(serverUrl, sessionGuid);
                var sw = Stopwatch.StartNew();
                var relayEverAnswered = false;
                var reachedReady = false;

                while (!reachedReady)
                {
                    launchCt.ThrowIfCancellationRequested();

                    bool? relayConnected = null;
                    if (!proc.HasExited)
                    {
                        relayConnected = await platform.CheckRelaySessionConnectedAsync(statusUrl, launchCt).ConfigureAwait(false);
                        if (relayConnected.HasValue)
                            relayEverAnswered = true;
                    }

                    var decision = LaunchRules.Decide(sw.Elapsed, proc.HasExited, relayConnected, relayEverAnswered);
                    switch (decision)
                    {
                        case Readiness.Exited:
                            await ReportProgressSafeAsync(
                                writeAsync,
                                launch.RequestId,
                                sessionIdStr,
                                LaunchStage.StageFailed,
                                LaunchRules.EarlyExitText(proc.ExitCode),
                                0,
                                streamCts.Token).ConfigureAwait(false);
                            return;

                        case Readiness.Ready:
                        case Readiness.ReadyUnconfirmed:
                            lock (_stateGate)
                            {
                                _sessionRunning = true;
                                _runningSessionId = sessionIdStr;
                            }
                            var readyDetail = decision == Readiness.Ready
                                ? "Remote PC Diagnostics is ready"
                                : "Remote PC Diagnostics started (relay status unconfirmed)";
                            await ReportProgressSafeAsync(
                                writeAsync,
                                launch.RequestId,
                                sessionIdStr,
                                LaunchStage.StageReady,
                                readyDetail,
                                100,
                                streamCts.Token).ConfigureAwait(false);
                            reachedReady = true;
                            break;

                        case Readiness.Wait:
                            await Task.Delay(_options.StatusPollInterval ?? LaunchRules.PollInterval(sw.Elapsed), launchCt).ConfigureAwait(false);
                            break;
                    }
                }

                // From READY on, the session no longer depends on the stream that launched it: a dropped stream must not
                // forget the running app (the relay keeps a READY launch and later sends the end request on a new stream).
                // Only an end request for this launch or the agent stopping ends the wait.
                using var sessionCts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                lock (_stateGate)
                {
                    if (string.Equals(_activeRequestId, launch.RequestId, StringComparison.OrdinalIgnoreCase))
                        _activeLaunchCts = sessionCts;
                }
                // An end request that arrived while switching over cancelled the launch token instead.
                if (launchCt.IsCancellationRequested && !streamCts.IsCancellationRequested)
                    sessionCts.Cancel();
                detached.TrySetResult();

                try
                {
                    await proc.WaitForExitAsync(sessionCts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested)
                {
                    proc.Kill();
                }
                finally
                {
                    lock (_stateGate)
                    {
                        _sessionRunning = false;
                        _runningSessionId = "";
                    }
                }

                await ReportEndedAsync(launch.RequestId, sessionIdStr, stoppingToken).ConfigureAwait(false);

                if (config.AgentLifetime == AgentLifetime.Session)
                {
                    _stopAfterSingleSession = true;
                    await platform.RemoveSelfAfterSessionAsync().ConfigureAwait(false);
                    CancellationTokenSource? current;
                    lock (_stateGate) current = _currentStreamCts;
                    if (current is not null)
                    {
                        try { await current.CancelAsync().ConfigureAwait(false); } catch (ObjectDisposedException) { }
                    }
                }
            }
        }
        catch (OperationCanceledException) when (!streamCts.IsCancellationRequested)
        {
            await ReportProgressSafeAsync(
                writeAsync,
                launch.RequestId,
                sessionIdStr,
                LaunchStage.StageFailed,
                "Launch cancelled",
                0,
                streamCts.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (!streamCts.IsCancellationRequested)
        {
            await ReportProgressSafeAsync(
                writeAsync,
                launch.RequestId,
                sessionIdStr,
                LaunchStage.StageFailed,
                $"Launch failed: {ex.Message}",
                0,
                streamCts.Token).ConfigureAwait(false);
        }
    }

    private async Task HandleUpdateRpcdAsync(
        UpdateRpcdCommand command,
        Func<AgentMessage, CancellationToken, Task> writeAsync,
        CancellationToken ct)
    {
        try
        {
            if (_options.UpdateRpcd is null)
            {
                await writeAsync(new AgentMessage
                {
                    UpdateRpcd = new UpdateRpcdProgress
                    {
                        RequestId = command.RequestId ?? "",
                        Stage = "failed",
                        Terminal = true,
                        Error = "This agent cannot install RPCD updates.",
                        Detail = "This agent cannot install RPCD updates.",
                        Channel = command.Channel ?? "",
                    },
                }, ct).ConfigureAwait(false);
                return;
            }

            await _options.UpdateRpcd(
                command,
                (progress, reportCt) => writeAsync(new AgentMessage { UpdateRpcd = progress }, reportCt),
                ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            Log($"[rpcd-update] {ex.Message}");
        }
    }

    private async Task HandleUpdateRpcdStatusAsync(
        UpdateRpcdStatusCommand command,
        Func<AgentMessage, CancellationToken, Task> writeAsync,
        CancellationToken ct)
    {
        try
        {
            var progress = _options.ReadUpdateRpcd?.Invoke(command.RequestId ?? "")
                ?? new UpdateRpcdProgress
                {
                    RequestId = command.RequestId ?? "",
                    Stage = "idle",
                    Detail = "No RPCD update has been requested.",
                };
            await writeAsync(new AgentMessage { UpdateRpcd = progress }, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            Log($"[rpcd-update] {ex.Message}");
        }
    }

    private static async Task ReportProgressSafeAsync(
        Func<AgentMessage, CancellationToken, Task> writeAsync,
        string requestId,
        string sessionId,
        LaunchStage stage,
        string detail,
        int percent,
        CancellationToken ct)
    {
        if (string.IsNullOrEmpty(requestId) || ct.IsCancellationRequested)
            return;

        try
        {
            await writeAsync(
                new AgentMessage
                {
                    Progress = new LaunchProgress
                    {
                        RequestId = requestId,
                        SessionId = sessionId ?? "",
                        Stage = stage,
                        Detail = detail ?? "",
                        Percent = percent,
                    },
                },
                ct).ConfigureAwait(false);
        }
        catch
        {
            // Stream closed while sending progress.
        }
    }

    /// <summary>
    /// Reports a READY session's "ended" stage on whichever stream is up now; with none up, the next connection sends it.
    /// </summary>
    private async Task ReportEndedAsync(string requestId, string sessionId, CancellationToken stoppingToken)
    {
        var progress = new LaunchProgress
        {
            RequestId = requestId,
            SessionId = sessionId ?? "",
            Stage = LaunchStage.StageEnded,
            Detail = "Session ended",
            Percent = 0,
        };
        Func<AgentMessage, CancellationToken, Task>? write;
        CancellationToken streamToken;
        lock (_stateGate)
        {
            write = _currentWrite;
            streamToken = _currentStreamCts?.Token ?? CancellationToken.None;
            if (write is null)
            {
                _undeliveredEnd = progress;
                return;
            }
        }
        if (stoppingToken.IsCancellationRequested)
            return;
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken, streamToken);
            await write(new AgentMessage { Progress = progress }, linked.Token).ConfigureAwait(false);
        }
        catch
        {
            lock (_stateGate) _undeliveredEnd ??= progress;
        }
    }

    private void RememberGroup(string? group)
    {
        var normalized = AgentLayout.NormalizeShopGroup(group);
        if (normalized is null) return;
        lock (_stateGate) _shopGroup = normalized;
    }

    private void AnnounceLink(bool connected)
    {
        string? group;
        lock (_stateGate)
        {
            if (connected) _linkAnnounced = true;
            else if (!_linkAnnounced) return;
            if (!connected) _linkAnnounced = false;
            group = _shopGroup;
        }
        try { _options.LinkChanged?.Invoke(connected, group); }
        catch { /* The badge file must not take down the stream. */ }
    }

    private void TriggerHardwareSyncOnConnect(string machineName, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(config.Key)
            || !config.Key.Trim().StartsWith(RemotePCDiagnostics.Core.Workflow.ShopRelayClient.ApiKeyPrefix, StringComparison.Ordinal)
            || !RemotePCDiagnostics.Core.Workflow.ShopRelayClient.TryParseRelayUri(config.Server, out var relayUri)
            || relayUri is null)
            return;

        _ = Task.Run(async () =>
        {
            try
            {
                await RemotePCDiagnostics.Core.Benchmarks.HardwareSyncService.SyncIfChangedAsync(
                    relayUri,
                    config.Key,
                    config.MachineId,
                    machineName,
                    AgentPaths.ProgramDataDir(),
                    log: Log,
                    ct: ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) { Log($"Hardware sync skipped: {ex.Message}"); }
        }, CancellationToken.None);
    }

    private void Log(string message) =>
        _options.Log?.Invoke($"{DateTimeOffset.Now:O} [agent] {message}");
}
