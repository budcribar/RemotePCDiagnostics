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
    Task<ConsentOutcome> RequestConsentAsync(string requester, int timeoutSeconds, CancellationToken ct);
    Task<(string? ExePath, string? Error)> ResolveHostExecutableAsync(
        Func<LaunchStage, string, int, Task> reportStageAsync,
        CancellationToken ct);
    (IAgentLaunchedProcess? Process, string? Error) StartHostProcess(string hostExePath, string fullCommandLine);
    Task<bool?> CheckRelaySessionConnectedAsync(string statusUrl, CancellationToken ct);
    Task RemoveSelfAfterSessionAsync();
}

public sealed class AgentSessionOptions
{
    public TimeSpan HeartbeatInterval { get; init; } = TimeSpan.FromSeconds(30);
    public TimeSpan StatusPollInterval { get; init; } = LaunchRules.StatusPollInterval;
    public int ConsentTimeoutSeconds { get; init; } = AgentCommandLine.DefaultConsentTimeoutSeconds;
    public Action<string>? Log { get; init; }
    /// <summary>
    /// Relay link opened, refreshed, or dropped. <c>group</c> is the shop slug when one is known.
    /// Called from the connection tasks; must not throw (exceptions are ignored).
    /// </summary>
    public Action<bool, string?>? LinkChanged { get; init; }
}

/// <summary>
/// Production Windows implementation of <see cref="IAgentPlatform"/> backed by <see cref="Win32Session"/> and <see cref="AgentPaths"/>.
/// </summary>
internal sealed class WindowsAgentPlatform : IAgentPlatform, IDisposable
{
    private readonly HttpClient _http = new(new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
    })
    {
        Timeout = TimeSpan.FromMinutes(10),
    };

    private readonly HttpClient _statusHttp = new()
    {
        Timeout = TimeSpan.FromSeconds(5),
    };

    public string MachineName => Environment.MachineName;
    public string GetOsVersion() => Win32Session.GetOsVersionText();
    public string GetActiveSignedInUser() => Win32Session.GetActiveSignedInUser();
    public string GetAgentVersion() => AgentPaths.GetAgentVersion();
    public string GetCachedOrInstalledAppVersion() => AgentPaths.GetInstalledOrCachedAppVersion();

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
        var (proc, err) = Win32Session.StartInActiveUserSession(
            hostExePath,
            fullCommandLine,
            workDir,
            preferElevatedToken: true,
            createNoWindow: false);

        return proc is null ? (null, err ?? "Failed to start Remote PC Diagnostics.") : (new SystemLaunchedProcess(proc), null);
    }

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

    private sealed class SystemLaunchedProcess(Process process) : IAgentLaunchedProcess
    {
        public bool HasExited
        {
            get
            {
                try { return process.HasExited; }
                catch { return true; }
            }
        }

        public uint ExitCode
        {
            get
            {
                try { return unchecked((uint)process.ExitCode); }
                catch { return 1; }
            }
        }

        public Task WaitForExitAsync(CancellationToken ct) => process.WaitForExitAsync(ct);

        public void Kill()
        {
            try { process.Kill(entireProcessTree: true); } catch { }
        }

        public void Dispose() => process.Dispose();
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

    /// <summary>
    /// Runs the persistent reconnection loop against <see cref="AgentConfig.Server"/> until <paramref name="stoppingToken"/> is cancelled
    /// (or until a <see cref="AgentLifetime.Session"/> agent finishes one session).
    /// </summary>
    public async Task RunLoopAsync(CancellationToken stoppingToken)
    {
        var backoff = new Backoff();

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
        };

        await WriteMessageAsync(new AgentMessage { Hello = hello }, token).ConfigureAwait(false);
        Log($"Sent AgentHello (machine={hello.MachineName}, user='{hello.SignedInUser}', version={hello.AgentVersion}).");
        AnnounceLink(true);

        var heartbeatTask = PumpHeartbeatsAsync(WriteMessageAsync, token);
        Task? activeLaunchTask = null;

        try
        {
            while (await call.ResponseStream.MoveNext(token).ConfigureAwait(false))
            {
                var command = call.ResponseStream.Current;
                switch (command.BodyCase)
                {
                    case HubCommand.BodyOneofCase.Launch:
                        activeLaunchTask = HandleLaunchCommand(command.Launch, WriteMessageAsync, streamCts);
                        break;

                    case HubCommand.BodyOneofCase.Cancel:
                        HandleCancelCommand(command.Cancel);
                        break;
                }
            }
        }
        finally
        {
            await streamCts.CancelAsync().ConfigureAwait(false);
            try { await heartbeatTask.ConfigureAwait(false); } catch { }
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
                bool running;
                string sessionId;
                lock (_stateGate)
                {
                    running = _sessionRunning;
                    sessionId = _runningSessionId;
                }

                var hb = new Heartbeat
                {
                    SignedInUser = platform.GetActiveSignedInUser(),
                    SessionRunning = running,
                    SessionId = sessionId,
                    CachedAppVersion = platform.GetCachedOrInstalledAppVersion(),
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

    private Task HandleLaunchCommand(
        LaunchCommand launch,
        Func<AgentMessage, CancellationToken, Task> writeAsync,
        CancellationTokenSource streamCts)
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

        return Task.Run(async () =>
        {
            try
            {
                await ExecuteLaunchCoreAsync(launch, writeAsync, launchCts.Token, streamCts).ConfigureAwait(false);
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
            }
        }, CancellationToken.None);
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
        CancellationToken launchCt,
        CancellationTokenSource streamCts)
    {
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

        var validationError = LaunchRules.Validate(launch.SessionId, launch.ServerUrl, out var sessionGuid, out var serverUrl);
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
                        await ReportProgressSafeAsync(writeAsync, launch.RequestId, sessionIdStr, LaunchStage.StageDeclined, "No answer within the consent time limit", 0, streamCts.Token).ConfigureAwait(false);
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

            var appCmdLine = LaunchRules.AppCommandLine(hostExePath, serverUrl, sessionGuid, launch.Group);
            await ReportProgressSafeAsync(writeAsync, launch.RequestId, sessionIdStr, LaunchStage.StageStarting, "Starting Remote PC Diagnostics...", 0, launchCt).ConfigureAwait(false);

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
                            await Task.Delay(_options.StatusPollInterval, launchCt).ConfigureAwait(false);
                            break;
                    }
                }

                // Wait until the Host process exits (or the launch/stream is cancelled).
                try
                {
                    await proc.WaitForExitAsync(launchCt).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!streamCts.IsCancellationRequested)
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

                await ReportProgressSafeAsync(
                    writeAsync,
                    launch.RequestId,
                    sessionIdStr,
                    LaunchStage.StageEnded,
                    "Session ended",
                    0,
                    streamCts.Token).ConfigureAwait(false);

                if (config.AgentLifetime == AgentLifetime.Session)
                {
                    _stopAfterSingleSession = true;
                    await platform.RemoveSelfAfterSessionAsync().ConfigureAwait(false);
                    await streamCts.CancelAsync().ConfigureAwait(false);
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

    private void Log(string message) =>
        _options.Log?.Invoke($"{DateTimeOffset.Now:O} [agent] {message}");
}
