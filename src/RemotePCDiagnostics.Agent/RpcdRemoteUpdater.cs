using System.Diagnostics;
using PeakSWC.RemoteWebView.Agent;
using RemotePCDiagnostics.Agent.Core;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Agent;

/// <summary>
/// Fleet-agent side of <c>update_rpcd</c>. Downloads the official GitHub installer, requires a matching SHA-256,
/// installs silently without replacing enrollment, consent, or lifetime, then relaunches RPCD so the session reconnects.
/// Status is written where a later process can read it: Setup stops this service. Agent.exe install, which Setup
/// runs outside this process, and the new service both seal that file so the relay's next read is terminal.
/// </summary>
internal sealed class RpcdRemoteUpdater : IDisposable
{
    private readonly RpcdUpdateSession _session;
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly Func<string?> _installedVersion;
    private readonly Func<IDisposable?> _holdUpdateLock;
    private readonly Func<IReadOnlyList<string>?> _relaunchArguments;
    private readonly Func<string?> _configuredServer;
    private readonly string _stagingDirectory;
    private readonly string _statusPath;
    private readonly string _lockPath;
    private readonly Action<string>? _log;
    private readonly bool _secureStaging;
    private readonly object _stagingGate = new();
    private string? _stagingError;
    private bool _restored;

    /// <summary>
    /// The service and elevated helper share the update status and a lock file in the admin-only staging folder.
    /// </summary>
    public RpcdRemoteUpdater(
        Func<string?> installedVersion,
        Func<IReadOnlyList<string>?> relaunchArguments,
        Action<string>? log,
        HttpClient? http = null,
        string? stagingDirectory = null,
        Func<string?>? configuredServer = null,
        Func<IDisposable?>? holdUpdateLock = null)
    {
        _installedVersion = installedVersion;
        _holdUpdateLock = holdUpdateLock ?? (() => UpdateBusyLock.TryHold(TimeSpan.FromSeconds(2)));
        _relaunchArguments = relaunchArguments;
        _configuredServer = configuredServer ?? (() => null);
        _log = log;
        _ownsHttp = http is null;
        _http = http ?? new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false })
        {
            Timeout = TimeSpan.FromMinutes(10),
        };
        _stagingDirectory = stagingDirectory ?? AgentSelfUpdater.StagingDirectory();
        _statusPath = Path.Combine(_stagingDirectory, "rpcd-update-status.json");
        _lockPath = Path.Combine(_stagingDirectory, "rpcd-update.lock");
        _session = new RpcdUpdateSession(Persist);
        _secureStaging = stagingDirectory is null;
        _ = TryPrepareStaging();
    }

    /// <summary>
    /// Secures the staging folder (and loads the saved status the first time it works). Run again on every start and, after a
    /// failure, on every read, so one failure at service start does not turn updates off until the service restarts.
    /// </summary>
    private bool TryPrepareStaging()
    {
        lock (_stagingGate)
        {
            try
            {
                if (_secureStaging)
                    AgentSelfUpdater.PrepareStaging(_stagingDirectory);
                if (!_restored)
                {
                    Restore();
                    _restored = true;
                }
                if (_stagingError is not null)
                    _log?.Invoke("[rpcd-update] Update staging is secured again.");
                _stagingError = null;
                return true;
            }
            catch (Exception ex)
            {
                if (_stagingError != ex.Message)
                    _log?.Invoke($"[rpcd-update] Could not secure update staging: {ex.Message}");
                _stagingError = ex.Message;
                return false;
            }
        }
    }

    private RpcdUpdateStatus StagingRefusal(string? requestId) => new()
    {
        RequestId = string.IsNullOrWhiteSpace(requestId) ? Guid.NewGuid().ToString("N") : requestId,
        Stage = RpcdUpdateStages.Refused,
        Terminal = true,
        Error = _stagingError,
        Detail = _stagingError,
        UpdatedUtc = DateTimeOffset.UtcNow,
    };

    public void Bind(AdminPipeServerOptions options)
    {
        options.StartUpdate = (request, relaunch, _) => Task.FromResult(Start(request, relaunch));
        options.ReadUpdate = requestId => Current(requestId);
    }

    public RpcdUpdateStatus? Current(string? requestId)
    {
        if (_stagingError is not null && !TryPrepareStaging())
            return StagingRefusal(requestId);
        LoadShared();
        return _session.Current(requestId, _installedVersion(), DateTimeOffset.UtcNow, ReadInstalledAgentProductVersion());
    }

    /// <summary>
    /// Starts an update unless something is running. The app's pipe request carries its own busy reason. For every request the
    /// agent also takes <see cref="UpdateBusyLock"/> and keeps it until Setup returns, so a hub command (whose busy reason is
    /// empty) is refused while the app holds it.
    /// </summary>
    public RpcdUpdateStatus Start(RpcdUpdateRequest request, IReadOnlyList<string>? relaunch)
    {
        if (!TryPrepareStaging())
            return StagingRefusal(null);

        var busyLock = _holdUpdateLock();
        if (busyLock is null && string.IsNullOrWhiteSpace(request.BusyReason))
            request = request with { BusyReason = UpdateBusyLock.BusyMessage };

        bool started;
        RpcdUpdateStatus status;
        var now = DateTimeOffset.UtcNow;
        using (var crossProcess = AcquireLock())
        {
            if (crossProcess is null)
            {
                busyLock?.Dispose();
                return new RpcdUpdateStatus
                {
                    RequestId = Guid.NewGuid().ToString("N"),
                    Stage = RpcdUpdateStages.Refused,
                    Channel = RpcdGitHubRelease.NormalizeChannel(request.Channel),
                    Terminal = true,
                    Error = "Another RPCD update request is being checked. Try again in a moment.",
                    Detail = "Another RPCD update request is being checked. Try again in a moment.",
                    UpdatedUtc = now,
                };
            }
            LoadShared();
            now = DateTimeOffset.UtcNow;
            started = _session.TryBegin(request, now, out status);
        }
        if (!started)
        {
            busyLock?.Dispose();
            return status;
        }

        var relaunchArgs = relaunch is { Count: > 0 } ? relaunch : _relaunchArguments();
        if (relaunchArgs is not null && !SessionLaunchOptions.IsRestartCommandLine(relaunchArgs))
        {
            _log?.Invoke("[rpcd-update] Ignoring a relaunch command line that is not a session restart.");
            relaunchArgs = null;
        }

        // Setup never starts the app. Its runasoriginaluser start would inherit an elevated helper's token, and in the service it
        // would land on Session 0. The agent starts the app un-elevated in the user's session instead (PendingAppRelaunch):
        // the new agent service does it when Setup restarts it, or this process does when Setup returns.
        var run = new RpcdUpdateRun
        {
            Http = _http,
            InstalledVersion = _installedVersion() ?? "",
            ReadInstalledVersion = _installedVersion,
            StagingDirectory = _stagingDirectory,
            RelaunchArguments = null,
            UtcNow = now,
            IsPersistentAgentInstalled = PersistentAgentInstalled,
            ReadInstalledAgentVersion = ReadInstalledAgentProductVersion,
            RunInstaller = (install, ct) => RunInstallerAsync(install, relaunchArgs, ct),
        };
        _ = Task.Run(async () =>
        {
            try
            {
                await _session.ExecuteAsync(request, run, CancellationToken.None).ConfigureAwait(false);
            }
            finally
            {
                busyLock?.Dispose();
            }
        });
        return status;
    }

    public async Task HandleHubAsync(
        UpdateRpcdCommand command,
        Func<UpdateRpcdProgress, CancellationToken, Task> report,
        CancellationToken reportCt)
    {
        var request = new RpcdUpdateRequest(
            command.Channel,
            string.IsNullOrWhiteSpace(command.Version) ? null : command.Version,
            command.Approved,
            string.IsNullOrWhiteSpace(command.ApprovedBy) ? null : command.ApprovedBy,
            BusyReason: null);
        var status = Start(request, relaunch: null);
        await ReportAsync(report, status, reportCt).ConfigureAwait(false);
        while (!status.Terminal && !reportCt.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(1), reportCt).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            var next = Current(status.RequestId) ?? status;
            if (next.Stage != status.Stage || next.Percent != status.Percent || next.Detail != status.Detail || next.Terminal)
            {
                status = next;
                await ReportAsync(report, status, reportCt).ConfigureAwait(false);
            }
        }
    }

    public UpdateRpcdProgress ToProgress(string? requestId)
    {
        var status = Current(string.IsNullOrWhiteSpace(requestId) ? null : requestId);
        if (status is null)
        {
            return new UpdateRpcdProgress
            {
                RequestId = requestId ?? "",
                Stage = RpcdUpdateStages.Idle,
                Detail = "No RPCD update has been requested.",
                Terminal = false,
            };
        }
        return ToProto(status);
    }

    public void Dispose()
    {
        if (_ownsHttp)
            _http.Dispose();
    }

    private async Task<int> RunInstallerAsync(RpcdPreparedInstall install, IReadOnlyList<string>? relaunch, CancellationToken ct)
    {
        await AppUpdateInstaller.VerifyPublisherAsync(install.InstallerPath, ct).ConfigureAwait(false);
        if (install.AgentMsiPath is { } agentMsiPath)
            await AppUpdateInstaller.VerifyPublisherAsync(agentMsiPath, ct).ConfigureAwait(false);
        // Save only when Setup is about to start so a refused update does not restart the app.
        if (relaunch is not null)
            PendingAppRelaunch.Save(_stagingDirectory, relaunch);

        // Session 0 (the agent service) can end the Host and still wait for Setup. The elevated helper is in the
        // Host's kill-on-close job, so it must not: Setup's script closes the Host after Setup has left that job.
        // Either way the Host has to be gone before Setup initializes. /SUPPRESSMSGBOXES answers the AppMutex
        // prompt with Cancel, and that Abort is exit code 1, before CloseApplications runs.
        if (RpcdSetupLog.CanCloseHostBeforeSetup(OperatingSystem.IsWindows() ? Process.GetCurrentProcess().SessionId : -1))
            RpcdHostShutdown.CloseRunningHost(_log);
        else
            _log?.Invoke("[rpcd-update] Leaving Remote PC Diagnostics running until Setup has started. Setup closes it.");

        // Cleared before Setup stops this service, so a crash during the hand-off does not start a second copy
        // that exits 0 and stays stopped. StartAndWait puts the actions back when Setup returns. Setup also puts
        // them back and starts the service, including when this process has already been stopped.
        AgentServiceRecovery.ClearFailureRestart(_log);
        var exit = await AgentSelfUpdater.StartAndWaitAsync(install.InstallerPath, install.Arguments, _stagingDirectory, _log, ct)
            .ConfigureAwait(false);
        var meaning = InnoSetupExitCodes.Describe(exit);
        _log?.Invoke($"[rpcd-update] Installer exited with code {exit} ({meaning}).");
        var tail = RpcdSetupLog.ReadTail(Path.Combine(_stagingDirectory, RpcdSetupLog.FileName));
        if (!string.IsNullOrWhiteSpace(tail))
            _log?.Invoke("[rpcd-update] Installer log (tail):" + Environment.NewLine + tail);
        // Setup closed the app. After a good install the restarted agent service usually starts it first; after a failed one the
        // previous build is still there. Either way the request is claimed once, so the app is started once and the file is gone.
        if (relaunch is not null)
            await ResumeRelaunchAsync().ConfigureAwait(false);
        return exit;
    }

    private async Task ResumeRelaunchAsync()
    {
        Process? started = null;
        string? startError = null;
        Func<string, string, string?> startHost = (hostExe, commandLine) =>
        {
            try
            {
                if (!OperatingSystem.IsWindows())
                    return "The app can only be started on Windows.";
                var workDir = Path.GetDirectoryName(hostExe) ?? AppContext.BaseDirectory;
                if (Process.GetCurrentProcess().SessionId == 0)
                {
                    var (proc, error) = Win32Session.StartInActiveUserSession(hostExe, commandLine, workDir, preferElevatedToken: false, createNoWindow: false);
                    proc?.Dispose();
                    return proc is null ? error ?? "Failed to start Remote PC Diagnostics." : null;
                }
                // The elevated helper: start the app with the signed-in user's shell token, never this process's elevated one.
                var args = SplitRestartCommandLine(commandLine, hostExe);
                if (args is null)
                    return "The relaunch command line could not be read.";
                started = UnelevatedProcess.StartAsync(hostExe, args, workDir, log: null).GetAwaiter().GetResult();
                return null;
            }
            catch (Exception ex)
            {
                startError = ex.Message;
                return ex.Message;
            }
        };
        await Task.Run(() => PendingAppRelaunch.TryResume(_stagingDirectory, _configuredServer(), startHost, _log)).ConfigureAwait(false);
        started?.Dispose();
        if (startError is not null)
            _log?.Invoke($"[rpcd-update] Could not start Remote PC Diagnostics again: {startError}");
    }

    /// <summary>
    /// The arguments after the exe in a command line <see cref="WindowsCommandLine.Join"/> built from a restart command line.
    /// Restart arguments never hold spaces or quotes (<see cref="SessionLaunchOptions.IsRestartCommandLine"/>), so splitting on spaces is exact.
    /// </summary>
    internal static IReadOnlyList<string>? SplitRestartCommandLine(string commandLine, string hostExe)
    {
        var quoted = WindowsCommandLine.Join([hostExe]);
        if (!commandLine.StartsWith(quoted, StringComparison.OrdinalIgnoreCase))
            return null;
        var args = commandLine[quoted.Length..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
        return SessionLaunchOptions.IsRestartCommandLine(args) ? args : null;
    }

    /// <summary>Reads the update status shared with the other agent process.</summary>
    private void LoadShared()
    {
        try
        {
            if (File.Exists(_statusPath))
                _session.Adopt(FinishFromSetupExit(RpcdUpdateStatus.Parse(File.ReadAllText(_statusPath))));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _log?.Invoke($"[rpcd-update] Could not read the saved update status: {ex.Message}");
        }
    }

    /// <summary>An exclusive handle on the lock file while one process decides whether to start, or null after a few seconds of waiting.</summary>
    private FileStream? AcquireLock()
    {
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (true)
        {
            try
            {
                Directory.CreateDirectory(_stagingDirectory);
                return new FileStream(_lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            }
            catch (IOException) when (DateTime.UtcNow < deadline)
            {
                Thread.Sleep(100);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                _log?.Invoke($"[rpcd-update] Could not take the update lock: {ex.Message}");
                return null;
            }
        }
    }

    private void Restore()
    {
        try
        {
            if (!File.Exists(_statusPath))
                return;
            var original = RpcdUpdateStatus.Parse(File.ReadAllText(_statusPath));
            if (original is null)
                return;
            // This process is the service, so a version that now matches was installed and the service is up.
            var status = RpcdUpdateSeal.Seal(FinishFromSetupExit(original) ?? original, InstalledHostVersion(), serviceRunning: true, DateTimeOffset.UtcNow, ReadInstalledAgentProductVersion());
            if (status is { Terminal: false }
                && status.Stage is not (RpcdUpdateStages.Installing or RpcdUpdateStages.Relaunching)
                && !IsOtherProcessAlive(status.OwnerPid))
            {
                var error = "The update stopped before the installer ran. Remote PC Diagnostics was not changed.";
                status = status with
                {
                    Stage = RpcdUpdateStages.Failed,
                    Terminal = true,
                    Error = error,
                    Detail = error,
                    UpdatedUtc = DateTimeOffset.UtcNow,
                };
            }
            _session.Restore(status);
            var reconciled = _session.Current(null, InstalledHostVersion(), DateTimeOffset.UtcNow, ReadInstalledAgentProductVersion());
            if (reconciled is not null && (reconciled.Stage != original.Stage || reconciled.Terminal != original.Terminal))
                Persist(reconciled);
        }
        catch (Exception ex)
        {
            _log?.Invoke($"[rpcd-update] Could not read the saved update status: {ex.Message}");
        }
    }

    /// <summary>
    /// An <c>installing</c> status whose Setup already wrote a failed exit code, made final and saved. This is how a hub update
    /// from the elevated helper ends: Setup closes the app, which ends the helper before Setup returns.
    /// </summary>
    private RpcdUpdateStatus? FinishFromSetupExit(RpcdUpdateStatus? status)
    {
        if (status is null || status.Terminal || status.Stage is not (RpcdUpdateStages.Installing or RpcdUpdateStages.Relaunching))
            return status;
        var exit = AgentSelfUpdater.ReadSetupExit(Path.Combine(_stagingDirectory, ScheduledSetup.ExitCodeFileName));
        if (exit is null)
            return status;
        if (exit == 0)
        {
            var agentChecked = RpcdUpdateSeal.ApplyZeroExitAgentCheck(status, exit, InstalledHostVersion(), ReadInstalledAgentProductVersion(), DateTimeOffset.UtcNow);
            if (agentChecked.Terminal)
            {
                _log?.Invoke("[rpcd-update] Setup exited 0 but the agent service is not the target build.");
                Persist(agentChecked);
            }
            return agentChecked;
        }
        var finished = RpcdUpdateSeal.ApplySetupExit(
            status,
            exit,
            InstalledHostVersion(),
            RpcdSetupLog.ReadTail(Path.Combine(_stagingDirectory, RpcdSetupLog.FileName)),
            DateTimeOffset.UtcNow);
        if (finished.Terminal)
        {
            _log?.Invoke($"[rpcd-update] Setup exited with code {exit} after the agent that started it had stopped. Recording the failure.");
            Persist(finished);
        }
        return finished;
    }

    private void Persist(RpcdUpdateStatus status)
    {
        try
        {
            if (File.Exists(_statusPath)
                && RpcdUpdateStatus.Parse(File.ReadAllText(_statusPath)) is { } onDisk
                && RpcdUpdateSeal.KeepSealedSuccess(onDisk, status))
            {
                _log?.Invoke("[rpcd-update] The installed update was already recorded as succeeded. Leaving that status in place.");
                return;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // The write below is this process's copy.
        }
        WriteAtomically(_statusPath, status.ToJson(), "update status");
    }

    /// <summary>
    /// Called from <c>Agent.exe install</c> after Setup has copied the new files. This process is not the agent
    /// that launched Setup, so the result is recorded even when that agent has already been stopped.
    /// </summary>
    internal static void SealStatusFile(string? installedVersion, bool serviceRunning, Action<string>? log)
    {
        try
        {
            var path = Path.Combine(AgentSelfUpdater.StagingDirectory(), RpcdUpdateSeal.FileName);
            if (!File.Exists(path))
                return;
            var parsed = RpcdUpdateStatus.Parse(File.ReadAllText(path));
            if (parsed is null)
                return;
            var done = RpcdUpdateSeal.Seal(parsed, installedVersion, serviceRunning, DateTimeOffset.UtcNow, ReadInstalledAgentProductVersion());
            if (RpcdUpdateSeal.KeepSealedSuccess(parsed, done))
                return;
            if (done.Stage == parsed.Stage && done.Terminal == parsed.Terminal)
                return;
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);
            var temp = path + ".seal.tmp";
            File.WriteAllText(temp, done.ToJson());
            File.Move(temp, path, overwrite: true);
            log?.Invoke($"[rpcd-update] Recorded {done.Stage} after install.");
        }
        catch (Exception ex)
        {
            log?.Invoke($"[rpcd-update] Could not record the update result after install: {ex.Message}");
        }
    }

    private string? InstalledHostVersion()
    {
        var host = AgentPaths.GetInstalledHostProductVersion();
        return string.IsNullOrWhiteSpace(host) ? _installedVersion() : host;
    }

    private void WriteAtomically(string path, string json, string what)
    {
        try
        {
            Directory.CreateDirectory(_stagingDirectory);
            var temp = $"{path}.{Environment.ProcessId}.tmp";
            File.WriteAllText(temp, json);
            File.Move(temp, path, overwrite: true);
        }
        catch (Exception ex)
        {
            _log?.Invoke($"[rpcd-update] Could not save the {what}: {ex.Message}");
        }
    }

    /// <summary>True when the update's owner is another agent process that is still running, so its download is not dead.</summary>
    private static bool IsOtherProcessAlive(int? pid)
    {
        if (pid is not > 0 || pid == Environment.ProcessId)
            return false;
        try
        {
            using var process = Process.GetProcessById(pid.Value);
            return !process.HasExited && string.Equals(process.ProcessName, Process.GetCurrentProcess().ProcessName, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static async Task ReportAsync(Func<UpdateRpcdProgress, CancellationToken, Task> report, RpcdUpdateStatus status, CancellationToken ct)
    {
        try
        {
            await report(ToProto(status), ct).ConfigureAwait(false);
        }
        catch
        {
            // The relay stream can drop while Setup is still running. The status file remains.
        }
    }

    internal static UpdateRpcdProgress ToProto(RpcdUpdateStatus status)
    {
        var progress = new UpdateRpcdProgress
        {
            RequestId = status.RequestId ?? "",
            Stage = status.Stage ?? "",
            Detail = status.Detail ?? "",
            Percent = status.Percent ?? 0,
            OldVersion = status.OldVersion ?? "",
            NewVersion = status.NewVersion ?? "",
            Terminal = status.Terminal,
            Error = status.Error ?? "",
            Channel = status.Channel ?? "",
            InstallerLog = status.InstallerLog ?? "",
            OldAgentVersion = status.OldAgentVersion ?? "",
            AgentVersion = status.AgentVersion ?? "",
        };
        if (status.InstallerExitCode is int exitCode)
            progress.InstallerExitCode = exitCode;
        return progress;
    }

    /// <summary>The persistent service executable, not the copy of Agent.exe that ships inside the desktop app.</summary>
    internal static bool PersistentAgentInstalled()
    {
        try { return File.Exists(AgentLayout.DefaultAgentExe()); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
    }

    internal static string? ReadInstalledAgentProductVersion() =>
        RpcdProductVersion.ReadFile(AgentLayout.DefaultAgentExe());

    /// <summary>The restart command line for the session the app published, so Setup brings that same session back.</summary>
    public static IReadOnlyList<string>? RelaunchForActiveSession(string? configuredServer)
    {
        var path = AgentLayout.ActiveSessionPath();
        if (!File.Exists(path) && File.Exists(AgentLayout.LegacyActiveSessionPath()))
            path = AgentLayout.LegacyActiveSessionPath();
        return RelaunchForActiveSession(configuredServer, path, IsHostProcessAlive);
    }

    /// <summary>
    /// The restart command line from the session file at <paramref name="path"/>, only while the Host that wrote it still runs.
    /// A file left behind by a Host that crashed would otherwise reopen the app into a session that is gone.
    /// </summary>
    internal static IReadOnlyList<string>? RelaunchForActiveSession(string? configuredServer, string path, Func<int, bool> hostAlive)
    {
        if (!Uri.TryCreate(configuredServer, UriKind.Absolute, out var server))
            return null;
        if (!File.Exists(path))
            return null;
        ActiveSessionInfo? info;
        try
        {
            info = ActiveSessionInfo.Parse(File.ReadAllText(path));
        }
        catch
        {
            return null;
        }
        if (info is null || !string.Equals(info.Mode, "Remote", StringComparison.OrdinalIgnoreCase))
            return null;
        if (!info.Running || info.ProcessId <= 0 || !hostAlive(info.ProcessId))
            return null;
        if (!Guid.TryParse(info.SessionId, out var sessionId) || sessionId == Guid.Empty)
            return null;
        var args = SessionLaunchOptions.RestartArguments(server, sessionId, info.Unattended, info.Voice, info.Group, info.Admin);
        return SessionLaunchOptions.IsRestartCommandLine(args) ? args : null;
    }

    private static bool IsHostProcessAlive(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return !process.HasExited &&
                string.Equals(process.ProcessName, RpcdHostShutdown.HostProcessName, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return false;
        }
    }
}
