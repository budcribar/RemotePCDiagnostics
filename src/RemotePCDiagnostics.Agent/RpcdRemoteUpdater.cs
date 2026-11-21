using System.Diagnostics;
using PeakSWC.RemoteWebView.Agent;
using RemotePCDiagnostics.Agent.Core;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Agent;

/// <summary>
/// Fleet-agent side of <c>update_rpcd</c>. Downloads the official GitHub installer, requires a matching SHA-256,
/// installs silently without replacing enrollment, consent, or lifetime, then relaunches RPCD so the session reconnects.
/// Status is written where a later process can read it: Setup stops this service, and the new one finishes the story.
/// </summary>
internal sealed class RpcdRemoteUpdater : IDisposable
{
    private readonly RpcdUpdateSession _session;
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly Func<string?> _installedVersion;
    private readonly Func<bool> _hostRunning;
    private readonly Func<IReadOnlyList<string>?> _relaunchArguments;
    private readonly Func<string?> _configuredServer;
    private readonly string _stagingDirectory;
    private readonly string _statusPath;
    private readonly string _activityPath;
    private readonly string _lockPath;
    private readonly Action<string>? _log;

    /// <summary>
    /// The agent service and an app's elevated helper each have one of these. They share the status, the app's activity report,
    /// and a lock file in the admin-only staging folder, so either can answer and only one update runs at a time.
    /// </summary>
    public RpcdRemoteUpdater(
        Func<string?> installedVersion,
        Func<bool> hostRunning,
        Func<IReadOnlyList<string>?> relaunchArguments,
        Action<string>? log,
        HttpClient? http = null,
        string? stagingDirectory = null,
        Func<string?>? configuredServer = null)
    {
        _installedVersion = installedVersion;
        _hostRunning = hostRunning;
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
        _activityPath = Path.Combine(_stagingDirectory, "rpcd-update-activity.json");
        _lockPath = Path.Combine(_stagingDirectory, "rpcd-update.lock");
        _session = new RpcdUpdateSession(Persist);
        Restore();
    }

    public void ReportActivity(string? busyReason)
    {
        var now = DateTimeOffset.UtcNow;
        _session.ReportActivity(busyReason, now);
        WriteAtomically(_activityPath, new RpcdActivityReport(string.IsNullOrWhiteSpace(busyReason) ? null : busyReason.Trim(), now).ToJson(), "activity report");
    }

    public void Bind(AdminPipeServerOptions options)
    {
        options.StartUpdate = (request, relaunch, _) => Task.FromResult(Start(request, relaunch, trustCallerBusyReason: true));
        options.ReadUpdate = requestId => Current(requestId);
        options.ReportActivity = ReportActivity;
    }

    public RpcdUpdateStatus? Current(string? requestId)
    {
        LoadShared();
        return _session.Current(requestId, _installedVersion(), DateTimeOffset.UtcNow);
    }

    public RpcdUpdateStatus Start(RpcdUpdateRequest request, IReadOnlyList<string>? relaunch, bool trustCallerBusyReason)
    {
        var now = DateTimeOffset.UtcNow;
        bool started;
        RpcdUpdateStatus status;
        using (var crossProcess = AcquireLock())
        {
            if (crossProcess is null)
            {
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
            // The other agent process may have started an update, or heard from the app, since this one last looked.
            LoadShared();
            started = _session.TryBegin(request, _hostRunning(), trustCallerBusyReason, now, out status);
        }
        if (!started)
            return status;

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
            RunInstaller = (install, ct) => RunInstallerAsync(install, relaunchArgs, ct),
        };
        _ = Task.Run(() => _session.ExecuteAsync(request, run, CancellationToken.None));
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
        var status = Start(request, relaunch: null, trustCallerBusyReason: false);
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
        try
        {
            AgentSelfUpdater.PrepareStaging(_stagingDirectory);
            // Saved only once Setup is about to start, so a refused or failed check does not restart the app.
            if (relaunch is not null)
                PendingAppRelaunch.Save(_stagingDirectory, relaunch);
        }
        catch (Exception ex)
        {
            _log?.Invoke($"[rpcd-update] Could not secure the staging directory: {ex.Message}");
            return -1;
        }

        var exit = await AgentSelfUpdater.StartAndWaitAsync(install.InstallerPath, install.Arguments, _stagingDirectory, _log, ct)
            .ConfigureAwait(false);
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

    /// <summary>Reads what the other agent process saved: its update status and the app's last activity report.</summary>
    private void LoadShared()
    {
        try
        {
            if (File.Exists(_statusPath))
                _session.Adopt(RpcdUpdateStatus.Parse(File.ReadAllText(_statusPath)));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        try
        {
            if (File.Exists(_activityPath) && RpcdActivityReport.Parse(File.ReadAllText(_activityPath)) is { } report)
                _session.ReportActivity(report.BusyReason, report.At);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
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
            var status = RpcdUpdateStatus.Parse(File.ReadAllText(_statusPath));
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
            var reconciled = _session.Current(null, _installedVersion(), DateTimeOffset.UtcNow);
            if (reconciled is not null && status is not null && (reconciled.Stage != status.Stage || reconciled.Terminal != status.Terminal))
                Persist(reconciled);
        }
        catch (Exception ex)
        {
            _log?.Invoke($"[rpcd-update] Could not read the saved update status: {ex.Message}");
        }
    }

    private void Persist(RpcdUpdateStatus status) => WriteAtomically(_statusPath, status.ToJson(), "update status");

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

    internal static UpdateRpcdProgress ToProto(RpcdUpdateStatus status) => new()
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
    };

    /// <summary>True when the app the agent started is still running, so its activity report has to be fresh.</summary>
    public static bool IsTrackedHostRunning()
    {
        var path = AgentLayout.ActiveSessionPath();
        if (!File.Exists(path) && File.Exists(AgentLayout.LegacyActiveSessionPath()))
            path = AgentLayout.LegacyActiveSessionPath();
        if (!File.Exists(path))
            return false;
        ActiveSessionInfo? info;
        try
        {
            info = ActiveSessionInfo.Parse(File.ReadAllText(path));
        }
        catch
        {
            return false;
        }
        if (info is not { Running: true, ProcessId: > 0 })
            return false;
        try
        {
            using var process = Process.GetProcessById(info.ProcessId);
            return !process.HasExited;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>The restart command line for the session the app published, so Setup brings that same session back.</summary>
    public static IReadOnlyList<string>? RelaunchForActiveSession(string? configuredServer)
    {
        if (!Uri.TryCreate(configuredServer, UriKind.Absolute, out var server))
            return null;
        var path = AgentLayout.ActiveSessionPath();
        if (!File.Exists(path) && File.Exists(AgentLayout.LegacyActiveSessionPath()))
            path = AgentLayout.LegacyActiveSessionPath();
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
        if (!Guid.TryParse(info.SessionId, out var sessionId) || sessionId == Guid.Empty)
            return null;
        var args = SessionLaunchOptions.RestartArguments(server, sessionId, info.Unattended, info.Voice, info.Group, info.Admin);
        return SessionLaunchOptions.IsRestartCommandLine(args) ? args : null;
    }
}
