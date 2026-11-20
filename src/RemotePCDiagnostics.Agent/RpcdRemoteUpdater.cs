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
    private readonly string _stagingDirectory;
    private readonly string _statusPath;
    private readonly Action<string>? _log;

    public RpcdRemoteUpdater(
        Func<string?> installedVersion,
        Func<bool> hostRunning,
        Func<IReadOnlyList<string>?> relaunchArguments,
        Action<string>? log,
        HttpClient? http = null,
        string? stagingDirectory = null)
    {
        _installedVersion = installedVersion;
        _hostRunning = hostRunning;
        _relaunchArguments = relaunchArguments;
        _log = log;
        _ownsHttp = http is null;
        _http = http ?? new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false })
        {
            Timeout = TimeSpan.FromMinutes(10),
        };
        _stagingDirectory = stagingDirectory ?? AgentSelfUpdater.StagingDirectory();
        _statusPath = Path.Combine(_stagingDirectory, "rpcd-update-status.json");
        _session = new RpcdUpdateSession(Persist);
        Restore();
    }

    public void ReportActivity(string? busyReason) =>
        _session.ReportActivity(busyReason, DateTimeOffset.UtcNow);

    public void Bind(AdminPipeServerOptions options)
    {
        options.StartUpdate = (request, relaunch, _) => Task.FromResult(Start(request, relaunch, trustCallerBusyReason: true));
        options.ReadUpdate = requestId => Current(requestId);
        options.ReportActivity = ReportActivity;
    }

    public RpcdUpdateStatus? Current(string? requestId) =>
        _session.Current(requestId, _installedVersion(), DateTimeOffset.UtcNow);

    public RpcdUpdateStatus Start(RpcdUpdateRequest request, IReadOnlyList<string>? relaunch, bool trustCallerBusyReason)
    {
        var now = DateTimeOffset.UtcNow;
        var started = _session.TryBegin(request, _hostRunning(), trustCallerBusyReason, now, out var status);
        if (!started)
            return status;

        var forSetup = relaunch is { Count: > 0 } ? relaunch : _relaunchArguments();
        if (forSetup is not null && !SessionLaunchOptions.IsRestartCommandLine(forSetup))
        {
            _log?.Invoke("[rpcd-update] Ignoring a relaunch command line that is not a session restart.");
            forSetup = null;
        }
        IReadOnlyList<string>? serviceRelaunch = null;
        if (forSetup is { Count: > 0 }
            && OperatingSystem.IsWindows()
            && Process.GetCurrentProcess().SessionId == 0)
        {
            // Setup would start the app on Session 0's desktop. The service starts it in the user's session instead.
            // Saved only once Setup is actually launched, so a refused or failed check does not restart the app.
            serviceRelaunch = forSetup;
            forSetup = null;
        }

        var run = new RpcdUpdateRun
        {
            Http = _http,
            InstalledVersion = _installedVersion() ?? "",
            ReadInstalledVersion = _installedVersion,
            StagingDirectory = _stagingDirectory,
            RelaunchArguments = forSetup,
            UtcNow = now,
            RunInstaller = (install, ct) => RunInstallerAsync(install, serviceRelaunch, ct),
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

    private async Task<int> RunInstallerAsync(RpcdPreparedInstall install, IReadOnlyList<string>? serviceRelaunch, CancellationToken ct)
    {
        try
        {
            AgentSelfUpdater.PrepareStaging(_stagingDirectory);
            if (serviceRelaunch is not null)
                PendingAppRelaunch.Save(_stagingDirectory, serviceRelaunch);
        }
        catch (Exception ex)
        {
            _log?.Invoke($"[rpcd-update] Could not secure the staging directory: {ex.Message}");
            return -1;
        }

        var exit = await AgentSelfUpdater.StartAndWaitAsync(install.InstallerPath, install.Arguments, _stagingDirectory, _log, ct)
            .ConfigureAwait(false);
        if (exit != 0)
        {
            // Setup closes the app before it copies files. A failed install leaves the previous build; bring that session back.
            if (serviceRelaunch is not null)
                StartRelaunch(serviceRelaunch);
            else
                TryRelaunch(install.Arguments);
        }
        return exit;
    }

    private void TryRelaunch(string setupArguments)
    {
        const string marker = "/RELAUNCHARGS=";
        var index = setupArguments.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (index < 0)
            return;
        var raw = setupArguments[(index + marker.Length)..].Trim().Trim('"');
        if (string.IsNullOrWhiteSpace(raw))
            return;
        var args = raw.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (!SessionLaunchOptions.IsRestartCommandLine(args))
            return;
        StartRelaunch(args);
    }

    private void StartRelaunch(IReadOnlyList<string> args)
    {
        var host = AgentPaths.TryFindLocalInstalledHostExe();
        if (host is null)
            return;
        try
        {
            var (proc, error) = Win32Session.StartInActiveUserSession(host, WindowsCommandLine.Join([host, .. args]), Path.GetDirectoryName(host) ?? AppContext.BaseDirectory, preferElevatedToken: false, createNoWindow: false);
            proc?.Dispose();
            if (error is not null)
                _log?.Invoke($"[rpcd-update] Could not bring the previous version back: {error}");
        }
        catch (Exception ex)
        {
            _log?.Invoke($"[rpcd-update] Could not bring the previous version back: {ex.Message}");
        }
    }

    private void Restore()
    {
        try
        {
            if (!File.Exists(_statusPath))
                return;
            var status = RpcdUpdateStatus.Parse(File.ReadAllText(_statusPath));
            if (status is { Terminal: false } && status.Stage is not (RpcdUpdateStages.Installing or RpcdUpdateStages.Relaunching))
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

    private void Persist(RpcdUpdateStatus status)
    {
        try
        {
            Directory.CreateDirectory(_stagingDirectory);
            var path = _statusPath;
            var temp = path + ".tmp";
            File.WriteAllText(temp, status.ToJson());
            File.Move(temp, path, overwrite: true);
        }
        catch (Exception ex)
        {
            _log?.Invoke($"[rpcd-update] Could not save update status: {ex.Message}");
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
        var args = SessionLaunchOptions.RestartArguments(server, sessionId, info.Unattended, info.Voice, info.Group);
        return SessionLaunchOptions.IsRestartCommandLine(args) ? args : null;
    }
}
