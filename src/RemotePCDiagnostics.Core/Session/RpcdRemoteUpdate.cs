using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace RemotePCDiagnostics.Core.Session;

/// <summary>Stages a caller can poll while <c>update_rpcd</c> runs. Terminal stages are the last word.</summary>
public static class RpcdUpdateStages
{
    public const string Idle = "idle";
    /// <summary>The PC was busy when the update was asked for. The agent starts it when the PC is free. Not terminal.</summary>
    public const string Waiting = "waiting";
    public const string Checking = "checking";
    public const string Refused = "refused";
    public const string AlreadyUpToDate = "already_up_to_date";
    public const string Downloading = "downloading";
    public const string Verifying = "verifying";
    public const string Installing = "installing";
    public const string Relaunching = "relaunching";
    public const string Succeeded = "succeeded";
    public const string Failed = "failed";
    /// <summary>The app reached the target and the installed agent service did not. Terminal. Not a success.</summary>
    public const string AgentNotUpdated = "agent_not_updated";
    /// <summary>A technician stopped an update while it was waiting. Nothing was installed. Terminal.</summary>
    public const string Cancelled = "cancelled";

    public static bool IsTerminal(string? stage) => stage is Refused or AlreadyUpToDate or Succeeded or Failed or AgentNotUpdated or Cancelled;
}

/// <summary>
/// One remote update. A non-empty <see cref="BusyReason"/> refuses it. The app fills it from what it is running; for a hub
/// command it is empty and the agent refuses through the update lock instead.
/// <see cref="Approved"/> must be true. A label in <see cref="ApprovedBy"/> is not approval.
/// </summary>
public sealed record RpcdUpdateRequest(
    string? Channel,
    string? Version,
    bool Approved,
    string? ApprovedBy = null,
    string? BusyReason = null);

/// <summary>Polled status of one update. <see cref="NewVersion"/> is the release being installed, then the version now on disk.</summary>
public sealed record RpcdUpdateStatus
{
    public string RequestId { get; init; } = "";
    public string Stage { get; init; } = RpcdUpdateStages.Idle;
    public string? Detail { get; init; }
    public int? Percent { get; init; }
    public string? OldVersion { get; init; }
    public string? NewVersion { get; init; }
    /// <summary>True when a persistent agent service was installed, so success requires that service's version as well as the app.</summary>
    public bool UpdateAgent { get; init; }
    /// <summary>Agent service product version before the attempt. Set only when <see cref="UpdateAgent"/> is true.</summary>
    public string? OldAgentVersion { get; init; }
    /// <summary>Agent service product version after the attempt.</summary>
    public string? AgentVersion { get; init; }
    public string? Channel { get; init; }
    public bool Terminal { get; init; }
    public string? Error { get; init; }
    public string? ApprovedBy { get; init; }
    /// <summary>Process exit code of Setup, set when the attempt failed after Setup was started. 0 is a real code (Setup exited 0 but the version did not change).</summary>
    public int? InstallerExitCode { get; init; }
    /// <summary>Masked tail of the Setup <c>/LOG</c> file, set on failure. About the last 200 lines.</summary>
    public string? InstallerLog { get; init; }
    public DateTimeOffset UpdatedUtc { get; init; }
    /// <summary>
    /// The agent process running this update. The agent service and an app's elevated helper share the status file, so a process
    /// that starts while another one is downloading must not call that update dead.
    /// </summary>
    public int? OwnerPid { get; init; }

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public string ToJson() => JsonSerializer.Serialize(this, Json);

    public static RpcdUpdateStatus? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return null;
        try
        {
            return JsonSerializer.Deserialize<RpcdUpdateStatus>(json, Json);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}

/// <summary>The verified installer the agent is allowed to start. No other file is installed.</summary>
public sealed record RpcdPreparedInstall(string InstallerPath, string Arguments, string TargetVersion, string OldVersion)
{
    /// <summary>The verified Agent MSI Setup is told to run, if any.</summary>
    public string? AgentMsiPath { get; init; }
}

/// <summary>What the agent needs around the pure update steps: clock, versions, and a way to run Setup.</summary>
public sealed class RpcdUpdateRun
{
    public required HttpClient Http { get; init; }
    public required string InstalledVersion { get; init; }
    public required Func<string?> ReadInstalledVersion { get; init; }
    public required string StagingDirectory { get; init; }
    public IReadOnlyList<string>? RelaunchArguments { get; init; }
    /// <summary>
    /// True when <c>C:\Program Files\RemotePCDiagnosticsAgent\RemotePCDiagnostics.Agent.exe</c> is installed.
    /// The update then downloads that release's Agent MSI and passes it as <c>/AGENTMSI</c>, the same way the in-app Update does.
    /// </summary>
    public Func<bool>? IsPersistentAgentInstalled { get; init; }
    /// <summary>Product version of the installed agent service executable. Null when it cannot be read.</summary>
    public Func<string?>? ReadInstalledAgentVersion { get; init; }
    public required Func<RpcdPreparedInstall, CancellationToken, Task<int>> RunInstaller { get; init; }
    public DateTimeOffset UtcNow { get; init; } = DateTimeOffset.UtcNow;
}

/// <summary>
/// Technician-approved update of the installed RPCD build from the official GitHub release.
/// Refuses without approval, while diagnostics work is running, or when the PC is already on that build.
/// The installer is downloaded only from GitHub and only after its SHA-256 matches. A failed check leaves the
/// installed build untouched. Inno Setup rolls back a failed copy; a non-zero exit is reported with the old version.
/// </summary>
public sealed class RpcdUpdateSession
{
    /// <summary>How long an <c>installing</c> status may sit unchanged, after this process is no longer running Setup, before it is a failure.</summary>
    public static readonly TimeSpan InstallGiveUp = TimeSpan.FromMinutes(20);

    /// <summary>How long a hub update waits for the PC to be free before it gives up.</summary>
    public static readonly TimeSpan WaitLimit = TimeSpan.FromMinutes(30);
    /// <summary>How often the waiting process refreshes the status, so another process can tell it is still alive.</summary>
    public static readonly TimeSpan WaitHeartbeat = TimeSpan.FromSeconds(30);
    /// <summary>A waiting status older than this belongs to an agent process that ended (a restart) and nothing is waiting any more.</summary>
    public static readonly TimeSpan WaitStale = TimeSpan.FromMinutes(2);

    public const string WaitingDetail =
        "Waiting for Remote PC Diagnostics to finish what it is doing (a check, fix, undo, service workflow, stress test or benchmark). The update starts when it is done.";

    public const string ApprovalRequired = "Technician approval is required before Remote PC Diagnostics can be updated on this PC.";
    private readonly object _gate = new();
    private readonly Action<RpcdUpdateStatus>? _onStatus;
    private RpcdUpdateStatus? _status;
    private int _localInstaller;
    private readonly int _ownerPid;

    public RpcdUpdateSession(Action<RpcdUpdateStatus>? onStatus = null, int? ownerPid = null)
    {
        _onStatus = onStatus;
        _ownerPid = ownerPid ?? Environment.ProcessId;
    }

    /// <summary>
    /// Takes a status another process saved when it is newer than the one held here, so both agent processes refuse a second update
    /// and report the same progress. Ignored while this process is running Setup.
    /// </summary>
    public void Adopt(RpcdUpdateStatus? saved)
    {
        if (saved is null)
            return;
        lock (_gate)
        {
            if (Volatile.Read(ref _localInstaller) != 0)
                return;
            if (_status is null || saved.UpdatedUtc > _status.UpdatedUtc)
                _status = saved;
        }
    }

    public void Restore(RpcdUpdateStatus? status)
    {
        lock (_gate)
            _status = status;
    }

    public RpcdUpdateStatus? Current(string? requestId, string? installedVersion, DateTimeOffset utcNow, string? installedAgentVersion = null)
    {
        RpcdUpdateStatus? status;
        lock (_gate)
        {
            if (_status is null)
                return null;
            if (Volatile.Read(ref _localInstaller) == 0)
                _status = RpcdGitHubRelease.Reconcile(_status, installedVersion, utcNow, InstallGiveUp, installedAgentVersion);
            status = _status;
        }
        if (!string.IsNullOrEmpty(requestId)
            && !string.Equals(status.RequestId, requestId, StringComparison.Ordinal))
            return null;
        return status;
    }

    /// <summary>
    /// Accepts or refuses. When it returns true the caller must run <see cref="ExecuteAsync"/> (the work continues if this process dies
    /// only through the status file the caller persisted). A non-empty <see cref="RpcdUpdateRequest.BusyReason"/> refuses. For a hub
    /// command the agent fills it from the update lock (see <c>UpdateBusyLock</c>), so a hub command cannot claim the PC is idle.
    /// </summary>
    /// <param name="waitIfBusy">
    /// When the request is busy, accept it in <see cref="RpcdUpdateStages.Waiting"/> instead of refusing. The caller then waits for the
    /// PC to be free and calls <see cref="TryLeaveWaiting"/> before <see cref="ExecuteAsync"/>.
    /// </param>
    public bool TryBegin(RpcdUpdateRequest request, DateTimeOffset utcNow, out RpcdUpdateStatus status, bool waitIfBusy = false)
    {
        var requestId = Guid.NewGuid().ToString("N");
        var channel = RpcdGitHubRelease.NormalizeChannel(request.Channel);
        var approvedBy = RpcdGitHubRelease.CleanLabel(request.ApprovedBy);
        RpcdUpdateStatus Refused(string error, bool persist, string? detail = null)
        {
            var full = string.IsNullOrWhiteSpace(detail) ? error : error + " " + detail.Trim();
            var refused = new RpcdUpdateStatus
            {
                RequestId = requestId,
                Stage = RpcdUpdateStages.Refused,
                Channel = channel,
                Terminal = true,
                Error = error,
                Detail = full,
                ApprovedBy = approvedBy,
                UpdatedUtc = utcNow,
            };
            return persist ? Set(refused) : refused;
        }

        // One lock from the in-progress check to the checking status, so two requests at once cannot both start.
        lock (_gate)
        {
            if (_status is { Terminal: false } && utcNow - _status.UpdatedUtc < InstallGiveUp
                && !(_status.Stage == RpcdUpdateStages.Waiting && utcNow - _status.UpdatedUtc > WaitStale))
            {
                status = Refused("An RPCD update is already in progress.", persist: false);
                return false;
            }

            if (!request.Approved)
            {
                status = Refused(ApprovalRequired, persist: true);
                return false;
            }
            if (channel is null)
            {
                status = Refused("Channel must be stable or prerelease.", persist: true);
                return false;
            }
            if (!string.IsNullOrWhiteSpace(request.Version) && AppVersionComparer.Normalize(request.Version) is null)
            {
                status = Refused("Version must look like 1.2.0 or 1.2.0-ci.996.1.", persist: true);
                return false;
            }

            if (!string.IsNullOrWhiteSpace(request.BusyReason))
            {
                if (!waitIfBusy)
                {
                    status = Refused(request.BusyReason.Trim(), persist: true);
                    return false;
                }
                status = Set(new RpcdUpdateStatus
                {
                    RequestId = requestId,
                    Stage = RpcdUpdateStages.Waiting,
                    Channel = channel,
                    Detail = WaitingDetail,
                    ApprovedBy = approvedBy,
                    Terminal = false,
                    UpdatedUtc = utcNow,
                    OwnerPid = _ownerPid,
                });
                return true;
            }

            status = Set(new RpcdUpdateStatus
            {
                RequestId = requestId,
                Stage = RpcdUpdateStages.Checking,
                Channel = channel,
                Detail = "Checking the official GitHub release...",
                OldVersion = null,
                ApprovedBy = approvedBy,
                Terminal = false,
                UpdatedUtc = utcNow,
                OwnerPid = _ownerPid,
            });
            return true;
        }
    }

    /// <summary>
    /// Refreshes a waiting update so other processes see it is alive. False when it is no longer waiting (cancelled, or replaced).
    /// </summary>
    public bool TouchWaiting(string requestId, DateTimeOffset utcNow, TimeSpan waited)
    {
        lock (_gate)
        {
            if (!IsWaiting(_status, requestId))
                return false;
            var minutes = (int)waited.TotalMinutes;
            var detail = minutes < 1 ? WaitingDetail : $"{WaitingDetail} Waiting {minutes} min so far.";
            SetNoLock(_status! with { Detail = detail, UpdatedUtc = utcNow });
        }
        PersistCurrent();
        return true;
    }

    /// <summary>
    /// Moves a waiting update on to <see cref="RpcdUpdateStages.Checking"/> once the caller holds the update lock. False when it was
    /// cancelled meanwhile: the caller must then release the lock and not install.
    /// </summary>
    public bool TryLeaveWaiting(string requestId, DateTimeOffset utcNow)
    {
        lock (_gate)
        {
            if (!IsWaiting(_status, requestId))
                return false;
            SetNoLock(_status! with
            {
                Stage = RpcdUpdateStages.Checking,
                Detail = "Checking the official GitHub release...",
                UpdatedUtc = utcNow,
            });
        }
        PersistCurrent();
        return true;
    }

    /// <summary>Ends a waiting update without installing: the wait limit passed. False when it was no longer waiting.</summary>
    public bool GiveUpWaiting(string requestId, DateTimeOffset utcNow)
    {
        var error = $"Remote PC Diagnostics was still busy after {(int)WaitLimit.TotalMinutes} minutes, so the update was not started. Try again when it is free.";
        lock (_gate)
        {
            if (!IsWaiting(_status, requestId))
                return false;
            SetNoLock(_status! with { Stage = RpcdUpdateStages.Refused, Terminal = true, Error = error, Detail = error, UpdatedUtc = utcNow });
        }
        PersistCurrent();
        return true;
    }

    /// <summary>
    /// Cancels the update named by <paramref name="requestId"/> (empty = the current one) while it is waiting. Returns the status after
    /// the call, or null when there is no update. An update past waiting is not stopped; its status is returned unchanged.
    /// </summary>
    public RpcdUpdateStatus? CancelWaiting(string? requestId, DateTimeOffset utcNow)
    {
        lock (_gate)
        {
            if (_status is null)
                return null;
            if (!string.IsNullOrWhiteSpace(requestId) && !string.Equals(_status.RequestId, requestId.Trim(), StringComparison.Ordinal))
                return null;
            if (_status.Stage != RpcdUpdateStages.Waiting || _status.Terminal)
                return _status;
            const string error = "The update was cancelled while it was waiting. Nothing was installed.";
            SetNoLock(_status with { Stage = RpcdUpdateStages.Cancelled, Terminal = true, Error = error, Detail = error, UpdatedUtc = utcNow });
        }
        return PersistCurrent();
    }

    private static bool IsWaiting(RpcdUpdateStatus? status, string requestId) =>
        status is { Stage: RpcdUpdateStages.Waiting, Terminal: false } && string.Equals(status.RequestId, requestId, StringComparison.Ordinal);

    public async Task ExecuteAsync(RpcdUpdateRequest request, RpcdUpdateRun run, CancellationToken ct)
    {
        var current = Current(null, null, run.UtcNow);
        if (current is null || current.Terminal)
            return;

        var channel = current.Channel ?? "stable";
        var oldVersion = string.IsNullOrWhiteSpace(run.InstalledVersion) ? null : run.InstalledVersion.Trim();
        Touch(current with { OldVersion = oldVersion, UpdatedUtc = run.UtcNow });

        try
        {
            var release = await RpcdGitHubRelease.FetchAsync(run.Http, channel, request.Version, ct).ConfigureAwait(false);
            if (release.Error is not null || release.Choice is null)
            {
                Fail(current, oldVersion, release.Error ?? "No RPCD installer was published.");
                return;
            }

            var target = release.Choice.Version;
            bool updateAgent;
            string? oldAgent;
            try
            {
                updateAgent = run.IsPersistentAgentInstalled?.Invoke() == true;
                oldAgent = updateAgent ? run.ReadInstalledAgentVersion?.Invoke() : null;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Fail(current, oldVersion, "Could not tell whether the agent service is installed. The update was not installed. " + ex.Message);
                return;
            }

            // Later `current with` copies keep this, including the status another process seals after Setup stops this one.
            current = current with { UpdateAgent = updateAgent, OldAgentVersion = oldAgent };

            if (!string.IsNullOrWhiteSpace(oldVersion))
            {
                var newer = AppVersionComparer.IsNewer(target, oldVersion);
                var same = string.Equals(AppVersionComparer.Normalize(target), AppVersionComparer.Normalize(oldVersion), StringComparison.OrdinalIgnoreCase);
                if (newer is null && !same)
                {
                    Fail(current, oldVersion, $"Cannot tell whether {target} is newer than {oldVersion}. The update was not installed.");
                    return;
                }
                // A newer app on the PC is not replaced with an older release, even when its agent is behind.
                if (newer == false && !same)
                {
                    var error = $"RPCD {oldVersion} is newer than the published {target}.";
                    Set(current with
                    {
                        Stage = RpcdUpdateStages.AlreadyUpToDate,
                        Terminal = true,
                        OldVersion = oldVersion,
                        NewVersion = target,
                        Error = error,
                        Detail = error,
                        UpdatedUtc = DateTimeOffset.UtcNow,
                    });
                    return;
                }
                var agentBehind = updateAgent && !RpcdGitHubRelease.SameBuild(oldAgent, target);
                if (newer != true && !agentBehind)
                {
                    var error = $"RPCD {oldVersion} is already up to date on the {channel} channel ({target}).";
                    Set(current with
                    {
                        Stage = RpcdUpdateStages.AlreadyUpToDate,
                        Terminal = true,
                        OldVersion = oldVersion,
                        NewVersion = target,
                        Error = error,
                        Detail = error,
                        UpdatedUtc = DateTimeOffset.UtcNow,
                    });
                    return;
                }
            }

            if (updateAgent && string.IsNullOrWhiteSpace(release.Choice.AgentMsiUrl))
            {
                Fail(current, oldVersion, release.Choice.AgentMsiError
                    ?? "The release has no verified Agent MSI. The update was not installed.");
                return;
            }

            Touch(current with
            {
                Stage = RpcdUpdateStages.Downloading,
                OldVersion = oldVersion,
                NewVersion = target,
                Detail = $"Downloading RPCD {target} from GitHub...",
                Percent = 0,
                UpdatedUtc = DateTimeOffset.UtcNow,
            });

            var packageDirectory = Path.Combine(run.StagingDirectory, Guid.NewGuid().ToString("N"));
            var installerPath = await AppUpdateInstaller.DownloadAndVerifyAsync(
                run.Http,
                release.Choice.InstallerUrl,
                release.Choice.Sha256Url,
                packageDirectory,
                progress => ReportDownload(current, oldVersion, target, progress),
                ct).ConfigureAwait(false);

            // Same download and SHA-256 check as AgentSelfUpdater / AppUpdateService. Required here: a missing or
            // unverified MSI must not end as success with the service left on the old build.
            string? agentMsiPath = null;
            if (updateAgent)
            {
                agentMsiPath = await AppUpdateInstaller.DownloadAgentMsiAsync(
                    run.Http,
                    release.Choice.AgentMsiUrl,
                    release.Choice.AgentMsiSha256Url,
                    packageDirectory,
                    required: true,
                    progress => ReportDownload(current, oldVersion, target, progress),
                    onSkipped: null,
                    ct).ConfigureAwait(false);
                if (string.IsNullOrWhiteSpace(agentMsiPath))
                {
                    Fail(current, oldVersion, "The Agent MSI could not be verified. The update was not installed.");
                    return;
                }
            }

            var logPath = Path.Combine(run.StagingDirectory, RpcdSetupLog.FileName);
            try
            {
                if (File.Exists(logPath))
                    File.Delete(logPath);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // A previous log may still be there. The tail is masked before it is stored.
            }

            // /AGENTMSI is the in-app path: Setup runs msiexec with no SERVER_URL, ENROLLMENT_KEY, CONSENT, or LIFETIME.
            // Empty MSI properties do not replace the machine id, key, consent, lifetime, or group already in agent.json.
            var arguments = AppUpdateInstaller.BuildSetupArguments(
                verySilent: true,
                agentMsiPath,
                run.RelaunchArguments,
                preserveAgentSettings: true,
                logPath: logPath,
                forceCloseApplications: true);

            Touch(current with
            {
                Stage = RpcdUpdateStages.Installing,
                OldVersion = oldVersion,
                NewVersion = target,
                Detail = updateAgent
                    ? $"Installing RPCD {target} and the agent service. The previous enrollment, consent, and lifetime settings are kept."
                    : $"Installing RPCD {target}. The previous enrollment, consent, and lifetime settings are kept.",
                Percent = 100,
                UpdatedUtc = DateTimeOffset.UtcNow,
            });

            int exit;
            Interlocked.Exchange(ref _localInstaller, 1);
            try
            {
                exit = await run.RunInstaller(
                    new RpcdPreparedInstall(installerPath, arguments, target, oldVersion ?? "") { AgentMsiPath = agentMsiPath },
                    ct).ConfigureAwait(false);
            }
            finally
            {
                Interlocked.Exchange(ref _localInstaller, 0);
            }

            var now = run.ReadInstalledVersion() ?? oldVersion;
            string? agentNow = null;
            if (updateAgent)
            {
                try { agentNow = run.ReadInstalledAgentVersion?.Invoke(); }
                catch (Exception ex) when (ex is not OperationCanceledException) { agentNow = null; }
            }
            var installerLog = RpcdSetupLog.ReadTail(logPath);
            var appOk = exit == 0 && RpcdGitHubRelease.InstalledMatches(now, target, oldVersion);
            var agentOk = !updateAgent || RpcdGitHubRelease.SameBuild(agentNow, target);
            if (appOk && agentOk)
            {
                var detail = updateAgent
                    ? $"RPCD {now} is installed (was {oldVersion ?? "unknown"}). The agent service is {agentNow}. The app is reconnecting."
                    : $"RPCD {now} is installed (was {oldVersion ?? "unknown"}). The app is reconnecting.";
                Set(current with
                {
                    Stage = RpcdUpdateStages.Succeeded,
                    Terminal = true,
                    OldVersion = oldVersion,
                    NewVersion = now,
                    AgentVersion = updateAgent ? AppVersionComparer.Normalize(agentNow) ?? agentNow : null,
                    Detail = detail,
                    Error = null,
                    Percent = 100,
                    UpdatedUtc = DateTimeOffset.UtcNow,
                });
                return;
            }

            var still = now ?? oldVersion ?? "the previous version";
            if (exit != 0)
            {
                Fail(current, oldVersion, InstallerFailed(exit, still), exit, installerLog);
                return;
            }

            if (appOk && updateAgent)
            {
                var error = RpcdGitHubRelease.AgentNotUpdatedError(now, agentNow, target);
                Set(current with
                {
                    Stage = RpcdUpdateStages.AgentNotUpdated,
                    Terminal = true,
                    OldVersion = oldVersion,
                    NewVersion = AppVersionComparer.Normalize(now) ?? now,
                    AgentVersion = string.IsNullOrWhiteSpace(agentNow) ? null : AppVersionComparer.Normalize(agentNow) ?? agentNow,
                    Error = error,
                    Detail = error,
                    InstallerExitCode = exit,
                    InstallerLog = installerLog,
                    Percent = 100,
                    UpdatedUtc = DateTimeOffset.UtcNow,
                });
                return;
            }

            Fail(current, oldVersion, $"The installer finished but Remote PC Diagnostics is still {still}. The previous version is still in place.", exit, installerLog);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            Fail(current, oldVersion, "The update was cancelled before the installer changed Remote PC Diagnostics. The previous version is still in place.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Fail(current, oldVersion, ex.Message);
        }
    }

    private void ReportDownload(RpcdUpdateStatus current, string? oldVersion, string target, AppUpdateProgress progress)
    {
        var stage = progress.Stage == "verifying" ? RpcdUpdateStages.Verifying : RpcdUpdateStages.Downloading;
        Touch(current with
        {
            Stage = stage,
            OldVersion = oldVersion,
            NewVersion = target,
            Detail = progress.Message,
            Percent = progress.Percent,
            UpdatedUtc = DateTimeOffset.UtcNow,
        });
    }

    private static string InstallerFailed(int exit, string still) =>
        $"The installer exited with code {exit} ({InnoSetupExitCodes.Describe(exit)}). Remote PC Diagnostics was not changed and is still {still}.";

    private void Fail(RpcdUpdateStatus current, string? oldVersion, string error, int? installerExitCode = null, string? installerLog = null) =>
        Set(current with
        {
            Stage = RpcdUpdateStages.Failed,
            Terminal = true,
            OldVersion = oldVersion ?? current.OldVersion,
            Error = error,
            Detail = error,
            InstallerExitCode = installerExitCode,
            InstallerLog = installerLog,
            UpdatedUtc = DateTimeOffset.UtcNow,
        });

    private void Touch(RpcdUpdateStatus status) => Set(status);

    private RpcdUpdateStatus Set(RpcdUpdateStatus status)
    {
        lock (_gate)
            _status = status;
        try { _onStatus?.Invoke(status); }
        catch { /* Persistence must not hide the status from the caller. */ }
        return status;
    }

    private void SetNoLock(RpcdUpdateStatus status) => _status = status;

    private RpcdUpdateStatus? PersistCurrent()
    {
        RpcdUpdateStatus? status;
        lock (_gate)
            status = _status;
        if (status is not null)
        {
            try { _onStatus?.Invoke(status); }
            catch { /* Persistence must not hide the status from the caller. */ }
        }
        return status;
    }
}

/// <param name="AgentMsiUrl">The Agent MSI from the same release, when one was published with a trusted checksum.</param>
/// <param name="AgentMsiError">Why that MSI could not be selected. Fatal only when a persistent agent service is installed.</param>
public sealed record RpcdReleaseChoice(
    string Version,
    string Tag,
    string InstallerUrl,
    string Sha256Url,
    string? ReleaseUrl,
    string? FilenameVersion,
    string? AgentMsiUrl = null,
    string? AgentMsiSha256Url = null,
    string? AgentMsiError = null);

public sealed record RpcdReleaseFetch(RpcdReleaseChoice? Choice, string? Error);

/// <summary>Reads one official GitHub release and picks the production Setup exe plus its <c>.sha256</c> asset.</summary>
public static class RpcdGitHubRelease
{
    public const string ApiRoot = "https://api.github.com/repos/budcribar/RemotePCDiagnostics";
    public const string PrereleaseTag = "prerelease";
    public const string AgentMsiPrefix = "RemotePCDiagnostics.Agent-";
    public const string AgentMsiSuffix = "-win-x64.msi";
    public const string AgentMsiArm64Suffix = "-win-arm64.msi";
    public const string AgentMsiMissing = "The release has no Agent MSI (RemotePCDiagnostics.Agent-<version>-win-x64.msi). The update was not installed.";
    public const string AgentMsiChecksumMissing = "The GitHub release has no SHA-256 checksum for the Agent MSI. The update was not installed.";
    private const string SetupPrefix = "RemotePCDiagnostics-Setup-";
    private const string SetupSuffix = "-win-x64.exe";
    private const string SetupArm64Suffix = "-win-arm64.exe";

    public static string? NormalizeChannel(string? channel)
    {
        if (string.IsNullOrWhiteSpace(channel))
            return null;
        if (string.Equals(channel.Trim(), "stable", StringComparison.OrdinalIgnoreCase))
            return "stable";
        if (string.Equals(channel.Trim(), "prerelease", StringComparison.OrdinalIgnoreCase))
            return "prerelease";
        return null;
    }

    public static string CatalogUrl(string channel) =>
        channel == "prerelease"
            ? $"{ApiRoot}/releases/tags/{PrereleaseTag}"
            : $"{ApiRoot}/releases/latest";

    public static string? CleanLabel(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;
        var trimmed = value.Trim();
        if (trimmed.Length > 120)
            trimmed = trimmed[..120];
        return trimmed.Any(char.IsControl) ? null : trimmed;
    }

    public static async Task<RpcdReleaseFetch> FetchAsync(HttpClient http, string channel, string? explicitVersion, CancellationToken ct)
    {
        var catalog = await GetReleaseAsync(http, CatalogUrl(channel), ct).ConfigureAwait(false);
        if (catalog.Error is not null)
            return new RpcdReleaseFetch(null, catalog.Error);
        var current = catalog.Choice!;
        var requested = AppVersionComparer.Normalize(explicitVersion);
        if (requested is null)
            return new RpcdReleaseFetch(current, null);
        if (Matches(current, requested))
            return new RpcdReleaseFetch(current, null);

        var tag = requested.Contains("-ci.", StringComparison.OrdinalIgnoreCase) ? requested : "v" + requested;
        var exact = await GetReleaseAsync(http, $"{ApiRoot}/releases/tags/{Uri.EscapeDataString(tag)}", ct).ConfigureAwait(false);
        if (exact.Choice is not null && Matches(exact.Choice, requested) && ChannelAllows(channel, exact.Choice, tag))
            return new RpcdReleaseFetch(exact.Choice, null);

        return new RpcdReleaseFetch(null,
            $"RPCD {requested} is not the current {channel} release ({current.Version}). Older rolling builds are replaced when a newer one is published.");
    }

    public static bool InstalledMatches(string? installed, string target, string? oldVersion)
    {
        if (SameBuild(installed, target))
            return true;
        if (string.IsNullOrWhiteSpace(installed))
            return false;
        return AppVersionComparer.IsNewer(installed, oldVersion) == true
            && AppVersionComparer.IsNewer(target, installed) != true;
    }

    /// <summary>True when both strings are the same RPCD build, ignoring a leading <c>v</c> and <c>+commit</c> metadata.</summary>
    public static bool SameBuild(string? installed, string? target) =>
        !string.IsNullOrWhiteSpace(installed)
        && !string.IsNullOrWhiteSpace(target)
        && string.Equals(AppVersionComparer.Normalize(installed), AppVersionComparer.Normalize(target), StringComparison.OrdinalIgnoreCase);

    public static string AgentNotUpdatedError(string? appVersion, string? agentVersion, string target)
    {
        var appText = string.IsNullOrWhiteSpace(appVersion) ? "unknown" : appVersion.Trim();
        var agentText = string.IsNullOrWhiteSpace(agentVersion) ? "unknown" : agentVersion.Trim();
        return $"RPCD {appText} is installed, but the agent service is {agentText} instead of {target}.";
    }

    /// <summary>
    /// After this process stopped running Setup: the installed version caught the target, or the install sat unfinished
    /// long enough that the previous build is still the one on disk.
    /// </summary>
    public static RpcdUpdateStatus Reconcile(RpcdUpdateStatus status, string? installedVersion, DateTimeOffset utcNow, TimeSpan giveUp, string? installedAgentVersion = null)
    {
        // The waiting process refreshes its status every WaitHeartbeat. One that stopped doing so ended (an agent restart).
        if (status is { Terminal: false, Stage: RpcdUpdateStages.Waiting } && utcNow - status.UpdatedUtc > RpcdUpdateSession.WaitStale)
        {
            const string error = "The agent restarted while the update was waiting for the PC to be free. Nothing was installed. Ask for the update again.";
            return status with { Stage = RpcdUpdateStages.Failed, Terminal = true, Error = error, Detail = error, UpdatedUtc = utcNow };
        }
        if (status.Terminal || status.Stage is not (RpcdUpdateStages.Installing or RpcdUpdateStages.Relaunching))
            return status;
        if (InstalledMatches(installedVersion, status.NewVersion ?? "", status.OldVersion))
        {
            var target = status.NewVersion ?? "";
            // Setup copies the app before [Run] starts the Agent MSI. While that MSI may still be running, an agent
            // that is not on the target yet is not a success and not yet a failure.
            if (status.UpdateAgent && !SameBuild(installedAgentVersion, target))
            {
                if (utcNow - status.UpdatedUtc <= giveUp)
                    return status;
                var error = AgentNotUpdatedError(installedVersion, installedAgentVersion, target);
                return status with
                {
                    Stage = RpcdUpdateStages.AgentNotUpdated,
                    Terminal = true,
                    NewVersion = AppVersionComparer.Normalize(installedVersion) ?? installedVersion,
                    AgentVersion = string.IsNullOrWhiteSpace(installedAgentVersion)
                        ? null
                        : AppVersionComparer.Normalize(installedAgentVersion) ?? installedAgentVersion,
                    Error = error,
                    Detail = error,
                    UpdatedUtc = utcNow,
                };
            }
            var agentNow = status.UpdateAgent
                ? AppVersionComparer.Normalize(installedAgentVersion) ?? installedAgentVersion
                : status.AgentVersion;
            var detail = status.UpdateAgent
                ? $"RPCD {installedVersion} is installed (was {status.OldVersion ?? "unknown"}). The agent service is {agentNow}. The app is reconnecting."
                : $"RPCD {installedVersion} is installed (was {status.OldVersion ?? "unknown"}). The app is reconnecting.";
            return status with
            {
                Stage = RpcdUpdateStages.Succeeded,
                Terminal = true,
                NewVersion = AppVersionComparer.Normalize(installedVersion) ?? installedVersion,
                AgentVersion = agentNow,
                Error = null,
                Detail = detail,
                UpdatedUtc = utcNow,
            };
        }
        if (utcNow - status.UpdatedUtc > giveUp)
        {
            var still = installedVersion ?? status.OldVersion ?? "the previous version";
            var error = $"The installer did not finish. Remote PC Diagnostics is still {still}.";
            return status with
            {
                Stage = RpcdUpdateStages.Failed,
                Terminal = true,
                Error = error,
                Detail = error,
                UpdatedUtc = utcNow,
            };
        }
        return status;
    }

    public static string? ParseBuildVersion(string? notes)
    {
        if (string.IsNullOrEmpty(notes))
            return null;
        const string marker = "Build version:";
        var i = notes.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (i < 0)
            return null;
        var rest = notes[(i + marker.Length)..].TrimStart();
        if (rest.StartsWith('`'))
            rest = rest[1..];
        var end = rest.IndexOfAny(['`', '\r', '\n', ' ', '\t']);
        var token = end < 0 ? rest : rest[..end];
        return AppVersionComparer.Normalize(token);
    }

    public static RpcdReleaseFetch Parse(string json, string? fallbackTag) =>
        Parse(json, fallbackTag, RuntimeInformation.OSArchitecture);

    public static RpcdReleaseFetch Parse(string json, string? fallbackTag, Architecture targetArch)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return new RpcdReleaseFetch(null, "The GitHub release was not a JSON object.");
            if (root.TryGetProperty("message", out var message) && root.TryGetProperty("documentation_url", out _))
            {
                return new RpcdReleaseFetch(null, "GitHub did not return that release.");
            }

            var tag = root.TryGetProperty("tag_name", out var tagEl) ? tagEl.GetString() : fallbackTag;
            var notes = root.TryGetProperty("body", out var bodyEl) ? bodyEl.GetString() : null;
            var releaseUrl = root.TryGetProperty("html_url", out var html) ? html.GetString() : null;
            if (!root.TryGetProperty("assets", out var assets) || assets.ValueKind != JsonValueKind.Array)
                return new RpcdReleaseFetch(null, "The GitHub release did not list any files.");

            string? x64ExeUrl = null;
            string? x64ExeName = null;
            string? arm64ExeUrl = null;
            string? arm64ExeName = null;
            var shaByName = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var x64AgentMsi = new List<(string Name, string Url)>();
            var arm64AgentMsi = new List<(string Name, string Url)>();
            foreach (var asset in assets.EnumerateArray())
            {
                var name = asset.TryGetProperty("name", out var nameEl) ? nameEl.GetString() : null;
                var url = asset.TryGetProperty("browser_download_url", out var urlEl) ? urlEl.GetString() : null;
                if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(url))
                    continue;
                if (name.Contains("TestShop", StringComparison.OrdinalIgnoreCase))
                    continue;
                if (name.EndsWith(".sha256", StringComparison.OrdinalIgnoreCase))
                {
                    shaByName[name] = url;
                    continue;
                }
                if (name.StartsWith(SetupPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    if (arm64ExeUrl is null && name.EndsWith(SetupArm64Suffix, StringComparison.OrdinalIgnoreCase))
                    {
                        arm64ExeName = name;
                        arm64ExeUrl = url;
                    }
                    else if (x64ExeUrl is null && name.EndsWith(SetupSuffix, StringComparison.OrdinalIgnoreCase))
                    {
                        x64ExeName = name;
                        x64ExeUrl = url;
                    }
                }
                if (name.StartsWith(AgentMsiPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    if (name.EndsWith(AgentMsiArm64Suffix, StringComparison.OrdinalIgnoreCase))
                        arm64AgentMsi.Add((name, url));
                    else if (name.EndsWith(AgentMsiSuffix, StringComparison.OrdinalIgnoreCase))
                        x64AgentMsi.Add((name, url));
                }
            }

            var preferArm64 = targetArch == Architecture.Arm64;
            var exeUrl = (preferArm64 && arm64ExeUrl is not null) ? arm64ExeUrl : x64ExeUrl;
            var exeName = (preferArm64 && arm64ExeUrl is not null) ? arm64ExeName : x64ExeName;
            var agentMsi = (preferArm64 && arm64AgentMsi.Count > 0) ? arm64AgentMsi : x64AgentMsi;

            if (exeUrl is null || exeName is null)
                return new RpcdReleaseFetch(null, "The release has no production installer. TestShop bundles are not installed by an update.");
            if (!AppVersionComparer.IsTrustedDownloadUrl(exeUrl))
                return new RpcdReleaseFetch(null, "Refusing to download the installer from a URL that is not the official GitHub release.");
            var shaName = exeName + ".sha256";
            if (!shaByName.TryGetValue(shaName, out var shaUrl) || !AppVersionComparer.IsTrustedDownloadUrl(shaUrl))
                return new RpcdReleaseFetch(null, AppUpdateInstaller.MissingChecksumMessage);

            var filenameVersion = FilenameVersion(exeName);
            var version = ParseBuildVersion(notes) ?? filenameVersion ?? AppVersionComparer.Normalize(tag);
            if (version is null)
                return new RpcdReleaseFetch(null, "The GitHub release did not name an RPCD version.");

            var (msiUrl, msiSha, msiError) = ChooseAgentMsi(agentMsi, shaByName, version, filenameVersion);
            return new RpcdReleaseFetch(new RpcdReleaseChoice(version, tag ?? "", exeUrl, shaUrl, releaseUrl, filenameVersion, msiUrl, msiSha, msiError), null);
        }
        catch (JsonException)
        {
            return new RpcdReleaseFetch(null, "The GitHub release could not be read.");
        }
    }

    private static bool Matches(RpcdReleaseChoice choice, string requested) =>
        string.Equals(AppVersionComparer.Normalize(choice.Version), requested, StringComparison.OrdinalIgnoreCase)
        || string.Equals(AppVersionComparer.Normalize(choice.FilenameVersion), requested, StringComparison.OrdinalIgnoreCase);

    private static bool ChannelAllows(string channel, RpcdReleaseChoice choice, string tag)
    {
        if (channel == "prerelease")
            return choice.Version.Contains("-ci.", StringComparison.OrdinalIgnoreCase)
                || string.Equals(tag, PrereleaseTag, StringComparison.OrdinalIgnoreCase)
                || string.Equals(choice.Tag, PrereleaseTag, StringComparison.OrdinalIgnoreCase);
        return !choice.Version.Contains("-ci.", StringComparison.OrdinalIgnoreCase)
            || tag.StartsWith('v') || tag.StartsWith('V');
    }

    /// <summary>
    /// The Agent MSI published next to Setup. A release names the file with the base version
    /// (<c>RemotePCDiagnostics.Agent-1.2.0-win-x64.msi</c>) while the notes name the CI build, so a single trusted
    /// MSI is that release's package. Several MSIs have to match the build version or the Setup file name.
    /// </summary>
    public static (string? Url, string? Sha256Url, string? Error) ChooseAgentMsi(
        IReadOnlyList<(string Name, string Url)> candidates,
        IReadOnlyDictionary<string, string> shaByName,
        string version,
        string? setupFilenameVersion)
    {
        if (candidates.Count == 0)
            return (null, null, AgentMsiMissing);

        var trusted = new List<(string Url, string Sha, string? FileVersion)>();
        var sawUntrusted = false;
        var sawMissingSha = false;
        foreach (var (name, url) in candidates)
        {
            if (!AppVersionComparer.IsTrustedDownloadUrl(url))
            {
                sawUntrusted = true;
                continue;
            }
            if (!shaByName.TryGetValue(name + ".sha256", out var sha) || !AppVersionComparer.IsTrustedDownloadUrl(sha))
            {
                sawMissingSha = true;
                continue;
            }
            trusted.Add((url, sha, AgentMsiFileVersion(name)));
        }

        if (trusted.Count == 0)
        {
            if (sawMissingSha)
                return (null, null, AgentMsiChecksumMissing);
            if (sawUntrusted)
                return (null, null, "Refusing to download the Agent MSI from a URL that is not the official GitHub release.");
            return (null, null, AgentMsiMissing);
        }

        var target = AppVersionComparer.Normalize(version);
        var setupVersion = AppVersionComparer.Normalize(setupFilenameVersion);
        (string Url, string Sha, string? FileVersion)? pick = null;
        foreach (var item in trusted)
        {
            if (item.FileVersion is not null && string.Equals(item.FileVersion, target, StringComparison.OrdinalIgnoreCase))
            {
                pick = item;
                break;
            }
        }
        if (pick is null && setupVersion is not null)
        {
            foreach (var item in trusted)
            {
                if (string.Equals(item.FileVersion, setupVersion, StringComparison.OrdinalIgnoreCase))
                {
                    pick = item;
                    break;
                }
            }
        }
        if (pick is null && trusted.Count == 1)
            pick = trusted[0];
        if (pick is null)
            return (null, null, $"The release lists more than one Agent MSI and none matches {version}. The update was not installed.");
        return (pick.Value.Url, pick.Value.Sha, null);
    }

    public static string? AgentMsiFileVersion(string name)
    {
        if (!name.StartsWith(AgentMsiPrefix, StringComparison.OrdinalIgnoreCase))
            return null;
        if (name.EndsWith(AgentMsiArm64Suffix, StringComparison.OrdinalIgnoreCase))
            return AppVersionComparer.Normalize(name[AgentMsiPrefix.Length..^AgentMsiArm64Suffix.Length]);
        if (name.EndsWith(AgentMsiSuffix, StringComparison.OrdinalIgnoreCase))
            return AppVersionComparer.Normalize(name[AgentMsiPrefix.Length..^AgentMsiSuffix.Length]);
        return null;
    }

    private static string? FilenameVersion(string exeName)
    {
        if (!exeName.StartsWith(SetupPrefix, StringComparison.OrdinalIgnoreCase))
            return null;
        if (exeName.EndsWith(SetupArm64Suffix, StringComparison.OrdinalIgnoreCase))
            return AppVersionComparer.Normalize(exeName[SetupPrefix.Length..^SetupArm64Suffix.Length]);
        if (exeName.EndsWith(SetupSuffix, StringComparison.OrdinalIgnoreCase))
            return AppVersionComparer.Normalize(exeName[SetupPrefix.Length..^SetupSuffix.Length]);
        return null;
    }

    private static async Task<RpcdReleaseFetch> GetReleaseAsync(HttpClient http, string url, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.TryAddWithoutValidation("User-Agent", "RemotePCDiagnostics-Agent");
        req.Headers.TryAddWithoutValidation("Accept", "application/vnd.github+json");
        HttpResponseMessage response;
        try
        {
            response = await http.SendAsync(req, ct).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            return new RpcdReleaseFetch(null, "Could not reach the official GitHub release. " + ex.Message);
        }

        using (response)
        {
            if (response.StatusCode == HttpStatusCode.NotFound)
                return new RpcdReleaseFetch(null, "GitHub did not return that release.");
            var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
                return new RpcdReleaseFetch(null, $"Could not read the official GitHub release ({(int)response.StatusCode}).");
            if (body.Length > 2 * 1024 * 1024)
                return new RpcdReleaseFetch(null, "The GitHub release description was larger than expected.");
            return Parse(body, fallbackTag: null);
        }
    }
}

/// <summary>
/// The update result written by a process that outlives the agent that launched Setup.
/// Setup stops that agent, so the <c>installing</c> line it already reported is otherwise the last word.
/// </summary>
public static class RpcdUpdateSeal
{
    public const string FileName = "rpcd-update-status.json";

    /// <summary>Tail of the failure stored when the new files are on disk and the service is not running.</summary>
    public const string ServiceNotRunning = "is installed, but the Remote PC Diagnostics Agent service is not running.";

    /// <summary>
    /// Turns <c>installing</c> into a terminal stage once the target version is on disk.
    /// <paramref name="serviceRunning"/> false means the files are updated and the service is not, which is still terminal:
    /// the relay stops polling only when <see cref="RpcdUpdateStatus.Terminal"/> is set.
    /// A later call with the service running promotes that specific failure to success.
    /// </summary>
    public static RpcdUpdateStatus Seal(RpcdUpdateStatus status, string? installedVersion, bool serviceRunning, DateTimeOffset utcNow, string? installedAgentVersion = null)
    {
        if (status.Terminal)
            return PromoteIfServiceStarted(status, installedVersion, serviceRunning, utcNow);
        var done = RpcdGitHubRelease.Reconcile(status, installedVersion, utcNow, RpcdUpdateSession.InstallGiveUp, installedAgentVersion);
        if (done.Stage != RpcdUpdateStages.Succeeded || serviceRunning)
            return done;
        var error = $"RPCD {done.NewVersion} {ServiceNotRunning}";
        return done with
        {
            Stage = RpcdUpdateStages.Failed,
            Terminal = true,
            Error = error,
            Detail = error,
        };
    }

    private static RpcdUpdateStatus PromoteIfServiceStarted(RpcdUpdateStatus status, string? installedVersion, bool serviceRunning, DateTimeOffset utcNow)
    {
        if (!serviceRunning
            || status.Stage != RpcdUpdateStages.Failed
            || status.Error is null
            || !status.Error.Contains(ServiceNotRunning, StringComparison.Ordinal)
            || !RpcdGitHubRelease.InstalledMatches(installedVersion, status.NewVersion ?? "", status.OldVersion))
            return status;
        var version = AppVersionComparer.Normalize(installedVersion) ?? installedVersion;
        return status with
        {
            Stage = RpcdUpdateStages.Succeeded,
            Terminal = true,
            NewVersion = version,
            Error = null,
            Detail = $"RPCD {version} is installed (was {status.OldVersion ?? "unknown"}). The app is reconnecting.",
            UpdatedUtc = utcNow,
        };
    }

    /// <summary>
    /// Finishes an <c>installing</c> status from the exit code Setup's wrapper script wrote, for when the agent that started
    /// Setup is gone. In the elevated helper that is expected: Setup closes the app, and the helper is in the app's kill-on-close
    /// job. A zero exit, or a version that now matches, is left to <see cref="Seal"/> and <c>Agent.exe install</c>.
    /// </summary>
    public static RpcdUpdateStatus ApplySetupExit(RpcdUpdateStatus status, int? exitCode, string? installedVersion, string? installerLog, DateTimeOffset utcNow)
    {
        if (exitCode is not int exit || exit == 0
            || status.Terminal
            || status.Stage is not (RpcdUpdateStages.Installing or RpcdUpdateStages.Relaunching)
            || RpcdGitHubRelease.InstalledMatches(installedVersion, status.NewVersion ?? "", status.OldVersion))
            return status;
        var still = installedVersion ?? status.OldVersion ?? "the previous version";
        var error = $"The installer exited with code {exit} ({InnoSetupExitCodes.Describe(exit)}). Remote PC Diagnostics was not changed and is still {still}.";
        return status with
        {
            Stage = RpcdUpdateStages.Failed,
            Terminal = true,
            Error = error,
            Detail = error,
            InstallerExitCode = exit,
            InstallerLog = installerLog ?? status.InstallerLog,
            UpdatedUtc = utcNow,
        };
    }

    /// <summary>
    /// Setup exited 0 and the app matches, but the agent service that was installed is not the target build.
    /// That is terminal immediately. Reconcile still waits while Setup may be inside the MSI step and no exit code has been written.
    /// </summary>
    public static RpcdUpdateStatus ApplyZeroExitAgentCheck(RpcdUpdateStatus status, int? exitCode, string? installedApp, string? installedAgent, DateTimeOffset utcNow)
    {
        var target = status.NewVersion ?? "";
        if (exitCode is not 0
            || status.Terminal
            || !status.UpdateAgent
            || status.Stage is not (RpcdUpdateStages.Installing or RpcdUpdateStages.Relaunching)
            || !RpcdGitHubRelease.InstalledMatches(installedApp, target, status.OldVersion)
            || RpcdGitHubRelease.SameBuild(installedAgent, target))
            return status;
        var error = RpcdGitHubRelease.AgentNotUpdatedError(installedApp, installedAgent, target);
        return status with
        {
            Stage = RpcdUpdateStages.AgentNotUpdated,
            Terminal = true,
            NewVersion = AppVersionComparer.Normalize(installedApp) ?? installedApp,
            AgentVersion = string.IsNullOrWhiteSpace(installedAgent) ? null : AppVersionComparer.Normalize(installedAgent) ?? installedAgent,
            Error = error,
            Detail = error,
            InstallerExitCode = 0,
            UpdatedUtc = utcNow,
        };
    }

    /// <summary>
    /// A later write from the agent that launched Setup must not replace a success already recorded by install.
    /// That agent is stopped while Setup is still running and can wake up just long enough to store a failure.
    /// </summary>
    public static bool KeepSealedSuccess(RpcdUpdateStatus onDisk, RpcdUpdateStatus incoming) =>
        onDisk.Terminal
        && onDisk.Stage == RpcdUpdateStages.Succeeded
        && string.Equals(onDisk.RequestId, incoming.RequestId, StringComparison.Ordinal)
        && incoming.Stage != RpcdUpdateStages.Succeeded;
}

/// <summary>Product version of an installed executable, without <c>+commit</c> metadata. Null when the file is missing.</summary>
public static class RpcdProductVersion
{
    public static string? ReadFile(string? path)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                return null;
            var info = FileVersionInfo.GetVersionInfo(path);
            var version = string.IsNullOrWhiteSpace(info.ProductVersion) ? info.FileVersion : info.ProductVersion;
            if (string.IsNullOrWhiteSpace(version))
                return null;
            var plus = version.IndexOf('+');
            return (plus > 0 ? version[..plus] : version).Trim();
        }
        catch (Exception)
        {
            return null;
        }
    }
}
