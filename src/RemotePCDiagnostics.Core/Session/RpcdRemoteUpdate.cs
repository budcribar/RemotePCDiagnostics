using System.Net;
using System.Text.Json;

namespace RemotePCDiagnostics.Core.Session;

/// <summary>Stages a caller can poll while <c>update_rpcd</c> runs. Terminal stages are the last word.</summary>
public static class RpcdUpdateStages
{
    public const string Idle = "idle";
    public const string Checking = "checking";
    public const string Refused = "refused";
    public const string AlreadyUpToDate = "already_up_to_date";
    public const string Downloading = "downloading";
    public const string Verifying = "verifying";
    public const string Installing = "installing";
    public const string Relaunching = "relaunching";
    public const string Succeeded = "succeeded";
    public const string Failed = "failed";

    public static bool IsTerminal(string? stage) => stage is Refused or AlreadyUpToDate or Succeeded or Failed;
}

/// <summary>
/// One remote update. <see cref="BusyReason"/> null means the caller did not say (the agent uses the app's last activity report);
/// empty means the app confirmed nothing is running; any other text refuses the update.
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

/// <summary>
/// The app's last "what is running" report, saved so the agent service sees it when the app reported to its own elevated helper.
/// A null <see cref="BusyReason"/> means idle.
/// </summary>
public sealed record RpcdActivityReport(string? BusyReason, DateTimeOffset At)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public string ToJson() => JsonSerializer.Serialize(this, Json);

    public static RpcdActivityReport? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return null;
        try
        {
            return JsonSerializer.Deserialize<RpcdActivityReport>(json, Json);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>Writes the report the agent reads. Returns the IO error, or null when the file is in place.</summary>
    public static string? TryWrite(string path, string? busyReason, DateTimeOffset at)
    {
        try
        {
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);
            var temp = path + "." + Environment.ProcessId.ToString() + ".tmp";
            var reason = string.IsNullOrWhiteSpace(busyReason) ? null : busyReason.Trim();
            File.WriteAllText(temp, new RpcdActivityReport(reason, at).ToJson());
            File.Move(temp, path, overwrite: true);
            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return ex.Message;
        }
    }
}

/// <summary>The verified installer the agent is allowed to start. No other file is installed.</summary>
public sealed record RpcdPreparedInstall(string InstallerPath, string Arguments, string TargetVersion, string OldVersion);

/// <summary>What the agent needs around the pure update steps: clock, versions, and a way to run Setup.</summary>
public sealed class RpcdUpdateRun
{
    public required HttpClient Http { get; init; }
    public required string InstalledVersion { get; init; }
    public required Func<string?> ReadInstalledVersion { get; init; }
    public required string StagingDirectory { get; init; }
    public IReadOnlyList<string>? RelaunchArguments { get; init; }
    public required Func<RpcdPreparedInstall, CancellationToken, Task<int>> RunInstaller { get; init; }
    public DateTimeOffset UtcNow { get; init; } = DateTimeOffset.UtcNow;
}

/// <summary>
/// Shop-owner update of the installed RPCD build from the official GitHub release.
/// Refuses without approval, while diagnostics work is running, or when the PC is already on that build.
/// The installer is downloaded only from GitHub and only after its SHA-256 matches. A failed check leaves the
/// installed build untouched. Inno Setup rolls back a failed copy; a non-zero exit is reported with the old version.
/// </summary>
public sealed class RpcdUpdateSession
{
    /// <summary>How long an <c>installing</c> status may sit unchanged, after this process is no longer running Setup, before it is a failure.</summary>
    public static readonly TimeSpan InstallGiveUp = TimeSpan.FromMinutes(20);

    public const string ApprovalRequired = "Shop owner approval is required before Remote PC Diagnostics can be updated on this PC.";
    public const string ActivityUnconfirmed = "A diagnostics session is open, but this agent could not confirm that no check, fix, workflow, or stress test is running. Wait a moment and try again.";

    /// <summary>How recent an activity report must be before a hub update trusts it.</summary>
    public static readonly TimeSpan ActivityFreshFor = TimeSpan.FromSeconds(90);

    public const string ProbeNoReport = "Probe: no activity report has arrived from the app (admin pipe and session activity file).";

    private readonly object _gate = new();
    private readonly Action<RpcdUpdateStatus>? _onStatus;
    private RpcdUpdateStatus? _status;
    private string? _activityReason;
    private DateTimeOffset? _activityAt;
    private int _localInstaller;
    private readonly int _ownerPid;

    public RpcdUpdateSession(Action<RpcdUpdateStatus>? onStatus = null, int? ownerPid = null)
    {
        _onStatus = onStatus;
        _ownerPid = ownerPid ?? Environment.ProcessId;
    }

    /// <summary>Records the app's report. A report older than the one already held (another process's copy) is ignored.</summary>
    public void ReportActivity(string? busyReason, DateTimeOffset utcNow)
    {
        lock (_gate)
        {
            if (_activityAt is { } held && utcNow < held)
                return;
            _activityReason = string.IsNullOrWhiteSpace(busyReason) ? null : busyReason.Trim();
            _activityAt = utcNow;
        }
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

    /// <summary>Null when the app confirmed it is idle recently. A missing report while the app is open refuses the update.</summary>
    public string? ActivityBlock(bool hostRunning, DateTimeOffset utcNow)
    {
        if (!hostRunning || ActivityDiagnosis(utcNow) is null)
        {
            if (!hostRunning)
                return null;
            lock (_gate)
                return _activityReason;
        }
        return ActivityUnconfirmed;
    }

    /// <summary>
    /// Why the cached report cannot be trusted, or null when it is fresh. The page's activity-data is a different path;
    /// this is only the report the app wrote for the agent.
    /// </summary>
    public string? ActivityDiagnosis(DateTimeOffset utcNow)
    {
        lock (_gate)
        {
            if (_activityAt is not { } at)
                return ProbeNoReport;
            var age = utcNow - at;
            if (age > ActivityFreshFor)
                return $"Probe: the last activity report is {(int)age.TotalSeconds} seconds old, past the {(int)ActivityFreshFor.TotalSeconds} second limit.";
            if (at > utcNow.AddSeconds(5))
                return $"Probe: the activity report is timestamped {(int)(at - utcNow).TotalSeconds} seconds ahead of this agent.";
            return null;
        }
    }

    private static string? JoinProbe(string? diagnosis, string? extra)
    {
        if (string.IsNullOrWhiteSpace(extra))
            return string.IsNullOrWhiteSpace(diagnosis) ? null : diagnosis.Trim();
        if (string.IsNullOrWhiteSpace(diagnosis) || extra.Contains(diagnosis.Trim(), StringComparison.Ordinal))
            return extra.Trim();
        if (diagnosis.Contains(extra.Trim(), StringComparison.Ordinal))
            return diagnosis.Trim();
        return diagnosis.Trim() + " " + extra.Trim();
    }

    public void Restore(RpcdUpdateStatus? status)
    {
        lock (_gate)
            _status = status;
    }

    public RpcdUpdateStatus? Current(string? requestId, string? installedVersion, DateTimeOffset utcNow)
    {
        RpcdUpdateStatus? status;
        lock (_gate)
        {
            if (_status is null)
                return null;
            if (Volatile.Read(ref _localInstaller) == 0)
                _status = RpcdGitHubRelease.Reconcile(_status, installedVersion, utcNow, InstallGiveUp);
            status = _status;
        }
        if (!string.IsNullOrEmpty(requestId)
            && !string.Equals(status.RequestId, requestId, StringComparison.Ordinal))
            return null;
        return status;
    }

    /// <summary>
    /// Accepts or refuses. When it returns true the caller must run <see cref="ExecuteAsync"/> (the work continues if this process dies
    /// only through the status file the caller persisted). <paramref name="trustCallerBusyReason"/> is for the app's own pipe request,
    /// which carries the live snapshot; a hub command must not be able to claim the PC is idle.
    /// </summary>
    public bool TryBegin(RpcdUpdateRequest request, bool hostRunning, bool trustCallerBusyReason, DateTimeOffset utcNow, out RpcdUpdateStatus status) =>
        TryBegin(request, hostRunning, trustCallerBusyReason, utcNow, null, out status);

    /// <param name="activityProblem">Why the activity probe failed. Appended to the refusal detail. Null when the caller has no extra fact.</param>
    public bool TryBegin(RpcdUpdateRequest request, bool hostRunning, bool trustCallerBusyReason, DateTimeOffset utcNow, string? activityProblem, out RpcdUpdateStatus status)
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
            if (_status is { Terminal: false } && utcNow - _status.UpdatedUtc < InstallGiveUp)
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

            string? busy;
            string? detail = null;
            if (trustCallerBusyReason)
                busy = string.IsNullOrWhiteSpace(request.BusyReason) ? null : request.BusyReason.Trim();
            else
            {
                busy = ActivityBlock(hostRunning, utcNow);
                if (busy == ActivityUnconfirmed)
                    detail = JoinProbe(ActivityDiagnosis(utcNow), activityProblem);
            }
            if (busy is not null)
            {
                status = Refused(busy, persist: true, detail);
                return false;
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
            if (!string.IsNullOrWhiteSpace(oldVersion))
            {
                var newer = AppVersionComparer.IsNewer(target, oldVersion);
                var same = string.Equals(AppVersionComparer.Normalize(target), AppVersionComparer.Normalize(oldVersion), StringComparison.OrdinalIgnoreCase);
                if (newer is null && !same)
                {
                    Fail(current, oldVersion, $"Cannot tell whether {target} is newer than {oldVersion}. The update was not installed.");
                    return;
                }
                if (newer != true)
                {
                    var error = same
                        ? $"RPCD {oldVersion} is already up to date on the {channel} channel ({target})."
                        : $"RPCD {oldVersion} is newer than the published {target}.";
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

            Touch(current with
            {
                Stage = RpcdUpdateStages.Downloading,
                OldVersion = oldVersion,
                NewVersion = target,
                Detail = $"Downloading RPCD {target} from GitHub...",
                Percent = 0,
                UpdatedUtc = DateTimeOffset.UtcNow,
            });

            var installerPath = await AppUpdateInstaller.DownloadAndVerifyAsync(
                run.Http,
                release.Choice.InstallerUrl,
                release.Choice.Sha256Url,
                run.StagingDirectory,
                progress =>
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
                },
                ct,
                requireChecksum: true).ConfigureAwait(false);

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

            var arguments = AppUpdateInstaller.BuildSetupArguments(
                verySilent: true,
                agentMsiPath: null,
                run.RelaunchArguments,
                preserveAgentSettings: true,
                logPath: logPath,
                forceCloseApplications: true);

            Touch(current with
            {
                Stage = RpcdUpdateStages.Installing,
                OldVersion = oldVersion,
                NewVersion = target,
                Detail = $"Installing RPCD {target}. The previous enrollment, consent, and lifetime settings are kept.",
                Percent = 100,
                UpdatedUtc = DateTimeOffset.UtcNow,
            });

            int exit;
            Interlocked.Exchange(ref _localInstaller, 1);
            try
            {
                exit = await run.RunInstaller(
                    new RpcdPreparedInstall(installerPath, arguments, target, oldVersion ?? ""),
                    ct).ConfigureAwait(false);
            }
            finally
            {
                Interlocked.Exchange(ref _localInstaller, 0);
            }

            var now = run.ReadInstalledVersion() ?? oldVersion;
            var installerLog = RpcdSetupLog.ReadTail(logPath);
            if (exit == 0 && RpcdGitHubRelease.InstalledMatches(now, target, oldVersion))
            {
                Set(current with
                {
                    Stage = RpcdUpdateStages.Succeeded,
                    Terminal = true,
                    OldVersion = oldVersion,
                    NewVersion = now,
                    Detail = $"RPCD {now} is installed (was {oldVersion ?? "unknown"}). The app is reconnecting.",
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
}

public sealed record RpcdReleaseChoice(string Version, string Tag, string InstallerUrl, string Sha256Url, string? ReleaseUrl, string? FilenameVersion);

public sealed record RpcdReleaseFetch(RpcdReleaseChoice? Choice, string? Error);

/// <summary>Reads one official GitHub release and picks the production Setup exe plus its <c>.sha256</c> asset.</summary>
public static class RpcdGitHubRelease
{
    public const string ApiRoot = "https://api.github.com/repos/budcribar/RemotePCDiagnostics";
    public const string PrereleaseTag = "prerelease";
    private const string SetupPrefix = "RemotePCDiagnostics-Setup-";
    private const string SetupSuffix = "-win-x64.exe";

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
        if (string.IsNullOrWhiteSpace(installed))
            return false;
        if (string.Equals(AppVersionComparer.Normalize(installed), AppVersionComparer.Normalize(target), StringComparison.OrdinalIgnoreCase))
            return true;
        return AppVersionComparer.IsNewer(installed, oldVersion) == true
            && AppVersionComparer.IsNewer(target, installed) != true;
    }

    /// <summary>
    /// After this process stopped running Setup: the installed version caught the target, or the install sat unfinished
    /// long enough that the previous build is still the one on disk.
    /// </summary>
    public static RpcdUpdateStatus Reconcile(RpcdUpdateStatus status, string? installedVersion, DateTimeOffset utcNow, TimeSpan giveUp)
    {
        if (status.Terminal || status.Stage is not (RpcdUpdateStages.Installing or RpcdUpdateStages.Relaunching))
            return status;
        if (InstalledMatches(installedVersion, status.NewVersion ?? "", status.OldVersion))
        {
            return status with
            {
                Stage = RpcdUpdateStages.Succeeded,
                Terminal = true,
                NewVersion = AppVersionComparer.Normalize(installedVersion) ?? installedVersion,
                Error = null,
                Detail = $"RPCD {installedVersion} is installed (was {status.OldVersion ?? "unknown"}). The app is reconnecting.",
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

    public static RpcdReleaseFetch Parse(string json, string? fallbackTag)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return new RpcdReleaseFetch(null, "The GitHub release was not a JSON object.");
            if (root.TryGetProperty("message", out var message) && root.TryGetProperty("documentation_url", out _))
            {
                var text = message.GetString();
                return new RpcdReleaseFetch(null, string.IsNullOrWhiteSpace(text)
                    ? "GitHub did not return that release."
                    : "GitHub did not return that release.");
            }

            var tag = root.TryGetProperty("tag_name", out var tagEl) ? tagEl.GetString() : fallbackTag;
            var notes = root.TryGetProperty("body", out var bodyEl) ? bodyEl.GetString() : null;
            var releaseUrl = root.TryGetProperty("html_url", out var html) ? html.GetString() : null;
            if (!root.TryGetProperty("assets", out var assets) || assets.ValueKind != JsonValueKind.Array)
                return new RpcdReleaseFetch(null, "The GitHub release did not list any files.");

            string? exeUrl = null;
            string? exeName = null;
            var shaByName = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
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
                if (exeUrl is null
                    && name.StartsWith(SetupPrefix, StringComparison.OrdinalIgnoreCase)
                    && name.EndsWith(SetupSuffix, StringComparison.OrdinalIgnoreCase))
                {
                    exeName = name;
                    exeUrl = url;
                }
            }

            if (exeUrl is null || exeName is null)
                return new RpcdReleaseFetch(null, "The release has no production installer. TestShop bundles are not installed by an update.");
            if (!AppVersionComparer.IsTrustedDownloadUrl(exeUrl))
                return new RpcdReleaseFetch(null, "Refusing to download the installer from a URL that is not the official GitHub release.");
            var shaName = exeName + ".sha256";
            if (!shaByName.TryGetValue(shaName, out var shaUrl) || !AppVersionComparer.IsTrustedDownloadUrl(shaUrl))
                return new RpcdReleaseFetch(null, "The GitHub release has no SHA-256 checksum for the installer. The update was not installed.");

            var filenameVersion = FilenameVersion(exeName);
            var version = ParseBuildVersion(notes) ?? filenameVersion ?? AppVersionComparer.Normalize(tag);
            if (version is null)
                return new RpcdReleaseFetch(null, "The GitHub release did not name an RPCD version.");

            return new RpcdReleaseFetch(new RpcdReleaseChoice(version, tag ?? "", exeUrl, shaUrl, releaseUrl, filenameVersion), null);
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

    private static string? FilenameVersion(string exeName)
    {
        if (!exeName.StartsWith(SetupPrefix, StringComparison.OrdinalIgnoreCase)
            || !exeName.EndsWith(SetupSuffix, StringComparison.OrdinalIgnoreCase))
            return null;
        var version = exeName[SetupPrefix.Length..^SetupSuffix.Length];
        return AppVersionComparer.Normalize(version);
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
