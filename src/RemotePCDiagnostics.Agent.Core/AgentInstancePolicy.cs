namespace RemotePCDiagnostics.Agent.Core;

/// <summary>
/// One running agent per PC. The Windows service, <c>run</c>, and a dev copy all take <see cref="MutexName"/>.
/// A second process logs who holds it and exits <see cref="ExitAlreadyRunning"/> (0). The service is installed with
/// restart-on-failure, and a non-zero exit is a failure the Service Control Manager would restart.
/// </summary>
public static class AgentInstancePolicy
{
    /// <summary>Global so session 0 (the service) and an interactive or dev process see the same mutex.</summary>
    public const string MutexName = @"Global\RemotePCDiagnostics.Agent";

    /// <summary>Same-session fallback when this process is not allowed to create a Global mutex.</summary>
    public const string SessionMutexName = @"Local\RemotePCDiagnostics.Agent";

    /// <summary>Clean exit. Must stay 0 so the service recovery actions do not run.</summary>
    public const int ExitAlreadyRunning = 0;

    /// <summary>
    /// How long a new process waits when the mutex is taken. The holder is often the previous service, already
    /// exiting: <c>TerminateProcess</c> and a service stop both leave the mutex owned for a moment, and the pid can
    /// still look alive. Exiting 0 in that window stops the new service cleanly, and recovery does not restart a clean exit.
    /// </summary>
    public static readonly TimeSpan DyingHolderWait = TimeSpan.FromSeconds(8);

    /// <summary>
    /// Leftover agent processes are ended without their children. Setup can be a child of the agent that started
    /// the update; a tree kill would end Setup before it starts the new service.
    /// </summary>
    public const bool KillEntireProcessTree = false;

    public const string LogPrefix = "[agent-instance]";

    /// <summary>
    /// <see cref="AgentLayout.ServiceName"/> is stopped and then started again. Any other service whose image path points at
    /// <see cref="AgentLayout.AgentExeName"/> is removed so an upgrade cannot leave a second registration running beside it.
    /// </summary>
    public static bool IsCurrentService(string? name) =>
        string.Equals(name?.Trim(), AgentLayout.ServiceName, StringComparison.OrdinalIgnoreCase);

    public static bool ImagePathLaunchesAgent(string? imagePath)
    {
        if (string.IsNullOrWhiteSpace(imagePath)) return false;
        return imagePath.Contains(AgentLayout.AgentExeName, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The executable path inside an SCM ImagePath. A path with spaces is quoted
    /// (<c>"C:\Program Files\...\RemotePCDiagnostics.Agent.exe" run</c>). An unquoted path is kept through the
    /// agent executable name so <c>C:\Program Files\...</c> is not cut at the first space.
    /// </summary>
    public static string? ExePathFromImage(string? imagePath)
    {
        if (string.IsNullOrWhiteSpace(imagePath)) return null;
        var text = imagePath.Trim();
        if (text.StartsWith('"'))
        {
            var end = text.IndexOf('"', 1);
            return end > 1 ? text[1..end] : null;
        }
        var at = text.IndexOf(AgentLayout.AgentExeName, StringComparison.OrdinalIgnoreCase);
        if (at >= 0)
            return text[..(at + AgentLayout.AgentExeName.Length)].Trim();
        var space = text.IndexOf(' ');
        return space > 0 ? text[..space] : text;
    }

    public static bool PathsEqual(string? a, string? b)
    {
        if (string.IsNullOrWhiteSpace(a) || string.IsNullOrWhiteSpace(b)) return false;
        var left = a.Trim().TrimEnd('\\', '/');
        var right = b.Trim().TrimEnd('\\', '/');
        return string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>A service to stop before the new agent starts.</summary>
    public static bool ServiceLaunchesAgent(string? serviceName, string? imagePath) =>
        IsCurrentService(serviceName) || ImagePathLaunchesAgent(imagePath);

    /// <summary>Other registrations of the agent are removed. The current service is stopped and started again in place.</summary>
    public static bool ShouldDeleteService(string? serviceName, string? imagePath) =>
        ServiceLaunchesAgent(serviceName, imagePath) && !IsCurrentService(serviceName);

    public static bool IsActiveState(string? state) =>
        state is not null && (
            state.Equals("Running", StringComparison.OrdinalIgnoreCase)
            || state.Equals("StartPending", StringComparison.OrdinalIgnoreCase)
            || state.Equals("StopPending", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Another registration that can start a second copy: a different service name, or the current service pointing
    /// at a different executable than the one this process is.
    /// </summary>
    public static bool IsExtraRegistration(AgentServiceRegistration service, string? currentImage)
    {
        if (!ServiceLaunchesAgent(service.Name, service.ImagePath)) return false;
        if (!IsCurrentService(service.Name)) return true;
        var exe = ExePathFromImage(service.ImagePath);
        return exe is not null && currentImage is not null && !PathsEqual(exe, currentImage);
    }

    public static IReadOnlyList<string> SideBySideInstallPaths(IEnumerable<AgentServiceRegistration> services, string? targetExe)
    {
        var paths = new List<string>();
        foreach (var service in services)
        {
            var exe = ExePathFromImage(service.ImagePath);
            if (string.IsNullOrWhiteSpace(exe) || !ImagePathLaunchesAgent(exe)) continue;
            if (PathsEqual(exe, targetExe)) continue;
            if (paths.Any(existing => PathsEqual(existing, exe))) continue;
            paths.Add(exe);
        }
        return paths;
    }

    /// <summary>
    /// What an upgrade does before it starts the service. Failure restart is turned off first, then each service is
    /// stopped. The start type stays Automatic: switching it off is what left the service stopped when the installer
    /// died with the old agent. Startup entries are removed next. Leftover processes that are not an ancestor of this
    /// process are ended without their process tree. The mutex must be free, and only then are other agent services deleted.
    /// Recovery (Automatic plus failure restart) is put back last. The caller starts the service after that.
    /// </summary>
    public static IReadOnlyList<AgentUpgradeAction> BeforeStart(IEnumerable<AgentServiceRegistration> services)
    {
        var plan = new List<AgentUpgradeAction>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var service in services)
        {
            if (!ServiceLaunchesAgent(service.Name, service.ImagePath)) continue;
            if (string.IsNullOrWhiteSpace(service.Name) || !seen.Add(service.Name)) continue;
            plan.Add(new DisableFailureRestartAction(service.Name));
            plan.Add(new StopServiceAction(service.Name));
        }
        plan.Add(new TerminateLeftoverProcessesAction());
        plan.Add(new WaitForInstanceMutexAction());
        var deleted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var service in services)
        {
            if (!ShouldDeleteService(service.Name, service.ImagePath)) continue;
            if (string.IsNullOrWhiteSpace(service.Name) || !deleted.Add(service.Name)) continue;
            plan.Add(new DeleteServiceAction(service.Name));
        }
        plan.Add(new EnsureServiceRecoveryAction(AgentLayout.ServiceName));
        return plan;
    }

    /// <summary>
    /// True while a failed mutex take should be retried. A holder that has already exited, a holder that is still
    /// listed because it is being killed, and a live second copy all wait out <paramref name="giveUp"/>. Stopping at
    /// the first busy mutex made the new service exit 0 and stay stopped.
    /// </summary>
    public static bool ShouldWaitForDyingHolder(
        AgentInstanceClaim? claim,
        bool claimPidAlive,
        IReadOnlyList<AgentProcessSighting> others,
        TimeSpan waited,
        TimeSpan giveUp)
    {
        _ = claim;
        _ = claimPidAlive;
        _ = others;
        return waited < giveUp;
    }

    /// <summary>
    /// A leftover agent process may be killed when it is not this process and not an ancestor in the same
    /// kill-on-close job. Killing that ancestor closes the job and ends Setup, which is the process that starts the new service.
    /// When the parent chain cannot be read and this process is in such a job, nothing is killed.
    /// </summary>
    public static bool MayTerminateLeftover(int pid, int selfPid, IReadOnlyList<int> protectedPids, bool inKillOnCloseJob, bool parentsKnown)
    {
        if (pid <= 0 || pid == selfPid)
            return false;
        foreach (var id in protectedPids)
        {
            if (id == pid)
                return false;
        }
        if (inKillOnCloseJob && !parentsKnown)
            return false;
        return true;
    }

    public static AgentStartupReport DescribeStartup(
        bool acquired,
        bool abandoned,
        AgentInstanceClaim? claim,
        bool claimPidAlive,
        IReadOnlyList<AgentProcessSighting> otherProcesses,
        IReadOnlyList<AgentServiceRegistration> services,
        string? currentImage)
    {
        var lines = new List<string>();
        if (!acquired)
        {
            lines.Add(DescribeDenial(claim, otherProcesses));
            return new AgentStartupReport(false, lines);
        }

        if (abandoned)
            lines.Add(DescribeAbandoned(claim, claimPidAlive));
        foreach (var process in otherProcesses)
            lines.Add(DescribeStaleProcess(process));
        foreach (var service in services)
        {
            if (IsExtraRegistration(service, currentImage))
                lines.Add(DescribeStaleService(service));
        }
        return new AgentStartupReport(true, lines);
    }

    public static string DescribeDyingHolder(AgentInstanceClaim? claim, bool claimPidAlive)
    {
        if (claim is null)
            return $"{LogPrefix} {MutexName} is held but no holder is recorded. Waiting for the previous process to exit instead of stopping this service.";
        if (!claimPidAlive)
            return $"{LogPrefix} {MutexName} is still held by pid {claim.Pid}, which has exited. Waiting for Windows to release it instead of stopping this service.";
        return $"{LogPrefix} {MutexName} is held by pid {claim.Pid}, version {Shown(claim.Version)}, which is still exiting. Waiting instead of stopping this service.";
    }

    public static string DescribeDenial(AgentInstanceClaim? claim, IReadOnlyList<AgentProcessSighting> others)
    {
        var text = $"{LogPrefix} Another Remote PC Diagnostics Agent already holds {MutexName}.";
        if (claim is not null)
            text += $" Holder pid {claim.Pid}, version {Shown(claim.Version)}, path {Shown(claim.Path)}.";
        var extras = claim is null ? others : others.Where(process => process.Pid != claim.Pid).ToList();
        if (extras.Count > 0)
        {
            text += " Also running " + string.Join("; ", extras.Select(static process =>
                $"pid {process.Pid}, version {Shown(process.Version)}, path {Shown(process.Path)}")) + ".";
        }
        text += " This process is exiting without starting so Windows does not restart the service.";
        return text;
    }

    public static string DescribeAbandoned(AgentInstanceClaim? claim, bool claimPidAlive)
    {
        if (claim is null)
            return $"{LogPrefix} The previous agent abandoned {MutexName} without recording a pid. This process is taking over.";
        var who = $"pid {claim.Pid}, version {Shown(claim.Version)}, path {Shown(claim.Path)}";
        if (!claimPidAlive)
            return $"{LogPrefix} The previous agent abandoned {MutexName} ({who}). That process is gone. This process is taking over.";
        return $"{LogPrefix} The previous agent abandoned {MutexName} but {who} is still running. This process holds the mutex; the other process is a stale duplicate.";
    }

    public static string DescribeStaleProcess(AgentProcessSighting process) =>
        $"{LogPrefix} Stale agent process is still running (pid {process.Pid}, version {Shown(process.Version)}, path {Shown(process.Path)}). This process holds {MutexName}. The extra process can keep an older build alive.";

    public static string DescribeStaleService(AgentServiceRegistration service)
    {
        var exe = ExePathFromImage(service.ImagePath);
        var where = string.IsNullOrWhiteSpace(exe) ? Shown(service.ImagePath) : exe;
        var running = IsActiveState(service.State) ? "still running" : "still registered";
        return $"{LogPrefix} Stale agent service '{service.Name}' is {running} ({service.State ?? "unknown state"}, image {where}). It is not this instance and can start a second copy.";
    }

    public static string DescribeSideBySide(string path) =>
        $"{LogPrefix} Replacing an agent that was installed at {path}. The new service uses {AgentLayout.InstallFolderName} and the old registration is removed before it starts.";

    public static string Shown(string? value) => string.IsNullOrWhiteSpace(value) ? "unknown" : value.Replace('\r', ' ').Replace('\n', ' ').Trim();
}

public sealed record AgentServiceRegistration(string Name, string? ImagePath, string? State);

public sealed record AgentProcessSighting(int Pid, string? Path, string? Version);

public sealed record AgentInstanceClaim(int Pid, string? Version, string? Path, string? StartedUtc)
{
    public static string Format(AgentInstanceClaim claim)
    {
        static string Line(string key, string? value) => key + "=" + (value ?? "").Replace('\r', ' ').Replace('\n', ' ');
        return string.Join('\n',
            Line("pid", claim.Pid.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            Line("version", claim.Version),
            Line("path", claim.Path),
            Line("startedUtc", claim.StartedUtc));
    }

    public static AgentInstanceClaim? Parse(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        int? pid = null;
        string? version = null;
        string? path = null;
        string? started = null;
        foreach (var raw in text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n'))
        {
            var line = raw.Trim();
            var cut = line.IndexOf('=');
            if (cut <= 0) continue;
            var key = line[..cut];
            var value = line[(cut + 1)..].Trim();
            if (value.Length == 0) value = null;
            if (key.Equals("pid", StringComparison.OrdinalIgnoreCase) && int.TryParse(value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var parsed) && parsed > 0)
                pid = parsed;
            else if (key.Equals("version", StringComparison.OrdinalIgnoreCase))
                version = value;
            else if (key.Equals("path", StringComparison.OrdinalIgnoreCase))
                path = value;
            else if (key.Equals("startedUtc", StringComparison.OrdinalIgnoreCase))
                started = value;
        }
        return pid is int id ? new AgentInstanceClaim(id, version, path, started) : null;
    }
}

public sealed record AgentStartupReport(bool Run, IReadOnlyList<string> Lines);

public abstract record AgentUpgradeAction;

public sealed record DisableFailureRestartAction(string ServiceName) : AgentUpgradeAction;

public sealed record StopServiceAction(string ServiceName) : AgentUpgradeAction;


public sealed record TerminateLeftoverProcessesAction : AgentUpgradeAction;

public sealed record WaitForInstanceMutexAction : AgentUpgradeAction;

public sealed record DeleteServiceAction(string ServiceName) : AgentUpgradeAction;

/// <summary>Puts Automatic startup and failure restart back on the service that is about to be started.</summary>
public sealed record EnsureServiceRecoveryAction(string ServiceName) : AgentUpgradeAction;
