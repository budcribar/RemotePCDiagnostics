using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>Snapshot of system uptime, total process resident memory, process count, and top consumers before or after a reboot.</summary>
public sealed record ResourceBaselineSnapshot(
    long UptimeSeconds,
    long UsedMemoryBytes,
    int ProcessCount,
    string TopProcesses)
{
    private const string Prefix = "reboot-baseline:";

    public string Encode() =>
        $"{Prefix}up={UptimeSeconds.ToString(CultureInfo.InvariantCulture)};" +
        $"mem={UsedMemoryBytes.ToString(CultureInfo.InvariantCulture)};" +
        $"procs={ProcessCount.ToString(CultureInfo.InvariantCulture)};" +
        $"top={Uri.EscapeDataString(TopProcesses ?? "")}";

    public static bool TryDecode(string? text, out ResourceBaselineSnapshot? snapshot)
    {
        snapshot = null;
        if (string.IsNullOrWhiteSpace(text) || !text.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase))
            return false;

        long up = 0, mem = 0;
        int procs = 0;
        string top = "";

        foreach (var part in text[Prefix.Length..].Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = part.IndexOf('=');
            if (eq <= 0) continue;
            var k = part[..eq].Trim();
            var v = part[(eq + 1)..].Trim();
            if (k.Equals("up", StringComparison.OrdinalIgnoreCase))
                long.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out up);
            else if (k.Equals("mem", StringComparison.OrdinalIgnoreCase))
                long.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out mem);
            else if (k.Equals("procs", StringComparison.OrdinalIgnoreCase))
                int.TryParse(v, NumberStyles.Integer, CultureInfo.InvariantCulture, out procs);
            else if (k.Equals("top", StringComparison.OrdinalIgnoreCase))
                top = Uri.UnescapeDataString(v);
        }

        snapshot = new(Math.Max(0, up), Math.Max(0, mem), Math.Max(0, procs), top);
        return true;
    }

    public static ResourceBaselineSnapshot From(SystemUptimeInfo? uptime, IReadOnlyList<ProcessResourceRow>? processes)
    {
        var upSec = uptime?.TotalSeconds ?? 0;
        if (processes is null || processes.Count == 0)
            return new(upSec, 0, 0, "");

        var totalMem = processes.Sum(p => Math.Max(0, p.ResidentBytes));
        var groups = ResourceUsage.GroupProcesses(processes)
            .OrderByDescending(g => g.MemoryBytes)
            .Take(3)
            .Select(g => $"{g.Name} ({HardwareInventory.FormatBytes(g.MemoryBytes)})");
        return new(upSec, totalMem, processes.Count, string.Join(", ", groups));
    }
}

/// <summary>Persisted pre-reboot state saved before a scheduled restart so the post-reboot instance can compare resource usage.</summary>
public sealed record PendingRebootState(
    DateTimeOffset InitiatedAtUtc,
    string Actor,
    SessionMode Mode,
    string? ServerUri,
    Guid SessionId,
    long PreUptimeSeconds,
    long PreUsedMemoryBytes,
    int PreProcessCount,
    string PreTopProcesses,
    bool Unattended = false,
    bool Voice = false,
    string? Group = null);

/// <summary>Result of comparing pre-reboot vs. post-reboot resource consumption after the PC restarts.</summary>
public sealed record PostRebootComparisonResult(
    PendingRebootState PreReboot,
    ResourceBaselineSnapshot PostReboot,
    long FreedMemoryBytes,
    int ReducedProcesses,
    string SummaryMessage,
    RemediationRecord Record);

/// <summary>
/// Coordinates remote/local PC restarts:
/// <list type="number">
/// <item>Captures pre-reboot resource usage (memory, process count, uptime, top consumers) and saves <see cref="PendingRebootState"/>.</item>
/// <item>Registers a Task Scheduler task that runs at the user's next sign-in with highest privileges, so <c>RemotePCDiagnostics</c> relaunches elevated,
/// without a UAC prompt, into the exact same remote session (<c>-u=&lt;server&gt; -i=&lt;sessionId&gt; --post-reboot</c>) after reboot. Only when the task
/// can't be registered does it fall back to a <c>HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce</c> entry, which waits at the UAC prompt.</item>
/// <item>On startup after the reboot, re-measures active resources, computes the memory and process reduction, and logs the result to History / Event Log (Event 1100).</item>
/// </list>
/// </summary>
public sealed class RebootResumeCoordinator(
    SystemCommandRunner commands,
    string? stateFilePath = null,
    string? executablePath = null,
    ILogger? log = null)
{
    public const string RunOnceRegistryKey = @"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce";
    public const string RunOnceValueName = "RemotePCDiagnosticsResume";

    /// <summary>The target of the record written after a restart: how much memory and how many processes the restart cleared.</summary>
    public const string PostRebootTarget = "Post-reboot resource comparison";

    /// <summary>
    /// True for the record the app writes by itself once it is back from a restart. It carries the actor who asked for the restart
    /// (so History shows who did it), but nobody did anything at that moment: it is not something to interrupt the person at the PC about.
    /// </summary>
    public static bool IsPostRebootComparison(RemediationRecord record) =>
        record.Kind == RemediationKind.ScheduleCleanRestart && record.Target == PostRebootTarget;

    /// <summary>The sign-in task that relaunches the app elevated after a restart it scheduled. Removed once the app is back, or when the restart is called off.</summary>
    public const string ResumeTaskName = "Remote PC Diagnostics - continue after restart";

    private readonly object _gate = new();
    private PendingRebootState? _memoryState;

    public string ExecutablePath =>
        !string.IsNullOrWhiteSpace(executablePath)
            ? executablePath
            : Environment.ProcessPath ?? "RemotePCDiagnostics.Host.exe";

    public string? LastRegisteredCommandLine { get; private set; }

    private void Log(string m) => (log ?? commands.Log).Info("[reboot-resume] " + m);
    private void LogWarn(string m) => (log ?? commands.Log).Warn("[reboot-resume] " + m);

    public static string DefaultStateFilePath() =>
        ProtectedState.PathFor(ProtectedState.PendingRebootFile);

    public static PendingRebootState? TryReadPendingStateFile(string? path = null)
    {
        var file = path ?? DefaultStateFilePath();
        if (string.IsNullOrWhiteSpace(file) || !File.Exists(file)) return null;
        try { return JsonSerializer.Deserialize<PendingRebootState>(File.ReadAllText(file)); }
        catch { return null; }
    }

    /// <summary>Captures the current resource baseline with <see cref="Process.GetProcesses()"/> (as the signed-in user, so no Agent is needed).</summary>
    public Task<ResourceBaselineSnapshot> CaptureBaselineAsync(CancellationToken ct = default)
    {
        var upSec = Math.Max(0, Environment.TickCount64 / 1000);
        long totalMem = 0;
        int count = 0;
        var byName = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                if (p.Id <= 4) continue;
                var ws = Math.Max(0, p.WorkingSet64);
                totalMem += ws;
                count++;
                var name = p.ProcessName + ".exe";
                byName[name] = byName.GetValueOrDefault(name) + ws;
            }
            catch { }
            finally { p.Dispose(); }
        }
        var top = byName.OrderByDescending(kv => kv.Value)
            .Take(3)
            .Select(kv => $"{kv.Key} ({HardwareInventory.FormatBytes(kv.Value)})");
        return Task.FromResult(new ResourceBaselineSnapshot(upSec, totalMem, count, string.Join(", ", top)));
    }

    /// <summary>
    /// Captures pre-reboot resources, persists <see cref="PendingRebootState"/>, and registers the sign-in task (or, failing that,
    /// the <c>RunOnce</c> registry entry) so <c>RemotePCDiagnostics</c> restarts with the same run stream after Windows reboots.
    /// </summary>
    public async Task<PendingRebootState> PrepareForRebootAsync(
        string actor,
        ISessionContext? session,
        string? actionTarget = null,
        CancellationToken ct = default)
    {
        ResourceBaselineSnapshot baseline;
        if (ResourceBaselineSnapshot.TryDecode(actionTarget, out var decoded) && decoded is not null && decoded.UsedMemoryBytes > 0)
            baseline = decoded;
        else
            baseline = await CaptureBaselineAsync(ct).ConfigureAwait(false);

        var mode = session?.Mode ?? SessionMode.Local;
        var serverUri = session?.ServerUri;
        var sessionId = session?.SessionId ?? Guid.Empty;
        var unattended = session?.Unattended ?? false;
        var voice = session?.Voice ?? false;
        var group = SessionLaunchOptions.NormalizeGroup(session?.Group);

        var state = new PendingRebootState(
            DateTimeOffset.UtcNow,
            actor,
            mode,
            serverUri?.AbsoluteUri,
            sessionId,
            baseline.UptimeSeconds,
            baseline.UsedMemoryBytes,
            baseline.ProcessCount,
            baseline.TopProcesses,
            unattended,
            voice,
            group);

        SavePendingState(state);

        var resumeCmd = SessionLaunchOptions.BuildResumeCommandLine(ExecutablePath, mode, serverUri, sessionId, unattended, voice, group);
        LastRegisteredCommandLine = resumeCmd;

        // The sign-in task runs the Agent's launcher (RemotePCDiagnostics.Agent.exe --launch …) with highest privileges, so there's no UAC
        // prompt after the restart; the launcher starts the app un-elevated, as the signed-in user, with the Agent connected. The app itself
        // never runs as administrator. Registering it needs administrator rights, so the Agent does it from a script it builds itself
        // (the app sends only the user and the launch arguments). Without the Agent the app registers its own task with limited rights,
        // and if that fails too, a RunOnce entry starts the app (un-elevated, without the Agent) instead.
        var launch = ResumeTaskScript.LaunchArguments(ExecutablePath, resumeCmd);
        var task = await commands.RunAgentScriptAsync(
            AgentScripts.Of(AgentScripts.ResumeTaskRegister, [AgentScripts.RebootTask, CurrentUser(), .. launch]), null, ct).ConfigureAwait(false);
        var how = "task";
        if (SystemCommandRunner.AgentFailure(task) is { } noAgent)
        {
            Log($"The Agent didn't register the resume task ({noAgent}); registering the app's own task with limited rights.");
            task = await RegisterLimitedResumeTaskAsync(ExecutablePath, resumeCmd, CurrentUser(), DateTimeOffset.Now, ct).ConfigureAwait(false);
            how = "task-limited";
        }
        int? regExit = null;
        if (task is not { ExitCode: 0 })
        {
            LogWarn($"Couldn't register the resume task (exit={task?.ExitCode} err={task?.StdErr.Trim()}); using RunOnce instead.");
            var reg = await commands.RunAsync(
                SystemCommandRunner.SystemTool("reg.exe"),
                ["add", RunOnceRegistryKey, "/v", RunOnceValueName, "/t", "REG_SZ", "/d", resumeCmd, "/f"],
                ct).ConfigureAwait(false);
            how = "runonce";
            regExit = reg?.ExitCode;
        }

        Log($"Prepared reboot resume: mode={mode} sessionId={sessionId} group={group} preMem={baseline.UsedMemoryBytes} preProcs={baseline.ProcessCount} via={how} regExit={regExit} cmd='{resumeCmd}'");
        return state;
    }

    private static string CurrentUser() => $"{Environment.UserDomainName}\\{Environment.UserName}";

    /// <summary>
    /// Builds the Task Scheduler XML for the app's own <see cref="ResumeTaskName"/> (when the Agent isn't available):
    /// limited rights only, with <see cref="SessionLaunchOptions.PendingRebootMaxAge"/> end boundary.
    /// </summary>
    public static string BuildRegisterResumeTaskXml(string executablePath, string resumeCommandLine, string user, DateTimeOffset now)
    {
        var exe = executablePath.Trim('"');
        var args = string.Join(' ', ResumeTaskScript.LaunchArguments(exe, resumeCommandLine));
        var slash = exe.LastIndexOfAny(['\\', '/']); // not Path.GetDirectoryName: a Windows path must split the same way wherever this runs
        var workDir = slash > 0 ? exe[..slash] : null;
        return ResumeTaskXml.Build(exe, args, workDir, user, now.Add(SessionLaunchOptions.PendingRebootMaxAge), highest: false);
    }

    private async Task<ProcessResult?> RegisterLimitedResumeTaskAsync(string executablePath, string resumeCommandLine, string user, DateTimeOffset now, CancellationToken ct)
    {
        if (commands.IsScripted || !OperatingSystem.IsWindows())
            return await commands.RunPowerShellAsync(BuildRegisterResumeTaskScript(executablePath, resumeCommandLine, user, now), ct).ConfigureAwait(false);

        try
        {
            var xml = BuildRegisterResumeTaskXml(executablePath, resumeCommandLine, user, now);
            await Task.Run(() => Platform.WindowsTaskScheduler.RegisterTask(ResumeTaskName, user, xml), ct).ConfigureAwait(false);
            return new ProcessResult(0, "", "");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { return new ProcessResult(1, "", ex.Message); }
    }

    /// <summary>
    /// PowerShell that registers the app's own <see cref="ResumeTaskName"/>, kept for scripted tests; runtime on Windows uses
    /// <see cref="BuildRegisterResumeTaskXml"/> with <see cref="Platform.WindowsTaskScheduler"/>.
    /// </summary>
    public static string BuildRegisterResumeTaskScript(string executablePath, string resumeCommandLine, string user, DateTimeOffset now)
    {
        var exe = executablePath.Trim('"');
        var args = string.Join(' ', ResumeTaskScript.LaunchArguments(exe, resumeCommandLine));
        var slash = exe.LastIndexOfAny(['\\', '/']); // not Path.GetDirectoryName: a Windows path must split the same way wherever this runs
        var workDir = slash > 0 ? exe[..slash] : null;
        return ResumeTaskScript.Register(ResumeTaskName, exe, args, workDir, user, now.Add(SessionLaunchOptions.PendingRebootMaxAge), highest: false);
    }

    /// <summary>Removes the sign-in task and the <c>RunOnce</c> startup entry, and deletes any saved pre-reboot snapshot, when a restart is cancelled or done.</summary>
    public async Task CancelPendingRebootAsync(CancellationToken ct = default)
    {
        ClearPendingState();
        LastRegisteredCommandLine = null;
        await commands.RunAsync(
            SystemCommandRunner.SystemTool("reg.exe"),
            ["delete", RunOnceRegistryKey, "/v", RunOnceValueName, "/f"],
            ct).ConfigureAwait(false);
        // The Agent removes the task it registered; without it, the app removes its own (limited) one.
        var removed = await commands.RunAgentScriptAsync(AgentScripts.Of(AgentScripts.ResumeTaskRemove, AgentScripts.RebootTask), null, ct).ConfigureAwait(false);
        if (SystemCommandRunner.AgentFailure(removed) is not null)
        {
            if (commands.IsScripted || !OperatingSystem.IsWindows())
                await commands.RunPowerShellAsync(ResumeTaskScript.Remove(ResumeTaskName), ct).ConfigureAwait(false);
            else
            {
                try { await Task.Run(() => Platform.WindowsTaskScheduler.RemoveTask(ResumeTaskName), ct).ConfigureAwait(false); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (Exception ex) { LogWarn($"Couldn't remove limited resume task: {ex.Message}"); }
            }
        }
        Log("Cleared pending reboot state, the resume task and the RunOnce entry.");
    }

    /// <summary>How long after a restart was scheduled (it runs 60 seconds later) a PC that has still not restarted counts as
    /// "the restart was called off": the saved session and the resume entry are then removed.</summary>
    public static readonly TimeSpan AbandonedAfter = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Checks if a pre-reboot snapshot is pending after a reboot, measures current post-reboot resources,
    /// records the reduction in <paramref name="remediation"/> (and Event Log 1100), and refreshes the <c>ResourceHogs</c> diagnostic check.
    /// Nothing is recorded unless Windows really restarted since the snapshot (<see cref="SessionLaunchOptions.RestartedSince"/>):
    /// how the app was started, or how much time has passed, does not show that.
    /// </summary>
    /// <param name="nowUtc">The time now (tests); default the clock.</param>
    public async Task<PostRebootComparisonResult?> CompletePostRebootIfPendingAsync(
        RemediationService remediation,
        DiagnosticsService? diagnostics = null,
        ResourceBaselineSnapshot? postBaselineOverride = null,
        CancellationToken ct = default,
        DateTimeOffset? nowUtc = null)
    {
        var pending = LoadPendingState();
        if (pending is null) return null;

        var now = nowUtc ?? DateTimeOffset.UtcNow;

        // Expire stale snapshots older than 48 hours.
        if ((now - pending.InitiatedAtUtc) > SessionLaunchOptions.PendingRebootMaxAge)
        {
            await CancelPendingRebootAsync(ct).ConfigureAwait(false);
            return null;
        }

        // Re-run ResourceHogsModule first so the UI and store have fresh post-reboot process/uptime cards.
        if (diagnostics is not null)
        {
            try { await diagnostics.RunAsync(ModuleSlugs.ResourceHogs, ct: ct).ConfigureAwait(false); }
            catch (Exception ex) when (ex is not OperationCanceledException) { LogWarn($"Post-reboot ResourceHogs refresh failed: {ex.Message}"); }
        }

        var post = postBaselineOverride ?? await CaptureBaselineAsync(ct).ConfigureAwait(false);

        // Confirm that a reboot actually happened: Windows started after the snapshot was saved. (osquery can come back without an
        // uptime, which reads as 0 here; the system's own counter is used then.)
        var uptime = TimeSpan.FromSeconds(post.UptimeSeconds > 0 ? post.UptimeSeconds : Environment.TickCount64 / 1000);
        if (!SessionLaunchOptions.RestartedSince(pending, now, uptime))
        {
            // Still counting down (the app itself was restarted in the meantime): leave everything for the start after the reboot.
            // Long past the countdown: the restart was called off outside the app, so the resume entry must not fire at a later sign-in.
            if (now - pending.InitiatedAtUtc > AbandonedAfter)
            {
                await CancelPendingRebootAsync(ct).ConfigureAwait(false);
                Log("The scheduled restart did not happen; cleared the saved session and the resume entry.");
            }
            return null;
        }

        await CancelPendingRebootAsync(ct).ConfigureAwait(false);

        var freedMem = Math.Max(0, pending.PreUsedMemoryBytes - post.UsedMemoryBytes);
        var reducedProcs = Math.Max(0, pending.PreProcessCount - post.ProcessCount);

        var sessionNote = pending.Mode == SessionMode.Remote && pending.SessionId != Guid.Empty
            ? $"resumed remote session {pending.SessionId.ToString("D")[..8]}…"
            : "resumed session";

        var memComparison = pending.PreUsedMemoryBytes > 0 || post.UsedMemoryBytes > 0
            ? freedMem > 0
                ? $"Process memory dropped from {HardwareInventory.FormatBytes(pending.PreUsedMemoryBytes)} to {HardwareInventory.FormatBytes(post.UsedMemoryBytes)} (freed about {HardwareInventory.FormatBytes(freedMem)} of RAM)"
                : $"Process memory after reboot is {HardwareInventory.FormatBytes(post.UsedMemoryBytes)} (was {HardwareInventory.FormatBytes(pending.PreUsedMemoryBytes)} before reboot)"
            : "System memory refreshed";

        var procComparison = pending.PreProcessCount > 0 || post.ProcessCount > 0
            ? reducedProcs > 0
                ? $" and running processes dropped from {pending.PreProcessCount} to {post.ProcessCount} ({reducedProcs} fewer background processes)."
                : $" across {post.ProcessCount} running processes (was {pending.PreProcessCount})."
            : ".";

        var summary = $"Clean restart completed ({sessionNote}). {memComparison}{procComparison}";

        var rec = remediation.RecordCompleted(
            pending.Actor,
            RemediationKind.ScheduleCleanRestart,
            PostRebootTarget,
            success: true,
            summary,
            freedMemoryBytes: freedMem,
            removedFiles: 0,
            freedDiskBytes: 0,
            updatesInstalled: 0);

        Log($"Completed post-reboot comparison: freedMem={freedMem} reducedProcs={reducedProcs} summary='{summary}'");
        return new(pending, post, freedMem, reducedProcs, summary, rec);
    }

    public void SavePendingState(PendingRebootState state)
    {
        lock (_gate) _memoryState = state;
        if (string.IsNullOrWhiteSpace(stateFilePath)) return;
        try
        {
            var dir = Path.GetDirectoryName(stateFilePath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.WriteAllText(stateFilePath, JsonSerializer.Serialize(state));
        }
        catch (Exception ex)
        {
            LogWarn($"SavePendingState failed: {ex.Message}");
        }
    }

    public PendingRebootState? LoadPendingState()
    {
        lock (_gate)
        {
            if (_memoryState is not null) return _memoryState;
        }
        if (string.IsNullOrWhiteSpace(stateFilePath) || !File.Exists(stateFilePath))
            return null;
        try
        {
            var json = File.ReadAllText(stateFilePath);
            var loaded = JsonSerializer.Deserialize<PendingRebootState>(json);
            lock (_gate) _memoryState = loaded;
            return loaded;
        }
        catch (Exception ex)
        {
            LogWarn($"LoadPendingState failed: {ex.Message}");
            return null;
        }
    }

    public void ClearPendingState()
    {
        lock (_gate) _memoryState = null;
        if (string.IsNullOrWhiteSpace(stateFilePath)) return;
        try
        {
            if (File.Exists(stateFilePath)) File.Delete(stateFilePath);
        }
        catch (Exception ex)
        {
            LogWarn($"ClearPendingState failed: {ex.Message}");
        }
    }
}
