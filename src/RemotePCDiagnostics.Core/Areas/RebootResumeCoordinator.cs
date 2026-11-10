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

    public static ResourceBaselineSnapshot FromOsquery(SystemUptimeInfo? uptime, IReadOnlyList<ProcessResourceRow>? processes)
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
    bool Mirror = false,
    bool ReverseMirror = false,
    bool Unattended = false,
    bool Voice = false);

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
/// <item>Registers a Windows <c>HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce</c> entry so <c>RemotePCDiagnostics</c> automatically relaunches into the exact same remote session (<c>-u=&lt;server&gt; -i=&lt;sessionId&gt; --post-reboot</c>) after reboot.</item>
/// <item>On startup after the reboot, re-measures active resources, computes the memory and process reduction, and logs the result to History / Event Log (Event 1100).</item>
/// </list>
/// </summary>
public sealed class RebootResumeCoordinator(
    SystemCommandRunner commands,
    OsqueryRunner? osquery = null,
    string? stateFilePath = null,
    string? executablePath = null,
    ILogger? log = null)
{
    public const string RunOnceRegistryKey = @"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce";
    public const string RunOnceValueName = "RemotePCDiagnosticsResume";

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

    /// <summary>Captures the current resource baseline via osquery (if available) or <see cref="Process.GetProcesses()"/>.</summary>
    public async Task<ResourceBaselineSnapshot> CaptureBaselineAsync(CancellationToken ct = default)
    {
        if (osquery is not null)
        {
            try
            {
                var upQ = await osquery.RunQueryAsync(ResourceUsage.UptimeSql, ct).ConfigureAwait(false);
                var procQ = await osquery.RunQueryAsync(ResourceUsage.ProcessesSql, ct).ConfigureAwait(false);
                if (upQ.Success || procQ.Success)
                {
                    var uptime = upQ.Success && upQ.Rows is { Count: > 0 } ? SystemUptimeInfo.FromRow(upQ.Rows[0]) : null;
                    var procs = procQ.Success && procQ.Rows is not null ? procQ.Rows.Select(ProcessResourceRow.FromRow).ToList() : null;
                    return ResourceBaselineSnapshot.FromOsquery(uptime, procs);
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                LogWarn($"osquery baseline capture failed, falling back to Process API: {ex.Message}");
            }
        }

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
        return new(upSec, totalMem, count, string.Join(", ", top));
    }

    /// <summary>
    /// Captures pre-reboot resources, persists <see cref="PendingRebootState"/>, and writes the <c>RunOnce</c> registry entry
    /// so <c>RemotePCDiagnostics</c> restarts with the same run stream after Windows reboots.
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
        var mirror = session?.Mirror ?? false;
        var reverseMirror = session?.ReverseMirror ?? false;
        var unattended = session?.Unattended ?? false;
        var voice = session?.Voice ?? false;

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
            mirror,
            reverseMirror,
            unattended,
            voice);

        SavePendingState(state);

        var resumeCmd = SessionLaunchOptions.BuildResumeCommandLine(ExecutablePath, mode, serverUri, sessionId, mirror, reverseMirror, unattended, voice);
        LastRegisteredCommandLine = resumeCmd;

        var reg = await commands.RunAsync(
            SystemCommandRunner.SystemTool("reg.exe"),
            ["add", RunOnceRegistryKey, "/v", RunOnceValueName, "/t", "REG_SZ", "/d", resumeCmd, "/f"],
            ct).ConfigureAwait(false);

        Log($"Prepared reboot resume: mode={mode} sessionId={sessionId} preMem={baseline.UsedMemoryBytes} preProcs={baseline.ProcessCount} regExit={reg?.ExitCode} cmd='{resumeCmd}'");
        return state;
    }

    /// <summary>Clears the <c>RunOnce</c> startup entry and deletes any saved pre-reboot snapshot when a restart is cancelled.</summary>
    public async Task CancelPendingRebootAsync(CancellationToken ct = default)
    {
        ClearPendingState();
        LastRegisteredCommandLine = null;
        await commands.RunAsync(
            SystemCommandRunner.SystemTool("reg.exe"),
            ["delete", RunOnceRegistryKey, "/v", RunOnceValueName, "/f"],
            ct).ConfigureAwait(false);
        Log("Cleared pending reboot state and RunOnce entry.");
    }

    /// <summary>
    /// Checks if a pre-reboot snapshot is pending after a reboot, measures current post-reboot resources,
    /// records the reduction in <paramref name="remediation"/> (and Event Log 1100), and refreshes the <c>ResourceHogs</c> diagnostic check.
    /// </summary>
    public async Task<PostRebootComparisonResult?> CompletePostRebootIfPendingAsync(
        RemediationService remediation,
        DiagnosticsService? diagnostics = null,
        bool postRebootArgPresent = false,
        ResourceBaselineSnapshot? postBaselineOverride = null,
        CancellationToken ct = default)
    {
        var pending = LoadPendingState();
        if (pending is null) return null;

        // Expire stale snapshots older than 48 hours.
        if ((DateTimeOffset.UtcNow - pending.InitiatedAtUtc) > TimeSpan.FromHours(48))
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

        // Confirm that a reboot actually happened (either --post-reboot arg was passed by RunOnce, or system uptime reset below pre-reboot uptime).
        bool rebootConfirmed = postRebootArgPresent
            || (pending.PreUptimeSeconds > 0 && post.UptimeSeconds < pending.PreUptimeSeconds)
            || (DateTimeOffset.UtcNow - pending.InitiatedAtUtc) >= TimeSpan.FromMinutes(2);

        if (!rebootConfirmed)
            return null;

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
            "Post-reboot resource comparison",
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
