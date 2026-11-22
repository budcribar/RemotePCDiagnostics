using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>Runs built-in Windows tools (PowerShell, wevtutil) for areas osquery can't cover. Logs every call; never throws except on cancellation.</summary>
public sealed class SystemCommandRunner(
    IProcessLauncher? launcher = null,
    ILogger? log = null,
    TimeSpan? timeout = null,
    IElevatedCommandBridge? elevatedBridge = null,
    Func<bool>? isProcessElevated = null,
    IAgentNativeOps? nativeOps = null)
{
    private readonly IProcessLauncher _launcher = launcher ?? new SystemProcessLauncher();
    public IProcessLauncher Launcher => _launcher;
    public bool IsScripted => _launcher is not SystemProcessLauncher;
    private readonly Func<bool> _isProcessElevated = isProcessElevated ?? ElevationService.DetectProcessElevated;
    public TimeSpan Timeout { get; } = timeout ?? TimeSpan.FromSeconds(60);
    public ILogger? Log { get; } = log;
    public IElevatedCommandBridge? ElevatedBridge => elevatedBridge;
    /// <summary>Whether the current process itself is running with administrator privileges (independent of the Agent bridge).</summary>
    public bool IsProcessElevated => _isProcessElevated();
    /// <summary>Whether an admin tool run through this runner gets administrator rights: the Agent is connected, or this process has them.</summary>
    public bool HasAdminRights => elevatedBridge is { IsConnected: true } || _isProcessElevated();

    /// <summary>Full path of a tool in the Windows system directory (falls back to the bare name, resolved via PATH).</summary>
    public static string SystemTool(string exe)
    {
        var dir = Environment.SystemDirectory;
        return string.IsNullOrEmpty(dir) ? exe : Path.Combine(dir, exe);
    }

    public static string PowerShell => SystemTool(Path.Combine("WindowsPowerShell", "v1.0", "powershell.exe"));

    /// <summary>Standard PowerShell arguments for running a script without profiles or prompts.</summary>
    public static IReadOnlyList<string> PowerShellArgs(string script) =>
        ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script];

    /// <summary>Runs a PowerShell script via <see cref="PowerShell"/> using <see cref="PowerShellArgs"/>.</summary>
    public Task<ProcessResult?> RunPowerShellAsync(string script, CancellationToken ct) =>
        RunAsync(PowerShell, PowerShellArgs(script), null, ct);

    /// <summary>Runs a PowerShell script via <see cref="PowerShell"/> with an optional timeout and output line callback.</summary>
    public Task<ProcessResult?> RunPowerShellAsync(string script, TimeSpan? timeout, CancellationToken ct, Action<string>? outputLine = null) =>
        RunAsync(PowerShell, PowerShellArgs(script), timeout, ct, outputLine);

    /// <summary>Returns the result, or null when the process couldn't start / timed out (details logged).</summary>
    public Task<ProcessResult?> RunAsync(string fileName, IReadOnlyList<string> arguments, CancellationToken ct) => RunAsync(fileName, arguments, null, ct);


    /// <summary>Same, with a longer limit for slow work (cleanup, updates); null = <see cref="Timeout"/>.</summary>
    public async Task<ProcessResult?> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan? timeout, CancellationToken ct, Action<string>? outputLine = null)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var effectiveTimeout = timeout ?? Timeout;

        if (!_isProcessElevated()
            && elevatedBridge is { IsConnected: true }
            && AdminCommandAllowlist.TryResolveSystemTool(fileName, out _)
            && !AdminCommandAllowlist.RunsWithoutAdmin(fileName, arguments))
        {
            // An admin tool goes to the Agent, and only to the Agent: when the call fails, the app doesn't run it itself (it would only
            // fail later without administrator rights, or half-work). The caller gets a failed result that says why.
            ProcessResult? bridged;
            try
            {
                bridged = await elevatedBridge.RunElevatedAsync(fileName, arguments, effectiveTimeout, ct, outputLine).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                Write($"[admin-helper] command {Path.GetFileName(fileName)} bridge call failed: {ex.Message}");
                return AgentFailed($"The Agent couldn't run {Path.GetFileNameWithoutExtension(fileName)}. " + ElevationService.AdminRepairHint);
            }
            if (bridged is null)
            {
                Write($"[admin-helper] command {Path.GetFileName(fileName)} was refused or failed in the Agent.");
                return AgentFailed($"The Agent didn't run {Path.GetFileNameWithoutExtension(fileName)}. Update Remote PC Diagnostics, then try again.");
            }
            LogResult("[admin-helper] ", fileName, arguments, bridged, sw.ElapsedMilliseconds);
            return bridged.TimedOut ? null : bridged;
        }

        ProcessResult pr;
        try
        {
            pr = outputLine is not null
                ? await _launcher.RunAsync(fileName, arguments, effectiveTimeout, ct, outputLine).ConfigureAwait(false)
                : await _launcher.RunAsync(fileName, arguments, effectiveTimeout, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            Write($"command {Path.GetFileName(fileName)} failed to start: {ex.Message}");
            return null;
        }
        LogResult("", fileName, arguments, pr, sw.ElapsedMilliseconds);
        return pr.TimedOut ? null : pr;
    }

    /// <summary>The exit code of a result the Agent never ran (refused, unreachable, or not connected): its StdErr says why.</summary>
    public const int AgentFailedExitCode = -0x41474E54;

    private static ProcessResult AgentFailed(string why) => new(AgentFailedExitCode, "", why);

    /// <summary>Why the Agent didn't run <paramref name="pr"/>'s command, or null when it ran (or the result isn't the Agent's).</summary>
    public static string? AgentFailure(ProcessResult? pr) => pr is { ExitCode: AgentFailedExitCode } ? pr.StdErr : null;

    /// <summary>
    /// Runs one of the Agent's own scripts (<see cref="AgentScripts"/>) with administrator rights. The app sends only the script's name and
    /// arguments; the Agent checks them and builds the PowerShell. Runs it in this process when it already has administrator rights (the
    /// Agent's own sessions, tests). Otherwise, without the Agent, the result is a failure that says to turn on Admin Repair Mode
    /// (<see cref="AgentFailure"/>). Null when it timed out.
    /// </summary>
    public async Task<ProcessResult?> RunAgentScriptAsync(AdminPipeScript script, TimeSpan? timeout, CancellationToken ct, Action<string>? outputLine = null)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var effectiveTimeout = timeout ?? Timeout;
        var label = $"agent script {script.Name} {string.Join(' ', script.Args ?? [])}";
        var elevated = _isProcessElevated();

        if (!elevated && elevatedBridge is { IsConnected: true } bridge)
        {
            ProcessResult pr;
            try
            {
                pr = await bridge.RunAgentScriptAsync(script, effectiveTimeout, ct, outputLine).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (AdminRequiredException ex) { Write($"[admin-helper] {label}: {ex.Message}"); return AgentFailed(ex.Message); }
            catch (Exception ex)
            {
                Write($"[admin-helper] {label} failed: {ex.Message}");
                return AgentFailed("The Agent couldn't make this change. " + ElevationService.AdminRepairHint);
            }
            Write($"[admin-helper] {label} exit={pr.ExitCode} timedOut={pr.TimedOut} ms={sw.ElapsedMilliseconds} stderr=\"{pr.StdErr.Trim()}\"");
            return pr.TimedOut ? null : pr;
        }

        if (!elevated && !IsScripted)
        {
            Write($"{label}: not run, the Agent isn't connected.");
            return AgentFailed("The Agent isn't connected. " + ElevationService.AdminRepairHint);
        }

        if (AgentScripts.Plan(script, AppContext.BaseDirectory, out var refusal) is not { } plan)
        {
            Write($"{label} refused: {refusal}");
            return AgentFailed(refusal ?? "That change isn't allowed.");
        }
        if (plan.Native is { } native)
        {
            // A scripted launcher (tests) makes these changes itself when it can; one that can't answers like an Agent that isn't there.
            var ops = nativeOps ?? _launcher as IAgentNativeOps ?? (IsScripted ? null : WindowsAgentNativeOps.Instance);
            if (ops is null) return AgentFailed("The Agent isn't connected. " + ElevationService.AdminRepairHint);
            var pr = await AgentNativeRunner.RunAsync(ops, native, effectiveTimeout, ct).ConfigureAwait(false);
            Write($"{label} exit={pr.ExitCode} timedOut={pr.TimedOut} ms={sw.ElapsedMilliseconds} stderr=\"{pr.StdErr.Trim()}\"");
            return pr.TimedOut ? null : pr;
        }
        return await RunAsync(PowerShell, PowerShellArgs(plan.Script!), timeout, ct, outputLine).ConfigureAwait(false);
    }

    private void LogResult(string prefix, string fileName, IReadOnlyList<string> arguments, ProcessResult pr, long elapsedMs)
    {
        var head = pr.StdOut.Length > 1024 ? pr.StdOut[..1024] : pr.StdOut;
        Write($"{prefix}command {Path.GetFileName(fileName)} {string.Join(' ', arguments.Select(a => a.Length > 200 ? a[..200] + "…" : a))} " +
              $"exit={pr.ExitCode} timedOut={pr.TimedOut} ms={elapsedMs} stdout_len={pr.StdOut.Length} " +
              $"stderr=\"{pr.StdErr.Trim()}\" stdout_head=\"{head.Replace("\r", "").Replace("\n", " ")}\"");
    }

    private void Write(string s) { try { Log.Line(s); } catch { } }
}
