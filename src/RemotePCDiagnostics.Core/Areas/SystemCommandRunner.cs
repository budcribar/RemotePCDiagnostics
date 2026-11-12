using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>Runs built-in Windows tools (PowerShell, wevtutil) for areas osquery can't cover. Logs every call; never throws except on cancellation.</summary>
public sealed class SystemCommandRunner(
    IProcessLauncher? launcher = null,
    ILogger? log = null,
    TimeSpan? timeout = null,
    IElevatedCommandBridge? elevatedBridge = null,
    Func<bool>? isProcessElevated = null)
{
    private readonly IProcessLauncher _launcher = launcher ?? new SystemProcessLauncher();
    private readonly Func<bool> _isProcessElevated = isProcessElevated ?? ElevationService.DetectProcessElevated;
    public TimeSpan Timeout { get; } = timeout ?? TimeSpan.FromSeconds(60);
    public ILogger? Log { get; } = log;

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
            && AdminCommandAllowlist.TryResolveSystemTool(fileName, out _))
        {
            try
            {
                var bridged = await elevatedBridge.RunElevatedAsync(fileName, arguments, effectiveTimeout, ct, outputLine).ConfigureAwait(false);
                if (bridged is not null)
                {
                    LogResult("[admin-helper] ", fileName, arguments, bridged, sw.ElapsedMilliseconds);
                    return bridged.TimedOut ? null : bridged;
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                Write($"[admin-helper] command {Path.GetFileName(fileName)} bridge call failed, falling back to direct execution: {ex.Message}");
            }
        }

        ProcessResult pr;
        try
        {
            pr = outputLine is not null && _launcher is SystemProcessLauncher system
                ? await system.RunAsync(fileName, arguments, effectiveTimeout, ct, outputLine).ConfigureAwait(false)
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

    private void LogResult(string prefix, string fileName, IReadOnlyList<string> arguments, ProcessResult pr, long elapsedMs)
    {
        var head = pr.StdOut.Length > 1024 ? pr.StdOut[..1024] : pr.StdOut;
        Write($"{prefix}command {Path.GetFileName(fileName)} {string.Join(' ', arguments.Select(a => a.Length > 200 ? a[..200] + "…" : a))} " +
              $"exit={pr.ExitCode} timedOut={pr.TimedOut} ms={elapsedMs} stdout_len={pr.StdOut.Length} " +
              $"stderr=\"{pr.StdErr.Trim()}\" stdout_head=\"{head.Replace("\r", "").Replace("\n", " ")}\"");
    }

    private void Write(string s) { try { Log.Line(s); } catch { } }
}
