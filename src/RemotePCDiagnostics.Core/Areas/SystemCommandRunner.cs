using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>Runs built-in Windows tools (PowerShell, wevtutil) for areas osquery can't cover. Logs every call; never throws except on cancellation.</summary>
public sealed class SystemCommandRunner(IProcessLauncher? launcher = null, ILogger? log = null, TimeSpan? timeout = null)
{
    private readonly IProcessLauncher _launcher = launcher ?? new SystemProcessLauncher();
    public TimeSpan Timeout { get; } = timeout ?? TimeSpan.FromSeconds(60);
    public ILogger? Log { get; } = log;

    /// <summary>Full path of a tool in the Windows system directory (falls back to the bare name, resolved via PATH).</summary>
    public static string SystemTool(string exe)
    {
        var dir = Environment.SystemDirectory;
        return string.IsNullOrEmpty(dir) ? exe : Path.Combine(dir, exe);
    }

    public static string PowerShell => SystemTool(Path.Combine("WindowsPowerShell", "v1.0", "powershell.exe"));

    /// <summary>Returns the result, or null when the process couldn't start / timed out (details logged).</summary>
    public Task<ProcessResult?> RunAsync(string fileName, IReadOnlyList<string> arguments, CancellationToken ct) => RunAsync(fileName, arguments, null, ct);

    /// <summary>Same, with a longer limit for slow work (cleanup, updates); null = <see cref="Timeout"/>.</summary>
    public async Task<ProcessResult?> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan? timeout, CancellationToken ct, Action<string>? outputLine = null)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        ProcessResult pr;
        try
        {
            pr = outputLine is not null && _launcher is SystemProcessLauncher system
                ? await system.RunAsync(fileName, arguments, timeout ?? Timeout, ct, outputLine).ConfigureAwait(false)
                : await _launcher.RunAsync(fileName, arguments, timeout ?? Timeout, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            Write($"command {Path.GetFileName(fileName)} failed to start: {ex.Message}");
            return null;
        }
        var head = pr.StdOut.Length > 1024 ? pr.StdOut[..1024] : pr.StdOut;
        Write($"command {Path.GetFileName(fileName)} {string.Join(' ', arguments.Select(a => a.Length > 200 ? a[..200] + "…" : a))} " +
              $"exit={pr.ExitCode} timedOut={pr.TimedOut} ms={sw.ElapsedMilliseconds} stdout_len={pr.StdOut.Length} " +
              $"stderr=\"{pr.StdErr.Trim()}\" stdout_head=\"{head.Replace("\r", "").Replace("\n", " ")}\"");
        return pr.TimedOut ? null : pr;
    }

    private void Write(string s) { try { Log.Line(s); } catch { } }
}
