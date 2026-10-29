using System.Diagnostics;

namespace RemotePCDiagnostics.Core.Osquery;

/// <summary>Outcome of a finished (or abandoned) child process.</summary>
public sealed record ProcessResult(int ExitCode, string StdOut, string StdErr, bool TimedOut = false);

/// <summary>Abstraction over starting a process so the runner can be tested without osqueryi.</summary>
public interface IProcessLauncher
{
    Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken);
}

/// <summary>Starts a real process with no console window, capturing stdout and stderr.</summary>
public sealed class SystemProcessLauncher : IProcessLauncher
{
    public async Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var psi = new ProcessStartInfo(fileName)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = Path.GetDirectoryName(fileName) ?? "",
        };
        foreach (var a in arguments) psi.ArgumentList.Add(a);

        using var p = new Process { StartInfo = psi };
        p.Start();
        var stdout = p.StandardOutput.ReadToEndAsync(CancellationToken.None);
        var stderr = p.StandardError.ReadToEndAsync(CancellationToken.None);

        using var timeoutCts = new CancellationTokenSource(timeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);
        try
        {
            await p.WaitForExitAsync(linked.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            try { p.Kill(entireProcessTree: true); } catch { /* already exited */ }
            cancellationToken.ThrowIfCancellationRequested();
            return new ProcessResult(-1, "", await SafeRead(stderr).ConfigureAwait(false), TimedOut: true);
        }
        return new ProcessResult(p.ExitCode, await stdout.ConfigureAwait(false), await stderr.ConfigureAwait(false));
    }

    private static async Task<string> SafeRead(Task<string> t)
    {
        try { return await t.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false); } catch { return ""; }
    }
}
