using System.Diagnostics;

namespace RemotePCDiagnostics.Core.Osquery;

/// <summary>Outcome of a finished (or abandoned) child process.</summary>
public sealed record ProcessResult(int ExitCode, string StdOut, string StdErr, bool TimedOut = false);

/// <summary>Abstraction over starting a process so the runner can be tested without osqueryi.</summary>
public interface IProcessLauncher
{
    Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken);

    /// <summary>
    /// Runs the process with <paramref name="workingDirectory"/> as its current directory when the launcher can.
    /// The default ignores the directory and calls <see cref="RunAsync(string, IReadOnlyList{string}, TimeSpan, CancellationToken)"/>.
    /// </summary>
    Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken, string? workingDirectory)
        => RunAsync(fileName, arguments, timeout, cancellationToken);

    /// <summary>
    /// Runs the process and invokes <paramref name="outputLine"/> as stdout lines arrive when the launcher supports streaming.
    /// The default ignores <paramref name="outputLine"/> and calls <see cref="RunAsync(string, IReadOnlyList{string}, TimeSpan, CancellationToken)"/>.
    /// </summary>
    Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken, Action<string>? outputLine)
        => RunAsync(fileName, arguments, timeout, cancellationToken);
}

/// <summary>Starts a real process with no console window, capturing stdout and stderr.</summary>
public sealed class SystemProcessLauncher : IProcessLauncher
{
    public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken) =>
        RunAsync(fileName, arguments, timeout, cancellationToken, outputLine: null, workingDirectory: null);

    Task<ProcessResult> IProcessLauncher.RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken, string? workingDirectory) =>
        RunAsync(fileName, arguments, timeout, cancellationToken, outputLine: null, workingDirectory: workingDirectory);

    public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout,
        CancellationToken cancellationToken, Action<string>? outputLine) =>
        RunAsync(fileName, arguments, timeout, cancellationToken, outputLine, workingDirectory: null);

    public async Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout,
        CancellationToken cancellationToken, Action<string>? outputLine, string? workingDirectory)
    {
        var psi = new ProcessStartInfo(fileName)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            // Callers that name a directory (the developer build temp folder) must not inherit the
            // executable's folder: that is often Program Files, which a non-elevated build cannot write.
            WorkingDirectory = !string.IsNullOrWhiteSpace(workingDirectory)
                ? workingDirectory
                : Path.GetDirectoryName(fileName) ?? "",
        };
        foreach (var a in arguments) psi.ArgumentList.Add(a);

        using var p = new Process { StartInfo = psi };
        p.Start();
        var stdout = outputLine is null ? p.StandardOutput.ReadToEndAsync(CancellationToken.None)
            : ReadOutputAsync(p.StandardOutput, outputLine);
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
            _ = SafeRead(stdout);
            var err = await SafeRead(stderr).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            return new ProcessResult(-1, "", err, TimedOut: true);
        }
        return new ProcessResult(p.ExitCode, await stdout.ConfigureAwait(false), await stderr.ConfigureAwait(false));
    }

    private static async Task<string> ReadOutputAsync(StreamReader reader, Action<string> outputLine)
    {
        var output = new System.Text.StringBuilder();
        while (await reader.ReadLineAsync().ConfigureAwait(false) is { } line)
        {
            output.AppendLine(line);
            outputLine(line);
        }
        return output.ToString();
    }

    private static async Task<string> SafeRead(Task<string> t)
    {
        try { return await t.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false); } catch { return ""; }
    }
}
