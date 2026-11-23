using System.Diagnostics;
using System.Text;
using RemotePCDiagnostics.Agent.Core;

namespace RemotePCDiagnostics.Agent;

/// <summary>
/// Starts Setup as a SYSTEM scheduled task. The service control manager's job does not allow breakaway, so a Setup
/// started as a child is killed when that service process exits, which is during the upgrade that Setup itself requested.
/// </summary>
internal static class ScheduledSetupLaunch
{
    public static bool TryStart(string setupExe, string arguments, string stagingDirectory, Action<string>? log, out ScheduledSetupWait? wait)
    {
        wait = null;
        if (!OperatingSystem.IsWindows())
            return false;

        try
        {
            Directory.CreateDirectory(stagingDirectory);
            var exitPath = Path.Combine(stagingDirectory, ScheduledSetup.ExitCodeFileName);
            var batchPath = Path.Combine(stagingDirectory, ScheduledSetup.BatchFileName);
            var xmlPath = Path.Combine(stagingDirectory, ScheduledSetup.TaskXmlFileName);
            try
            {
                if (File.Exists(exitPath))
                    File.Delete(exitPath);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                log?.Invoke($"[rpcd-update] Could not clear the previous Setup exit code: {ex.Message}");
            }

            var batch = ScheduledSetup.BatchScript(setupExe, arguments, exitPath);
            if (!ScheduledSetup.IsAscii(batch))
            {
                log?.Invoke("[rpcd-update] Setup's command line is not ASCII, so it cannot be handed to a cmd task.");
                return false;
            }

            var cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
            var xml = ScheduledSetup.TaskXml(cmd, "/d /c " + WindowsCommandLine.Quote(batchPath), stagingDirectory);
            File.WriteAllText(batchPath, batch, Encoding.ASCII);
            File.WriteAllText(xmlPath, xml, new UnicodeEncoding(bigEndian: false, byteOrderMark: true));

            var task = WindowsCommandLine.Quote(AgentLayout.SetupTaskName);
            // A previous update may still be registered. End it before replacing the task, or /Create /F fails while it runs.
            // Missing-task errors here are normal and are not logged.
            RunSchtasks("/End /TN " + task, log, logFailure: false);
            RunSchtasks("/Delete /F /TN " + task, log, logFailure: false);
            var (created, createOut) = RunSchtasks("/Create /F /TN " + task + " /XML " + WindowsCommandLine.Quote(xmlPath), log);
            if (created != 0)
            {
                log?.Invoke($"[rpcd-update] Could not register the Setup task ({created}): {createOut}");
                return false;
            }
            var (started, startOut) = RunSchtasks("/Run /TN " + task, log);
            if (started != 0)
            {
                log?.Invoke($"[rpcd-update] Could not start the Setup task ({started}): {startOut}");
                RunSchtasks("/Delete /F /TN " + task, log);
                return false;
            }

            log?.Invoke("[rpcd-update] Setup is running as a scheduled task, outside this service's job.");
            wait = new ScheduledSetupWait(exitPath, task, log);
            return true;
        }
        catch (Exception ex)
        {
            log?.Invoke($"[rpcd-update] Could not start Setup outside the service job: {ex.Message}");
            wait = null;
            return false;
        }
    }

    private static (int ExitCode, string Output) RunSchtasks(string arguments, Action<string>? log, bool logFailure = true)
    {
        var exe = Path.Combine(Environment.SystemDirectory, "schtasks.exe");
        if (!File.Exists(exe))
            exe = "schtasks.exe";
        try
        {
            using var proc = Process.Start(new ProcessStartInfo
            {
                FileName = exe,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            });
            if (proc is null)
                return (-1, "schtasks.exe did not start.");
            var stdout = proc.StandardOutput.ReadToEnd();
            var stderr = proc.StandardError.ReadToEnd();
            proc.WaitForExit(30_000);
            var output = (stdout + "\n" + stderr).Trim();
            if (proc.ExitCode != 0 && logFailure)
                log?.Invoke($"[rpcd-update] schtasks {arguments} -> {proc.ExitCode} {output}".Trim());
            return (proc.ExitCode, output);
        }
        catch (Exception ex)
        {
            log?.Invoke($"[rpcd-update] schtasks {arguments} did not run: {ex.Message}");
            return (-1, ex.Message);
        }
    }
}

/// <summary>
/// Waits until the task's cmd script has written Setup's exit code. Gives up with <see cref="ScheduledSetup.NoExitCode"/> when
/// the task has stopped without writing one (killed at its time limit, or cmd failed) or after <see cref="ScheduledSetup.WaitLimit"/>.
/// Does not stop the task if this process is cancelled.
/// </summary>
internal sealed class ScheduledSetupWait : IDisposable
{
    private readonly string _exitPath;
    private readonly string _taskArgument;
    private readonly Action<string>? _log;
    private readonly Func<string?> _taskState;
    private int _disposed;

    public ScheduledSetupWait(string exitPath, string taskArgument, Action<string>? log, Func<string?>? taskState = null)
    {
        _exitPath = exitPath;
        _taskArgument = taskArgument;
        _log = log;
        _taskState = taskState ?? (() => QueryTaskState(AgentLayout.SetupTaskName));
    }

    public async Task<int> WaitAsync(CancellationToken ct)
    {
        var started = DateTime.UtcNow;
        var nextCheck = started + ScheduledSetup.StateCheckAfter;
        while (true)
        {
            var code = ReadCode();
            if (code is int exit)
            {
                Cleanup();
                return exit;
            }

            var now = DateTime.UtcNow;
            if (now - started > ScheduledSetup.WaitLimit)
            {
                _log?.Invoke($"[rpcd-update] Setup's task has not reported an exit code after {(int)ScheduledSetup.WaitLimit.TotalMinutes} minutes. Giving up on it.");
                Cleanup();
                return ScheduledSetup.NoExitCode;
            }

            if (now >= nextCheck)
            {
                nextCheck = now + ScheduledSetup.StateCheckEvery;
                var state = _taskState();
                if (!ScheduledSetup.MayStillRun(state))
                {
                    // The script writes the code as its last step; give a write that just landed one more look.
                    await Task.Delay(2000, ct).ConfigureAwait(false);
                    if (ReadCode() is int late)
                    {
                        Cleanup();
                        return late;
                    }
                    _log?.Invoke($"[rpcd-update] Setup's task is {state?.Trim()} and did not write an exit code. Setup was stopped or never ran.");
                    Cleanup();
                    return ScheduledSetup.NoExitCode;
                }
            }

            await Task.Delay(500, ct).ConfigureAwait(false);
        }
    }

    private static string? QueryTaskState(string taskName)
    {
        if (!OperatingSystem.IsWindows())
            return null;
        try
        {
            return RemotePCDiagnostics.Core.Platform.WindowsTaskScheduler.GetTaskState("\\", taskName);
        }
        catch
        {
            return null;
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;
        // The exit file means Setup's script finished. Cancelling the wait leaves the task running on purpose.
        if (ReadCode() is not null)
            Cleanup();
    }

    private int? ReadCode()
    {
        try
        {
            if (!File.Exists(_exitPath))
                return null;
            return ScheduledSetup.ParseExitCode(File.ReadAllText(_exitPath));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private void Cleanup()
    {
        var exe = Path.Combine(Environment.SystemDirectory, "schtasks.exe");
        if (!File.Exists(exe))
            exe = "schtasks.exe";
        try
        {
            using var proc = Process.Start(new ProcessStartInfo
            {
                FileName = exe,
                Arguments = "/Delete /F /TN " + _taskArgument,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            });
            proc?.WaitForExit(15_000);
        }
        catch (Exception ex)
        {
            _log?.Invoke($"[rpcd-update] Could not remove the Setup task: {ex.Message}");
        }

        foreach (var name in new[] { ScheduledSetup.BatchFileName, ScheduledSetup.TaskXmlFileName, ScheduledSetup.ExitCodeFileName })
        {
            try
            {
                var path = Path.Combine(Path.GetDirectoryName(_exitPath) ?? "", name);
                if (File.Exists(path))
                    File.Delete(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // The next update overwrites these.
            }
        }
    }
}
