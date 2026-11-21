using System.Diagnostics;

namespace RemotePCDiagnostics.Agent;

/// <summary>
/// Ends a running Remote PC Diagnostics before Setup initializes.
/// The Host holds <c>Global\RemotePCDiagnostics.Host</c> for the whole technician session.
/// Inno Setup checks that mutex during initialization, and <c>/SUPPRESSMSGBOXES</c> answers the prompt with Cancel,
/// so Setup exits 1 before <c>CloseApplications</c> can run. Only the agent service (session 0) calls this.
/// The elevated helper is inside the Host's job and would be ended with it.
/// </summary>
internal static class RpcdHostShutdown
{
    public const string HostProcessName = "RemotePCDiagnostics.Host";

    public static void CloseRunningHost(Action<string>? log)
    {
        if (!OperatingSystem.IsWindows())
            return;

        Process[] running;
        try
        {
            running = Process.GetProcessesByName(HostProcessName);
        }
        catch (Exception ex)
        {
            log?.Invoke($"[rpcd-update] Could not look for Remote PC Diagnostics: {ex.Message}");
            return;
        }

        if (running.Length == 0)
            return;

        log?.Invoke("[rpcd-update] Closing Remote PC Diagnostics before Setup. A silent install exits 1 while the app mutex is held.");
        foreach (var process in running)
        {
            try
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                    process.WaitForExit(10_000);
                }
            }
            catch (Exception ex)
            {
                log?.Invoke($"[rpcd-update] Could not close Remote PC Diagnostics ({process.Id}): {ex.Message}");
            }
            finally
            {
                process.Dispose();
            }
        }

        var until = DateTime.UtcNow.AddSeconds(15);
        while (DateTime.UtcNow < until && MutexHeld())
            Thread.Sleep(200);
        if (MutexHeld())
            log?.Invoke("[rpcd-update] Remote PC Diagnostics is still running. Setup will try to close it.");
        else
            log?.Invoke("[rpcd-update] Remote PC Diagnostics has exited.");
    }

    /// <summary>True when the instance mutex exists. Access denied counts as held: another session created it.</summary>
    private static bool MutexHeld()
    {
        try
        {
            using var mutex = Mutex.OpenExisting(@"Global\RemotePCDiagnostics.Host");
            return true;
        }
        catch (WaitHandleCannotBeOpenedException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return true;
        }
    }
}
