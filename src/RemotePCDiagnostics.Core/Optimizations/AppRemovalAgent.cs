using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Optimizations;

/// <summary>
/// The part of app removal that needs administrator rights, run by the Agent (the elevated helper or the agent service) when the app
/// asks over the admin pipe: removing Store packages for every account and their provisioned copies, running an allowlisted
/// program's own uninstaller, and turning allowlisted scheduled tasks off or on. The app never runs as administrator. Every request is
/// checked again here against <see cref="AppRemoval"/> and <see cref="ScheduledTaskAllowlist"/>, and the scripts are built here, so
/// the app only ever names what to remove, never how.
/// </summary>
public static class AppRemovalAgent
{
    public static readonly TimeSpan RemoveTimeout = TimeSpan.FromMinutes(10);
    public static readonly TimeSpan UninstallTimeout = TimeSpan.FromMinutes(15);
    public static readonly TimeSpan TaskTimeout = TimeSpan.FromMinutes(1);
    /// <summary>How long to wait for an Inno Setup uninstaller's file to go after it hands over to its temporary copy.</summary>
    public static TimeSpan UninstallerGoneWait { get; set; } = TimeSpan.FromMinutes(3);

    public sealed record Result(bool Ok, string? Error = null, IReadOnlyList<string>? Left = null, int ExitCode = 0, string? TaskState = null);

    /// <summary>
    /// Removes allowlisted packages for all users (<see cref="AppRemoval.RemoveScript"/>). <see cref="Result.Left"/> is the family names
    /// still installed, or null when the script didn't finish.
    /// </summary>
    public static async Task<Result> RemoveAppxAsync(IProcessLauncher launcher, IReadOnlyList<(string Name, string PublisherId)> requested, CancellationToken ct)
    {
        var apps = new List<RemovableAppx>();
        foreach (var (name, publisher) in requested)
        {
            if (AppRemoval.FindPackage(name, publisher) is not { } app) return new(false, $"{name}_{publisher} isn't a package this app may remove.");
            apps.Add(app);
        }
        if (apps.Count == 0) return new(false, "No packages were named.");
        var r = await launcher.RunAsync(SystemCommandRunner.PowerShell, SystemCommandRunner.PowerShellArgs(AppRemoval.RemoveScript(apps)), RemoveTimeout, ct).ConfigureAwait(false);
        var left = r.TimedOut ? null : AppRemoval.ParseLeft(r.StdOut);
        return new(left is not null, left is null ? (r.TimedOut ? "Removing the packages timed out." : "The removal didn't finish. " + r.StdErr.Trim()) : null, left, r.ExitCode);
    }

    /// <summary>Runs an uninstaller <see cref="AppRemoval.IsAllowedCommand"/> accepts, and waits for it to finish.</summary>
    public static async Task<Result> RunUninstallerAsync(IProcessLauncher launcher, UninstallCommand command, CancellationToken ct, IReadOnlyList<string>? roots = null)
    {
        if (!AppRemoval.IsAllowedCommand(command, roots)) return new(false, "That uninstaller isn't one this app may run.");
        var file = command.Msi ? Path.Combine(Environment.SystemDirectory, "msiexec.exe") : command.Path;
        if (!File.Exists(file)) return new(false, "The uninstaller wasn't found.");
        var r = await launcher.RunAsync(file, command.Arguments, UninstallTimeout, ct).ConfigureAwait(false);
        if (r.TimedOut) return new(false, "The uninstaller didn't finish in time.", ExitCode: -1);
        // msiexec: 0 = done, 3010 = done, restart needed, 1605 = not installed any more.
        var ok = r.ExitCode is 0 or 3010 or 1605;
        // Inno Setup uninstallers (unins000.exe) hand over to a temporary copy and exit at once: wait for the uninstaller file to go.
        if (!command.Msi && ok)
        {
            var until = DateTime.UtcNow + UninstallerGoneWait;
            while (File.Exists(file) && DateTime.UtcNow < until) await Task.Delay(1000, ct).ConfigureAwait(false);
        }
        return ok ? new(true, ExitCode: r.ExitCode) : new(false, $"The uninstaller ended with code {r.ExitCode}.", ExitCode: r.ExitCode);
    }

    /// <summary>Turns an allowlisted scheduled task off or on; <see cref="Result.TaskState"/> is its state afterwards.</summary>
    public static async Task<Result> SetScheduledTaskAsync(IProcessLauncher launcher, string? path, bool enabled, CancellationToken ct)
    {
        if (!ScheduledTaskAllowlist.IsAllowed(path)) return new(false, $"{path} isn't a scheduled task this app may change.");
        if (OperatingSystem.IsWindows() && launcher is SystemProcessLauncher)
        {
            var (folder, name) = ScheduledTaskAllowlist.Split(path!);
            if (folder is null) return new(false, $"{path} isn't a scheduled task this app may change.");
            try
            {
                var nativeState = await Task.Run(() => Platform.WindowsTaskScheduler.SetTaskEnabled(folder, name, enabled), CancellationToken.None)
                    .WaitAsync(TaskTimeout, ct).ConfigureAwait(false);
                return new(true, ExitCode: 0, TaskState: nativeState);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (TimeoutException) { return new(false, "Task Scheduler didn't answer in time.", ExitCode: -1); }
            catch (Exception ex) { return new(false, ex.Message, ExitCode: 1); }
        }
        var r = await launcher.RunAsync(SystemCommandRunner.PowerShell, SystemCommandRunner.PowerShellArgs(ScheduledTaskAllowlist.SetScript(path!, enabled)), TaskTimeout, ct).ConfigureAwait(false);
        var state = r.ExitCode == 0 && !r.TimedOut
            ? r.StdOut.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).LastOrDefault()
            : null;
        return string.IsNullOrEmpty(state) ? new(false, r.TimedOut ? "Task Scheduler didn't answer in time." : r.StdErr.Trim(), ExitCode: r.ExitCode)
            : new(true, ExitCode: r.ExitCode, TaskState: state);
    }
}
