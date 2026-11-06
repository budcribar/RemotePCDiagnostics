using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Optimizations;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// #3 / #8 / #10 app removal: detection with registry reads only (installed and provisioned Store packages, Uninstall entries, scheduled
/// task tree, ContentDeliveryManager / GameDVR values). Package sizes are measured once per package version and cached for the app's lifetime.
/// Removal runs only allowlisted packages, programs and tasks (<see cref="AppRemoval"/>, <see cref="ScheduledTaskAllowlist"/>).
/// </summary>
public sealed partial class WindowsMemorySystem
{
    private const string ProvisionedKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications";
    private const string UninstallKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    private const string TaskTreeKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree";

    /// <summary>Package sizes by the set of installed full names (a new version gets measured again). Shared by every instance.</summary>
    private static readonly ConcurrentDictionary<string, long?> s_packageSizes = new(StringComparer.OrdinalIgnoreCase);

    public AppRemovalInfo? ReadRemovableApps()
    {
        try
        {
            var found = new Dictionary<string, (RemovableAppx App, bool User, bool Prov, SortedSet<string> FullNames, HashSet<string> Folders)>(StringComparer.OrdinalIgnoreCase);
            void Add(string fullName, bool user, string? folder)
            {
                if (AppRemoval.ParseFullName(fullName) is not { } id || AppRemoval.FindPackage(id.Name, id.PublisherId) is not { } app) return;
                if (!found.TryGetValue(app.FamilyName, out var f)) f = (app, false, false, new SortedSet<string>(StringComparer.OrdinalIgnoreCase), new HashSet<string>(StringComparer.OrdinalIgnoreCase));
                f.FullNames.Add(fullName);
                f.Folders.Add(folder is { Length: > 0 } ? folder : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WindowsApps", fullName));
                found[app.FamilyName] = (f.App, f.User || user, f.Prov || !user, f.FullNames, f.Folders);
            }

            using (var pk = Registry.CurrentUser.OpenSubKey(PackagesKey))
                foreach (var full in pk?.GetSubKeyNames() ?? [])
                {
                    using var k = pk!.OpenSubKey(full);
                    Add(full, true, k?.GetValue("PackageRootFolder") as string);
                }
            using (var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
            using (var prov = hklm.OpenSubKey(ProvisionedKey))
                foreach (var full in prov?.GetSubKeyNames() ?? [])
                    Add(full, false, null);

            var packages = found.Values.Select(f => new InstalledAppx(f.App.Name, f.App.PublisherId, f.User, f.Prov,
                s_packageSizes.GetOrAdd(string.Join("|", f.FullNames), _ => PackageSize(f.App, f.Folders)))).ToList();

            return new(packages, ReadRemovablePrograms(), ReadAppRemovalSettings(), ReadAllowlistedTasks(), ReadNarratorInUse());
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { LogWarn("App removal read failed: " + ex.Message); return null; }
    }

    /// <summary>Install folders plus this account's app data (%LOCALAPPDATA%\Packages\&lt;family&gt;). Null when nothing could be read.</summary>
    private long? PackageSize(RemovableAppx app, IEnumerable<string> folders)
    {
        long sum = 0;
        var any = false;
        foreach (var dir in folders.Append(Path.Combine(LocalAppData, "Packages", app.FamilyName)))
        {
            try
            {
                if (!Directory.Exists(dir)) continue;
                any = true;
                foreach (var f in Directory.EnumerateFiles(dir, "*", new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint }))
                    try { sum += new FileInfo(f).Length; } catch (IOException) { }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { Log($"Size {dir}: {ex.Message}"); }
        }
        return any ? sum : null;
    }

    /// <summary>Uninstall entries (64-bit, 32-bit and per-user) whose DisplayName and Publisher match an allowlisted program.</summary>
    private List<UninstallEntry> ReadRemovablePrograms()
    {
        var list = new List<UninstallEntry>();
        foreach (var (hive, label, view) in new[]
        {
            (RegistryHive.LocalMachine, "HKLM64", RegistryView.Registry64), (RegistryHive.LocalMachine, "HKLM32", RegistryView.Registry32),
            (RegistryHive.CurrentUser, "HKCU", RegistryView.Registry64),
        })
        {
            try
            {
                using var root = RegistryKey.OpenBaseKey(hive, view);
                using var un = root.OpenSubKey(UninstallKey);
                foreach (var name in un?.GetSubKeyNames() ?? [])
                {
                    using var k = un!.OpenSubKey(name);
                    if (k?.GetValue("DisplayName") is not string display) continue;
                    var p = new UninstallEntry(label, name, display, k.GetValue("Publisher") as string, k.GetValue("QuietUninstallString") as string,
                        k.GetValue("UninstallString") as string, k.GetValue("WindowsInstaller") is int wi && wi == 1,
                        k.GetValue("EstimatedSize") is int kb && kb > 0 ? kb * 1024L : null, k.GetValue("DisplayVersion") as string);
                    if (AppRemoval.Programs.Any(a => a.Matches(p))) list.Add(p);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException) { Log($"Uninstall keys ({label}): {ex.Message}"); }
        }
        return list;
    }

    /// <summary>
    /// Narrator running, or listed in the Accessibility "Configuration" value (start at sign-in for this account, HKCU; on the sign-in
    /// screen, HKLM). Null when it couldn't be read.
    /// </summary>
    private bool? ReadNarratorInUse()
    {
        try
        {
            if (Process.GetProcessesByName("Narrator") is { Length: > 0 } running) { foreach (var p in running) p.Dispose(); return true; }
            const string acc = @"Software\Microsoft\Windows NT\CurrentVersion\Accessibility";
            using var hkcu = Registry.CurrentUser.OpenSubKey(acc);
            using var hklm = Registry.LocalMachine.OpenSubKey(acc);
            bool Listed(RegistryKey? k) => (k?.GetValue("Configuration") as string ?? "").Split(',', StringSplitOptions.TrimEntries).Any(x => x.Equals("narrator", StringComparison.OrdinalIgnoreCase));
            return Listed(hkcu) || Listed(hklm);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException) { Log("Narrator state: " + ex.Message); return null; }
    }

    private Dictionary<string, int?> ReadAppRemovalSettings()
    {
        var d = new Dictionary<string, int?>(StringComparer.OrdinalIgnoreCase);
        foreach (var s in AppRemoval.ContentDeliverySettings.Concat(AppRemoval.XboxSettings).Append(RegistryAllowlist.NarratorWinEnterLaunch))
            try { d[s.Target] = ReadDword(s); }
            catch (Exception ex) when (ex is InvalidOperationException or UnauthorizedAccessException or System.Security.SecurityException or IOException) { Log($"{s.Target}: {ex.Message}"); }
        return d;
    }

    /// <summary>Allowlisted tasks that exist, from Task Scheduler's registry tree (no PowerShell).</summary>
    private List<string> ReadAllowlistedTasks()
    {
        var list = new List<string>();
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            foreach (var rule in ScheduledTaskAllowlist.All)
            {
                using var folder = hklm.OpenSubKey(TaskTreeKey + rule.Folder.TrimEnd('\\'));
                if (folder is null) continue;
                foreach (var name in rule.NamePrefix ? folder.GetSubKeyNames().Where(n => n.StartsWith(rule.Name, StringComparison.OrdinalIgnoreCase)) : new[] { rule.Name })
                {
                    using var task = folder.OpenSubKey(name);
                    var path = rule.Folder + name;
                    if (task?.GetValue("Id") is string && ScheduledTaskAllowlist.IsAllowed(path)) list.Add(path);
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException) { LogWarn("Task tree read failed: " + ex.Message); }
        return list;
    }

    public async Task<IReadOnlyList<string>?> RemoveAppxPackagesAsync(IReadOnlyList<RemovableAppx> apps, CancellationToken ct)
    {
        if (apps.Count == 0 || apps.Any(a => AppRemoval.FindPackage(a.Name, a.PublisherId) != a)) { Log("Refused: package not on the allowlist"); return null; }
        var r = await RunPowerShellAsync(AppRemoval.RemoveScript(apps), ct, TimeSpan.FromMinutes(10)).ConfigureAwait(false);
        var left = AppRemoval.ParseLeft(r.Output);
        Log($"Remove {string.Join(", ", apps.Select(a => a.FamilyName))}: exit={r.ExitCode} left=[{(left is null ? "?" : string.Join(", ", left))}] err={r.Error.Trim()}");
        return left;
    }

    public async Task<ActionOutcome> RunUninstallerAsync(UninstallCommand command, CancellationToken ct)
    {
        if (!AppRemoval.IsAllowedCommand(command)) { Log("Refused uninstall: " + command.Display); return new(false, "That uninstaller isn't one this app may run."); }
        var file = command.Msi ? Path.Combine(Environment.SystemDirectory, "msiexec.exe") : command.Path;
        if (!File.Exists(file)) return new(false, "The uninstaller wasn't found.");
        var psi = new ProcessStartInfo(file) { UseShellExecute = false, CreateNoWindow = true };
        foreach (var a in command.Arguments) psi.ArgumentList.Add(a);
        try
        {
            using var p = Process.Start(psi)!;
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromMinutes(15));
            try
            {
                await p.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                // Stuck past the time limit: end it. A cancel by the user leaves the uninstaller running, since killing it mid-way can leave the app half removed.
                try { p.Kill(entireProcessTree: true); } catch { }
                throw;
            }
            Log($"Uninstall {command.Display}: exit={p.ExitCode}");
            // msiexec: 0 = done, 3010 = done, restart needed, 1605 = not installed any more.
            var ok = p.ExitCode is 0 or 3010 or 1605;
            // Inno Setup uninstallers (unins000.exe) hand over to a temporary copy and exit at once: wait for the uninstaller file to go.
            if (!command.Msi && ok)
            {
                var until = DateTime.UtcNow.AddMinutes(3);
                while (File.Exists(file) && DateTime.UtcNow < until) await Task.Delay(1000, ct).ConfigureAwait(false);
            }
            return ok ? new(true, "Uninstalled.") : new(false, $"The uninstaller ended with code {p.ExitCode}.");
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException || (ex is OperationCanceledException && !ct.IsCancellationRequested))
        {
            LogWarn($"Uninstall {command.Display} failed: {ex.Message}");
            return new(false, "Couldn't run the uninstaller.");
        }
    }

    public async Task<string?> GetScheduledTaskStateAsync(string path, CancellationToken ct)
    {
        if (!ScheduledTaskAllowlist.IsAllowed(path)) return null;
        var r = await RunPowerShellAsync(ScheduledTaskAllowlist.StateScript(path), ct).ConfigureAwait(false);
        return TaskState(r.ExitCode, r.Output);
    }

    public async Task<string?> SetScheduledTaskEnabledAsync(string path, bool enabled, CancellationToken ct)
    {
        if (!ScheduledTaskAllowlist.IsAllowed(path)) { Log("Refused task: " + path); return null; }
        var r = await RunPowerShellAsync(ScheduledTaskAllowlist.SetScript(path, enabled), ct).ConfigureAwait(false);
        Log($"Task {path} {(enabled ? "enable" : "disable")}: exit={r.ExitCode} out={r.Output.Trim()} err={r.Error.Trim()}");
        return TaskState(r.ExitCode, r.Output);
    }

    private static string? TaskState(int exitCode, string output)
    {
        if (exitCode != 0) return null;
        var last = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).LastOrDefault();
        return string.IsNullOrEmpty(last) ? null : last;
    }
}
