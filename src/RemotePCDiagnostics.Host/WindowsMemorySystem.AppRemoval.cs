using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// #3 / #8 / #10 app removal: detection with registry reads only (installed and provisioned Store packages, Uninstall entries, scheduled
/// task tree, ContentDeliveryManager / GameDVR values). Package sizes are measured once per package version and cached for the app's lifetime.
/// Removal runs only allowlisted packages, programs and tasks (<see cref="AppRemoval"/>, <see cref="ScheduledTaskAllowlist"/>), and it's done
/// by the Agent (<see cref="AppRemovalAgent"/>), since it needs administrator rights.
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
            if (Process.GetProcessesByName("Narrator") is { Length: > 0 } running)
            {
                foreach (var p in running)
                {
                    p.Dispose();
                }
                return true;
            }
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

    // Removing packages for every account, running uninstallers and changing system tasks need administrator rights: the Agent does them
    // (AppRemovalAgent, over the admin pipe), and checks each request against the same allowlists. The app never runs as administrator.
    // The call itself isn't cancelled (a half-read answer would break the pipe); a cancel stops waiting and leaves the Agent to finish.

    public async Task<IReadOnlyList<string>?> RemoveAppxPackagesAsync(IReadOnlyList<RemovableAppx> apps, CancellationToken ct)
    {
        if (apps.Count == 0 || apps.Any(a => AppRemoval.FindPackage(a.Name, a.PublisherId) != a)) { Log("Refused: package not on the allowlist"); return null; }
        var r = await AskAgentAsync("remove " + string.Join(", ", apps.Select(a => a.FamilyName)), b => b.RemoveAppxPackagesAsync(apps, CancellationToken.None), ct).ConfigureAwait(false);
        if (r is null) return null;
        Log($"Remove {string.Join(", ", apps.Select(a => a.FamilyName))} (Agent): ok={r.Ok} exit={r.ExitCode} left=[{(r.Left is null ? "?" : string.Join(", ", r.Left))}] {r.Error}");
        return r.Left;
    }

    public async Task<ActionOutcome> RunUninstallerAsync(UninstallCommand command, CancellationToken ct)
    {
        if (!AppRemoval.IsAllowedCommand(command)) { Log("Refused uninstall: " + command.Display); return new(false, "That uninstaller isn't one this app may run."); }
        var r = await AskAgentAsync("uninstall " + command.Display, b => b.RunUninstallerAsync(command, CancellationToken.None), ct).ConfigureAwait(false);
        if (r is null) return new(false, "Couldn't run the uninstaller. " + ElevationService.AdminRepairHint);
        Log($"Uninstall {command.Display} (Agent): ok={r.Ok} exit={r.ExitCode} {r.Error}");
        return r.Ok ? new(true, "Uninstalled.") : new(false, r.Error ?? "Couldn't run the uninstaller.");
    }

    /// <summary>The Agent's answer, or null (logged) when it isn't connected, is too old to do it, or the pipe broke.</summary>
    private async Task<AppRemovalAgent.Result?> AskAgentAsync(string what, Func<IElevatedCommandBridge, Task<AppRemovalAgent.Result>> call, CancellationToken ct)
    {
        if (agent is not { IsConnected: true }) { LogWarn($"Can't {what}: the Agent isn't connected (Admin Repair Mode is off)"); return null; }
        try { return await call(agent).WaitAsync(ct).ConfigureAwait(false); }
        catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException or IOException or ObjectDisposedException)
        {
            LogWarn($"Can't {what}: {ex.Message}");
            return null;
        }
    }

    public async Task<string?> GetScheduledTaskStateAsync(string path, CancellationToken ct)
    {
        if (!ScheduledTaskAllowlist.IsAllowed(path)) return null;
        var (folder, name) = ScheduledTaskAllowlist.Split(path);
        if (folder is null) return null;
        try
        {
            return await Task.Run(() => RemotePCDiagnostics.Core.Platform.WindowsTaskScheduler.GetTaskState(folder, name), ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { LogWarn($"Task {path} state check failed: {ex.Message}"); return null; }
    }

    public async Task<string?> SetScheduledTaskEnabledAsync(string path, bool enabled, CancellationToken ct)
    {
        if (!ScheduledTaskAllowlist.IsAllowed(path)) { Log("Refused task: " + path); return null; }
        var r = await AskAgentAsync($"{(enabled ? "enable" : "disable")} task {path}", b => b.SetScheduledTaskEnabledAsync(path, enabled, CancellationToken.None), ct).ConfigureAwait(false);
        if (r is null) return null;
        Log($"Task {path} {(enabled ? "enable" : "disable")} (Agent): ok={r.Ok} state={r.TaskState ?? "?"} {r.Error}");
        return r.Ok ? r.TaskState : null;
    }
}
