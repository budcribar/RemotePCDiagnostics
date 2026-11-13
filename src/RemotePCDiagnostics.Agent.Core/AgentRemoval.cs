namespace RemotePCDiagnostics.Agent.Core;

public sealed record AgentCleanupResult(IReadOnlyList<string> Removed, IReadOnlyList<string> Skipped);

/// <summary>
/// What <c>uninstall</c> deletes, and when the agent should remove itself because the desktop app is gone.
/// The protected state folder (undo journal, workflow, benchmarks) is never in the list.
/// A cached copy under <c>%ProgramData%\RemotePCDiagnostics\app</c> is the agent's download, not a user install:
/// a fleet agent that has never seen Setup or the Store package stays installed.
/// </summary>
public static class AgentRemoval
{
    public const int AbsentPollsBeforeRemoval = 2;

    public static readonly string[] ScheduledTaskNames =
    [
        AgentLayout.ScheduledTaskName,
        AgentLayout.ServiceName,
        "Remote PC Diagnostics Agent",
    ];

    public static IReadOnlyList<string> OwnedFiles(string programDataDir)
    {
        var root = programDataDir;
        return
        [
            Path.Combine(root, AgentLayout.ConfigFileName),
            Path.Combine(root, AgentLayout.StatusFileName),
            Path.Combine(root, AgentLayout.HostWatchFileName),
            Path.Combine(root, "logs", AgentLayout.AgentLogFileName),
        ];
    }

    public static bool IsOwnedFileName(string? path)
    {
        var name = Path.GetFileName(path ?? "");
        return name.Equals(AgentLayout.ConfigFileName, StringComparison.OrdinalIgnoreCase)
            || name.Equals(AgentLayout.StatusFileName, StringComparison.OrdinalIgnoreCase)
            || name.Equals(AgentLayout.HostWatchFileName, StringComparison.OrdinalIgnoreCase)
            || name.Equals(AgentLayout.AgentLogFileName, StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsAgentInstallDirectory(string? directory)
    {
        if (string.IsNullOrWhiteSpace(directory)) return false;
        var name = Path.GetFileName(directory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        return name.Equals(AgentLayout.InstallFolderName, StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsPathUnder(string? path, string? directory)
    {
        if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(directory)) return false;
        var full = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var root = Path.GetFullPath(directory).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return full.Equals(root, StringComparison.OrdinalIgnoreCase)
            || full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    public static bool ShouldScheduleInstallDirectoryDelete(string? processPath, string installDir) =>
        IsAgentInstallDirectory(installDir) && IsPathUnder(processPath, installDir);

    /// <summary>cmd.exe arguments that retry <c>rmdir</c> after this process has released the executable. <c>ping</c> waits without reading the console (<c>timeout</c> fails when stdin is not a console).</summary>
    public static string DelayedDirectoryDeleteArguments(string directory)
    {
        var quoted = WindowsCommandLine.Quote(Path.GetFullPath(directory));
        return "/c ping -n 6 127.0.0.1 >nul & rmdir /s /q " + quoted + " & ping -n 6 127.0.0.1 >nul & rmdir /s /q " + quoted;
    }

    public static bool CommandLaunchesAgent(string? command)
    {
        if (string.IsNullOrWhiteSpace(command)) return false;
        return command.Contains(AgentLayout.AgentExeName, StringComparison.OrdinalIgnoreCase);
    }

    public static bool ShouldRemoveRunValue(string? valueName, string? command)
    {
        if (string.Equals(valueName, AgentLayout.RunValueName, StringComparison.OrdinalIgnoreCase)) return true;
        if (string.Equals(valueName, AgentLayout.ScheduledTaskName, StringComparison.OrdinalIgnoreCase)) return true;
        if (string.Equals(valueName, "Remote PC Diagnostics Agent", StringComparison.OrdinalIgnoreCase)) return true;
        return CommandLaunchesAgent(command);
    }

    public static string TaskLeafName(string? taskName)
    {
        if (string.IsNullOrWhiteSpace(taskName)) return "";
        var trimmed = taskName.Trim();
        var slash = Math.Max(trimmed.LastIndexOf('\\'), trimmed.LastIndexOf('/'));
        return slash >= 0 && slash < trimmed.Length - 1 ? trimmed[(slash + 1)..] : trimmed;
    }

    public static bool ShouldDeleteScheduledTask(string? taskName, string? action)
    {
        var leaf = TaskLeafName(taskName);
        foreach (var known in ScheduledTaskNames)
        {
            if (leaf.Equals(known, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return CommandLaunchesAgent(action);
    }

    public static bool IsAgentStartupShortcut(string? fileName)
    {
        var name = Path.GetFileName(fileName ?? "");
        if (name.Length == 0) return false;
        if (name.Equals(AgentLayout.AgentExeName.Replace(".exe", ".lnk", StringComparison.OrdinalIgnoreCase), StringComparison.OrdinalIgnoreCase))
            return true;
        if (name.Equals("Remote PC Diagnostics Agent.lnk", StringComparison.OrdinalIgnoreCase)) return true;
        return name.Contains(AgentLayout.AgentExeName, StringComparison.OrdinalIgnoreCase)
            || name.Contains("RemotePCDiagnostics.Agent", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Task paths to delete. A block that names a known agent task, or that mentions the agent executable, is removed.
    /// The executable check does not depend on the English label "Task To Run", so a localized <c>schtasks</c> listing still matches.
    /// </summary>
    public static IReadOnlyList<string> TaskNamesToDelete(string? schtasksListOutput)
    {
        var names = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(schtasksListOutput)) return names;

        var text = schtasksListOutput.Replace("\r\n", "\n", StringComparison.Ordinal);
        foreach (var block in text.Split("\n\n", StringSplitOptions.RemoveEmptyEntries))
        {
            string? path = null;
            var launchesAgent = false;
            var knownName = false;
            foreach (var raw in block.Split('\n'))
            {
                var line = raw.Trim();
                if (line.Length == 0) continue;
                var colon = line.IndexOf(':');
                var value = colon >= 0 ? line[(colon + 1)..].Trim() : line;
                if (path is null && value.StartsWith('\\') && value.Length > 1)
                    path = value;
                if (CommandLaunchesAgent(line))
                    launchesAgent = true;
                var leaf = TaskLeafName(value);
                foreach (var known in ScheduledTaskNames)
                {
                    if (leaf.Equals(known, StringComparison.OrdinalIgnoreCase))
                        knownName = true;
                }
            }

            if (path is null || (!launchesAgent && !knownName)) continue;
            if (seen.Add(path))
                names.Add(path);
        }
        return names;
    }

    /// <summary>Setup <c>RemotePCDiagnostics.Host.exe</c> locations. The ProgramData app cache is intentionally absent.</summary>
    public static IReadOnlyList<string> SetupHostExeCandidates(string? programFiles, string? programFilesX86)
    {
        var list = new List<string>();
        void Add(string? root)
        {
            if (string.IsNullOrWhiteSpace(root)) return;
            list.Add(Path.Combine(root, "RemotePCDiagnostics", "RemotePCDiagnostics.Host.exe"));
            list.Add(Path.Combine(root, "Remote PC Diagnostics", "RemotePCDiagnostics.Host.exe"));
        }
        Add(programFiles);
        if (!string.IsNullOrWhiteSpace(programFilesX86)
            && !string.Equals(programFiles, programFilesX86, StringComparison.OrdinalIgnoreCase))
            Add(programFilesX86);
        return list;
    }

    public static bool IsDesktopMsixPackage(string? packageFullName)
    {
        if (string.IsNullOrWhiteSpace(packageFullName)) return false;
        var name = packageFullName.Trim();
        var cut = name.IndexOf('_');
        if (cut >= 0) name = name[..cut];
        if (name.EndsWith(".Agent", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith(".RemotePCDiagnosticsAgent", StringComparison.OrdinalIgnoreCase))
            return false;
        if (name.Equals("RemotePCDiagnostics", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Equals(AgentLayout.DefaultMsixPackageName, StringComparison.OrdinalIgnoreCase)) return true;
        return name.EndsWith(".RemotePCDiagnostics", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsDesktopUninstallRegistryKey(string? keyName)
    {
        if (string.IsNullOrWhiteSpace(keyName)) return false;
        if (keyName.Contains(AgentLayout.AgentMsiUpgradeCode, StringComparison.OrdinalIgnoreCase)) return false;
        return keyName.Contains(AgentLayout.DesktopUninstallAppId, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Deletes the enrollment key, link status, host-seen flag, agent log, download cache, and (when asked) the
    /// install directory. Refuses the state folder and any install path whose folder name is not the agent directory.
    /// </summary>
    public static AgentCleanupResult DeleteOwnedFiles(string programDataDir, string? installDir, bool deleteInstallDirectory, IEnumerable<string>? extraFiles = null)
    {
        var removed = new List<string>();
        var skipped = new List<string>();
        var files = new List<string>(OwnedFiles(programDataDir));
        if (extraFiles is not null)
        {
            foreach (var extra in extraFiles)
            {
                if (!string.IsNullOrWhiteSpace(extra))
                    files.Add(extra);
            }
        }

        foreach (var file in files.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!IsOwnedFileName(file) || IsProtected(file, programDataDir))
            {
                skipped.Add(file);
                continue;
            }
            TryDeleteFile(file, removed);
        }

        var cache = Path.Combine(programDataDir, AgentLayout.AppCacheFolderName);
        TryDeleteDirectory(cache, programDataDir, installDir: null, removed, skipped);

        if (deleteInstallDirectory && installDir is not null)
            TryDeleteDirectory(installDir, programDataDir, installDir, removed, skipped);

        return new AgentCleanupResult(removed, skipped);
    }

    private static bool IsProtected(string path, string programDataDir)
    {
        var state = Path.Combine(programDataDir, "state");
        return IsPathUnder(path, state);
    }

    private static void TryDeleteFile(string path, List<string> removed)
    {
        try
        {
            if (IsReparse(path)) return;
            if (!File.Exists(path)) return;
            File.SetAttributes(path, FileAttributes.Normal);
            File.Delete(path);
            removed.Add(path);
        }
        catch
        {
            // Best effort. A file still in use is removed by the delayed install-directory delete when it lives there.
        }
    }

    private static void TryDeleteDirectory(string path, string programDataDir, string? installDir, List<string> removed, List<string> skipped)
    {
        try
        {
            if (!Directory.Exists(path)) return;
            if (IsReparse(path) || IsProtected(path, programDataDir))
            {
                skipped.Add(path);
                return;
            }
            var cache = Path.Combine(Path.GetFullPath(programDataDir), AgentLayout.AppCacheFolderName);
            var isCache = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                .Equals(cache.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), StringComparison.OrdinalIgnoreCase);
            var isInstall = installDir is not null && IsAgentInstallDirectory(installDir) && IsPathUnder(path, installDir);
            if (!isCache && !isInstall)
            {
                skipped.Add(path);
                return;
            }
            Directory.Delete(path, recursive: true);
            removed.Add(path);
        }
        catch
        {
            skipped.Add(path);
        }
    }

    private static bool IsReparse(string path)
    {
        try
        {
            return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
        }
        catch
        {
            return false;
        }
    }
}

/// <summary>One look at whether a user-facing desktop install is still on the machine.</summary>
public readonly record struct DesktopInstallObservation(
    bool SetupExePresent,
    bool SetupUninstallKeyPresent,
    bool MsixPackagePresent,
    bool SetupCheckFailed,
    bool MsixCheckFailed,
    bool DesktopProcessRunning)
{
    public bool ConfirmedPresent => SetupExePresent || SetupUninstallKeyPresent || MsixPackagePresent;

    /// <summary>Both probes answered and neither found Setup, the Inno uninstall key, or the Store package.</summary>
    public bool ConfirmedAbsent => !ConfirmedPresent && !SetupCheckFailed && !MsixCheckFailed;
}

public static class AgentSelfRemoval
{
    public static int NextAbsentStreak(int streak, DesktopInstallObservation observation)
    {
        if (observation.ConfirmedPresent) return 0;
        if (observation.ConfirmedAbsent) return streak + 1;
        return streak;
    }

    /// <summary>
    /// Remove only after the desktop install was seen before, two polls in a row confirm it is gone, and
    /// <c>RemotePCDiagnostics.Host</c> is not running. A failed registry read does not count as gone.
    /// </summary>
    public static bool ShouldRemove(bool hostEverSeen, int absentStreak, DesktopInstallObservation observation, int requiredStreak = AgentRemoval.AbsentPollsBeforeRemoval) =>
        hostEverSeen
        && !observation.DesktopProcessRunning
        && observation.ConfirmedAbsent
        && absentStreak >= requiredStreak;
}
