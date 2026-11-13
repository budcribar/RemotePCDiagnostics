using System.Diagnostics;
using Microsoft.Win32;
using RemotePCDiagnostics.Agent.Core;

namespace RemotePCDiagnostics.Agent;

/// <summary>
/// Run keys, Startup-folder shortcuts, and scheduled tasks that launch the agent. <c>install</c> itself only registers
/// the Windows service; invite scripts may also leave a Run value or a task. The desktop app's workflow resume task
/// is left alone because its action is Host.exe, not the agent.
/// </summary>
internal static class AgentStartupCleanup
{
    private static readonly (RegistryHive Hive, RegistryView View, string Subkey)[] RunKeys =
    [
        (RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (RegistryHive.CurrentUser, RegistryView.Default, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.CurrentUser, RegistryView.Default, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ];

    public static List<string> RemoveAll()
    {
        var lines = new List<string>();
        if (!OperatingSystem.IsWindows())
            return lines;
        lines.AddRange(RemoveRunValues());
        lines.AddRange(RemoveStartupShortcuts());
        lines.AddRange(RemoveScheduledTasks());
        return lines;
    }

    public static void ScheduleInstallDirectoryDelete(string installDir)
    {
        if (!OperatingSystem.IsWindows() || !AgentRemoval.IsAgentInstallDirectory(installDir))
            return;
        var cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        if (!File.Exists(cmd))
            cmd = "cmd.exe";
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = cmd,
                Arguments = AgentRemoval.DelayedDirectoryDeleteArguments(installDir),
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            });
        }
        catch
        {
            // The service and the key are already gone. A leftover folder can be deleted by hand.
        }
    }

    private static List<string> RemoveRunValues()
    {
        var lines = new List<string>();
        foreach (var (hive, view, subkey) in RunKeys)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                using var key = baseKey.OpenSubKey(subkey, writable: true);
                if (key is null) continue;
                foreach (var name in key.GetValueNames())
                {
                    var command = key.GetValue(name) as string;
                    if (!AgentRemoval.ShouldRemoveRunValue(name, command)) continue;
                    key.DeleteValue(name, throwOnMissingValue: false);
                    lines.Add($"Removed startup value '{name}' from {hive}\\{subkey}.");
                }
            }
            catch
            {
                // This hive may not be writable (another user's HKCU). The elevated uninstall still clears HKLM.
            }
        }
        return lines;
    }

    private static List<string> RemoveStartupShortcuts()
    {
        var lines = new List<string>();
        foreach (var folder in new[]
                 {
                     Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
                     Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                 })
        {
            if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder)) continue;
            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(folder); }
            catch { continue; }
            foreach (var file in files)
            {
                if (!AgentRemoval.IsAgentStartupShortcut(file)) continue;
                try
                {
                    File.Delete(file);
                    lines.Add($"Removed startup shortcut '{file}'.");
                }
                catch { }
            }
        }
        return lines;
    }

    private static List<string> RemoveScheduledTasks()
    {
        var lines = new List<string>();
        string output;
        try
        {
            output = RunSchtasks("/Query /FO LIST /V").Output;
        }
        catch
        {
            output = "";
        }

        var names = AgentRemoval.TaskNamesToDelete(output);
        if (names.Count == 0)
        {
            // Query can fail when no tasks are visible. Still try the names install scripts use.
            names = AgentRemoval.ScheduledTaskNames.ToList();
        }

        foreach (var name in names)
        {
            var (code, _) = RunSchtasks("/Delete /F /TN " + WindowsCommandLine.Quote(name));
            if (code == 0)
                lines.Add($"Removed scheduled task '{name}'.");
        }
        return lines;
    }

    private static (int ExitCode, string Output) RunSchtasks(string arguments)
    {
        var exe = Path.Combine(Environment.SystemDirectory, "schtasks.exe");
        if (!File.Exists(exe))
            exe = "schtasks.exe";
        var psi = new ProcessStartInfo
        {
            FileName = exe,
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        using var proc = Process.Start(psi) ?? throw new InvalidOperationException("Failed to start schtasks.exe.");
        var stdoutTask = proc.StandardOutput.ReadToEndAsync();
        var stderrTask = proc.StandardError.ReadToEndAsync();
        if (!proc.WaitForExit(30_000))
        {
            try { proc.Kill(entireProcessTree: true); } catch { }
        }
        var stdout = stdoutTask.GetAwaiter().GetResult();
        var stderr = stderrTask.GetAwaiter().GetResult();
        return (proc.ExitCode, (stdout + "\n" + stderr).Trim());
    }
}
