using System.Diagnostics;
using Microsoft.Win32;
using RemotePCDiagnostics.Agent.Core;

namespace RemotePCDiagnostics.Agent;

/// <summary>
/// Detects a user-facing Remote PC Diagnostics install: the Setup exe, the Inno uninstall key, or the Store package.
/// The agent's own download cache under ProgramData is not an install. A probe that throws is a failure, not "gone".
/// </summary>
internal static class DesktopInstallProbe
{
    private static readonly string[] PackageKeys =
    [
        @"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications",
    ];

    public static DesktopInstallObservation Observe()
    {
        if (!OperatingSystem.IsWindows())
            return new DesktopInstallObservation(false, false, false, SetupCheckFailed: true, MsixCheckFailed: true, DesktopProcessRunning: true);

        var setupFailed = false;
        var exe = false;
        try
        {
            var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            foreach (var candidate in AgentRemoval.SetupHostExeCandidates(programFiles, programFilesX86))
            {
                if (File.Exists(candidate))
                {
                    exe = true;
                    break;
                }
            }
        }
        catch
        {
            setupFailed = true;
        }

        var uninstall = false;
        try
        {
            uninstall = UninstallKeyPresent();
        }
        catch
        {
            setupFailed = true;
        }

        var package = false;
        var packageFailed = false;
        try
        {
            package = PackagePresent(out packageFailed);
        }
        catch
        {
            packageFailed = true;
        }

        return new DesktopInstallObservation(
            exe,
            uninstall,
            package,
            setupFailed && !exe && !uninstall,
            packageFailed && !package,
            HostProcessRunning());
    }

    private static bool HostProcessRunning()
    {
        try
        {
            return Process.GetProcessesByName("RemotePCDiagnostics.Host").Length > 0;
        }
        catch
        {
            // If we cannot tell, assume the app is open so we do not remove the agent underneath it.
            return true;
        }
    }

    private static bool UninstallKeyPresent()
    {
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using var uninstall = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
            if (uninstall is null) continue;
            foreach (var name in uninstall.GetSubKeyNames())
            {
                if (AgentRemoval.IsDesktopUninstallRegistryKey(name))
                    return true;
            }
        }
        return false;
    }

    private static bool PackagePresent(out bool failed)
    {
        failed = false;
        var found = false;
        var opened = false;
        foreach (var subkey in PackageKeys)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                using var key = baseKey.OpenSubKey(subkey);
                // A missing key is not the same as "no packages". Only an opened key can prove the Store app is gone.
                if (key is null) continue;
                opened = true;
                foreach (var name in key.GetSubKeyNames())
                {
                    if (!AgentRemoval.IsDesktopMsixPackage(name)) continue;
                    found = true;
                    break;
                }
            }
            catch
            {
                failed = true;
            }
            if (found) break;
        }
        if (!opened)
            failed = true;
        return found;
    }
}
