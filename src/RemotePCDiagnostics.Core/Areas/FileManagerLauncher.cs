using System.Diagnostics;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// Opens the platform file manager (e.g. Windows File Explorer) with the specified file or folder selected.
/// </summary>
public static class FileManagerLauncher
{
    /// <summary>Optional override for testing or custom launch interception.</summary>
    public static Func<string, bool>? CustomOpener { get; set; }

    /// <summary>
    /// Opens the file manager to the specified file, selecting/highlighting it if possible.
    /// Falls back to opening the containing directory if the file does not exist.
    /// </summary>
    public static bool RevealFile(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;

        if (CustomOpener is not null)
            return CustomOpener(path);

        try
        {
            if (OperatingSystem.IsWindows())
            {
                var explorer = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
                if (File.Exists(path))
                {
                    using var p = Process.Start(new ProcessStartInfo(explorer, $"/select,\"{path}\"") { UseShellExecute = true });
                    return true;
                }
                if (Directory.Exists(path))
                {
                    using var p = Process.Start(new ProcessStartInfo(explorer, $"\"{path}\"") { UseShellExecute = true });
                    return true;
                }
                var dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
                {
                    using var p = Process.Start(new ProcessStartInfo(explorer, $"\"{dir}\"") { UseShellExecute = true });
                    return true;
                }
                return false;
            }

            if (OperatingSystem.IsMacOS())
            {
                const string openExe = "/usr/bin/open";
                if (File.Exists(path))
                {
                    using var p = Process.Start(new ProcessStartInfo(openExe, $"-R \"{path}\"") { UseShellExecute = true });
                    return true;
                }
                var target = Directory.Exists(path) ? path : Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(target) && Directory.Exists(target))
                {
                    using var p = Process.Start(new ProcessStartInfo(openExe, $"\"{target}\"") { UseShellExecute = true });
                    return true;
                }
                return false;
            }

            if (OperatingSystem.IsLinux())
            {
                var dir = Directory.Exists(path) ? path : Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
                {
                    using var p = Process.Start(new ProcessStartInfo("/usr/bin/xdg-open", $"\"{dir}\"") { UseShellExecute = true });
                    return true;
                }
            }
        }
        catch
        {
            return false;
        }

        return false;
    }
}
