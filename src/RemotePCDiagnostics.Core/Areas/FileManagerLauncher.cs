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
            if (OperatingSystem.IsWindows()) return RevealWindows(path);
            if (OperatingSystem.IsMacOS()) return RevealMacOS(path);
            if (OperatingSystem.IsLinux()) return RevealLinux(path);
        }
        catch
        {
            return false;
        }

        return false;
    }

    private static bool RevealWindows(string path)
    {
        var explorer = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
        if (File.Exists(path)) return StartShell(explorer, $"/select,\"{path}\"");
        var dir = ResolveExistingDirectory(path);
        return dir is not null && StartShell(explorer, $"\"{dir}\"");
    }

    private static bool RevealMacOS(string path)
    {
        const string openExe = "/usr/bin/open";
        if (File.Exists(path)) return StartShell(openExe, $"-R \"{path}\"");
        var dir = ResolveExistingDirectory(path);
        return dir is not null && StartShell(openExe, $"\"{dir}\"");
    }

    private static bool RevealLinux(string path)
    {
        var dir = ResolveExistingDirectory(path);
        return dir is not null && StartShell("/usr/bin/xdg-open", $"\"{dir}\"");
    }

    private static string? ResolveExistingDirectory(string path)
    {
        var candidate = Directory.Exists(path) ? path : Path.GetDirectoryName(path);
        return !string.IsNullOrEmpty(candidate) && Directory.Exists(candidate) ? candidate : null;
    }

    private static bool StartShell(string fileName, string arguments)
    {
        using var p = Process.Start(new ProcessStartInfo(fileName, arguments) { UseShellExecute = true });
        return true;
    }
}
