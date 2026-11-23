using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>Runs the installed Windows kernel debugger on a selected system dump.</summary>
public static class CrashDumpDebugger
{
    /// <summary>A .dmp file on a local drive. Paths are normalised first, so "//server/share" and "\\?\UNC\…" are refused like "\\server\share".</summary>
    public static bool IsLocalDump(string? path) =>
        TryNormalizeLocalDumpPath(path, out var full) && File.Exists(full);

    /// <summary>True when <paramref name="path"/> is a local .dmp file under <c>%SystemRoot%\Minidump</c>, <c>%SystemRoot%\LiveKernelReports</c>, or <c>%SystemRoot%\MEMORY.DMP</c>.</summary>
    public static bool IsAllowedSystemDumpPath(string? path, string? windowsDir = null)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Any(char.IsControl)) return false;
        var win = string.IsNullOrWhiteSpace(windowsDir)
            ? Environment.GetFolderPath(Environment.SpecialFolder.Windows)
            : windowsDir;
        if (string.IsNullOrWhiteSpace(win)) win = @"C:\Windows";
        string full;
        if (OperatingSystem.IsWindows())
        {
            if (!TryNormalizeLocalDumpPath(path, out full)) return false;
        }
        else
        {
            var trimmed = path.Trim();
            if (trimmed.StartsWith(@"\\", StringComparison.Ordinal) || trimmed.StartsWith("//", StringComparison.Ordinal)
                || trimmed.Contains("..", StringComparison.Ordinal)
                || !trimmed.EndsWith(".dmp", StringComparison.OrdinalIgnoreCase))
                return false;
            full = trimmed.Replace('/', '\\');
            win = win.Replace('/', '\\');
        }
        win = win.TrimEnd('\\', '/');
        var minidumpPrefix = win + @"\Minidump\";
        var liveKernelPrefix = win + @"\LiveKernelReports\";
        var memoryDmp = win + @"\MEMORY.DMP";
        return full.StartsWith(minidumpPrefix, StringComparison.OrdinalIgnoreCase)
            || full.StartsWith(liveKernelPrefix, StringComparison.OrdinalIgnoreCase)
            || full.Equals(memoryDmp, StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryNormalizeLocalDumpPath(string? path, out string full)
    {
        full = "";
        if (string.IsNullOrWhiteSpace(path) || path.Any(char.IsControl)) return false;
        try { full = Path.GetFullPath(path); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { return false; }
        return !full.StartsWith(@"\\", StringComparison.Ordinal) && !full.StartsWith("//", StringComparison.Ordinal)
            && full.EndsWith(".dmp", StringComparison.OrdinalIgnoreCase);
    }

    private static bool CanReadFile(string fullPath)
    {
        try
        {
            if (!File.Exists(fullPath)) return false;
            using var _ = File.Open(fullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            return true;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            return false;
        }
    }

    public static async Task<string> AnalyzeAsync(string path, SystemCommandRunner? commands = null, CancellationToken ct = default)
    {
        if (!TryNormalizeLocalDumpPath(path, out var full))
            return "The dump file is missing or inaccessible.";

        if (CanReadFile(full))
            return await AnalyzeLocalAsync(full, ct).ConfigureAwait(false);

        if (IsAllowedSystemDumpPath(path))
        {
            if (commands is not null)
            {
                var target = OperatingSystem.IsWindows() ? full : path.Trim();
                var pr = await commands.RunAgentScriptAsync(
                    AgentScripts.Of(AgentScripts.AnalyzeCrashDump, target),
                    TimeSpan.FromMinutes(3), ct).ConfigureAwait(false);
                if (pr is { ExitCode: 0 } && !string.IsNullOrWhiteSpace(pr.StdOut))
                    return pr.StdOut.Trim();
                if (pr is not null && !string.IsNullOrWhiteSpace(pr.StdErr))
                    return pr.StdErr.Trim();
            }
            return "This dump file requires administrator access to read. Connect the Admin Agent or run Remote PC Diagnostics as administrator, then try again.";
        }

        return "The dump file is missing or inaccessible.";
    }

    /// <summary>Runs <c>kd.exe</c> directly in the current process (used when already readable or inside the elevated Admin Agent).</summary>
    public static async Task<string> AnalyzeLocalAsync(string path, CancellationToken ct = default)
    {
        if (!IsLocalDump(path)) return "The dump file is missing or inaccessible.";

        var arch = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture switch
        {
            System.Runtime.InteropServices.Architecture.Arm64 => "arm64",
            System.Runtime.InteropServices.Architecture.X86 => "x86",
            _ => "x64"
        };
        var kd = new[] { Environment.SpecialFolder.ProgramFilesX86, Environment.SpecialFolder.ProgramFiles }
            .Select(Environment.GetFolderPath)
            .Where(root => root.Length > 0)
            .Select(root => Path.Combine(root, "Windows Kits", "10", "Debuggers", arch, "kd.exe"))
            .FirstOrDefault(File.Exists);
        if (kd is null)
            return "Install Debugging Tools for Windows from the Windows SDK to analyze this dump.";

        var symbols = Path.Combine(Path.GetTempPath(), "RemotePCDiagnostics", "Symbols");
        var result = await new SystemCommandRunner().RunAsync(kd,
            ["-z", path, "-y", $"srv*{symbols}*https://msdl.microsoft.com/download/symbols", "-c", "!analyze -v; q"],
            TimeSpan.FromMinutes(3), ct).ConfigureAwait(false);
        if (result is null)
            return "The debugger could not start or did not finish within three minutes.";
        var output = (result.StdOut + "\n" + result.StdErr).Trim();
        if (result.ExitCode != 0)
            output = $"Debugger exited with code {result.ExitCode}.\n{output}";
        if (output.Length == 0)
            return "The debugger returned no analysis.";
        const int limit = 48_000;
        return output.Length <= limit ? output : "Earlier debugger output omitted.\n" + output[^limit..];
    }
}
