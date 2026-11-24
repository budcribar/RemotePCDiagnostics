using System.Runtime.InteropServices;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// Analyzes a local Windows <c>.dmp</c> file: extracts header/minidump details in pure C# (<see cref="CrashDumpParser"/>),
/// and runs Microsoft Store WinDbg or Windows SDK Debugging Tools (<c>kd.exe</c>/<c>cdb.exe</c>) when installed for full symbol-resolved analysis.
/// </summary>
public static class CrashDumpDebugger
{
    public const string InstallHint =
        "Install WinDbg (winget install Microsoft.WinDbg) or Debugging Tools for Windows from the Windows SDK for full symbol-resolved stack analysis.";

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

    /// <summary>
    /// Finds an installed console debugger (<c>kd.exe</c> or <c>cdb.exe</c>), checking Microsoft Store WinDbg first,
    /// then Windows SDK Debugging Tools.
    /// </summary>
    public static string? FindDebugger(
        bool userMode = false,
        Architecture? architecture = null,
        string? localAppData = null,
        string? programFiles = null,
        string? programFilesX86 = null,
        Func<string, bool>? fileExists = null,
        Func<string, string, IEnumerable<string>>? enumerateDirectories = null)
    {
        var arch = architecture ?? RuntimeInformation.OSArchitecture;
        var sdkArch = arch switch
        {
            Architecture.Arm64 => "arm64",
            Architecture.X86 => "x86",
            _ => "x64",
        };
        var storeArch = arch switch
        {
            Architecture.Arm64 => "arm64",
            Architecture.X86 => "x86",
            _ => "amd64",
        };

        var local = localAppData ?? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var pf = programFiles ?? Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var pfx86 = programFilesX86 ?? Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var exists = fileExists ?? File.Exists;
        var enumDirs = enumerateDirectories ?? SafeEnumerateDirectories;

        // Prefer cdb.exe for user-mode minidumps when available, falling back to kd.exe.
        string[] exeNames = userMode ? ["cdb.exe", "kd.exe"] : ["kd.exe"];

        foreach (var exe in exeNames)
        {
            // 1. Microsoft Store WinDbg (App Execution Alias + package folder)
            if (!string.IsNullOrEmpty(local))
            {
                var winAppsLocal = Path.Combine(local, "Microsoft", "WindowsApps");
                var alias = Path.Combine(winAppsLocal, exe);
                if (exists(alias)) return alias;

                foreach (var pkgDir in enumDirs(winAppsLocal, "Microsoft.WinDbg_*"))
                {
                    var direct = Path.Combine(pkgDir, exe);
                    if (exists(direct)) return direct;
                    var nested = Path.Combine(pkgDir, storeArch, exe);
                    if (exists(nested)) return nested;
                }
            }

            if (!string.IsNullOrEmpty(pf))
            {
                var winAppsGlobal = Path.Combine(pf, "WindowsApps");
                foreach (var pkgDir in enumDirs(winAppsGlobal, "Microsoft.WinDbg_*").OrderByDescending(d => d, StringComparer.OrdinalIgnoreCase))
                {
                    var nested = Path.Combine(pkgDir, storeArch, exe);
                    if (exists(nested)) return nested;
                    var direct = Path.Combine(pkgDir, exe);
                    if (exists(direct)) return direct;
                }
            }

            // 2. Windows SDK Debugging Tools
            foreach (var root in new[] { pfx86, pf })
            {
                if (string.IsNullOrEmpty(root)) continue;
                var candidate = Path.Combine(root, "Windows Kits", "10", "Debuggers", sdkArch, exe);
                if (exists(candidate)) return candidate;
            }
        }

        return null;
    }

    private static IEnumerable<string> SafeEnumerateDirectories(string path, string searchPattern)
    {
        if (!Directory.Exists(path)) return [];
        try { return Directory.EnumerateDirectories(path, searchPattern); }
        catch { return []; }
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

    /// <summary>Parses the dump in pure C# and runs Store WinDbg / SDK <c>kd.exe</c> or <c>cdb.exe</c> in the current process (when readable or inside the elevated Admin Agent).</summary>
    public static async Task<string> AnalyzeLocalAsync(string path, CancellationToken ct = default)
    {
        if (!IsLocalDump(path)) return "The dump file is missing or inaccessible.";

        var parsed = CrashDumpParser.TryReadFile(path);
        var headerSummary = parsed?.FormatText();

        var debugger = FindDebugger(userMode: parsed?.Kind == CrashDumpKind.UserMinidump);
        if (debugger is null)
        {
            return headerSummary is not null
                ? $"{headerSummary}\n\n{InstallHint}"
                : InstallHint;
        }

        var symbols = Path.Combine(Path.GetTempPath(), "RemotePCDiagnostics", "Symbols");
        var result = await new SystemCommandRunner().RunAsync(debugger,
            ["-z", path, "-y", $"srv*{symbols}*https://msdl.microsoft.com/download/symbols", "-c", "!analyze -v; q"],
            TimeSpan.FromMinutes(3), ct).ConfigureAwait(false);
        if (result is null)
        {
            const string failed = "The debugger could not start or did not finish within three minutes.";
            return headerSummary is not null ? $"{headerSummary}\n\n{failed}" : failed;
        }
        var output = (result.StdOut + "\n" + result.StdErr).Trim();
        if (result.ExitCode != 0)
            output = $"Debugger exited with code {result.ExitCode}.\n{output}";
        if (output.Length == 0)
            return headerSummary is not null ? $"{headerSummary}\n\nThe debugger returned no analysis." : "The debugger returned no analysis.";
        const int limit = 48_000;
        var trimmed = output.Length <= limit ? output : "Earlier debugger output omitted.\n" + output[^limit..];
        return headerSummary is not null ? $"{headerSummary}\n\n--- Debugger (!analyze -v) ---\n{trimmed}" : trimmed;
    }
}
