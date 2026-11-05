namespace RemotePCDiagnostics.Core.Areas;

/// <summary>Runs the installed Windows kernel debugger on a selected system dump.</summary>
public static class CrashDumpDebugger
{
    public static async Task<string> AnalyzeAsync(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.StartsWith(@"\\", StringComparison.Ordinal)
            || !path.EndsWith(".dmp", StringComparison.OrdinalIgnoreCase) || !File.Exists(path))
            return "The dump file is missing or inaccessible.";

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
            TimeSpan.FromMinutes(3), CancellationToken.None).ConfigureAwait(false);
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
