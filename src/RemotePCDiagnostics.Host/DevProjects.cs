using System.Diagnostics;
using System.IO;
using RemotePCDiagnostics.Core.Projects;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// Where this PC's source code is (shared by the NuGet cleanup and the Defender exclusions). Cached for a few minutes:
/// the editors' lists are small files, but the Windows Search query starts PowerShell.
/// </summary>
public static class DevProjects
{
    private static readonly SemaphoreSlim Gate = new(1, 1);
    private static (DateTime At, IReadOnlyList<ProjectRoot> Roots)? s_last;
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(5);

    public static async Task<IReadOnlyList<ProjectRoot>> FindAsync(ILogger? log, CancellationToken ct)
    {
        await Gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (s_last is { } l && DateTime.UtcNow - l.At < Ttl) return l.Roots;
            var roots = await new ProjectLocator(ProjectLocatorPaths.Current(), c => SearchIndexAsync(log, c), log).FindAsync(ct).ConfigureAwait(false);
            s_last = (DateTime.UtcNow, roots);
            return roots;
        }
        finally { Gate.Release(); }
    }

    /// <summary>Asks the Windows Search index for project files (only folders Windows indexes; quick when the service runs).</summary>
    public static string SearchIndexScript => RemotePCDiagnostics.Core.Scripts.PowerShellScripts.Get("SearchIndexProjects");

    private static async Task<IReadOnlyList<string>> SearchIndexAsync(ILogger? log, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe"))
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", SearchIndexScript }) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(20));
        try
        {
            var outTask = p.StandardOutput.ReadToEndAsync(timeout.Token);
            var errTask = p.StandardError.ReadToEndAsync(timeout.Token);
            await p.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            var output = await outTask.ConfigureAwait(false);
            if (p.ExitCode != 0) { log.Info("[projects] search index unavailable: " + (await errTask.ConfigureAwait(false)).Trim()); return []; }
            return output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        }
        catch (OperationCanceledException)
        {
            try { p.Kill(true); } catch { }
            if (ct.IsCancellationRequested) throw;
            log.Warn("[projects] search index timed out");
            return [];
        }
    }

    /// <summary>Visual Studio's own build tools (full paths, as Defender process exclusions require). dotnet.exe is left out: it also runs every .NET app.</summary>
    public static IReadOnlyList<string> BuildTools()
    {
        var found = new List<string>();
        foreach (var pf in new[] { Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86) })
        {
            var vs = Path.Combine(pf, "Microsoft Visual Studio");
            if (pf.Length == 0 || !Directory.Exists(vs)) continue;
            try
            {
                foreach (var version in Directory.EnumerateDirectories(vs))      // 2022, 18, …
                    foreach (var edition in Directory.EnumerateDirectories(version)) // Community, Professional, Enterprise, BuildTools, Preview
                        foreach (var rel in new[] { @"Common7\IDE\devenv.exe", @"MSBuild\Current\Bin\MSBuild.exe", @"MSBuild\Current\Bin\amd64\MSBuild.exe", @"MSBuild\Current\Bin\Roslyn\VBCSCompiler.exe" })
                            if (File.Exists(Path.Combine(edition, rel))) found.Add(Path.Combine(edition, rel));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
        return found.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }
}
