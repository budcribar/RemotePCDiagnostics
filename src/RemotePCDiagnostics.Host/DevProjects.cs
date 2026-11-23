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

    private const string SearchIndexSql =
        "SELECT TOP 5000 System.ItemPathDisplay FROM SYSTEMINDEX WHERE " +
        "System.FileName = 'project.assets.json' OR System.FileExtension = '.sln' OR System.FileExtension = '.slnx' OR System.FileExtension = '.csproj'";

    private static async Task<IReadOnlyList<string>> SearchIndexAsync(ILogger? log, CancellationToken ct)
    {
        try
        {
            return await Task.Run(() => QuerySearchIndex(ct), CancellationToken.None)
                .WaitAsync(TimeSpan.FromSeconds(20), ct)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (TimeoutException)
        {
            log.Warn("[projects] search index timed out");
            return [];
        }
        catch (Exception ex)
        {
            log.Info("[projects] search index unavailable: " + ex.Message);
            return [];
        }
    }

    private static List<string> QuerySearchIndex(CancellationToken ct)
    {
        var results = new List<string>();
        object? connObj = null;
        object? rsObj = null;
        try
        {
            var connType = Type.GetTypeFromProgID("ADODB.Connection")
                ?? throw new InvalidOperationException("ADODB.Connection is not registered.");
            connObj = Activator.CreateInstance(connType)
                ?? throw new InvalidOperationException("Could not create ADODB.Connection.");
            dynamic conn = connObj;
            conn.Open("Provider=Search.CollatorDSO;Extended Properties='Application=Windows';");
            rsObj = conn.Execute(SearchIndexSql);
            dynamic rs = rsObj;
            while (!(bool)rs.EOF)
            {
                ct.ThrowIfCancellationRequested();
                var val = rs.Fields.Item(0).Value?.ToString();
                if (!string.IsNullOrWhiteSpace(val))
                    results.Add(val.Trim());
                rs.MoveNext();
            }
            try { rs.Close(); } catch { }
            try { conn.Close(); } catch { }
        }
        finally
        {
            SafeReleaseCom(rsObj);
            SafeReleaseCom(connObj);
        }
        return results;
    }

    private static void SafeReleaseCom(object? obj)
    {
        if (obj is null) return;
        try
        {
            if (System.Runtime.InteropServices.Marshal.IsComObject(obj))
                System.Runtime.InteropServices.Marshal.FinalReleaseComObject(obj);
        }
        catch { }
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
