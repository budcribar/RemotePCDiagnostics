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
}
