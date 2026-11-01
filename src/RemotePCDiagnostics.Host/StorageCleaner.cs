using System.Diagnostics;
using RemotePCDiagnostics.Core.Storage;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// Runs the storage cleanups on this PC. Only a category id comes in (from the workflow or a click), never a path: the folders are rebuilt
/// from this account's profile and AppData, the category's rule is evaluated again on disk right before deleting, and
/// <see cref="StorageCleanupEngine"/> deletes only inside the category's allowlisted roots, never through a junction or symlink, skips
/// files in use, and skips the whole category while its app (VS Code, the browser, Outlook, OneDrive, Office, …) is running.
/// </summary>
public static class StorageCleaner
{
    public static async Task<StorageCleanResult> CleanAsync(string id, Action<string>? log, CancellationToken ct)
    {
        if (StorageCleanupCatalog.Find(id) is not { } category)
        {
            log?.Invoke($"[storage] refused unknown cleanup '{id}'");
            return StorageCleanResult.NotRun(id, "That cleanup isn't one this app may run.");
        }
        IReadOnlyList<string> projects = [];
        if (category.UsesProjects)
        {
            try { projects = [.. (await DevProjects.FindAsync(log, ct).ConfigureAwait(false)).Select(r => r.Path)]; }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                log?.Invoke("[storage] project search failed: " + ex.Message); // no projects found = no package versions are removed
            }
        }
        var ctx = new StorageScanContext(StorageRoots.Current(), projects, DateTime.UtcNow, log);
        var result = await Task.Run(() => StorageCleanupEngine.Clean(category, ctx, IsAppRunning, ct), ct).ConfigureAwait(false);
        log?.Invoke($"[storage] {id}: {result.Message}");
        return result;
    }

    /// <summary>Any process with this name in any session (another user's VS Code or Outlook keeps its own files open too).</summary>
    public static bool IsAppRunning(string processName)
    {
        var ps = Process.GetProcessesByName(processName);
        try { return ps.Length > 0; }
        finally { foreach (var p in ps) p.Dispose(); }
    }
}
