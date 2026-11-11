using System.Globalization;
using System.IO.Enumeration;
using RemotePCDiagnostics.Core.Optimizations;

namespace RemotePCDiagnostics.Core.Storage;

/// <summary>The account folders every cleanup rule is built from (never from saved state or the journal).</summary>
public sealed record StorageRoots(string UserProfile, string LocalAppData, string RoamingAppData)
{
    public static StorageRoots Current() => new(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
}

/// <param name="ProjectRoots">Code folders found on this PC (only the NuGet rule uses them, to keep referenced package versions).</param>
public sealed record StorageScanContext(StorageRoots Roots, IReadOnlyList<string> ProjectRoots, DateTime UtcNow, ILogger? Log = null);

public enum StorageTargetMode
{
    /// <summary>Files inside <see cref="StorageTarget.Root"/> that match the filters; the root folder itself stays.</summary>
    Contents,
    /// <summary>One folder strictly inside the root, removed with everything in it.</summary>
    Directory,
    /// <summary>One file strictly inside the root.</summary>
    File,
}

/// <summary>
/// One thing a cleanup rule wants deleted. <see cref="Root"/> must be one of the category's allowlisted roots and
/// <see cref="Path"/> must be that root (<see cref="StorageTargetMode.Contents"/>) or strictly inside it.
/// </summary>
/// <param name="OlderThanUtc">Contents: only files last written before this.</param>
/// <param name="Pattern">Contents: only file names matching this simple wildcard (e.g. "*.dmp").</param>
/// <param name="TopLevelOnly">Contents: don't look into subfolders.</param>
/// <param name="MaxFileBytes">Contents: only files at most this big (lock files are tiny).</param>
/// <param name="DeleteFirst">Directory: top-level marker patterns (e.g. NuGet's .nupkg.metadata / *.nupkg.sha512) deleted last only after
/// verifying no file in the folder is in use, so a locked package is never left half-deleted or hidden from future scans.</param>
public sealed record StorageTarget(string Root, string Path, StorageTargetMode Mode, DateTime? OlderThanUtc = null, string? Pattern = null,
    bool TopLevelOnly = false, long? MaxFileBytes = null, IReadOnlyList<string>? DeleteFirst = null)
{
    public static StorageTarget Contents(string root, DateTime? olderThanUtc = null, string? pattern = null, bool topLevelOnly = false, long? maxFileBytes = null) =>
        new(root, root, StorageTargetMode.Contents, olderThanUtc, pattern, topLevelOnly, maxFileBytes);
    public static StorageTarget Folder(string root, string path, IReadOnlyList<string>? deleteFirst = null) =>
        new(root, path, StorageTargetMode.Directory, DeleteFirst: deleteFirst);
    public static StorageTarget OneFile(string root, string path) => new(root, path, StorageTargetMode.File);
}

/// <summary>
/// One cleanup category (one workflow fix). <see cref="AllowedRoots"/> are the only folders it may delete in; <see cref="Targets"/>
/// re-evaluates the rule on disk every time it's called (the scan and, again, right before deleting).
/// </summary>
/// <param name="BlockingApps">Process names (no ".exe"); while any of them runs the whole category is skipped.</param>
/// <param name="AppLabel">"VS Code", "Chrome", … for the skipped message.</param>
/// <param name="MinBytes">Smallest total worth offering (lock files are offered at any size).</param>
public sealed record StorageCategory(
    string Id, string Title, string Description, bool AutoChecked,
    IReadOnlyList<string> BlockingApps, string AppLabel,
    Func<StorageScanContext, IReadOnlyList<string>> AllowedRoots,
    Func<StorageScanContext, CancellationToken, IReadOnlyList<StorageTarget>> Targets,
    long MinBytes = 10L << 20, bool UsesProjects = false);

/// <param name="Ran">False = nothing was attempted (an app was open, unknown category, or the rule couldn't be evaluated).</param>
/// <param name="FilesSkipped">Files left because they were in use or couldn't be deleted.</param>
/// <param name="Refused">Targets refused by the allowlist / link checks (should always be 0).</param>
public sealed record StorageCleanResult(string Id, bool Ran, long FilesRemoved, long BytesFreed, int FilesSkipped, string Message,
    IReadOnlyList<string>? RunningApps = null, int Refused = 0, int LinksSkipped = 0)
{
    public static StorageCleanResult NotRun(string id, string message) => new(id, false, 0, 0, 0, message);
}

/// <summary>
/// Measures and deletes <see cref="StorageTarget"/>s with hard safety rules: only inside the category's exact allowlisted roots,
/// never through (or into) a reparse point (junction, symlink, mount point), never cookies / saved logins / history / bookmarks /
/// browser preferences / .pst files, files in use are skipped and the rest continues, and a category whose app is running is skipped entirely.
/// </summary>
public static class StorageCleanupEngine
{
    /// <summary>File names never deleted, wherever they are (browser profile data that isn't cache).</summary>
    private static readonly HashSet<string> NeverDelete = new(StringComparer.OrdinalIgnoreCase)
    {
        "Cookies", "Cookies-journal", "Login Data", "Login Data-journal", "Login Data For Account", "Login Data For Account-journal",
        "History", "History-journal", "Bookmarks", "Bookmarks.bak", "Web Data", "Web Data-journal", "Preferences", "Secure Preferences",
        "Local State", "Favicons", "Favicons-journal", "Top Sites", "Top Sites-journal", "Shortcuts", "Shortcuts-journal",
    };

    public static bool IsProtectedFile(string name) =>
        NeverDelete.Contains(name) || name.EndsWith(".pst", StringComparison.OrdinalIgnoreCase);

    public static string Normalize(string path) => System.IO.Path.TrimEndingDirectorySeparator(System.IO.Path.GetFullPath(path));

    /// <summary>True for a reparse point, and for anything whose attributes can't be read (treated as unsafe).</summary>
    public static bool IsReparsePoint(string path)
    {
        try { return (System.IO.File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return true; }
    }

    /// <summary>
    /// The target is on the allowlist: its root is one of <paramref name="allowedRoots"/> exactly, its path is the root (Contents) or
    /// strictly inside it (Directory/File), the root exists, and neither the root nor any folder from the root down to the target is a reparse point.
    /// </summary>
    /// <remarks>Every folder from the account folder (<paramref name="account"/>: profile, Local or Roaming AppData) down to the target is checked,
    /// so a root reached through a junction is refused too; a root outside the account folders is refused.</remarks>
    public static bool IsAllowed(StorageTarget t, IEnumerable<string> allowedRoots, StorageRoots account, out string why)
    {
        string root, path;
        try { root = Normalize(t.Root); path = Normalize(t.Path); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { why = "not a valid path"; return false; }
        if (!allowedRoots.Any(r => string.Equals(Normalize(r), root, StringComparison.OrdinalIgnoreCase))) { why = "root isn't on the allowlist"; return false; }
        if (t.Mode == StorageTargetMode.Contents)
        {
            if (!string.Equals(path, root, StringComparison.OrdinalIgnoreCase)) { why = "contents target isn't its root"; return false; }
        }
        else if (!path.StartsWith(root + System.IO.Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) { why = "outside its root"; return false; }
        if (!System.IO.Directory.Exists(root)) { why = "root is missing"; return false; }
        var bases = new[] { account.LocalAppData, account.RoamingAppData, account.UserProfile }
            .Where(b => !string.IsNullOrWhiteSpace(b)).Select(Normalize)
            .Where(b => root.StartsWith(b + System.IO.Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(b => b.Length).ToList();
        if (bases.Count == 0) { why = "root is outside the account folders"; return false; }
        var current = bases[0];
        foreach (var part in System.IO.Path.GetRelativePath(current, path).Split(System.IO.Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries))
        {
            if (part is "." or "..") { why = "relative segment"; return false; }
            current = System.IO.Path.Combine(current, part);
            if ((System.IO.Directory.Exists(current) || System.IO.File.Exists(current)) && IsReparsePoint(current)) { why = "goes through a link"; return false; }
        }
        if (t.Mode == StorageTargetMode.File && IsProtectedFile(System.IO.Path.GetFileName(path))) { why = "protected file"; return false; }
        why = "";
        return true;
    }

    /// <summary>The newest write time anywhere in a folder (or of a file). Unreadable, or containing a link: "now" (so age rules keep it).</summary>
    public static DateTime NewestWriteUtc(string path, DateTime utcNow, CancellationToken ct = default)
    {
        try
        {
            if (IsReparsePoint(path)) return utcNow;
            if (System.IO.File.Exists(path)) return System.IO.File.GetLastWriteTimeUtc(path);
            var newest = System.IO.Directory.GetLastWriteTimeUtc(path);
            var pending = new Stack<string>();
            pending.Push(path);
            while (pending.TryPop(out var dir))
            {
                ct.ThrowIfCancellationRequested();
                foreach (var e in new DirectoryInfo(dir).EnumerateFileSystemInfos())
                {
                    if ((e.Attributes & FileAttributes.ReparsePoint) != 0) return utcNow;
                    if (e.LastWriteTimeUtc > newest) newest = e.LastWriteTimeUtc;
                    if (e is DirectoryInfo d) pending.Push(d.FullName);
                }
            }
            return newest;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return utcNow; }
    }

    private sealed class Tally
    {
        public long Files, Bytes;
        public int InUse, Links, Protected, Refused;
        public readonly List<string> Dirs = [];
    }

    private static bool Matches(StorageTarget t, FileInfo f) =>
        (t.OlderThanUtc is null || f.LastWriteTimeUtc < t.OlderThanUtc.Value)
        && (t.Pattern is null || FileSystemName.MatchesSimpleExpression(t.Pattern, f.Name))
        && (t.MaxFileBytes is null || f.Length <= t.MaxFileBytes.Value);

    /// <summary>Files the target covers. Never enters or returns a reparse point; folders visited are recorded for pruning.</summary>
    private static IEnumerable<FileInfo> Matching(StorageTarget t, Tally tally, CancellationToken ct)
    {
        if (t.Mode == StorageTargetMode.File)
        {
            var fi = new FileInfo(t.Path);
            if (!fi.Exists) yield break;
            if ((fi.Attributes & FileAttributes.ReparsePoint) != 0) { tally.Links++; yield break; }
            if (IsProtectedFile(fi.Name)) { tally.Protected++; yield break; }
            yield return fi;
            yield break;
        }
        if (!System.IO.Directory.Exists(t.Path) || IsReparsePoint(t.Path)) yield break;
        var pending = new Stack<string>();
        pending.Push(t.Path);
        var n = 0;
        while (pending.TryPop(out var dir))
        {
            ct.ThrowIfCancellationRequested();
            List<FileSystemInfo> entries;
            try { entries = new DirectoryInfo(dir).EnumerateFileSystemInfos().ToList(); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { tally.InUse++; continue; }
            tally.Dirs.Add(dir);
            foreach (var e in entries)
            {
                if ((++n & 1023) == 0) ct.ThrowIfCancellationRequested();
                if ((e.Attributes & FileAttributes.ReparsePoint) != 0) { tally.Links++; continue; } // never followed, never deleted
                if (e is DirectoryInfo d)
                {
                    if (t.Mode == StorageTargetMode.Directory || !t.TopLevelOnly) pending.Push(d.FullName);
                    continue;
                }
                var f = (FileInfo)e;
                if (IsProtectedFile(f.Name)) { tally.Protected++; continue; }
                if (t.Mode == StorageTargetMode.Contents && !Matches(t, f)) continue;
                yield return f;
            }
        }
    }

    /// <summary>Files and bytes the target would delete right now (same walk and rules as <see cref="Clean"/>).</summary>
    public static (long Files, long Bytes) Measure(StorageTarget t, CancellationToken ct = default)
    {
        long files = 0, bytes = 0;
        foreach (var f in Matching(t, new Tally(), ct))
        {
            try { bytes += f.Length; files++; } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
        return (files, bytes);
    }

    private static bool TryDelete(FileInfo f, Tally tally)
    {
        try
        {
            f.Refresh();
            if (!f.Exists) return false;
            if ((f.Attributes & FileAttributes.ReparsePoint) != 0) { tally.Links++; return false; }
            var len = f.Length;
            var attrs = f.Attributes;
            if ((attrs & FileAttributes.ReadOnly) != 0) f.Attributes = attrs & ~FileAttributes.ReadOnly;
            try { f.Delete(); }
            catch
            {
                try { if ((attrs & FileAttributes.ReadOnly) != 0) { f.Refresh(); if (f.Exists) f.Attributes = attrs; } } catch { }
                throw;
            }
            f.Refresh();
            if (f.Exists) { tally.InUse++; return false; } // read back: still there (delete pending / refused)
            tally.Files++;
            tally.Bytes += len;
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { tally.InUse++; return false; }
    }

    private static bool CanDeleteExclusively(FileInfo f)
    {
        FileAttributes attrs = 0;
        var clearedReadOnly = false;
        try
        {
            f.Refresh();
            if (!f.Exists) return true;
            if ((f.Attributes & FileAttributes.ReparsePoint) != 0) return false;
            attrs = f.Attributes;
            if ((attrs & FileAttributes.ReadOnly) != 0)
            {
                f.Attributes = attrs & ~FileAttributes.ReadOnly;
                clearedReadOnly = true;
            }
            using var _ = new FileStream(f.FullName, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
        finally
        {
            if (clearedReadOnly)
            {
                try { f.Refresh(); if (f.Exists) f.Attributes = attrs; } catch { }
            }
        }
    }

    private static bool IsMarker(string name, IReadOnlyList<string> patterns)
    {
        foreach (var p in patterns)
            if (FileSystemName.MatchesSimpleExpression(p, name)) return true;
        return false;
    }

    private static void DeleteAtomicFolder(StorageTarget t, IReadOnlyList<string> markerPatterns, Tally tally, CancellationToken ct)
    {
        if (!System.IO.Directory.Exists(t.Path) || IsReparsePoint(t.Path)) return;
        var root = Normalize(t.Path);
        var dirs = new List<string>();
        var markers = new List<FileInfo>();
        var payload = new List<FileInfo>();
        var pending = new Stack<string>();
        pending.Push(t.Path);
        var n = 0;
        while (pending.TryPop(out var dir))
        {
            ct.ThrowIfCancellationRequested();
            List<FileSystemInfo> entries;
            try { entries = new DirectoryInfo(dir).EnumerateFileSystemInfos().ToList(); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { tally.InUse++; return; }
            var normDir = Normalize(dir);
            dirs.Add(normDir);
            var isTop = string.Equals(normDir, root, StringComparison.OrdinalIgnoreCase);
            foreach (var e in entries)
            {
                if ((++n & 1023) == 0) ct.ThrowIfCancellationRequested();
                if ((e.Attributes & FileAttributes.ReparsePoint) != 0) { tally.Links++; continue; }
                if (e is DirectoryInfo d) { pending.Push(d.FullName); continue; }
                var f = (FileInfo)e;
                if (IsProtectedFile(f.Name)) { tally.Protected++; continue; }
                if (isTop && IsMarker(f.Name, markerPatterns)) markers.Add(f);
                else payload.Add(f);
            }
        }

        // Pre-check exclusive access on every file (markers and payload) before deleting anything so a locked DLL or marker leaves the package complete.
        foreach (var f in markers)
        {
            ct.ThrowIfCancellationRequested();
            if (!CanDeleteExclusively(f)) { tally.InUse++; return; }
        }
        foreach (var f in payload)
        {
            ct.ThrowIfCancellationRequested();
            if (!CanDeleteExclusively(f)) { tally.InUse++; return; }
        }

        // Delete payload files first: if a file becomes locked in a race, markers remain on disk so NuGet and future scans stay consistent.
        string? checkedDir = null;
        foreach (var f in payload)
        {
            ct.ThrowIfCancellationRequested();
            var dir = f.DirectoryName!;
            if (!string.Equals(dir, checkedDir, StringComparison.OrdinalIgnoreCase))
            {
                if (IsReparsePoint(dir)) { tally.Links++; return; }
                checkedDir = dir;
            }
            f.Refresh();
            if (!f.Exists) continue;
            if (!TryDelete(f, tally)) return;
        }

        if (IsReparsePoint(root)) { tally.Links++; return; }
        var backups = new List<(string Path, byte[] Bytes, DateTime LastWriteUtc, FileAttributes Attributes)>(markers.Count);
        foreach (var m in markers)
        {
            try
            {
                m.Refresh();
                if (m.Exists) backups.Add((m.FullName, System.IO.File.ReadAllBytes(m.FullName), m.LastWriteTimeUtc, m.Attributes));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { tally.InUse++; return; }
        }

        var deletedMarkers = new List<(string Path, byte[] Bytes, DateTime LastWriteUtc, FileAttributes Attributes)>(markers.Count);
        for (var i = 0; i < markers.Count; i++)
        {
            var m = markers[i];
            m.Refresh();
            if (!m.Exists) continue;
            if (!TryDelete(m, tally))
            {
                foreach (var b in deletedMarkers)
                {
                    try
                    {
                        System.IO.File.WriteAllBytes(b.Path, b.Bytes);
                        System.IO.File.SetLastWriteTimeUtc(b.Path, b.LastWriteUtc);
                        var normalAttrs = b.Attributes & ~FileAttributes.ReparsePoint;
                        if (normalAttrs != 0) System.IO.File.SetAttributes(b.Path, normalAttrs);
                        tally.Files--;
                        tally.Bytes -= b.Bytes.Length;
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
                }
                return;
            }
            var match = backups.FirstOrDefault(b => string.Equals(b.Path, m.FullName, StringComparison.OrdinalIgnoreCase));
            if (match.Path is not null) deletedMarkers.Add(match);
        }

        foreach (var d in dirs.Distinct(StringComparer.OrdinalIgnoreCase).OrderByDescending(x => x.Length))
        {
            try
            {
                if (!System.IO.Directory.Exists(d) || IsReparsePoint(d) || System.IO.Directory.EnumerateFileSystemEntries(d).Any()) continue;
                System.IO.Directory.Delete(d, recursive: false);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }

    private static void Delete(StorageTarget t, Tally tally, CancellationToken ct)
    {
        if (t.Mode == StorageTargetMode.Directory && t.DeleteFirst is { Count: > 0 } first)
        {
            DeleteAtomicFolder(t, first, tally, ct);
            return;
        }

        var touched = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var tallyDirsStart = tally.Dirs.Count;
        string? checkedDir = null;
        foreach (var f in Matching(t, tally, ct))
        {
            var dir = f.DirectoryName!;
            if (!string.Equals(dir, checkedDir, StringComparison.OrdinalIgnoreCase))
            {
                if (IsReparsePoint(dir)) { tally.Links++; continue; } // swapped for a link since it was listed
                checkedDir = dir;
            }
            f.Refresh();
            if (!f.Exists) continue;
            if (t.Mode == StorageTargetMode.Contents && !Matches(t, f)) continue; // re-checked right before deleting
            if (TryDelete(f, tally)) touched.Add(dir);
        }

        if (t.Mode == StorageTargetMode.File) return;
        // Remove folders left empty: the whole tree for a Directory target; for Contents only folders we emptied (never the root).
        var root = Normalize(t.Path);
        var prune = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (t.Mode == StorageTargetMode.Directory) foreach (var d in tally.Dirs.Skip(tallyDirsStart)) prune.Add(Normalize(d));
        else
            foreach (var d in touched)
                for (var cur = Normalize(d); cur.Length > root.Length && cur.StartsWith(root, StringComparison.OrdinalIgnoreCase); cur = Normalize(System.IO.Path.GetDirectoryName(cur)!))
                    prune.Add(cur);
        if (t.Mode == StorageTargetMode.Contents) prune.Remove(root);
        foreach (var d in prune.OrderByDescending(x => x.Length))
        {
            try
            {
                if (!System.IO.Directory.Exists(d) || IsReparsePoint(d) || System.IO.Directory.EnumerateFileSystemEntries(d).Any()) continue;
                System.IO.Directory.Delete(d, recursive: false);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }

    /// <summary>
    /// Runs one category: skips it entirely if its app is open, evaluates its rule again on disk, refuses any target that isn't on its
    /// allowlist or goes through a link, deletes, and reports what was removed.
    /// </summary>
    public static StorageCleanResult Clean(StorageCategory c, StorageScanContext ctx, Func<string, bool> isAppRunning, CancellationToken ct = default)
    {
        var running = c.BlockingApps.Where(a =>
        {
            try { return isAppRunning(a); } catch (Exception) { return true; } // can't tell: treat as open
        }).ToList();
        if (running.Count > 0)
            return new(c.Id, false, 0, 0, 0, $"Skipped: {c.AppLabel} is open, so nothing was deleted. Close it and run this again.", running);

        IReadOnlyList<string> allowed;
        IReadOnlyList<StorageTarget> targets;
        try
        {
            allowed = c.AllowedRoots(ctx).Select(Normalize).ToList();
            targets = c.Targets(ctx, ct);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            ctx.Log.Warn($"[storage] {c.Id}: couldn't evaluate the rule: {ex.Message}");
            return StorageCleanResult.NotRun(c.Id, "Couldn't check what to delete, so nothing was deleted.");
        }

        var tally = new Tally();
        foreach (var t in targets)
        {
            ct.ThrowIfCancellationRequested();
            if (!IsAllowed(t, allowed, ctx.Roots, out var why))
            {
                tally.Refused++;
                ctx.Log.Info($"[storage] {c.Id}: refused {t.Path}: {why}");
                continue;
            }
            Delete(t, tally, ct);
        }
        ctx.Log.Info($"[storage] {c.Id}: removed {tally.Files} files ({tally.Bytes} bytes); in use {tally.InUse}, links {tally.Links}, protected {tally.Protected}, refused {tally.Refused}");
        return new(c.Id, true, tally.Files, tally.Bytes, tally.InUse, Describe(tally), Refused: tally.Refused, LinksSkipped: tally.Links);
    }

    /// <summary>"4.1 GB", "350 MB", or "2 KB" for small amounts (lock files).</summary>
    public static string SizeText(long bytes) => bytes >= 1L << 20 ? MemoryText.Size(bytes)
        : (bytes <= 0 ? 0 : Math.Max(1, (bytes + 1023) / 1024)).ToString(CultureInfo.InvariantCulture) + " KB";

    private static string Describe(Tally t)
    {
        var left = t.InUse > 0 ? $"{MemoryText.Plural(t.InUse, "file was", "files were")} in use and left as is." : "";
        if (t.Files > 0)
            return $"Freed {SizeText(t.Bytes)} ({t.Files.ToString("N0", CultureInfo.InvariantCulture)} {(t.Files == 1 ? "file" : "files")} deleted)." + (left.Length > 0 ? " " + left : "");
        return t.InUse > 0 ? "Nothing was deleted: " + left : "Nothing left to delete.";
    }
}
