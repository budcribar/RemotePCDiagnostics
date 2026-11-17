using System.Globalization;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Storage;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>One large file found during disk space analysis.</summary>
public sealed record LargeFileInfo(string Name, string FullPath, long SizeBytes, DateTime LastModifiedUtc, string Category)
{
    public static string Classify(string extension) => extension.ToLowerInvariant() switch
    {
        ".mp4" or ".mkv" or ".avi" or ".mov" or ".wmv" or ".flv" or ".webm" => "Video",
        ".iso" or ".img" or ".vhd" or ".vhdx" or ".vmdk" or ".qcow2" => "Disc / VM Image",
        ".zip" or ".7z" or ".rar" or ".tar" or ".gz" or ".bz2" or ".xz" or ".bak" => "Archive / Backup",
        ".dmp" or ".sys" => "Crash dump / System",
        ".exe" or ".msi" or ".cab" or ".msix" or ".appx" => "Installer",
        ".pst" or ".ost" or ".db" or ".sqlite" or ".mdf" or ".ldf" => "Database / Mail",
        _ => "Other file",
    };
}

/// <summary>One folder ranked by its total size.</summary>
public sealed record FolderSpaceInfo(string Name, string FullPath, long TotalSizeBytes, int FileCount);

/// <summary>
/// Scans storage drives to show where disk space went: surfaces the top largest files (>= 100 MB by default)
/// and largest top-level / user folders.
/// </summary>
public sealed class DiskSpaceModule(ILogger? log = null, string? targetRoot = null, long minFileSizeBytes = 100L * 1024 * 1024)
    : AreaModuleBase(log), ICancellableScan
{
    public const string ModuleName = ModuleSlugs.DiskSpace;
    public const int MaxLargeFiles = 50;
    public const int MaxFolders = 20;

    private readonly object _scanGate = new();
    private CancellationTokenSource? _scanCts;

    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.DiskSpace;
    public override string DisplayName => "Large files & folders";
    protected override string FailedMessage => "Couldn't scan disk space on this PC.";

    public long MinFileSizeBytes => minFileSizeBytes;
    public string RootPath => targetRoot ?? Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\";

    public void Cancel()
    {
        lock (_scanGate) _scanCts?.Cancel();
    }

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        using var scan = CancellationTokenSource.CreateLinkedTokenSource(ct);
        lock (_scanGate) _scanCts = scan;
        try
        {
            return await Task.Run(() => Scan(RootPath, minFileSizeBytes, progress, scan.Token), scan.Token).ConfigureAwait(false);
        }
        finally
        {
            lock (_scanGate) { if (ReferenceEquals(_scanCts, scan)) _scanCts = null; }
        }
    }

    public AreaReport Scan(string root, long minSizeBytes, IProgress<string>? progress, CancellationToken ct)
    {
        if (!Directory.Exists(root))
            return AreaReport.Failed($"Target drive or folder '{root}' does not exist.");

        progress.ReportStep(1, 3, $"Scanning folders on {root}…");

        var largeFiles = new List<LargeFileInfo>();
        var folderSizes = new Dictionary<string, (long Bytes, int Files)>(StringComparer.OrdinalIgnoreCase);

        // Gather candidate top-level branches to measure (e.g. C:\Users, C:\Program Files, C:\Windows, C:\Users\<user>\*)
        var branchRoots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var dir in Directory.EnumerateDirectories(root))
            {
                ct.ThrowIfCancellationRequested();
                if (StorageCleanupEngine.IsReparsePoint(dir)) continue;
                branchRoots.Add(dir);

                // If Users directory, also break down per-user folders
                if (string.Equals(Path.GetFileName(dir), "Users", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        foreach (var userDir in Directory.EnumerateDirectories(dir))
                        {
                            ct.ThrowIfCancellationRequested();
                            if (!StorageCleanupEngine.IsReparsePoint(userDir))
                            {
                                branchRoots.Add(userDir);
                                foreach (var sub in new[] { "Downloads", "Documents", "Videos", "Music", "Pictures", "Desktop" })
                                {
                                    var subPath = Path.Combine(userDir, sub);
                                    if (Directory.Exists(subPath) && !StorageCleanupEngine.IsReparsePoint(subPath))
                                        branchRoots.Add(subPath);
                                }
                            }
                        }
                    }
                    catch { /* skip inaccessible user folders */ }
                }
            }
        }
        catch { /* root enumeration error */ }

        // Stack-based directory traversal
        var pendingDirs = new Stack<string>();
        pendingDirs.Push(root);

        int scannedFolders = 0;
        long totalScannedBytes = 0;

        while (pendingDirs.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var currentDir = pendingDirs.Pop();

            if (scannedFolders++ % 100 == 0)
            {
                progress.ReportStep(2, 3, $"Scanning {Path.GetFileName(currentDir)} ({largeFiles.Count} large files found)…");
            }

            // Enumerate files in current directory
            try
            {
                var dirInfo = new DirectoryInfo(currentDir);
                foreach (var file in dirInfo.EnumerateFiles())
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        long len = file.Length;
                        totalScannedBytes += len;

                        // Attribute to branch roots
                        foreach (var branch in branchRoots)
                        {
                            if (currentDir.StartsWith(branch, StringComparison.OrdinalIgnoreCase))
                            {
                                var current = folderSizes.GetValueOrDefault(branch);
                                folderSizes[branch] = (current.Bytes + len, current.Files + 1);
                            }
                        }

                        // Check if file qualifies as large file
                        if (len >= minSizeBytes)
                        {
                            largeFiles.Add(new LargeFileInfo(
                                file.Name,
                                file.FullName,
                                len,
                                file.LastWriteTimeUtc,
                                LargeFileInfo.Classify(file.Extension)));
                        }
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PathTooLongException)
            {
                // Inaccessible folder; continue with remaining folders
                continue;
            }

            // Enumerate subdirectories
            try
            {
                foreach (var subDir in Directory.EnumerateDirectories(currentDir))
                {
                    ct.ThrowIfCancellationRequested();
                    if (StorageCleanupEngine.IsReparsePoint(subDir)) continue;
                    pendingDirs.Push(subDir);
                }
            }
            catch { }
        }

        progress.ReportStep(3, 3, "Compiling disk space breakdown…");

        // Sort and pick top large files
        var topFiles = largeFiles.OrderByDescending(f => f.SizeBytes).Take(MaxLargeFiles).ToList();

        // Sort and pick top folders
        var topFolders = folderSizes
            .Select(kv => new FolderSpaceInfo(Path.GetFileName(kv.Key) is { Length: > 0 } n ? n : kv.Key, kv.Key, kv.Value.Bytes, kv.Value.Files))
            .OrderByDescending(f => f.TotalSizeBytes)
            .Take(MaxFolders)
            .ToList();

        return BuildReport(root, minSizeBytes, topFiles, topFolders);
    }

    public static AreaReport BuildReport(string root, long minSizeBytes, IReadOnlyList<LargeFileInfo> files, IReadOnlyList<FolderSpaceInfo> folders)
    {
        var cards = new List<AreaCard>();
        long totalLargeFilesBytes = files.Sum(f => f.SizeBytes);

        // Card 1: Largest Folders
        string[] folderCols = ["Folder", "Size", "Items", "Path"];
        var folderRows = folders.Select(f => new AreaRow(
            AreaLevel.Neutral,
            [f.Name, HardwareInventory.FormatBytes(f.TotalSizeBytes), f.FileCount.ToString("N0", CultureInfo.InvariantCulture), f.FullPath],
            SortKeys: [f.Name, f.TotalSizeBytes.ToString("D19"), f.FileCount.ToString("D10"), f.FullPath],
            Detail: $"{f.FullPath}: {HardwareInventory.FormatBytes(f.TotalSizeBytes)} across {f.FileCount:N0} files")).ToList();

        cards.Add(new AreaCard(
            "folders",
            "Largest Folders",
            AreaLevel.Neutral,
            folders.Count > 0 ? $"{folders.Count} largest directories on {root}" : "No large folders found",
            folders.Count > 0 ? $"Top folder: {folders[0].Name} ({HardwareInventory.FormatBytes(folders[0].TotalSizeBytes)})" : "",
            folderCols,
            folderRows,
            EmptyText: "No folder details available."));

        // Card 2: Top Large Files
        string[] fileCols = ["File", "Size", "Type", "Modified", "Folder"];
        var fileRows = files.Select(f => new AreaRow(
            AreaLevel.Neutral,
            [f.Name, HardwareInventory.FormatBytes(f.SizeBytes), f.Category, f.LastModifiedUtc.ToString("yyyy-MM-dd"), Path.GetDirectoryName(f.FullPath) ?? ""],
            SortKeys: [f.Name, f.SizeBytes.ToString("D19"), f.Category, f.LastModifiedUtc.ToString("s"), f.FullPath],
            Detail: $"{f.FullPath}\nSize: {HardwareInventory.FormatBytes(f.SizeBytes)} ({f.SizeBytes:N0} bytes)\nType: {f.Category}\nModified: {f.LastModifiedUtc:yyyy-MM-dd HH:mm:ss} UTC")).ToList();

        cards.Add(new AreaCard(
            "files",
            "Top Large Files",
            AreaLevel.Neutral,
            files.Count > 0 ? $"{files.Count} files >= {HardwareInventory.FormatBytes(minSizeBytes)} (total {HardwareInventory.FormatBytes(totalLargeFilesBytes)})" : $"No files >= {HardwareInventory.FormatBytes(minSizeBytes)} found",
            files.Count > 0 ? $"Largest: {files[0].Name} ({HardwareInventory.FormatBytes(files[0].SizeBytes)})" : "",
            fileCols,
            fileRows,
            EmptyText: $"No files larger than {HardwareInventory.FormatBytes(minSizeBytes)} were found."));

        string summary = files.Count > 0
            ? $"Found {files.Count} large files on {root} totaling {HardwareInventory.FormatBytes(totalLargeFilesBytes)}"
            : $"Scan complete on {root} · No files >= {HardwareInventory.FormatBytes(minSizeBytes)}";

        return new AreaReport(cards, summary, DiagnosticStatus.Ok);
    }
}
