using System.Globalization;
using System.Runtime.InteropServices;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Storage;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>Drive capacity details (total, used, free) for a scanned storage volume.</summary>
public sealed record DriveCapacityInfo(
    string DriveName,
    string VolumeLabel,
    string DriveFormat,
    long TotalBytes,
    long FreeBytes)
{
    public long UsedBytes => Math.Max(0, TotalBytes - FreeBytes);
    public double UsedPercent => TotalBytes > 0 ? (double)UsedBytes / TotalBytes * 100.0 : 0.0;
}

/// <summary>One large file found during disk space analysis.</summary>
public sealed record LargeFileInfo(
    string Name,
    string FullPath,
    long SizeBytes,
    DateTime LastModifiedUtc,
    string Category,
    bool IsCloudOnly = false,
    long DiskSizeBytes = -1)
{
    public long ActualDiskBytes => DiskSizeBytes >= 0 ? DiskSizeBytes : (IsCloudOnly ? 0L : SizeBytes);
    public string StorageState => IsCloudOnly ? "Cloud-only" : "Local";

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

/// <summary>One folder ranked by its total size on disk.</summary>
public sealed record FolderSpaceInfo(
    string Name,
    string FullPath,
    long TotalSizeBytes,
    int FileCount,
    long LogicalSizeBytes = -1)
{
    public long TotalLogicalBytes => LogicalSizeBytes >= 0 ? LogicalSizeBytes : TotalSizeBytes;
}

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
        var folderSizes = new Dictionary<string, (long DiskBytes, int Files, long LogicalBytes)>(StringComparer.OrdinalIgnoreCase);
        var windowsDir = GetWindowsDirectory();
        var drives = GetDrivesForScan(root);

        // Gather candidate top-level branches to measure (e.g. C:\Users, C:\Program Files, C:\Windows, C:\Users\<user>\*)
        var branchRoots = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var dir in Directory.EnumerateDirectories(root))
            {
                ct.ThrowIfCancellationRequested();
                if (StorageCleanupEngine.IsReparsePoint(dir)) continue;
                if (IsSystemDirectory(dir)) continue;
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
                                foreach (var sub in new[] { "Downloads", "Documents", "Videos", "Music", "Pictures", "Desktop", "OneDrive" })
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
        long lastReportTicks = Environment.TickCount64;

        while (pendingDirs.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var currentDir = pendingDirs.Pop();

            scannedFolders++;
            var now = Environment.TickCount64;
            // Throttle progress updates to at most once per 250ms to prevent flooding the Blazor UI dispatcher
            if (now - lastReportTicks >= 250)
            {
                lastReportTicks = now;
                progress?.ReportStep(2, 3, $"Scanning {Path.GetFileName(currentDir)} ({largeFiles.Count} large files found)…");
            }

            // Determine matching branch roots once for the current folder instead of repeatedly per file
            List<string>? currentMatchingBranches = null;
            foreach (var branch in branchRoots)
            {
                if (currentDir.StartsWith(branch, StringComparison.OrdinalIgnoreCase))
                {
                    currentMatchingBranches ??= [];
                    currentMatchingBranches.Add(branch);
                }
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
                        bool isCloud = IsCloudOnlyFile(file);
                        long diskBytes = GetDiskSpaceUsed(file, isCloud);

                        totalScannedBytes += diskBytes;

                        // Attribute to branch roots (accumulating actual disk space and logical space)
                        if (currentMatchingBranches is not null)
                        {
                            foreach (var branch in currentMatchingBranches)
                            {
                                var current = folderSizes.GetValueOrDefault(branch);
                                folderSizes[branch] = (current.DiskBytes + diskBytes, current.Files + 1, current.LogicalBytes + len);
                            }
                        }

                        // Check if file qualifies as large file and is not a system file
                        if (Math.Max(len, diskBytes) >= minSizeBytes && !IsSystemFile(file, windowsDir))
                        {
                            largeFiles.Add(new LargeFileInfo(
                                file.Name,
                                file.FullName,
                                len,
                                file.LastWriteTimeUtc,
                                LargeFileInfo.Classify(file.Extension),
                                IsCloudOnly: isCloud,
                                DiskSizeBytes: diskBytes));
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
                    if (IsSystemDirectory(subDir)) continue;
                    pendingDirs.Push(subDir);
                }
            }
            catch { }
        }

        progress.ReportStep(3, 3, "Compiling disk space breakdown…");

        // Sort and pick top large files (primary: space on disk, secondary: logical size)
        var topFiles = largeFiles
            .OrderByDescending(f => f.ActualDiskBytes)
            .ThenByDescending(f => f.SizeBytes)
            .Take(MaxLargeFiles)
            .ToList();

        // Sort and pick top folders by actual disk space
        var topFolders = folderSizes
            .Select(kv => new FolderSpaceInfo(
                Path.GetFileName(kv.Key) is { Length: > 0 } n ? n : kv.Key,
                kv.Key,
                kv.Value.DiskBytes,
                kv.Value.Files,
                kv.Value.LogicalBytes))
            .OrderByDescending(f => f.TotalSizeBytes)
            .Take(MaxFolders)
            .ToList();

        return BuildReport(root, minSizeBytes, topFiles, topFolders, drives);
    }

    public static string? GetWindowsDirectory()
    {
        var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrWhiteSpace(win))
        {
            var sys = Environment.SystemDirectory;
            if (!string.IsNullOrWhiteSpace(sys))
            {
                win = Path.GetDirectoryName(sys);
            }
        }
        return string.IsNullOrWhiteSpace(win) ? null : win;
    }

    public static bool IsSystemDirectory(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var lastSlash = Math.Max(path.LastIndexOf('\\'), path.LastIndexOf('/'));
        var name = lastSlash >= 0 ? path[(lastSlash + 1)..] : path;
        return string.Equals(name, "System Volume Information", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(name, "$Recycle.Bin", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(name, "$Windows.~BT", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(name, "$WinREAgent", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsSystemFile(FileInfo file, string? windowsDir = null)
    {
        try
        {
            if ((file.Attributes & FileAttributes.System) != 0)
                return true;
        }
        catch { }

        return IsSystemFilePath(file.FullName, file.Extension, windowsDir);
    }

    public static bool IsSystemFilePath(string fullPath, string? extension = null, string? windowsDir = null)
    {
        if (string.IsNullOrWhiteSpace(fullPath)) return false;

        extension ??= Path.GetExtension(fullPath);
        if (string.Equals(extension, ".sys", StringComparison.OrdinalIgnoreCase))
            return true;

        if (!string.IsNullOrEmpty(windowsDir))
        {
            var normalizedWin = windowsDir.Replace('/', '\\').TrimEnd('\\');
            var normalizedPath = fullPath.Replace('/', '\\');
            if (normalizedPath.StartsWith(normalizedWin + "\\", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(normalizedPath, normalizedWin, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        if (fullPath.Contains("System Volume Information", StringComparison.OrdinalIgnoreCase) ||
            fullPath.Contains("$Recycle.Bin", StringComparison.OrdinalIgnoreCase) ||
            fullPath.Contains("$Windows.~BT", StringComparison.OrdinalIgnoreCase) ||
            fullPath.Contains("$WinREAgent", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var lastSlash = Math.Max(fullPath.LastIndexOf('\\'), fullPath.LastIndexOf('/'));
        var fileName = lastSlash >= 0 ? fullPath[(lastSlash + 1)..] : fullPath;
        return string.Equals(fileName, "pagefile.sys", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(fileName, "hiberfil.sys", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(fileName, "swapfile.sys", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(fileName, "dumpstack.log.tmp", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(fileName, "dumpstack.log", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(fileName, "bootmgr", StringComparison.OrdinalIgnoreCase);
    }

    public const long AttributeOffline = 0x1000L;
    public const long AttributeRecallOnOpen = 0x00040000L;
    public const long AttributeRecallOnDataAccess = 0x00400000L;

    public static bool IsCloudOnlyFile(FileInfo file)
    {
        try
        {
            var attrs = (long)file.Attributes;
            if (IsCloudOnlyAttributes(attrs))
                return true;
        }
        catch { }

        return IsCloudOnlyPath(file.FullName);
    }

    public static bool IsCloudOnlyAttributes(long attributes)
    {
        const long mask = AttributeOffline | AttributeRecallOnOpen | AttributeRecallOnDataAccess;
        return (attributes & mask) != 0;
    }

    public static bool IsCloudOnlyPath(string fullPath)
    {
        if (string.IsNullOrWhiteSpace(fullPath)) return false;
        return fullPath.Contains("Phone Link", StringComparison.OrdinalIgnoreCase) ||
               fullPath.Contains("Your Phone", StringComparison.OrdinalIgnoreCase) ||
               fullPath.Contains("CrossDevice", StringComparison.OrdinalIgnoreCase);
    }

    public static long GetDiskSpaceUsed(FileInfo file, bool isCloudOnly)
    {
        if (isCloudOnly) return 0L;

        if (OperatingSystem.IsWindows())
        {
            try
            {
                var attrs = file.Attributes;
                if ((attrs & (FileAttributes.Compressed | FileAttributes.SparseFile)) != 0)
                {
                    uint high;
                    uint low = GetCompressedFileSizeW(file.FullName, out high);
                    if (low != 0xFFFFFFFF || Marshal.GetLastWin32Error() == 0)
                    {
                        return ((long)high << 32) | low;
                    }
                }
            }
            catch { }
        }

        return file.Length;
    }

    [DllImport("kernel32.dll", EntryPoint = "GetCompressedFileSizeW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetCompressedFileSizeW(string lpFileName, out uint lpFileSizeHigh);

    public static IReadOnlyList<DriveCapacityInfo> GetDrivesForScan(string root)
    {
        var list = new List<DriveCapacityInfo>();
        try
        {
            var pathRoot = Path.GetPathRoot(root);
            if (!string.IsNullOrEmpty(pathRoot))
            {
                var d = new DriveInfo(pathRoot);
                if (d.IsReady)
                {
                    list.Add(new DriveCapacityInfo(
                        d.Name,
                        string.IsNullOrWhiteSpace(d.VolumeLabel) ? d.Name : d.VolumeLabel,
                        d.DriveFormat,
                        d.TotalSize,
                        d.TotalFreeSpace));
                }
            }
        }
        catch { }

        if (list.Count == 0)
        {
            try
            {
                foreach (var d in DriveInfo.GetDrives())
                {
                    if (d.IsReady && (d.DriveType == DriveType.Fixed || string.Equals(d.Name, root, StringComparison.OrdinalIgnoreCase)))
                    {
                        list.Add(new DriveCapacityInfo(
                            d.Name,
                            string.IsNullOrWhiteSpace(d.VolumeLabel) ? d.Name : d.VolumeLabel,
                            d.DriveFormat,
                            d.TotalSize,
                            d.TotalFreeSpace));
                    }
                }
            }
            catch { }
        }

        return list;
    }

    public static AreaReport BuildReport(
        string root,
        long minSizeBytes,
        IReadOnlyList<LargeFileInfo> files,
        IReadOnlyList<FolderSpaceInfo> folders,
        IReadOnlyList<DriveCapacityInfo>? drives = null)
    {
        drives ??= GetDrivesForScan(root);
        var cards = new List<AreaCard>();
        long totalLargeFilesDiskBytes = files.Sum(f => f.ActualDiskBytes);

        // Card 1: Drive Capacity
        if (drives.Count > 0)
        {
            string[] driveCols = ["Drive", "Total", "Used", "Free", "% Used", "Format"];
            var driveRows = drives.Select(d => new AreaRow(
                d.UsedPercent >= 90.0 ? AreaLevel.Warning : AreaLevel.Neutral,
                [d.DriveName, HardwareInventory.FormatBytes(d.TotalBytes), HardwareInventory.FormatBytes(d.UsedBytes), HardwareInventory.FormatBytes(d.FreeBytes), $"{d.UsedPercent:0.#}%", d.DriveFormat],
                SortKeys: [d.DriveName, d.TotalBytes.ToString("D19"), d.UsedBytes.ToString("D19"), d.FreeBytes.ToString("D19"), d.UsedPercent.ToString("F2"), d.DriveFormat],
                Detail: $"{d.DriveName} ({d.VolumeLabel})\nTotal capacity: {HardwareInventory.FormatBytes(d.TotalBytes)} ({d.TotalBytes:N0} bytes)\nUsed space: {HardwareInventory.FormatBytes(d.UsedBytes)} ({d.UsedBytes:N0} bytes, {d.UsedPercent:0.#}%)\nFree space: {HardwareInventory.FormatBytes(d.FreeBytes)} ({d.FreeBytes:N0} bytes)\nFile system: {d.DriveFormat}",
                FilePath: d.DriveName)).ToList();

            cards.Add(new AreaCard(
                "drives",
                "Drive Capacity",
                drives.Any(d => d.UsedPercent >= 90.0) ? AreaLevel.Warning : AreaLevel.Neutral,
                drives.Count == 1
                    ? $"{drives[0].DriveName} {HardwareInventory.FormatBytes(drives[0].UsedBytes)} used of {HardwareInventory.FormatBytes(drives[0].TotalBytes)} ({HardwareInventory.FormatBytes(drives[0].FreeBytes)} free)"
                    : $"{drives.Count} drives scanned",
                drives.Count == 1 ? $"{drives[0].UsedPercent:0.#}% used · {drives[0].DriveFormat} file system" : $"{HardwareInventory.FormatBytes(drives.Sum(d => d.FreeBytes))} total free space",
                driveCols,
                driveRows,
                EmptyText: "No drive capacity information available."));
        }

        // Card 2: Largest Folders
        string[] folderCols = ["Folder", "Size", "Items", "Path"];
        var folderRows = folders.Select(f => new AreaRow(
            AreaLevel.Neutral,
            [f.Name, HardwareInventory.FormatBytes(f.TotalSizeBytes), f.FileCount.ToString("N0", CultureInfo.InvariantCulture), f.FullPath],
            SortKeys: [f.Name, f.TotalSizeBytes.ToString("D19"), f.FileCount.ToString("D10"), f.FullPath],
            Detail: f.TotalLogicalBytes > f.TotalSizeBytes
                ? $"{f.FullPath}: {HardwareInventory.FormatBytes(f.TotalSizeBytes)} on disk ({HardwareInventory.FormatBytes(f.TotalLogicalBytes)} total including cloud-only) across {f.FileCount:N0} files"
                : $"{f.FullPath}: {HardwareInventory.FormatBytes(f.TotalSizeBytes)} across {f.FileCount:N0} files",
            FilePath: f.FullPath)).ToList();

        cards.Add(new AreaCard(
            "folders",
            "Largest Folders",
            AreaLevel.Neutral,
            folders.Count > 0 ? $"{folders.Count} largest directories on {root}" : "No large folders found",
            folders.Count > 0 ? $"Top folder: {folders[0].Name} ({HardwareInventory.FormatBytes(folders[0].TotalSizeBytes)} on disk)" : "",
            folderCols,
            folderRows,
            EmptyText: "No folder details available."));

        // Card 3: Top Large Files
        string[] fileCols = ["File", "Size", "Type", "Storage", "Modified", "Folder"];
        var fileRows = files.Select(f => new AreaRow(
            AreaLevel.Neutral,
            [
                f.Name,
                f.IsCloudOnly ? $"0 B ({HardwareInventory.FormatBytes(f.SizeBytes)} cloud)" : HardwareInventory.FormatBytes(f.ActualDiskBytes),
                f.Category,
                f.StorageState,
                f.LastModifiedUtc.ToString("yyyy-MM-dd"),
                Path.GetDirectoryName(f.FullPath) ?? ""
            ],
            SortKeys: [f.Name, f.ActualDiskBytes.ToString("D19"), f.Category, f.StorageState, f.LastModifiedUtc.ToString("s"), f.FullPath],
            Detail: $"{f.FullPath}\nSize on disk: {HardwareInventory.FormatBytes(f.ActualDiskBytes)} ({f.ActualDiskBytes:N0} bytes)\nApparent size: {HardwareInventory.FormatBytes(f.SizeBytes)} ({f.SizeBytes:N0} bytes)\nStorage: {(f.IsCloudOnly ? "Cloud-only (remote/offline file, takes 0 bytes on disk)" : "Local")}\nType: {f.Category}\nModified: {f.LastModifiedUtc:yyyy-MM-dd HH:mm:ss} UTC",
            FilePath: f.FullPath)).ToList();

        cards.Add(new AreaCard(
            "files",
            "Top Large Files",
            AreaLevel.Neutral,
            files.Count > 0 ? $"{files.Count} files >= {HardwareInventory.FormatBytes(minSizeBytes)} (total {HardwareInventory.FormatBytes(totalLargeFilesDiskBytes)} on disk)" : $"No files >= {HardwareInventory.FormatBytes(minSizeBytes)} found",
            files.Count > 0 ? $"Largest: {files[0].Name} ({HardwareInventory.FormatBytes(files[0].ActualDiskBytes)})" : "",
            fileCols,
            fileRows,
            EmptyText: $"No files larger than {HardwareInventory.FormatBytes(minSizeBytes)} were found."));

        string drivePart = drives.Count > 0
            ? $"{drives[0].DriveName} ({HardwareInventory.FormatBytes(drives[0].UsedBytes)} used of {HardwareInventory.FormatBytes(drives[0].TotalBytes)}, {HardwareInventory.FormatBytes(drives[0].FreeBytes)} free) · "
            : "";

        string summary = files.Count > 0
            ? $"{drivePart}Found {files.Count} large files on {root} totaling {HardwareInventory.FormatBytes(totalLargeFilesDiskBytes)}"
            : $"{drivePart}Scan complete on {root} · No files >= {HardwareInventory.FormatBytes(minSizeBytes)}";

        return new AreaReport(cards, summary, DiagnosticStatus.Ok);
    }
}
