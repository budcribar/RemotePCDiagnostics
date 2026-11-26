using System.Globalization;
using System.Runtime.InteropServices;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Storage;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>Capacity (total, used, free) of one storage volume. <see cref="Removable"/> is a USB stick or memory card.</summary>
public sealed record DriveCapacityInfo(
    string DriveName,
    string VolumeLabel,
    string DriveFormat,
    long TotalBytes,
    long FreeBytes,
    bool Removable = false)
{
    /// <summary>A volume is low on space when it has less than this share of its capacity free and less than <see cref="LowFreeBytes"/>.</summary>
    public const double LowFreePercent = 10.0;
    /// <summary>Both limits must be passed: 5% free of a 4 TB drive is still 200 GB, which is no problem.</summary>
    public const long LowFreeBytes = 20L * 1024 * 1024 * 1024;

    public long UsedBytes => Math.Max(0, TotalBytes - FreeBytes);
    public double UsedPercent => TotalBytes > 0 ? (double)UsedBytes / TotalBytes * 100.0 : 0.0;
    public double FreePercent => TotalBytes > 0 ? (double)FreeBytes / TotalBytes * 100.0 : 0.0;

    /// <summary>The volume as people say it: "C:".</summary>
    public string Letter => DriveName.TrimEnd('\\', '/');

    /// <summary>Nearly full. Never a removable volume: a full USB stick or camera card is normal.</summary>
    public bool IsLowOnSpace => !Removable && TotalBytes > 0 && FreePercent < LowFreePercent && FreeBytes < LowFreeBytes;

    /// <summary>"C: is nearly full (12 GB free of 238 GB)".</summary>
    public string NearlyFullText => $"{Letter} is nearly full ({HardwareInventory.FormatBytes(FreeBytes)} free of {HardwareInventory.FormatBytes(TotalBytes)})";
}

/// <summary>Reads volume capacity from Windows (<see cref="DriveInfo"/>): quick, no scan and no administrator rights.</summary>
public static class DriveVolumes
{
    /// <summary>One volume's capacity, or null when it isn't ready or can't be read. Never throws.</summary>
    public static DriveCapacityInfo? TryRead(DriveInfo drive, ILogger? log = null)
    {
        try
        {
            if (!drive.IsReady) return null;
            return new DriveCapacityInfo(
                drive.Name,
                string.IsNullOrWhiteSpace(drive.VolumeLabel) ? drive.Name : drive.VolumeLabel,
                drive.DriveFormat,
                drive.TotalSize,
                drive.TotalFreeSpace,
                Removable: drive.DriveType == DriveType.Removable);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            log.Warn($"Volume {drive.Name}: capacity not read: {ex.Message}");
            return null;
        }
    }

    /// <summary>Every fixed and removable volume that is ready. Network and optical drives are never touched: asking a
    /// disconnected network drive whether it is ready can take many seconds. One unreadable volume doesn't hide the others.</summary>
    public static IReadOnlyList<DriveCapacityInfo> ReadLocal(ILogger? log = null)
    {
        DriveInfo[] all;
        try { all = DriveInfo.GetDrives(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            log.Warn($"Volume list not read: {ex.Message}");
            return [];
        }
        var list = new List<DriveCapacityInfo>();
        foreach (var d in all)
        {
            if (d.DriveType is not (DriveType.Fixed or DriveType.Removable)) continue;
            if (TryRead(d, log) is { } volume) list.Add(volume);
        }
        return list;
    }
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
public sealed class DiskSpaceModule(
    ILogger? log = null,
    string? targetRoot = null,
    long minFileSizeBytes = 100L * 1024 * 1024,
    LargeFileIgnoreStore? ignoreStore = null)
    : AreaModuleBase(log), ICancellableScan
{
    public const string ModuleName = ModuleSlugs.DiskSpace;
    public const int MaxLargeFiles = 50;
    public const int MaxFolders = 20;

    private readonly LargeFileIgnoreStore _ignoreStore = ignoreStore ?? LargeFileIgnoreStore.Default;
    private readonly object _scanGate = new();
    private CancellationTokenSource? _scanCts;

    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.DiskSpace;
    public override string DisplayName => "Large files & folders";
    protected override string FailedMessage => "Couldn't scan disk space on this PC.";

    public long MinFileSizeBytes => minFileSizeBytes;
    public string RootPath => targetRoot ?? SystemRoot;

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
        // Cancel() stops only this scan's token, so the base class would log the exception as a failed collection (Critical).
        catch (OperationCanceledException) when (scan.IsCancellationRequested && !ct.IsCancellationRequested)
        {
            return AreaReport.ScanCancelled();
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
        var ignoredPaths = _ignoreStore.GetIgnoredPaths();
        var drives = GetDrivesForScan(root, Logger);

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
            if ((scannedFolders & 63) == 0) Thread.Yield();
            var now = Environment.TickCount64;
            // Throttle progress updates to at most once per 500ms to prevent flooding the Blazor UI dispatcher
            if (now - lastReportTicks >= 500)
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

                        // Check if file qualifies as a local large file on disk and is not a system file, virtual disk (.vhdx), or user-ignored file
                        if (!isCloud
                            && diskBytes >= minSizeBytes
                            && !IsSystemFile(file, windowsDir)
                            && !IsIgnoredLargeFileExtension(file.Extension)
                            && !ignoredPaths.Contains(file.FullName))
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

    /// <summary>
    /// Extensions excluded from Top Large Files by default (e.g. <c>.vhdx</c> virtual disks used by Dev Drives,
    /// WSL2, Docker Desktop, and Hyper-V). They still count toward folder totals.
    /// </summary>
    public static bool IsIgnoredLargeFileExtension(string? extension) =>
        string.Equals(extension, ".vhdx", StringComparison.OrdinalIgnoreCase);

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

    /// <summary>The system drive's root ("C:\\"): what a scan covers unless told otherwise.</summary>
    public static string SystemRoot => Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\";

    /// <summary>The volume <paramref name="root"/> is on; when that can't be read, every fixed volume.</summary>
    public static IReadOnlyList<DriveCapacityInfo> GetDrivesForScan(string root, ILogger? log = null)
    {
        try
        {
            var pathRoot = Path.GetPathRoot(root);
            if (!string.IsNullOrEmpty(pathRoot) && DriveVolumes.TryRead(new DriveInfo(pathRoot), log) is { } volume)
                return [volume];
        }
        catch (ArgumentException ex) { log.Warn($"Volume of '{root}' not read: {ex.Message}"); }

        return DriveVolumes.ReadLocal(log).Where(v => !v.Removable).ToList();
    }

    /// <summary>Id of the "Drive Capacity" card in this module's report.</summary>
    public const string CapacityCardId = "drives";

    /// <summary>The "Drive Capacity" card: one row per volume, a warning on each that is nearly full
    /// (<see cref="DriveCapacityInfo.IsLowOnSpace"/>), and the byte totals as numbers on the card.</summary>
    public static AreaCard BuildDriveCapacityCard(IReadOnlyList<DriveCapacityInfo> drives, string cardId = CapacityCardId)
    {
        string[] driveCols = ["Drive", "Total", "Used", "Free", "% Used", "Format"];
        var driveRows = drives.Select(d => new AreaRow(
            d.IsLowOnSpace ? AreaLevel.Warning : AreaLevel.Neutral,
            [d.DriveName, HardwareInventory.FormatBytes(d.TotalBytes), HardwareInventory.FormatBytes(d.UsedBytes), HardwareInventory.FormatBytes(d.FreeBytes), $"{d.UsedPercent:0.#}%", d.DriveFormat],
            SortKeys: [d.DriveName, d.TotalBytes.ToString("D19"), d.UsedBytes.ToString("D19"), d.FreeBytes.ToString("D19"), d.UsedPercent.ToString("F2"), d.DriveFormat],
            Detail: $"{d.DriveName} ({d.VolumeLabel})\nTotal capacity: {HardwareInventory.FormatBytes(d.TotalBytes)} ({d.TotalBytes:N0} bytes)\nUsed space: {HardwareInventory.FormatBytes(d.UsedBytes)} ({d.UsedBytes:N0} bytes, {d.UsedPercent:0.#}%)\nFree space: {HardwareInventory.FormatBytes(d.FreeBytes)} ({d.FreeBytes:N0} bytes)\nFile system: {d.DriveFormat}",
            FilePath: d.DriveName)).ToList();

        var low = drives.Where(d => d.IsLowOnSpace).ToList();
        long total = drives.Sum(d => d.TotalBytes), free = drives.Sum(d => d.FreeBytes), used = drives.Sum(d => d.UsedBytes);
        var headline = drives.Count == 1
            ? $"{drives[0].DriveName} {HardwareInventory.FormatBytes(free)} free of {HardwareInventory.FormatBytes(total)}"
            : $"{HardwareInventory.FormatBytes(free)} free across {drives.Count} drives";
        var meta = string.Join(" · ", new[]
        {
            low.Count > 0 ? "Nearly full: " + string.Join(", ", low.Select(d => d.Letter)) : null,
            drives.Count == 1 ? $"{drives[0].UsedPercent:0.#}% used" : $"{HardwareInventory.FormatBytes(total)} total capacity",
            drives.Count == 1 ? $"{drives[0].DriveFormat} file system" : null,
        }.Where(x => x is not null));

        return new AreaCard(
            cardId,
            "Drive Capacity",
            low.Count > 0 ? AreaLevel.Warning : AreaLevel.Neutral,
            headline,
            meta,
            driveCols,
            driveRows,
            EmptyText: "No drive capacity information available.")
        {
            TotalBytes = total, FreeBytes = free, UsedBytes = used,
        };
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
            cards.Add(BuildDriveCapacityCard(drives));
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

        // Card 3: Top Large Files (local files occupying space on disk)
        var localFiles = files.Where(f => !f.IsCloudOnly).ToList();
        totalLargeFilesDiskBytes = localFiles.Sum(f => f.ActualDiskBytes);
        string[] fileCols = ["File", "Size", "Type", "Modified", "Folder"];
        var fileRows = localFiles.Select(f => new AreaRow(
            AreaLevel.Neutral,
            [
                f.Name,
                HardwareInventory.FormatBytes(f.ActualDiskBytes),
                f.Category,
                f.LastModifiedUtc.ToString("yyyy-MM-dd"),
                Path.GetDirectoryName(f.FullPath) ?? ""
            ],
            SortKeys: [f.Name, f.ActualDiskBytes.ToString("D19"), f.Category, f.LastModifiedUtc.ToString("s"), f.FullPath],
            Detail: $"{f.FullPath}\nSize on disk: {HardwareInventory.FormatBytes(f.ActualDiskBytes)} ({f.ActualDiskBytes:N0} bytes)\nApparent size: {HardwareInventory.FormatBytes(f.SizeBytes)} ({f.SizeBytes:N0} bytes)\nType: {f.Category}\nModified: {f.LastModifiedUtc:yyyy-MM-dd HH:mm:ss} UTC",
            Actions: [new AreaAction(RemediationKind.DeleteLargeFile, "Delete", f.FullPath, f.Name)],
            FilePath: f.FullPath)).ToList();

        cards.Add(new AreaCard(
            "files",
            "Top Large Files",
            AreaLevel.Neutral,
            localFiles.Count > 0 ? $"{localFiles.Count} files >= {HardwareInventory.FormatBytes(minSizeBytes)} (total {HardwareInventory.FormatBytes(totalLargeFilesDiskBytes)} on disk)" : $"No files >= {HardwareInventory.FormatBytes(minSizeBytes)} found",
            localFiles.Count > 0 ? $"Largest: {localFiles[0].Name} ({HardwareInventory.FormatBytes(localFiles[0].ActualDiskBytes)})" : "",
            fileCols,
            fileRows,
            EmptyText: $"No files larger than {HardwareInventory.FormatBytes(minSizeBytes)} were found."));

        string drivePart = drives.Count > 0
            ? $"{drives[0].DriveName} ({HardwareInventory.FormatBytes(drives[0].UsedBytes)} used of {HardwareInventory.FormatBytes(drives[0].TotalBytes)}, {HardwareInventory.FormatBytes(drives[0].FreeBytes)} free) · "
            : "";

        string summary = localFiles.Count > 0
            ? $"{drivePart}Found {localFiles.Count} large files on {root} totaling {HardwareInventory.FormatBytes(totalLargeFilesDiskBytes)}"
            : $"{drivePart}Scan complete on {root} · No files >= {HardwareInventory.FormatBytes(minSizeBytes)}";

        return new AreaReport(cards, summary, DiagnosticStatus.Ok);
    }
}
