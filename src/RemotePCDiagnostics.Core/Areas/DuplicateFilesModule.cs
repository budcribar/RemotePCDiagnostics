using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using RemotePCDiagnostics.Core.Storage;

namespace RemotePCDiagnostics.Core.Areas;

public interface IRecycleBinDeleter
{
    bool SendToRecycleBin(string path, out string? error);
}

/// <summary>Sends files to the Windows Recycle Bin using the Shell32 SHFileOperation API.</summary>
public sealed class WindowsRecycleBinDeleter : IRecycleBinDeleter
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SHFILEOPSTRUCT
    {
        public IntPtr hwnd;
        public uint wFunc;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pFrom;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? pTo;
        public ushort fFlags;
        [MarshalAs(UnmanagedType.Bool)]
        public bool fAnyOperationsAborted;
        public IntPtr hNameMappings;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? lpszProgressTitle;
    }

    private const uint FO_DELETE = 0x0003;
    private const ushort FOF_ALLOWUNDO = 0x0040;
    private const ushort FOF_NOCONFIRMATION = 0x0010;
    private const ushort FOF_SILENT = 0x0004;

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int SHFileOperation(ref SHFILEOPSTRUCT fileOp);

    public bool SendToRecycleBin(string path, out string? error)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            error = "Recycle Bin deletion is only supported on Windows.";
            return false;
        }

        try
        {
            if (!File.Exists(path))
            {
                error = "File does not exist.";
                return false;
            }

            // pFrom must be double-null terminated
            var op = new SHFILEOPSTRUCT
            {
                wFunc = FO_DELETE,
                pFrom = path + "\0\0",
                fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT,
            };

            int ret = SHFileOperation(ref op);
            if (ret != 0 || op.fAnyOperationsAborted)
            {
                error = $"SHFileOperation failed with code {ret}";
                return false;
            }

            error = null;
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }
}

/// <summary>A set of confirmed duplicate files sharing identical content.</summary>
public sealed record DuplicateGroup(string HashHex, long SizeBytes, IReadOnlyList<string> FilePaths)
{
    public long WastedBytes => SizeBytes * (FilePaths.Count - 1);
}

/// <summary>
/// Scans folders for duplicate files by matching exact file size, confirming with a cryptographic hash,
/// and allowing deletion to the Recycle Bin.
/// </summary>
public sealed class DuplicateFilesModule(
    ILogger? log = null,
    IRecycleBinDeleter? recycleBin = null,
    IReadOnlyList<string>? searchRoots = null,
    long minFileSizeBytes = 1024L * 1024)
    : AreaModuleBase(log), ICancellableScan
{
    public const string ModuleName = ModuleSlugs.DuplicateFiles;
    public const int PrefixBytesToRead = 4096;

    private readonly IRecycleBinDeleter _recycleBin = recycleBin ?? new WindowsRecycleBinDeleter();

    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.DuplicateFiles;
    public override string DisplayName => "Duplicate files";
    protected override string FailedMessage => "Couldn't scan for duplicate files on this PC.";

    public long MinFileSizeBytes => minFileSizeBytes;

    public IReadOnlyList<string> SearchRoots => searchRoots ?? DefaultRoots();

    public static IReadOnlyList<string> DefaultRoots()
    {
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrWhiteSpace(userProfile) || !Directory.Exists(userProfile))
            return [Directory.GetCurrentDirectory()];

        var list = new List<string>();
        foreach (var sub in new[] { "Downloads", "Documents", "Pictures", "Videos", "Music", "Desktop" })
        {
            var p = Path.Combine(userProfile, sub);
            if (Directory.Exists(p)) list.Add(p);
        }
        return list.Count > 0 ? list : [userProfile];
    }

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct) =>
        await Task.Run(() => Scan(SearchRoots, minFileSizeBytes, progress, ct), ct).ConfigureAwait(false);

    public AreaReport Scan(IReadOnlyList<string> roots, long minSizeBytes, IProgress<string>? progress, CancellationToken ct)
    {
        progress.ReportStep(1, 4, "Gathering candidate files…");

        // Phase 1: Group by file length
        var bySize = new Dictionary<long, List<string>>();
        int filesCount = 0;

        foreach (var root in roots)
        {
            ct.ThrowIfCancellationRequested();
            if (!Directory.Exists(root)) continue;

            var pendingDirs = new Stack<string>();
            pendingDirs.Push(root);

            while (pendingDirs.Count > 0)
            {
                ct.ThrowIfCancellationRequested();
                var currentDir = pendingDirs.Pop();

                try
                {
                    var dirInfo = new DirectoryInfo(currentDir);
                    foreach (var file in dirInfo.EnumerateFiles())
                    {
                        ct.ThrowIfCancellationRequested();
                        try
                        {
                            long len = file.Length;
                            if (len < minSizeBytes) continue;

                            if (!bySize.TryGetValue(len, out var list))
                            {
                                list = [];
                                bySize[len] = list;
                            }
                            list.Add(file.FullName);
                            filesCount++;
                        }
                        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
                    }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PathTooLongException) { continue; }

                try
                {
                    foreach (var subDir in Directory.EnumerateDirectories(currentDir))
                    {
                        if (StorageCleanupEngine.IsReparsePoint(subDir)) continue;
                        pendingDirs.Push(subDir);
                    }
                }
                catch { }
            }
        }

        // Keep only size groups with 2 or more files
        var sizeCandidates = bySize.Where(kv => kv.Value.Count >= 2).ToList();

        progress.ReportStep(2, 4, $"Checking headers for {sizeCandidates.Sum(kv => kv.Value.Count)} potential duplicates…");

        // Phase 2: Prefix hash comparison
        var byPrefix = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var (size, fileList) in sizeCandidates)
        {
            ct.ThrowIfCancellationRequested();
            foreach (var filePath in fileList)
            {
                ct.ThrowIfCancellationRequested();
                string? prefixHash = ComputePrefixHash(filePath);
                if (prefixHash is null) continue;

                string key = $"{size}:{prefixHash}";
                if (!byPrefix.TryGetValue(key, out var list))
                {
                    list = [];
                    byPrefix[key] = list;
                }
                list.Add(filePath);
            }
        }

        // Keep only prefix groups with 2 or more files
        var prefixCandidates = byPrefix.Where(kv => kv.Value.Count >= 2).ToList();

        progress.ReportStep(3, 4, $"Calculating confirmation hashes on {prefixCandidates.Sum(kv => kv.Value.Count)} files…");

        // Phase 3: Full SHA-256 confirmation hash
        var confirmedDuplicates = new List<DuplicateGroup>();
        var byFullHash = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

        foreach (var (prefixKey, fileList) in prefixCandidates)
        {
            ct.ThrowIfCancellationRequested();
            long size = long.Parse(prefixKey.Split(':')[0], CultureInfo.InvariantCulture);

            byFullHash.Clear();
            foreach (var filePath in fileList)
            {
                ct.ThrowIfCancellationRequested();
                string? fullHash = ComputeFullHash(filePath);
                if (fullHash is null) continue;

                if (!byFullHash.TryGetValue(fullHash, out var list))
                {
                    list = [];
                    byFullHash[fullHash] = list;
                }
                list.Add(filePath);
            }

            foreach (var (hash, matchingFiles) in byFullHash)
            {
                if (matchingFiles.Count >= 2)
                {
                    confirmedDuplicates.Add(new DuplicateGroup(hash, size, matchingFiles));
                }
            }
        }

        progress.ReportStep(4, 4, "Finalizing duplicate analysis…");
        return BuildReport(confirmedDuplicates.OrderByDescending(g => g.WastedBytes).ToList(), minSizeBytes);
    }

    public static AreaReport BuildReport(IReadOnlyList<DuplicateGroup> groups, long minSizeBytes)
    {
        var cards = new List<AreaCard>();
        long totalWastedBytes = groups.Sum(g => g.WastedBytes);
        int totalDuplicateFiles = groups.Sum(g => g.FilePaths.Count - 1);

        string[] cols = ["File Name", "Size", "Copies", "Wasted Space", "Locations"];
        var rows = groups.Select(g =>
        {
            string fileName = Path.GetFileName(g.FilePaths[0]);
            string filePathsSummary = string.Join("; ", g.FilePaths.Select(p => Path.GetDirectoryName(p) ?? p));
            string detail = $"Duplicate set for '{fileName}' ({HardwareInventory.FormatBytes(g.SizeBytes)}):\n" +
                            string.Join("\n", g.FilePaths.Select((p, idx) => $"  [{idx + 1}] {p} (Last modified: {FileLastWriteSafe(p)})"));

            return new AreaRow(
                AreaLevel.Neutral,
                [fileName, HardwareInventory.FormatBytes(g.SizeBytes), g.FilePaths.Count.ToString(CultureInfo.InvariantCulture), HardwareInventory.FormatBytes(g.WastedBytes), filePathsSummary],
                SortKeys: [fileName, g.SizeBytes.ToString("D19"), g.FilePaths.Count.ToString("D5"), g.WastedBytes.ToString("D19"), filePathsSummary],
                Detail: detail);
        }).ToList();

        string headline = groups.Count > 0
            ? $"{groups.Count} sets of identical files found ({HardwareInventory.FormatBytes(totalWastedBytes)} reclaimable)"
            : "No duplicate files found";

        cards.Add(new AreaCard(
            "duplicates",
            "Duplicate File Sets",
            groups.Count > 0 ? AreaLevel.Neutral : AreaLevel.Ok,
            headline,
            groups.Count > 0 ? $"Deletions move files safely to the Recycle Bin." : $"Files >= {HardwareInventory.FormatBytes(minSizeBytes)} checked.",
            cols,
            rows,
            EmptyText: $"No duplicate files larger than {HardwareInventory.FormatBytes(minSizeBytes)} were found."));

        string summary = groups.Count > 0
            ? $"Found {groups.Count} duplicate sets ({totalDuplicateFiles} extra copies, {HardwareInventory.FormatBytes(totalWastedBytes)} wasted space)"
            : "No duplicate files found";

        return new AreaReport(cards, summary, AreaLevel.Ok);
    }

    public bool DeleteToRecycleBin(string path, out string? error) =>
        _recycleBin.SendToRecycleBin(path, out error);

    private static string? ComputePrefixHash(string filePath)
    {
        try
        {
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            byte[] buffer = new byte[PrefixBytesToRead];
            int read = stream.Read(buffer, 0, buffer.Length);
            if (read == 0) return "";
            byte[] hash = SHA256.HashData(buffer.AsSpan(0, read));
            return Convert.ToHexString(hash);
        }
        catch { return null; }
    }

    private static string? ComputeFullHash(string filePath)
    {
        try
        {
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 64 * 1024);
            byte[] hash = SHA256.HashData(stream);
            return Convert.ToHexString(hash);
        }
        catch { return null; }
    }

    private static string FileLastWriteSafe(string path)
    {
        try { return File.GetLastWriteTime(path).ToString("yyyy-MM-dd HH:mm:ss"); }
        catch { return "unknown"; }
    }
}
