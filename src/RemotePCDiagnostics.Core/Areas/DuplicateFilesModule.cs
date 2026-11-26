using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Storage;

namespace RemotePCDiagnostics.Core.Areas;

public interface IRecycleBinDeleter
{
    bool SendToRecycleBin(string path, out string? error);
}

/// <summary>
/// Requests sending files to the Windows Recycle Bin using the Shell32 SHFileOperation API with FOF_ALLOWUNDO.
/// Note that Recycle Bin storage is requested where supported by the volume; unbuffered drives, network shares,
/// or volumes configured to bypass the Recycle Bin may delete files permanently.
/// </summary>
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
/// and allowing deletions that request moving files to the Recycle Bin where supported.
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
    private readonly object _scanGate = new();
    private CancellationTokenSource? _scanCts;

    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.DuplicateFiles;
    public override string DisplayName => "Duplicate files";
    protected override string FailedMessage => "Couldn't scan for duplicate files on this PC.";

    public long MinFileSizeBytes => minFileSizeBytes;

    public IReadOnlyList<string> SearchRoots => searchRoots ?? DefaultRoots();

    public void Cancel()
    {
        lock (_scanGate) _scanCts?.Cancel();
    }

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

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        using var scan = CancellationTokenSource.CreateLinkedTokenSource(ct);
        lock (_scanGate) _scanCts = scan;
        try
        {
            return await Task.Run(() => Scan(SearchRoots, minFileSizeBytes, progress, scan.Token), scan.Token).ConfigureAwait(false);
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
                        ct.ThrowIfCancellationRequested();
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
                string? prefixHash = ComputePrefixHash(filePath, ct);
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
                string? fullHash = ComputeFullHash(filePath, ct);
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

    public sealed record DuplicateDeletionSet(string Keep, IReadOnlyList<string> Delete);

    private static readonly JsonSerializerOptions DeletionJson = new(JsonSerializerDefaults.Web);

    public static string SerializeDeletionSets(IReadOnlyList<DuplicateDeletionSet> sets) =>
        JsonSerializer.Serialize(sets, DeletionJson);

    public static bool TryParseDeletionSets(string? target, out IReadOnlyList<DuplicateDeletionSet> sets)
    {
        sets = [];
        if (string.IsNullOrWhiteSpace(target)) return false;
        try
        {
            var parsed = JsonSerializer.Deserialize<List<DuplicateDeletionSet>>(target, DeletionJson);
            if (parsed is null || parsed.Count == 0) return false;
            var valid = parsed
                .Where(s => !string.IsNullOrWhiteSpace(s.Keep) && s.Delete is { Count: > 0 })
                .Select(s => new DuplicateDeletionSet(s.Keep, s.Delete.Where(p => !string.IsNullOrWhiteSpace(p)).Distinct(StringComparer.OrdinalIgnoreCase).ToList()))
                .Where(s => s.Delete.Count > 0)
                .ToList();
            if (valid.Count == 0) return false;
            sets = valid;
            return true;
        }
        catch (JsonException) { return false; }
    }

    public static AreaReport BuildReport(IReadOnlyList<DuplicateGroup> groups, long minSizeBytes)
    {
        var cards = new List<AreaCard>();
        long totalWastedBytes = groups.Sum(g => g.WastedBytes);
        int totalDuplicateFiles = groups.Sum(g => g.FilePaths.Count - 1);

        string[] cols = ["File Name", "Size", "Copies", "Wasted Space", "Locations"];
        var allDeletionSets = new List<DuplicateDeletionSet>();
        var rows = groups.Select(g =>
        {
            var ordered = g.FilePaths
                .OrderBy(FileLastWriteUtcSafe)
                .ThenBy(p => p.Length)
                .ThenBy(p => p, StringComparer.OrdinalIgnoreCase)
                .ToList();
            string fileName = Path.GetFileName(ordered[0]);
            string filePathsSummary = string.Join("; ", ordered.Select(p => Path.GetDirectoryName(p) ?? p));
            string detail = $"Duplicate set for '{fileName}' ({HardwareInventory.FormatBytes(g.SizeBytes)}):\n" +
                            string.Join("\n", ordered.Select((p, idx) => $"  [{(idx == 0 ? "1 · keep" : (idx + 1).ToString(CultureInfo.InvariantCulture))}] {p} (Last modified: {FileLastWriteSafe(p)})"));

            var deletionSet = new DuplicateDeletionSet(ordered[0], ordered.Skip(1).ToList());
            allDeletionSets.Add(deletionSet);
            int extraCount = ordered.Count - 1;
            string buttonText = extraCount == 1 ? "Delete extra copy" : $"Delete {extraCount} extra copies";
            AreaAction deleteAction = new(
                RemediationKind.DeleteDuplicateFiles,
                buttonText,
                SerializeDeletionSets([deletionSet]),
                $"{fileName} ({HardwareInventory.FormatBytes(g.WastedBytes)})");

            return new AreaRow(
                AreaLevel.Neutral,
                [fileName, HardwareInventory.FormatBytes(g.SizeBytes), ordered.Count.ToString(CultureInfo.InvariantCulture), HardwareInventory.FormatBytes(g.WastedBytes), filePathsSummary],
                SortKeys: [fileName, g.SizeBytes.ToString("D19"), ordered.Count.ToString("D5"), g.WastedBytes.ToString("D19"), filePathsSummary],
                Key: g.HashHex,
                Actions: [deleteAction],
                Detail: detail);
        }).ToList();

        string headline = groups.Count > 0
            ? $"{groups.Count} sets of identical files found ({HardwareInventory.FormatBytes(totalWastedBytes)} reclaimable)"
            : "No duplicate files found";

        IReadOnlyList<AreaAction>? cardActions = groups.Count > 1
            ? [new(RemediationKind.DeleteDuplicateFiles,
                $"Delete all {totalDuplicateFiles} extra copies",
                SerializeDeletionSets(allDeletionSets),
                $"{totalDuplicateFiles} extra copies ({HardwareInventory.FormatBytes(totalWastedBytes)})")]
            : null;

        cards.Add(new AreaCard(
            "duplicates",
            "Duplicate File Sets",
            groups.Count > 0 ? AreaLevel.Neutral : AreaLevel.Ok,
            headline,
            groups.Count > 0 ? "Deletions request moving files to the Recycle Bin where supported." : $"Files >= {HardwareInventory.FormatBytes(minSizeBytes)} checked.",
            cols,
            rows,
            EmptyText: $"No duplicate files larger than {HardwareInventory.FormatBytes(minSizeBytes)} were found.",
            Actions: cardActions));

        string summary = groups.Count > 0
            ? $"Found {groups.Count} duplicate sets ({totalDuplicateFiles} extra copies, {HardwareInventory.FormatBytes(totalWastedBytes)} wasted space)"
            : "No duplicate files found";

        return new AreaReport(cards, summary, DiagnosticStatus.Ok);
    }

    /// <summary>Moves each extra copy in <paramref name="sets"/> to the Recycle Bin after re-verifying SHA-256 against its kept copy.</summary>
    public (bool Success, string Message, long FreedBytes, int RemovedFiles) DeleteDuplicates(IReadOnlyList<DuplicateDeletionSet> sets, CancellationToken ct = default)
    {
        int removed = 0, failed = 0;
        long freedBytes = 0;
        string? firstError = null;
        foreach (var set in sets)
        {
            foreach (var target in set.Delete)
            {
                ct.ThrowIfCancellationRequested();
                long size = 0;
                try { if (File.Exists(target)) size = new FileInfo(target).Length; } catch { }
                if (DeleteToRecycleBin(target, set.Keep, out var err))
                {
                    removed++;
                    freedBytes += size;
                }
                else
                {
                    failed++;
                    firstError ??= err ?? $"Couldn't delete {Path.GetFileName(target)}.";
                }
            }
        }
        if (removed == 0)
            return (false, firstError ?? "No duplicate files were deleted.", 0, 0);
        var noun = removed == 1 ? "duplicate file" : "duplicate files";
        if (failed > 0)
            return (true, $"Moved {removed} {noun} to the Recycle Bin ({HardwareInventory.FormatBytes(freedBytes)} freed); {failed} skipped ({firstError}).", freedBytes, removed);
        return (true, $"Moved {removed} {noun} to the Recycle Bin ({HardwareInventory.FormatBytes(freedBytes)} freed).", freedBytes, removed);
    }

    /// <summary>
    /// Revalidates that the target duplicate and a surviving duplicate still exist, are different files,
    /// have matching sizes, and share identical cryptographic hashes before requesting deletion to the Recycle Bin.
    /// </summary>
    public bool DeleteToRecycleBin(string targetPath, string survivingPath, out string? error)
    {
        if (string.IsNullOrWhiteSpace(targetPath))
        {
            error = "Target file path is required.";
            return false;
        }

        if (string.IsNullOrWhiteSpace(survivingPath))
        {
            error = "Surviving duplicate file path is required for safety validation.";
            return false;
        }

        try
        {
            string fullTarget = Path.GetFullPath(targetPath);
            string fullSurviving = Path.GetFullPath(survivingPath);

            if (string.Equals(fullTarget, fullSurviving, StringComparison.OrdinalIgnoreCase))
            {
                error = "Target file and surviving duplicate cannot be the same file.";
                return false;
            }

            if (!File.Exists(fullTarget))
            {
                error = "File to delete no longer exists.";
                return false;
            }

            if (!File.Exists(fullSurviving))
            {
                error = "Surviving duplicate file no longer exists; aborting deletion to preserve the only remaining copy.";
                return false;
            }

            var targetInfo = new FileInfo(fullTarget);
            var survivingInfo = new FileInfo(fullSurviving);

            if (targetInfo.Length != survivingInfo.Length)
            {
                error = "File sizes no longer match; the target file may have changed since the scan.";
                return false;
            }

            string? targetHash = ComputeFullHash(fullTarget, CancellationToken.None);
            string? survivingHash = ComputeFullHash(fullSurviving, CancellationToken.None);

            if (targetHash is null || survivingHash is null)
            {
                error = "Could not compute cryptographic hashes to verify duplicate contents.";
                return false;
            }

            if (!string.Equals(targetHash, survivingHash, StringComparison.OrdinalIgnoreCase))
            {
                error = "File contents no longer match the surviving copy; the target file may have been modified since the scan.";
                return false;
            }

            return _recycleBin.SendToRecycleBin(fullTarget, out error);
        }
        catch (Exception ex)
        {
            error = $"Validation error before deletion: {ex.Message}";
            return false;
        }
    }

    private static string? ComputePrefixHash(string filePath, CancellationToken ct = default)
    {
        try
        {
            ct.ThrowIfCancellationRequested();
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            byte[] buffer = new byte[PrefixBytesToRead];
            int read = stream.Read(buffer, 0, buffer.Length);
            if (read == 0) return "";
            byte[] hash = SHA256.HashData(buffer.AsSpan(0, read));
            return Convert.ToHexString(hash);
        }
        catch (OperationCanceledException) { throw; }
        catch { return null; }
    }

    private static string? ComputeFullHash(string filePath, CancellationToken ct = default)
    {
        try
        {
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 64 * 1024);
            using var incremental = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            byte[] buffer = new byte[64 * 1024];
            int read;
            while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                ct.ThrowIfCancellationRequested();
                incremental.AppendData(buffer, 0, read);
            }
            return Convert.ToHexString(incremental.GetHashAndReset());
        }
        catch (OperationCanceledException) { throw; }
        catch { return null; }
    }

    private static DateTime FileLastWriteUtcSafe(string path)
    {
        try { return File.GetLastWriteTimeUtc(path); }
        catch { return DateTime.MaxValue; }
    }

    private static string FileLastWriteSafe(string path)
    {
        try { return File.GetLastWriteTime(path).ToString("yyyy-MM-dd HH:mm:ss"); }
        catch { return "unknown"; }
    }
}
