using System.Runtime.InteropServices;

namespace RemotePCDiagnostics.Core.Stress;

/// <summary>A local fixed drive that can be tested.</summary>
public sealed record TestDrive(string Root, string Label, long FreeBytes, long TotalBytes, bool IsSystem)
{
    public string DisplayName => string.IsNullOrWhiteSpace(Label) ? Root.TrimEnd('\\', '/') : $"{Label} ({Root.TrimEnd('\\', '/')})";
}

/// <summary>
/// File-system access for the disk speed test. Implementations must only ever touch files inside the dedicated
/// test folder whose names match <see cref="DiskSpeedTest.TempFilePattern"/>; no other file is opened, read or deleted.
/// </summary>
public interface IDiskTestFileSystem
{
    IReadOnlyList<TestDrive> GetFixedDrives();
    /// <summary>The dedicated folder (used only by this test) that holds the temporary test file on <paramref name="drive"/>.</summary>
    string GetTestFolder(TestDrive drive);
    long GetFreeBytes(string driveRoot);
    void CreateDirectory(string path);
    IEnumerable<string> FindFiles(string directory, string searchPattern);
    bool FileExists(string path);
    void DeleteFile(string path);
    void DeleteDirectoryIfEmpty(string path);
    /// <summary>Opens (creating) the test file for unbuffered, write-through random access.</summary>
    Stream OpenTestFile(string path, long length);
}

/// <summary>Real file system: <see cref="FileOptions.WriteThrough"/> plus Windows FILE_FLAG_NO_BUFFERING with sector-aligned buffers.</summary>
public sealed class PhysicalDiskTestFileSystem(ILogger? log = null) : IDiskTestFileSystem
{
    private const FileOptions NoBuffering = (FileOptions)0x20000000;

    public IReadOnlyList<TestDrive> GetFixedDrives()
    {
        var sys = Path.GetPathRoot(Environment.SystemDirectory) ?? "";
        var list = new List<TestDrive>();
        foreach (var d in DriveInfo.GetDrives())
        {
            try
            {
                if (d.DriveType != DriveType.Fixed || !d.IsReady) continue;
                list.Add(new TestDrive(d.RootDirectory.FullName, d.VolumeLabel, d.AvailableFreeSpace, d.TotalSize,
                    string.Equals(d.RootDirectory.FullName, sys, StringComparison.OrdinalIgnoreCase)));
            }
            catch (Exception ex) { log.Info($"Disk speed: skipping drive {d.Name}: {ex.Message}"); }
        }
        return list.OrderByDescending(d => d.IsSystem).ThenBy(d => d.Root).ToList();
    }

    public const string FolderName = "RemotePCDiagnostics.SpeedTest";

    /// <summary>System drive: under the user's temp folder; other drives: a dedicated folder at the drive root.</summary>
    public string GetTestFolder(TestDrive drive)
    {
        var temp = Path.GetTempPath();
        return string.Equals(Path.GetPathRoot(temp), drive.Root, StringComparison.OrdinalIgnoreCase)
            ? Path.Combine(temp, FolderName)
            : Path.Combine(drive.Root, FolderName);
    }

    public long GetFreeBytes(string driveRoot) => new DriveInfo(driveRoot).AvailableFreeSpace;
    public void CreateDirectory(string path) => Directory.CreateDirectory(path);
    public IEnumerable<string> FindFiles(string directory, string searchPattern) =>
        Directory.Exists(directory) ? Directory.EnumerateFiles(directory, searchPattern, SearchOption.TopDirectoryOnly).ToList() : [];
    public bool FileExists(string path) => File.Exists(path);
    public void DeleteFile(string path) => File.Delete(path);
    public void DeleteDirectoryIfEmpty(string path)
    {
        if (Directory.Exists(path) && !Directory.EnumerateFileSystemEntries(path).Any()) Directory.Delete(path);
    }

    public Stream OpenTestFile(string path, long length)
    {
        FileStream Open(FileOptions o) => new(path, new FileStreamOptions
        {
            Mode = FileMode.Create, Access = FileAccess.ReadWrite, Share = FileShare.None, BufferSize = 0, Options = o, PreallocationSize = length,
        });
        if (OperatingSystem.IsWindows())
        {
            try { return Open(FileOptions.WriteThrough | NoBuffering); }
            catch (Exception ex) { log.Warn($"Disk speed: unbuffered open failed ({ex.Message}); using write-through only"); }
        }
        return Open(FileOptions.WriteThrough);
    }
}

/// <summary>Pinned buffer whose start is aligned to <paramref name="alignment"/> (required for unbuffered I/O).</summary>
public sealed class AlignedBuffer
{
    private readonly byte[] _array;
    private readonly int _offset;
    public int Length { get; }

    public AlignedBuffer(int length, int alignment = 4096)
    {
        Length = length;
        _array = GC.AllocateArray<byte>(length + alignment, pinned: true);
        var addr = (long)Marshal.UnsafeAddrOfPinnedArrayElement(_array, 0);
        _offset = (int)((alignment - addr % alignment) % alignment);
    }

    public Span<byte> Span => _array.AsSpan(_offset, Length);
    public Span<byte> Slice(int length) => _array.AsSpan(_offset, length);
}
