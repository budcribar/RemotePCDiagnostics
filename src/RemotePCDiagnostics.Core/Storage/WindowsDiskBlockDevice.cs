using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;

namespace RemotePCDiagnostics.Core.Storage;

/// <summary>
/// <c>\\.\PhysicalDriveN</c> opened with GENERIC_READ only and FILE_FLAG_NO_BUFFERING, so every read goes to the disk. Needs administrator
/// (it runs in the Agent). Nothing here can write: the handle has no write access and the only I/O call is ReadFile.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed unsafe class WindowsDiskBlockDevice : IDiskBlockDevice
{
    private readonly SafeFileHandle _handle;
    private void* _buffer;
    private int _bufferBytes;

    public long SizeBytes { get; }
    public int SectorBytes { get; }
    public bool? IncursSeekPenalty { get; }
    public IReadOnlyList<DiskPartitionInfo> Partitions { get; }

    private WindowsDiskBlockDevice(SafeFileHandle handle, long size, int sector, bool? seekPenalty, IReadOnlyList<DiskPartitionInfo> partitions)
    {
        _handle = handle;
        SizeBytes = size;
        SectorBytes = sector;
        IncursSeekPenalty = seekPenalty;
        Partitions = partitions;
    }

    /// <summary>Opens disk <paramref name="number"/> for reading; throws with Windows' reason when it can't.</summary>
    public static WindowsDiskBlockDevice Open(int number)
    {
        if (number is < 0 or > DiskReadScanAction.MaxDisk)
            throw new ArgumentOutOfRangeException(nameof(number), number, $"Disk number must be between 0 and {DiskReadScanAction.MaxDisk}.");
        var handle = CreateFileW($@"\\.\PhysicalDrive{number}", GenericRead, FileShareRead | FileShareWrite, IntPtr.Zero, OpenExisting,
            FileFlagNoBuffering, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            throw new IOException(error == 2 ? $"There's no disk {number}." : $"Windows couldn't open disk {number} for reading (error {error}).");
        }
        try
        {
            var size = Ioctl<long>(handle, IoctlDiskGetLengthInfo) ?? throw new IOException($"Windows didn't give the size of disk {number}.");
            var sector = Geometry(handle) is > 0 and <= 65536 and var s ? s : 512;
            return new WindowsDiskBlockDevice(handle, size, sector, SeekPenalty(handle), ReadPartitions(handle, number));
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    public int Read(long offset, int length)
    {
        if (length <= 0 || length % SectorBytes != 0 || offset % SectorBytes != 0) return 87; // ERROR_INVALID_PARAMETER
        if (length > _bufferBytes)
        {
            if (_buffer is not null)
            {
                NativeMemory.AlignedFree(_buffer);
                _buffer = null;
                _bufferBytes = 0;
            }
            _buffer = NativeMemory.AlignedAlloc((nuint)length, (nuint)Math.Max(4096, SectorBytes));
            _bufferBytes = length;
        }
        var overlapped = new NativeOverlapped { OffsetLow = (int)(offset & 0xFFFFFFFF), OffsetHigh = (int)(offset >> 32) };
        if (ReadFile(_handle, _buffer, (uint)length, out var read, &overlapped)) return read == length ? 0 : DiskReadErrors.SectorNotFound;
        var error = Marshal.GetLastPInvokeError();
        return error == 0 ? DiskReadErrors.IoDevice : error;
    }

    public void Dispose()
    {
        _handle.Dispose();
        if (_buffer is not null) { NativeMemory.AlignedFree(_buffer); _buffer = null; _bufferBytes = 0; }
    }

    private static int Geometry(SafeFileHandle h)
    {
        // DISK_GEOMETRY_EX: DISK_GEOMETRY (Cylinders 8, MediaType 4, TracksPerCylinder 4, SectorsPerTrack 4, BytesPerSector 4), DiskSize 8, ...
        var buffer = stackalloc byte[256];
        return DeviceIoControl(h, IoctlDiskGetDriveGeometryEx, null, 0, buffer, 256, out var got, IntPtr.Zero) && got >= 24
            ? *(int*)(buffer + 20) : 0;
    }

    private static bool? SeekPenalty(SafeFileHandle h)
    {
        // STORAGE_PROPERTY_QUERY { PropertyId = StorageDeviceSeekPenaltyProperty (7), QueryType = PropertyStandardQuery (0) }.
        var query = stackalloc int[3];
        query[0] = 7;
        query[1] = 0;
        // DEVICE_SEEK_PENALTY_DESCRIPTOR { Version, Size, IncursSeekPenalty (BOOLEAN) }.
        var answer = stackalloc byte[12];
        return DeviceIoControl(h, IoctlStorageQueryProperty, query, 12, answer, 12, out var got, IntPtr.Zero) && got >= 9
            ? answer[8] != 0 : null;
    }

    private static IReadOnlyList<DiskPartitionInfo> ReadPartitions(SafeFileHandle h, int disk)
    {
        // DRIVE_LAYOUT_INFORMATION_EX: PartitionStyle 4, PartitionCount 4, a 40-byte union, then PARTITION_INFORMATION_EX[] of 144 bytes
        // (StartingOffset at 8, PartitionLength at 16, PartitionNumber at 24).
        const int Header = 48, Entry = 144, Max = 128;
        var size = Header + Entry * Max;
        var buffer = (byte*)NativeMemory.Alloc((nuint)size);
        try
        {
            if (!DeviceIoControl(h, IoctlDiskGetDriveLayoutEx, null, 0, buffer, (uint)size, out var got, IntPtr.Zero) || got < Header) return [];
            var count = Math.Min(*(int*)(buffer + 4), Max);
            var letters = VolumeLetters(disk);
            var list = new List<DiskPartitionInfo>();
            for (var i = 0; i < count && Header + (i + 1) * Entry <= got; i++)
            {
                var p = buffer + Header + i * Entry;
                var offset = *(long*)(p + 8);
                var length = *(long*)(p + 16);
                var number = *(int*)(p + 24);
                if (length <= 0 || number <= 0) continue;
                var letter = letters.FirstOrDefault(l => l.Offset == offset).Letter;
                list.Add(new DiskPartitionInfo(number, offset, length, letter));
            }
            return list;
        }
        finally { NativeMemory.Free(buffer); }
    }

    /// <summary>Each lettered volume that starts on disk <paramref name="disk"/>, with where it starts.</summary>
    private static List<(long Offset, string Letter)> VolumeLetters(int disk)
    {
        var found = new List<(long, string)>();
        // VOLUME_DISK_EXTENTS: NumberOfDiskExtents 4 (+4), DISK_EXTENT[] { DiskNumber 4 (+4), StartingOffset 8, ExtentLength 8 }.
        const int Size = 8 + 24 * 8;
        var buffer = stackalloc byte[Size];
        foreach (var drive in DriveInfo.GetDrives())
        {
            if (drive.DriveType is not (DriveType.Fixed or DriveType.Removable)) continue;
            var letter = drive.Name[..2];
            using var v = CreateFileW($@"\\.\{letter}", 0, FileShareRead | FileShareWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
            if (v.IsInvalid) continue;
            if (!DeviceIoControl(v, IoctlVolumeGetVolumeDiskExtents, null, 0, buffer, Size, out var got, IntPtr.Zero) || got < 32) continue;
            var n = Math.Min(*(int*)buffer, 8);
            for (var i = 0; i < n && 8 + (i + 1) * 24 <= got; i++)
            {
                var e = buffer + 8 + i * 24;
                if (*(int*)e == disk) found.Add((*(long*)(e + 8), letter));
            }
        }
        return found;
    }

    private static T? Ioctl<T>(SafeFileHandle h, uint code) where T : unmanaged
    {
        T value;
        return DeviceIoControl(h, code, null, 0, &value, (uint)sizeof(T), out var got, IntPtr.Zero) && got >= sizeof(T) ? value : null;
    }

    private const uint GenericRead = 0x80000000, FileShareRead = 1, FileShareWrite = 2, OpenExisting = 3, FileFlagNoBuffering = 0x20000000;
    private const uint IoctlDiskGetLengthInfo = 0x0007405C, IoctlDiskGetDriveGeometryEx = 0x000700A0, IoctlDiskGetDriveLayoutEx = 0x00070050,
        IoctlStorageQueryProperty = 0x002D1400, IoctlVolumeGetVolumeDiskExtents = 0x00560000;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadFile(SafeFileHandle file, void* buffer, uint toRead, out int read, NativeOverlapped* overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(SafeFileHandle device, uint code, void* inBuffer, uint inSize, void* outBuffer, uint outSize,
        out int returned, IntPtr overlapped);
}

/// <summary>
/// On the PC: slow down while on battery below 30 %, or while the drive is over its temperature warning (Windows' reliability counter
/// <c>TemperatureMax</c>, else <see cref="DriveHealth.HotC"/>). The Agent reads the counter itself (it runs as administrator).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsDiskScanConditions(int disk, IWmiSource? wmi = null) : IDiskScanConditions
{
    public const int LowBatteryPercent = 30;
    private readonly IWmiSource _wmi = wmi ?? new SystemWmiSource(timeout: TimeSpan.FromSeconds(10));
    private string? _objectId;
    private DateTime _nextTemperature;
    private string? _hot;

    public string? ThrottleReason()
    {
        if (GetSystemPowerStatus(out var power) && power.ACLineStatus == 0 && power.BatteryLifePercent is < LowBatteryPercent)
            return $"On battery at {power.BatteryLifePercent} %: reading slowly until the PC is plugged in.";
        // The counter is a WMI query: every 30 seconds is plenty for a temperature.
        if (DateTime.UtcNow >= _nextTemperature)
        {
            _nextTemperature = DateTime.UtcNow.AddSeconds(30);
            _hot = HotReason();
        }
        return _hot;
    }

    private string? HotReason()
    {
        _objectId ??= _wmi.QueryAsync(DriveReader.StorageNamespace, DriveReader.DiskSql).GetAwaiter().GetResult().Rows?
            .FirstOrDefault(r => r.Str("DeviceId") == disk.ToString(System.Globalization.CultureInfo.InvariantCulture))?.Str("ObjectId");
        if (string.IsNullOrEmpty(_objectId)) return null;
        var counter = _wmi.QueryAsync(DriveReader.StorageNamespace, DriveReader.CounterSql(_objectId)).GetAwaiter().GetResult().Rows?.FirstOrDefault();
        if (counter?.Long("Temperature") is not { } t || t is <= 0 or >= 150) return null;
        var warning = counter!.Long("TemperatureMax") is > 30 and < 150 and var max ? max : DriveHealth.HotC;
        return t >= warning ? $"The drive is at {t} °C (warning {warning} °C): reading slowly until it cools down." : null;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SystemPowerStatus
    {
        public byte ACLineStatus, BatteryFlag, BatteryLifePercent, SystemStatusFlag;
        public int BatteryLifeTime, BatteryFullLifeTime;
    }

    [DllImport("kernel32.dll")]
    private static extern bool GetSystemPowerStatus(out SystemPowerStatus status);
}
