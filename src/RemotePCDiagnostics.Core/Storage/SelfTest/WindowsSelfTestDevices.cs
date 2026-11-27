using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace RemotePCDiagnostics.Core.Storage;

/// <summary>
/// The drives' self-test commands through Windows' storage IOCTLs (in the Agent, which has the administrator rights raw disk access needs):
/// <list type="bullet">
/// <item>bus and model: <c>IOCTL_STORAGE_QUERY_PROPERTY</c> (StorageDeviceProperty);</item>
/// <item>NVMe: Identify Controller and the Device Self-test log through <c>IOCTL_STORAGE_QUERY_PROPERTY</c> (protocol-specific
/// property), the Device Self-test command (admin opcode 14h) through <c>IOCTL_STORAGE_PROTOCOL_COMMAND</c> (Windows 10 1903 or later);</item>
/// <item>ATA: SMART READ DATA, READ LOG (06h) and EXECUTE OFF-LINE IMMEDIATE through <c>IOCTL_ATA_PASS_THROUGH</c>.</item>
/// </list>
/// The drive's serial number is never read.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsSelfTestDevices : ISelfTestDevices
{
    private const uint GenericRead = 0x80000000, GenericWrite = 0x40000000, ShareReadWrite = 3, OpenExisting = 3;
    private const uint IoctlStorageQueryProperty = 0x002D1400;
    private const uint IoctlStorageProtocolCommand = 0x002DD3C0;
    private const uint IoctlAtaPassThrough = 0x0004D02C;
    private const int ErrorFileNotFound = 2;

    private static readonly string[] BusNames =
    [
        "Unknown", "Scsi", "Atapi", "Ata", "1394", "Ssa", "Fibre", "Usb", "Raid", "iScsi", "Sas", "Sata", "Sd", "Mmc", "Virtual",
        "FileBackedVirtual", "Spaces", "Nvme", "Scm", "Ufs",
    ];

    public IReadOnlyList<int> Disks()
    {
        var disks = new List<int>();
        for (var n = 0; n <= AgentDriveSelfTest.MaxDisk; n++)
        {
            using var h = Open(n, out var err);
            if (!h.IsInvalid || err is not ErrorFileNotFound and not 3 /* path not found */) disks.Add(n);
        }
        return disks;
    }

    public SelfTestDriveAnswer Read(int disk)
    {
        using var h = Open(disk, out var err);
        if (h.IsInvalid) return new() { Disk = disk, Error = $"the drive couldn't be opened (error {err})" };
        var (bus, model) = Describe(h);
        var answer = new SelfTestDriveAnswer { Disk = disk, Bus = bus, Model = model };
        if (SelfTestDecoder.BusReason(bus) is not null) return answer;
        if (bus == "Nvme") return ReadNvme(h, answer);
        // SATA and ATA drives, and drives Windows reports as SCSI or unknown, which are often SATA behind a SAT layer.
        return ReadAta(h, answer);
    }

    public string? Start(int disk, SelfTestProtocol protocol, SelfTestKind kind) => Send(disk, protocol, (byte)kind);

    public string? Abort(int disk, SelfTestProtocol protocol) => Send(disk, protocol, protocol == SelfTestProtocol.Nvme ? (byte)0x0F : (byte)0x7F);

    private string? Send(int disk, SelfTestProtocol protocol, byte code)
    {
        using var h = Open(disk, out var err);
        if (h.IsInvalid) return $"the drive couldn't be opened (error {err})";
        return protocol switch
        {
            SelfTestProtocol.Nvme => NvmeSelfTest(h, code),
            // ATA subcommands: 1 short and 2 extended (off-line mode, so the drive keeps serving reads and writes), 127 abort.
            SelfTestProtocol.Ata => AtaCommand(h, 0xD4, code, sectorCount: 0, dataIn: null) ? null : "the drive refused the command",
            _ => "the drive can't be asked for a self-test",
        };
    }

    private static SafeFileHandle Open(int disk, out int error)
    {
        var h = CreateFileW($@"\\.\PhysicalDrive{disk}", GenericRead | GenericWrite, ShareReadWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
        error = h.IsInvalid ? Marshal.GetLastWin32Error() : 0;
        return h;
    }

    private static (string Bus, string Model) Describe(SafeFileHandle h)
    {
        var buf = new byte[1024];
        // STORAGE_PROPERTY_QUERY { PropertyId = StorageDeviceProperty (0), QueryType = PropertyStandardQuery (0) }.
        if (!DeviceIoControl(h, IoctlStorageQueryProperty, buf, 12, buf, buf.Length, out var got, IntPtr.Zero) || got < 32) return ("Unknown", "");
        var busType = BinaryPrimitives.ReadInt32LittleEndian(buf.AsSpan(28));
        var bus = busType >= 0 && busType < BusNames.Length ? BusNames[busType] : "Unknown";
        var vendor = AsciiAt(buf, BinaryPrimitives.ReadInt32LittleEndian(buf.AsSpan(12)), got);
        var product = AsciiAt(buf, BinaryPrimitives.ReadInt32LittleEndian(buf.AsSpan(16)), got);
        var model = vendor.Length > 0 && !vendor.Equals("ATA", StringComparison.OrdinalIgnoreCase) && !product.StartsWith(vendor, StringComparison.OrdinalIgnoreCase)
            ? vendor + " " + product : product;
        return (bus, model.Trim());
    }

    private static string AsciiAt(byte[] buf, int offset, int length)
    {
        if (offset <= 0 || offset >= length) return "";
        var end = Array.IndexOf(buf, (byte)0, offset);
        if (end < 0 || end > length) end = length;
        return Encoding.ASCII.GetString(buf, offset, end - offset).Trim();
    }

    // ---- NVMe ----

    private const int ProtocolTypeNvme = 3, NvmeDataTypeIdentify = 1, NvmeDataTypeLogPage = 2;
    private const int AdapterProtocolSpecificProperty = 49, DeviceProtocolSpecificProperty = 50;
    private const int ProtocolSpecificDataBytes = 40;

    private static SelfTestDriveAnswer ReadNvme(SafeFileHandle h, SelfTestDriveAnswer answer)
    {
        answer = answer with { Protocol = "nvme" };
        if (QueryNvme(h, NvmeDataTypeIdentify, 1, 4096, out var identify) is { } idWhy) return answer with { Error = "identify: " + idWhy };
        var oacs = BinaryPrimitives.ReadUInt16LittleEndian(identify.AsSpan(256));
        var edstt = BinaryPrimitives.ReadUInt16LittleEndian(identify.AsSpan(316));
        answer = answer with { NvmeOacs = oacs, NvmeExtendedMinutes = edstt };
        if ((oacs & SelfTestDecoder.NvmeOacsSelfTestBit) == 0) return answer;
        return QueryNvme(h, NvmeDataTypeLogPage, 0x06, SelfTestDecoder.NvmeLogBytes, out var log) is { } logWhy
            ? answer with { Error = "self-test log: " + logWhy }
            : answer with { SelfTestLog = Convert.ToHexString(log) };
    }

    /// <summary>Identify data or a log page through the protocol-specific storage property; tries the adapter, then the device.</summary>
    private static string? QueryNvme(SafeFileHandle h, int dataType, int requestValue, int length, out byte[] data)
    {
        data = [];
        string? why = null;
        foreach (var property in new[] { AdapterProtocolSpecificProperty, DeviceProtocolSpecificProperty })
        {
            var buf = new byte[8 + ProtocolSpecificDataBytes + length];
            var s = buf.AsSpan();
            BinaryPrimitives.WriteInt32LittleEndian(s[0..], property);
            BinaryPrimitives.WriteInt32LittleEndian(s[4..], 0); // PropertyStandardQuery
            // STORAGE_PROTOCOL_SPECIFIC_DATA
            BinaryPrimitives.WriteInt32LittleEndian(s[8..], ProtocolTypeNvme);
            BinaryPrimitives.WriteInt32LittleEndian(s[12..], dataType);
            BinaryPrimitives.WriteInt32LittleEndian(s[16..], requestValue);
            BinaryPrimitives.WriteInt32LittleEndian(s[20..], 0); // sub value (log page offset, low)
            BinaryPrimitives.WriteInt32LittleEndian(s[24..], ProtocolSpecificDataBytes); // ProtocolDataOffset
            BinaryPrimitives.WriteInt32LittleEndian(s[28..], length); // ProtocolDataLength
            if (!DeviceIoControl(h, IoctlStorageQueryProperty, buf, buf.Length, buf, buf.Length, out _, IntPtr.Zero))
            {
                why = $"error {Marshal.GetLastWin32Error()}";
                continue;
            }
            // STORAGE_PROTOCOL_DATA_DESCRIPTOR { Version, Size, STORAGE_PROTOCOL_SPECIFIC_DATA }: the data follows the specific data.
            var offset = BinaryPrimitives.ReadInt32LittleEndian(s[(8 + 16)..]);
            var got = BinaryPrimitives.ReadInt32LittleEndian(s[(8 + 20)..]);
            if (offset <= 0 || got < length || 8 + offset + length > buf.Length) { why = "the driver returned no data"; continue; }
            data = buf.AsSpan(8 + offset, length).ToArray();
            return null;
        }
        return why;
    }

    /// <summary>The NVMe Device Self-test admin command for every namespace (Self-test Code 1 short, 2 extended, Fh abort).</summary>
    private static string? NvmeSelfTest(SafeFileHandle h, byte code)
    {
        const int header = 80, commandBytes = 64, errorBytes = 64;
        var buf = new byte[header + commandBytes + errorBytes];
        var s = buf.AsSpan();
        BinaryPrimitives.WriteInt32LittleEndian(s[0..], 1); // STORAGE_PROTOCOL_STRUCTURE_VERSION
        BinaryPrimitives.WriteInt32LittleEndian(s[4..], 84); // sizeof(STORAGE_PROTOCOL_COMMAND)
        BinaryPrimitives.WriteInt32LittleEndian(s[8..], ProtocolTypeNvme);
        BinaryPrimitives.WriteUInt32LittleEndian(s[12..], 0x80000000); // STORAGE_PROTOCOL_COMMAND_FLAG_ADAPTER_REQUEST
        BinaryPrimitives.WriteInt32LittleEndian(s[24..], commandBytes); // CommandLength
        BinaryPrimitives.WriteInt32LittleEndian(s[28..], errorBytes); // ErrorInfoLength
        BinaryPrimitives.WriteInt32LittleEndian(s[40..], 30); // TimeOutValue, seconds
        BinaryPrimitives.WriteInt32LittleEndian(s[44..], header + commandBytes); // ErrorInfoOffset
        BinaryPrimitives.WriteInt32LittleEndian(s[56..], 1); // STORAGE_PROTOCOL_SPECIFIC_NVME_ADMIN_COMMAND
        // The NVMe command: CDW0 opcode 14h, NSID FFFFFFFFh (the controller and every namespace), CDW10 the self-test code.
        s[header] = 0x14;
        BinaryPrimitives.WriteUInt32LittleEndian(s[(header + 4)..], 0xFFFFFFFF);
        BinaryPrimitives.WriteUInt32LittleEndian(s[(header + 40)..], code);
        if (!DeviceIoControl(h, IoctlStorageProtocolCommand, buf, buf.Length, buf, buf.Length, out _, IntPtr.Zero))
            return $"Windows didn't pass the command to the drive (error {Marshal.GetLastWin32Error()}; Windows 10 version 1903 or later is needed)";
        var status = BinaryPrimitives.ReadUInt32LittleEndian(s[16..]); // ReturnStatus: 1 = success
        if (status != 1) return $"the drive answered with status {status} (error code {BinaryPrimitives.ReadUInt32LittleEndian(s[20..])})";
        return null;
    }

    // ---- ATA ----

    private static SelfTestDriveAnswer ReadAta(SafeFileHandle h, SelfTestDriveAnswer answer)
    {
        var data = new byte[SelfTestDecoder.AtaPageBytes];
        if (!AtaCommand(h, 0xD0, 0, sectorCount: 1, dataIn: data))
            return answer with { Error = answer.Bus is "Sata" or "Ata" ? "SMART READ DATA failed (SMART may be turned off in the BIOS)" : "the drive doesn't answer ATA commands" };
        answer = answer with { Protocol = "ata", SmartData = Convert.ToHexString(data) };
        var log = new byte[SelfTestDecoder.AtaPageBytes];
        return AtaCommand(h, 0xD5, 0x06, sectorCount: 1, dataIn: log)
            ? answer with { SelfTestLog = Convert.ToHexString(log) }
            : answer with { Error = "the drive didn't return its self-test log" };
    }

    /// <summary>One SMART command (B0h) with <paramref name="feature"/> and <paramref name="lbaLow"/>, reading 512 bytes when given a buffer.</summary>
    private static bool AtaCommand(SafeFileHandle h, byte feature, byte lbaLow, byte sectorCount, byte[]? dataIn)
    {
        // ATA_PASS_THROUGH_EX: the data-buffer offset is pointer sized, so the layout differs between 32- and 64-bit processes.
        var wide = IntPtr.Size == 8;
        int structBytes = wide ? 48 : 40, bufferOffsetAt = wide ? 24 : 20, currentTaskFileAt = wide ? 40 : 32;
        var length = dataIn?.Length ?? 0;
        var buf = new byte[structBytes + length];
        var s = buf.AsSpan();
        BinaryPrimitives.WriteUInt16LittleEndian(s[0..], (ushort)structBytes);
        BinaryPrimitives.WriteUInt16LittleEndian(s[2..], (ushort)(dataIn is null ? 0x01 : 0x03)); // ATA_FLAGS_DRDY_REQUIRED | ATA_FLAGS_DATA_IN
        BinaryPrimitives.WriteUInt32LittleEndian(s[8..], (uint)length);
        BinaryPrimitives.WriteUInt32LittleEndian(s[12..], 30); // seconds
        if (wide) BinaryPrimitives.WriteUInt64LittleEndian(s[bufferOffsetAt..], (ulong)structBytes);
        else BinaryPrimitives.WriteUInt32LittleEndian(s[bufferOffsetAt..], (uint)structBytes);
        var tf = s.Slice(currentTaskFileAt, 8);
        tf[0] = feature;
        tf[1] = sectorCount;
        tf[2] = lbaLow;
        tf[3] = 0x4F; // SMART signature, LBA mid
        tf[4] = 0xC2; // LBA high
        tf[5] = 0xA0;
        tf[6] = 0xB0; // SMART
        if (!DeviceIoControl(h, IoctlAtaPassThrough, buf, buf.Length, buf, buf.Length, out _, IntPtr.Zero)) return false;
        if ((tf[6] & 0x01) != 0) return false; // the status register's ERR bit
        if (dataIn is not null) buf.AsSpan(structBytes, length).CopyTo(dataIn);
        return true;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(SafeFileHandle device, uint code, byte[] inBuffer, int inSize, byte[] outBuffer, int outSize, out int returned, IntPtr overlapped);
}
