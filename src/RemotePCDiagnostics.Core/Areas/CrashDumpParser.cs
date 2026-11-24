using System.Buffers.Binary;
using System.Globalization;
using System.Text;

namespace RemotePCDiagnostics.Core.Areas;

public enum CrashDumpKind
{
    Kernel64,
    Kernel32,
    UserMinidump,
}

/// <summary>Structured summary extracted directly from a Windows <c>.dmp</c> file in pure C# (no <c>kd.exe</c> or symbols required).</summary>
public sealed record CrashDumpSummary(
    CrashDumpKind Kind,
    string Architecture,
    uint? OsBuild = null,
    int? ProcessorCount = null,
    DateTimeOffset? CrashTimeUtc = null,
    TimeSpan? Uptime = null,
    string? DumpType = null,
    uint? BugCheckCode = null,
    ulong[]? BugCheckParameters = null,
    uint? ExceptionCode = null,
    ulong? ExceptionAddress = null,
    string? FaultingModule = null,
    string? FaultingModuleVersion = null,
    string? ProcessModule = null)
{
    public string FormatText()
    {
        var sb = new StringBuilder();
        var kindLabel = Kind switch
        {
            CrashDumpKind.Kernel64 => "Kernel crash dump (64-bit)",
            CrashDumpKind.Kernel32 => "Kernel crash dump (32-bit)",
            CrashDumpKind.UserMinidump => "User-mode minidump (MDMP)",
            _ => "Crash dump",
        };
        sb.AppendLine($"Dump format: {kindLabel}" + (DumpType is not null ? $" ({DumpType})" : ""));

        var sysParts = new List<string>();
        if (!string.IsNullOrEmpty(Architecture)) sysParts.Add(Architecture);
        if (OsBuild is > 0) sysParts.Add($"OS build {OsBuild.Value}");
        if (ProcessorCount is > 0) sysParts.Add($"{ProcessorCount.Value} logical processors");
        if (sysParts.Count > 0) sb.AppendLine("System: " + string.Join(" · ", sysParts));

        if (CrashTimeUtc is { } t)
            sb.AppendLine($"Crash time: {t.ToLocalTime():g} ({t:u})");
        if (Uptime is { } up && up > TimeSpan.Zero)
            sb.AppendLine($"System uptime before crash: {FormatUptime(up)}");

        if (BugCheckCode is { } bc)
        {
            sb.AppendLine($"BugCheck stop code: {BsodHistoryModule.FormatStopCode(bc)}");
            if (BugCheckParameters is { Length: 4 } p)
                sb.AppendLine($"BugCheck parameters: 0x{p[0]:x16}, 0x{p[1]:x16}, 0x{p[2]:x16}, 0x{p[3]:x16}");
        }

        if (ExceptionCode is { } ex)
        {
            sb.AppendLine($"Exception code: {CrashDumpParser.FormatExceptionCode(ex)}");
            if (ExceptionAddress is { } addr and > 0)
                sb.AppendLine($"Faulting address: 0x{addr:x16}");
        }

        if (!string.IsNullOrEmpty(FaultingModule))
        {
            var ver = string.IsNullOrEmpty(FaultingModuleVersion) ? "" : $" (v{FaultingModuleVersion})";
            sb.AppendLine($"Faulting module: {FaultingModule}{ver}");
        }

        if (!string.IsNullOrEmpty(ProcessModule) && !string.Equals(ProcessModule, FaultingModule, StringComparison.OrdinalIgnoreCase))
            sb.AppendLine($"Process image: {ProcessModule}");

        return sb.ToString().TrimEnd();
    }

    public string ShortSummary()
    {
        if (BugCheckCode is { } bc)
            return $"Stop code {BsodHistoryModule.FormatStopCode(bc)}";
        if (ExceptionCode is { } ex)
        {
            var mod = string.IsNullOrEmpty(FaultingModule) ? "" : $" in {FaultingModule}";
            return $"{CrashDumpParser.FormatExceptionCode(ex)}{mod}";
        }
        return Kind == CrashDumpKind.UserMinidump ? "User-mode minidump" : "Kernel crash dump";
    }

    private static string FormatUptime(TimeSpan up)
    {
        if (up.TotalDays >= 1) return $"{(int)up.TotalDays}d {up.Hours}h {up.Minutes}m";
        if (up.TotalHours >= 1) return $"{(int)up.TotalHours}h {up.Minutes}m";
        return $"{up.Minutes}m {up.Seconds}s";
    }
}

/// <summary>
/// Pure-C# binary reader for Windows kernel dumps (<c>PAGEDU64</c>, <c>PAGEDUMP</c>) and user-mode minidumps (<c>MDMP</c>).
/// Reads only headers and directory streams so even multi-gigabyte <c>MEMORY.DMP</c> files parse in milliseconds.
/// </summary>
public static class CrashDumpParser
{
    private const uint SigPage = 0x45474150; // "PAGE"
    private const uint SigDu64 = 0x34365544; // "DU64"
    private const uint SigDump = 0x504D5544; // "DUMP"
    private const uint SigMdmp = 0x504D444D; // "MDMP"

    private const uint StreamModuleList = 4;
    private const uint StreamException = 6;
    private const uint StreamSystemInfo = 7;

    /// <summary>Parses a local <c>.dmp</c> file, returning null when unreadable or unrecognized.</summary>
    public static CrashDumpSummary? TryReadFile(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return TryRead(fs);
        }
        catch { return null; }
    }

    /// <summary>Parses a Windows <c>.dmp</c> stream from position 0, returning null when unrecognized or truncated.</summary>
    public static CrashDumpSummary? TryRead(Stream stream)
    {
        if (stream is null || !stream.CanRead || !stream.CanSeek) return null;
        if (stream.Length < 32) return null;

        Span<byte> magic = stackalloc byte[8];
        stream.Position = 0;
        if (ReadExact(stream, magic) < 8) return null;

        var sig = BinaryPrimitives.ReadUInt32LittleEndian(magic[..4]);
        var sig2 = BinaryPrimitives.ReadUInt32LittleEndian(magic[4..8]);

        if (sig == SigPage && sig2 == SigDu64)
            return ReadKernel64(stream);
        if (sig == SigPage && sig2 == SigDump)
            return ReadKernel32(stream);
        if (sig == SigMdmp)
            return ReadMinidump(stream);
        return null;
    }

    private static CrashDumpSummary? ReadKernel64(Stream stream)
    {
        // DUMP_HEADER64: fixed fields up to 0x1038 (SystemUpTime).
        var readLen = (int)Math.Min(stream.Length, 0x1040);
        if (readLen < 0x60) return null;

        var buf = new byte[readLen];
        stream.Position = 0;
        if (ReadExact(stream, buf) < 0x60) return null;
        ReadOnlySpan<byte> s = buf;

        var osBuild = BinaryPrimitives.ReadUInt32LittleEndian(s[0x0C..]);
        var machine = BinaryPrimitives.ReadUInt32LittleEndian(s[0x30..]);
        var procs = BinaryPrimitives.ReadUInt32LittleEndian(s[0x34..]);
        var bugCheck = BinaryPrimitives.ReadUInt32LittleEndian(s[0x38..]);
        var p1 = BinaryPrimitives.ReadUInt64LittleEndian(s[0x40..]);
        var p2 = BinaryPrimitives.ReadUInt64LittleEndian(s[0x48..]);
        var p3 = BinaryPrimitives.ReadUInt64LittleEndian(s[0x50..]);
        var p4 = BinaryPrimitives.ReadUInt64LittleEndian(s[0x58..]);

        string? dumpType = readLen >= 0xF9C ? FormatKernelDumpType(BinaryPrimitives.ReadUInt32LittleEndian(s[0xF98..])) : null;
        DateTimeOffset? crashTime = readLen >= 0xFB0 ? TryFileTime(BinaryPrimitives.ReadInt64LittleEndian(s[0xFA8..])) : null;
        TimeSpan? uptime = readLen >= 0x1038 ? TryUptime(BinaryPrimitives.ReadInt64LittleEndian(s[0x1030..])) : null;

        return new CrashDumpSummary(
            Kind: CrashDumpKind.Kernel64,
            Architecture: FormatMachineImageType(machine),
            OsBuild: osBuild > 0 ? osBuild : null,
            ProcessorCount: procs is > 0 and <= 1024 ? (int)procs : null,
            CrashTimeUtc: crashTime,
            Uptime: uptime,
            DumpType: dumpType,
            BugCheckCode: bugCheck != 0 ? bugCheck : null,
            BugCheckParameters: bugCheck != 0 ? [p1, p2, p3, p4] : null);
    }

    private static CrashDumpSummary? ReadKernel32(Stream stream)
    {
        var readLen = (int)Math.Min(stream.Length, 0x1000);
        if (readLen < 0x3C) return null;

        var buf = new byte[readLen];
        stream.Position = 0;
        if (ReadExact(stream, buf) < 0x3C) return null;
        ReadOnlySpan<byte> s = buf;

        var osBuild = BinaryPrimitives.ReadUInt32LittleEndian(s[0x0C..]);
        var machine = BinaryPrimitives.ReadUInt32LittleEndian(s[0x20..]);
        var procs = BinaryPrimitives.ReadUInt32LittleEndian(s[0x24..]);
        var bugCheck = BinaryPrimitives.ReadUInt32LittleEndian(s[0x28..]);
        ulong p1 = BinaryPrimitives.ReadUInt32LittleEndian(s[0x2C..]);
        ulong p2 = BinaryPrimitives.ReadUInt32LittleEndian(s[0x30..]);
        ulong p3 = BinaryPrimitives.ReadUInt32LittleEndian(s[0x34..]);
        ulong p4 = BinaryPrimitives.ReadUInt32LittleEndian(s[0x38..]);

        string? dumpType = readLen >= 0xF8C ? FormatKernelDumpType(BinaryPrimitives.ReadUInt32LittleEndian(s[0xF88..])) : null;
        DateTimeOffset? crashTime = readLen >= 0xFC8 ? TryFileTime(BinaryPrimitives.ReadInt64LittleEndian(s[0xFC0..])) : null;

        return new CrashDumpSummary(
            Kind: CrashDumpKind.Kernel32,
            Architecture: FormatMachineImageType(machine),
            OsBuild: osBuild > 0 ? osBuild : null,
            ProcessorCount: procs is > 0 and <= 1024 ? (int)procs : null,
            CrashTimeUtc: crashTime,
            DumpType: dumpType,
            BugCheckCode: bugCheck != 0 ? bugCheck : null,
            BugCheckParameters: bugCheck != 0 ? [p1, p2, p3, p4] : null);
    }

    private static CrashDumpSummary? ReadMinidump(Stream stream)
    {
        // MINIDUMP_HEADER is 32 bytes.
        Span<byte> hdr = stackalloc byte[32];
        stream.Position = 0;
        if (ReadExact(stream, hdr) < 32) return null;

        var numStreams = BinaryPrimitives.ReadUInt32LittleEndian(hdr[8..]);
        var dirRva = BinaryPrimitives.ReadUInt32LittleEndian(hdr[12..]);
        var timestamp = BinaryPrimitives.ReadUInt32LittleEndian(hdr[20..]);

        DateTimeOffset? crashTime = timestamp > 946684800 // after 2000-01-01
            ? DateTimeOffset.FromUnixTimeSeconds(timestamp)
            : null;

        var arch = "";
        uint? osBuild = null;
        int? procs = null;
        uint? exceptionCode = null;
        ulong? exceptionAddress = null;
        uint moduleStreamRva = 0, moduleStreamSize = 0;

        if (numStreams > 0 && numStreams <= 256 && dirRva + (long)numStreams * 12 <= stream.Length)
        {
            var dirBuf = new byte[numStreams * 12];
            stream.Position = dirRva;
            if (ReadExact(stream, dirBuf) == dirBuf.Length)
            {
                Span<byte> sys = stackalloc byte[20];
                Span<byte> ex = stackalloc byte[32];
                for (var i = 0; i < numStreams; i++)
                {
                    var entry = dirBuf.AsSpan(i * 12, 12);
                    var streamType = BinaryPrimitives.ReadUInt32LittleEndian(entry[0..]);
                    var dataSize = BinaryPrimitives.ReadUInt32LittleEndian(entry[4..]);
                    var rva = BinaryPrimitives.ReadUInt32LittleEndian(entry[8..]);
                    if (rva == 0 || dataSize == 0 || rva + (long)dataSize > stream.Length) continue;

                    if (streamType == StreamSystemInfo && dataSize >= 20)
                    {
                        stream.Position = rva;
                        if (ReadExact(stream, sys) == 20)
                        {
                            arch = FormatProcessorArchitecture(BinaryPrimitives.ReadUInt16LittleEndian(sys[0..]));
                            procs = sys[6] > 0 ? sys[6] : null;
                            var build = BinaryPrimitives.ReadUInt32LittleEndian(sys[16..]);
                            if (build > 0) osBuild = build;
                        }
                    }
                    else if (streamType == StreamException && dataSize >= 32)
                    {
                        stream.Position = rva;
                        if (ReadExact(stream, ex) == 32)
                        {
                            var code = BinaryPrimitives.ReadUInt32LittleEndian(ex[8..]);
                            var addr = BinaryPrimitives.ReadUInt64LittleEndian(ex[24..]);
                            if (code != 0) exceptionCode = code;
                            if (addr != 0) exceptionAddress = addr;
                        }
                    }
                    else if (streamType == StreamModuleList && dataSize >= 4)
                    {
                        moduleStreamRva = rva;
                        moduleStreamSize = dataSize;
                    }
                }
            }
        }

        string? faultingModule = null, faultingVersion = null, processModule = null;
        if (moduleStreamRva > 0 && moduleStreamSize >= 4)
        {
            ReadMinidumpModules(stream, moduleStreamRva, moduleStreamSize, exceptionAddress,
                out processModule, out faultingModule, out faultingVersion);
        }

        return new CrashDumpSummary(
            Kind: CrashDumpKind.UserMinidump,
            Architecture: arch,
            OsBuild: osBuild,
            ProcessorCount: procs,
            CrashTimeUtc: crashTime,
            ExceptionCode: exceptionCode,
            ExceptionAddress: exceptionAddress,
            FaultingModule: faultingModule,
            FaultingModuleVersion: faultingVersion,
            ProcessModule: processModule);
    }

    private static void ReadMinidumpModules(
        Stream stream, uint rva, uint size, ulong? exceptionAddress,
        out string? processModule, out string? faultingModule, out string? faultingVersion)
    {
        processModule = null;
        faultingModule = null;
        faultingVersion = null;

        Span<byte> countBuf = stackalloc byte[4];
        stream.Position = rva;
        if (ReadExact(stream, countBuf) < 4) return;
        var count = BinaryPrimitives.ReadUInt32LittleEndian(countBuf);
        const int moduleSize = 108; // sizeof(MINIDUMP_MODULE) with Pack=4
        var maxCount = (uint)Math.Min(count, Math.Min(2048u, (size - 4) / moduleSize));
        if (maxCount == 0) return;

        var buf = new byte[maxCount * moduleSize];
        if (ReadExact(stream, buf) < buf.Length) return;

        for (var i = 0; i < maxCount; i++)
        {
            var m = buf.AsSpan(i * moduleSize, moduleSize);
            var baseAddr = BinaryPrimitives.ReadUInt64LittleEndian(m[0..]);
            var imageSize = BinaryPrimitives.ReadUInt32LittleEndian(m[8..]);
            var nameRva = BinaryPrimitives.ReadUInt32LittleEndian(m[20..]);

            if (i == 0)
            {
                var full = ReadMinidumpString(stream, nameRva);
                if (!string.IsNullOrWhiteSpace(full))
                    processModule = Path.GetFileName(full.Replace('\\', '/'));
            }

            if (faultingModule is null && exceptionAddress is { } addr && addr >= baseAddr && addr < baseAddr + imageSize)
            {
                var full = ReadMinidumpString(stream, nameRva);
                if (!string.IsNullOrWhiteSpace(full))
                    faultingModule = Path.GetFileName(full.Replace('\\', '/'));
                // VS_FIXEDFILEINFO starts at offset 24; dwFileVersionMS at +8 (32), dwFileVersionLS at +12 (36)
                var sig = BinaryPrimitives.ReadUInt32LittleEndian(m[24..]);
                if (sig == 0xFEEF04BD)
                {
                    var ms = BinaryPrimitives.ReadUInt32LittleEndian(m[32..]);
                    var ls = BinaryPrimitives.ReadUInt32LittleEndian(m[36..]);
                    if (ms != 0 || ls != 0)
                        faultingVersion = $"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}";
                }
            }

            if (processModule is not null && (exceptionAddress is null || faultingModule is not null))
                break;
        }
    }

    private static string? ReadMinidumpString(Stream stream, uint rva)
    {
        if (rva == 0 || rva + 4L > stream.Length) return null;
        Span<byte> lenBuf = stackalloc byte[4];
        stream.Position = rva;
        if (ReadExact(stream, lenBuf) < 4) return null;
        var byteLen = BinaryPrimitives.ReadUInt32LittleEndian(lenBuf);
        if (byteLen == 0 || byteLen > 4096 || rva + 4L + byteLen > stream.Length) return null;
        var bytes = new byte[byteLen];
        if (ReadExact(stream, bytes) < bytes.Length) return null;
        return Encoding.Unicode.GetString(bytes).TrimEnd('\0');
    }

    private static int ReadExact(Stream stream, Span<byte> buffer)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var n = stream.Read(buffer[total..]);
            if (n <= 0) break;
            total += n;
        }
        return total;
    }

    private static DateTimeOffset? TryFileTime(long fileTime)
    {
        // Valid FILETIME between 2000-01-01 and 2100-01-01.
        if (fileTime < 125_911_584_000_000_000L || fileTime > 157_469_184_000_000_000L) return null;
        try { return DateTimeOffset.FromFileTime(fileTime).ToUniversalTime(); }
        catch { return null; }
    }

    private static TimeSpan? TryUptime(long ticks)
    {
        if (ticks <= 0 || ticks > TimeSpan.FromDays(3650).Ticks) return null;
        return TimeSpan.FromTicks(ticks);
    }

    public static string FormatExceptionCode(uint code) => $"0x{code:x8}" + (code switch
    {
        0xC0000005 => " · Access violation",
        0xC00000FD => " · Stack overflow",
        0xC0000094 => " · Integer division by zero",
        0xC000001D => " · Illegal instruction",
        0xC0000409 => " · Stack buffer overrun / fast fail",
        0xC0000374 => " · Heap corruption",
        0x80000003 => " · Breakpoint",
        0xE0434352 => " · .NET CLR exception",
        0xE06D7363 => " · C++ exception",
        _ => ""
    });

    private static string FormatMachineImageType(uint machine) => machine switch
    {
        0x8664 => "x64",
        0xAA64 => "ARM64",
        0x014C => "x86",
        0x01C4 => "ARM",
        _ => machine == 0 ? "" : $"0x{machine:x4}",
    };

    private static string FormatProcessorArchitecture(ushort arch) => arch switch
    {
        9 => "x64",
        12 => "ARM64",
        0 => "x86",
        5 => "ARM",
        _ => "",
    };

    private static string? FormatKernelDumpType(uint dumpType) => dumpType switch
    {
        1 => "Full memory dump",
        2 => "Kernel summary dump",
        3 => "Header dump",
        4 => "Small memory dump (minidump)",
        5 => "Active memory dump",
        6 => "Automatic memory dump",
        _ => null,
    };
}
