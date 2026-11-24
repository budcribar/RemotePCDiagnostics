using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Tests;

public class CrashDumpParserTests
{
    [Fact]
    public void ParsesKernel64DumpHeader()
    {
        var buf = new byte[0x1040];
        Encoding.ASCII.GetBytes("PAGEDU64").CopyTo(buf, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(0x08), 15);        // MajorVersion
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(0x0C), 26100);     // MinorVersion (OS build)
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(0x30), 0x8664);    // x64
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(0x34), 16);        // NumberProcessors
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(0x38), 0x0000009F);// DRIVER_POWER_STATE_FAILURE
        BinaryPrimitives.WriteUInt64LittleEndian(buf.AsSpan(0x40), 0x3);
        BinaryPrimitives.WriteUInt64LittleEndian(buf.AsSpan(0x48), 0xFFFF800123456789);
        BinaryPrimitives.WriteUInt64LittleEndian(buf.AsSpan(0x50), 0xFFFF8001AABBCCDD);
        BinaryPrimitives.WriteUInt64LittleEndian(buf.AsSpan(0x58), 0xFFFF800100001111);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(0xF98), 4);        // Small memory dump (minidump)
        var expectedTime = new DateTimeOffset(2026, 11, 24, 15, 30, 0, TimeSpan.Zero);
        BinaryPrimitives.WriteInt64LittleEndian(buf.AsSpan(0xFA8), expectedTime.ToFileTime());
        var expectedUptime = TimeSpan.FromHours(5) + TimeSpan.FromMinutes(12);
        BinaryPrimitives.WriteInt64LittleEndian(buf.AsSpan(0x1030), expectedUptime.Ticks);

        using var ms = new MemoryStream(buf);
        var summary = CrashDumpParser.TryRead(ms);

        Assert.NotNull(summary);
        Assert.Equal(CrashDumpKind.Kernel64, summary.Kind);
        Assert.Equal("x64", summary.Architecture);
        Assert.Equal(26100u, summary.OsBuild);
        Assert.Equal(16, summary.ProcessorCount);
        Assert.Equal(expectedTime, summary.CrashTimeUtc);
        Assert.Equal(expectedUptime, summary.Uptime);
        Assert.Equal("Small memory dump (minidump)", summary.DumpType);
        Assert.Equal(0x9Fu, summary.BugCheckCode);
        Assert.Equal([0x3UL, 0xFFFF800123456789UL, 0xFFFF8001AABBCCDDUL, 0xFFFF800100001111UL], summary.BugCheckParameters!);

        var text = summary.FormatText();
        Assert.Contains("0x0000009f · Driver power state failure", text);
        Assert.Contains("OS build 26100", text);
        Assert.Contains("5h 12m", text);
    }

    [Fact]
    public void ParsesKernel32DumpHeader()
    {
        var buf = new byte[0x1000];
        Encoding.ASCII.GetBytes("PAGEDUMP").CopyTo(buf, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(0x0C), 19045);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(0x20), 0x014C);    // x86
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(0x24), 4);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(0x28), 0xD1);      // DRIVER_IRQL_NOT_LESS_OR_EQUAL
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(0x2C), 0x10);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(0x30), 0x02);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(0x34), 0x00);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(0x38), 0x80501234);

        using var ms = new MemoryStream(buf);
        var summary = CrashDumpParser.TryRead(ms);

        Assert.NotNull(summary);
        Assert.Equal(CrashDumpKind.Kernel32, summary.Kind);
        Assert.Equal("x86", summary.Architecture);
        Assert.Equal(19045u, summary.OsBuild);
        Assert.Equal(4, summary.ProcessorCount);
        Assert.Equal(0xD1u, summary.BugCheckCode);
        Assert.Equal([0x10UL, 0x02UL, 0x00UL, 0x80501234UL], summary.BugCheckParameters!);
    }

    [Fact]
    public void ParsesUserModeMinidumpAndResolvesFaultingModule()
    {
        // Build a valid minimal MDMP stream with SystemInfo, Exception, and ModuleList streams.
        var ms = new MemoryStream();
        var buf = new byte[2048];

        // MINIDUMP_HEADER (0..32)
        Encoding.ASCII.GetBytes("MDMP").CopyTo(buf, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(8), 3);     // NumberOfStreams
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(12), 32);   // StreamDirectoryRva
        var crashTime = new DateTimeOffset(2026, 11, 24, 18, 0, 0, TimeSpan.Zero);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(20), (uint)crashTime.ToUnixTimeSeconds());

        // Directory at 32 (3 * 12 = 36 bytes -> ends at 68)
        // Entry 0: SystemInfoStream (7) at 100, size 24
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(32), 7);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(36), 24);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(40), 100);
        // Entry 1: ExceptionStream (6) at 140, size 40
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(44), 6);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(48), 40);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(52), 140);
        // Entry 2: ModuleListStream (4) at 200, size 4 + 2*108 = 220
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(56), 4);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(60), 220);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(64), 200);

        // SystemInfo at 100
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(100), 9);       // x64
        buf[106] = 8;                                                       // NumberOfProcessors
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(116), 26100);   // BuildNumber

        // ExceptionStream at 140
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(148), 0xC0000005);          // Access violation
        BinaryPrimitives.WriteUInt64LittleEndian(buf.AsSpan(164), 0x00007FF812345678);  // ExceptionAddress inside module 1

        // ModuleListStream at 200 (2 modules)
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(200), 2);

        // Module 0 (process exe) at 204
        BinaryPrimitives.WriteUInt64LittleEndian(buf.AsSpan(204 + 0), 0x00007FF700000000);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(204 + 8), 0x100000);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(204 + 20), 500); // name RVA

        // Module 1 (faulting DLL) at 204 + 108 = 312
        BinaryPrimitives.WriteUInt64LittleEndian(buf.AsSpan(312 + 0), 0x00007FF812300000);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(312 + 8), 0x100000);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(312 + 20), 700); // name RVA
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(312 + 24), 0xFEEF04BD); // VS_FIXEDFILEINFO signature
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(312 + 32), (31u << 16) | 0u);     // 31.0
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(312 + 36), (15u << 16) | 5123u);  // 15.5123

        WriteMinidumpString(buf, 500, @"C:\Program Files\MyApp\myapp.exe");
        WriteMinidumpString(buf, 700, @"C:\Windows\System32\DriverStore\nvwgf2umx.dll");

        ms.Write(buf, 0, buf.Length);
        var summary = CrashDumpParser.TryRead(ms);

        Assert.NotNull(summary);
        Assert.Equal(CrashDumpKind.UserMinidump, summary.Kind);
        Assert.Equal("x64", summary.Architecture);
        Assert.Equal(26100u, summary.OsBuild);
        Assert.Equal(8, summary.ProcessorCount);
        Assert.Equal(crashTime, summary.CrashTimeUtc);
        Assert.Equal(0xC0000005u, summary.ExceptionCode);
        Assert.Equal(0x00007FF812345678UL, summary.ExceptionAddress);
        Assert.Equal("myapp.exe", summary.ProcessModule);
        Assert.Equal("nvwgf2umx.dll", summary.FaultingModule);
        Assert.Equal("31.0.15.5123", summary.FaultingModuleVersion);

        var text = summary.FormatText();
        Assert.Contains("0xc0000005 · Access violation", text);
        Assert.Contains("Faulting module: nvwgf2umx.dll (v31.0.15.5123)", text);
        Assert.Contains("Process image: myapp.exe", text);
    }

    [Fact]
    public void UnrecognizedOrTruncatedDataReturnsNull()
    {
        using var empty = new MemoryStream([]);
        Assert.Null(CrashDumpParser.TryRead(empty));

        using var garbage = new MemoryStream(Encoding.ASCII.GetBytes("NOT_A_DUMP_FILE_AT_ALL_0123456789ABCDEF"));
        Assert.Null(CrashDumpParser.TryRead(garbage));
    }

    [Fact]
    public void FindDebugger_DetectsStoreWinDbgAndSdkFallback()
    {
        var storePkg = Path.Combine(@"C:\Program Files\WindowsApps", "Microsoft.WinDbg_1.2402.24001.0_x64__8wekyb3d8bbwe");
        var storeKd = Path.Combine(storePkg, "amd64", "kd.exe");
        var storeCdb = Path.Combine(storePkg, "amd64", "cdb.exe");
        var sdkKd = Path.Combine(@"C:\Program Files (x86)", "Windows Kits", "10", "Debuggers", "x64", "kd.exe");

        // Store WinDbg package folder preferred over SDK
        var foundStore = CrashDumpDebugger.FindDebugger(
            userMode: false,
            architecture: Architecture.X64,
            localAppData: @"C:\Users\me\AppData\Local",
            programFiles: @"C:\Program Files",
            programFilesX86: @"C:\Program Files (x86)",
            fileExists: p => p == storeKd || p == sdkKd,
            enumerateDirectories: (dir, _) => dir.EndsWith("WindowsApps", StringComparison.OrdinalIgnoreCase) && dir.StartsWith(@"C:\Program Files", StringComparison.OrdinalIgnoreCase)
                ? [storePkg] : []);
        Assert.Equal(storeKd, foundStore);

        // User-mode prefers cdb.exe
        var foundCdb = CrashDumpDebugger.FindDebugger(
            userMode: true,
            architecture: Architecture.X64,
            localAppData: @"C:\Users\me\AppData\Local",
            programFiles: @"C:\Program Files",
            programFilesX86: @"C:\Program Files (x86)",
            fileExists: p => p == storeCdb || p == storeKd,
            enumerateDirectories: (dir, _) => dir.EndsWith("WindowsApps", StringComparison.OrdinalIgnoreCase) && dir.StartsWith(@"C:\Program Files", StringComparison.OrdinalIgnoreCase)
                ? [storePkg] : []);
        Assert.Equal(storeCdb, foundCdb);

        // Falls back to Windows SDK when Store WinDbg isn't installed
        var foundSdk = CrashDumpDebugger.FindDebugger(
            userMode: false,
            architecture: Architecture.X64,
            localAppData: @"C:\Users\me\AppData\Local",
            programFiles: @"C:\Program Files",
            programFilesX86: @"C:\Program Files (x86)",
            fileExists: p => p == sdkKd,
            enumerateDirectories: (_, _) => []);
        Assert.Equal(sdkKd, foundSdk);

        // Returns null when neither is installed
        var none = CrashDumpDebugger.FindDebugger(
            userMode: false,
            architecture: Architecture.X64,
            localAppData: @"C:\Users\me\AppData\Local",
            programFiles: @"C:\Program Files",
            programFilesX86: @"C:\Program Files (x86)",
            fileExists: _ => false,
            enumerateDirectories: (_, _) => []);
        Assert.Null(none);
    }

    private static void WriteMinidumpString(byte[] buf, int rva, string value)
    {
        var bytes = Encoding.Unicode.GetBytes(value);
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(rva), (uint)bytes.Length);
        bytes.CopyTo(buf, rva + 4);
    }
}
