using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Tests;

/// <summary>Crash dump files for a test, as the Agent would list them.</summary>
internal sealed class FixedCrashDumps(IReadOnlyList<MinidumpFile>? minidumps = null, IReadOnlyList<MinidumpFile>? liveKernelReports = null) : ICrashDumpSource
{
    public bool MinidumpsRead { get; private set; }
    public Task<IReadOnlyList<MinidumpFile>> ReadMinidumpsAsync(CancellationToken ct) { MinidumpsRead = true; return Task.FromResult(minidumps ?? []); }
    public Task<IReadOnlyList<MinidumpFile>> ReadLiveKernelReportsAsync(CancellationToken ct) => Task.FromResult(liveKernelReports ?? []);
}

/// <summary>Drivers for a test (null: they couldn't be read).</summary>
internal sealed class FixedDrivers(IReadOnlyList<DriverEntry>? drivers) : IDeviceDriverSource
{
    public int Reads { get; private set; }
    public Task<IReadOnlyList<ProblemDevice>?> ReadProblemDevicesAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<ProblemDevice>?>([]);
    public Task<IReadOnlyList<DriverEntry>?> ReadDriversAsync(CancellationToken ct) { Reads++; return Task.FromResult(drivers); }
}

public sealed class WmiCrashDumpSourceTests
{
    [Fact]
    public void Asks_for_the_dump_folders_with_escaped_paths()
    {
        Assert.Equal(@"SELECT Name, FileSize, LastModified FROM CIM_DataFile WHERE Drive = 'C:' AND Path = '\\Windows\\Minidump\\' AND Extension = 'dmp'",
            WmiCrashDumpSource.FilesSql(@"C:\Windows\Minidump", "dmp"));
        Assert.Equal(@"SELECT Name, FileSize, LastModified FROM CIM_DataFile WHERE Name = 'C:\\Windows\\MEMORY.DMP'", WmiCrashDumpSource.FileSql(@"C:\Windows\MEMORY.DMP"));
        Assert.Equal(@"SELECT Name FROM Win32_Directory WHERE Drive = 'D:' AND Path = '\\Win\'s\\LiveKernelReports\\'",
            WmiCrashDumpSource.FoldersSql(@"D:\Win's\LiveKernelReports\"));
    }

    [Fact]
    public void Reads_a_file_row_and_skips_one_without_a_time()
    {
        var f = WmiCrashDumpSource.File(RemotePCDiagnostics.Core.DataSources.WmiRow.From(new Dictionary<string, object?>
            { ["Name"] = @"c:\windows\minidump\111026-01.dmp", ["FileSize"] = 1024UL, ["LastModified"] = "20261110001200.000000-420" }));
        Assert.NotNull(f);
        Assert.Equal("111026-01.dmp", f.FileName);
        Assert.Equal(1024, f.SizeBytes);
        Assert.Equal(new DateTimeOffset(2026, 11, 10, 7, 12, 0, TimeSpan.Zero), f.Created);
        Assert.Null(WmiCrashDumpSource.File(RemotePCDiagnostics.Core.DataSources.WmiRow.From(new Dictionary<string, object?> { ["Name"] = "x.dmp" })));
    }
}
