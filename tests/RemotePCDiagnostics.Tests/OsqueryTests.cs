using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Tests;

internal sealed class FakeLauncher(Func<string, Task<ProcessResult>> run) : IProcessLauncher
{
    public List<(string File, IReadOnlyList<string> Args)> Calls { get; } = new();
    public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct)
    {
        lock (Calls) Calls.Add((fileName, arguments));
        return run(arguments[^1]);
    }
}

public class OsqueryJsonTests
{
    private const string SystemInfoJson = """
    [
      {"board_model":"0K8J6M","board_serial":"/ABC123/CNXYZ/","board_vendor":"Dell Inc.","board_version":"A00","computer_name":"DESKTOP-TEST02",
       "cpu_brand":"13th Gen Intel(R) Core(TM) i7-13700","cpu_logical_cores":"24","cpu_microcode":"","cpu_physical_cores":"16",
       "cpu_sockets":"1","cpu_subtype":"-1","cpu_type":"x86_64","hardware_model":"OptiPlex 7010","hardware_serial":"ABC123",
       "hardware_vendor":"Dell Inc.","hardware_version":"","hostname":"DESKTOP-TEST02","local_hostname":"DESKTOP-TEST02",
       "physical_memory":"34359738368","uuid":"4c4c4544-0042-4310-8030-b1c04f4d3233"}
    ]
    """;
    private const string CpuJson = """
    [{"address_width":"64","availability":"3","cpu_status":"1","current_clock_speed":"2100","device_id":"CPU0","load_percentage":"7",
      "logical_processors":"24","manufacturer":"GenuineIntel","max_clock_speed":"2100","model":"13th Gen Intel(R) Core(TM) i7-13700",
      "number_of_cores":"16","number_of_efficiency_cores":"8","number_of_performance_cores":"8","processor_type":"3","socket_designation":"LGA1700"}]
    """;
    private const string MemoryJson = """
    [{"array_handle":"0x0030","asset_tag":"","bank_locator":"BANK 0","configured_clock_speed":"4400","configured_voltage":"1100","data_width":"64",
      "device_locator":"DIMM1","form_factor":"DIMM","handle":"0x0031","manufacturer":"SK Hynix","max_speed":"4800","max_voltage":"1100",
      "memory_type":"DDR5","memory_type_details":"Synchronous","min_voltage":"1100","part_number":"HMCG78AGBUA081N","serial_number":"12345678","set":"0","size":"16384","total_width":"64"},
     {"bank_locator":"BANK 1","device_locator":"DIMM2","size":"0","memory_type":"Unknown","max_speed":"","configured_clock_speed":""}]
    """;
    private const string DiskJson = """
    [{"description":"Disk drive","disk_index":"0","disk_size":"1024203640320","hardware_model":"PC801 NVMe SK hynix 1TB","id":"\\\\.\\PHYSICALDRIVE0",
      "manufacturer":"(Standard disk drives)","name":"\\\\.\\PHYSICALDRIVE0","partitions":"3","pnp_device_id":"SCSI\\DISK&VEN_NVME","serial":"ACE4_2E00","type":"SCSI"}]
    """;

    [Fact]
    public void SystemInfo_ParsesStringsAndNumbers()
    {
        var s = SystemInfo.FromRow(OsqueryJson.ParseRows(SystemInfoJson).Single());
        Assert.Equal("Dell Inc.", s.HardwareVendor);
        Assert.Equal("OptiPlex 7010", s.HardwareModel);
        Assert.Equal(16, s.CpuPhysicalCores);
        Assert.Equal(24, s.CpuLogicalCores);
        Assert.Equal(34359738368L, s.PhysicalMemoryBytes);
        Assert.Equal("", s.HardwareVersion);
    }

    [Fact]
    public void CpuInfo_Parses()
    {
        var c = CpuInfo.FromRow(OsqueryJson.ParseRows(CpuJson).Single());
        Assert.Equal("CPU0", c.DeviceId);
        Assert.Equal(16, c.NumberOfCores);
        Assert.Equal(2100, c.MaxClockSpeedMhz);
        Assert.Equal("LGA1700", c.SocketDesignation);
    }

    [Fact]
    public void MemoryDevices_ParsesPopulatedAndEmptySlots()
    {
        var m = OsqueryJson.ParseRows(MemoryJson).Select(MemoryDevice.FromRow).ToList();
        Assert.Equal(2, m.Count);
        Assert.Equal(16384, m[0].SizeMb);
        Assert.True(m[0].IsPopulated);
        Assert.Equal(4400, m[0].ConfiguredClockSpeedMts);
        Assert.False(m[1].IsPopulated);
        Assert.Null(m[1].MaxSpeedMts);            // empty string -> null
        Assert.Equal("", m[1].Manufacturer);      // missing column -> ""
    }

    [Fact]
    public void DiskInfo_Parses()
    {
        var d = DiskInfo.FromRow(OsqueryJson.ParseRows(DiskJson).Single());
        Assert.Equal(0, d.DiskIndex);
        Assert.Equal(1024203640320L, d.SizeBytes);
        Assert.Equal(@"\\.\PHYSICALDRIVE0", d.Id);
        Assert.Equal(3, d.Partitions);
    }

    [Fact]
    public void EmptyArray_YieldsNoRows() => Assert.Empty(OsqueryJson.ParseRows("[]\n"));

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not json")]
    [InlineData("[{\"a\":\"1\"")]
    [InlineData("{\"a\":\"1\"}")]
    public void Malformed_ThrowsFormatException(string json) => Assert.Throws<FormatException>(() => OsqueryJson.ParseRows(json));

    [Fact]
    public void NonStringValues_AndBadNumbers_AreTolerated()
    {
        var row = OsqueryJson.ParseRows("""[{"size":16384,"max_speed":"fast","part_number":null,"extra":{"x":1},"configured_clock_speed":" 3200 ","total_width":"1.5e3"}]""").Single();
        var m = MemoryDevice.FromRow(row);
        Assert.Equal(16384, m.SizeMb);
        Assert.Null(m.MaxSpeedMts);
        Assert.Equal("", m.PartNumber);
        Assert.Equal(3200, m.ConfiguredClockSpeedMts);
        Assert.Equal(1500, row.Int("total_width"));
        Assert.Null(row.Long("missing"));
    }

    [Fact]
    public void FormatBytes() 
    {
        Assert.Equal("32 GB", HardwareInventory.FormatBytes(34359738368));
        Assert.Equal("—", HardwareInventory.FormatBytes(null));
    }
}

public class OsqueryRunnerTests
{
    private static OsqueryRunner Runner(FakeLauncher l, bool exists = true) =>
        new(Path.Combine("C:", "app"), launcher: l, fileExists: _ => exists);

    [Fact]
    public async Task NotFound_ReturnsErrorWithoutLaunching()
    {
        var l = new FakeLauncher(_ => throw new InvalidOperationException("should not run"));
        var r = Runner(l, exists: false);
        var q = await r.RunQueryAsync("SELECT 1;");
        Assert.False(q.Success);
        Assert.Contains("not found", q.Error);
        Assert.Contains(r.ResolvedPath, q.Error);
        Assert.Empty(l.Calls);
        Assert.False(r.CheckAvailability().IsAvailable);
    }

    [Fact]
    public async Task ConfiguredPath_Overrides()
    {
        var p = Path.Combine(Path.GetTempPath(), "custom", "osqueryi.exe");
        var r = new OsqueryRunner(options: new OsqueryOptions { ExecutablePath = p }, fileExists: _ => false);
        Assert.Equal(Path.GetFullPath(p), r.ResolvedPath);
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Success_PassesJsonFlagAndSql()
    {
        var l = new FakeLauncher(_ => Task.FromResult(new ProcessResult(0, """[{"hostname":"h"}]""", "")));
        var q = await Runner(l).RunQueryAsync("SELECT * FROM system_info;");
        Assert.True(q.Success);
        Assert.Equal("h", q.Rows!.Single()["hostname"]);
        Assert.Equal(["--disable_extensions", "--json", "SELECT * FROM system_info;"], l.Calls.Single().Args);
    }

    [Theory]
    [InlineData(1, "", "Error: no such table: bogus", "exited with code 1")]
    [InlineData(0, "garbage", "", "invalid JSON")]
    [InlineData(0, "", "", "no output")]
    public async Task Failures_BecomePerQueryErrors(int code, string stdout, string stderr, string expected)
    {
        var l = new FakeLauncher(_ => Task.FromResult(new ProcessResult(code, stdout, stderr)));
        var q = await Runner(l).RunQueryAsync("SELECT * FROM bogus;");
        Assert.False(q.Success);
        Assert.Contains(expected, q.Error);
        if (stderr.Length > 0) Assert.Contains("no such table", q.Error);
    }

    [Fact]
    public async Task Timeout_And_LaunchFailure_AreErrors()
    {
        var t = await Runner(new FakeLauncher(_ => Task.FromResult(new ProcessResult(-1, "", "", TimedOut: true)))).RunQueryAsync("x");
        Assert.Contains("timed out", t.Error);
        var f = await Runner(new FakeLauncher(_ => throw new System.ComponentModel.Win32Exception("access denied"))).RunQueryAsync("x");
        Assert.Contains("Failed to start", f.Error);
    }

    [Fact]
    public async Task Cancellation_Propagates()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var l = new FakeLauncher(_ => Task.FromException<ProcessResult>(new OperationCanceledException(cts.Token)));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Runner(l).RunQueryAsync("x", cts.Token));
    }

    [Fact]
    public async Task Module_OneFailingQuery_OthersStillReported()
    {
        var l = new FakeLauncher(sql => Task.FromResult(sql.Contains("disk_info")
            ? new ProcessResult(1, "", "boom")
            : new ProcessResult(0, sql.Contains("system_info") ? """[{"hardware_vendor":"Dell","hardware_model":"X","physical_memory":"8589934592"}]""" : "[]", "")));
        var store = new ResultStore();
        var r = await new DiagnosticsService(store, [new OsqueryModule(Runner(l))]).RunAsync("Osquery");
        Assert.Equal(DiagnosticStatus.Warning, r.Status);
        var inv = Assert.IsType<HardwareInventory>(store.Get("Osquery").Payload);
        Assert.True(inv.System.Success);
        Assert.Equal("Dell", inv.System.Items.Single().HardwareVendor);
        Assert.True(inv.Cpus.Success);
        Assert.False(inv.Disks.Success);
        Assert.Contains("boom", inv.Disks.Error);
        Assert.Contains("8 GB", r.Message);
    }

    [Fact]
    public async Task Module_AllFail_IsError()
    {
        var l = new FakeLauncher(_ => Task.FromResult(new ProcessResult(2, "", "bad")));
        var r = await new DiagnosticsService(new ResultStore(), [new OsqueryModule(Runner(l))]).RunAsync("Osquery");
        Assert.Equal(DiagnosticStatus.Error, r.Status);
    }
}
