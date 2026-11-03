using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Tests;

public class AutoRunTests
{
    private static readonly TimeSpan Wait = TimeSpan.FromSeconds(10);

    [Theory]
    [InlineData(null, true)]
    [InlineData("1", true)]
    [InlineData("0", false)]
    [InlineData("false", false)]
    [InlineData("OFF", false)]
    public void IsEnabled_HonoursEnvironment(string? value, bool expected) =>
        Assert.Equal(expected, AutoRun.IsEnabled(k => k == AutoRun.EnvironmentVariable ? value : null));

    [Fact]
    public async Task Start_RunsModuleInBackground_AndStoreGoesRunningThenOk()
    {
        var gate = new TaskCompletionSource();
        var m = new FakeModule("Osquery", async _ => { await gate.Task; return FakeModule.Ok("Osquery"); });
        var store = new ResultStore();
        var svc = new DiagnosticsService(store, [m]);
        var tasks = AutoRun.Start(svc, _ => null, null, "Osquery");
        Assert.Equal(DiagnosticStatus.Running, store.Get("Osquery").Status);
        gate.SetResult();
        var r = await Assert.Single(tasks).WaitAsync(Wait);
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        Assert.Equal(DiagnosticStatus.Ok, store.Get("Osquery").Status);
    }

    [Fact]
    public void Start_Disabled_DoesNothing()
    {
        var calls = 0;
        var m = new FakeModule("Osquery", _ => { Interlocked.Increment(ref calls); return Task.FromResult(FakeModule.Ok("Osquery")); });
        var store = new ResultStore();
        var tasks = AutoRun.Start(new DiagnosticsService(store, [m]), _ => "0", null, "Osquery");
        Assert.Empty(tasks);
        Assert.Equal(0, calls);
        Assert.Equal(DiagnosticStatus.NotRun, store.Get("Osquery").Status);
    }

    [Fact]
    public async Task NoDoubleRun_WhileInProgress()
    {
        var gate = new TaskCompletionSource();
        var calls = 0;
        var m = new FakeModule("Osquery", async _ => { Interlocked.Increment(ref calls); await gate.Task; return FakeModule.Ok("Osquery"); });
        var svc = new DiagnosticsService(new ResultStore(), [m]);
        var auto = AutoRun.Start(svc, _ => null, null, "Osquery")[0];
        var manual = svc.RunAsync("Osquery");
        var all = svc.RunAllAsync();
        Assert.True(svc.IsRunning("Osquery"));
        gate.SetResult();
        await Task.WhenAll(auto, manual, all).WaitAsync(Wait);
        Assert.Equal(1, calls);
        // After completion a new run is allowed.
        await svc.RunAsync("Osquery").WaitAsync(Wait);
        Assert.Equal(2, calls);
    }
}

public class OsqueryDiagnosticsAndFallbackTests
{
    private static OsqueryRunner Runner(FakeLauncher l, List<string>? log = null, bool exists = true) =>
        new(Path.Combine("C:", "app"), new OsqueryOptions { Log = log is null ? null : log.Add }, l, _ => exists);

    private static FakeLauncher Responder(Func<string, string> json) => new(sql => Task.FromResult(new ProcessResult(0, json(sql), "W warn")));

    [Fact]
    public async Task Diagnostics_RecordedOnResult_AndLogged_NotInMessage()
    {
        var log = new List<string>();
        var big = "[" + string.Join(",", Enumerable.Repeat("""{"hostname":"h"}""", 300)) + "]";
        var q = await Runner(new FakeLauncher(_ => Task.FromResult(new ProcessResult(0, big, "W0101 note"))), log).RunQueryAsync("SELECT * FROM system_info;");
        Assert.Equal(300, q.RowCount);
        Assert.Equal(0, q.ExitCode);
        Assert.Equal("W0101 note", q.RawStdErr);
        Assert.Equal(OsqueryQueryResult.StdOutHeadLength, q.RawStdOutHead.Length);
        Assert.True(q.ElapsedMs >= 0);
        var line = Assert.Single(log);
        Assert.Contains("rows=300", line);
        Assert.Contains("exit=0", line);
        Assert.Contains("W0101 note", line);
    }

    [Fact]
    public async Task FailedQuery_LogsExitCodeAndStderr()
    {
        var log = new List<string>();
        var q = await Runner(new FakeLauncher(_ => Task.FromResult(new ProcessResult(1, "", "Error: no such column: x"))), log).RunQueryAsync("SELECT x FROM disk_info;");
        Assert.Equal(1, q.ExitCode);
        Assert.Contains("exit=1", log.Single());
        Assert.Contains("no such column", log.Single());
    }

    [Fact]
    public async Task Fallbacks_CpuFromSystemInfo_MemoryFromPhysical_DiskSizeFromLogicalDrives()
    {
        var l = Responder(sql => sql switch
        {
            _ when sql.Contains("system_info") => """[{"computer_name":"DESKTOP-TEST01","hardware_vendor":"LENOVO","hardware_model":"IdeaPad 5","cpu_brand":"AMD Ryzen 7 5700U","cpu_physical_cores":"8","cpu_logical_cores":"16","physical_memory":"17179869184"}]""",
            _ when sql.Contains("disk_info") => """[{"disk_index":"0","hardware_model":"WDC PC SN530","disk_size":""}]""",
            _ when sql.Contains("logical_drives") => """[{"device_id":"C:","type":"Local Disk","size":"511000000000"},{"device_id":"D:","type":"CD-ROM Disc","size":"0"},{"device_id":"E:","type":"Removable Disk","size":"32000000000"}]""",
            _ => "[]",
        });
        var inv = await HardwareInventory.CollectAsync(Runner(l));
        Assert.Equal(0, inv.FailedSections);
        var cpu = Assert.Single(inv.Cpus.Items);
        Assert.True(inv.Cpus.FromFallback);
        Assert.Equal("AMD Ryzen 7 5700U", cpu.Model);
        Assert.Equal(8, cpu.NumberOfCores);
        Assert.Equal(16, cpu.LogicalProcessors);
        Assert.True(inv.Memory.FromFallback);
        Assert.Equal(17179869184, inv.TotalMemoryBytes);
        Assert.True(inv.Disks.FromFallback);
        Assert.Equal(511000000000, inv.Disks.Items.Single().SizeBytes);
        var summary = inv.FriendlySummary();
        Assert.Contains("DESKTOP-TEST01 (LENOVO IdeaPad 5)", summary);
        Assert.Contains("AMD Ryzen 7 5700U", summary);
        Assert.Contains("16 GB memory", summary);
        Assert.Contains("1 drive", summary);
    }

    [Fact]
    public async Task NoFallback_WhenTablesHaveData_AndLogicalDrivesNotQueried()
    {
        var l = Responder(sql => sql switch
        {
            _ when sql.Contains("system_info") => """[{"cpu_brand":"X","physical_memory":"8589934592"}]""",
            _ when sql.Contains("cpu_info") => """[{"model":"Real CPU"}]""",
            _ when sql.Contains("memory_devices") => """[{"size":"8192"}]""",
            _ when sql.Contains("disk_info") => """[{"disk_size":"1000"}]""",
            _ => throw new InvalidOperationException("unexpected " + sql),
        });
        var inv = await HardwareInventory.CollectAsync(Runner(l));
        Assert.False(inv.Cpus.FromFallback || inv.Memory.FromFallback || inv.Disks.FromFallback);
        Assert.Equal("Real CPU", inv.Cpus.Items.Single().Model);
        Assert.DoesNotContain(l.Calls, c => c.Args[^1].Contains("logical_drives"));
    }

    [Fact]
    public void SumFixedDrives_FallsBackToAllSizedDrives_WhenTypeUnknown()
    {
        var rows = OsqueryJson.ParseRows("""[{"type":"weird","size":"10"},{"type":"","size":"5"}]""");
        Assert.Equal(15, HardwareInventory.SumFixedDrives(rows));
    }

    [Fact]
    public async Task UserMessages_AreFriendly_NoDeveloperText()
    {
        var missing = await new DiagnosticsService(new ResultStore(), [new OsqueryModule(Runner(new FakeLauncher(_ => throw new Exception()), exists: false))]).RunAsync("Osquery");
        Assert.Equal(DiagnosticStatus.Error, missing.Status);
        Assert.Equal(OsqueryModule.ToolMissingMessage, missing.Message);

        var broken = await new DiagnosticsService(new ResultStore(), [new OsqueryModule(Runner(new FakeLauncher(_ => Task.FromResult(new ProcessResult(3, "", "boom")))))]).RunAsync("Osquery");
        Assert.Equal(OsqueryModule.AllFailedMessage, broken.Message);

        foreach (var msg in new[] { missing.Message, broken.Message })
            foreach (var bad in new[] { "osquery", "exit", "_info", "SELECT", ".exe", "stderr", "rows" })
                Assert.DoesNotContain(bad, msg, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Module_DisplayName_IsHardwareInventory()
    {
        IDiagnosticModule m = new OsqueryModule(new OsqueryRunner(fileExists: _ => false));
        Assert.Equal("Hardware inventory", m.DisplayName);
        Assert.Equal("Osquery", m.Name);
    }
}
