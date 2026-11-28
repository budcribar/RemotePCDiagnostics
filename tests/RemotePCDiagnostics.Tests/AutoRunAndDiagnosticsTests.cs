using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Tests;

public class AutoRunTests
{
    private static readonly TimeSpan Wait = TimeSpan.FromSeconds(10);

    /// <summary>The environment with auto-run turned on (it is off by default).</summary>
    private static string? On(string key) => key == AutoRun.EnvironmentVariable ? "1" : null;

    [Theory]
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData("1", true)]
    [InlineData("true", true)]
    [InlineData("ON", true)]
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
        var tasks = AutoRun.Start(svc, On, null, "Osquery");
        Assert.Equal(DiagnosticStatus.Running, store.Get("Osquery").Status);
        gate.SetResult();
        var r = await Assert.Single(tasks).WaitAsync(Wait);
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        Assert.Equal(DiagnosticStatus.Ok, store.Get("Osquery").Status);
    }

    private sealed class SlowDetectModule(string name, Task<ModuleDetection> detection) : IDetectableModule
    {
        public int DetectCalls;
        public int RefreshCalls;
        public string Name => name;
        public Guid Id => TestIds.For(name);
        public event EventHandler<DiagnosticResult>? Updated { add { } remove { } }
        public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct = default) => Task.FromResult(ModuleAvailability.Available);
        public Task<DiagnosticResult> RefreshAsync(IProgress<string>? p, CancellationToken ct = default)
        {
            Interlocked.Increment(ref RefreshCalls);
            return Task.FromResult(FakeModule.Ok(name));
        }
        public Task<ModuleDetection> DetectAsync(CancellationToken ct = default)
        {
            Interlocked.Increment(ref DetectCalls);
            return detection;
        }
    }

    [Fact]
    public async Task Start_IncludesDetectableModule_WhoseDetectionIsStillRunning()
    {
        // Drive health detects its drives at launch; auto-run used to skip it because Modules hides it until detection finishes.
        var applicable = new TaskCompletionSource<ModuleDetection>(TaskCreationOptions.RunContinuationsAsynchronously);
        var presentMod = new SlowDetectModule("SlowPresent", applicable.Task);
        var presentStore = new ResultStore();
        var presentSvc = new DiagnosticsService(presentStore, [presentMod]);
        Assert.DoesNotContain(presentSvc.Modules, m => m.Name == "SlowPresent");
        var presentTasks = AutoRun.Start(presentSvc, On, null, "SlowPresent");
        _ = Assert.Single(presentTasks);
        applicable.SetResult(ModuleDetection.For([new ModuleInstance("dev-1", "Device 1")]));
        var presentResults = await Task.WhenAll(presentTasks).WaitAsync(Wait);
        Assert.Equal(DiagnosticStatus.Ok, Assert.Single(presentResults).Status);
        Assert.Equal(DiagnosticStatus.Ok, presentStore.Get("SlowPresent").Status);
        Assert.Equal(1, presentMod.DetectCalls);
        Assert.Equal(1, presentMod.RefreshCalls);
        Assert.Contains(presentSvc.Modules, m => m.Name == "SlowPresent");

        // When detection resolves to NotApplicable, RefreshAsync must not run or store a bogus Ok, and DetectAsync runs only once.
        var notApplicable = new TaskCompletionSource<ModuleDetection>(TaskCreationOptions.RunContinuationsAsynchronously);
        var absentMod = new SlowDetectModule("SlowDetect", notApplicable.Task);
        var absentStore = new ResultStore();
        var absentSvc = new DiagnosticsService(absentStore, [absentMod]);
        Assert.DoesNotContain(absentSvc.Modules, m => m.Name == "SlowDetect");
        var absentTasks = AutoRun.Start(absentSvc, On, null, "SlowDetect");
        _ = Assert.Single(absentTasks);
        notApplicable.SetResult(ModuleDetection.NotApplicable("none here"));
        var absentResults = await Task.WhenAll(absentTasks).WaitAsync(Wait);
        Assert.Equal(DiagnosticStatus.NotRun, Assert.Single(absentResults).Status);
        Assert.Equal(DiagnosticStatus.NotRun, absentStore.Get("SlowDetect").Status);
        Assert.Equal(1, absentMod.DetectCalls);
        Assert.Equal(0, absentMod.RefreshCalls);
        Assert.DoesNotContain(absentSvc.Modules, m => m.Name == "SlowDetect");
    }

    /// <summary>Bud, Nov 28: the Dashboard header said "Querying hardware…" until someone ran the checks. The hardware inventory is read
    /// right away, even with auto-run off.</summary>
    [Fact]
    public async Task ReadHardwareInventory_RunsOsquery_EvenWithAutoRunOff()
    {
        var m = new FakeModule(ModuleSlugs.Osquery, _ => Task.FromResult(FakeModule.Ok(ModuleSlugs.Osquery)));
        var store = new ResultStore();
        var svc = new DiagnosticsService(store, [m]);
        Assert.False(AutoRun.IsEnabled(_ => null));

        var r = await AutoRun.ReadHardwareInventoryAsync(svc, store, null).WaitAsync(Wait);

        Assert.Equal(DiagnosticStatus.Ok, r?.Status);
        Assert.Equal(DiagnosticStatus.Ok, store.Get(ModuleSlugs.Osquery).Status);
    }

    [Fact]
    public async Task ReadHardwareInventory_JoinsARunningRead_AndSkipsWhenItHasAResult()
    {
        var gate = new TaskCompletionSource();
        var calls = 0;
        var m = new FakeModule(ModuleSlugs.Osquery, async _ => { Interlocked.Increment(ref calls); await gate.Task; return FakeModule.Ok(ModuleSlugs.Osquery); });
        var store = new ResultStore();
        var svc = new DiagnosticsService(store, [m]);

        var first = AutoRun.ReadHardwareInventoryAsync(svc, store, null);
        var second = AutoRun.ReadHardwareInventoryAsync(svc, store, null); // joins the first read
        Assert.False(second.IsCompleted);
        gate.SetResult();
        await Task.WhenAll(first, second).WaitAsync(Wait);
        Assert.Equal(DiagnosticStatus.Ok, second.Result?.Status);
        Assert.Null(await AutoRun.ReadHardwareInventoryAsync(svc, store, null).WaitAsync(Wait)); // has a result
        Assert.Equal(1, calls);

        // No Osquery module here (or it can't run): nothing starts and nothing throws.
        var empty = new ResultStore();
        Assert.Null(await AutoRun.ReadHardwareInventoryAsync(new DiagnosticsService(empty, []), empty, null).WaitAsync(Wait));
    }

    /// <summary>Bud, Nov 28 (BUDSLAPTOP): the startup read ran before the Agent's pipe was up and showed "Couldn't read hardware details".
    /// It now waits for the Agent first.</summary>
    [Fact]
    public async Task ReadHardwareInventory_WaitsForTheAgent_BeforeReading()
    {
        var connected = false;
        var readWhileConnected = new List<bool>();
        var m = new FakeModule(ModuleSlugs.Osquery, _ => { lock (readWhileConnected) readWhileConnected.Add(Volatile.Read(ref connected)); return Task.FromResult(FakeModule.Ok(ModuleSlugs.Osquery)); });
        var store = new ResultStore();
        var svc = new DiagnosticsService(store, [m]);

        var read = AutoRun.ReadHardwareInventoryAsync(svc, store, null, () => Volatile.Read(ref connected), agentWait: TimeSpan.FromSeconds(10));
        await Task.Delay(400);
        Assert.False(read.IsCompleted);
        Assert.Equal(DiagnosticStatus.NotRun, store.Get(ModuleSlugs.Osquery).Status); // the header keeps "Querying hardware…"
        Volatile.Write(ref connected, true);

        Assert.Equal(DiagnosticStatus.Ok, (await read.WaitAsync(Wait))?.Status);
        Assert.Equal([true], readWhileConnected);
    }

    [Fact]
    public async Task ReadHardwareInventory_NoAgentOrTimeout_ReadsWithoutIt()
    {
        var m = new FakeModule(ModuleSlugs.Osquery, _ => Task.FromResult(FakeModule.Ok(ModuleSlugs.Osquery)));
        var store = new ResultStore();
        var svc = new DiagnosticsService(store, [m]);
        // A PC with no Agent (the Store edition on its own) doesn't wait.
        var r = await AutoRun.ReadHardwareInventoryAsync(svc, store, null, () => false, () => true, TimeSpan.FromMinutes(5)).WaitAsync(Wait);
        Assert.Equal(DiagnosticStatus.Ok, r?.Status);

        // An Agent that never connects: it reads anyway once the wait is over.
        var store2 = new ResultStore();
        var r2 = await AutoRun.ReadHardwareInventoryAsync(new DiagnosticsService(store2, [m]), store2, null, () => false, agentWait: TimeSpan.FromMilliseconds(300)).WaitAsync(Wait);
        Assert.Equal(DiagnosticStatus.Ok, r2?.Status);
    }

    /// <summary>When the Agent connects, a hardware read that failed (it ran before the Agent) is read again, before the sensors.</summary>
    [Fact]
    public async Task ReadHardwareInventory_RereadFailed_ReadsAFailedResultAgain()
    {
        var calls = 0;
        var m = new FakeModule(ModuleSlugs.Osquery, _ => { Interlocked.Increment(ref calls); return Task.FromResult(FakeModule.Ok(ModuleSlugs.Osquery)); });
        var store = new ResultStore();
        var svc = new DiagnosticsService(store, [m]);
        store.Set(new DiagnosticResult(ModuleSlugs.Osquery, DiagnosticStatus.Error, "Couldn't read hardware details on this PC.", DateTimeOffset.Now));

        Assert.Null(await AutoRun.ReadHardwareInventoryAsync(svc, store, null).WaitAsync(Wait)); // only on request
        Assert.Equal(DiagnosticStatus.Ok, (await AutoRun.ReadHardwareInventoryAsync(svc, store, null, rereadFailed: true).WaitAsync(Wait))?.Status);
        Assert.Null(await AutoRun.ReadHardwareInventoryAsync(svc, store, null, rereadFailed: true).WaitAsync(Wait)); // a good result stays
        Assert.Equal(1, calls);
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
        var auto = AutoRun.Start(svc, On, null, "Osquery")[0];
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

    [Fact]
    public async Task BackgroundAutoRun_MarkedAsBackground_AndUpgradedWhenUserStartsRun()
    {
        var gate = new TaskCompletionSource();
        var m = new FakeModule("Osquery", async _ => { await gate.Task; return FakeModule.Ok("Osquery"); });
        var svc = new DiagnosticsService(new ResultStore(), [m]);
        var auto = AutoRun.Start(svc, On, null, "Osquery")[0];
        Assert.True(svc.IsBackgroundAutoRun("Osquery"));

        // Joining the same in-flight run from a manual user action upgrades it to a blocking user check.
        var manual = svc.RunAsync("Osquery");
        Assert.False(svc.IsBackgroundAutoRun("Osquery"));

        gate.SetResult();
        await Task.WhenAll(auto, manual).WaitAsync(Wait);
        Assert.False(svc.IsBackgroundAutoRun("Osquery"));
    }

    [Fact]
    public async Task StartEnabledChecksAsync_RunsPriorityFirst_AndDelaysSlowerChecks()
    {
        var slowStarted = new TaskCompletionSource();
        var fastDone = new TaskCompletionSource();
        var fast = new FakeModule(ModuleSlugs.Osquery, _ => { fastDone.TrySetResult(); return Task.FromResult(FakeModule.Ok(ModuleSlugs.Osquery)); });
        var slow = new FakeModule("SlowCheck", _ => { slowStarted.TrySetResult(); return Task.FromResult(FakeModule.Ok("SlowCheck")); });
        var svc = new DiagnosticsService(new ResultStore(), [fast, slow]);

        using var cts = new CancellationTokenSource();
        var run = AutoRun.StartEnabledChecksAsync(svc, null, On, null, slowChecksDelay: TimeSpan.FromSeconds(5), ct: cts.Token);

        await fastDone.Task.WaitAsync(Wait);
        // Slow check must not have started yet during the delay window.
        Assert.False(slowStarted.Task.IsCompleted);

        cts.Cancel();
        await run.WaitAsync(Wait);
        Assert.False(slowStarted.Task.IsCompleted);
    }
}

public class OsqueryDiagnosticsAndFallbackTests
{
    private static OsqueryRunner Runner(FakeLauncher l, List<string>? log = null, bool exists = true) =>
        new(Path.Combine("C:", "app"), new OsqueryOptions { Log = log is null ? null : new LineLogger(log.Add) }, l, _ => exists);

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
        var inv = await RemotePCDiagnostics.Legacy.OsqueryHardwareInventorySource.CollectAsync(Runner(l));
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
        var inv = await RemotePCDiagnostics.Legacy.OsqueryHardwareInventorySource.CollectAsync(Runner(l));
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
        var missing = await new DiagnosticsService(new ResultStore(), [new OsqueryModule(new RemotePCDiagnostics.Legacy.OsqueryHardwareInventorySource(Runner(new FakeLauncher(_ => throw new Exception()), exists: false)))]).RunAsync("Osquery");
        Assert.Equal(DiagnosticStatus.Error, missing.Status);
        Assert.Equal(OsqueryModule.ToolMissingMessage, missing.Message);

        var broken = await new DiagnosticsService(new ResultStore(), [new OsqueryModule(new RemotePCDiagnostics.Legacy.OsqueryHardwareInventorySource(Runner(new FakeLauncher(_ => Task.FromResult(new ProcessResult(3, "", "boom"))))))]).RunAsync("Osquery");
        Assert.Equal(OsqueryModule.AllFailedMessage, broken.Message);

        foreach (var msg in new[] { missing.Message, broken.Message })
            foreach (var bad in new[] { "osquery", "exit", "_info", "SELECT", ".exe", "stderr", "rows" })
                Assert.DoesNotContain(bad, msg, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Module_DisplayName_IsHardwareInventory()
    {
        IDiagnosticModule m = new OsqueryModule(new RemotePCDiagnostics.Legacy.OsqueryHardwareInventorySource(new OsqueryRunner(fileExists: _ => false)));
        Assert.Equal("Hardware inventory", m.DisplayName);
        Assert.Equal("Osquery", m.Name);
    }
}
