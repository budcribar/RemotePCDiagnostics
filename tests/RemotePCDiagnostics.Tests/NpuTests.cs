using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Npu;

namespace RemotePCDiagnostics.Tests;

public class NpuTests
{
    private static PnpRow Row(string name, string? cls = "ComputeAccelerator", string id = @"PCI\VEN_8086&DEV_7D1D&SUBSYS_00000000&REV_04\3&11583659&0&58",
        int? code = 0, string? status = "OK", string? driver = "32.0.100.3104") =>
        new(id, name, cls, null, "Intel Corporation", status, code, driver, [id.Split('\\')[0] + "\\" + id.Split('\\')[1]]);

    private static DxCoreAdapterRow Adapter(long luid = 0x1234, uint ven = 0x8086, uint dev = 0x7D1D, bool npuType = true, bool gfx = false, bool core = false, bool ml = true) =>
        new(luid, "Intel(R) AI Boost", ven, dev, 0x0020_0000_0064_0C20UL, npuType, gfx, core, ml, true);

    private static NpuDevice Dev(int? code = 0, string? status = "OK", long? luid = 1, NpuComputeLevel lvl = NpuComputeLevel.CoreCompute) =>
        new("id", "Test NPU", "Intel", "1.0", status, code, NpuSource.Both, null, luid, lvl);

    private sealed class FakeIo(Func<NpuWorkloadRequest, CancellationToken, Task<NpuWorkloadResult>> run, params NpuDevice[] devices) : INpuIo
    {
        public int Calls;
        public IReadOnlyList<NpuDevice> ListDevices() => devices;
        public Task<NpuWorkloadResult> RunWorkloadAsync(NpuDevice device, NpuWorkloadRequest request, CancellationToken ct) { Calls++; return run(request, ct); }
    }

    private static Func<NpuWorkloadRequest, CancellationToken, Task<NpuWorkloadResult>> Correct(double avgMs = 0.01) =>
        (r, _) => Task.FromResult(new NpuWorkloadResult(NpuWorkloadKind.MatMulComputeShader, NpuTestModule.CpuMatMul(r.A, r.B, r.MatrixSize), 1, avgMs, 50, "Fake NPU"));

    // ---- detection ----

    [Theory]
    [InlineData("Intel(R) AI Boost", "System", true)]
    [InlineData("NPU Compute Accelerator Device", "ComputeAccelerator", true)]
    [InlineData("AMD IPU Device", "System", true)]
    [InlineData("Snapdragon(R) X Elite - X1E80100 - Qualcomm(R) Hexagon(TM) NPU", "ComputeAccelerator", true)]
    [InlineData("Anything", "ComputeAccelerator", true)]
    [InlineData("AMD Radeon(TM) Graphics", "Display", false)]
    [InlineData("Intel NPU display shim", "Display", false)]
    [InlineData("Realtek Audio", "MEDIA", false)]
    [InlineData("Input processor", "System", false)]
    public void Pnp_candidates(string name, string cls, bool expected) => Assert.Equal(expected, NpuDetection.IsNpuCandidate(Row(name, cls)));

    [Fact]
    public void Class_guid_alone_marks_a_candidate() =>
        Assert.True(NpuDetection.IsNpuCandidate(new PnpRow("X", "Device", null, "{f01a9d53-3ff6-48d2-9f97-c8a7004be10c}", null, "OK", 0, null, null)));

    [Theory]
    [InlineData(@"PCI\VEN_8086&DEV_7D1D", null, "Intel")]
    [InlineData(@"PCI\VEN_1022&DEV_1502", null, "AMD")]
    [InlineData(@"ACPI\QCOM0D0A\2&DABA3FF&0", null, "Qualcomm")]
    [InlineData(@"ROOT\X\0000", "Advanced Micro Devices, Inc.", "AMD")]
    [InlineData(@"ROOT\X\0000", "Contoso", "Contoso")]
    [InlineData(@"ROOT\X\0000", null, "Unknown")]
    public void Vendor_from_ids(string id, string? manufacturer, string expected) => Assert.Equal(expected, NpuDetection.VendorOf(id, manufacturer, "Device"));

    [Fact]
    public void Driver_version_is_four_16_bit_parts() => Assert.Equal("32.0.100.3104", NpuDetection.FormatDriverVersion(0x0020_0000_0064_0C20UL));

    [Fact]
    public void Npu_adapters_exclude_gpus_and_software()
    {
        Assert.True(NpuDetection.IsNpuAdapter(Adapter()));
        Assert.True(NpuDetection.IsNpuAdapter(Adapter(npuType: false))); // older Windows: ML-capable, no graphics
        Assert.False(NpuDetection.IsNpuAdapter(Adapter(npuType: false, gfx: true, core: true))); // a GPU
        Assert.False(NpuDetection.IsNpuAdapter(Adapter() with { IsHardware = false })); // WARP
    }

    [Fact]
    public void Merge_matches_pnp_and_dxcore_by_pci_id()
    {
        var list = NpuDetection.Merge([Row("Intel(R) AI Boost", "System"), Row("Realtek Audio", "MEDIA")], [Adapter(core: true), Adapter(luid: 9, gfx: true, npuType: false, core: true)]);
        var d = Assert.Single(list);
        Assert.Equal(NpuSource.Both, d.Source);
        Assert.Equal(0x1234, d.AdapterLuid);
        Assert.Equal("Intel", d.Vendor);
        Assert.Equal(NpuComputeLevel.CoreCompute, d.Compute);
        Assert.Equal("32.0.100.3104", d.DriverVersion);
        Assert.True(d.DriverHealthy);
    }

    [Fact]
    public void Merge_keeps_pnp_only_and_dxcore_only_devices()
    {
        var list = NpuDetection.Merge([Row("AMD IPU Device", "System", @"PCI\VEN_1022&DEV_1502\4&1", code: 28, driver: null)], [Adapter(luid: 7, ven: 0x17CB, dev: 1)]);
        Assert.Equal(2, list.Count);
        Assert.Contains(list, d => d is { Vendor: "AMD", Source: NpuSource.PnP, HasAdapter: false, DriverHealthy: false });
        Assert.Contains(list, d => d is { Vendor: "Qualcomm", Source: NpuSource.DXCore, HasAdapter: true, Compute: NpuComputeLevel.GenericMl });
    }

    [Fact]
    public void No_rows_means_no_devices() => Assert.Empty(NpuDetection.Merge([Row("Realtek Audio", "MEDIA")], [Adapter(gfx: true, npuType: false)]));

    [Theory]
    [InlineData(28, "Drivers are not installed (code 28)")]
    [InlineData(43, "Windows stopped this device after it reported problems (code 43)")]
    [InlineData(99, "Device problem (code 99)")]
    public void Problem_codes(int code, string text) => Assert.Equal(text, NpuDetection.ProblemText(code));

    // ---- decision table ----

    [Fact]
    public async Task No_npu_is_a_clean_skip()
    {
        var m = new NpuTestModule(new NullNpuIo());
        var r = await m.RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Warning, r.Status);
        Assert.Equal("Skipped: No NPU found.", r.Message);
        Assert.Equal(NpuVerdict.NoNpu, Assert.IsType<NpuTestReport>(r.Payload).Overall);
        Assert.False(m.IncludeInRunAll);
    }

    [Fact]
    public async Task Driver_problem_fails_without_running_work()
    {
        var io = new FakeIo(Correct(), Dev(code: 43));
        var r = await new NpuTestModule(io).RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Error, r.Status);
        Assert.Contains("code 43", r.Message);
        Assert.Equal(0, io.Calls);
    }

    [Fact]
    public async Task Missing_adapter_fails()
    {
        var r = await new NpuTestModule(new FakeIo(Correct(), Dev(luid: null))).RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Error, r.Status);
        Assert.Equal(NpuVerdict.NoAdapter, ((NpuTestReport)r.Payload!).Overall);
    }

    [Fact]
    public async Task Correct_fast_result_passes_with_throughput()
    {
        var m = new NpuTestModule(new FakeIo(Correct(), Dev())) { Settings = { Duration = TimeSpan.FromSeconds(1) } };
        var r = await m.RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        var d = Assert.Single(((NpuTestReport)r.Payload!).Devices);
        Assert.Equal(NpuVerdict.Pass, d.Verdict);
        Assert.True(d.Gflops > 0);
        Assert.Equal(0, d.MaxAbsError);
        Assert.Contains("GFLOPS", r.Message);
    }

    [Fact]
    public async Task Wrong_numbers_fail()
    {
        var io = new FakeIo((r, _) =>
        {
            var c = NpuTestModule.CpuMatMul(r.A, r.B, r.MatrixSize);
            c[123] += 1;
            return Task.FromResult(new NpuWorkloadResult(NpuWorkloadKind.MatMulComputeShader, c, 1, 0.01, 10, "Fake"));
        }, Dev());
        var r = await new NpuTestModule(io).RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Error, r.Status);
        Assert.Equal(NpuVerdict.Mismatch, ((NpuTestReport)r.Payload!).Overall);
    }

    [Fact]
    public async Task Exception_fails()
    {
        var io = new FakeIo((_, _) => Task.FromException<NpuWorkloadResult>(new NpuDeviceException("device removed")), Dev());
        var r = await new NpuTestModule(io).RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Error, r.Status);
        Assert.Contains("device removed", r.Message);
    }

    [Fact]
    public async Task Synchronous_throw_in_io_still_fails_cleanly()
    {
        var io = new FakeIo((_, _) => throw new InvalidOperationException("boom"), Dev());
        var r = await new NpuTestModule(io).RefreshAsync(null);
        Assert.Equal(NpuVerdict.WorkloadFailed, ((NpuTestReport)r.Payload!).Overall);
    }

    [Fact]
    public void Slow_device_warns_and_smoke_only_warns()
    {
        var res = new NpuWorkloadResult(NpuWorkloadKind.MatMulComputeShader, [], 1, 100, 5, "x");
        Assert.Equal(NpuVerdict.Slow, NpuTestModule.Decide(res, 0, cpuAverageMs: 100 / (NpuTestModule.SlowFactor + 1)));
        Assert.Equal(NpuVerdict.Pass, NpuTestModule.Decide(res, 0, cpuAverageMs: 100 / (NpuTestModule.SlowFactor - 1)));
        Assert.Equal(NpuVerdict.Mismatch, NpuTestModule.Decide(res, NpuTestModule.MaxAbsError * 2, 100));
        Assert.Equal(NpuVerdict.Mismatch, NpuTestModule.Decide(res, double.NaN, 100));
        Assert.Equal(NpuVerdict.Mismatch, NpuTestModule.Decide(res, null, 100));
        Assert.Equal(NpuVerdict.SmokeOnly, NpuTestModule.Decide(res with { Kind = NpuWorkloadKind.QueueRoundTrip, Output = null }, null, 100));
        Assert.Equal(NpuVerdict.WorkloadFailed, NpuTestModule.Decide(res with { Iterations = 0 }, 0, 100));
        Assert.Equal(DiagnosticStatus.Warning, NpuTestModule.StatusOf(NpuVerdict.Slow));
        Assert.Equal(DiagnosticStatus.Warning, NpuTestModule.StatusOf(NpuVerdict.SmokeOnly));
    }

    [Fact]
    public void Worst_verdict_wins() =>
        Assert.Equal(NpuVerdict.Mismatch, NpuTestModule.Worst([NpuVerdict.Pass, NpuVerdict.Slow, NpuVerdict.Mismatch]));

    [Fact]
    public void Max_error_handles_nan_and_length() 
    {
        Assert.True(double.IsNaN(NpuTestModule.MaxError([float.NaN], [0])));
        Assert.True(double.IsPositiveInfinity(NpuTestModule.MaxError([0, 0], [0])));
    }

    // ---- caps, watchdog, cancel ----

    [Fact]
    public void Duration_is_capped()
    {
        Assert.Equal(NpuTestModule.MaxDuration, NpuTestModule.ClampDuration(TimeSpan.FromHours(1)));
        Assert.Equal(NpuTestModule.DefaultDuration, NpuTestModule.ClampDuration(TimeSpan.Zero));
        Assert.Equal(TimeSpan.FromSeconds(60), NpuTestModule.MaxDuration);
        Assert.Equal(TimeSpan.FromSeconds(10), NpuTestModule.DefaultDuration);
        Assert.True(NpuTestModule.MatrixSize <= NpuTestModule.MaxMatrixSize);
    }

    [Fact]
    public async Task Hung_driver_is_abandoned_by_the_watchdog()
    {
        var hang = new TaskCompletionSource<NpuWorkloadResult>(); // never completes, ignores cancellation
        var io = new FakeIo((_, _) => hang.Task, Dev());
        var (a, b) = NpuTestModule.Inputs(16);
        var reference = NpuTestModule.CpuMatMul(a, b, 16);
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var rep = await NpuTestModule.TestDeviceAsync(io, Dev(), a, b, reference, 1, TimeSpan.FromMilliseconds(50), TimeSpan.FromMilliseconds(100), CancellationToken.None);
        Assert.Equal(NpuVerdict.TimedOut, rep.Verdict);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5));
        Assert.Equal(DiagnosticStatus.Error, NpuTestModule.StatusOf(rep.Verdict));
    }

    [Fact]
    public async Task Cancel_stops_a_hung_run_and_marks_it_cancelled()
    {
        var started = new TaskCompletionSource();
        var io = new FakeIo((_, _) => { started.TrySetResult(); return new TaskCompletionSource<NpuWorkloadResult>().Task; }, Dev());
        var m = new NpuTestModule(io);
        var run = m.RefreshAsync(null);
        await started.Task.WaitAsync(TimeSpan.FromSeconds(10));
        m.Cancel();
        var r = await run.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(r.Cancelled);
    }

    [Fact]
    public void Cpu_matmul_is_correct_on_a_tiny_case()
    {
        float[] a = [1, 2, 3, 4], b = [5, 6, 7, 8];
        Assert.Equal([19, 22, 43, 50], NpuTestModule.CpuMatMul(a, b, 2));
    }

    [Fact]
    public void Npu_test_is_a_separate_step() =>
        Assert.True(ChecksScreenState.IsSeparateStep(new NpuTestModule(new NullNpuIo())));

    [Fact]
    public async Task Each_npu_is_an_instance_and_the_page_report_lists_them_all()
    {
        var second = Dev() with { Id = "npu2", Name = "Second NPU", HardwareId = "PCI\\VEN_2" };
        var m = new NpuTestModule(new FakeIo(Correct(), Dev(), second)) { Settings = { Duration = TimeSpan.FromSeconds(1) } };
        var store = new ResultStore();
        var svc = new DiagnosticsService(store, [m]);
        await svc.RedetectAsync();
        Assert.Equal(2, svc.InstancesOf(m).Count);

        var r = await svc.RunAsync(NpuTestModule.ModuleName);
        Assert.Equal(2, store.InstancesOf(NpuTestModule.ModuleName).Count);
        var rep = Assert.IsType<NpuTestReport>(r.Report());
        Assert.Equal(2, rep.Devices.Count);
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
    }

    [Fact]
    public async Task No_npu_means_the_test_does_not_apply()
    {
        var detection = await new NpuTestModule(new FakeIo(Correct())).DetectAsync();
        Assert.False(detection.Applies);
    }
}

public class NpuVisibilityTests
{
    private static readonly NpuDevice Npu = new("id", "Fake NPU", "Intel", "1.0", "OK", 0, NpuSource.Both, null, 1, NpuComputeLevel.CoreCompute);

    private sealed class ListIo(Func<IReadOnlyList<NpuDevice>> list) : INpuIo
    {
        public int ListCalls;
        public IReadOnlyList<NpuDevice> ListDevices() { Interlocked.Increment(ref ListCalls); return list(); }
        public Task<NpuWorkloadResult> RunWorkloadAsync(NpuDevice device, NpuWorkloadRequest request, CancellationToken ct) =>
            Task.FromResult(new NpuWorkloadResult(NpuWorkloadKind.MatMulComputeShader, NpuTestModule.CpuMatMul(request.A, request.B, request.MatrixSize), 1, 0.01, 5, "Fake"));
    }

    private sealed class Other : IDiagnosticModule
    {
        public string Name => "Other";
        public Guid Id => TestIds.For("Other");
        public event EventHandler<DiagnosticResult>? Updated { add { } remove { } }
        public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken c = default) => Task.FromResult(ModuleAvailability.Available);
        public Task<DiagnosticResult> RefreshAsync(IProgress<string>? p, CancellationToken c = default) =>
            Task.FromResult(new DiagnosticResult(Name, DiagnosticStatus.Ok, "ok", DateTimeOffset.Now));
    }

    private static readonly ResultStore Store = new();

    private static async Task<(DiagnosticsService Svc, NpuTestModule M)> Start(INpuIo io)
    {
        var m = new NpuTestModule(io);
        var svc = new DiagnosticsService(Store, [new Other(), m]);
        await m.DetectPresenceAsync().WaitAsync(TimeSpan.FromSeconds(10));
        for (var i = 0; i < 200 && svc.IsDetectingHardware; i++) await Task.Delay(10);
        return (svc, m);
    }

    [Fact]
    public async Task Visible_with_an_npu()
    {
        var (svc, m) = await Start(new ListIo(() => [Npu]));
        Assert.True(m.IsPresent);
        Assert.Contains(svc.Modules, x => x is INpuTestModule);
        Assert.Contains(new ChecksScreenState(svc, Store).StressModules, x => x.Name == NpuTestModule.ModuleName);
        var r = await svc.RunAsync(NpuTestModule.ModuleName);
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
    }

    [Fact]
    public async Task Hidden_without_an_npu_and_cannot_run()
    {
        var (svc, m) = await Start(new ListIo(() => []));
        Assert.False(m.IsPresent);
        Assert.DoesNotContain(svc.Modules, x => x is INpuTestModule);
        Assert.Contains(svc.Modules, x => x.Name == "Other");
        var screen = new ChecksScreenState(svc, Store);
        Assert.DoesNotContain(screen.StressModules, x => x.Name == NpuTestModule.ModuleName);
        Assert.DoesNotContain(screen.ChecksModules, x => x.Name == NpuTestModule.ModuleName);
        await Assert.ThrowsAsync<ArgumentException>(() => svc.RunAsync(NpuTestModule.ModuleName));
    }

    [Fact]
    public async Task Hidden_when_detection_throws()
    {
        var (svc, m) = await Start(new ListIo(() => throw new InvalidOperationException("WMI broke")));
        Assert.False(m.IsPresent);
        Assert.DoesNotContain(svc.Modules, x => x is INpuTestModule);
        Assert.False(svc.IsDetectingHardware);
    }

    [Fact]
    public async Task Detection_runs_once_and_is_cached()
    {
        var io = new ListIo(() => [Npu]);
        var m = new NpuTestModule(io);
        Assert.False(m.IsPresent); // hidden until detected
        Assert.True(await m.DetectPresenceAsync());
        Assert.True(await m.DetectPresenceAsync());
        Assert.Equal(1, io.ListCalls);
    }
}
