using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Tests;

/// <summary>A GPU that computes the reference kernel on the CPU, with scripted faults. CI has no GPU.</summary>
internal sealed class FakeGpuDevice(GpuAdapterInfo? adapter = null, int threads = 1024) : IGpuComputeDevice
{
    public GpuAdapterInfo Adapter { get; } = adapter ?? new GpuAdapterInfo("AMD Radeon(TM) Graphics", GpuAdapterKind.Hardware, 512L << 20, 0x1002);
    public int ThreadCount => threads;
    public TimeSpan Took { get; set; } = TimeSpan.FromMilliseconds(150);
    public int? CorruptAtBatch, LoseAtBatch, ThrowAtBatch;
    public int Batches; public bool Disposed; public readonly List<uint> Iterations = [];

    public GpuBatchResult RunBatch(uint seed, uint iterations)
    {
        Batches++; Iterations.Add(iterations);
        if (Batches == LoseAtBatch) throw new GpuDeviceLostException("device removed 0x887A0006");
        if (Batches == ThrowAtBatch) throw new InvalidOperationException("boom");
        var o = new uint[threads];
        for (uint i = 0; i < threads; i++) o[i] = GpuStressKernel.Reference(seed, i, iterations);
        if (Batches >= CorruptAtBatch) for (int i = 0; i < threads; i += 7) o[i] ^= 0x10;
        return new GpuBatchResult(o, Took);
    }

    public void Dispose() => Disposed = true;
}

internal sealed class FakeGpuFactory(GpuOpenResult result) : IGpuDeviceFactory
{
    public int Opens;
    public GpuOpenResult Open() { Opens++; return result; }
    public static FakeGpuFactory With(FakeGpuDevice d) => new(GpuOpenResult.Ok(d));
}

public class GpuStressTests
{
    private static GpuStressOptions Opts(int minutes = 1) => new() { Duration = TimeSpan.FromMinutes(minutes), Gap = TimeSpan.FromSeconds(1), SensorInterval = TimeSpan.Zero };
    private static GpuStressTest Make(IGpuDeviceFactory f, ISensorProvider? s = null) => new(f, s ?? SequenceSensorProvider.Unavail(), new FakeStressClock());

    private static SensorSnapshot GpuSnap(double? gpuTemp, double cpuTemp = 60, double? gpuFan = null) => new(
    [
        new("AMD Ryzen 7 5700U", HardwareKind.Cpu, "Core (Tctl/Tdie)", SensorKind.Temperature, cpuTemp, cpuTemp, cpuTemp, "°C"),
        new("AMD Radeon(TM) Graphics", HardwareKind.Gpu, "GPU Hot Spot", SensorKind.Temperature, gpuTemp, gpuTemp, gpuTemp, "°C"),
        new("AMD Radeon(TM) Graphics", HardwareKind.Gpu, "GPU Fan", SensorKind.Fan, gpuFan, gpuFan, gpuFan, "RPM"),
    ], IsElevated: true);

    [Fact]
    public void Kernel_ReferenceIsDeterministicAndSeedSensitive()
    {
        Assert.Equal(GpuStressKernel.Reference(7, 3, 100), GpuStressKernel.Reference(7, 3, 100));
        Assert.NotEqual(GpuStressKernel.Reference(7, 3, 100), GpuStressKernel.Reference(8, 3, 100));
        Assert.NotEqual(GpuStressKernel.Reference(7, 3, 100), GpuStressKernel.Reference(7, 4, 100));
        Assert.NotEqual(GpuStressKernel.Reference(7, 3, 100), GpuStressKernel.Reference(7, 3, 101));
        Assert.Contains("[numthreads(256, 1, 1)]", GpuStressKernel.Hlsl);
        Assert.Equal(256, GpuStressKernel.GroupSize);
    }

    [Fact]
    public async Task HealthyGpu_Passes_WithLiveProgress()
    {
        var dev = new FakeGpuDevice();
        var progress = new List<GpuStressProgress>();
        var r = await Make(FakeGpuFactory.With(dev)).RunAsync(Opts(), new SyncProgress<GpuStressProgress>(progress.Add));
        Assert.Equal(GpuStressOutcome.Passed, r.Outcome);
        Assert.Equal("Passed", r.Headline);
        Assert.Equal(0, r.Mismatches);
        Assert.True(r.Batches >= 50);
        Assert.Equal(r.Batches * 512, r.ValuesChecked);
        Assert.Equal("AMD Radeon(TM) Graphics", r.AdapterName);
        Assert.NotEmpty(progress);
        Assert.True(progress[^1].Fraction > 0.9);
        Assert.True(dev.Disposed);
        Assert.Equal(DiagnosticStatus.Ok, GpuStressModule.ToStatus(r.Outcome));
    }

    [Fact]
    public async Task WrongAnswers_AreGpuErrors()
    {
        var dev = new FakeGpuDevice { CorruptAtBatch = 3 };
        var r = await Make(FakeGpuFactory.With(dev)).RunAsync(Opts());
        Assert.Equal(GpuStressOutcome.ErrorsFound, r.Outcome);
        Assert.True(r.Mismatches > 0);
        Assert.Equal(DiagnosticStatus.Error, GpuStressModule.ToStatus(r.Outcome));
        Assert.DoesNotContain("0x", r.Explanation);
    }

    [Fact]
    public async Task DeviceLost_IsDriverReset_WithPlainMessage()
    {
        var dev = new FakeGpuDevice { LoseAtBatch = 4 };
        var logs = new List<string>();
        var r = await new GpuStressTest(FakeGpuFactory.With(dev), SequenceSensorProvider.Unavail(), new FakeStressClock(), logs.Add).RunAsync(Opts());
        Assert.Equal(GpuStressOutcome.DriverReset, r.Outcome);
        Assert.Equal("Graphics driver stopped responding", r.Headline);
        Assert.DoesNotContain("0x", r.Explanation);
        Assert.Contains(logs, l => l.Contains("0x887A0006"));
        Assert.True(dev.Disposed);
        Assert.Equal(DiagnosticStatus.Error, GpuStressModule.ToStatus(r.Outcome));
    }

    [Fact]
    public async Task UnexpectedError_IsFailed()
    {
        var r = await Make(FakeGpuFactory.With(new FakeGpuDevice { ThrowAtBatch = 2 })).RunAsync(Opts());
        Assert.Equal(GpuStressOutcome.Failed, r.Outcome);
        Assert.DoesNotContain("boom", r.Explanation);
    }

    [Theory]
    [InlineData(GpuOpenStatus.NoGpu, GpuStressOutcome.NoGpu)]
    [InlineData(GpuOpenStatus.SoftwareOnly, GpuStressOutcome.SoftwareOnly)]
    [InlineData(GpuOpenStatus.Failed, GpuStressOutcome.Failed)]
    public async Task NoUsableGpu_IsNeverAPass(GpuOpenStatus status, GpuStressOutcome expected)
    {
        var r = await Make(new FakeGpuFactory(new GpuOpenResult(status, Detail: "E_FAIL"))).RunAsync(Opts());
        Assert.Equal(expected, r.Outcome);
        Assert.Equal(0, r.Batches);
        Assert.NotEqual(DiagnosticStatus.Ok, GpuStressModule.ToStatus(r.Outcome));
        Assert.DoesNotContain("E_FAIL", r.Explanation);
    }

    [Fact]
    public async Task FactoryThrows_IsFailed()
    {
        var r = await Make(new ThrowingFactory()).RunAsync(Opts());
        Assert.Equal(GpuStressOutcome.Failed, r.Outcome);
    }

    private sealed class ThrowingFactory : IGpuDeviceFactory { public GpuOpenResult Open() => throw new DllNotFoundException("d3d11.dll"); }

    [Theory]
    [InlineData(GpuAdapterKind.Software, 0x1002u)]
    [InlineData(GpuAdapterKind.Hardware, GpuAdapterInfo.MicrosoftVendorId)]
    public async Task WarpDevice_IsRefused_NeverPasses(GpuAdapterKind kind, uint vendor)
    {
        var dev = new FakeGpuDevice(new GpuAdapterInfo("Microsoft Basic Render Driver", kind, 0, vendor));
        var r = await Make(FakeGpuFactory.With(dev)).RunAsync(Opts());
        Assert.Equal(GpuStressOutcome.SoftwareOnly, r.Outcome);
        Assert.Equal(0, dev.Batches);
        Assert.Equal(DiagnosticStatus.Warning, GpuStressModule.ToStatus(r.Outcome));
        Assert.Contains("basic display driver", r.Explanation);
    }

    [Fact]
    public async Task CriticalTemperature_Aborts()
    {
        var sensors = new SequenceSensorProvider(n => GpuSnap(n >= 5 ? 110 : 70));
        var r = await Make(FakeGpuFactory.With(new FakeGpuDevice()), sensors).RunAsync(Opts());
        Assert.Equal(GpuStressOutcome.Overheated, r.Outcome);
        Assert.Equal("Stopped: PC got too hot", r.Headline);
        Assert.InRange(r.Batches, 3, 5);
    }

    [Fact]
    public async Task CriticalCpuTemperature_AlsoAborts()
    {
        var sensors = new SequenceSensorProvider(n => GpuSnap(null, cpuTemp: n >= 3 ? 110 : 60));
        var r = await Make(FakeGpuFactory.With(new FakeGpuDevice()), sensors).RunAsync(Opts());
        Assert.Equal(GpuStressOutcome.Overheated, r.Outcome);
    }

    [Fact]
    public async Task MissingOrZeroGpuTemp_IsNoData_AndGpuFanPreferred()
    {
        var progress = new List<GpuStressProgress>();
        var sensors = new SequenceSensorProvider(n => GpuSnap(n % 2 == 0 ? 0 : null, gpuFan: 1800));
        var r = await Make(FakeGpuFactory.With(new FakeGpuDevice()), sensors).RunAsync(Opts(), new SyncProgress<GpuStressProgress>(progress.Add));
        Assert.Equal(GpuStressOutcome.Passed, r.Outcome);
        Assert.Null(r.MaxGpuTemperatureC);
        Assert.All(progress, p => Assert.Null(p.GpuTemperatureC));
        Assert.All(progress, p => Assert.Equal(1800, p.FanRpm));
        Assert.All(progress, p => Assert.True(p.SensorsAvailable));
    }

    [Fact]
    public async Task GpuTemp_IsReported()
    {
        var r = await Make(FakeGpuFactory.With(new FakeGpuDevice()), new SequenceSensorProvider(n => GpuSnap(60 + n % 10))).RunAsync(Opts());
        Assert.Equal(GpuStressOutcome.Passed, r.Outcome);
        Assert.Equal(69, r.MaxGpuTemperatureC);
    }

    [Fact]
    public async Task StopToken_Stops()
    {
        using var cts = new CancellationTokenSource();
        int n = 0;
        var r = await Make(FakeGpuFactory.With(new FakeGpuDevice())).RunAsync(Opts(10), new SyncProgress<GpuStressProgress>(_ => { if (++n == 3) cts.Cancel(); }), cts.Token);
        Assert.Equal(GpuStressOutcome.StoppedByUser, r.Outcome);
        Assert.Equal("Stopped by you", r.Headline);
        Assert.InRange(r.Batches, 3, 4);
    }

    [Fact]
    public void NextIterations_StaysFarBelowTdr()
    {
        var o = new GpuStressOptions();
        Assert.Equal(128u, GpuStressTest.NextIterations(64, TimeSpan.FromMilliseconds(10), o));    // fast: at most double
        Assert.Equal(64u, GpuStressTest.NextIterations(64, TimeSpan.FromMilliseconds(150), o));    // on target: keep
        Assert.Equal(48u, GpuStressTest.NextIterations(64, TimeSpan.FromMilliseconds(200), o));    // a bit slow: scale down
        Assert.Equal(32u, GpuStressTest.NextIterations(64, TimeSpan.FromMilliseconds(1500), o));   // slow: halve now
        Assert.Equal(1u, GpuStressTest.NextIterations(1, TimeSpan.FromSeconds(1), o));
        Assert.Equal(o.MaxIterations, GpuStressTest.NextIterations(o.MaxIterations, TimeSpan.FromMilliseconds(1), o));
        Assert.True(o.TargetDispatch < TimeSpan.FromSeconds(2) / 4);
    }

    [Fact]
    public async Task AdaptiveDispatch_GrowsOnFastGpu_ShrinksOnSlowGpu()
    {
        var fast = new FakeGpuDevice(threads: 256) { Took = TimeSpan.FromMilliseconds(20) };
        await Make(FakeGpuFactory.With(fast)).RunAsync(Opts() with { Duration = TimeSpan.FromSeconds(6), MaxIterations = 1024 });
        Assert.Equal([64u, 128u, 256u, 512u, 1024u, 1024u], fast.Iterations);
        var slow = new FakeGpuDevice(threads: 256) { Took = TimeSpan.FromMilliseconds(900) };
        await Make(FakeGpuFactory.With(slow)).RunAsync(Opts() with { Duration = TimeSpan.FromSeconds(4) });
        Assert.Equal([64u, 32u, 16u, 8u], slow.Iterations);
    }

    [Fact]
    public void Verify_RotatesThroughBuffer_AndFlagsShortReadback()
    {
        var o = new uint[64];
        for (uint i = 0; i < 64; i++) o[i] = GpuStressKernel.Reference(1, i, 10);
        int off = 0;
        Assert.Equal((16, 0), GpuStressTest.Verify(o, 1, 10, 64, 16, ref off));
        Assert.Equal(1, off);
        o[1] ^= 1;
        Assert.Equal((16, 1), GpuStressTest.Verify(o, 1, 10, 64, 16, ref off));
        Assert.Equal(0, GpuStressTest.Verify(new uint[10], 1, 10, 64, 16, ref off).Checked);
        Assert.True(GpuStressTest.Verify(new uint[10], 1, 10, 64, 16, ref off).Mismatches > 0);
    }

    [Fact]
    public async Task Module_IsExcludedFromRunAll_AndNeverStartsByItself()
    {
        var store = new ResultStore();
        var f = FakeGpuFactory.With(new FakeGpuDevice());
        var gpu = new GpuStressModule(f, SequenceSensorProvider.Unavail(), clockFactory: () => new FakeStressClock()) { Options = Opts() };
        var svc = new DiagnosticsService(store, [gpu, new FakeModule("Other", _ => Task.FromResult(FakeModule.Ok("Other")))]);
        var results = await svc.RunAllAsync();
        Assert.Single(results);
        Assert.Equal(DiagnosticStatus.NotRun, store.Get(GpuStressModule.ModuleName).Status);
        Assert.False(gpu.IncludeInRunAll);
        Assert.Equal(0, f.Opens);
    }

    [Fact]
    public async Task Module_StopButton_StopsRun()
    {
        var store = new ResultStore();
        var gpu = new GpuStressModule(FakeGpuFactory.With(new FakeGpuDevice()), SequenceSensorProvider.Unavail(), clockFactory: () => new FakeStressClock())
            { Options = Opts(), Duration = TimeSpan.FromMinutes(10) };
        gpu.ProgressChanged += (_, p) => { if (p.Elapsed >= TimeSpan.FromSeconds(5)) gpu.Stop(); };
        var r = await new DiagnosticsService(store, [gpu]).RunAsync(GpuStressModule.ModuleName);
        Assert.Equal(DiagnosticStatus.Warning, r.Status);
        Assert.Equal("Stopped by you", store.Get(GpuStressModule.ModuleName).Message);
        Assert.IsType<GpuStressReport>(r.Payload);
        Assert.NotNull(gpu.LastProgress);
    }

    [Fact]
    public void Messages_AreEndUserFriendly()
    {
        foreach (var o in Enum.GetValues<GpuStressOutcome>())
        {
            var r = new GpuStressReport(o, TimeSpan.Zero, null, 0, 0, 0, null, null);
            foreach (var text in new[] { r.Headline, r.Explanation })
            {
                Assert.False(string.IsNullOrWhiteSpace(text));
                foreach (var bad in new[] { "0x", "HRESULT", "WARP", "D3D", "DXGI", "TDR", "exit code", "\\", "Exception" }) Assert.DoesNotContain(bad, text);
            }
        }
    }
}
