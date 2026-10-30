using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Tests;

/// <summary>Manual clock: each delay advances time instantly (with a tiny real pause so workers make progress).</summary>
internal sealed class FakeStressClock : IStressClock
{
    private long _ticks;
    public TimeSpan Elapsed => TimeSpan.FromTicks(Interlocked.Read(ref _ticks));
    public int Delays;
    public void Advance(TimeSpan delta) => Interlocked.Add(ref _ticks, delta.Ticks);
    public async Task DelayAsync(TimeSpan delay, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        await Task.Delay(2, ct);
        Interlocked.Add(ref _ticks, delay.Ticks);
        Interlocked.Increment(ref Delays);
    }
}

internal sealed class SequenceSensorProvider(Func<int, SensorSnapshot> read, bool available = true) : ISensorProvider
{
    public int Reads;
    public ModuleAvailability CheckAvailability() => available ? ModuleAvailability.Available : ModuleAvailability.Unavailable("no driver");
    public SensorSnapshot Read() => read(Interlocked.Increment(ref Reads));

    public static SensorSnapshot Cpu(double temp, double fan = 1200) => new(
    [
        new("Intel Core i9-14900K", HardwareKind.Cpu, "CPU Package", SensorKind.Temperature, temp, temp, temp, "°C"),
        new("Nuvoton NCT6798D", HardwareKind.Motherboard, "Fan #1", SensorKind.Fan, fan, fan, fan, "RPM"),
    ], IsElevated: true);
}

/// <summary>Returns a wrong checksum on the Nth call (the precompute pass uses the first SeedCount calls).</summary>
internal sealed class FaultyWorkload(int failOnCall) : ICpuWorkload
{
    private int _calls;
    public ulong Compute(ulong seed, int iterations)
    {
        var v = DeterministicCpuWorkload.Instance.Compute(seed, iterations);
        return Interlocked.Increment(ref _calls) == failOnCall ? v ^ 1 : v;
    }
}

public class CpuStressTests
{
    private static CpuStressOptions Opts(int minutes = 1) => new()
    {
        Duration = TimeSpan.FromMinutes(minutes), Threads = 2, ChunkIterations = 500, SampleInterval = TimeSpan.FromSeconds(10), ThrottleRatio = 0, SeedCount = 4,
    };

    [Fact]
    public void Workload_IsDeterministic_AndMatchesKnownVector()
    {
        var w = DeterministicCpuWorkload.Instance;
        Assert.Equal(0x3F2020C2282551FFUL, w.Compute(1, 1000));
        Assert.Equal(0xA57BAA0144618A75UL, w.Compute(CpuStressTest.SeedFor(0), 1000));
        Assert.Equal(w.Compute(42, 5000), w.Compute(42, 5000));
        Assert.NotEqual(w.Compute(42, 5000), w.Compute(43, 5000));
    }

    [Fact]
    public async Task ParallelChecksums_HealthyWorkload_HasNoErrors()
    {
        var test = new CpuStressTest(SequenceSensorProvider.Unavail(), new FakeStressClock());
        var r = await test.RunAsync(Opts() with { Threads = Environment.ProcessorCount });
        Assert.Equal(0, r.Errors);
        Assert.True(r.ChunksDone > 0);
    }

    [Fact]
    public async Task TimeLimit_EndsRun_AndPasses()
    {
        var clock = new FakeStressClock();
        var sensors = new SequenceSensorProvider(_ => SequenceSensorProvider.Cpu(60));
        var progress = new List<CpuStressProgress>();
        var r = await new CpuStressTest(sensors, clock).RunAsync(Opts(), new SyncProgress<CpuStressProgress>(progress.Add));
        Assert.Equal(CpuStressOutcome.Passed, r.Outcome);
        Assert.Equal("Passed", r.Headline);
        Assert.Equal(TimeSpan.FromMinutes(1), r.Ran);
        Assert.Equal(6, clock.Delays);
        Assert.Equal(1.0, progress[^1].Fraction);
        Assert.Equal(60, progress[^1].CpuTemperatureC);
        Assert.Equal(1200, progress[^1].FanRpm);
        Assert.Equal(60, r.MaxCpuTemperatureC);
    }

    [Fact]
    public async Task Duration_IsClampedToTenMinutes()
    {
        var r = await new CpuStressTest(SequenceSensorProvider.Unavail(), new FakeStressClock()).RunAsync(Opts(60) with { SampleInterval = TimeSpan.FromMinutes(1) });
        Assert.Equal(TimeSpan.FromMinutes(10), r.Requested);
        Assert.Equal(TimeSpan.FromMinutes(10), r.Ran);
    }

    [Fact]
    public async Task StopToken_StopsEarly()
    {
        using var cts = new CancellationTokenSource();
        int n = 0;
        var r = await new CpuStressTest(SequenceSensorProvider.Unavail(), new FakeStressClock())
            .RunAsync(Opts(), new SyncProgress<CpuStressProgress>(_ => { if (++n == 2) cts.Cancel(); }), cts.Token);
        Assert.Equal(CpuStressOutcome.StoppedByUser, r.Outcome);
        Assert.Equal("Stopped by you", r.Headline);
        Assert.True(r.Ran < TimeSpan.FromMinutes(1));
    }

    [Fact]
    public async Task CriticalCpuTemperature_AbortsRun()
    {
        // Intel critical is 98°C (SensorThresholds.IntelCpu); third read is critical.
        var sensors = new SequenceSensorProvider(i => SequenceSensorProvider.Cpu(i >= 3 ? 99 : 70));
        var r = await new CpuStressTest(sensors, new FakeStressClock()).RunAsync(Opts(10));
        Assert.Equal(CpuStressOutcome.Overheated, r.Outcome);
        Assert.Equal("Stopped: CPU got too hot", r.Headline);
        Assert.Equal(99, r.MaxCpuTemperatureC);
        Assert.Equal(TimeSpan.FromSeconds(20), r.Ran);
        Assert.Equal(DiagnosticStatus.Error, CpuStressModule.ToStatus(r.Outcome));
    }

    [Fact]
    public async Task WarningTemperature_DoesNotAbort()
    {
        var r = await new CpuStressTest(new SequenceSensorProvider(_ => SequenceSensorProvider.Cpu(95)), new FakeStressClock()).RunAsync(Opts());
        Assert.Equal(CpuStressOutcome.Passed, r.Outcome);
    }

    [Fact]
    public async Task ChecksumMismatch_ReportsPossibleCpuErrors()
    {
        var r = await new CpuStressTest(SequenceSensorProvider.Unavail(), new FakeStressClock(), new FaultyWorkload(failOnCall: 4 + 3)).RunAsync(Opts());
        Assert.Equal(CpuStressOutcome.ComputationErrors, r.Outcome);
        Assert.Equal(1, r.Errors);
        Assert.Equal("Possible CPU errors found", r.Headline);
        Assert.Equal(DiagnosticStatus.Error, CpuStressModule.ToStatus(r.Outcome));
    }

    [Fact]
    public async Task SensorReadFailure_DoesNotStopTest()
    {
        var r = await new CpuStressTest(new SequenceSensorProvider(_ => throw new InvalidOperationException("driver")), new FakeStressClock()).RunAsync(Opts());
        Assert.Equal(CpuStressOutcome.Passed, r.Outcome);
        Assert.Null(r.MaxCpuTemperatureC);
    }

    [Theory]
    [InlineData(new double[] { 100, 100, 100, 100, 100, 100, 100 }, false)]
    [InlineData(new double[] { 50, 100, 100, 95, 90, 80, 80 }, true)]
    [InlineData(new double[] { 100, 100 }, false)]
    public void Throttling_ComparesEarlyAndLateThroughput(double[] samples, bool throttled)
    {
        var (e, l) = CpuStressTest.SplitThroughput(samples);
        Assert.Equal(throttled, CpuStressTest.IsThrottled(e, l, 0.85));
    }

    [Fact]
    public void ThrottledReport_HasFriendlyWording()
    {
        var r = new CpuStressReport(CpuStressOutcome.Throttled, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1), 8, 10, 0, 90, 100, 70, true);
        Assert.Equal("Slowed down under load", r.Headline);
        Assert.Contains("30% slower", r.Explanation);
        Assert.Equal(DiagnosticStatus.Warning, CpuStressModule.ToStatus(r.Outcome));
    }

    [Fact]
    public async Task Module_IsExcludedFromRunAll_AndNeverStartsByItself()
    {
        var store = new ResultStore();
        var stress = new CpuStressModule(SequenceSensorProvider.Unavail(), clockFactory: () => new FakeStressClock()) { Options = Opts() };
        var svc = new DiagnosticsService(store, [stress, new FakeModule("Other", _ => Task.FromResult(FakeModule.Ok("Other")))]);
        var results = await svc.RunAllAsync();
        Assert.Single(results);
        Assert.Equal("Other", results[0].ModuleName);
        Assert.Equal(DiagnosticStatus.NotRun, store.Get(CpuStressModule.ModuleName).Status);
        Assert.False(stress.IncludeInRunAll);
    }

    [Fact]
    public async Task Module_StopButton_StopsRun()
    {
        var store = new ResultStore();
        var stress = new CpuStressModule(SequenceSensorProvider.Unavail(), clockFactory: () => new FakeStressClock()) { Options = Opts(), Duration = TimeSpan.FromMinutes(10) };
        stress.ProgressChanged += (_, p) => { if (p.Elapsed >= TimeSpan.FromSeconds(20)) stress.Stop(); };
        var svc = new DiagnosticsService(store, [stress]);
        var r = await svc.RunAsync(CpuStressModule.ModuleName);
        Assert.Equal(DiagnosticStatus.Warning, r.Status);
        Assert.Equal("Stopped by you", store.Get(CpuStressModule.ModuleName).Message);
        Assert.IsType<CpuStressReport>(r.Payload);
    }
}

internal sealed class SyncProgress<T>(Action<T> a) : IProgress<T> { public void Report(T value) => a(value); }

internal static class SensorProviderExt
{
    extension(SequenceSensorProvider)
    {
        public static SequenceSensorProvider Unavail() => new(_ => throw new PlatformNotSupportedException(), available: false);
    }
}
