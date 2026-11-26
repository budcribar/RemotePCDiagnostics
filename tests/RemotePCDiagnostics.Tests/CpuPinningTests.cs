using System.Buffers.Binary;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Tests;

/// <summary>Pretend pinning: remembers, per thread, which processor the thread was "pinned" to, and counts pins and restores.</summary>
internal sealed class FakePinning(IReadOnlyList<LogicalProcessor> processors, Func<LogicalProcessor, bool>? refuse = null) : ICpuPinning
{
    [ThreadStatic] public static LogicalProcessor? Current;
    public int Pins, Restores;
    public IReadOnlyList<LogicalProcessor> Processors => processors;

    public IDisposable? Pin(LogicalProcessor processor)
    {
        if (refuse?.Invoke(processor) == true) return null;
        Interlocked.Increment(ref Pins);
        Current = processor;
        return new Undo(this);
    }

    private sealed class Undo(FakePinning owner) : IDisposable
    {
        public void Dispose() { Current = null; Interlocked.Increment(ref owner.Restores); }
    }

    /// <summary><paramref name="count"/> logical processors, two per core (SMT), all of efficiency class 1.</summary>
    public static IReadOnlyList<LogicalProcessor> Smt(int count) =>
        Enumerable.Range(0, count).Select(i => new LogicalProcessor(i, 0, (byte)i, i / 2, 1)).ToList();
}

/// <summary>Gives wrong answers on the processors in <paramref name="faulty"/>; signals once every pinned processor has done a few chunks.</summary>
internal sealed class PerCpuWorkload(int processors, params int[] faulty) : ICpuWorkload
{
    private readonly int[] _calls = new int[processors];
    private readonly TaskCompletionSource _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public Task EveryCpuWorked => _ready.Task;

    public ulong Compute(ulong seed, int iterations)
    {
        var v = DeterministicCpuWorkload.Instance.Compute(seed, iterations);
        if (FakePinning.Current is not { } cpu) return v; // the precompute pass runs unpinned
        Interlocked.Increment(ref _calls[cpu.Index]);
        if (_calls.All(c => c >= 3)) _ready.TrySetResult();
        return faulty.Contains(cpu.Index) ? v ^ 1 : v;
    }
}

public class CpuPinningTests
{
    private static CpuStressOptions Opts(int threads) => new()
    {
        Duration = TimeSpan.FromMinutes(1), Threads = threads, ChunkIterations = 500, SampleInterval = TimeSpan.FromSeconds(10), ThrottleRatio = 0, SeedCount = 4,
    };

    private static async Task<CpuStressReport> Run(FakePinning pinning, PerCpuWorkload workload, int threads)
    {
        var clock = new FakeStressClock(async (step, ct) =>
        {
            if (step == 1) await workload.EveryCpuWorked.WaitAsync(TimeSpan.FromSeconds(10), ct);
        });
        return await new CpuStressTest(SequenceSensorProvider.Unavail(), clock, workload, pinning: pinning).RunAsync(Opts(threads));
    }

    [Fact]
    public async Task OneWorkerPerProcessor_IsPinned_AndErrorsNameTheCore()
    {
        var pinning = new FakePinning(FakePinning.Smt(4));
        var r = await Run(pinning, new PerCpuWorkload(4, faulty: 3), threads: 4);

        Assert.Equal(CpuStressOutcome.ComputationErrors, r.Outcome);
        Assert.NotNull(r.Processors);
        Assert.Equal([0, 1, 2, 3], r.Processors!.Select(p => p.Cpu));
        Assert.All(r.Processors, p => Assert.True(p.Chunks >= 3));
        Assert.Equal(r.Errors, r.Processors.Single(p => p.Cpu == 3).Errors);
        Assert.All(r.Processors.Where(p => p.Cpu != 3), p => Assert.Equal(0, p.Errors));
        Assert.Equal("All of them came from CPU 3 (core 1), which points to that core.", r.FaultyNote);
        Assert.Contains("CPU 3 (core 1)", r.Explanation);
        Assert.Equal(4, pinning.Pins);
        Assert.Equal(pinning.Pins, pinning.Restores); // scheduler threads are reused, so the old affinity must come back
    }

    [Fact]
    public async Task ErrorsOnManyCores_PointToHeatOrPower()
    {
        var r = await Run(new FakePinning(FakePinning.Smt(8)), new PerCpuWorkload(8, 0, 2, 4, 6), threads: 8);
        Assert.Equal("They came from 4 different cores, which points to heat, power or overclocking rather than one bad core.", r.FaultyNote);
    }

    [Fact]
    public async Task FewerThreadsThanProcessors_IsNotPinned()
    {
        var pinning = new FakePinning(FakePinning.Smt(4));
        var clock = new FakeStressClock();
        var r = await new CpuStressTest(SequenceSensorProvider.Unavail(), clock, pinning: pinning).RunAsync(Opts(2));
        Assert.Equal(0, pinning.Pins);
        Assert.Null(r.Processors);
        Assert.Null(r.FaultyNote);
    }

    [Fact]
    public async Task RefusedPin_LeavesThatProcessorOutOfTheResults()
    {
        var pinning = new FakePinning(FakePinning.Smt(2), refuse: p => p.Index == 1);
        var r = await new CpuStressTest(SequenceSensorProvider.Unavail(), new FakeStressClock(), pinning: pinning).RunAsync(Opts(2));
        Assert.Equal(CpuStressOutcome.Passed, r.Outcome);
        Assert.Equal([0], r.Processors!.Select(p => p.Cpu));
    }

    [Fact]
    public void ErrorsOnAnEfficiencyCore_SayWhichKind()
    {
        var cpus = new[] { 0L, 0, 0, 2 }.Select((e, i) => new CpuProcessorResult(i, i, i < 2 ? (byte)1 : (byte)0, 100, e)).ToList();
        var r = new CpuStressReport(CpuStressOutcome.ComputationErrors, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1), 4, 400, 2, null, null, null, false, cpus);
        Assert.Equal("All of them came from CPU 3 (core 3, an efficiency core), which points to that core.", r.FaultyNote);
    }

    [Fact]
    public void ParseProcessorCores_ReadsSmtAndHybridLayout()
    {
        // Core 0: performance (class 1) with SMT, LPs 0 and 1. Core 1: efficiency (class 0), LP 2. Core 2: efficiency, group 1 LP 0.
        var buffer = Record(1, 0, 0b11).Concat(Record(0, 0, 0b100)).Concat(Record(0, 1, 0b1)).ToArray();
        var lps = WindowsCpuPinning.ParseProcessorCores(buffer);
        Assert.Equal(
            [new(0, 0, 0, 0, 1), new(1, 0, 1, 0, 1), new(2, 0, 2, 1, 0), new LogicalProcessor(3, 1, 0, 2, 0)],
            lps);
    }

    [Fact]
    public void ParseProcessorCores_StopsAtATruncatedRecord()
    {
        var buffer = Record(1, 0, 0b1).Concat(Record(1, 0, 0b10)[..20]).ToArray();
        Assert.Single(WindowsCpuPinning.ParseProcessorCores(buffer));
    }

    [Fact]
    public void ThreadQos_IsANoOpOffWindows()
    {
        if (OperatingSystem.IsWindows()) Assert.True(StressThreadQos.DisableForCurrentThread());
        else Assert.False(StressThreadQos.DisableForCurrentThread());
    }

    /// <summary>One SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX RelationProcessorCore record with a single GROUP_AFFINITY.</summary>
    private static byte[] Record(byte efficiencyClass, ushort group, ulong mask)
    {
        var b = new byte[48];
        BinaryPrimitives.WriteUInt32LittleEndian(b, 0);            // RelationProcessorCore
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(4), 48); // Size
        b[8] = System.Numerics.BitOperations.PopCount(mask) > 1 ? (byte)1 : (byte)0; // LTP_PC_SMT
        b[9] = efficiencyClass;
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(30), 1); // GroupCount
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(32), mask);
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(40), group);
        return b;
    }
}
