using System.Diagnostics;

namespace RemotePCDiagnostics.Core.Stress;

/// <summary>Time source for stress tests (injectable so tests can drive time).</summary>
public interface IStressClock
{
    TimeSpan Elapsed { get; }
    /// <summary>Waits for <paramref name="delay"/> of this clock's time.</summary>
    Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken);
}

/// <summary>Real time, starting at construction.</summary>
public sealed class StopwatchStressClock : IStressClock
{
    private readonly Stopwatch _sw = Stopwatch.StartNew();
    public TimeSpan Elapsed => _sw.Elapsed;
    public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) => Task.Delay(delay, cancellationToken);
}

/// <summary>Deterministic compute kernel. Same seed + iterations must always give the same checksum on healthy hardware.</summary>
public interface ICpuWorkload
{
    ulong Compute(ulong seed, int iterations);
}

/// <summary>Integer (xorshift/multiply/rotate) and IEEE-754 floating point (sqrt, multiply-add: exactly rounded, so deterministic) mix.</summary>
public sealed class DeterministicCpuWorkload : ICpuWorkload
{
    public static readonly DeterministicCpuWorkload Instance = new();

    public ulong Compute(ulong seed, int iterations)
    {
        ulong x = seed | 1UL, acc = 0xCBF29CE484222325UL;
        double d = (seed % 1000) + 1.5;
        for (int i = 0; i < iterations; i++)
        {
            x ^= x << 13; x ^= x >> 7; x ^= x << 17;
            acc = ulong.RotateLeft(acc ^ x, 5) * 0x100000001B3UL;
            d = Math.Sqrt(d * 1.0000001 + (x & 0xFFFF)) + 1.0;
            if ((i & 63) == 0) acc ^= (ulong)BitConverter.DoubleToInt64Bits(d);
        }
        return acc ^ (ulong)BitConverter.DoubleToInt64Bits(d);
    }
}
