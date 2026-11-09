using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Core.Stress;

/// <summary>
/// CPU stress test: one worker per logical core runs <see cref="ICpuWorkload"/> chunks and verifies each checksum
/// against a value precomputed before load. A sampler watches time, stop requests and CPU temperature
/// (<see cref="ISensorProvider"/>, aborting at <see cref="SensorLevel.Critical"/>) and records throughput to detect slowing.
/// </summary>
public sealed class CpuStressTest(ISensorProvider sensors, IStressClock? clock = null, ICpuWorkload? workload = null, ILogger? log = null, StressCleanup? cleanup = null)
{
    private readonly ICpuWorkload _workload = workload ?? DeterministicCpuWorkload.Instance;

    public static ulong SeedFor(int index) => 0x9E3779B97F4A7C15UL * (ulong)(index + 1);

    public async Task<CpuStressReport> RunAsync(CpuStressOptions options, IProgress<CpuStressProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        var clk = clock ?? new StopwatchStressClock();
        int threads = Math.Max(1, options.Threads), seeds = Math.Max(1, options.SeedCount);
        var duration = options.Duration <= TimeSpan.Zero ? TimeSpan.FromMinutes(1) : options.Duration > CpuStressOptions.MaxDuration ? CpuStressOptions.MaxDuration : options.Duration;
        log.Info($"CPU stress: start threads={threads} duration={duration} chunk={options.ChunkIterations}");

        var expected = new ulong[seeds];
        for (int i = 0; i < seeds; i++) expected[i] = _workload.Compute(SeedFor(i), options.ChunkIterations);

        var sensorsOk = SafeAvailability();
        long chunks = 0, errors = 0;
        int stop = 0;
        var start = clk.Elapsed;
        using var cancelReg = cancellationToken.Register(() => Volatile.Write(ref stop, 1));

        var workers = StressTaskScheduler.RunParallel(threads, t =>
        {
            int n = t;
            while (Volatile.Read(ref stop) == 0)
            {
                int s = n++ % seeds;
                var got = _workload.Compute(SeedFor(s), options.ChunkIterations);
                if (got != expected[s])
                {
                    var e = Interlocked.Increment(ref errors);
                    if (e <= 10) log.Warn($"CPU stress: checksum mismatch thread={t} seed#{s} expected={expected[s]:X16} got={got:X16}");
                }
                Interlocked.Increment(ref chunks);
            }
        });

        cleanup?.Register("CPU workers", () => Volatile.Write(ref stop, 1));

        var outcome = CpuStressOutcome.Passed;
        var samples = new List<double>();
        double? maxTemp = null;
        long lastChunks = 0; var lastT = start;
        try
        {
            while (true)
            {
                var (temp, fan, crit, level) = sensorsOk ? ReadCpu() : (null, null, null, SensorLevel.Neutral);
                if (temp is { } tv) maxTemp = Math.Max(maxTemp ?? tv, tv);
                var now = clk.Elapsed;
                var c = Interlocked.Read(ref chunks);
                var dt = (now - lastT).TotalSeconds;
                if (dt > 0 && now > start) samples.Add((c - lastChunks) / dt);
                lastChunks = c; lastT = now;
                progress?.Report(new CpuStressProgress(now - start, duration, c, Interlocked.Read(ref errors), temp, fan, crit, sensorsOk));

                if (level == SensorLevel.Critical) { outcome = CpuStressOutcome.Overheated; log.Warn($"CPU stress: abort, CPU temperature {temp:0.0}°C reached critical {crit:0}°C"); break; }
                if (cancellationToken.IsCancellationRequested) { outcome = CpuStressOutcome.StoppedByUser; break; }
                if (now - start >= duration) break;
                var wait = options.SampleInterval < duration - (now - start) ? options.SampleInterval : duration - (now - start);
                try { await clk.DelayAsync(wait, cancellationToken).ConfigureAwait(false); }
                catch (OperationCanceledException) { outcome = CpuStressOutcome.StoppedByUser; break; }
            }
        }
        finally
        {
            Volatile.Write(ref stop, 1);
            await workers.ConfigureAwait(false);
        }

        var ran = clk.Elapsed - start;
        var (early, late) = SplitThroughput(samples);
        var errs = Interlocked.Read(ref errors);
        if (errs > 0) outcome = CpuStressOutcome.ComputationErrors;
        else if (outcome == CpuStressOutcome.Passed && IsThrottled(early, late, options.ThrottleRatio)) outcome = CpuStressOutcome.Throttled;

        var report = new CpuStressReport(outcome, ran, duration, threads, Interlocked.Read(ref chunks), errs, maxTemp, early, late, sensorsOk);
        log.Info($"CPU stress: done outcome={outcome} ran={ran} chunks={report.ChunksDone} errors={errs} maxTemp={maxTemp} early={early:0.0}/s late={late:0.0}/s samples={samples.Count}");
        return report;
    }

    /// <summary>Mean throughput of the first and last third of samples (first sample skipped as warm-up when there are enough). Null when fewer than 3 samples.</summary>
    public static (double? Early, double? Late) SplitThroughput(IReadOnlyList<double> samples)
    {
        var s = samples.Count >= 6 ? samples.Skip(1).ToList() : samples.ToList();
        if (s.Count < 3) return (null, null);
        int third = Math.Max(1, s.Count / 3);
        return (s.Take(third).Average(), s.Skip(s.Count - third).Average());
    }

    public static bool IsThrottled(double? early, double? late, double ratio) =>
        early is > 0 && late is { } l && l < early.Value * ratio;

    private bool SafeAvailability()
    {
        try { var a = sensors.CheckAvailability(); if (!a.IsAvailable) log.Info($"CPU stress: sensors unavailable: {a.Reason}"); return a.IsAvailable; }
        catch (Exception ex) { log.Error($"CPU stress: sensor availability failed: {ex}"); return false; }
    }

    /// <summary>Hottest CPU temperature, fastest fan, its critical limit and the worst CPU temperature level.</summary>
    private (double? Temp, double? Fan, double? Critical, SensorLevel Level) ReadCpu()
    {
        try
        {
            var snap = sensors.Read();
            var cpu = snap.Readings.Where(r => r.SensorType == SensorKind.Temperature && r.HardwareType == HardwareKind.Cpu && r.IsLive).ToList();
            var hottest = cpu.OrderByDescending(r => r.Value).FirstOrDefault();
            var fan = snap.Readings.Where(r => r.SensorType == SensorKind.Fan && r.HasData).Select(r => r.Value).DefaultIfEmpty().Max();
            var level = cpu.Count == 0 ? SensorLevel.Neutral : cpu.Max(SensorThresholds.Evaluate);
            return (hottest?.Value, fan, hottest is null ? null : SensorThresholds.For(hottest)?.Critical, level);
        }
        catch (Exception ex)
        {
            log.Warn($"CPU stress: sensor read failed: {ex.Message}");
            return (null, null, null, SensorLevel.Neutral);
        }
    }
}
