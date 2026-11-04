using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Core.Stress;

/// <summary>
/// GPU stress test: repeatedly dispatches a deterministic integer compute kernel on the GPU for the time limit,
/// verifies a rotating sample of every dispatch's output against the CPU reference (any mismatch = GPU error),
/// keeps each dispatch short (adaptive, ~150 ms, far below the 2 s TDR limit), and stops on Stop, a driver reset,
/// or a critical temperature. A software adapter (WARP) is never tested or reported as a pass.
/// </summary>
public sealed class GpuStressTest(IGpuDeviceFactory factory, ISensorProvider sensors, IStressClock? clock = null, Action<string>? log = null, StressCleanup? cleanup = null)
{
    public Task<GpuStressReport> RunAsync(GpuStressOptions o, IProgress<GpuStressProgress>? progress = null, CancellationToken cancellationToken = default) =>
        Task.Run(() => RunCoreAsync(o, progress, cancellationToken), CancellationToken.None);

    private async Task<GpuStressReport> RunCoreAsync(GpuStressOptions o, IProgress<GpuStressProgress>? progress, CancellationToken ct)
    {
        var scope = cleanup ?? new StressCleanup(log);
        try { return await RunInnerAsync(o, progress, ct, scope).ConfigureAwait(false); }
        finally { await scope.RunAsync().ConfigureAwait(false); }
    }

    private async Task<GpuStressReport> RunInnerAsync(GpuStressOptions o, IProgress<GpuStressProgress>? progress, CancellationToken ct, StressCleanup scope)
    {
        var clk = clock ?? new StopwatchStressClock();
        var start = clk.Elapsed;
        var duration = o.Duration <= TimeSpan.Zero ? TimeSpan.FromMinutes(1) : o.Duration > GpuStressOptions.MaxDuration ? GpuStressOptions.MaxDuration : o.Duration;
        long batches = 0, checkedValues = 0, mismatches = 0;
        double? temp = null, fan = null, maxT = null, rate = null;
        bool stopped = false, hot = false;
        GpuStressOutcome? fatal = null;
        string? adapterName = null;

        GpuOpenResult open;
        try { open = factory.Open(); }
        catch (Exception ex) { log?.Invoke($"GPU stress: open failed: {ex}"); open = new GpuOpenResult(GpuOpenStatus.Failed, Detail: ex.Message); }

        if (open.Status != GpuOpenStatus.Opened || open.Device is null)
        {
            log?.Invoke($"GPU stress: no device status={open.Status} detail={open.Detail}");
            var outcome = open.Status switch { GpuOpenStatus.NoGpu => GpuStressOutcome.NoGpu, GpuOpenStatus.SoftwareOnly => GpuStressOutcome.SoftwareOnly, _ => GpuStressOutcome.Failed };
            return new GpuStressReport(outcome, TimeSpan.Zero, null, 0, 0, 0, null, null);
        }

        var device = open.Device;
        int released = 0;
        scope.Register("GPU device", () => { if (Interlocked.Exchange(ref released, 1) == 0) device.Dispose(); });
        adapterName = device.Adapter.Name;
        if (device.Adapter.IsSoftware)
        {
            // Defense in depth: a factory must never hand back WARP, but if it does it is not a GPU pass.
            log?.Invoke($"GPU stress: refusing software adapter '{adapterName}' vendor=0x{device.Adapter.VendorId:X4}");
            return new GpuStressReport(GpuStressOutcome.SoftwareOnly, TimeSpan.Zero, adapterName, 0, 0, 0, null, null);
        }

        var sensorsOk = SafeAvailability();
        var nextSensor = TimeSpan.Zero;
        uint iterations = Math.Max(1, o.StartIterations);
        uint seed = 0x12345u;
        int threads = Math.Max(1, device.ThreadCount);
        int sampleOffset = 0;
        log?.Invoke($"GPU stress: start adapter='{adapterName}' vendor=0x{device.Adapter.VendorId:X4} vram={device.Adapter.DedicatedMemoryBytes} threads={threads} duration={duration}");

        try
        {
            while (true)
            {
                var elapsed = clk.Elapsed - start;
                if (ct.IsCancellationRequested) { stopped = true; break; }
                if (elapsed >= duration) break;

                if (sensorsOk && elapsed >= nextSensor)
                {
                    nextSensor = elapsed + o.SensorInterval;
                    var (t, f, critical, what) = ReadSensors();
                    temp = t; fan = f;
                    if (t is { } tv) maxT = Math.Max(maxT ?? tv, tv);
                    if (critical) { hot = true; log?.Invoke($"GPU stress: abort, critical temperature: {what}"); break; }
                }

                seed = unchecked(seed * 1664525u + 1013904223u);
                var result = device.RunBatch(seed, iterations);
                batches++;
                var (n, bad) = Verify(result.Output, seed, iterations, threads, o.ChecksPerBatch, ref sampleOffset);
                checkedValues += n;
                if (bad > 0)
                {
                    mismatches += bad;
                    log?.Invoke($"GPU stress: {bad} mismatches in batch {batches} seed=0x{seed:X8} iterations={iterations}");
                }
                if (result.GpuTime > TimeSpan.Zero) rate = (double)threads * iterations / result.GpuTime.TotalSeconds / 1e9;
                var next = NextIterations(iterations, result.GpuTime, o);
                if (result.GpuTime >= o.SlowDispatch) log?.Invoke($"GPU stress: slow dispatch {result.GpuTime.TotalMilliseconds:0} ms at {iterations} iterations, cutting to {next}");
                iterations = next;

                progress?.Report(new GpuStressProgress(clk.Elapsed - start, duration, adapterName, batches, checkedValues, mismatches, temp, fan, sensorsOk, rate));
                try { await clk.DelayAsync(o.Gap, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { stopped = true; break; }
            }
        }
        catch (GpuDeviceLostException ex)
        {
            fatal = GpuStressOutcome.DriverReset;
            log?.Invoke($"GPU stress: device lost after {batches} batches at {iterations} iterations: {ex.Message} {ex.InnerException}");
        }
        catch (Exception ex)
        {
            fatal = GpuStressOutcome.Failed;
            log?.Invoke($"GPU stress: failed: {ex}");
        }

        var outcome2 = fatal is { } fo ? fo
            : hot ? GpuStressOutcome.Overheated
            : mismatches > 0 ? GpuStressOutcome.ErrorsFound
            : stopped ? GpuStressOutcome.StoppedByUser
            : batches == 0 ? GpuStressOutcome.Failed
            : GpuStressOutcome.Passed;
        var report = new GpuStressReport(outcome2, clk.Elapsed - start, adapterName, batches, checkedValues, mismatches, maxT, rate);
        log?.Invoke($"GPU stress: done outcome={outcome2} batches={batches} checked={checkedValues} mismatches={mismatches} maxTemp={maxT} rate={rate:0.00}G/s");
        return report;
    }

    /// <summary>Checks <paramref name="count"/> values spread over the buffer, starting at a rotating offset so the whole buffer is covered over time.</summary>
    public static (int Checked, int Mismatches) Verify(uint[] output, uint seed, uint iterations, int threads, int count, ref int offset)
    {
        if (output.Length < threads) return (0, Math.Max(1, threads - output.Length)); // short readback is itself a failure
        count = Math.Clamp(count, 1, threads);
        int stride = Math.Max(1, threads / count), bad = 0;
        for (int k = 0; k < count; k++)
        {
            var i = (uint)((offset + k * stride) % threads);
            if (output[i] != GpuStressKernel.Reference(seed, i, iterations)) bad++;
        }
        offset = (offset + 1) % stride;
        return (count, bad);
    }

    /// <summary>Scales work toward the target dispatch time: at most x2 up per step, halves right away when a dispatch is slow.</summary>
    public static uint NextIterations(uint current, TimeSpan took, GpuStressOptions o)
    {
        if (took >= o.SlowDispatch) return Math.Max(1, current / 2);
        double factor = took <= TimeSpan.Zero ? 2 : Math.Clamp(o.TargetDispatch / took, 0.5, 2);
        var next = (uint)Math.Clamp(current * factor, 1, o.MaxIterations);
        return next;
    }

    private bool SafeAvailability()
    {
        try { var a = sensors.CheckAvailability(); if (!a.IsAvailable) log?.Invoke($"GPU stress: sensors unavailable: {a.Reason}"); return a.IsAvailable; }
        catch (Exception ex) { log?.Invoke($"GPU stress: sensor availability failed: {ex.Message}"); return false; }
    }

    /// <summary>GPU temperature (null when not reported: many integrated GPUs don't expose one), GPU fan (else any fan), and any critical temperature.</summary>
    private (double? Temp, double? Fan, bool Critical, string What) ReadSensors()
    {
        try
        {
            var snap = sensors.Read();
            var temps = snap.Readings.Where(r => r.SensorType == SensorKind.Temperature && r.IsLive).ToList();
            var gpuTemps = temps.Where(r => r.HardwareType == HardwareKind.Gpu).ToList();
            double? gpu = gpuTemps.Count == 0 ? null : gpuTemps.Max(r => r.Value);
            var fans = snap.Readings.Where(r => r.SensorType == SensorKind.Fan && r.HasData).ToList();
            var gpuFans = fans.Where(r => r.HardwareType == HardwareKind.Gpu).ToList();
            var useFans = gpuFans.Count > 0 ? gpuFans : fans;
            double? fan = useFans.Count == 0 ? null : useFans.Max(r => r.Value);
            var crit = temps.FirstOrDefault(r => SensorThresholds.Evaluate(r) == SensorLevel.Critical);
            return (gpu, fan, crit is not null, crit is null ? "" : $"{crit.HardwareName} {crit.SensorName} {crit.Value:0.0}°C");
        }
        catch (Exception ex) { log?.Invoke($"GPU stress: sensor read failed: {ex.Message}"); return (null, null, false, ""); }
    }
}
