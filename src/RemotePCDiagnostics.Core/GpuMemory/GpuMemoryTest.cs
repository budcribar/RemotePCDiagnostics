using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Core.GpuMemory;

/// <summary>
/// Tests one graphics chip's memory: allocates up to 80 % of its free memory in blocks, then runs passes of patterns over every block
/// (write all blocks, then check all blocks, so the data has to come back from memory and not from the chip's cache) until the time is up.
/// Stops at once on a wrong word's pass end, a driver reset, a dispatch that never comes back (the watchdog), a critical temperature, or
/// Cancel. Everything runs offscreen (no window), so it works in a remote session. The blocks are freed however it ends.
/// </summary>
public sealed class GpuMemoryTest(IGpuMemorySource source, ISensorProvider? sensors = null, IStressClock? clock = null, ILogger? log = null)
{
    private sealed class Run(GpuMemoryOptions o)
    {
        public long Errors;
        public uint Flipped;
        public readonly List<GpuMemoryError> First = [];
        public double? Temp, MaxTemp, StartTemp;
        public bool Hot;
        public string? HotWhat;
        public TimeSpan NextSensor;
        public void Add(GpuBlockResult r, long blockStartByte, GpuMemoryPattern p, int pass)
        {
            if (r.Errors <= 0) return;
            Errors += r.Errors;
            foreach (var e in r.First)
            {
                Flipped |= e.Expected ^ e.Actual;
                if (First.Count < o.MaxRecordedErrors) First.Add(new(blockStartByte + (long)e.Word * 4, e.Expected, e.Actual, p, pass + 1));
            }
        }
    }

    public async Task<GpuMemoryAdapterResult> RunAsync(GpuMemoryAdapter adapter, GpuMemoryOptions o, int index = 0, int count = 1,
        IProgress<GpuMemoryProgress>? progress = null, CancellationToken ct = default)
    {
        var clk = clock ?? new StopwatchStressClock();
        var start = clk.Elapsed;
        var duration = o.EffectiveDuration;
        var memory = GpuMemoryPlan.MemoryBytes(adapter);
        var planned = GpuMemoryPlan.Target(adapter, o.BlockBytes);
        var run = new Run(o);
        int passes = 0;
        long tested = 0;
        int blocks = 0;
        GpuMemoryAdapterResult Result(GpuMemoryOutcome outcome, string? reason = null) =>
            new(adapter, outcome, o.Mode, memory, planned, tested, blocks, passes, run.Errors, [.. run.First], run.Flipped, run.MaxTemp, run.StartTemp,
                clk.Elapsed - start, reason);

        if (planned <= 0)
        {
            var why = $"too little free graphics memory to test ({Mb(adapter.FreeBytes ?? 0)} free of {Mb(memory)})";
            log.Info($"GPU memory: {adapter.Name}: {why}");
            return Result(GpuMemoryOutcome.CouldNotRun, why);
        }

        IGpuMemoryDevice device;
        try { device = source.Open(adapter.Id); }
        catch (Exception ex)
        {
            log.Warn($"GPU memory: {adapter.Name}: open failed: {ex.Message}");
            return Result(GpuMemoryOutcome.CouldNotRun, "the graphics chip couldn't be opened: " + ex.Message);
        }

        var sensorsOk = SafeAvailability();
        Task? hungOp = null;
        try
        {
            ReadSensors(run, sensorsOk, clk.Elapsed - start, o.SensorInterval, force: true);
            run.StartTemp = run.Temp;
            // Allocate the blocks. The chip saying "no more" before the target is fine: the verdict says how much was covered.
            while (tested < planned && !ct.IsCancellationRequested)
            {
                var size = Math.Min(o.BlockBytes, planned - tested);
                bool ok;
                try { ok = device.TryAllocateBlock(size); }
                catch (Exception ex) when (ex is not GpuDeviceLostException) { log.Warn($"GPU memory: {adapter.Name}: allocation failed after {Mb(tested)}: {ex.Message}"); ok = false; }
                if (!ok) break;
                tested += size;
                blocks++;
            }
            log.Info($"GPU memory: {adapter.Name}: mode={o.Mode} memory={memory} free={adapter.FreeBytes} planned={planned} allocated={tested} blocks={blocks} duration={duration}");
            if (ct.IsCancellationRequested) return Result(GpuMemoryOutcome.Cancelled);
            if (blocks == 0)
                return Result(GpuMemoryOutcome.CouldNotRun, $"the graphics chip had no memory to give the test ({Mb(adapter.FreeBytes ?? 0)} free)");

            var sizes = device.Blocks;
            var startByte = new long[sizes.Count];
            for (var b = 1; b < sizes.Count; b++) startByte[b] = startByte[b - 1] + sizes[b - 1];

            async Task<GpuBlockResult> Op(int block, GpuMemoryOp op, GpuMemoryStep step, bool inverted)
            {
                ct.ThrowIfCancellationRequested();
                var baseWord = unchecked((uint)(startByte[block] / 4));
                var task = StressTaskScheduler.Run(() => device.Run(block, op, step.Pattern, step.Seed, inverted, baseWord), CancellationToken.None);
                try { return await task.WaitAsync(o.OpWatchdog, CancellationToken.None).ConfigureAwait(false); }
                catch (TimeoutException) { hungOp = task; throw; }
            }

            void Tick(int pass)
            {
                var now = clk.Elapsed - start;
                ReadSensors(run, sensorsOk, now, o.SensorInterval);
                progress?.Report(new(adapter.Name, index, count, now > duration ? duration : now, duration, pass + 1, tested, run.Errors, run.Temp));
            }

            for (var pass = 0; ; pass++)
            {
                foreach (var step in GpuMemoryStep.ForPass(o.Mode, pass))
                {
                    // Write every block, then check every block.
                    for (var b = 0; b < sizes.Count; b++) { await Op(b, GpuMemoryOp.Write, step, false).ConfigureAwait(false); Tick(pass); if (run.Hot) break; }
                    if (run.Hot) break;
                    if (!step.MovingInversion)
                    {
                        for (var b = 0; b < sizes.Count; b++) { run.Add(await Op(b, GpuMemoryOp.Verify, step, false).ConfigureAwait(false), startByte[b], step.Pattern, pass); Tick(pass); }
                    }
                    else
                    {
                        // Check and complement upwards, check the complement and restore downwards, then check the pattern again.
                        for (var b = 0; b < sizes.Count; b++) { run.Add(await Op(b, GpuMemoryOp.VerifyThenInvert, step, false).ConfigureAwait(false), startByte[b], step.Pattern, pass); Tick(pass); }
                        for (var b = sizes.Count - 1; b >= 0; b--) { run.Add(await Op(b, GpuMemoryOp.VerifyThenInvert, step, true).ConfigureAwait(false), startByte[b], step.Pattern, pass); Tick(pass); }
                        for (var b = 0; b < sizes.Count; b++) { run.Add(await Op(b, GpuMemoryOp.Verify, step, false).ConfigureAwait(false), startByte[b], step.Pattern, pass); Tick(pass); }
                    }
                    if (run.Hot || run.Errors > 0) break;
                    // A pass far over its time (a slow chip, a huge card): stop between steps rather than run on.
                    if (clk.Elapsed - start > duration * 1.5) break;
                }
                if (run.Hot)
                {
                    log.Warn($"GPU memory: {adapter.Name}: stopped, critical temperature: {run.HotWhat}");
                    return Result(GpuMemoryOutcome.Overheated, "stopped because the PC got too hot: " + run.HotWhat);
                }
                if (run.Errors > 0) { passes = pass + 1; break; }
                if (clk.Elapsed - start > duration * 1.5) break;
                passes = pass + 1;
                if (clk.Elapsed - start >= duration) break;
            }
            var outcome = run.Errors > 0 ? GpuMemoryOutcome.ErrorsFound : passes == 0 ? GpuMemoryOutcome.CouldNotRun : GpuMemoryOutcome.Passed;
            log.Info($"GPU memory: {adapter.Name}: done outcome={outcome} passes={passes} tested={tested} errors={run.Errors} flipped=0x{run.Flipped:X8} maxTemp={run.MaxTemp}");
            return Result(outcome, outcome == GpuMemoryOutcome.CouldNotRun ? "no pass finished in the time allowed" : null);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            log.Info($"GPU memory: {adapter.Name}: cancelled after {passes} passes");
            return Result(GpuMemoryOutcome.Cancelled);
        }
        catch (GpuDeviceLostException ex)
        {
            log.Warn($"GPU memory: {adapter.Name}: device lost after {passes} passes: {ex.Message}");
            return Result(GpuMemoryOutcome.DriverReset, ex.Message);
        }
        catch (TimeoutException)
        {
            log.Warn($"GPU memory: {adapter.Name}: a dispatch didn't come back within {o.OpWatchdog.TotalSeconds:0} s");
            return Result(GpuMemoryOutcome.Hung, $"a test step didn't finish within {o.OpWatchdog.TotalSeconds:0} seconds");
        }
        finally
        {
            // Free the memory. A dispatch still stuck in the driver holds the device: free it when that call returns.
            if (hungOp is { IsCompleted: false } stuck) _ = stuck.ContinueWith(_ => SafeDispose(device), TaskScheduler.Default);
            else SafeDispose(device);
        }
    }

    private void SafeDispose(IGpuMemoryDevice d)
    {
        try { d.Dispose(); } catch (Exception ex) { log.Warn($"GPU memory: releasing the device failed: {ex.Message}"); }
    }

    public static string Mb(long bytes) => $"{bytes / GpuMemoryPlan.MB:N0} MB";

    private bool SafeAvailability()
    {
        if (sensors is null) return false;
        try { return sensors.CheckAvailability().IsAvailable; }
        catch (Exception ex) { log.Warn($"GPU memory: sensor availability failed: {ex.Message}"); return false; }
    }

    /// <summary>The GPU's temperature (null when it reports none: many integrated GPUs don't) and whether anything is at a critical temperature.</summary>
    private void ReadSensors(Run run, bool ok, TimeSpan now, TimeSpan every, bool force = false)
    {
        if (!ok || sensors is null || (!force && now < run.NextSensor)) return;
        run.NextSensor = now + every;
        try
        {
            var temps = sensors.Read().Readings.Where(r => r.SensorType == SensorKind.Temperature && r.IsLive).ToList();
            var gpu = temps.Where(r => r.HardwareType == HardwareKind.Gpu).ToList();
            run.Temp = gpu.Count == 0 ? null : gpu.Max(r => r.Value);
            if (run.Temp is { } t) run.MaxTemp = Math.Max(run.MaxTemp ?? t, t);
            var crit = temps.FirstOrDefault(r => SensorThresholds.Evaluate(r) == SensorLevel.Critical);
            if (crit is not null) { run.Hot = true; run.HotWhat = $"{crit.HardwareName} {crit.SensorName} {crit.Value:0}°C"; }
        }
        catch (Exception ex) { log.Warn($"GPU memory: sensor read failed: {ex.Message}"); }
    }
}
