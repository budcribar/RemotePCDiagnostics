using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Core.Stress;

/// <summary>
/// Orchestrates a memory test in a separate helper process (so running out of memory or a crash can't take down the app):
/// sizes the test, starts the helper, reads its progress lines, watches temperatures, and kills the helper on Stop,
/// overheating, or when it overruns the time limit.
/// </summary>
public sealed class MemoryTest(IMemoryInfo memory, IMemTestHelperLauncher launcher, ISensorProvider sensors, IStressClock? clock = null, Action<string>? log = null)
{
    private const int StopNone = 0, StopUser = 1, StopHot = 2, StopTimeout = 3;

    public async Task<MemoryTestReport> RunAsync(MemoryTestOptions o, IProgress<MemoryTestProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        var clk = clock ?? new StopwatchStressClock();
        var start = clk.Elapsed;
        var duration = o.Duration <= TimeSpan.Zero ? MemoryTestOptions.DefaultDuration(o.Mode) : o.Duration > MemoryTestOptions.MaxDuration ? MemoryTestOptions.MaxDuration : o.Duration;
        MemoryTestReport Report(MemoryTestOutcome outcome, long bytes = 0, int passes = 0, long errors = 0, double? maxT = null) =>
            new(outcome, o.Mode, bytes, passes, errors, clk.Elapsed - start, maxT);

        long available, total;
        try { (available, total) = memory.Read(); }
        catch (Exception ex) { log?.Invoke($"Memory test: memory status failed: {ex.Message}"); return Report(MemoryTestOutcome.Failed); }
        if (MemorySizing.Plan(available, o.Mode) is not { } bytes)
        {
            log?.Invoke($"Memory test: not enough free memory available={available} total={total}");
            return Report(MemoryTestOutcome.Failed);
        }
        log?.Invoke($"Memory test: mode={o.Mode} bytes={bytes} available={available} total={total} duration={duration}");

        IMemTestHelperProcess proc;
        try { proc = launcher.Start(bytes, duration); }
        catch (Exception ex) { log?.Invoke($"Memory test: helper start failed: {ex}"); return Report(MemoryTestOutcome.Failed); }

        var sensorsOk = SafeAvailability();
        int stop = StopNone, pass = 0; double frac = 0; long errors = 0, tested = bytes;
        MemTestMessage.Done? done = null; string? fail = null;
        double? temp = null, fan = null, maxT = null;
        using (proc)
        {
            var reader = Task.Run(async () =>
            {
                while (await proc.ReadLineAsync(CancellationToken.None).ConfigureAwait(false) is { } line)
                {
                    switch (MemTestMessage.Parse(line))
                    {
                        case MemTestMessage.Allocated a: tested = a.Bytes; break;
                        case MemTestMessage.Progress p: pass = p.Pass; frac = p.Fraction; Interlocked.Exchange(ref errors, Math.Max(Interlocked.Read(ref errors), p.Errors)); break;
                        case MemTestMessage.BadWord b: log?.Invoke($"Memory test: bad word at offset {b.Offset} expected {b.Expected:X16} got {b.Actual:X16}"); break;
                        case MemTestMessage.Done d: done = d; Interlocked.Exchange(ref errors, Math.Max(Interlocked.Read(ref errors), d.Errors)); break;
                        case MemTestMessage.Fail f: fail = f.Reason; log?.Invoke($"Memory test: helper failed: {f.Reason}"); break;
                        default: log?.Invoke($"Memory test helper: {line}"); break;
                    }
                }
            }, CancellationToken.None);

            while (!reader.IsCompleted)
            {
                if (sensorsOk)
                {
                    var (t, f, critical, what) = ReadSensors();
                    temp = t; fan = f;
                    if (t is { } tv) maxT = Math.Max(maxT ?? tv, tv);
                    if (critical && stop == StopNone) { stop = StopHot; log?.Invoke($"Memory test: abort, critical temperature: {what}"); proc.Kill(); }
                }
                var elapsed = clk.Elapsed - start;
                if (cancellationToken.IsCancellationRequested && stop == StopNone) { stop = StopUser; proc.Kill(); }
                if (elapsed > duration + o.Grace && stop == StopNone) { stop = StopTimeout; log?.Invoke("Memory test: helper overran the time limit; killing it"); proc.Kill(); }
                progress?.Report(new MemoryTestProgress(elapsed > duration ? duration : elapsed, duration, tested, pass, frac, Interlocked.Read(ref errors), temp, fan, sensorsOk));
                if (stop != StopNone) break;
                await Task.WhenAny(reader, clk.DelayAsync(o.SampleInterval, CancellationToken.None)).ConfigureAwait(false);
            }
            try { await reader.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false); }
            catch (Exception ex) { log?.Invoke($"Memory test: reading helper output: {ex.Message}"); }
            log?.Invoke($"Memory test: helper exit code={proc.ExitCode?.ToString() ?? "(running/killed)"}");
        }

        var errs = Interlocked.Read(ref errors);
        var outcome = errs > 0 ? MemoryTestOutcome.MemoryErrors
            : stop == StopHot ? MemoryTestOutcome.Overheated
            : stop == StopUser ? MemoryTestOutcome.StoppedByUser
            : done is { Passes: > 0 } && fail is null ? MemoryTestOutcome.Passed
            : MemoryTestOutcome.Failed;
        var report = Report(outcome, done?.Bytes ?? tested, done?.Passes ?? pass, errs, maxT);
        log?.Invoke($"Memory test: done outcome={outcome} bytes={report.TestBytes} passes={report.Passes} errors={errs}");
        return report;
    }

    private bool SafeAvailability()
    {
        try { var a = sensors.CheckAvailability(); if (!a.IsAvailable) log?.Invoke($"Memory test: sensors unavailable: {a.Reason}"); return a.IsAvailable; }
        catch (Exception ex) { log?.Invoke($"Memory test: sensor availability failed: {ex.Message}"); return false; }
    }

    /// <summary>Hottest CPU temperature, fastest fan, and whether any temperature is critical.</summary>
    private (double? Temp, double? Fan, bool Critical, string What) ReadSensors()
    {
        try
        {
            var snap = sensors.Read();
            var temps = snap.Readings.Where(r => r.SensorType == SensorKind.Temperature && r.IsLive).ToList();
            var cpu = temps.Where(r => r.HardwareType == HardwareKind.Cpu).Select(r => r.Value).DefaultIfEmpty().Max();
            var fan = snap.Readings.Where(r => r.SensorType == SensorKind.Fan && r.HasData).Select(r => r.Value).DefaultIfEmpty().Max();
            var crit = temps.FirstOrDefault(r => SensorThresholds.Evaluate(r) == SensorLevel.Critical);
            return (cpu, fan, crit is not null, crit is null ? "" : $"{crit.HardwareName} {crit.SensorName} {crit.Value:0.0}°C");
        }
        catch (Exception ex) { log?.Invoke($"Memory test: sensor read failed: {ex.Message}"); return (null, null, false, ""); }
    }
}
