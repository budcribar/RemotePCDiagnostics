using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Core.Stress;

/// <summary>
/// Orchestrates a memory test in a separate helper process (so running out of memory or a crash can't take down the app):
/// sizes the test, starts the helper, reads its progress lines, watches temperatures, and kills the helper on Stop,
/// overheating, or when it overruns the time limit.
/// </summary>
public sealed class MemoryTest(IMemoryInfo memory, IMemTestHelperLauncher launcher, ISensorProvider sensors, IStressClock? clock = null, Action<string>? log = null, StressCleanup? cleanup = null)
{
    private const int StopNone = 0, StopUser = 1, StopHot = 2, StopTimeout = 3;

    public async Task<MemoryTestReport> RunAsync(MemoryTestOptions o, IProgress<MemoryTestProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        var clk = clock ?? new StopwatchStressClock();
        var start = clk.Elapsed;
        var duration = o.Duration <= TimeSpan.Zero ? MemoryTestOptions.DefaultDuration(o.Mode) : o.Duration > MemoryTestOptions.MaxDuration ? MemoryTestOptions.MaxDuration : o.Duration;
        long available = 0, total = 0, planned = 0;
        MemoryTestReport Report(MemoryTestOutcome outcome, long bytes = 0, int passes = 0, long errors = 0, double? maxT = null,
            int? exitCode = null, bool lowMemory = false, string? notice = null) =>
            new(outcome, o.Mode, bytes, passes, errors, clk.Elapsed - start, maxT, available, total, planned, exitCode, lowMemory, notice);
        static string Mb(long b) => $"{b / MemorySizing.MB:N0} MB";

        try { (available, total) = memory.Read(); }
        catch (Exception ex)
        {
            log?.Invoke($"Memory test: memory status failed: {ex.Message}");
            return Report(MemoryTestOutcome.CouldNotRun, notice: $"couldn't read the memory status: {ex.Message}");
        }
        if (MemorySizing.Plan(available, o.Mode) is not { } bytes)
        {
            var why = $"not enough free memory: {Mb(available)} free of {Mb(total)}, needs at least {Mb(MemorySizing.MinAvailableBytes)}";
            log?.Invoke($"Memory test: {why} (available={available} total={total})");
            return Report(MemoryTestOutcome.CouldNotRun, lowMemory: true, notice: why);
        }
        planned = bytes;
        log?.Invoke($"Memory test: mode={o.Mode} bytes={bytes} available={available} total={total} duration={duration}");

        IMemTestHelperProcess proc;
        try { proc = launcher.Start(bytes, duration); }
        catch (Exception ex)
        {
            log?.Invoke($"Memory test: helper start failed: {ex}");
            return Report(MemoryTestOutcome.CouldNotRun, notice: $"the memory test helper couldn't start: {ex.Message}");
        }

        cleanup?.Register("memory helper process", proc.Kill);
        var sensorsOk = SafeAvailability();
        int stop = StopNone, pass = 0; double frac = 0; long errors = 0, tested = bytes;
        MemTestMessage.Done? done = null; string? fail = null;
        double? temp = null, fan = null, maxT = null; int? exit = null; bool allocated = false;
        var badOffsets = new HashSet<long>(); // only touched by the reader task
        using (proc)
        {
            var reader = Task.Run(async () =>
            {
                while (await proc.ReadLineAsync(CancellationToken.None).ConfigureAwait(false) is { } line)
                {
                    switch (MemTestMessage.Parse(line))
                    {
                        case MemTestMessage.Allocated a: Interlocked.Exchange(ref tested, a.Bytes); Volatile.Write(ref allocated, true); break;
                        case MemTestMessage.Progress p: Volatile.Write(ref pass, p.Pass); Volatile.Write(ref frac, p.Fraction); Interlocked.Exchange(ref errors, Math.Max(Interlocked.Read(ref errors), p.Errors)); break;
                        case MemTestMessage.BadWord b:
                            log?.Invoke($"Memory test: bad word at offset {b.Offset} expected {b.Expected:X16} got {b.Actual:X16}");
                            // Count it now: the helper may die before its next PROGRESS/DONE carries the total.
                            if (badOffsets.Add(b.Offset)) Interlocked.Exchange(ref errors, Math.Max(Interlocked.Read(ref errors), badOffsets.Count));
                            break;
                        case MemTestMessage.Done d: Volatile.Write(ref done, d); Interlocked.Exchange(ref errors, Math.Max(Interlocked.Read(ref errors), d.Errors)); break;
                        case MemTestMessage.Fail f: Volatile.Write(ref fail, f.Reason); log?.Invoke($"Memory test: helper failed: {f.Reason}"); break;
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
                progress?.Report(new MemoryTestProgress(elapsed > duration ? duration : elapsed, duration, Interlocked.Read(ref tested), Volatile.Read(ref pass), Volatile.Read(ref frac), Interlocked.Read(ref errors), temp, fan, sensorsOk));
                if (stop != StopNone) break;
                await Task.WhenAny(reader, clk.DelayAsync(o.SampleInterval, CancellationToken.None)).ConfigureAwait(false);
            }
            try { await reader.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false); }
            catch (Exception ex) { log?.Invoke($"Memory test: reading helper output: {ex.Message}"); }
            exit = proc.ExitCode;
            log?.Invoke($"Memory test: helper exit code={exit?.ToString() ?? "(running/killed)"}");
        }

        var errs = Interlocked.Read(ref errors);
        // The helper never got any memory: the PC is too short on memory right now, not a memory fault.
        var noMemory = errs == 0 && stop == StopNone && !Volatile.Read(ref allocated) && fail is not null;
        var outcome = errs > 0 ? MemoryTestOutcome.MemoryErrors
            : stop == StopHot ? MemoryTestOutcome.Overheated
            : stop == StopUser ? MemoryTestOutcome.StoppedByUser
            : noMemory ? MemoryTestOutcome.CouldNotRun
            : done is { Passes: > 0 } && fail is null ? MemoryTestOutcome.Passed
            : MemoryTestOutcome.Failed;
        string? notice = outcome switch
        {
            MemoryTestOutcome.CouldNotRun => $"the helper couldn't allocate memory ({fail}): {Mb(available)} free of {Mb(total)}",
            MemoryTestOutcome.Failed => stop == StopTimeout ? "the helper overran the time limit and was stopped"
                : fail is not null ? $"the helper failed: {fail}"
                : done is null ? $"the helper exited before finishing (exit code {exit?.ToString() ?? "none"})"
                : "no complete pattern was checked in the time allowed",
            _ => null,
        };
        var report = Report(outcome, done?.Bytes ?? tested, done?.Passes ?? pass, errs, maxT, exit, noMemory, notice);
        log?.Invoke($"Memory test: done outcome={outcome} bytes={report.TestBytes} passes={report.Passes} errors={errs}{(notice is null ? "" : " reason=" + notice)}");
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
