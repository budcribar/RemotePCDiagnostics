using System.Collections.Concurrent;
using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Core.Stress;

/// <summary>
/// Network stability test: pings the router and a public host every interval for the whole time limit (latency, loss,
/// jitter over time), runs chunk-looped capped HTTPS download/upload with ~200 ms internet-only bufferbloat probes,
/// compares adapter error/drop counters before and after, and stops on Stop or a critical temperature.
/// </summary>
public sealed class NetworkTest(
    IPinger pinger,
    IGatewayResolver gateway,
    ISpeedTester speed,
    IAdapterCounters counters,
    ISensorProvider sensors,
    NetworkTestSettings? settings = null,
    IStressClock? clock = null,
    ILogger? log = null,
    StressCleanup? cleanup = null,
    IConnectionCostProvider? connectionCost = null,
    IWifiLinkRateReader? wifiLinkRate = null,
    Func<TimeSpan, CancellationToken, Task>? probeDelay = null)
{
    private readonly NetworkTestSettings _s = settings ?? new NetworkTestSettings();
    private readonly Func<TimeSpan, CancellationToken, Task> _probeDelay = probeDelay ?? ((d, ct) => Task.Delay(d, ct));

    private sealed record TransferChunkWindow(TimeSpan Start, TimeSpan End);
    private sealed record DenseProbeSample(TimeSpan StartedAt, TimeSpan CompletedAt, double? RttMs);

    public async Task<NetworkTestReport> RunAsync(NetworkTestOptions o, IProgress<NetworkTestProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        var clk = clock ?? new StopwatchStressClock();
        var start = clk.Elapsed;
        var duration = o.Duration <= TimeSpan.Zero ? TimeSpan.FromMinutes(1) : o.Duration > NetworkTestOptions.MaxDuration ? NetworkTestOptions.MaxDuration : o.Duration;
        var testDeadline = start + duration;
        var samples = new List<NetworkSample>();
        var stopped = false; var hot = false; var failed = false;
        double? temp = null, fan = null, maxT = null;
        TransferResult? down = null, up = null;
        BufferbloatResult? bufferbloat = null;
        string? wifiLinkText = null;
        AdapterTotals? before = null, after = null;
        var sensorsOk = SafeAvailability();
        string? gw = null;
        var runCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var speedCts = CancellationTokenSource.CreateLinkedTokenSource(runCts.Token);
        var ctsGate = new object();
        CancellationTokenSource? runCtsRef = runCts, speedCtsRef = speedCts;
        Task? speedTask = null;
        Task<List<double>>? idleTask = null;
        CancellationTokenSource? idleCts = null;
        var bloatHost = _s.PublicHosts.Count > 0 ? _s.PublicHosts[0] : "1.1.1.1";
        cleanup?.Register("network test", () =>
        {
            lock (ctsGate)
            {
                try { speedCtsRef?.Cancel(); } catch (ObjectDisposedException) { }
                try { runCtsRef?.Cancel(); } catch (ObjectDisposedException) { }
            }
        });
        string step = "Checking your connection";

        try
        {
            gw = SafeGateway();
            before = await SafeCounters(runCts.Token).ConfigureAwait(false);
            wifiLinkText = await SafeWifiLinkRate(runCts.Token).ConfigureAwait(false);
            log.Info($"Network test: start gateway={gw ?? "(none)"} hosts={string.Join(",", _s.PublicHosts)} server={_s.SpeedServer} duration={duration} counters={before} wifiLink={wifiLinkText ?? "(none)"}");

            if (o.RunSpeedTest && duration > o.SpeedTestDelay + TimeSpan.FromSeconds(2))
            {
                idleCts = CancellationTokenSource.CreateLinkedTokenSource(speedCts.Token);
                idleTask = CollectIdleBaselineAsync(bloatHost, o, testDeadline, clk, idleCts.Token);
            }

            int hostIdx = 0;
            while (true)
            {
                var elapsed = clk.Elapsed - start;
                if (runCts.IsCancellationRequested) { stopped = true; break; }
                if (elapsed >= duration) break;

                if (sensorsOk)
                {
                    var (t, f, critical, what) = ReadSensors();
                    temp = t; fan = f;
                    if (t is { } tv) maxT = Math.Max(maxT ?? tv, tv);
                    if (critical) { hot = true; log.Warn($"Network test: abort, critical temperature: {what}"); break; }
                }

                var host = _s.PublicHosts.Count == 0 ? "1.1.1.1" : _s.PublicHosts[hostIdx++ % _s.PublicHosts.Count];
                var pInternet = pinger.PingAsync(host, o.PingTimeout, runCts.Token);
                var pGateway = gw is null ? Task.FromResult(new PingReply(false, null)) : pinger.PingAsync(gw, o.PingTimeout, runCts.Token);
                PingReply ri, rg;
                try { ri = await pInternet.ConfigureAwait(false); rg = await pGateway.ConfigureAwait(false); }
                catch (OperationCanceledException) when (runCts.IsCancellationRequested) { stopped = true; break; }
                samples.Add(new NetworkSample(elapsed, rg.Success ? rg.RoundTripMs : null, ri.Success ? ri.RoundTripMs : null, gw is not null));

                if (o.RunSpeedTest && speedTask is null && elapsed >= o.SpeedTestDelay)
                {
                    var left = duration - elapsed;
                    if (left > TimeSpan.FromSeconds(2))
                    {
                        speedTask = StressTaskScheduler.Run(async () =>
                        {
                            List<double> idleSamples = [];
                            if (idleTask is not null)
                            {
                                idleCts?.Cancel();
                                try { idleSamples = await idleTask.ConfigureAwait(false); }
                                catch { }
                            }

                            var cost = SafeConnectionCost();
                            var dlBudget = cost == ConnectionCostKind.Unrestricted ? _s.OrdinaryDownloadBytes : _s.DownloadBytes;
                            var ulBudget = cost == ConnectionCostKind.Unrestricted ? _s.OrdinaryUploadBytes : _s.UploadBytes;

                            Volatile.Write(ref step, "Measuring download speed");
                            var (dlResult, dlProbes, dlBudgetExhausted) = await RunDirectionAsync(
                                bloatHost,
                                dlBudget,
                                _s.MaxDownloadChunkBytes,
                                (chunkBytes, timeout, ct) => speed.DownloadAsync(chunkBytes, timeout, ct),
                                o,
                                testDeadline,
                                clk,
                                speedCts.Token).ConfigureAwait(false);
                            down = dlResult;

                            Volatile.Write(ref step, "Measuring upload speed");
                            var (ulResult, ulProbes, ulBudgetExhausted) = await RunDirectionAsync(
                                bloatHost,
                                ulBudget,
                                _s.MaxUploadChunkBytes,
                                (chunkBytes, timeout, ct) => speed.UploadAsync(chunkBytes, timeout, ct),
                                o,
                                testDeadline,
                                clk,
                                speedCts.Token).ConfigureAwait(false);
                            up = ulResult;

                            bufferbloat = BufferbloatResult.Evaluate(idleSamples, dlProbes, ulProbes, dlBudgetExhausted, ulBudgetExhausted);
                            Volatile.Write(ref step, "Checking your connection");
                            log.Info($"Network test: cost={cost} download {down.Bytes} B in {down.Elapsed} ({down.Mbps:0.0} Mbps, err={down.Error}); upload {up.Bytes} B in {up.Elapsed} ({up.Mbps:0.0} Mbps, err={up.Error}); bufferbloat={bufferbloat.HeadlineText} (idle={bufferbloat.IdleSamples}, dl={bufferbloat.DownloadSamples}, ul={bufferbloat.UploadSamples})");
                        }, CancellationToken.None);
                    }
                }

                progress?.Report(new NetworkTestProgress(elapsed, duration, Volatile.Read(ref step), samples.ToList(), temp, fan, sensorsOk));
                try { await clk.DelayAsync(o.Interval, runCts.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) { stopped = true; break; }
            }
        }
        catch (OperationCanceledException) when (runCts.IsCancellationRequested)
        {
            stopped = true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            failed = true;
            log.Error($"Network test: failed: {ex}");
        }
        finally
        {
            if (speedTask is not null)
            {
                if (stopped || hot || failed) speedCts.Cancel();
                try { await speedTask.ConfigureAwait(false); }
                catch (OperationCanceledException) { }
                catch (Exception ex) { log.Warn($"Network test: speed test error: {ex.Message}"); }
            }
            if (idleTask is not null)
            {
                idleCts?.Cancel();
                try { await idleTask.ConfigureAwait(false); } catch { }
            }
            idleCts?.Dispose();
            lock (ctsGate) { speedCtsRef = null; runCtsRef = null; }
            speedCts.Dispose();
            runCts.Dispose();
        }
        if (!stopped && !hot && !failed) after = await SafeCounters(CancellationToken.None).ConfigureAwait(false);

        var gwStats = PingStats.From(samples.Where(s => s.GatewayTried).Select(s => s.GatewayMs));
        var netStats = PingStats.From(samples.Select(s => s.InternetMs));
        long? newErr = before is not null && after is not null ? Math.Max(0, after.Errors - before.Errors) : null;
        long? newDrop = before is not null && after is not null ? Math.Max(0, after.Drops - before.Drops) : null;
        var outcome = Verdict(o, stopped, hot, failed, samples.Count, netStats, down, newErr, newDrop);
        var report = new NetworkTestReport(outcome, clk.Elapsed - start, gw is not null, gwStats, netStats, down?.Mbps, up?.Mbps, newErr, newDrop, samples, maxT, bufferbloat, wifiLinkText);
        log.Info($"Network test: done outcome={outcome} internet={netStats} gateway={gwStats} down={report.DownloadMbps:0.0} up={report.UploadMbps:0.0} newErrors={newErr} newDrops={newDrop}");
        return report;
    }

    private async Task<List<double>> CollectIdleBaselineAsync(
        string host,
        NetworkTestOptions o,
        TimeSpan testDeadline,
        IStressClock clk,
        CancellationToken ct)
    {
        var results = new List<double>();
        var targetCount = BufferbloatResult.MinSamplesPerPhase;
        for (var i = 0; i < targetCount; i++)
        {
            if (ct.IsCancellationRequested || clk.Elapsed >= testDeadline) break;
            try
            {
                var reply = await pinger.PingAsync(host, o.PingTimeout, ct).ConfigureAwait(false);
                if (reply.Success && reply.RoundTripMs is { } ms)
                    results.Add(ms);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch { }

            if (i + 1 < targetCount && !ct.IsCancellationRequested && clk.Elapsed < testDeadline)
            {
                try { await _probeDelay(o.BufferbloatProbeInterval, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
        }
        return results;
    }

    private async Task<(TransferResult Result, List<double> QualifiedProbes, bool BudgetExhausted)> RunDirectionAsync(
        string bloatHost,
        long byteBudget,
        long maxChunkBytes,
        Func<long, TimeSpan, CancellationToken, Task<TransferResult>> transferChunk,
        NetworkTestOptions o,
        TimeSpan testDeadline,
        IStressClock clk,
        CancellationToken ct)
    {
        var phaseStart = clk.Elapsed;
        var ceiling = _s.DirectionTimeCeiling < _s.TransferTimeout ? _s.DirectionTimeCeiling : _s.TransferTimeout;
        var directionDeadline = phaseStart + ceiling;
        if (testDeadline < directionDeadline)
            directionDeadline = testDeadline;

        var windows = new List<TransferChunkWindow>();
        var probes = new ConcurrentBag<DenseProbeSample>();
        var remainingBudget = Math.Max(0, byteBudget);
        long usableBytes = 0;
        var usableElapsed = TimeSpan.Zero;
        string? lastError = null;
        var chunkCap = maxChunkBytes > 0 ? maxChunkBytes : byteBudget;

        using var probeCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var probeTask = RunDenseProbesAsync(bloatHost, o, clk, probes, probeCts.Token);

        try
        {
            while (remainingBudget > 0 && !ct.IsCancellationRequested)
            {
                var now = clk.Elapsed;
                var timeLeft = directionDeadline - now;
                if (timeLeft <= TimeSpan.Zero) break;

                var requestBytes = Math.Min(chunkCap, remainingBudget);
                var beforeChunk = clk.Elapsed;
                TransferResult chunk;
                try
                {
                    chunk = await transferChunk(requestBytes, timeLeft, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (Exception ex)
                {
                    lastError = ex.Message;
                    break;
                }
                var afterChunk = clk.Elapsed;

                var observed = chunk.BudgetBytes;
                if (observed > 0)
                {
                    var winStart = chunk.FirstPayloadByteAt ?? beforeChunk;
                    var winEnd = chunk.LastPayloadByteAt ?? afterChunk;
                    if (winEnd >= winStart)
                        windows.Add(new TransferChunkWindow(winStart, winEnd));
                    remainingBudget = Math.Max(0, remainingBudget - observed);
                }

                if (chunk.Error is null && chunk.Bytes > 0 && chunk.Elapsed > TimeSpan.Zero)
                {
                    usableBytes += chunk.Bytes;
                    usableElapsed += chunk.Elapsed;
                }
                else if (chunk.Error is not null)
                {
                    lastError = chunk.Error;
                }

                // Avoid spinning if the endpoint returned 0 bytes with no progress.
                if (observed <= 0) break;
            }
        }
        finally
        {
            probeCts.Cancel();
            try { await probeTask.ConfigureAwait(false); }
            catch (OperationCanceledException) { }
            catch { }
        }

        // Count a probe toward the loaded median ONLY when it starts and completes within the same active chunk's payload window.
        var qualified = new List<double>();
        foreach (var p in probes)
        {
            if (p.RttMs is not { } ms) continue;
            if (windows.Any(w => p.StartedAt >= w.Start && p.CompletedAt <= w.End))
                qualified.Add(ms);
        }

        var result = usableBytes > 0 && usableElapsed > TimeSpan.Zero
            ? new TransferResult(usableBytes, usableElapsed, Error: null, ClientObservedBytes: byteBudget - remainingBudget)
            : new TransferResult(0, clk.Elapsed - phaseStart, Error: lastError ?? "Transfer did not complete.", ClientObservedBytes: byteBudget - remainingBudget);

        return (result, qualified, remainingBudget == 0);
    }

    private async Task RunDenseProbesAsync(
        string host,
        NetworkTestOptions o,
        IStressClock clk,
        ConcurrentBag<DenseProbeSample> sink,
        CancellationToken ct)
    {
        var maxInFlight = Math.Max(1, o.MaxInFlightBufferbloatProbes);
        using var gate = new SemaphoreSlim(maxInFlight, maxInFlight);
        var inFlight = new List<Task>();

        try
        {
            while (!ct.IsCancellationRequested)
            {
                await gate.WaitAsync(ct).ConfigureAwait(false);
                var task = RunOneProbeAsync(host, o.PingTimeout, clk, sink, gate, ct);
                inFlight.Add(task);
                inFlight.RemoveAll(t => t.IsCompleted);

                await _probeDelay(o.BufferbloatProbeInterval, ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) { }
        finally
        {
            if (inFlight.Count > 0)
            {
                try { await Task.WhenAll(inFlight).ConfigureAwait(false); }
                catch { }
            }
        }
    }

    private async Task RunOneProbeAsync(
        string host,
        TimeSpan timeout,
        IStressClock clk,
        ConcurrentBag<DenseProbeSample> sink,
        SemaphoreSlim gate,
        CancellationToken ct)
    {
        try
        {
            var started = clk.Elapsed;
            var reply = await pinger.PingAsync(host, timeout, ct).ConfigureAwait(false);
            var completed = clk.Elapsed;
            sink.Add(new DenseProbeSample(started, completed, reply.Success ? reply.RoundTripMs : null));
        }
        catch (OperationCanceledException) { }
        catch { }
        finally
        {
            try { gate.Release(); } catch (ObjectDisposedException) { }
        }
    }

    public static NetworkTestOutcome Verdict(NetworkTestOptions o, bool stopped, bool hot, bool failed, int samples, PingStats internet,
        TransferResult? download, long? newErrors, long? newDrops)
    {
        if (hot) return NetworkTestOutcome.Overheated;
        if (stopped) return NetworkTestOutcome.StoppedByUser;
        if (failed || samples == 0) return NetworkTestOutcome.Failed;
        // ICMP may be blocked on some networks: a successful download still proves the internet is reachable.
        var internetUp = internet.Received > 0 || download?.Mbps is not null;
        if (!internetUp) return NetworkTestOutcome.NoInternet;
        var loss = internet.Received > 0 ? internet.LossPercent ?? 0 : 0;
        if (loss >= o.UnstableLossPercent || internet.JitterMs >= o.UnstableJitterMs || newErrors > 0) return NetworkTestOutcome.Unstable;
        if (loss >= o.SomeLossPercent || newDrops > 0) return NetworkTestOutcome.SomeLoss;
        return NetworkTestOutcome.Stable;
    }

    private ConnectionCostKind SafeConnectionCost()
    {
        try { return connectionCost?.GetConnectionCost() ?? ConnectionCostKind.Unknown; }
        catch { return ConnectionCostKind.Unknown; }
    }

    private async Task<string?> SafeWifiLinkRate(CancellationToken ct)
    {
        if (wifiLinkRate is null) return null;
        try { return await wifiLinkRate.ReadLinkRateTextAsync(ct).ConfigureAwait(false); }
        catch { return null; }
    }

    private string? SafeGateway()
    {
        try { return gateway.GetDefaultGateway(); }
        catch (Exception ex) { log.Warn($"Network test: gateway lookup failed: {ex.Message}"); return null; }
    }

    private async Task<AdapterTotals?> SafeCounters(CancellationToken ct)
    {
        try { return await counters.ReadAsync(ct).ConfigureAwait(false); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { log.Warn($"Network test: adapter counters failed: {ex.Message}"); return null; }
    }

    private bool SafeAvailability()
    {
        try { var a = sensors.CheckAvailability(); if (!a.IsAvailable) log.Info($"Network test: sensors unavailable: {a.Reason}"); return a.IsAvailable; }
        catch (Exception ex) { log.Warn($"Network test: sensor availability failed: {ex.Message}"); return false; }
    }

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
        catch (Exception ex) { log.Warn($"Network test: sensor read failed: {ex.Message}"); return (null, null, false, ""); }
    }
}
