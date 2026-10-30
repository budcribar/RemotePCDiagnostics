using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Core.Stress;

/// <summary>
/// Network stability test: pings the router and a public host every interval for the whole time limit (latency, loss,
/// jitter over time), runs one capped HTTPS download/upload part-way through, compares adapter error/drop counters
/// before and after, and stops on Stop or a critical temperature.
/// </summary>
public sealed class NetworkTest(IPinger pinger, IGatewayResolver gateway, ISpeedTester speed, IAdapterCounters counters, ISensorProvider sensors,
    NetworkTestSettings? settings = null, IStressClock? clock = null, Action<string>? log = null)
{
    private readonly NetworkTestSettings _s = settings ?? new NetworkTestSettings();

    public async Task<NetworkTestReport> RunAsync(NetworkTestOptions o, IProgress<NetworkTestProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        var clk = clock ?? new StopwatchStressClock();
        var start = clk.Elapsed;
        var duration = o.Duration <= TimeSpan.Zero ? TimeSpan.FromMinutes(1) : o.Duration > NetworkTestOptions.MaxDuration ? NetworkTestOptions.MaxDuration : o.Duration;
        var samples = new List<NetworkSample>();
        var stopped = false; var hot = false; var failed = false;
        double? temp = null, fan = null, maxT = null;
        TransferResult? down = null, up = null;
        AdapterTotals? before = null, after = null;
        var sensorsOk = SafeAvailability();
        string? gw = null;
        using var speedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        Task? speedTask = null;
        string step = "Checking your connection";

        try
        {
            gw = SafeGateway();
            before = await SafeCounters(cancellationToken).ConfigureAwait(false);
            log?.Invoke($"Network test: start gateway={gw ?? "(none)"} hosts={string.Join(",", _s.PublicHosts)} server={_s.SpeedServer} duration={duration} counters={before}");
            int hostIdx = 0;
            while (true)
            {
                var elapsed = clk.Elapsed - start;
                if (cancellationToken.IsCancellationRequested) { stopped = true; break; }
                if (elapsed >= duration) break;

                if (sensorsOk)
                {
                    var (t, f, critical, what) = ReadSensors();
                    temp = t; fan = f;
                    if (t is { } tv) maxT = Math.Max(maxT ?? tv, tv);
                    if (critical) { hot = true; log?.Invoke($"Network test: abort, critical temperature: {what}"); break; }
                }

                var host = _s.PublicHosts.Count == 0 ? "1.1.1.1" : _s.PublicHosts[hostIdx++ % _s.PublicHosts.Count];
                var pInternet = pinger.PingAsync(host, o.PingTimeout, cancellationToken);
                var pGateway = gw is null ? Task.FromResult(new PingReply(false, null)) : pinger.PingAsync(gw, o.PingTimeout, cancellationToken);
                PingReply ri, rg;
                try { ri = await pInternet.ConfigureAwait(false); rg = await pGateway.ConfigureAwait(false); }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { stopped = true; break; }
                samples.Add(new NetworkSample(elapsed, rg.Success ? rg.RoundTripMs : null, ri.Success ? ri.RoundTripMs : null, gw is not null));

                if (o.RunSpeedTest && speedTask is null && elapsed >= o.SpeedTestDelay)
                {
                    var left = duration - elapsed;
                    var limit = left < _s.TransferTimeout ? left : _s.TransferTimeout;
                    if (limit > TimeSpan.FromSeconds(2))
                    {
                        speedTask = Task.Run(async () =>
                        {
                            Volatile.Write(ref step, "Measuring download speed");
                            down = await speed.DownloadAsync(_s.DownloadBytes, limit, speedCts.Token).ConfigureAwait(false);
                            Volatile.Write(ref step, "Measuring upload speed");
                            up = await speed.UploadAsync(_s.UploadBytes, limit, speedCts.Token).ConfigureAwait(false);
                            Volatile.Write(ref step, "Checking your connection");
                            log?.Invoke($"Network test: download {down.Bytes} B in {down.Elapsed} ({down.Mbps:0.0} Mbps, err={down.Error}); upload {up.Bytes} B in {up.Elapsed} ({up.Mbps:0.0} Mbps, err={up.Error})");
                        }, CancellationToken.None);
                    }
                }

                progress?.Report(new NetworkTestProgress(elapsed, duration, Volatile.Read(ref step), samples.ToList(), temp, fan, sensorsOk));
                try { await clk.DelayAsync(o.Interval, cancellationToken).ConfigureAwait(false); }
                catch (OperationCanceledException) { stopped = true; break; }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            failed = true;
            log?.Invoke($"Network test: failed: {ex}");
        }
        finally
        {
            if (speedTask is not null)
            {
                if (stopped || hot || failed) speedCts.Cancel();
                try { await speedTask.ConfigureAwait(false); }
                catch (OperationCanceledException) { }
                catch (Exception ex) { log?.Invoke($"Network test: speed test error: {ex.Message}"); }
            }
        }
        if (!stopped && !hot && !failed) after = await SafeCounters(CancellationToken.None).ConfigureAwait(false);

        var gwStats = PingStats.From(samples.Where(s => s.GatewayTried).Select(s => s.GatewayMs));
        var netStats = PingStats.From(samples.Select(s => s.InternetMs));
        long? newErr = before is not null && after is not null ? Math.Max(0, after.Errors - before.Errors) : null;
        long? newDrop = before is not null && after is not null ? Math.Max(0, after.Drops - before.Drops) : null;
        var outcome = Verdict(o, stopped, hot, failed, samples.Count, netStats, down, newErr, newDrop);
        var report = new NetworkTestReport(outcome, clk.Elapsed - start, gw is not null, gwStats, netStats, down?.Mbps, up?.Mbps, newErr, newDrop, samples, maxT);
        log?.Invoke($"Network test: done outcome={outcome} internet={netStats} gateway={gwStats} down={report.DownloadMbps:0.0} up={report.UploadMbps:0.0} newErrors={newErr} newDrops={newDrop}");
        return report;
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

    private string? SafeGateway()
    {
        try { return gateway.GetDefaultGateway(); }
        catch (Exception ex) { log?.Invoke($"Network test: gateway lookup failed: {ex.Message}"); return null; }
    }

    private async Task<AdapterTotals?> SafeCounters(CancellationToken ct)
    {
        try { return await counters.ReadAsync(ct).ConfigureAwait(false); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { log?.Invoke($"Network test: adapter counters failed: {ex.Message}"); return null; }
    }

    private bool SafeAvailability()
    {
        try { var a = sensors.CheckAvailability(); if (!a.IsAvailable) log?.Invoke($"Network test: sensors unavailable: {a.Reason}"); return a.IsAvailable; }
        catch (Exception ex) { log?.Invoke($"Network test: sensor availability failed: {ex.Message}"); return false; }
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
        catch (Exception ex) { log?.Invoke($"Network test: sensor read failed: {ex.Message}"); return (null, null, false, ""); }
    }
}
