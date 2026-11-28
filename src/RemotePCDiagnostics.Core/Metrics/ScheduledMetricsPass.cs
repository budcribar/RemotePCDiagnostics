using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Core.Metrics;

/// <summary>Measures one check for the scheduled pass: one result, or one per drive for a per-drive check.</summary>
public interface IMetricsProbes
{
    Task<IReadOnlyList<DiagnosticResult>> MeasureAsync(string checkId, CancellationToken ct);
}

/// <summary>
/// One scheduled pass: measures each check, writes each result to the PC's History (so the check card's trend has these points too),
/// and adds its status and key metrics to the outbox for Admin. A check that fails is recorded as such; it never stops the others.
/// </summary>
public sealed class ScheduledMetricsPass(IMetricsProbes probes, MetricsOutbox outbox, Action<DiagnosticResult>? history, string appVersion, ILogger? log = null)
{
    /// <summary>Longest one check may take before the pass moves on.</summary>
    public static readonly TimeSpan CheckTimeout = TimeSpan.FromMinutes(3);

    /// <summary>This pass's limit per check (<see cref="CheckTimeout"/>; tests shorten it).</summary>
    public TimeSpan Timeout { get; init; } = CheckTimeout;

    public async Task<int> RunAsync(MetricsSchedule schedule, CancellationToken ct)
    {
        var added = 0;
        foreach (var check in schedule.Checks)
        {
            ct.ThrowIfCancellationRequested();
            IReadOnlyList<DiagnosticResult> results;
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(Timeout);
            try
            {
                // The token alone can't stop a probe that blocks (a hung WMI call): the pass stops waiting at the deadline and moves on,
                // and the probe is left to finish or fail by itself.
                var probe = Task.Run(() => probes.MeasureAsync(check, timeout.Token), CancellationToken.None);
                results = await probe.WaitAsync(Timeout, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                log.Warn($"[metrics] {check} failed: {ex.GetType().Name}: {ex.Message}");
                results = [CouldNotRun.Result(check, "The scheduled measurement didn't finish.")];
            }
            foreach (var r in results)
            {
                try { history?.Invoke(r); } catch (Exception ex) { log.Warn($"[metrics] History not written for {check}: {ex.Message}"); }
                var metrics = r.Payload is IKeyMetrics { KeyMetrics: { } km }
                    ? km.Select(k => new MetricsValue(k.Id, k.Label, k.Value, k.Unit, k.Better)).ToList()
                    : [];
                outbox.Add(r.ModuleName, r.InstanceKey, r.InstanceLabel, r.Timestamp, ResultEventLogger.Outcome(r), r.Message ?? "", metrics, appVersion);
                added++;
            }
        }
        log.Info($"[metrics] Scheduled pass recorded {added} run(s); {outbox.Count} waiting for Admin.");
        return added;
    }
}

/// <summary>
/// The pass's measurements, run by the Agent itself (it has administrator, so drive reliability counters and temperatures read directly).
/// Battery and memory are read the way the app's checks read them and carry the same key metrics (<see cref="CheckKeyMetrics"/>).
/// </summary>
/// <param name="appFolder">The app's folder, for osquery (the battery). Null when no app is installed or cached: the battery is then skipped.</param>
/// <param name="sensors">Reads temperatures (the Agent's sensor provider), or null when there is none.</param>
/// <param name="wmi">Where WMI is read (a recording in the replay tests); the PC's own WMI when null.</param>
/// <param name="driveHistoryPath">The drives' history file; the protected state folder's when null.</param>
public sealed class CoreMetricsProbes(string? appFolder, Func<CancellationToken, Task<SensorSnapshot?>>? sensors, ILogger? log = null,
    DataSources.IWmiSource? wmi = null, string? driveHistoryPath = null) : IMetricsProbes
{
    public async Task<IReadOnlyList<DiagnosticResult>> MeasureAsync(string checkId, CancellationToken ct)
    {
        if (string.Equals(checkId, ModuleSlugs.DriveHealth, StringComparison.OrdinalIgnoreCase)) return await DrivesAsync(ct).ConfigureAwait(false);
        if (string.Equals(checkId, ModuleSlugs.BatteryPower, StringComparison.OrdinalIgnoreCase)) return await BatteryAsync(ct).ConfigureAwait(false);
        if (string.Equals(checkId, ModuleSlugs.Sensors, StringComparison.OrdinalIgnoreCase)) return await SensorsAsync(ct).ConfigureAwait(false);
        if (string.Equals(checkId, ModuleSlugs.ResourceHogs, StringComparison.OrdinalIgnoreCase)) return [Memory()];
        return [];
    }

    private async Task<IReadOnlyList<DiagnosticResult>> DrivesAsync(CancellationToken ct)
    {
        var module = new DriveHealthModule(new WmiDriveSource(wmi ?? new DataSources.SystemWmiSource(log)),
            historyStore: new DriveHealthHistoryStore(driveHistoryPath ?? ProtectedState.PathFor("drive_health_history.json"), log), log: log);
        var detection = await module.DetectAsync(ct).ConfigureAwait(false);
        var list = new List<DiagnosticResult>();
        foreach (var instance in detection.Instances)
        {
            var r = await module.RefreshAsync(instance, null, ct).ConfigureAwait(false);
            list.Add(r with { InstanceKey = instance.Key, InstanceLabel = instance.Label });
        }
        return list;
    }

    private async Task<IReadOnlyList<DiagnosticResult>> BatteryAsync(CancellationToken ct)
    {
        var batteries = await BatteryReader.ReadWmiAsync(wmi ?? new DataSources.SystemWmiSource(log), ct).ConfigureAwait(false);
        if (batteries is null) return [CouldNotRun.Result(ModuleSlugs.BatteryPower, "Couldn't read the battery.")];
        if (batteries.Count == 0) return []; // no battery: nothing to track
        // One result per pack, so a worn second battery has its own series. A PC with one battery keeps the series it always had
        // (no instance); with more, each is keyed by its place in WMI's list, which follows the battery's instance name.
        var list = new List<DiagnosticResult>(batteries.Count);
        for (var i = 0; i < batteries.Count; i++)
        {
            var b = batteries[i];
            var worn = b.HealthPercent is < BatteryStatus.LowHealthPercent;
            // The same fault states the app's check fails on (no charging check here: the pass takes one reading).
            var fault = BatteryCondition.Faults(b).FirstOrDefault(f => f.Level == AreaLevel.Error);
            var summary = fault?.Text ?? (b.HealthPercent is { } h ? $"Battery health {h}%" : "Battery present");
            var status = fault is not null ? DiagnosticStatus.Error : worn ? DiagnosticStatus.Warning : DiagnosticStatus.Ok;
            var report = new AreaReport([], summary, status) { KeyMetrics = CheckKeyMetrics.Battery(b) };
            var result = new DiagnosticResult(ModuleSlugs.BatteryPower, status, summary, DateTimeOffset.Now, report);
            list.Add(batteries.Count == 1 ? result : result with { InstanceKey = "battery-" + i, InstanceLabel = BatteryLabel(b, i) });
        }
        return list;
    }

    private static string BatteryLabel(BatteryStatus b, int index) =>
        string.IsNullOrWhiteSpace(b.Model) ? $"Battery {index + 1}" : $"Battery {index + 1} ({b.Model.Trim()})";

    private async Task<IReadOnlyList<DiagnosticResult>> SensorsAsync(CancellationToken ct)
    {
        if (sensors is null) return [];
        var snap = await sensors(ct).ConfigureAwait(false);
        if (snap is null) return [CouldNotRun.Result(ModuleSlugs.Sensors, "Couldn't read the temperature sensors.")];
        var report = LibreHardwareMonitorModule.BuildReport(snap);
        return [new DiagnosticResult(ModuleSlugs.Sensors, LibreHardwareMonitorModule.ToStatus(report), LibreHardwareMonitorModule.Summarize(report), DateTimeOffset.Now, report)];
    }

    private static DiagnosticResult Memory()
    {
        var (available, total) = new Stress.SystemMemoryInfo().Read();
        var percent = total <= 0 ? 0 : (int)Math.Round(100.0 * (total - available) / total);
        var up = TimeSpan.FromMilliseconds(Environment.TickCount64);
        var summary = $"Memory {percent}% in use · up {Math.Floor(up.TotalDays)} days";
        var report = new AreaReport([], summary, DiagnosticStatus.Ok) { KeyMetrics = [CheckKeyMetrics.MemoryUsed(percent), CheckKeyMetrics.Uptime(up)] };
        return new DiagnosticResult(ModuleSlugs.ResourceHogs, DiagnosticStatus.Ok, summary, DateTimeOffset.Now, report);
    }
}
