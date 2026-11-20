using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Sensors;

/// <summary>Live temperatures and fan speeds (LibreHardwareMonitorLib via <see cref="ISensorProvider"/>).</summary>
public sealed class LibreHardwareMonitorModule(ISensorProvider provider) : IDiagnosticModule
{
    public const string ModuleName = ModuleSlugs.Sensors;
    public string Name => ModuleName;
    public Guid Id => ModuleIds.Sensors;
    public string DisplayName => "Temperatures & fans";
    public event EventHandler<DiagnosticResult>? Updated;

    public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult(provider.CheckAvailability());

    public async Task<DiagnosticResult> RefreshAsync(IProgress<string>? progress, CancellationToken cancellationToken = default)
    {
        progress?.Report("Reading sensors…");
        var snap = await Task.Run(provider.Read, cancellationToken).ConfigureAwait(false);
        var report = BuildReport(snap);
        return new DiagnosticResult<SensorReport>(Name, ToStatus(report, snap), Summarize(report), DateTimeOffset.Now, report);
    }

    public static readonly (string Id, string Title, string MissingLabel, Func<SensorReading, bool> Match)[] GroupDefs =
    [
        ("cpu", "CPU temps", "CPU temperatures", r => r.SensorType == SensorKind.Temperature && r.HardwareType == HardwareKind.Cpu),
        ("gpu", "GPU temps", "GPU temperatures", r => r.SensorType == SensorKind.Temperature && r.HardwareType == HardwareKind.Gpu),
        ("storage", "Storage temps", "storage temperatures", r => r.SensorType == SensorKind.Temperature && r.HardwareType == HardwareKind.Storage),
        ("board", "Board & memory temps", "board and memory temperatures", r => r.SensorType == SensorKind.Temperature && r.HardwareType is HardwareKind.Motherboard or HardwareKind.Memory or HardwareKind.Controller or HardwareKind.Other),
        ("fans", "Fans", "fans", r => r.SensorType == SensorKind.Fan),
    ];

    public static SensorReport BuildReport(SensorSnapshot snap)
    {
        snap = snap with { Readings = SensorReading.OnlyWithData(snap.Readings) };
        return new(snap, GroupDefs.Select(g => new SensorGroup(g.Id, g.Title,
            snap.Readings.Where(g.Match).Select(r => r.IsLimit ? new EvaluatedReading(r, SensorLevel.Neutral, null) : new EvaluatedReading(r, SensorThresholds.Evaluate(r), SensorThresholds.For(r))).ToList(),
            g.MissingLabel)).ToList());
    }

    public static DiagnosticStatus ToStatus(SensorReport report, SensorSnapshot snap) => ToStatus(report);

    public static DiagnosticStatus ToStatus(SensorReport report) => report.Level switch
    {
        SensorLevel.Critical => DiagnosticStatus.Error,
        SensorLevel.Warning => DiagnosticStatus.Warning,
        _ when report.Snapshot.Readings.Count == 0 => DiagnosticStatus.Warning,
        _ => DiagnosticStatus.Ok,
    };

    public static string Summarize(SensorReport report)
    {
        var s = report.Snapshot; // already filtered to readings with data by BuildReport
        if (s.Readings.Count == 0)
            return s.IsElevated ? "No temperature or fan sensors found" : "No sensors found. " + ElevationService.AdminRepairHint;
        string T(string id) => report.Groups.First(g => g.Id == id).Hottest is { } v ? $"{v:0}°C" : "—";
        var fans = s.Readings.Where(r => r.SensorType == SensorKind.Fan).ToList();
        var text = $"CPU {T("cpu")} · GPU {T("gpu")} · Storage {StorageText(report.Groups.First(g => g.Id == "storage"))} · {FansText(fans.Count, fans.Count(r => r.Value == 0))}";
        return s.IsElevated ? text : text + " (some sensors need administrator rights)";
    }

    /// <summary>"fan speed not reported" (many laptops don't expose fans), "1 fan", "3 fans"; stopped (0 RPM) fans are
    /// still counted and called out: "1 fan, stopped", "3 fans, 1 stopped".</summary>
    public static string FansText(int fans, int stopped = 0)
    {
        var text = fans switch { 0 => "fan speed not reported", 1 => "1 fan", _ => $"{fans} fans" };
        if (stopped <= 0 || fans == 0) return text;
        return fans == 1 || stopped >= fans ? text + ", stopped" : $"{text}, {stopped} stopped";
    }

    /// <summary>Gap (°C) above which the hottest drive sensor is shown next to the overall drive temperature.</summary>
    public const double StorageSensorGapC = 5;

    /// <summary>
    /// Per drive, the temperature the drive itself reports as its own (NVMe "Composite", else a plain "Temperature"), which is
    /// what Windows and the Drive health check show. Falls back to the drive's hottest sensor when it has neither. Null when no drive reports.
    /// </summary>
    public static double? DriveOverall(IEnumerable<SensorReading> storage)
    {
        double? best = null;
        foreach (var drive in storage.Where(r => r.IsLive && r.HardwareType == HardwareKind.Storage).GroupBy(r => r.HardwareName))
        {
            var overall = drive.FirstOrDefault(r => r.SensorName.Trim().StartsWith("Composite", StringComparison.OrdinalIgnoreCase))
                ?? drive.FirstOrDefault(r => r.SensorName.Trim().Equals("Temperature", StringComparison.OrdinalIgnoreCase));
            var v = overall?.Value ?? drive.Max(r => r.Value);
            if (v is { } t && (best is null || t > best)) best = t;
        }
        return best;
    }

    /// <summary>"42°C" (overall drive temperature, matching Drive health), or "42°C (hottest sensor 64°C)" when an internal
    /// sensor such as the controller runs notably hotter, so the two numbers can be reconciled.</summary>
    public static string StorageText(SensorGroup storage)
    {
        var overall = DriveOverall(storage.Readings.Select(r => r.Reading));
        if (overall is not { } o) return "—";
        return storage.Hottest is { } h && h - o >= StorageSensorGapC ? $"{o:0}°C (hottest sensor {h:0}°C)" : $"{o:0}°C";
    }

    internal void RaiseUpdated(DiagnosticResult r) => Updated?.Invoke(this, r);
}
