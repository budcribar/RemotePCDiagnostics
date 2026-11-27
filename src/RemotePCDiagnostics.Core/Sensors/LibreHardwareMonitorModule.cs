using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Sensors;

/// <summary>Live temperatures and fan speeds (LibreHardwareMonitorLib via <see cref="ISensorProvider"/>).</summary>
/// <param name="noAgent">True when no Agent is installed (the Store app on its own): the sensors that need administrator rights are
/// just left out, so the check reports what it could read without a warning or a hint to turn on Admin Repair Mode.</param>
public sealed class LibreHardwareMonitorModule(ISensorProvider provider, Func<bool>? noAgent = null) : IDiagnosticModule
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
        var quiet = noAgent?.Invoke() == true && !snap.IsElevated;
        return new DiagnosticResult<SensorReport>(Name, ToStatus(report, quiet), Summarize(report, quiet), DateTimeOffset.Now, report);
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

    public static DiagnosticStatus ToStatus(SensorReport report, bool noAgent = false) => report.Level switch
    {
        SensorLevel.Critical => DiagnosticStatus.Error,
        SensorLevel.Warning => DiagnosticStatus.Warning,
        _ when report.Snapshot.Readings.Count == 0 && !noAgent => DiagnosticStatus.Warning,
        _ => DiagnosticStatus.Ok,
    };

    public static string Summarize(SensorReport report, bool noAgent = false)
    {
        var s = report.Snapshot; // already filtered to readings with data by BuildReport
        if (s.Readings.Count == 0)
            return s.IsElevated ? "No temperature or fan sensors found"
                : noAgent ? "No temperature or fan sensors readable on this PC"
                : "No sensors found. " + ElevationService.AdminRepairHint;
        var parts = new List<string>(4);
        if (report.Groups.FirstOrDefault(g => g.Id == "cpu")?.Hottest is { } cpu) parts.Add($"CPU {cpu:0}°C");
        if (report.Groups.FirstOrDefault(g => g.Id == "gpu")?.Hottest is { } gpu) parts.Add($"GPU {gpu:0}°C");
        if (report.Groups.FirstOrDefault(g => g.Id == "storage") is { } storage && StorageText(storage) is { } st) parts.Add($"Storage {st}");
        if (parts.Count == 0 && report.Groups.FirstOrDefault(g => g.Id == "board")?.Hottest is { } board) parts.Add($"Board {board:0}°C");
        var fans = s.Readings.Where(r => r.SensorType == SensorKind.Fan).ToList();
        var fansText = FansText(fans.Count, fans.Count(r => r.Value == 0));
        if (!string.IsNullOrEmpty(fansText)) parts.Add(fansText);
        if (parts.Count == 0)
            return s.IsElevated ? "No temperature or fan sensors found"
                : noAgent ? "No temperature or fan sensors readable on this PC"
                : "No sensors found. " + ElevationService.AdminRepairHint;
        var text = string.Join(" · ", parts);
        return s.IsElevated || noAgent ? text : text + " (some sensors need administrator rights)";
    }

    /// <summary>"" when no fans are reported, otherwise "1 fan", "3 fans"; stopped (0 RPM) fans are
    /// still counted and called out: "1 fan, stopped", "3 fans, 1 stopped".</summary>
    public static string FansText(int fans, int stopped = 0)
    {
        if (fans <= 0) return "";
        var text = fans == 1 ? "1 fan" : $"{fans} fans";
        if (stopped <= 0) return text;
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
    /// sensor such as the controller runs notably hotter, so the two numbers can be reconciled. Null when no drive reports.</summary>
    public static string? StorageText(SensorGroup storage)
    {
        var overall = DriveOverall(storage.Readings.Select(r => r.Reading));
        if (overall is not { } o) return null;
        return storage.Hottest is { } h && h - o >= StorageSensorGapC ? $"{o:0}°C (hottest sensor {h:0}°C)" : $"{o:0}°C";
    }

    internal void RaiseUpdated(DiagnosticResult r) => Updated?.Invoke(this, r);
}
