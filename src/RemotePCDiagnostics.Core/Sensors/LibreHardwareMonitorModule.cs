namespace RemotePCDiagnostics.Core.Sensors;

/// <summary>Live temperatures and fan speeds (LibreHardwareMonitorLib via <see cref="ISensorProvider"/>).</summary>
public sealed class LibreHardwareMonitorModule(ISensorProvider provider) : IDiagnosticModule
{
    public const string ModuleName = "Sensors";
    public string Name => ModuleName;
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

    public static readonly (string Id, string Title, Func<SensorReading, bool> Match)[] GroupDefs =
    [
        ("cpu", "CPU temps", r => r.SensorType == SensorKind.Temperature && r.HardwareType == HardwareKind.Cpu),
        ("gpu", "GPU temps", r => r.SensorType == SensorKind.Temperature && r.HardwareType == HardwareKind.Gpu),
        ("storage", "Storage temps", r => r.SensorType == SensorKind.Temperature && r.HardwareType == HardwareKind.Storage),
        ("board", "Board & memory temps", r => r.SensorType == SensorKind.Temperature && r.HardwareType is HardwareKind.Motherboard or HardwareKind.Memory or HardwareKind.Controller or HardwareKind.Other),
        ("fans", "Fans", r => r.SensorType == SensorKind.Fan),
    ];

    public static SensorReport BuildReport(SensorSnapshot snap) => new(snap,
        GroupDefs.Select(g => new SensorGroup(g.Id, g.Title,
            snap.Readings.Where(g.Match).Select(r => new EvaluatedReading(r, SensorThresholds.Evaluate(r), SensorThresholds.For(r))).ToList())).ToList());

    public static DiagnosticStatus ToStatus(SensorReport report, SensorSnapshot snap) => report.Level switch
    {
        SensorLevel.Critical => DiagnosticStatus.Error,
        SensorLevel.Warning => DiagnosticStatus.Warning,
        _ when snap.Readings.Count == 0 => DiagnosticStatus.Warning,
        _ => DiagnosticStatus.Ok,
    };

    public static string Summarize(SensorReport report)
    {
        var s = report.Snapshot;
        if (s.Readings.Count == 0)
            return s.IsElevated ? "No temperature or fan sensors found" : "No sensors found. Try running the app as administrator.";
        string T(string id) => report.Groups.First(g => g.Id == id).Hottest is { } v ? $"{v:0}°C" : "—";
        var fans = s.Readings.Count(r => r.SensorType == SensorKind.Fan);
        var text = $"CPU {T("cpu")} · GPU {T("gpu")} · Storage {T("storage")} · {fans} fan(s)";
        return s.IsElevated ? text : text + " (some sensors need administrator rights)";
    }

    internal void RaiseUpdated(DiagnosticResult r) => Updated?.Invoke(this, r);
}
