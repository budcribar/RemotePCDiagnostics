using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;

namespace RemotePCDiagnostics.Core.Sensors;

/// <summary>One drive temperature from Windows (the drive's own reliability counters).</summary>
public sealed record DriveTemperatureSample(string DriveName, double? Celsius);

/// <summary>Drive temperatures read without LibreHardwareMonitor. May throw on failure (the caller catches).</summary>
public interface IDriveTemperatureSource
{
    IReadOnlyList<DriveTemperatureSample> Read();
}

/// <summary>
/// Drive temperatures from Windows Storage WMI (MSFT_StorageReliabilityCounter, the same data Drive health reads). The counters need
/// administrator rights, so this runs in the Agent. Drive temperatures change slowly, so one read is reused for a few seconds,
/// and a read that takes too long is skipped so sensor polling never stalls.
/// </summary>
public sealed class WmiDriveTemperatureSource(IWmiSource wmi, TimeSpan? reuseFor = null, TimeSpan? timeout = null, Func<DateTime>? utcNow = null)
    : IDriveTemperatureSource
{
    private readonly TimeSpan _reuseFor = reuseFor ?? TimeSpan.FromSeconds(10);
    private readonly TimeSpan _timeout = timeout ?? TimeSpan.FromSeconds(5);
    private readonly Func<DateTime> _now = utcNow ?? (() => DateTime.UtcNow);
    private readonly object _gate = new();
    private IReadOnlyList<DriveTemperatureSample>? _last;
    private DateTime _lastAt;

    public IReadOnlyList<DriveTemperatureSample> Read()
    {
        lock (_gate)
        {
            if (_last is not null && _now() - _lastAt < _reuseFor) return _last;
            using var cts = new CancellationTokenSource(_timeout);
            var drives = DriveReader.ReadWmiAsync(wmi, cts.Token).WaitAsync(_timeout).GetAwaiter().GetResult();
            _last = drives is null ? [] : [.. drives.Select(d => new DriveTemperatureSample(d.Name, d.TemperatureC))];
            _lastAt = _now();
            return _last;
        }
    }
}

/// <summary>
/// Our own sensor readers come first; LibreHardwareMonitor only fills the gaps. For a GPU or drive that one of our readers
/// measured, LHM's live temperatures for that device are dropped (its fans and the drive's reported limits stay), and devices
/// only LHM sees are kept. CPU package temperatures and board fans have no reader of ours, so they always come from LHM.
/// </summary>
public static class OwnSensorSources
{
    public const string DriveSensorName = "Temperature";

    /// <summary>Valid GPU temperatures from the first source that has any (same rules as before: plausible values, hottest per adapter).</summary>
    public static List<SensorReading> ReadGpu(IReadOnlyList<IGpuTemperatureSource> sources, ILogger? log = null) =>
        GpuTemperatureFallback.Apply([], sources, log);

    public static List<SensorReading> ReadDrives(IDriveTemperatureSource? source, ILogger? log = null)
    {
        if (source is null) return [];
        IReadOnlyList<DriveTemperatureSample> samples;
        try { samples = source.Read(); }
        catch (Exception ex) { log.Warn($"Drive temperatures from Windows failed: {ex.Message}"); return []; }
        return [.. samples
            .Where(s => !string.IsNullOrWhiteSpace(s.DriveName) && GpuTemperatureFallback.Valid(s.Celsius).HasValue)
            .Select(s => new SensorReading(s.DriveName.Trim(), HardwareKind.Storage, DriveSensorName, SensorKind.Temperature,
                GpuTemperatureFallback.Valid(s.Celsius), null, null, "°C"))];
    }

    /// <summary>Our readings plus whatever LHM has for devices or sensors ours didn't cover.</summary>
    public static List<SensorReading> Merge(IReadOnlyList<SensorReading> own, IReadOnlyList<SensorReading> lhm)
    {
        var covered = own.Where(r => r.SensorType == SensorKind.Temperature && r.IsLive).ToList();
        var list = new List<SensorReading>(own);
        foreach (var r in lhm)
        {
            var duplicate = r.SensorType == SensorKind.Temperature && r.IsLive &&
                covered.Any(o => o.HardwareType == r.HardwareType && SameDevice(o.HardwareName, r.HardwareName));
            if (!duplicate) list.Add(r);
        }
        return list;
    }

    /// <summary>
    /// Same device under two readers' names. LHM sometimes adds a vendor prefix ("NVIDIA NVIDIA GeForce RTX 4060") or drops a
    /// suffix, so one name containing the other counts.
    /// </summary>
    public static bool SameDevice(string a, string b)
    {
        a = a.Trim(); b = b.Trim();
        if (a.Length == 0 || b.Length == 0) return false;
        return a.Contains(b, StringComparison.OrdinalIgnoreCase) || b.Contains(a, StringComparison.OrdinalIgnoreCase);
    }
}
