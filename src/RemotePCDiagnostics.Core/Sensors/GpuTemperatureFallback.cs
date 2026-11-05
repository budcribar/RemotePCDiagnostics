namespace RemotePCDiagnostics.Core.Sensors;

/// <summary>One GPU temperature as reported by a Windows/driver source. Celsius null = source answered but had no value.</summary>
public sealed record GpuTemperatureSample(string AdapterName, double? Celsius);

/// <summary>
/// A GPU temperature source other than LibreHardwareMonitor (e.g. the WDDM kernel adapter perf data Task Manager uses).
/// Implementations must not throw for "not supported"; they may throw on failure (the caller catches) and must be quick.
/// </summary>
public interface IGpuTemperatureSource
{
    string Name { get; }
    IReadOnlyList<GpuTemperatureSample> Read();
}

/// <summary>
/// Adds GPU temperature readings from Windows when the hardware library has no valid GPU temperature
/// (e.g. AMD Ryzen APU iGPUs where LHM reports nothing). Sources are tried in order; the first one that returns at
/// least one valid value wins. The reading comes from the GPU driver via Windows, so it is NOT flagged approximate.
/// </summary>
public static class GpuTemperatureFallback
{
    public const string SensorName = "GPU temperature (from Windows)";

    /// <summary>Plausible °C or null (null/NaN/≤0/≥150 = no data).</summary>
    public static double? Valid(double? c) => c is { } v && !double.IsNaN(v) && v > 0 && v < 150 ? Math.Round(v, 1) : null;

    public static List<SensorReading> Apply(IReadOnlyList<SensorReading> readings, IReadOnlyList<IGpuTemperatureSource>? sources, ILogger? log = null)
    {
        var list = readings.ToList();
        if (sources is null || sources.Count == 0) return list;
        if (list.Any(r => r.SensorType == SensorKind.Temperature && r.HardwareType == HardwareKind.Gpu && r.IsLive)) return list;
        foreach (var src in sources)
        {
            IReadOnlyList<GpuTemperatureSample> samples;
            try { samples = src.Read() ?? []; }
            catch (Exception ex) { log.Warn($"GPU temperature fallback: {src.Name} failed: {ex.Message}"); continue; }
            log.Info($"GPU temperature fallback: {src.Name} returned [{string.Join("; ", samples.Select(s => $"{s.AdapterName}={(s.Celsius?.ToString("0.0") ?? "null")}"))}]");
            var valid = samples.Select(s => (s.AdapterName, C: Valid(s.Celsius))).Where(s => s.C.HasValue)
                .GroupBy(s => s.AdapterName).Select(g => (Name: g.Key, C: g.Max(x => x.C)!.Value)).ToList();
            if (valid.Count == 0) continue;
            foreach (var (name, c) in valid)
                list.Add(new SensorReading(string.IsNullOrWhiteSpace(name) ? "GPU" : name, HardwareKind.Gpu, SensorName, SensorKind.Temperature, c, null, null, "°C"));
            log.Info($"GPU temperature fallback: using {src.Name}");
            return list;
        }
        log.Info("GPU temperature fallback: no source returned a valid GPU temperature");
        return list;
    }
}

/// <summary>Runs another source with a short timeout; after a timeout the source is skipped for the rest of the session.</summary>
public sealed class TimeoutGpuTemperatureSource(IGpuTemperatureSource inner, TimeSpan timeout) : IGpuTemperatureSource
{
    private readonly object _gate = new();
    private Task<IReadOnlyList<GpuTemperatureSample>>? _pending;
    private bool _disabled;
    public string Name => inner.Name;

    public IReadOnlyList<GpuTemperatureSample> Read()
    {
        Task<IReadOnlyList<GpuTemperatureSample>> t;
        lock (_gate)
        {
            if (_disabled) throw new TimeoutException("disabled after an earlier timeout");
            t = _pending ??= Task.Run(inner.Read);
        }
        bool completed;
        try { completed = t.Wait(timeout); }
        catch
        {
            lock (_gate) { if (ReferenceEquals(_pending, t)) _pending = null; }
            throw;
        }
        lock (_gate)
        {
            if (!completed)
            {
                _disabled = true;
                throw new TimeoutException($"no answer within {timeout.TotalMilliseconds:0} ms");
            }
            if (ReferenceEquals(_pending, t)) _pending = null;
        }
        return t.GetAwaiter().GetResult();
    }
}
