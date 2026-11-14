using System.Security.Principal;
using LibreHardwareMonitor.Hardware;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Sensors;

/// <summary>ISensorProvider backed by LibreHardwareMonitorLib. Many sensors (CPU MSRs, SuperIO fans) need admin.</summary>
public sealed class LhmSensorProvider(
    IEcFanSource ecFan,
    IElevatedCommandBridge? elevatedBridge = null,
    ILogger? logger = null) : ISensorProvider, IDisposable
{
    private readonly ILogger? _logger = logger;
    private readonly object _gate = new();
    private Computer? _computer;
    private string? _openError;
    private bool _loggedRead, _fallbackLogged, _gpuLogged;
    private readonly IThermalZoneReader? _zones = OperatingSystem.IsWindows() ? new WmiThermalZoneReader() : null;
    // Used only when LHM has no valid GPU temperature (e.g. Ryzen APU iGPUs). Order = preference.
    private readonly Lazy<(bool Available, string Detail)> _driver = new(PawnIoProbe.Check);
    private readonly IGpuTemperatureSource[] _gpuSources = OperatingSystem.IsWindows()
        ? [new TimeoutGpuTemperatureSource(new D3dkmtGpuTemperatureSource(), TimeSpan.FromSeconds(2))] : [];

    public ModuleAvailability CheckAvailability()
    {
        lock (_gate)
        {
            EnsureOpen();
            return _openError is null ? ModuleAvailability.Available : ModuleAvailability.Unavailable("Temperature monitoring couldn't start on this PC.");
        }
    }

    public SensorSnapshot Read()
    {
        lock (_gate)
        {
            if (elevatedBridge is { IsConnected: true } && !IsElevated())
            {
                try
                {
                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                    var remote = elevatedBridge.ReadSensorsAsync(cts.Token).GetAwaiter().GetResult();
                    if (remote is { Readings.Count: > 0 })
                        return remote;
                }
                catch (Exception ex)
                {
                    _logger?.Warn($"Failed to read sensors from elevated helper: {ex.Message}");
                }
            }

            EnsureOpen();
            if (_computer is null) throw new InvalidOperationException("Temperature monitoring couldn't start on this PC.");
            var list = new List<SensorReading>();
            foreach (var hw in _computer.Hardware) Collect(hw, list);
            if (!_loggedRead) { _loggedRead = true; LogInventory(_computer, "first read"); }
            if (!_fallbackLogged && !list.Any(r => r.HardwareType == HardwareKind.Cpu && r.SensorType == SensorKind.Temperature))
                _logger?.Info("LibreHardwareMonitor: no usable CPU temperature (sensor missing or 0). LHM 0.9.5+ needs the PawnIO driver for low-level CPU access; using ACPI thermal zone fallback if available.");
            var first = !_fallbackLogged; _fallbackLogged = true;
            var firstGpu = !_gpuLogged; _gpuLogged = true;
            if (firstGpu) _logger?.Info($"GPU temperature: LHM valid GPU temperature={(list.Any(r => r.HardwareType == HardwareKind.Gpu && r.SensorType == SensorKind.Temperature && r.IsLive) ? "yes" : "no")}; fallback sources={string.Join(", ", _gpuSources.Select(s => s.Name))}");
            list = GpuTemperatureFallback.Apply(list, _gpuSources, firstGpu ? _logger : null);
            // CPU fallbacks (only when LHM has no valid CPU temp): APU shared die from the Windows GPU reading, then ACPI thermal zone.
            var cpuName = _computer.Hardware.FirstOrDefault(h => h.HardwareType == HardwareType.Cpu)?.Name;
            list = CpuTemperatureFallback.ApplyApuDie(list, cpuName, first ? _logger : null);
            list = ThermalZoneFallback.Apply(list, _zones, first ? _logger : null);
            // EC fan diagnostic (82R4 only; empty elsewhere or until a plausible reading). Never throws.
            if (!list.Any(r => r.SensorType == SensorKind.Fan && r.HasData)) list.AddRange(ecFan.Read());
            var driver = _driver.Value;
            if (first) _logger?.Info($"CPU sensor driver (PawnIO, needed by LHM 0.9.5+ for Ryzen/Intel CPU temperatures): {driver.Detail}");
            var cpuNote = CpuTemperatureFallback.Note(list, driver.Available);
            var elevated = IsElevated();
            return new SensorSnapshot(list, elevated, elevated ? null : "Some readings need administrator rights and may be missing.", cpuNote);
        }
    }

    private void EnsureOpen()
    {
        if (_computer is not null || _openError is not null) return;
        try
        {
            var elevated = IsElevated();
            var c = new Computer
            {
                IsCpuEnabled = true,
                IsGpuEnabled = true,
                // SuperIO / embedded-controller probes require ring-0 driver access; skip in un-elevated Store launches.
                IsMotherboardEnabled = elevated,
                IsStorageEnabled = true,
                IsMemoryEnabled = true,
                IsControllerEnabled = elevated,
            };
            c.Open();
            _computer = c;
            LogInventory(c, "opened");
        }
        catch (Exception ex) { _openError = ex.Message; _logger?.Error($"LibreHardwareMonitor open failed: {ex}"); }
    }

    private static void Collect(IHardware hw, List<SensorReading> list)
    {
        try { hw.Update(); } catch { /* one device failing should not hide the rest */ }
        var kind = Map(hw.HardwareType);
        foreach (var s in hw.Sensors)
        {
            SensorKind? sk = s.SensorType switch { SensorType.Temperature => SensorKind.Temperature, SensorType.Fan => SensorKind.Fan, _ => null };
            if (sk is null) continue;
            var reading = new SensorReading(hw.Name, kind, s.Name, sk.Value, s.Value, s.Min, s.Max, SensorReading.UnitFor(sk.Value));
            if (reading.HasData) list.Add(reading); // 0 °C / null = sensor not really supported here
        }
        foreach (var sub in hw.SubHardware) Collect(sub, list);
    }

    /// <summary>Log-only dump of everything the library exposes (never shown in the UI).</summary>
    private void LogInventory(Computer c, string when)
    {
        try
        {
            var sb = new System.Text.StringBuilder($"LibreHardwareMonitor devices ({when}):");
            void Dump(IHardware hw, string indent)
            {
                sb.Append($"\n{indent}{hw.Name} [{hw.HardwareType}] sensors={hw.Sensors.Length}");
                foreach (var s in hw.Sensors) sb.Append($"\n{indent}  {s.Name} [{s.SensorType}] = {(s.Value?.ToString("0.##") ?? "null")}");
                foreach (var sub in hw.SubHardware) Dump(sub, indent + "  ");
            }
            foreach (var hw in c.Hardware) Dump(hw, "  ");
            _logger?.Info(sb.ToString());
        }
        catch (Exception ex) { _logger?.Warn($"LibreHardwareMonitor inventory log failed: {ex.Message}"); }
    }

    private static HardwareKind Map(HardwareType t) => t switch
    {
        HardwareType.Cpu => HardwareKind.Cpu,
        HardwareType.GpuNvidia or HardwareType.GpuAmd or HardwareType.GpuIntel => HardwareKind.Gpu,
        HardwareType.Motherboard or HardwareType.SuperIO => HardwareKind.Motherboard,
        HardwareType.Storage => HardwareKind.Storage,
        HardwareType.Memory => HardwareKind.Memory,
        HardwareType.Cooler or HardwareType.EmbeddedController => HardwareKind.Controller,
        _ => HardwareKind.Other,
    };

    private static bool IsElevated() =>
        OperatingSystem.IsWindows() && ElevationService.DetectProcessElevated();

    /// <summary>Resets the cached Computer instance and diagnostic state so sensors can be re-evaluated with updated elevation or privileges.</summary>
    public void Reset()
    {
        lock (_gate)
        {
            try { _computer?.Close(); } catch { }
            _computer = null;
            _openError = null;
            _loggedRead = false;
            _fallbackLogged = false;
            _gpuLogged = false;
        }
    }

    public void Dispose() { lock (_gate) { _computer?.Close(); _computer = null; } try { ecFan.Dispose(); } catch { } }
}
