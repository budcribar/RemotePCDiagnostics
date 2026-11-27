using System.Runtime.InteropServices;
using System.Security.Principal;
using LibreHardwareMonitor.Hardware;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Sensors;

/// <summary>
/// Sensor provider: our own readers first (GPU temperature through Windows, drive temperatures from their reliability counters,
/// ACPI thermal zone), LibreHardwareMonitorLib for what they don't cover (CPU package, board fans). Many sensors need admin.
/// </summary>
public sealed class LhmSensorProvider(
    IEcFanSource ecFan,
    IElevatedCommandBridge? elevatedBridge = null,
    ILogger? logger = null,
    Func<bool>? isLocalProcessElevated = null,
    IDriveTemperatureSource? driveTemperatures = null) : ISensorProvider, IDisposable
{
    private readonly ILogger? _logger = logger;
    private readonly Func<bool> _isLocalElevated = isLocalProcessElevated ?? IsLocalProcessElevated;
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
            // Our own readers (GPU, drives, thermal zone) still work when LHM can't open.
            return _openError is null || _gpuSources.Length > 0 || driveTemperatures is not null || _zones is not null
                ? ModuleAvailability.Available : ModuleAvailability.Unavailable("Temperature monitoring couldn't start on this PC.");
        }
    }

    public SensorSnapshot Read()
    {
        lock (_gate)
        {
            if (elevatedBridge is { IsConnected: true } && !_isLocalElevated())
            {
                try
                {
                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                    var remote = elevatedBridge.ReadSensorsAsync(cts.Token).GetAwaiter().GetResult();
                    if (remote is not null)
                    {
                        return remote with { IsElevated = true, Note = null };
                    }
                }
                catch (Exception ex)
                {
                    _logger?.Warn($"Failed to read sensors from elevated helper: {ex.Message}");
                }
            }

            EnsureOpen();
            // Our own readers first (GPU through Windows, drives through their reliability counters); LHM fills the gaps.
            var firstGpu = !_gpuLogged; _gpuLogged = true;
            var own = OwnSensorSources.ReadGpu(_gpuSources, firstGpu ? _logger : null);
            own.AddRange(OwnSensorSources.ReadDrives(driveTemperatures, firstGpu ? _logger : null));
            var lhm = new List<SensorReading>();
            if (_computer is not null)
            {
                foreach (var hw in _computer.Hardware) Collect(hw, lhm);
                if (!_loggedRead) { _loggedRead = true; LogInventory(_computer, "first read"); }
            }
            var list = OwnSensorSources.Merge(own, lhm);
            if (firstGpu) _logger?.Info($"Sensors: own readers gave {own.Count} reading(s) ({string.Join(", ", own.Select(r => $"{r.HardwareName}={r.Value:0.0}"))}); LibreHardwareMonitor {(_computer is null ? "not open" : $"gave {lhm.Count}")}; merged {list.Count}");
            if (!_fallbackLogged && !list.Any(r => r.HardwareType == HardwareKind.Cpu && r.SensorType == SensorKind.Temperature))
                _logger?.Info("LibreHardwareMonitor: no usable CPU temperature (sensor missing or 0). LHM 0.9.5+ needs the PawnIO driver for low-level CPU access; using ACPI thermal zone fallback if available.");
            var first = !_fallbackLogged; _fallbackLogged = true;
            // CPU fallbacks (only when LHM has no valid CPU temp): APU shared die from the Windows GPU reading, then ACPI thermal zone.
            var cpuName = _computer?.Hardware.FirstOrDefault(h => h.HardwareType == HardwareType.Cpu)?.Name;
            list = CpuTemperatureFallback.ApplyApuDie(list, cpuName, first ? _logger : null);
            list = ThermalZoneFallback.Apply(list, _zones, first ? _logger : null);
            // EC fan diagnostic (82R4 only; empty elsewhere or until a plausible reading). Never throws.
            if (!list.Any(r => r.SensorType == SensorKind.Fan && r.HasData)) list.AddRange(ecFan.Read());
            var driver = _driver.Value;
            if (first) _logger?.Info($"CPU sensor driver (PawnIO, needed by LHM 0.9.5+ for Ryzen/Intel CPU temperatures): {driver.Detail}");
            var cpuNote = CpuTemperatureFallback.Note(list, driver.Available);
            // Only when nothing at all could be read and LHM didn't open is the check unable to start.
            if (_computer is null && !list.Any(r => r.HasData)) throw new InvalidOperationException("Temperature monitoring couldn't start on this PC.");
            var elevated = IsElevated();
            return new SensorSnapshot(list, elevated, elevated ? null : "Some readings need administrator rights and may be missing.", cpuNote);
        }
    }

    private void EnsureOpen()
    {
        if (_computer is not null || _openError is not null) return;
        try
        {
            var elevated = _isLocalElevated();
            var cpuSupported = SupportsLhmCpu(RuntimeInformation.ProcessArchitecture);
            if (!cpuSupported) _logger?.Info($"LibreHardwareMonitor CPU sensors skipped: they use x86 CPUID, which crashes in a {RuntimeInformation.ProcessArchitecture} process. CPU temperature comes from the ACPI thermal zone instead.");
            var c = new Computer
            {
                // LHM's CPU group runs x86 CPUID code; on ARM64 (Snapdragon) it throws an SEHException that aborts Open() for every device.
                IsCpuEnabled = cpuSupported,
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

    /// <summary>LibreHardwareMonitor's CPU sensors only work in x86/x64 processes (they execute the CPUID instruction).</summary>
    public static bool SupportsLhmCpu(Architecture processArchitecture) =>
        processArchitecture is Architecture.X64 or Architecture.X86;

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

    private static bool IsLocalProcessElevated() =>
        OperatingSystem.IsWindows() && ElevationService.DetectProcessElevated();

    private bool IsElevated() =>
        _isLocalElevated() || elevatedBridge is { IsConnected: true };

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
