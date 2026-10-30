using System.Security.Principal;
using LibreHardwareMonitor.Hardware;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Host.Sensors;

/// <summary>ISensorProvider backed by LibreHardwareMonitorLib. Many sensors (CPU MSRs, SuperIO fans) need admin.</summary>
public sealed class LhmSensorProvider : ISensorProvider, IDisposable
{
    private readonly object _gate = new();
    private Computer? _computer;
    private string? _openError;
    private bool _loggedRead, _fallbackLogged;
    private readonly IThermalZoneReader? _zones = OperatingSystem.IsWindows() ? new WmiThermalZoneReader() : null;

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
            EnsureOpen();
            if (_computer is null) throw new InvalidOperationException("Temperature monitoring couldn't start on this PC.");
            var list = new List<SensorReading>();
            foreach (var hw in _computer.Hardware) Collect(hw, list);
            if (!_loggedRead) { _loggedRead = true; LogInventory(_computer, "first read"); }
            if (!_fallbackLogged && !list.Any(r => r.HardwareType == HardwareKind.Cpu && r.SensorType == SensorKind.Temperature))
                App.Log("LibreHardwareMonitor: no usable CPU temperature (sensor missing or 0). LHM 0.9.5+ needs the PawnIO driver for low-level CPU access; using ACPI thermal zone fallback if available.");
            var first = !_fallbackLogged; _fallbackLogged = true;
            list = ThermalZoneFallback.Apply(list, _zones, first ? App.Log : null);
            var elevated = IsElevated();
            return new SensorSnapshot(list, elevated, elevated ? null : "Some readings need administrator rights and may be missing.");
        }
    }

    private void EnsureOpen()
    {
        if (_computer is not null || _openError is not null) return;
        try
        {
            var c = new Computer
            {
                IsCpuEnabled = true, IsGpuEnabled = true, IsMotherboardEnabled = true,
                IsStorageEnabled = true, IsMemoryEnabled = true, IsControllerEnabled = true,
            };
            c.Open();
            _computer = c;
            LogInventory(c, "opened");
        }
        catch (Exception ex) { _openError = ex.Message; App.Log($"LibreHardwareMonitor open failed: {ex}"); }
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
    private static void LogInventory(Computer c, string when)
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
            App.Log(sb.ToString());
        }
        catch (Exception ex) { App.Log($"LibreHardwareMonitor inventory log failed: {ex.Message}"); }
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

    private static bool IsElevated()
    {
        if (!OperatingSystem.IsWindows()) return false;
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }

    public void Dispose() { lock (_gate) { _computer?.Close(); _computer = null; } }
}
