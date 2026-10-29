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
            list.Add(new SensorReading(hw.Name, kind, s.Name, sk.Value, s.Value, s.Min, s.Max, SensorReading.UnitFor(sk.Value)));
        }
        foreach (var sub in hw.SubHardware) Collect(sub, list);
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
