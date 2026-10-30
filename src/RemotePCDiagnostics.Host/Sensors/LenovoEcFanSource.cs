using System.Management;
using LibreHardwareMonitor.PawnIo;
using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Host.Sensors;

/// <summary>
/// Host wiring for <see cref="EcFanMonitor"/>: WMI model check, PawnIO detection, LibreHardwareMonitorLib 0.9.6's public
/// <see cref="LpcAcpiEc"/> (loads the signed PawnIO "LpcACPIEC" module embedded in LHM; exposes ioctl_pio_read/ioctl_pio_write
/// port access) and the shared "Global\Access_EC" mutex. LHM's WindowsEmbeddedControllerIO is not used because it writes the
/// EC bank register (0xFF); our own read-only ACPI EC protocol (<see cref="AcpiEcReader"/>) runs on top of the port access.
/// </summary>
public static class LenovoEcFanSource
{
    public static IEcFanSource Create(Action<string> log)
    {
        if (!OperatingSystem.IsWindows()) return new NoEcFanSource();
        return new EcFanMonitor(ReadModel, CheckPawnIo, () => new PawnIoEcPortIo(), new GlobalEcMutex(), log);
    }

    /// <summary>Win32_ComputerSystemProduct.Name, e.g. "82R4" (Lenovo machine type).</summary>
    private static string? ReadModel()
    {
        using var s = new ManagementObjectSearcher("SELECT Name FROM Win32_ComputerSystemProduct");
        foreach (var o in s.Get()) using (o) return o["Name"]?.ToString();
        return null;
    }

    private static (bool, string) CheckPawnIo()
    {
        try { return LibreHardwareMonitor.PawnIo.PawnIo.IsInstalled ? (true, $"PawnIO {LibreHardwareMonitor.PawnIo.PawnIo.Version}") : (false, "PawnIO driver not installed"); }
        catch (Exception ex) { return (false, $"PawnIO check failed: {ex.Message}"); }
    }

    private sealed class PawnIoEcPortIo : IEcPortIo
    {
        private readonly LpcAcpiEc _ec = new();
        public byte ReadPort(byte port) => _ec.ReadPort(port);
        public void WritePort(byte port, byte value) => _ec.WritePort(port, value);
        public void Dispose() => _ec.Close();
    }

    /// <summary>Same named mutex LHM and other EC tools use. Thread-affine: EcFanMonitor enters and exits within one call.</summary>
    private sealed class GlobalEcMutex : IEcLock
    {
        private Mutex? _m;
        public bool TryEnter(TimeSpan timeout)
        {
            _m ??= Open();
            try { return _m.WaitOne(timeout); }
            catch (AbandonedMutexException) { return true; } // previous owner died; we now own it
        }
        public void Exit() => _m?.ReleaseMutex();

        private static Mutex Open()
        {
            try { return new Mutex(false, @"Global\Access_EC"); }
            catch (UnauthorizedAccessException) { return Mutex.OpenExisting(@"Global\Access_EC"); }
        }
    }
}
