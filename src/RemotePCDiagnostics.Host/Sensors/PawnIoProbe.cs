using Microsoft.Win32;

namespace RemotePCDiagnostics.Host.Sensors;

/// <summary>
/// LibreHardwareMonitorLib 0.9.5+ reads CPU temperature registers (AMD SMN / MSRs) through the separately installed,
/// signed PawnIO kernel driver (https://pawnio.eu). It is not bundled: installing a kernel driver needs its own
/// installer and admin consent. Here we only detect whether its service is registered and running.
/// </summary>
public static class PawnIoProbe
{
    public static (bool Available, string Detail) Check()
    {
        try
        {
            if (!OperatingSystem.IsWindows()) return (false, "not Windows");
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\PawnIO");
            if (key is null) return (false, "missing (service HKLM\\...\\Services\\PawnIO not registered; install PawnIO to get CPU temperatures from LHM)");
            var start = key.GetValue("Start");
            return (true, $"registered (Start={start}); if CPU temperatures are still 0 the driver may be blocked (e.g. Memory Integrity/HVCI or vulnerable-driver blocklist) or the CPU unsupported");
        }
        catch (Exception ex) { return (false, $"check failed: {ex.Message}"); }
    }
}
