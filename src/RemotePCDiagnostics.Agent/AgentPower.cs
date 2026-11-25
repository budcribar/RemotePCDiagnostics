using System.Runtime.InteropServices;
using RemotePCDiagnostics.Agent.Core;

namespace RemotePCDiagnostics.Agent;

/// <summary>Reads whether the PC is on AC or battery (GetSystemPowerStatus). A PC with no battery is on AC.</summary>
internal static class AgentPower
{
    public static PowerReading Read()
    {
        try
        {
            if (!OperatingSystem.IsWindows() || !GetSystemPowerStatus(out var s))
                return PowerReading.Unknown;
            if (s.BatteryFlag == 128)
                return PowerReading.Ac;
            return s.ACLineStatus switch
            {
                1 => PowerReading.Ac,
                0 => PowerReading.Battery,
                _ => PowerReading.Unknown,
            };
        }
        catch
        {
            return PowerReading.Unknown;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_POWER_STATUS { public byte ACLineStatus, BatteryFlag, BatteryLifePercent, SystemStatusFlag; public int BatteryLifeTime, BatteryFullLifeTime; }

    [DllImport("kernel32.dll")] private static extern bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS s);
}
