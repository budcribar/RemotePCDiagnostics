using System.Management;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Platform;

/// <summary>
/// Native in-process C# reader for problem devices (Win32_PnPEntity where ConfigManagerErrorCode != 0).
/// Standard user processes can query Win32_PnPEntity via WMI without Administrator privileges.
/// Replaces ProblemDevices.ps1 to eliminate ~400 ms of PowerShell overhead.
/// </summary>
public static class ProblemDevicesReader
{
    public static List<ProblemDevice> Read()
    {
        var result = new List<ProblemDevice>();
        if (!OperatingSystem.IsWindows())
            return result;

        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT Name, PNPClass, DeviceID, ConfigManagerErrorCode, Status FROM Win32_PnPEntity WHERE ConfigManagerErrorCode <> 0");
            using var collection = searcher.Get();

            foreach (var item in collection)
            {
                if (item is not ManagementObject mo)
                    continue;

                using (mo)
                {
                    var name = mo["Name"]?.ToString() ?? "Unknown device";
                    var pnpClass = mo["PNPClass"]?.ToString() ?? "";
                    var deviceId = mo["DeviceID"]?.ToString() ?? "";
                    var errorCode = 0;
                    if (mo["ConfigManagerErrorCode"] is uint uCode) errorCode = (int)uCode;
                    else if (mo["ConfigManagerErrorCode"] is int iCode) errorCode = iCode;
                    var status = mo["Status"]?.ToString() ?? "";

                    result.Add(new ProblemDevice(name, pnpClass, deviceId, errorCode, status));
                }
            }
        }
        catch
        {
        }

        return result;
    }
}
