using System.Management;
using System.Runtime.Versioning;
using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Core.Sensors;

/// <summary>root\WMI MSAcpi_ThermalZoneTemperature (needs admin). Values are tenths of Kelvin.</summary>
[SupportedOSPlatform("windows")]
public sealed class WmiThermalZoneReader : IThermalZoneReader
{
    public IReadOnlyList<double> ReadTenthsKelvin()
    {
        if (!OperatingSystem.IsWindows()) return [];
        var list = new List<double>();
        using var s = new ManagementObjectSearcher(@"root\WMI", "SELECT CurrentTemperature FROM MSAcpi_ThermalZoneTemperature");
        foreach (var o in s.Get()) using (o) list.Add(Convert.ToDouble(o["CurrentTemperature"]));
        return list;
    }
}
