using System.Management;
using RemotePCDiagnostics.Core.Sensors;

namespace RemotePCDiagnostics.Host.Sensors;

/// <summary>root\WMI MSAcpi_ThermalZoneTemperature (needs admin). Values are tenths of Kelvin.</summary>
public sealed class WmiThermalZoneReader : IThermalZoneReader
{
    public IReadOnlyList<double> ReadTenthsKelvin()
    {
        var list = new List<double>();
        using var s = new ManagementObjectSearcher(@"root\WMI", "SELECT CurrentTemperature FROM MSAcpi_ThermalZoneTemperature");
        foreach (var o in s.Get()) using (o) list.Add(Convert.ToDouble(o["CurrentTemperature"]));
        return list;
    }
}
