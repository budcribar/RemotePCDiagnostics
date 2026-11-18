using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.Win32;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Platform;

/// <summary>
/// Native in-process C# reader for network adapter configuration, IP, DNS, proxy, and adapter traffic statistics.
/// Replaces IpConfig.ps1 and NetAdapterStatistics.ps1 to eliminate ~600 ms of PowerShell overhead.
/// </summary>
public static class NetworkInfoReader
{
    public static IpConfigSnapshot ReadIpConfig()
    {
        var adapters = new List<ActiveAdapterIp>();

        try
        {
            var ifaces = NetworkInterface.GetAllNetworkInterfaces();
            foreach (var iface in ifaces)
            {
                if (iface.OperationalStatus != OperationalStatus.Up)
                    continue;

                // Skip loopback
                if (iface.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                    continue;

                var ipProps = iface.GetIPProperties();
                var ipv4 = ipProps.UnicastAddresses
                    .FirstOrDefault(u => u.Address.AddressFamily == AddressFamily.InterNetwork)?.Address.ToString() ?? "";

                var gateway = ipProps.GatewayAddresses
                    .FirstOrDefault(g => g.Address.AddressFamily == AddressFamily.InterNetwork)?.Address.ToString() ?? "";

                var dnsServers = ipProps.DnsAddresses
                    .Where(d => d.AddressFamily == AddressFamily.InterNetwork)
                    .Select(d => d.ToString())
                    .ToList();
                var dnsStr = string.Join(", ", dnsServers);

                bool? dnsManual = null;
                if (OperatingSystem.IsWindows())
                {
                    try
                    {
                        var guid = iface.Id;
                        using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{guid}");
                        var nameServer = key?.GetValue("NameServer") as string;
                        dnsManual = !string.IsNullOrWhiteSpace(nameServer);
                    }
                    catch
                    {
                    }
                }

                adapters.Add(new ActiveAdapterIp(
                    Alias: iface.Name,
                    Description: iface.Description,
                    IPv4: ipv4,
                    Gateway: gateway,
                    Dns: dnsStr,
                    DnsManual: dnsManual));
            }
        }
        catch
        {
        }

        var (proxyEnabled, proxyServer) = ReadProxySettings();
        return new IpConfigSnapshot(adapters, proxyEnabled, proxyServer);
    }

    private static (bool ProxyEnabled, string ProxyServer) ReadProxySettings()
    {
        if (!OperatingSystem.IsWindows())
            return (false, "");

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
            if (key is not null)
            {
                var enabled = (key.GetValue("ProxyEnable") as int? ?? 0) == 1;
                var server = (key.GetValue("ProxyServer") as string)?.Trim() ?? "";
                return (enabled, enabled ? server : "");
            }
        }
        catch
        {
        }

        return (false, "");
    }

    public static Dictionary<string, AdapterStats> ReadAdapterStatistics()
    {
        var result = new Dictionary<string, AdapterStats>(StringComparer.OrdinalIgnoreCase);

        try
        {
            var ifaces = NetworkInterface.GetAllNetworkInterfaces();
            foreach (var iface in ifaces)
            {
                var stats = iface.GetIPv4Statistics();
                // Match by iface.Name
                result[iface.Name] = new AdapterStats(
                    Name: iface.Name,
                    PacketsIn: stats.UnicastPacketsReceived + stats.NonUnicastPacketsReceived,
                    PacketsOut: stats.UnicastPacketsSent + stats.NonUnicastPacketsSent,
                    ErrorsIn: stats.IncomingPacketsWithErrors,
                    ErrorsOut: stats.OutgoingPacketsWithErrors,
                    DropsIn: stats.IncomingPacketsDiscarded,
                    DropsOut: OperatingSystem.IsWindows() ? stats.OutgoingPacketsDiscarded : 0);
            }
        }
        catch
        {
        }

        return result;
    }
}

public sealed record AdapterStats(
    string Name,
    long PacketsIn,
    long PacketsOut,
    long ErrorsIn,
    long ErrorsOut,
    long DropsIn,
    long DropsOut);
