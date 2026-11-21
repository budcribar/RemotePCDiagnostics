using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.Win32;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Wake;

/// <summary>
/// Reads the adapters, the subnet each one is on, and whether Windows will let a magic packet wake the PC.
/// <c>powercfg /a</c> and <c>powercfg /devicequery wake_armed</c> need no administrator. The magic-packet, pattern,
/// ARP-offload and NS-offload values are the NIC advanced properties (the same settings Get-NetAdapterPowerManagement shows).
/// </summary>
public static class WakeInventory
{
    public static async Task<WakeSnapshot> ReadAsync(SystemCommandRunner commands, CancellationToken ct)
    {
        // The two powercfg queries are independent. Run them together so a slow one does not wait on the other.
        var statesTask = ReadPowerCfgAsync(commands, ["/a"], ct);
        var armedTask = ReadPowerCfgAsync(commands, DeviceWake.QueryArgs, ct);
        await Task.WhenAll(statesTask, armedTask).ConfigureAwait(false);
        var states = await statesTask.ConfigureAwait(false);
        var armedText = await armedTask.ConfigureAwait(false);
        WakePowerInfo? power = null;
        var powerRead = false;
        if (states is { ExitCode: 0 })
        {
            power = WakePowerInfo.Parse(states.StdOut);
            powerRead = power is not null;
        }
        IReadOnlyList<string>? armed = armedText is { ExitCode: 0 } ? DeviceWake.ParseArmed(armedText.StdOut) : null;

        var (settings, registryRead) = ReadNicSettings();
        return WakeSnapshot.Compose(power, powerRead, armed, settings, registryRead, ReadAdapterFacts());
    }

    private static async Task<ProcessResult?> ReadPowerCfgAsync(
        SystemCommandRunner commands, IReadOnlyList<string> args, CancellationToken ct)
    {
        try
        {
            return await commands.RunAsync(DeviceWake.PowerCfg, args, TimeSpan.FromSeconds(8), ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return null; }
    }

    /// <summary>Up IPv4 interfaces a wake packet can leave from, including a virtual switch that bridges to the shop LAN.</summary>
    public static IReadOnlyList<WakeEndpoint> ReadSendEndpoints()
    {
        var list = new List<WakeEndpoint>();
        NetworkInterface[] ifaces;
        try { ifaces = NetworkInterface.GetAllNetworkInterfaces(); }
        catch { return list; }

        foreach (var iface in ifaces)
        {
            try
            {
                if (iface.OperationalStatus != OperationalStatus.Up) continue;
                if (iface.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;
                foreach (var uni in iface.GetIPProperties().UnicastAddresses)
                {
                    if (uni.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                    if (IPAddress.IsLoopback(uni.Address) || WakeAddresses.IsLinkLocal(uni.Address)) continue;
                    var prefix = uni.PrefixLength;
                    if (prefix is <= 0 or > 32) prefix = MaskPrefix(uni);
                    if (prefix is <= 0 or >= 32) continue;
                    if (!WakeAddresses.TrySubnet(uni.Address, prefix, out _, out var broadcast)) continue;
                    if (uni.Address.Equals(broadcast)) continue;
                    list.Add(new(iface.Name, uni.Address.ToString(), broadcast.ToString(), prefix));
                }
            }
            catch { }
        }
        return list;
    }

    private static int MaskPrefix(UnicastIPAddressInformation uni)
    {
        try { return WakeAddresses.PrefixOf(uni.IPv4Mask); }
        catch { return 0; }
    }

    private static List<WakeAdapterFacts> ReadAdapterFacts()
    {
        var facts = new List<WakeAdapterFacts>();
        NetworkInterface[] ifaces;
        try { ifaces = NetworkInterface.GetAllNetworkInterfaces(); }
        catch { return facts; }

        foreach (var iface in ifaces)
        {
            try
            {
                var kind = AdapterKind(iface.NetworkInterfaceType);
                if (!WakeSnapshot.IncludeInReport(iface.Name, iface.Description, kind)) continue;
                var mac = Format(iface.GetPhysicalAddress());
                var id = WakeSnapshot.NormalizeGuid(iface.Id);
                var added = false;
                foreach (var uni in iface.GetIPProperties().UnicastAddresses)
                {
                    if (uni.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                    if (IPAddress.IsLoopback(uni.Address) || WakeAddresses.IsLinkLocal(uni.Address)) continue;
                    var prefix = uni.PrefixLength;
                    if (prefix is <= 0 or > 32) prefix = MaskPrefix(uni);
                    facts.Add(new(iface.Name, iface.Description, kind, mac, uni.Address.ToString(), prefix, id));
                    added = true;
                }
                if (!added)
                    facts.Add(new(iface.Name, iface.Description, kind, mac, "", 0, id));
            }
            catch { }
        }
        return facts;
    }

    /// <summary>Ethernet and Wi-Fi only. Anything else is <c>Other</c> and is not stored.</summary>
    public static string AdapterKind(NetworkInterfaceType type) => type switch
    {
        NetworkInterfaceType.Wireless80211 => "Wi-Fi",
        NetworkInterfaceType.Ethernet or NetworkInterfaceType.FastEthernetT
            or NetworkInterfaceType.FastEthernetFx or NetworkInterfaceType.GigabitEthernet => "Ethernet",
        _ => "Other",
    };

    private static string Format(PhysicalAddress address)
    {
        try
        {
            var bytes = address.GetAddressBytes();
            return bytes.Length == 6 ? WakeAddresses.FormatMac(bytes) : "";
        }
        catch { return ""; }
    }

    private static (Dictionary<string, WakeNicSetting> Settings, bool Read) ReadNicSettings()
    {
        var map = new Dictionary<string, WakeNicSetting>(StringComparer.OrdinalIgnoreCase);
        if (!OperatingSystem.IsWindows()) return (map, false);
        try
        {
            using var root = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}");
            if (root is null) return (map, false);
            foreach (var sub in root.GetSubKeyNames())
            {
                if (!int.TryParse(sub, NumberStyles.None, CultureInfo.InvariantCulture, out _)) continue;
                try
                {
                    using var inst = root.OpenSubKey(sub);
                    if (inst is null) continue;
                    var id = WakeSnapshot.NormalizeGuid(inst.GetValue("NetCfgInstanceId") as string);
                    if (id.Length == 0) continue;
                    var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
                    foreach (var name in inst.GetValueNames())
                        values[name] = RegString(inst.GetValue(name));
                    map[id] = WakeNicSetting.FromValues(values);
                }
                catch { }
            }
            return (map, true);
        }
        catch { return (map, false); }
    }

    private static string? RegString(object? value) => value switch
    {
        null => null,
        string s => s,
        int i => i.ToString(CultureInfo.InvariantCulture),
        uint i => i.ToString(CultureInfo.InvariantCulture),
        _ => null,
    };
}
