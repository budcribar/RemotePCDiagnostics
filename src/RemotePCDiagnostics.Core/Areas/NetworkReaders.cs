using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Recording;

namespace RemotePCDiagnostics.Core.Areas;

// Where the Network check reads the adapters and the IP configuration from. The app registers the WMI reader (WMI through the Agent, the
// registry in the app); the Store edition also has the legacy osquery + PowerShell reader (RemotePCDiagnostics.Legacy) for when the Agent
// isn't connected. Wi-Fi signal (netsh), event history (wevtutil) and the reachability probes are read by the check itself, as before.

/// <summary>One network adapter with traffic and error counters.</summary>
/// <param name="ConnectionStatus">Win32_NetworkAdapter NetConnectionStatus as a number in text ("2" = connected); "" when not reported.</param>
public sealed record NetworkAdapter(
    string Name, string Description, string Manufacturer, string Mac, string ConnectionStatus, bool? Enabled, bool? Physical,
    long? SpeedBps, long? PacketsIn, long? PacketsOut, long? ErrorsIn, long? ErrorsOut, long? DropsIn, long? DropsOut)
{
    /// <summary>One row of osquery <c>interface_details</c> (all values text).</summary>
    public static NetworkAdapter FromRow(IReadOnlyDictionary<string, string> r) => new(
        FirstNonEmpty(r.Str("connection_id"), r.Str("friendly_name"), r.Str("description"), r.Str("interface")),
        r.Str("description"), r.Str("manufacturer"), r.Str("mac"), r.Str("connection_status"), Bool(r.Str("enabled")), Bool(r.Str("physical_adapter")),
        Positive(r.Long("speed")) ?? Positive(r.Long("link_speed")) * 1_000_000,
        r.Long("ipackets"), r.Long("opackets"), r.Long("ierrors"), r.Long("oerrors"), r.Long("idrops"), r.Long("odrops"));

    internal static string FirstNonEmpty(params string[] s) => s.FirstOrDefault(x => x.Length > 0) ?? "";
    private static bool? Bool(string s) => s switch { "1" or "true" or "True" => true, "0" or "false" or "False" => false, _ => null };
    /// <summary>A real speed: WMI reports long.MaxValue (and osquery 0) when it doesn't know.</summary>
    internal static long? Positive(long? v) => v is > 0 and < long.MaxValue / 1_000_000 ? v : null;

    public bool IsBluetooth =>
        Name.Contains("Bluetooth", StringComparison.OrdinalIgnoreCase)
        || Description.Contains("Bluetooth", StringComparison.OrdinalIgnoreCase);

    /// <summary>Win32_NetworkAdapter NetConnectionStatus codes (osquery reports the number).</summary>
    public string FriendlyConnection => ConnectionStatus switch
    {
        "2" => "Connected", "7" => IsBluetooth ? "Not connected" : "Cable unplugged / no signal", "0" => "Disconnected", "1" => "Connecting", "3" => "Disconnecting",
        "4" => "Hardware not present", "5" => "Hardware disabled", "6" => "Hardware problem", "8" => "Authenticating", "9" => "Authenticated",
        "10" => "Authentication failed", "11" => "Invalid address", "12" => "Credentials required",
        "" => Enabled == false ? "Turned off" : "Unknown",
        _ => ConnectionStatus,
    };

    public bool IsConnected => ConnectionStatus is "2" or "9";
    public bool HasCounters => PacketsIn is not null || ErrorsIn is not null || ErrorsOut is not null;
    public long Errors => (ErrorsIn ?? 0) + (ErrorsOut ?? 0);
    public long Drops => (DropsIn ?? 0) + (DropsOut ?? 0);
    public long Packets => (PacketsIn ?? 0) + (PacketsOut ?? 0);

    /// <summary>Errors (not drops) above 1% of traffic, or any errors with almost no traffic, are flagged.</summary>
    public const double ErrorRateWarning = 0.01;

    public AreaLevel Level
    {
        get
        {
            if (!HasCounters) return IsConnected ? AreaLevel.Ok : AreaLevel.Neutral;
            if (Errors > 0 && (Packets == 0 || (double)Errors / Packets >= ErrorRateWarning)) return AreaLevel.Warning;
            return IsConnected ? AreaLevel.Ok : AreaLevel.Neutral;
        }
    }

    public static string FormatSpeed(long? bps) => bps switch
    {
        null or <= 0 => "",
        >= 1_000_000_000 => $"{bps / 1_000_000_000.0:0.#} Gbps",
        >= 1_000_000 => $"{bps / 1_000_000.0:0.#} Mbps",
        _ => $"{bps / 1000.0:0.#} Kbps",
    };
}

/// <summary>Where the Network check reads from (see <see cref="IBatteryPowerSource"/> for which one the app uses).</summary>
public interface INetworkSource
{
    /// <summary>Every network adapter, with its counters when they could be read; null when the adapters couldn't be read.</summary>
    Task<IReadOnlyList<NetworkAdapter>?> ReadAdaptersAsync(CancellationToken ct);
    /// <summary>IP, gateway and DNS of each adapter that is up, and the signed-in user's proxy; null when it couldn't be read.</summary>
    Task<IpConfigSnapshot?> ReadIpConfigAsync(CancellationToken ct);
    /// <summary>Whether the check can run (the legacy reader needs osqueryi.exe).</summary>
    Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct) => Task.FromResult(ModuleAvailability.Available);
}

/// <summary>
/// The adapters from WMI <c>Win32_NetworkAdapter</c> (what osquery's <c>interface_details</c> reads) with the counters
/// <c>Get-NetAdapterStatistics</c> shows (<c>MSFT_NetAdapterStatisticsSettingData</c>), and the IP configuration from
/// <c>Win32_NetworkAdapterConfiguration</c>. WMI goes through the Agent; whether DNS was entered by hand and the proxy are registry values the
/// app reads itself (a standard user can).
/// </summary>
public sealed class WmiNetworkSource(IWmiSource wmi, IRegistrySource registry) : INetworkSource
{
    public const string AdaptersSql =
        "SELECT DeviceID, NetConnectionID, Description, Manufacturer, MACAddress, NetEnabled, PhysicalAdapter, NetConnectionStatus, Speed FROM Win32_NetworkAdapter";
    public const string StandardCimv2 = @"root\StandardCimv2";
    public const string StatisticsSql =
        "SELECT Name, ReceivedUnicastPackets, ReceivedMulticastPackets, ReceivedBroadcastPackets, SentUnicastPackets, SentMulticastPackets, " +
        "SentBroadcastPackets, ReceivedPacketErrors, OutboundPacketErrors, ReceivedDiscardedPackets, OutboundDiscardedPackets FROM MSFT_NetAdapterStatisticsSettingData";
    /// <summary>The adapters as Get-NetAdapter lists them, which names every adapter that is up. Win32_NetworkAdapter can leave one out: on an
    /// HP OmniBook X (arm64) its Wi-Fi adapter has no connection name or status there.</summary>
    public const string NetAdaptersSql = "SELECT Name, InterfaceDescription, DeviceID, InterfaceOperationalStatus, Hidden FROM MSFT_NetAdapter";
    public const string ConfigSql =
        "SELECT Index, SettingID, Description, IPAddress, DefaultIPGateway, DNSServerSearchOrder FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE";

    /// <summary>Each interface's TCP/IP settings, by its GUID; NameServer is set only when DNS servers were entered by hand.</summary>
    public static readonly RegistryRead InterfacesRead =
        new(RegistryRoot.LocalMachine, @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces", ["NameServer"], SubKeys: true);
    public static readonly RegistryRead ProxyRead =
        new(RegistryRoot.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Internet Settings", ["ProxyEnable", "ProxyServer"]);

    public async Task<IReadOnlyList<NetworkAdapter>?> ReadAdaptersAsync(CancellationToken ct)
    {
        var q = await wmi.QueryAsync(WmiHardwareInventorySource.Cimv2, AdaptersSql, ct).ConfigureAwait(false);
        if (!q.Success) return null;
        // The counters are extra: without them the adapters are still shown, saying their error counts aren't reported.
        var stats = await wmi.QueryAsync(StandardCimv2, StatisticsSql, ct).ConfigureAwait(false);
        var byName = new Dictionary<string, WmiRow>(StringComparer.OrdinalIgnoreCase);
        foreach (var s in stats.Rows ?? [])
            if (s.Str("Name") is { Length: > 0 } n) byName.TryAdd(n, s);
        var list = q.Rows!.Select(Adapter).ToList();
        list.AddRange(await MissingUpAdaptersAsync(list, q.Rows!, ct).ConfigureAwait(false));
        return list.Select(a => byName.TryGetValue(a.Name, out var s) ? WithCounters(a, s) : a).ToList();
    }

    /// <summary>
    /// Adapters that are up but that Win32_NetworkAdapter (and so osquery) doesn't name: on an HP OmniBook X (arm64) the connected Wi-Fi
    /// adapter has no connection name, status or physical flag there, so the check said "Not connected". Get-NetAdapter's list
    /// (MSFT_NetAdapter) names it; it is added as a connected network card. Its hardware address and speed aren't known.
    /// </summary>
    private async Task<IEnumerable<NetworkAdapter>> MissingUpAdaptersAsync(List<NetworkAdapter> known, IReadOnlyList<WmiRow> win32, CancellationToken ct)
    {
        var q = await wmi.QueryAsync(StandardCimv2, NetAdaptersSql, ct).ConfigureAwait(false);
        if (!q.Success) return [];
        var names = known.Select(a => a.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return q.Rows!
            .Where(r => r.Bool("Hidden") != true && r.Long("InterfaceOperationalStatus") == 1 && r.Str("Name") is { Length: > 0 } n && !names.Contains(n))
            .Select(r =>
            {
                var description = r.Str("InterfaceDescription");
                var manufacturer = win32.FirstOrDefault(w => w.Str("Description").Equals(description, StringComparison.OrdinalIgnoreCase))?.Str("Manufacturer") ?? "";
                return new NetworkAdapter(r.Str("Name"), description, manufacturer, "", "2", true, true, null, null, null, null, null, null, null);
            }).ToList();
    }

    /// <summary>One Win32_NetworkAdapter, named as osquery names it: the connection name ("Wi-Fi"), else the description, else the index.</summary>
    public static NetworkAdapter Adapter(WmiRow r) => new(
        NetworkAdapter.FirstNonEmpty(r.Str("NetConnectionID"), r.Str("Description"), r.Str("DeviceID")),
        r.Str("Description"), r.Str("Manufacturer"), r.Str("MACAddress"),
        r.Long("NetConnectionStatus") is { } status ? status.ToString(CultureInfo.InvariantCulture) : "",
        r.Bool("NetEnabled"), r.Bool("PhysicalAdapter"), NetworkAdapter.Positive(r.Long("Speed")),
        null, null, null, null, null, null);

    /// <summary>The counters as Get-NetAdapterStatistics adds them up (unicast + multicast + broadcast). A count Windows doesn't report stays null.</summary>
    public static NetworkAdapter WithCounters(NetworkAdapter a, WmiRow s) => a with
    {
        PacketsIn = Sum(s, "ReceivedUnicastPackets", "ReceivedMulticastPackets", "ReceivedBroadcastPackets"),
        PacketsOut = Sum(s, "SentUnicastPackets", "SentMulticastPackets", "SentBroadcastPackets"),
        ErrorsIn = Count(s, "ReceivedPacketErrors"), ErrorsOut = Count(s, "OutboundPacketErrors"),
        DropsIn = Count(s, "ReceivedDiscardedPackets"), DropsOut = Count(s, "OutboundDiscardedPackets"),
    };

    /// <summary>A counter: never negative, and not the "unknown" marker WMI uses for an unsigned 64-bit value it can't read.</summary>
    private static long? Count(WmiRow r, string name) => r.Long(name) is { } v and >= 0 and < long.MaxValue ? v : null;

    private static long? Sum(WmiRow r, params string[] names)
    {
        long? total = null;
        foreach (var n in names)
            if (Count(r, n) is { } v) total = (total ?? 0) + Math.Min(v, long.MaxValue / 4);
        return total;
    }

    public async Task<IpConfigSnapshot?> ReadIpConfigAsync(CancellationToken ct)
    {
        var configs = await wmi.QueryAsync(WmiHardwareInventorySource.Cimv2, ConfigSql, ct).ConfigureAwait(false);
        var adapters = await wmi.QueryAsync(StandardCimv2, NetAdaptersSql, ct).ConfigureAwait(false);
        if (!configs.Success || !adapters.Success) return null;
        var interfaces = await registry.ReadAsync(InterfacesRead, ct).ConfigureAwait(false);
        var proxy = await registry.ReadAsync(ProxyRead, ct).ConfigureAwait(false);

        // MSFT_NetAdapter's DeviceID is the interface GUID, the configuration's SettingID.
        var byGuid = new Dictionary<string, WmiRow>(StringComparer.OrdinalIgnoreCase);
        foreach (var a in adapters.Rows!)
            if (a.Str("DeviceID") is { Length: > 0 } id) byGuid.TryAdd(id, a);
        // Unread (no rows) means unknown, as in the PowerShell script when the key can't be read.
        Dictionary<string, WmiRow>? manualDns = interfaces.Success
            ? interfaces.Rows!.GroupBy(r => r.Str(RegistryRead.KeyColumn), StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase)
            : null;

        var list = new List<ActiveAdapterIp>();
        foreach (var c in configs.Rows!)
        {
            // As Get-NetIPConfiguration with NetAdapter.Status 'Up': a visible adapter whose interface is up (InterfaceOperationalStatus 1).
            var guid = c.Str("SettingID");
            if (!byGuid.TryGetValue(guid, out var adapter) || adapter.Bool("Hidden") == true || adapter.Long("InterfaceOperationalStatus") != 1) continue;
            bool? dnsManual = manualDns is null ? null : manualDns.TryGetValue(guid, out var key) && key.Str("NameServer").Length > 0;
            list.Add(new ActiveAdapterIp(
                NetworkAdapter.FirstNonEmpty(adapter.Str("Name"), adapter.Str("InterfaceDescription")),
                NetworkAdapter.FirstNonEmpty(adapter.Str("InterfaceDescription"), c.Str("Description")),
                Ipv4(c, "IPAddress").FirstOrDefault() ?? "",
                Ipv4(c, "DefaultIPGateway").FirstOrDefault() ?? "",
                string.Join(", ", Ipv4(c, "DNSServerSearchOrder")),
                dnsManual));
        }

        var p = proxy.Rows?.FirstOrDefault();
        var proxyOn = p?.Long("ProxyEnable") == 1;
        return new IpConfigSnapshot(list, proxyOn, proxyOn ? p!.Str("ProxyServer") : "");
    }

    /// <summary>
    /// The IPv4 addresses in a string-array property (WMI lists the IPv6 ones too). A recording replaces addresses with placeholders that keep
    /// the family (<c>&lt;ipv4:…&gt;</c>, <c>&lt;ipv6:…&gt;</c>) and DNS servers with <c>&lt;serial:…&gt;</c>, which are kept unless an IPv4 address is there.
    /// </summary>
    private static IEnumerable<string> Ipv4(WmiRow r, string name)
    {
        if (!r.Values.TryGetValue(name, out var v)) return [];
        IEnumerable<string> items = v.ValueKind switch
        {
            JsonValueKind.Array => v.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.String).Select(e => e.GetString()!.Trim()),
            JsonValueKind.String => [v.GetString()!.Trim()],
            _ => [],
        };
        var list = items.Where(s => s.Length > 0).ToList();
        var v4 = list.Where(s => (IPAddress.TryParse(s, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork)
                                 || s.StartsWith(RecordingPlaceholders.Ipv4, StringComparison.Ordinal)).ToList();
        return v4.Count > 0 ? v4 : list.Where(s => !IPAddress.TryParse(s, out _) && !s.StartsWith(RecordingPlaceholders.Ipv6, StringComparison.Ordinal)).ToList();
    }
}

/// <inheritdoc cref="AgentOrFallbackBatteryPowerSource"/>
public sealed class AgentOrFallbackNetworkSource(Session.IElevatedCommandBridge agent, INetworkSource withAgent, INetworkSource fallback) : INetworkSource
{
    private INetworkSource Current => agent.IsConnected ? withAgent : fallback;
    public Task<IReadOnlyList<NetworkAdapter>?> ReadAdaptersAsync(CancellationToken ct) => Current.ReadAdaptersAsync(ct);
    public Task<IpConfigSnapshot?> ReadIpConfigAsync(CancellationToken ct) => Current.ReadIpConfigAsync(ct);
    public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct) => Current.CheckAvailabilityAsync(ct);
}
