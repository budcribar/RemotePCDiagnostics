using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace RemotePCDiagnostics.Core.Areas;

public static class NetworkDiagnostics
{
    public const int EventLimit = 50;
    private const string Wlan = "Microsoft-Windows-WLAN-AutoConfig/Operational";
    private const string Profiles = "Microsoft-Windows-NetworkProfile/Operational";
    private const string Wired = "Microsoft-Windows-Wired-AutoConfig/Operational";
    private const string SystemLog = "System";
    private const string DnsName = "www.msftconnecttest.com";
    private static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(2);

    public static async Task<AreaCard> ReadHistoryAsync(SystemCommandRunner commands, CancellationToken ct)
    {
        var log = new WindowsEventLog(commands);
        var sources = new[]
        {
            (Wlan, "EventID=8001 or EventID=8002 or EventID=8003"),
            (Profiles, "EventID=10000 or EventID=10001"),
            (Wired, "EventID=15501"),
            (SystemLog, "(Provider[@Name='Microsoft-Windows-NDIS'] and EventID=10400) or (Provider[@Name='e1dexpress'] and (EventID=27 or EventID=32))")
        };
        var results = await Task.WhenAll(sources.Select(async source => (source.Item1, await log.QueryAsync(source.Item1,
            $"*[System[({source.Item2}) and TimeCreated[timediff(@SystemTime) <= 604800000]]]", EventLimit, ct).ConfigureAwait(false)))).ConfigureAwait(false);
        return BuildHistory(results);
    }

    public static AreaCard BuildHistory(IEnumerable<(string Channel, IReadOnlyList<WinEvent>? Events)> sources)
    {
        var results = sources.ToList();
        var available = results.Count(s => s.Events is not null);
        var rows = results.SelectMany(s => s.Events ?? []).Where(e => e.Time != default)
            .OrderByDescending(e => e.Time).Take(EventLimit)
            .Select(e => new AreaRow(AreaLevel.Neutral, [WindowsEventLog.FormatTime(e.Time), EventLabel(e), $"{e.Source} / {e.EventId}"],
                [AreaSort.TimeKey(e.Time), null, null], Detail: e.Message)).ToList();
        return new("network-timeline", "Recent network events", AreaLevel.Neutral,
            available == 0 ? "Event history unavailable" : rows.Count == 0 ? "No matching events recorded" : $"{rows.Count} recent events shown",
            $"Last 7 days · {available} of {results.Count} Windows logs readable", ["When", "Event", "Source"], rows,
            EmptyText: available == 0 ? "Windows did not return network event history." : "The readable logs contained no matching events.",
            Note: "The latest 50 events are shown. Profile disconnects can include wired or virtual networks. Event history depends on enabled logs and driver support.",
            PreserveRowOrder: true);
    }

    private static string EventLabel(WinEvent e) => (e.Channel, e.EventId) switch
    {
        (Wlan, 8001) => "Wi-Fi connected",
        (Wlan, 8002) => "Wi-Fi connection failed",
        (Wlan, 8003) => "Wi-Fi disconnected",
        (Wired, 15501) => "Wired adapter connected",
        (Profiles, 10000) => "Network profile connected",
        (Profiles, 10001) => "Network profile disconnected",
        (SystemLog, 10400) => "Network adapter reset started",
        (SystemLog, 27) when e.Provider.Equals("e1dexpress", StringComparison.OrdinalIgnoreCase) => "Intel Ethernet link dropped",
        (SystemLog, 32) when e.Provider.Equals("e1dexpress", StringComparison.OrdinalIgnoreCase) => "Intel Ethernet link established",
        _ => "Network event"
    };

    public const string DualStackProbeHost = "speed.cloudflare.com";
    public static readonly TimeSpan Ipv6ProbeTimeout = TimeSpan.FromSeconds(3);

    public static async Task<AreaCard> ProbeAsync(string? gateway, CancellationToken ct)
    {
        var gatewayPing = IPAddress.TryParse(gateway, out var address) ? PingAsync(address, ct) : Task.FromResult<bool?>(null);
        var destinationPing = PingAsync(DnsSpeedTest.CloudflareIp, ct);
        var dns = ResolveAsync(ct);
        var ipv6 = ProbeIpv6FallbackAsync(DualStackProbeHost, Ipv6ProbeTimeout, ct: ct);
        await Task.WhenAll(gatewayPing, destinationPing, dns, ipv6).ConfigureAwait(false);
        return BuildProbes(gateway, await gatewayPing.ConfigureAwait(false), await dns.ConfigureAwait(false), await destinationPing.ConfigureAwait(false), await ipv6.ConfigureAwait(false));
    }

    public static AreaCard BuildProbes(string? gateway, bool? gatewayReply, bool? dnsReply, bool? destinationReply, Ipv6FallbackResult? ipv6 = null)
    {
        AreaRow PingRow(string label, string? target, bool? reply) => new(AreaLevel.Neutral,
            [label, target ?? "Unavailable", reply switch { true => "Replied", false => "No ICMP reply", null => "Unavailable" }]);

        var rows = new List<AreaRow>
        {
            PingRow("Gateway", string.IsNullOrWhiteSpace(gateway) ? null : gateway, gatewayReply),
            new(AreaLevel.Neutral, ["System DNS", DnsName, dnsReply switch { true => "Resolved", false => "Resolution failed or timed out", null => "Unavailable" }]),
            PingRow("Public IP", DnsSpeedTest.CloudflareIp.ToString(), destinationReply),
        };

        var brokenIpv6 = ipv6 is { BrokenIpv6Fallback: true };
        if (ipv6 is { HasGlobalIpv6WithRoute: true })
        {
            if (brokenIpv6)
                rows.Add(new(AreaLevel.Warning, ["IPv6 fallback", $"{ipv6.Host}:443", "IPv6 failed; IPv4 works"]));
            else if (ipv6.Ipv6Connected == true)
                rows.Add(new(AreaLevel.Neutral, ["IPv6", $"{ipv6.Host}:443", "Connected"]));
            else
                rows.Add(new(AreaLevel.Neutral, ["IPv6", $"{ipv6.Host}:443", "IPv6 and IPv4 both failed"]));
        }

        var level = brokenIpv6 ? AreaLevel.Warning : AreaLevel.Neutral;
        var headline = brokenIpv6
            ? "Broken IPv6 fallback (IPv6 failed, IPv4 works)"
            : gatewayReply == true && dnsReply == true && destinationReply == true
                ? "All three probes responded"
                : "See individual probe results";
        var note = brokenIpv6
            ? "This PC has a global IPv6 address and IPv6 default route, but TCP 443 over IPv6 failed while IPv4 succeeded. Apps and browsers may stall while falling back to IPv4. "
            : "";
        note += "ICMP can be blocked even when traffic works. DNS uses the system resolver, which may have a cached answer. Compare this snapshot with event times when investigating earlier drops.";

        return new("network-reachability", "Reachability now", level, headline,
            "Current snapshot", ["Layer", "Target", "Result"], rows, Note: note);
    }

    public static async Task<Ipv6FallbackResult> ProbeIpv6FallbackAsync(
        string host = DualStackProbeHost,
        TimeSpan? timeout = null,
        Func<bool>? hasGlobalIpv6WithRoute = null,
        Func<string, AddressFamily, TimeSpan, CancellationToken, Task<bool>>? tcpConnect = null,
        CancellationToken ct = default)
    {
        var checkIpv6 = hasGlobalIpv6WithRoute ?? HasGlobalIpv6AndDefaultRoute;
        if (!checkIpv6())
            return new Ipv6FallbackResult(false, null, null, host);

        var t = timeout ?? Ipv6ProbeTimeout;
        var connect = tcpConnect ?? ConnectTcp443Async;
        var v6Task = SafeConnectAsync(connect, host, AddressFamily.InterNetworkV6, t, ct);
        var v4Task = SafeConnectAsync(connect, host, AddressFamily.InterNetwork, t, ct);
        await Task.WhenAll(v6Task, v4Task).ConfigureAwait(false);
        return new Ipv6FallbackResult(true, await v6Task.ConfigureAwait(false), await v4Task.ConfigureAwait(false), host);
    }

    public static bool HasGlobalIpv6AndDefaultRoute()
    {
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;
                var props = nic.GetIPProperties();
                var hasGlobalV6 = props.UnicastAddresses.Any(u => IsGlobalUnicastIpv6(u.Address));
                if (!hasGlobalV6) continue;
                var hasV6Gateway = props.GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetworkV6 && !g.Address.Equals(IPAddress.IPv6None));
                if (hasV6Gateway) return true;
            }
            return false;
        }
        catch (NetworkInformationException) { return false; }
    }

    public static bool IsGlobalUnicastIpv6(IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetworkV6) return false;
        if (address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6Multicast || IPAddress.IsLoopback(address)) return false;
        if (address.Equals(IPAddress.IPv6Any) || address.Equals(IPAddress.IPv6None)) return false;
        var bytes = address.GetAddressBytes();
        // Exclude Unique Local Addresses (fc00::/7)
        if ((bytes[0] & 0xfe) == 0xfc) return false;
        // Global unicast is 2000::/3 (first 3 bits = 001)
        return (bytes[0] & 0xe0) == 0x20;
    }

    private static async Task<bool> SafeConnectAsync(Func<string, AddressFamily, TimeSpan, CancellationToken, Task<bool>> connect,
        string host, AddressFamily family, TimeSpan timeout, CancellationToken ct)
    {
        try { return await connect(host, family, timeout, ct).ConfigureAwait(false); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return false; }
    }

    private static async Task<bool> ConnectTcp443Async(string host, AddressFamily family, TimeSpan timeout, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        var addresses = await Dns.GetHostAddressesAsync(host, family, cts.Token).ConfigureAwait(false);
        if (addresses.Length == 0) return false;
        using var socket = new Socket(family, SocketType.Stream, ProtocolType.Tcp);
        await socket.ConnectAsync(addresses[0], 443, cts.Token).ConfigureAwait(false);
        return true;
    }

    private static async Task<bool?> PingAsync(IPAddress address, CancellationToken ct)
    {
        try
        {
            using var ping = new Ping();
            return (await ping.SendPingAsync(address, ProbeTimeout, cancellationToken: ct).ConfigureAwait(false)).Status == IPStatus.Success;
        }
        catch (PingException) { return null; }
        catch (SocketException) { return null; }
    }

    private static async Task<bool?> ResolveAsync(CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(ProbeTimeout);
        try { return (await Dns.GetHostAddressesAsync(DnsName, timeout.Token).ConfigureAwait(false)).Length > 0; }
        catch (SocketException) { return false; }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return false; }
    }
}

public sealed record Ipv6FallbackResult(bool HasGlobalIpv6WithRoute, bool? Ipv6Connected, bool? Ipv4Connected, string Host)
{
    public bool BrokenIpv6Fallback => HasGlobalIpv6WithRoute && Ipv6Connected == false && Ipv4Connected == true;
}
