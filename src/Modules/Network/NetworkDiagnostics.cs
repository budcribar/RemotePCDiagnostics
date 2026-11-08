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

    public static async Task<AreaCard> ProbeAsync(string? gateway, CancellationToken ct)
    {
        var gatewayPing = IPAddress.TryParse(gateway, out var address) ? PingAsync(address, ct) : Task.FromResult<bool?>(null);
        var destinationPing = PingAsync(DnsSpeedTest.CloudflareIp, ct);
        var dns = ResolveAsync(ct);
        await Task.WhenAll(gatewayPing, destinationPing, dns).ConfigureAwait(false);
        return BuildProbes(gateway, await gatewayPing.ConfigureAwait(false), await dns.ConfigureAwait(false), await destinationPing.ConfigureAwait(false));
    }

    public static AreaCard BuildProbes(string? gateway, bool? gatewayReply, bool? dnsReply, bool? destinationReply)
    {
        AreaRow PingRow(string label, string? target, bool? reply) => new(AreaLevel.Neutral,
            [label, target ?? "Unavailable", reply switch { true => "Replied", false => "No ICMP reply", null => "Unavailable" }]);
        return new("network-reachability", "Reachability now", AreaLevel.Neutral,
            gatewayReply == true && dnsReply == true && destinationReply == true ? "All three probes responded" : "See individual probe results",
            "Current snapshot", ["Layer", "Target", "Result"],
            [PingRow("Gateway", string.IsNullOrWhiteSpace(gateway) ? null : gateway, gatewayReply),
             new(AreaLevel.Neutral, ["System DNS", DnsName, dnsReply switch { true => "Resolved", false => "Resolution failed or timed out", null => "Unavailable" }]),
             PingRow("Public IP", DnsSpeedTest.CloudflareIp.ToString(), destinationReply)],
            Note: "ICMP can be blocked even when traffic works. DNS uses the system resolver, which may have a cached answer. Compare this snapshot with event times when investigating earlier drops.");
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
