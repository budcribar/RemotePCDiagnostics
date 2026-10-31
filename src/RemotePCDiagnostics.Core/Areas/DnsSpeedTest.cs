using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>Sends one DNS query to a specific server and returns the raw answer (throws on timeout / no answer).</summary>
public interface IDnsTransport
{
    Task<byte[]> QueryAsync(IPAddress server, byte[] query, TimeSpan timeout, CancellationToken ct);
}

public sealed class UdpDnsTransport : IDnsTransport
{
    public async Task<byte[]> QueryAsync(IPAddress server, byte[] query, TimeSpan timeout, CancellationToken ct)
    {
        using var udp = new UdpClient(server.AddressFamily);
        using var to = CancellationTokenSource.CreateLinkedTokenSource(ct);
        to.CancelAfter(timeout);
        await udp.SendAsync(query, new IPEndPoint(server, 53), to.Token).ConfigureAwait(false);
        var r = await udp.ReceiveAsync(to.Token).ConfigureAwait(false);
        return r.Buffer;
    }
}

/// <summary>Median lookup time for one DNS server; null when it didn't answer enough of the lookups.</summary>
public sealed record DnsServerTiming(string Name, string Address, double? MedianMs, int Answered, int Asked);

/// <summary>
/// Your current DNS vs Cloudflare (1.1.1.1) and Google (8.8.8.8), measured by asking each server directly (nothing on the PC
/// is changed). Switching is only suggested when a public resolver is clearly faster here.
/// </summary>
public sealed record DnsComparison(DnsServerTiming Current, DnsServerTiming Cloudflare, DnsServerTiming Google)
{
    /// <summary>"Clearly faster": at least 15% and 3 ms quicker than the current DNS, and answering reliably.</summary>
    public const double MinRelative = 0.15, MinMs = 3;

    public DnsServerTiming? Best => new[] { Cloudflare, Google }.Where(t => t.MedianMs is not null).OrderBy(t => t.MedianMs).FirstOrDefault();

    public bool PublicIsFaster =>
        Current.MedianMs is { } cur && Best?.MedianMs is { } best && cur - best >= MinMs && (cur - best) / cur >= MinRelative;

    public string Text
    {
        get
        {
            string Ms(DnsServerTiming t) => t.MedianMs is { } v ? $"{v:0} ms" : "no answer";
            var line = $"Website lookups: your DNS ({Current.Address}) {Ms(Current)} · Cloudflare {Ms(Cloudflare)} · Google {Ms(Google)}.";
            return line + (PublicIsFaster
                ? $" {Best!.Name} is faster on this PC, so switching is suggested."
                : Current.MedianMs is null ? " Your current DNS didn't answer the test, so it couldn't be compared." : " Your current DNS is as fast or faster here, so switching isn't suggested.");
        }
    }
}

public sealed class DnsSpeedTest(IDnsTransport? transport = null, Action<string>? log = null)
{
    public static readonly IPAddress CloudflareIp = IPAddress.Parse("1.1.1.1"), GoogleIp = IPAddress.Parse("8.8.8.8");
    public const int Lookups = 12;
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(2);
    private readonly IDnsTransport _t = transport ?? new UdpDnsTransport();

    public static bool IsPublicAlready(string? dnsServers) =>
        (dnsServers ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Any(s => s is "1.1.1.1" or "1.0.0.1" or "8.8.8.8" or "8.8.4.4");

    /// <summary>Compares the first IPv4 DNS server in <paramref name="currentDns"/> ("192.168.1.1, …") with the public resolvers; null when there's nothing to compare.</summary>
    public async Task<DnsComparison?> CompareAsync(string? currentDns, CancellationToken ct)
    {
        var first = (currentDns ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(s => IPAddress.TryParse(s, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork ? ip : null).FirstOrDefault(ip => ip is not null);
        if (first is null) return null;
        var servers = new[] { ("Your DNS", first), ("Cloudflare", CloudflareIp), ("Google", GoogleIp) };
        var times = servers.Select(_ => new List<double>()).ToArray();
        var domains = Benchmarks.BenchmarkRunner.LookupDomains;
        for (var i = 0; i < Lookups; i++)
        {
            // Same never-cached name for every server, servers in rotating order, so each gets the same conditions.
            var name = $"rpd-{Guid.NewGuid():N}"[..16] + "." + domains[i % domains.Length];
            for (var k = 0; k < servers.Length; k++)
            {
                var j = (i + k) % servers.Length;
                if (await TimeOneAsync(servers[j].Item2, name, ct).ConfigureAwait(false) is { } ms) times[j].Add(ms);
            }
        }
        DnsServerTiming T(int j) => new(servers[j].Item1, servers[j].Item2.ToString(),
            times[j].Count >= Lookups * 2 / 3 ? Median(times[j]) : null, times[j].Count, Lookups);
        var c = new DnsComparison(T(0), T(1), T(2));
        log?.Invoke($"DNS speed: current {c.Current.Address}={c.Current.MedianMs:0.0}ms ({c.Current.Answered}/{Lookups}) cloudflare={c.Cloudflare.MedianMs:0.0} google={c.Google.MedianMs:0.0} faster={c.PublicIsFaster}");
        return c;
    }

    private async Task<double?> TimeOneAsync(IPAddress server, string name, CancellationToken ct)
    {
        var (query, id) = BuildQuery(name);
        var sw = Stopwatch.StartNew();
        try
        {
            var answer = await _t.QueryAsync(server, query, Timeout, ct).ConfigureAwait(false);
            return IsAnswerTo(answer, id) ? sw.Elapsed.TotalMilliseconds : null;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return null; }
        catch (SocketException) { return null; }
    }

    private static double Median(List<double> v) { var s = v.OrderBy(x => x).ToList(); return s.Count % 2 == 1 ? s[s.Count / 2] : (s[s.Count / 2 - 1] + s[s.Count / 2]) / 2; }

    /// <summary>Standard DNS query for an A record, recursion desired.</summary>
    public static (byte[] Packet, ushort Id) BuildQuery(string name)
    {
        var id = (ushort)Random.Shared.Next(0, 65536);
        var bytes = new List<byte> { (byte)(id >> 8), (byte)id, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0 };
        foreach (var label in name.Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            var l = System.Text.Encoding.ASCII.GetBytes(label);
            bytes.Add((byte)l.Length); bytes.AddRange(l);
        }
        bytes.AddRange([0, 0, 1, 0, 1]); // root, QTYPE A, QCLASS IN
        return (bytes.ToArray(), id);
    }

    /// <summary>A reply (QR bit) with our id; "no such name" counts — it's a complete answer.</summary>
    public static bool IsAnswerTo(byte[] answer, ushort id) =>
        answer.Length >= 12 && answer[0] == (byte)(id >> 8) && answer[1] == (byte)id && (answer[2] & 0x80) != 0;
}
