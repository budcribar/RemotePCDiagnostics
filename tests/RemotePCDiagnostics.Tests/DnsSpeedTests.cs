using System.Net;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Tests;

public class DnsSpeedTests
{
    /// <summary>Answers after a per-server delay (or not at all when the delay is null).</summary>
    private sealed class FakeTransport(Dictionary<string, int?> delayMs) : IDnsTransport
    {
        public List<string> Asked = [];
        public async Task<byte[]> QueryAsync(IPAddress server, byte[] query, TimeSpan timeout, CancellationToken ct)
        {
            lock (Asked) Asked.Add(server.ToString());
            if (delayMs[server.ToString()] is not { } d) throw new OperationCanceledException();
            await Task.Delay(d, ct);
            var reply = (byte[])query.Clone();
            reply[2] |= 0x80; // response bit
            return reply;
        }
    }

    [Fact]
    public async Task PublicClearlyFaster_IsSuggested_WithNumbers()
    {
        var t = new FakeTransport(new() { ["192.168.1.1"] = 120, ["1.1.1.1"] = 5, ["8.8.8.8"] = 15 });
        var c = (await new DnsSpeedTest(t).CompareAsync("192.168.1.1, fe80::1", default))!;
        Assert.True(c.PublicIsFaster);
        Assert.Equal("Cloudflare", c.Best!.Name);
        Assert.Equal(DnsSpeedTest.Lookups * 3, t.Asked.Count);
        Assert.Contains("Cloudflare is faster on this PC", c.Text);
    }

    [Fact]
    public async Task CurrentAsFast_NotSuggested()
    {
        var t = new FakeTransport(new() { ["192.168.1.1"] = 5, ["1.1.1.1"] = 6, ["8.8.8.8"] = 120 });
        var c = (await new DnsSpeedTest(t).CompareAsync("192.168.1.1", default))!;
        Assert.False(c.PublicIsFaster);
        Assert.Contains("as fast or faster", c.Text);
    }

    [Fact]
    public async Task NoAnswers_CountAsUnavailable()
    {
        var t = new FakeTransport(new() { ["192.168.1.1"] = 5, ["1.1.1.1"] = null, ["8.8.8.8"] = null });
        var c = (await new DnsSpeedTest(t).CompareAsync("192.168.1.1", default))!;
        Assert.Null(c.Cloudflare.MedianMs);
        Assert.False(c.PublicIsFaster);
        Assert.Null(await new DnsSpeedTest(t).CompareAsync("fe80::1", default)); // no IPv4 server to compare
    }

    [Fact]
    public void QueryPacket_AndAnswerCheck()
    {
        var (q, id) = DnsSpeedTest.BuildQuery("rpd-x.example.com");
        Assert.Equal(12 + 1 + 5 + 1 + 7 + 1 + 3 + 1 + 4, q.Length);
        Assert.Equal(1, q[5]);                       // one question
        Assert.False(DnsSpeedTest.IsAnswerTo(q, id)); // a query isn't an answer
        var a = (byte[])q.Clone(); a[2] |= 0x80;
        Assert.True(DnsSpeedTest.IsAnswerTo(a, id));
        Assert.False(DnsSpeedTest.IsAnswerTo(a, (ushort)(id + 1)));
    }

    // ---- what the card offers ----
    private static readonly DnsComparison Faster = new(new("Your DNS", "192.168.1.1", 30, 12, 12), new("Cloudflare", "1.1.1.1", 10, 12, 12), new("Google", "8.8.8.8", 14, 12, 12));
    private static readonly DnsComparison Slower = new(new("Your DNS", "192.168.1.1", 9, 12, 12), new("Cloudflare", "1.1.1.1", 10, 12, 12), new("Google", "8.8.8.8", 14, 12, 12));

    private static IReadOnlyList<AreaAction> Actions(ActiveAdapterIp a, DnsComparison? dns) =>
        WifiConfigModule.Build(null, true, new IpConfigSnapshot([a], false, ""), dns).Cards.Single(c => c.Id == "ipdns").Rows.Single().Actions ?? [];

    [Fact]
    public void PublicDns_OnlyWhenMeasuredFaster_ResetOnlyWhenManual()
    {
        var auto = new ActiveAdapterIp("Wi-Fi", "Intel", "192.168.1.45", "192.168.1.1", "192.168.1.1", DnsManual: false);
        Assert.Empty(Actions(auto, null));     // untested: not offered; automatic: nothing to reset
        Assert.Empty(Actions(auto, Slower));
        var faster = Assert.Single(Actions(auto, Faster));
        Assert.Equal(RemediationKind.SetPublicDns, faster.Kind);
        Assert.Contains("10 ms vs 30 ms", faster.ButtonText);

        var manual = auto with { DnsManual = true, Dns = "9.9.9.9" };
        Assert.Equal([RemediationKind.ResetDhcpDns], Actions(manual, Slower).Select(x => x.Kind));
        var already = auto with { Dns = "1.1.1.1, 8.8.8.8", DnsManual = true };
        Assert.DoesNotContain(Actions(already, Faster), x => x.Kind == RemediationKind.SetPublicDns);
    }

    [Fact]
    public void Card_ExplainsTheMeasurement() =>
        Assert.Contains("isn't suggested", WifiConfigModule.Build(null, true, new IpConfigSnapshot([new("Wi-Fi", "", "1", "2", "192.168.1.1")], false, ""), Slower)
            .Cards.Single(c => c.Id == "ipdns").Note);
}
