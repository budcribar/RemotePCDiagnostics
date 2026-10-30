using System.Net;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Tests;

/// <summary>Scripted pings: reply(host, n) returns the RTT for the nth ping to that host, or null for a lost ping.</summary>
internal sealed class FakePinger(Func<string, int, double?> reply) : IPinger
{
    private readonly Dictionary<string, int> _n = new();
    public readonly List<string> Hosts = [];
    public Task<PingReply> PingAsync(string host, TimeSpan timeout, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        int n;
        lock (_n) { _n[host] = n = _n.GetValueOrDefault(host) + 1; Hosts.Add(host); }
        var v = reply(host, n);
        return Task.FromResult(new PingReply(v.HasValue, v));
    }
}

internal sealed class FakeGateway(string? gw) : IGatewayResolver { public string? GetDefaultGateway() => gw; }

internal sealed class FakeSpeed(TransferResult? down = null, TransferResult? up = null) : ISpeedTester
{
    public long? RequestedDown, RequestedUp; public int Calls;
    public Task<TransferResult> DownloadAsync(long maxBytes, TimeSpan timeout, CancellationToken ct) { Calls++; RequestedDown = maxBytes; return Task.FromResult(down ?? new TransferResult(25_000_000, TimeSpan.FromSeconds(2))); }
    public Task<TransferResult> UploadAsync(long bytes, TimeSpan timeout, CancellationToken ct) { RequestedUp = bytes; return Task.FromResult(up ?? new TransferResult(10_000_000, TimeSpan.FromSeconds(4))); }
}

internal sealed class FakeCounters(params AdapterTotals?[] reads) : IAdapterCounters
{
    private int _i;
    public Task<AdapterTotals?> ReadAsync(CancellationToken ct) => Task.FromResult(reads.Length == 0 ? null : reads[Math.Min(_i++, reads.Length - 1)]);
}

/// <summary>Serves a fixed body for any request and records it (for the real HttpSpeedTester).</summary>
internal sealed class FakeHttpHandler(int bodyBytes) : HttpMessageHandler
{
    public readonly List<HttpRequestMessage> Requests = [];
    public long UploadedBytes;
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        Requests.Add(request);
        if (request.Content is not null) UploadedBytes = (await request.Content.ReadAsByteArrayAsync(ct)).Length;
        return new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(new byte[bodyBytes]) };
    }
}

public class NetworkTestTests
{
    private static readonly NetworkTestOptions Opts = new() { Duration = TimeSpan.FromMinutes(1), Interval = TimeSpan.FromSeconds(1), SpeedTestDelay = TimeSpan.FromSeconds(5) };
    private static SequenceSensorProvider NoSensors() => new(_ => throw new PlatformNotSupportedException(), available: false);
    private static NetworkTest Make(FakePinger p, string? gw = "192.168.1.1", FakeSpeed? speed = null, FakeCounters? counters = null, ISensorProvider? sensors = null, FakeStressClock? clock = null) =>
        new(p, new FakeGateway(gw), speed ?? new FakeSpeed(), counters ?? new FakeCounters(new AdapterTotals(3, 10), new AdapterTotals(3, 10)), sensors ?? NoSensors(), null, clock ?? new FakeStressClock());

    [Fact]
    public void PingStats_LossLatencyJitter()
    {
        var s = PingStats.From([10, 20, null, 10, 30]);
        Assert.Equal(5, s.Sent); Assert.Equal(4, s.Received);
        Assert.Equal(20, s.LossPercent);
        Assert.Equal(17.5, s.AverageMs);
        Assert.Equal((10 + 10 + 20) / 3.0, s.JitterMs);
        Assert.Equal(30, s.WorstMs);
        Assert.Null(PingStats.From([]).LossPercent);
        Assert.Null(PingStats.From([null, null]).AverageMs);
    }

    [Fact]
    public void TransferResult_Mbps()
    {
        Assert.Equal(100, new TransferResult(25_000_000, TimeSpan.FromSeconds(2)).Mbps);
        Assert.Null(new TransferResult(100, TimeSpan.FromSeconds(1), "boom").Mbps);
        Assert.Null(new TransferResult(0, TimeSpan.FromSeconds(1)).Mbps);
    }

    [Fact]
    public async Task StableConnection_FullTimeLimit_WithSpeedAndCounters()
    {
        var speed = new FakeSpeed();
        var clock = new FakeStressClock();
        var r = await Make(new FakePinger((h, n) => h == "192.168.1.1" ? 2 : 15 + n % 2), speed: speed, clock: clock).RunAsync(Opts);
        Assert.Equal(NetworkTestOutcome.Stable, r.Outcome);
        Assert.Equal("Stable", r.Headline);
        Assert.Equal(60, r.Samples.Count);
        Assert.Equal(TimeSpan.FromMinutes(1), r.Ran);
        Assert.Equal(0, r.Internet.LossPercent);
        Assert.InRange(r.Internet.JitterMs!.Value, 0.4, 0.6); // 16,16,15,15,… (hosts alternate)
        Assert.Equal(100, r.DownloadMbps);
        Assert.Equal(20, r.UploadMbps);
        Assert.Equal(1, speed.Calls);
        Assert.Equal(25_000_000, speed.RequestedDown); // capped transfer sizes
        Assert.Equal(10_000_000, speed.RequestedUp);
        Assert.Equal(0, r.NewAdapterErrors);
        Assert.Equal(DiagnosticStatus.Ok, NetworkTestModule.ToStatus(r.Outcome));
    }

    [Fact]
    public async Task PublicHosts_Alternate()
    {
        var p = new FakePinger((_, _) => 10);
        await Make(p, gw: null).RunAsync(Opts with { Duration = TimeSpan.FromSeconds(4), RunSpeedTest = false });
        Assert.Equal(["1.1.1.1", "8.8.8.8", "1.1.1.1", "8.8.8.8"], p.Hosts);
    }

    [Fact]
    public async Task OccasionalLoss_IsSomePacketLoss()
    {
        var r = await Make(new FakePinger((h, n) => h != "192.168.1.1" && n % 50 == 0 ? null : 12)).RunAsync(Opts with { Duration = TimeSpan.FromMinutes(2) });
        Assert.Equal(NetworkTestOutcome.SomeLoss, r.Outcome);
        Assert.Equal("Some packet loss", r.Headline);
        Assert.Contains(r.Samples, s => s.InternetLost);
    }

    [Fact]
    public async Task HeavyLossOrJitter_IsUnstable()
    {
        var loss = await Make(new FakePinger((h, n) => n % 5 == 0 ? null : 12)).RunAsync(Opts);
        Assert.Equal(NetworkTestOutcome.Unstable, loss.Outcome);
        Assert.Equal("Unstable connection", loss.Headline);
        var jitter = await Make(new FakePinger((h, n) => n % 2 == 0 ? 10 : 120)).RunAsync(Opts);
        Assert.Equal(NetworkTestOutcome.Unstable, jitter.Outcome);
    }

    [Fact]
    public async Task AdapterErrorIncrease_IsFlagged()
    {
        var r = await Make(new FakePinger((_, _) => 10), counters: new FakeCounters(new AdapterTotals(3, 10), new AdapterTotals(7, 10))).RunAsync(Opts);
        Assert.Equal(4, r.NewAdapterErrors);
        Assert.Equal(NetworkTestOutcome.Unstable, r.Outcome);
        var drops = await Make(new FakePinger((_, _) => 10), counters: new FakeCounters(new AdapterTotals(3, 10), new AdapterTotals(3, 15))).RunAsync(Opts);
        Assert.Equal(5, drops.NewAdapterDrops);
        Assert.Equal(NetworkTestOutcome.SomeLoss, drops.Outcome);
        var none = await Make(new FakePinger((_, _) => 10), counters: new FakeCounters()).RunAsync(Opts);
        Assert.Null(none.NewAdapterErrors);
        Assert.Equal(NetworkTestOutcome.Stable, none.Outcome);
    }

    [Fact]
    public async Task Offline_IsNoInternet()
    {
        var failedDown = new FakeSpeed(new TransferResult(0, TimeSpan.FromSeconds(1), "no route"), new TransferResult(0, TimeSpan.FromSeconds(1), "no route"));
        var r = await Make(new FakePinger((_, _) => null), gw: null, speed: failedDown).RunAsync(Opts);
        Assert.Equal(NetworkTestOutcome.NoInternet, r.Outcome);
        Assert.Equal("No internet connection", r.Headline);
        Assert.Contains("isn't connected", r.Explanation);
        var routerOnly = await Make(new FakePinger((h, _) => h == "192.168.1.1" ? 2 : null), speed: failedDown).RunAsync(Opts);
        Assert.Equal(NetworkTestOutcome.NoInternet, routerOnly.Outcome);
        Assert.Contains("router", routerOnly.Explanation);
    }

    [Fact]
    public async Task IcmpBlocked_ButDownloadWorks_IsNotOffline()
    {
        var r = await Make(new FakePinger((_, _) => null)).RunAsync(Opts);
        Assert.Equal(NetworkTestOutcome.Stable, r.Outcome);
        Assert.Contains("blocks the checks", r.Explanation);
    }

    [Fact]
    public async Task StopToken_Stops()
    {
        using var cts = new CancellationTokenSource();
        int n = 0;
        var r = await Make(new FakePinger((_, _) => 10)).RunAsync(Opts, new SyncProgress<NetworkTestProgress>(_ => { if (++n == 3) cts.Cancel(); }), cts.Token);
        Assert.Equal(NetworkTestOutcome.StoppedByUser, r.Outcome);
        Assert.Equal("Stopped by you", r.Headline);
        Assert.InRange(r.Samples.Count, 3, 4);
    }

    [Fact]
    public async Task CriticalTemperature_Aborts()
    {
        var sensors = new SequenceSensorProvider(i => SequenceSensorProvider.Cpu(i >= 4 ? 99 : 70));
        var r = await Make(new FakePinger((_, _) => 10), sensors: sensors).RunAsync(Opts);
        Assert.Equal(NetworkTestOutcome.Overheated, r.Outcome);
        Assert.Equal("Stopped: PC got too hot", r.Headline);
        Assert.Equal(3, r.Samples.Count);
        Assert.Equal(99, r.MaxCpuTemperatureC);
    }

    [Fact]
    public async Task TimeLimit_IsClampedToTenMinutes()
    {
        var r = await Make(new FakePinger((_, _) => 10)).RunAsync(Opts with { Duration = TimeSpan.FromHours(1), Interval = TimeSpan.FromSeconds(30) });
        Assert.Equal(TimeSpan.FromMinutes(10), r.Ran);
        Assert.Equal(20, r.Samples.Count);
    }

    [Fact]
    public async Task HttpSpeedTester_CapsDownload_AndUsesEndpoints()
    {
        var handler = new FakeHttpHandler(5_000_000);
        var s = new NetworkTestSettings { SpeedServer = "https://speed.example.test/" };
        var t = new HttpSpeedTester(s, new HttpClient(handler));
        var d = await t.DownloadAsync(1_000_000, TimeSpan.FromSeconds(10), CancellationToken.None);
        Assert.Equal(1_000_000, d.Bytes); // server sent 5 MB; only the cap was read
        Assert.Equal("https://speed.example.test/__down?bytes=1000000", handler.Requests[0].RequestUri!.ToString());
        var u = await t.UploadAsync(200_000, TimeSpan.FromSeconds(10), CancellationToken.None);
        Assert.Equal(200_000, u.Bytes);
        Assert.Equal(200_000, handler.UploadedBytes);
        Assert.Equal(HttpMethod.Post, handler.Requests[1].Method);
        Assert.Equal("https://speed.example.test/__up", handler.Requests[1].RequestUri!.ToString());
    }

    [Fact]
    public void Settings_FromEnvironment()
    {
        Assert.Equal(NetworkTestSettings.DefaultSpeedServer, NetworkTestSettings.FromEnvironment(_ => null).SpeedServer);
        Assert.Equal("https://speed.mycompany.example/", NetworkTestSettings.FromEnvironment(_ => "https://speed.mycompany.example").SpeedServer);
        Assert.Equal(NetworkTestSettings.DefaultSpeedServer, NetworkTestSettings.FromEnvironment(_ => "not a url").SpeedServer);
        Assert.Equal("https://speed.cloudflare.com/__down?bytes=25000000", new NetworkTestSettings().DownloadUrl(25_000_000));
    }

    [Fact]
    public void AdapterCounters_Sum()
    {
        var rows = new List<IReadOnlyDictionary<string, string>>
        {
            new Dictionary<string, string> { ["Name"] = "Ethernet", ["ierrors"] = "2", ["oerrors"] = "1", ["idrops"] = "5", ["odrops"] = "" },
            new Dictionary<string, string> { ["Name"] = "Wi-Fi", ["ierrors"] = "0", ["oerrors"] = "0", ["idrops"] = "1", ["odrops"] = "2" },
        };
        Assert.Equal(new AdapterTotals(3, 8), SystemAdapterCounters.Sum(rows));
    }

    [Fact]
    public async Task Module_ExcludedFromRunAll()
    {
        var m = new NetworkTestModule(new FakePinger((_, _) => 10), new FakeGateway("10.0.0.1"), new FakeSpeed(), new FakeCounters(), NoSensors(), clockFactory: () => new FakeStressClock()) { Options = Opts };
        var store = new ResultStore();
        var svc = new DiagnosticsService(store, [m, new FakeModule("Other", _ => Task.FromResult(FakeModule.Ok("Other")))]);
        Assert.Single(await svc.RunAllAsync());
        Assert.Equal(DiagnosticStatus.NotRun, store.Get(NetworkTestModule.ModuleName).Status);
        var r = await svc.RunAsync(NetworkTestModule.ModuleName);
        Assert.Equal("Stable", r.Message);
        Assert.IsType<NetworkTestReport>(r.Payload);
    }
}
