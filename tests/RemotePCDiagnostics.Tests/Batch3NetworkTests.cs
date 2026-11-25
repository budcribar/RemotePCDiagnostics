using System.Net;
using System.Net.Sockets;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Stress;
using Xunit;

namespace RemotePCDiagnostics.Tests;

public sealed class Batch3NetworkTests
{
    private const string BudsLaptopInterfaces24Ghz = """
        There is 1 interface on the system:

            Name                   : Wi-Fi
            Description            : Intel(R) Wi-Fi 6E AX211 160MHz
            GUID                   : 12345678-1234-1234-1234-1234567890ab
            Physical address       : aa:bb:cc:dd:ee:ff
            State                  : connected
            SSID                   : HomeNet
            BSSID                  : 11:22:33:44:55:66
            Network type           : Infrastructure
            Radio type             : 802.11n
            Authentication         : WPA2-Personal
            Cipher                 : CCMP
            Connection mode        : Auto Connect
            Band                   : 2.4 GHz
            Channel                : 6
            Receive rate (Mbps)    : 144.4
            Transmit rate (Mbps)   : 130
            Signal                 : 84%
            Profile                : HomeNet
        """;

    private const string BudsLaptopNetworksBssid = """
        Interface name : Wi-Fi
        There are 2 networks currently visible.

        SSID 1 : HomeNet
            Network type            : Infrastructure
            Authentication          : WPA2-Personal
            Encryption              : CCMP
            BSSID 1                 : 11:22:33:44:55:66
                 Signal             : 84%
                 Radio type         : 802.11n
                 Band               : 2.4 GHz
                 Channel            : 6
            BSSID 2                 : 11:22:33:44:55:67
                 Signal             : 78%
                 Radio type         : 802.11ax
                 Band               : 5 GHz
                 Channel            : 149

        SSID 2 : Neighbor5G
            Network type            : Infrastructure
            BSSID 1                 : 99:88:77:66:55:44
                 Signal             : 60%
                 Radio type         : 802.11ac
                 Band               : 5 GHz
                 Channel            : 36
        """;

    private const string BudsLaptopDriversDualBand = """
        Interface name: Wi-Fi

            Driver                    : Intel(R) Wi-Fi 6E AX211 160MHz
            Vendor                    : Intel Corporation
            Radio types supported     : 802.11b 802.11g 802.11n 802.11a 802.11ac 802.11ax
        """;

    private const string LegacyDrivers24Only = """
        Interface name: Wi-Fi

            Driver                    : Legacy 2.4GHz Adapter
            Radio types supported     : 802.11b 802.11g 802.11n
        """;

    // -------------------------------------------------------------------------
    // 3a. Wi-Fi band & slow link rate
    // -------------------------------------------------------------------------

    [Fact]
    public void WifiBand_Flags24GhzOnlyWhenSameSsidOn5Or6GhzAndAdapterSupportsIt()
    {
        var wifi = WifiConfigModule.ParseNetshWlan(BudsLaptopInterfaces24Ghz);
        Assert.NotNull(wifi);
        Assert.True(WifiConfigModule.Is24Ghz(wifi));
        Assert.True(WifiConfigModule.HasSameSsidOn5Or6Ghz(BudsLaptopNetworksBssid, "HomeNet"));
        Assert.False(WifiConfigModule.HasSameSsidOn5Or6Ghz(BudsLaptopNetworksBssid, "Only24Ssid"));
        Assert.True(WifiConfigModule.ParseNetshDriversSupports5Or6Ghz(BudsLaptopDriversDualBand));
        Assert.False(WifiConfigModule.ParseNetshDriversSupports5Or6Ghz(LegacyDrivers24Only));

        var ip = new IpConfigSnapshot([new("Wi-Fi", "Intel AX211", "192.168.1.50", "192.168.1.1", "1.1.1.1")], false, "");

        // Both true -> Warning
        var flagged = WifiConfigModule.Build(wifi, true, ip, bandContext: new(true, true));
        var card1 = Assert.Single(flagged.Cards, c => c.Id == "wifi");
        Assert.Equal(AreaLevel.Warning, card1.Level);
        Assert.Contains("2.4 GHz", card1.Note ?? "");
        // Also has Neutral row for < 150 Mbps link rate (144.4 / 130 Mbps)
        Assert.Contains(card1.Rows, r => r.Level == AreaLevel.Neutral && r.Values[1].Contains("slower than most internet plans"));

        // Same SSID not on 5/6 GHz -> Ok (not flagged)
        var no5g = WifiConfigModule.Build(wifi, true, ip, bandContext: new(false, true));
        Assert.Equal(AreaLevel.Ok, Assert.Single(no5g.Cards, c => c.Id == "wifi").Level);

        // Adapter does not support 5/6 GHz -> Ok (not flagged)
        var legacyAdapter = WifiConfigModule.Build(wifi, true, ip, bandContext: new(true, false));
        Assert.Equal(AreaLevel.Ok, Assert.Single(legacyAdapter.Cards, c => c.Id == "wifi").Level);
    }

    // -------------------------------------------------------------------------
    // 3b. Broken IPv6 fallback
    // -------------------------------------------------------------------------

    [Fact]
    public async Task Ipv6Fallback_WarnsWhenIpv6FailsAndIpv4Works()
    {
        Assert.True(NetworkDiagnostics.IsGlobalUnicastIpv6(IPAddress.Parse("2606:4700:4700::1111")));
        Assert.False(NetworkDiagnostics.IsGlobalUnicastIpv6(IPAddress.Parse("fe80::1")));
        Assert.False(NetworkDiagnostics.IsGlobalUnicastIpv6(IPAddress.Parse("fd12:3456::1")));
        Assert.False(NetworkDiagnostics.IsGlobalUnicastIpv6(IPAddress.IPv6Loopback));

        var broken = await NetworkDiagnostics.ProbeIpv6FallbackAsync(
            "speed.cloudflare.com",
            TimeSpan.FromSeconds(3),
            hasGlobalIpv6WithRoute: () => true,
            tcpConnect: (_, family, _, _) => Task.FromResult(family == AddressFamily.InterNetwork));

        Assert.True(broken.BrokenIpv6Fallback);
        var card = NetworkDiagnostics.BuildProbes("192.168.1.1", true, true, true, broken);
        Assert.Equal(AreaLevel.Warning, card.Level);
        Assert.Contains(card.Rows, r => r.Level == AreaLevel.Warning && r.Values[0] == "IPv6 fallback");

        // No global IPv6 route -> probe skipped, no sockets opened
        var calls = 0;
        var skipped = await NetworkDiagnostics.ProbeIpv6FallbackAsync(
            "speed.cloudflare.com",
            TimeSpan.FromSeconds(3),
            hasGlobalIpv6WithRoute: () => false,
            tcpConnect: (_, _, _, _) => { calls++; return Task.FromResult(true); });
        Assert.False(skipped.HasGlobalIpv6WithRoute);
        Assert.Equal(0, calls);
    }

    // -------------------------------------------------------------------------
    // 3c. Bufferbloat grading boundaries & evaluation
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData(0, "A")]
    [InlineData(29, "A")]
    [InlineData(30, "B")]
    [InlineData(59, "B")]
    [InlineData(60, "C")]
    [InlineData(199, "C")]
    [InlineData(200, "D")]
    [InlineData(399, "D")]
    [InlineData(400, "F")]
    public void Bufferbloat_GradeBoundaries(double addedMs, string expectedGrade) =>
        Assert.Equal(expectedGrade, BufferbloatResult.GradeForAddedMs(addedMs));

    [Fact]
    public void Bufferbloat_Evaluate_HandlesFullPartialAndUngraded()
    {
        double[] idle = [10, 10, 10, 10, 10];
        double[] dl = [35, 35, 35, 35, 35]; // +25 -> A
        double[] ul = [90, 90, 90, 90, 90]; // +80 -> C

        var both = BufferbloatResult.Evaluate(idle, dl, ul);
        Assert.Equal("C", both.Grade);
        Assert.False(both.IsPartial);
        Assert.Equal(25, both.DownloadAddedMs);
        Assert.Equal(80, both.UploadAddedMs);

        var partialDl = BufferbloatResult.Evaluate(idle, dl, [90, 90], uploadBudgetExhausted: true);
        Assert.Equal("A", partialDl.Grade);
        Assert.True(partialDl.IsPartial);
        Assert.Equal("Download", partialDl.MeasuredDirection);
        Assert.Contains("budget", partialDl.UngradedReason ?? "", StringComparison.OrdinalIgnoreCase);

        var ungradedBaseline = BufferbloatResult.Evaluate([10, 10, 10], dl, ul);
        Assert.Null(ungradedBaseline.Grade);
        Assert.Equal("Not graded", ungradedBaseline.HeadlineText);

        var ungradedLoaded = BufferbloatResult.Evaluate(idle, [35, 35], [90], downloadBudgetExhausted: true, uploadBudgetExhausted: true);
        Assert.Null(ungradedLoaded.Grade);
        Assert.Contains("budget", ungradedLoaded.UngradedReason ?? "", StringComparison.OrdinalIgnoreCase);
    }

    // -------------------------------------------------------------------------
    // 3c. Bufferbloat end-to-end with fake clock, pinger, and chunk-looping speed client
    // -------------------------------------------------------------------------

    [Fact]
    public async Task NetworkTest_OrdinaryFastLink_LoopsChunksAndGradesBothDirections()
    {
        var clock = new FakeStressClock(beforeDelay: (_, ct) => Task.Delay(25, ct));
        var phase = "idle";
        var dlChunks = 0;
        var ulChunks = 0;
        var dlRequested = new List<long>();
        var ulRequested = new List<long>();

        var settings = new NetworkTestSettings
        {
            OrdinaryDownloadBytes = 120_000_000,
            OrdinaryUploadBytes = 60_000_000,
            MaxDownloadChunkBytes = 50_000_000,
            MaxUploadChunkBytes = 25_000_000,
            DirectionTimeCeiling = TimeSpan.FromSeconds(5),
        };

        var pinger = new FakePinger((h, _) => phase switch
        {
            "down" => 55, // +45 ms -> B
            "up" => 25,   // +15 ms -> A
            _ => 10,      // idle 10 ms
        });

        var speed = new ScriptedSpeedTester(
            onDownload: async (maxBytes, _, ct) =>
            {
                phase = "down";
                dlChunks++;
                dlRequested.Add(maxBytes);
                var start = clock.Elapsed;
                await Task.Delay(18, ct); // let dense probes complete inside this chunk window
                var end = clock.Elapsed + TimeSpan.FromMilliseconds(500);
                return new TransferResult(maxBytes, TimeSpan.FromMilliseconds(500), FirstPayloadByteAt: start, LastPayloadByteAt: end, ClientObservedBytes: maxBytes);
            },
            onUpload: async (bytes, _, ct) =>
            {
                phase = "up";
                ulChunks++;
                ulRequested.Add(bytes);
                var start = clock.Elapsed;
                await Task.Delay(18, ct);
                var end = clock.Elapsed + TimeSpan.FromMilliseconds(500);
                return new TransferResult(bytes, TimeSpan.FromMilliseconds(500), FirstPayloadByteAt: start, LastPayloadByteAt: end, ClientObservedBytes: bytes);
            });

        var test = new NetworkTest(
            pinger,
            new FakeGateway("192.168.1.1"),
            speed,
            new FakeCounters(new AdapterTotals(0, 0), new AdapterTotals(0, 0)),
            new SequenceSensorProvider(_ => throw new PlatformNotSupportedException(), available: false),
            settings,
            clock,
            connectionCost: new FixedCost(ConnectionCostKind.Unrestricted),
            wifiLinkRate: new FixedWifiLink("866 / 866 Mbps"),
            probeDelay: (_, ct) => Task.Delay(2, ct));

        var opts = new NetworkTestOptions
        {
            Duration = TimeSpan.FromSeconds(14),
            Interval = TimeSpan.FromSeconds(1),
            SpeedTestDelay = TimeSpan.FromSeconds(2),
            BufferbloatProbeInterval = TimeSpan.FromMilliseconds(2),
        };

        var report = await test.RunAsync(opts);

        Assert.Equal(NetworkTestOutcome.Stable, report.Outcome);
        Assert.Equal([50_000_000L, 50_000_000L, 20_000_000L], dlRequested);
        Assert.Equal([25_000_000L, 25_000_000L, 10_000_000L], ulRequested);
        Assert.Equal(3, dlChunks);
        Assert.Equal(3, ulChunks);
        Assert.NotNull(report.DownloadMbps);
        Assert.NotNull(report.UploadMbps);
        Assert.Equal("866 / 866 Mbps", report.WifiLinkRateText);
        Assert.NotNull(report.Bufferbloat);
        Assert.Equal("B", report.Bufferbloat!.Grade);
        Assert.False(report.Bufferbloat.IsPartial);
        Assert.Equal(14, report.Samples.Count); // 1s stability cadence untouched
    }

    [Fact]
    public async Task NetworkTest_OrdinaryLinkWithFastUploadExhaustion_ProducesPartialDownloadGrade()
    {
        var clock = new FakeStressClock(beforeDelay: (_, ct) => Task.Delay(25, ct));
        var phase = "idle";
        var pinger = new FakePinger((_, _) => phase == "down" ? 30 : 10);

        var speed = new ScriptedSpeedTester(
            onDownload: async (maxBytes, _, ct) =>
            {
                phase = "down";
                var start = clock.Elapsed;
                await Task.Delay(30, ct);
                return new TransferResult(maxBytes, TimeSpan.FromSeconds(1), FirstPayloadByteAt: start, LastPayloadByteAt: clock.Elapsed + TimeSpan.FromMilliseconds(200), ClientObservedBytes: maxBytes);
            },
            onUpload: (bytes, _, _) =>
            {
                phase = "up";
                // Instantaneous upload exhausts budget before probes can land inside the payload window
                var t = clock.Elapsed;
                return Task.FromResult(new TransferResult(bytes, TimeSpan.FromMilliseconds(50), FirstPayloadByteAt: t + TimeSpan.FromSeconds(10), LastPayloadByteAt: t + TimeSpan.FromSeconds(10), ClientObservedBytes: bytes));
            });

        var settings = new NetworkTestSettings { OrdinaryDownloadBytes = 50_000_000, OrdinaryUploadBytes = 25_000_000 };
        var test = new NetworkTest(
            pinger, new FakeGateway(null), speed, new FakeCounters(),
            new SequenceSensorProvider(_ => throw new PlatformNotSupportedException(), available: false),
            settings, clock,
            connectionCost: new FixedCost(ConnectionCostKind.Unrestricted),
            probeDelay: async (_, ct) => { ct.ThrowIfCancellationRequested(); await Task.Yield(); });

        var report = await test.RunAsync(new NetworkTestOptions { Duration = TimeSpan.FromSeconds(10), SpeedTestDelay = TimeSpan.FromSeconds(2) });

        Assert.NotNull(report.DownloadMbps);
        Assert.NotNull(report.UploadMbps);
        Assert.NotNull(report.Bufferbloat);
        Assert.True(report.Bufferbloat!.IsPartial);
        Assert.Equal("Download", report.Bufferbloat.MeasuredDirection);
        Assert.Equal("A", report.Bufferbloat.Grade);
    }

    [Fact]
    public async Task NetworkTest_MeteredBudgetExhaustion_IsUngradedButKeepsSpeed()
    {
        var clock = new FakeStressClock();
        var dlReqs = new List<long>();
        var ulReqs = new List<long>();
        var speed = new ScriptedSpeedTester(
            onDownload: (bytes, _, _) =>
            {
                dlReqs.Add(bytes);
                var t = clock.Elapsed + TimeSpan.FromSeconds(10);
                return Task.FromResult(new TransferResult(bytes, TimeSpan.FromMilliseconds(200), FirstPayloadByteAt: t, LastPayloadByteAt: t, ClientObservedBytes: bytes));
            },
            onUpload: (bytes, _, _) =>
            {
                ulReqs.Add(bytes);
                var t = clock.Elapsed + TimeSpan.FromSeconds(10);
                return Task.FromResult(new TransferResult(bytes, TimeSpan.FromMilliseconds(200), FirstPayloadByteAt: t, LastPayloadByteAt: t, ClientObservedBytes: bytes));
            });

        var test = new NetworkTest(
            new FakePinger((_, _) => 12), new FakeGateway(null), speed, new FakeCounters(),
            new SequenceSensorProvider(_ => throw new PlatformNotSupportedException(), available: false),
            new NetworkTestSettings(), clock,
            connectionCost: new FixedCost(ConnectionCostKind.Metered),
            probeDelay: (_, ct) => Task.Delay(2, ct));

        var report = await test.RunAsync(new NetworkTestOptions { Duration = TimeSpan.FromSeconds(8), SpeedTestDelay = TimeSpan.FromSeconds(1) });

        Assert.Equal([25_000_000L], dlReqs);
        Assert.Equal([10_000_000L], ulReqs);
        Assert.NotNull(report.DownloadMbps);
        Assert.NotNull(report.UploadMbps);
        Assert.NotNull(report.Bufferbloat);
        Assert.Null(report.Bufferbloat!.Grade);
        Assert.Equal("Not graded", report.Bufferbloat.HeadlineText);
    }

    [Fact]
    public async Task NetworkTest_PartialTimedOutUploadBytesReduceBudget_AndInterChunkGapsContributeNoProbes()
    {
        var clock = new FakeStressClock();
        var ulReqs = new List<long>();
        var attempt = 0;

        var speed = new ScriptedSpeedTester(
            onDownload: (bytes, _, _) =>
            {
                // Window is strictly [t+50s, t+50s], so all probes occurring at clock.Elapsed (~1-8s) are outside payload windows (simulating inter-chunk gap / setup)
                var future = TimeSpan.FromSeconds(50);
                return Task.FromResult(new TransferResult(bytes, TimeSpan.FromSeconds(1), FirstPayloadByteAt: future, LastPayloadByteAt: future, ClientObservedBytes: bytes));
            },
            onUpload: (bytes, _, _) =>
            {
                ulReqs.Add(bytes);
                attempt++;
                if (attempt == 1)
                {
                    // Timed out after writing 6 MB client-observed bytes: must reduce remaining 10 MB budget to 4 MB, and not count toward Mbps!
                    return Task.FromResult(new TransferResult(0, TimeSpan.FromSeconds(2), Error: "timeout", FirstPayloadByteAt: TimeSpan.FromSeconds(50), LastPayloadByteAt: TimeSpan.FromSeconds(50), ClientObservedBytes: 6_000_000));
                }
                return Task.FromResult(new TransferResult(bytes, TimeSpan.FromSeconds(1), FirstPayloadByteAt: TimeSpan.FromSeconds(50), LastPayloadByteAt: TimeSpan.FromSeconds(50), ClientObservedBytes: bytes));
            });

        var test = new NetworkTest(
            new FakePinger((_, _) => 15), new FakeGateway(null), speed, new FakeCounters(),
            new SequenceSensorProvider(_ => throw new PlatformNotSupportedException(), available: false),
            new NetworkTestSettings { UploadBytes = 10_000_000, MaxUploadChunkBytes = 10_000_000 }, clock,
            connectionCost: new FixedCost(ConnectionCostKind.Metered),
            probeDelay: (_, ct) => Task.Delay(2, ct));

        var report = await test.RunAsync(new NetworkTestOptions { Duration = TimeSpan.FromSeconds(8), SpeedTestDelay = TimeSpan.FromSeconds(1) });

        // First chunk requested 10 MB, wrote 6 MB before timing out; second chunk requested only the remaining 4 MB!
        Assert.Equal([10_000_000L, 4_000_000L], ulReqs);
        // Upload speed only reflects the 4 MB usable transfer in 1s = 32 Mbps (not the timed-out 6 MB).
        Assert.Equal(32.0, report.UploadMbps);
        // Zero probes landed inside payload windows -> 0 qualified download & upload samples.
        Assert.Equal(0, report.Bufferbloat!.DownloadSamples);
        Assert.Equal(0, report.Bufferbloat.UploadSamples);
        Assert.Null(report.Bufferbloat.Grade);
    }

    [Fact]
    public async Task NetworkTest_BlockedIcmp_LeavesBufferbloatUngradedAndKeepsSpeedAndStableOutcome()
    {
        var clock = new FakeStressClock();
        var test = new NetworkTest(
            new FakePinger((_, _) => null),
            new FakeGateway(null),
            new FakeSpeed(),
            new FakeCounters(),
            new SequenceSensorProvider(_ => throw new PlatformNotSupportedException(), available: false),
            new NetworkTestSettings(),
            clock,
            probeDelay: (_, ct) => Task.Delay(2, ct));

        var report = await test.RunAsync(new NetworkTestOptions { Duration = TimeSpan.FromSeconds(8), SpeedTestDelay = TimeSpan.FromSeconds(1) });

        Assert.Equal(NetworkTestOutcome.Stable, report.Outcome);
        Assert.NotNull(report.DownloadMbps);
        Assert.NotNull(report.UploadMbps);
        Assert.NotNull(report.Bufferbloat);
        Assert.Null(report.Bufferbloat!.Grade);
        Assert.Contains("ICMP", report.Bufferbloat.UngradedReason ?? "", StringComparison.OrdinalIgnoreCase);
    }

    // -------------------------------------------------------------------------
    // Fakes
    // -------------------------------------------------------------------------

    private sealed class FixedCost(ConnectionCostKind kind) : IConnectionCostProvider
    {
        public ConnectionCostKind GetConnectionCost() => kind;
    }

    private sealed class FixedWifiLink(string? text) : IWifiLinkRateReader
    {
        public Task<string?> ReadLinkRateTextAsync(CancellationToken ct) => Task.FromResult(text);
    }

    private sealed class ScriptedSpeedTester(
        Func<long, TimeSpan, CancellationToken, Task<TransferResult>> onDownload,
        Func<long, TimeSpan, CancellationToken, Task<TransferResult>> onUpload) : ISpeedTester
    {
        public Task<TransferResult> DownloadAsync(long maxBytes, TimeSpan timeout, CancellationToken cancellationToken) =>
            onDownload(maxBytes, timeout, cancellationToken);

        public Task<TransferResult> UploadAsync(long bytes, TimeSpan timeout, CancellationToken cancellationToken) =>
            onUpload(bytes, timeout, cancellationToken);
    }
}
