using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Legacy;

namespace RemotePCDiagnostics.Tests;

public class NetworkTests
{
    private const string Json = """
    [{"interface":"12","connection_id":"Ethernet","description":"Intel(R) Ethernet I219-V","manufacturer":"Intel","mac":"00:11:22:33:44:55",
      "connection_status":"2","enabled":"1","physical_adapter":"1","speed":"1000000000","ipackets":"100000","opackets":"50000","ierrors":"3","oerrors":"0","idrops":"10","odrops":"0"},
     {"interface":"14","connection_id":"Wi-Fi","description":"Intel Wi-Fi 6E AX211","mac":"66:77:88:99:AA:BB","connection_status":"7","enabled":"1","physical_adapter":"1",
      "speed":"","ipackets":"","opackets":"","ierrors":"","oerrors":"","idrops":"","odrops":""},
     {"interface":"1","connection_id":"","description":"Hyper-V Virtual Ethernet Adapter","mac":"00:15:5D:00:00:01","connection_status":"2","enabled":"1","physical_adapter":"0"}]
    """;

    [Fact]
    public async Task PhysicalAdapters_WithCounters()
    {
        var r = await new NetworkModule(new OsqueryNetworkSource(ScriptedLauncher.Osquery(new ScriptedLauncher((f, a) => ScriptedLauncher.Ok(Json))))).RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        Assert.Equal("1 of 2 adapters connected · errors within normal range", r.Message);
        var rep = Assert.IsType<AreaReport>(r.Payload);
        Assert.Equal(["Ethernet", "Wi-Fi"], rep.Cards.Select(c => c.Title));
        Assert.Equal("Connected · 1 Gbps", rep.Cards[0].Headline);
        Assert.Equal("3 errors · 10 dropped", rep.Cards[0].Meta);
        Assert.Equal("Error counts aren't reported for this adapter", rep.Cards[1].Meta);
        Assert.Equal("Cable unplugged / no signal", rep.Cards[1].Headline);
    }

    [Fact]
    public void Bluetooth_MediaDisconnected_ShowsNotConnected()
    {
        var bt = new NetworkAdapter("Bluetooth Network Connection", "Bluetooth Device (Personal Area Network)", "Microsoft",
            "58:CD:C9:7F:9B:14", "7", true, true, 3_000_000, null, null, null, null, null, null);
        Assert.Equal("Not connected", bt.FriendlyConnection);
        var rep = NetworkModule.Build([bt]);
        Assert.Equal("Not connected", rep.Cards.Single().Headline);
        Assert.DoesNotContain("Cable", rep.Cards.Single().Headline, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task BlankCounters_FilledFromAdapterStatistics()
    {
        const string osq = """[{"connection_id":"Ethernet 4","description":"Microsoft Hyper-V Network Adapter","mac":"e4:fa","connection_status":"2","enabled":"1","physical_adapter":"1","speed":"0","ipackets":"","ierrors":"","oerrors":""}]""";
        const string ps = """[{"Name":"Ethernet 4","ipackets":"5000","opackets":"4000","ierrors":"0","oerrors":"0","idrops":"2","odrops":"0"}]""";
        var l = new ScriptedLauncher((f, a) => f.StartsWith("osqueryi") ? ScriptedLauncher.Ok(osq) : ScriptedLauncher.Ok(ps));
        var r = await new NetworkModule(new OsqueryNetworkSource(ScriptedLauncher.Osquery(l), new SystemCommandRunner(l))).RefreshAsync(null);
        var card = Assert.IsType<AreaReport>(r.Payload).Cards.Single();
        Assert.Equal("2 dropped", card.Meta);
        Assert.Equal("Connected", card.Headline);
        Assert.Equal("1 of 1 adapter connected · no errors", r.Message);
        Assert.Contains("Get-NetAdapterStatistics", l.Calls[1].Args[^1]);
    }

    [Fact]
    public void HighErrorRate_Warns()
    {
        var a = new NetworkAdapter("Ethernet", "", "", "m", "2", true, true, null, 1000, 0, 50, 0, 0, 0);
        Assert.Equal(AreaLevel.Warning, a.Level);
        var rep = NetworkModule.Build([a]);
        Assert.Equal(DiagnosticStatus.Warning, rep.Status);
        Assert.Equal("1 of 1 adapter connected · 1 with errors", rep.Summary);
    }

    [Fact]
    public void NoneConnected_Warns() =>
        Assert.Equal("Not connected to a network", NetworkModule.Build([new("Wi-Fi", "", "", "m", "7", true, true, null, null, null, null, null, null, null)]).Summary);

    [Fact]
    public void Empty_Friendly() => Assert.Equal("No network adapters were found.", NetworkModule.Build([]).Summary);

    [Fact]
    public void ConnectivityHistory_OrdersEventsAndDistinguishesMissingLogs()
    {
        const string wlan = "Microsoft-Windows-WLAN-AutoConfig/Operational";
        const string profiles = "Microsoft-Windows-NetworkProfile/Operational";
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var history = NetworkDiagnostics.BuildHistory([
            (wlan, [new(now.AddMinutes(-1), wlan, "Microsoft-Windows-WLAN-AutoConfig", 8003, 4, "Disconnected", [], new Dictionary<string, string>())]),
            ("System", [new(now, "System", "e1dexpress", 27, 3, "Link is disconnected", [], new Dictionary<string, string>())]),
            (profiles, null)
        ]);
        Assert.Equal(["Intel Ethernet link dropped", "Wi-Fi disconnected"], history.Rows.Select(r => r.Values[1]));
        Assert.Contains("2 of 3", history.Meta);
        Assert.Equal("Event history unavailable", NetworkDiagnostics.BuildHistory([(wlan, null)]).Headline);
        Assert.Equal("No matching events recorded", NetworkDiagnostics.BuildHistory([(wlan, [])]).Headline);
    }

    [Fact]
    public void Reachability_KeepsGatewayDnsAndDestinationOutcomesSeparate()
    {
        var card = NetworkDiagnostics.BuildProbes(null, null, true, false);
        Assert.Equal(["Unavailable", "Resolved", "No ICMP reply"], card.Rows.Select(r => r.Values[2]));
        Assert.Equal(AreaLevel.Neutral, card.Level);
        Assert.Equal("All three probes responded", NetworkDiagnostics.BuildProbes("192.0.2.1", true, true, true).Headline);
    }

    [Fact]
    public void EmptyIpSnapshot_WithConnectedAdapter_DoesNotClaimOffline()
    {
        // Issue #69: netsh saw no wireless interface and the IP read came back empty while osquery said Wi-Fi was connected.
        var empty = new IpConfigSnapshot([], false, "");
        var rep = WifiConfigModule.Build(null, wlanOk: true, empty, connectedAdapters: 1);
        Assert.Equal("Connected, but IP details couldn't be read", rep.Summary);
        var ip = rep.Cards.Single(c => c.Id == "ipdns");
        Assert.Equal("IP details couldn't be read", ip.Headline);
        Assert.Contains("1 adapter connected", ip.Meta);

        Assert.Equal("No active network connection", WifiConfigModule.Build(null, wlanOk: true, empty).Summary);
        Assert.Equal("No network adapters are currently up", WifiConfigModule.Build(null, wlanOk: true, empty).Cards.Single(c => c.Id == "ipdns").Meta);
    }

    [Fact]
    public void ConnectedCount_MatchesSummaryCount()
    {
        var wifi = new NetworkAdapter("Wi-Fi", "", "", "m", "2", true, true, null, null, null, null, null, null, null);
        var hyperV = new NetworkAdapter("vEthernet", "", "", "v", "2", true, false, null, null, null, null, null, null, null);
        Assert.Equal(1, NetworkModule.ConnectedCount([wifi, hyperV]));
        Assert.StartsWith("1 of 1 adapter connected", NetworkModule.Build([wifi, hyperV]).Summary);
        Assert.Equal(0, NetworkModule.ConnectedCount([wifi with { ConnectionStatus = "7" }]));
    }

    [Theory]
    [InlineData("69%", 69)]
    [InlineData("69 %", 69)]
    [InlineData("100%", 100)]
    [InlineData("150%", 100)]
    [InlineData("%", null)]
    [InlineData("n/a", null)]
    public void ParsePercent_ReadsNumberBeforePercentSign(string text, int? expected) =>
        Assert.Equal(expected, WifiConfigModule.ParsePercent(text));

    [Fact]
    public async Task QueryFails_Friendly()
    {
        var r = await new NetworkModule(new OsqueryNetworkSource(ScriptedLauncher.Osquery(new ScriptedLauncher((f, a) => ScriptedLauncher.Fail())))).RefreshAsync(null);
        Assert.Equal("Couldn't read network adapter details on this PC.", r.Message);
    }
}
