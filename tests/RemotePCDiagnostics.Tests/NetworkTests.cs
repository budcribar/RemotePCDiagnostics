using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;

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
        var r = await new NetworkModule(ScriptedLauncher.Osquery(new ScriptedLauncher((f, a) => ScriptedLauncher.Ok(Json)))).RefreshAsync(null);
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
    public async Task QueryFails_Friendly()
    {
        var r = await new NetworkModule(ScriptedLauncher.Osquery(new ScriptedLauncher((f, a) => ScriptedLauncher.Fail()))).RefreshAsync(null);
        Assert.Equal("Couldn't read network adapter details on this PC.", r.Message);
    }
}
