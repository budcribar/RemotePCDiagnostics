using System.Xml.Linq;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using static RemotePCDiagnostics.Tests.Network.WifiRadioTests;

namespace RemotePCDiagnostics.Tests.Network;

/// <summary>The interactive Wi-Fi connect test (DiagnosticTest #289): connect, ping, judge, and always go back.</summary>
public sealed class WifiConnectTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("wifi-connect-").FullName;
    private WifiRestoreMarker Marker => new(Path.Combine(_dir, "restore.json"));
    public void Dispose() => Directory.Delete(_dir, true);

    private static readonly WifiNetworkSeen Home = Net("Home", -50, saved: true, connected: true);
    private static readonly WifiNetworkSeen Shop = Net("Shop", -60, saved: true);
    private static readonly WifiNetworkSeen Guest = Net("Guest", -65);

    private WifiConnectModule Module(FakeWifi wifi, Func<string, long?>? ping = null, IReadOnlyList<WifiNetworkSeen>? networks = null, Action? onPing = null) =>
        new(new FakeRadio(new([Adapter(networks ?? [Home, Shop, Guest])])), wifi, Marker, delay: (_, ct) => { ct.ThrowIfCancellationRequested(); return Task.CompletedTask; },
            ping: (host, _, _) => { onPing?.Invoke(); return Task.FromResult(ping is null ? 3L : ping(host)); }, isOnlyRoute: _ => true);

    private static WifiConnectReport Report(DiagnosticResult r) => Assert.IsType<WifiConnectReport>(r.Payload);

    [Fact]
    public async Task A_saved_network_connects_pings_and_the_PC_goes_back_to_its_network()
    {
        var wifi = new FakeWifi("Home");
        var m = Module(wifi);
        m.Settings.Ssid = "Shop";

        var r = await m.RefreshAsync(null);

        var rep = Report(r);
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        Assert.Equal(WifiConnectOutcome.Passed, rep.Outcome);
        Assert.Equal("Saved profile", rep.Mode);
        Assert.Equal(30, rep.GatewayPings!.Sent);
        Assert.Equal(0, rep.GatewayPings.LossPercent);
        Assert.Equal((-58, -58), (rep.RssiMin, rep.RssiMax));
        Assert.Equal(WifiRestoreOutcome.Restored, rep.Restore);
        Assert.Equal("Home", rep.OriginalSsid);
        Assert.Equal(["disconnect", "profile Shop", "profile Home"], wifi.Calls);
        Assert.Equal("Home", wifi.Ssid);
        Assert.Null(Marker.Load());
        Assert.Contains("Back on Home.", r.Message);
    }

    [Fact]
    public async Task A_typed_password_connects_with_a_temporary_profile_and_is_forgotten()
    {
        var wifi = new FakeWifi("Home") { Passwords = { ["Guest"] = "correct horse" } };
        var m = Module(wifi);
        m.Settings.Ssid = "Guest";
        m.Settings.Password = "correct horse";

        var r = await m.RefreshAsync(null);

        Assert.Equal(WifiConnectOutcome.Passed, Report(r).Outcome);
        Assert.Equal("Typed password", Report(r).Mode);
        Assert.Null(m.Settings.Password);
        Assert.Contains("temporary Guest", wifi.Calls);
        Assert.DoesNotContain("correct horse", System.Text.Json.JsonSerializer.Serialize(Report(r)));
        Assert.DoesNotContain("correct horse", File.Exists(Path.Combine(_dir, "restore.json")) ? File.ReadAllText(Path.Combine(_dir, "restore.json")) : "");
    }

    [Fact]
    public async Task A_wrong_password_fails_and_still_goes_back()
    {
        var wifi = new FakeWifi("Home") { Passwords = { ["Guest"] = "the right one" } };
        var m = Module(wifi);
        m.Settings.Ssid = "Guest";
        m.Settings.Password = "the wrong one";

        var r = await m.RefreshAsync(null);

        Assert.Equal(DiagnosticStatus.Error, r.Status);
        Assert.Equal(WifiConnectOutcome.CouldNotConnect, Report(r).Outcome);
        Assert.Equal(WifiRestoreOutcome.Restored, Report(r).Restore);
        Assert.Equal("Home", wifi.Ssid);
        Assert.Contains("Check the password", r.Message);
    }

    [Fact]
    public async Task Cancelling_mid_ping_restores_the_original_network()
    {
        var wifi = new FakeWifi("Home");
        WifiConnectModule? m = null;
        var pings = 0;
        m = Module(wifi, onPing: () => { if (++pings == 10) m!.Cancel(); });
        m.Settings.Ssid = "Shop";

        var r = await m.RefreshAsync(null);

        Assert.True(r.Cancelled);
        Assert.Equal("Home", wifi.Ssid);
        Assert.Null(Marker.Load());
    }

    [Fact]
    public async Task A_PC_that_wasnt_on_Wi_Fi_is_disconnected_again()
    {
        var wifi = new FakeWifi(null);
        var m = Module(wifi, networks: [Net("Home", -50, saved: true), Shop]);
        m.Settings.Ssid = "Shop";

        var r = await m.RefreshAsync(null);

        Assert.Equal(WifiRestoreOutcome.Disconnected, Report(r).Restore);
        Assert.Null(wifi.Ssid);
        Assert.Equal(["profile Shop", "disconnect"], wifi.Calls);
    }

    [Fact]
    public async Task Without_a_pick_it_reconnects_to_the_network_the_PC_is_on()
    {
        var wifi = new FakeWifi("Home");
        var r = await Module(wifi).RefreshAsync(null);

        Assert.Equal("Home", Report(r).Ssid);
        Assert.Equal(["disconnect", "profile Home"], wifi.Calls);   // already back on Home: no second reconnect
        Assert.Equal(WifiRestoreOutcome.Restored, Report(r).Restore);
    }

    [Fact]
    public async Task Lost_router_pings_fail_and_lost_internet_pings_only_warn()
    {
        var countdown = 0;
        var everyFifth = Module(new FakeWifi("Home"), ping: host => host == "192.168.1.1" && ++countdown % 5 == 0 ? null : 3);
        var internetDown = Module(new FakeWifi("Home"), ping: host => host == WifiConnect.InternetHost ? null : 3);

        Assert.Equal(WifiConnectOutcome.HighLoss, Report(await everyFifth.RefreshAsync(null)).Outcome);      // 20 % lost
        var net = await internetDown.RefreshAsync(null);
        Assert.Equal(WifiConnectOutcome.InternetLoss, Report(net).Outcome);
        Assert.Equal(DiagnosticStatus.Warning, net.Status);
    }

    [Fact]
    public void A_router_that_never_answers_ping_is_judged_by_the_internet_pings()
    {
        Assert.Equal(WifiConnectOutcome.Passed, WifiConnect.Judge(new("Router", 30, 0, null, null), new("Internet", 30, 30, 12, 20), -55));
        Assert.Equal(WifiConnectOutcome.HighLoss, WifiConnect.Judge(new("Router", 30, 0, null, null), new("Internet", 30, 20, 12, 20), -55));
        Assert.Equal(WifiConnectOutcome.WeakSignal, WifiConnect.Judge(new("Router", 30, 30, 2, 4), new("Internet", 30, 30, 12, 20), -78.5));
        Assert.Equal(WifiConnectOutcome.Passed, WifiConnect.Judge(new("Router", 30, 27, 2, 4), new("Internet", 30, 27, 12, 20), -60));   // exactly 10 %
    }

    [Fact]
    public async Task A_network_without_a_saved_profile_needs_a_password_and_nothing_is_changed()
    {
        var wifi = new FakeWifi("Home");
        var m = Module(wifi);
        m.Settings.Ssid = "Guest";

        var r = await m.RefreshAsync(null);

        Assert.Equal(WifiConnectOutcome.NeedsPassword, Report(r).Outcome);
        Assert.Equal(RunEnd.CouldNotRun, Report(r).RunEnd);
        Assert.Empty(wifi.Calls);
        Assert.Null(Marker.Load());
    }

    [Fact]
    public async Task Connected_without_an_address_fails()
    {
        var wifi = new FakeWifi("Home") { GatewayComes = false };
        var m = Module(wifi);
        m.Settings.Ssid = "Shop";

        Assert.Equal(WifiConnectOutcome.NoAddress, Report(await m.RefreshAsync(null)).Outcome);
        Assert.Equal("Home", wifi.Ssid);
    }

    [Fact]
    public async Task When_the_original_network_doesnt_come_back_the_marker_stays_and_the_next_start_restores_it()
    {
        var wifi = new FakeWifi("Home") { Unreachable = { "Home" } };
        var m = Module(wifi);
        m.Settings.Ssid = "Shop";

        var r = await m.RefreshAsync(null);

        Assert.Equal(WifiRestoreOutcome.Failed, Report(r).Restore);
        Assert.Contains("Windows keeps trying", r.Message);
        Assert.Equal("Home", Marker.Load()?.Profile);

        wifi.Unreachable.Clear();
        await Module(wifi).RestorePendingAsync(default);

        Assert.Equal("Home", wifi.Ssid);
        Assert.Null(Marker.Load());
    }

    [Fact]
    public async Task An_old_marker_is_dropped_without_touching_the_Wi_Fi()
    {
        Marker.Save(new("{x}", "Home", "Home", DateTimeOffset.Now.AddDays(-2)));
        var wifi = new FakeWifi("Shop");

        await Module(wifi).RestorePendingAsync(default);

        Assert.Empty(wifi.Calls);
        Assert.Null(Marker.Load());
    }

    [Fact]
    public async Task No_adapter_with_its_radio_on_cant_run()
    {
        var m = new WifiConnectModule(new FakeRadio(new([Adapter([], hw: false, connected: false)])), new FakeWifi(null), Marker);
        var r = await m.RefreshAsync(null);
        Assert.Equal(WifiConnectOutcome.NoAdapter, Report(r).Outcome);
        Assert.StartsWith("Not supported", r.Message);
    }

    [Fact]
    public void Profiles_are_built_as_escaped_XML_and_only_for_networks_a_password_can_join()
    {
        var xml = WifiConnect.ProfileXml("Tom & Jerry's <5G>", "WPA3-Personal", "p&ss<word>!");
        var doc = XDocument.Parse(xml!);
        XNamespace ns = "http://www.microsoft.com/networking/WLAN/profile/v1";
        Assert.Equal("Tom & Jerry's <5G>", doc.Root!.Element(ns + "name")!.Value);
        Assert.Equal(Convert.ToHexString("Tom & Jerry's <5G>"u8), doc.Descendants(ns + "hex").Single().Value);
        Assert.Equal("WPA3SAE", doc.Descendants(ns + "authentication").Single().Value);
        Assert.Equal("p&ss<word>!", doc.Descendants(ns + "keyMaterial").Single().Value);
        Assert.Equal("manual", doc.Root.Element(ns + "connectionMode")!.Value);

        Assert.Empty(XDocument.Parse(WifiConnect.ProfileXml("Cafe", WifiRadio.Open, null)!).Descendants(ns + "sharedKey"));
        Assert.Null(WifiConnect.ProfileXml("Office", "WPA2-Enterprise", "whatever1"));
        Assert.Null(WifiConnect.ProfileXml("Old", "WEP", "12345678"));
        Assert.Null(WifiConnect.ProfileXml("Home", "WPA2-Personal", "short"));
    }

    [Theory]
    [InlineData("12345678", true)]
    [InlineData("1234567", false)]
    [InlineData("café au lait", false)]
    public void Passphrases(string p, bool valid) => Assert.Equal(valid, WifiConnect.IsValidPassphrase(p));

    /// <summary>A Wi-Fi adapter: saved profiles named by their SSID, typed passwords, and networks that never connect.</summary>
    private sealed class FakeWifi(string? connectedTo) : IWifiConnector
    {
        public string? Ssid { get; private set; } = connectedTo;
        public List<string> Calls { get; } = [];
        public Dictionary<string, string> Passwords { get; } = [];
        public HashSet<string> Unreachable { get; } = [];
        public bool GatewayComes { get; init; } = true;

        public WifiLinkState? Read(string interfaceId) => Ssid is null ? new("Disconnected", null, null, null) : new("Connected", Ssid, Ssid, -58);

        public uint ConnectProfile(string interfaceId, string profileName)
        {
            Calls.Add($"profile {profileName}");
            if (!Unreachable.Contains(profileName)) Ssid = profileName;
            return 0;
        }

        public uint ConnectTemporary(string interfaceId, string profileXml)
        {
            var doc = XDocument.Parse(profileXml);
            var name = doc.Root!.Elements().First().Value;
            Calls.Add($"temporary {name}");
            var key = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "keyMaterial")?.Value;
            if (Passwords.TryGetValue(name, out var right) && right == key) Ssid = name;
            return 0;
        }

        public uint Disconnect(string interfaceId) { Calls.Add("disconnect"); Ssid = null; return 0; }
        public string? Gateway(string interfaceId) => Ssid is not null && GatewayComes ? "192.168.1.1" : null;
    }
}
