using System.Runtime.InteropServices;
using System.Text.Json;
using System.Xml.Linq;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Recording;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Tests.Network;

/// <summary>The Network check's Wi-Fi radio and scan cards (DiagnosticTest #289).</summary>
public class WifiRadioTests
{
    private const string Id = "{6a1f0c3e-8b2d-4e5f-9a7b-1c2d3e4f5a6b}";

    internal static WifiNetworkSeen Net(string ssid, int rssi, int mhz = 5180, string security = "WPA2-Personal", bool saved = false, bool connected = false) =>
        new(ssid, security, rssi, WifiRadio.QualityOf(rssi), mhz, saved, connected, saved ? ssid : null, 1, [WifiRadio.BandOf(mhz)]);

    internal static WifiRadioInterface Adapter(IReadOnlyList<WifiNetworkSeen> networks, bool? sw = true, bool? hw = true, bool connected = true,
        bool? dual = true, bool refused = false) =>
        new(Id, "Intel(R) Wi-Fi 6E AX211 160MHz", connected ? "Connected" : "Disconnected", sw, hw,
            connected ? networks.FirstOrDefault(n => n.Connected)?.Ssid : null, connected ? networks.FirstOrDefault(n => n.Connected)?.ProfileName : null,
            connected ? networks.FirstOrDefault(n => n.Connected)?.Rssi : null, networks, dual, refused);

    private static AreaCard Card(IReadOnlyList<AreaCard> cards, string id) => cards.Single(c => c.Id == id);

    [Fact]
    public void A_working_radio_that_sees_networks_passes_and_lists_them_strongest_first()
    {
        var reading = new WifiRadioReading([Adapter([Net("Shop", -48, saved: true, connected: true), Net("Cafe", -70, 2437), Net("Far", -88, 2412)])], AirplaneMode: false);

        var cards = WifiRadio.BuildCards(reading);

        var radio = Card(cards, WifiRadio.RadioCardId);
        Assert.Equal(AreaLevel.Ok, radio.Level);
        Assert.Equal("Radio on", radio.Headline);
        Assert.Equal(WifiRadio.ConnectTestPath, radio.OpenPage?.Path);
        Assert.Contains(radio.Rows, r => r.Values[0] == "Connected signal" && r.Values[1] == "-48 dBm (100%)");
        var scan = Card(cards, WifiRadio.ScanCardId);
        Assert.Equal(AreaLevel.Ok, scan.Level);
        Assert.Equal("3 networks found · strongest -48 dBm", scan.Headline);
        Assert.Equal(["Shop", "Cafe", "Far"], scan.Rows.Select(r => r.Values[0]));
        Assert.Equal(["Shop", "WPA2-Personal", "5 GHz", "36", "-48 dBm", "Connected"], scan.Rows[0].Values);
        Assert.Equal(AreaLevel.Warning, scan.Rows[2].Level);   // −88 dBm is weak
    }

    [Fact]
    public void The_hardware_switch_off_fails_and_nothing_is_scanned()
    {
        var cards = WifiRadio.BuildCards(new([Adapter([], sw: true, hw: false, connected: false)]));

        var radio = Card(cards, WifiRadio.RadioCardId);
        Assert.Equal(AreaLevel.Error, radio.Level);
        Assert.Equal("Wi-Fi radio is off by its hardware switch", radio.Headline);
        Assert.Null(radio.OpenPage);
        var scan = Card(cards, WifiRadio.ScanCardId);
        Assert.Equal(AreaLevel.Neutral, scan.Level);
        Assert.Equal("Not scanned: the radio is off", scan.Headline);
    }

    [Fact]
    public void A_radio_that_is_on_but_sees_nothing_fails_no_networks_found()
    {
        var scan = Card(WifiRadio.BuildCards(new([Adapter([], connected: false)])), WifiRadio.ScanCardId);

        Assert.Equal(AreaLevel.Error, scan.Level);
        Assert.Equal("No networks found", scan.Headline);
        Assert.Contains("antenna", scan.EmptyText);
    }

    [Fact]
    public void A_refused_scan_warns_about_location_access_instead_of_failing()
    {
        var cards = WifiRadio.BuildCards(new([Adapter([], connected: false, refused: true)]));

        Assert.Equal(AreaLevel.Warning, Card(cards, WifiRadio.ScanCardId).Level);
        Assert.Contains("location", Card(cards, WifiRadio.ScanCardId).Headline);
        Assert.Contains("Location", Card(cards, WifiRadio.RadioCardId).Note);
    }

    [Fact]
    public void A_weak_strongest_network_warns()
    {
        var scan = Card(WifiRadio.BuildCards(new([Adapter([Net("Only", -80, connected: true, saved: true)])])), WifiRadio.ScanCardId);

        Assert.Equal(AreaLevel.Warning, scan.Level);
        Assert.Contains("weaker than -75 dBm", scan.Meta);
    }

    [Fact]
    public void Airplane_mode_the_Windows_toggle_and_a_24_GHz_only_card_warn()
    {
        Assert.Equal("Airplane mode is on", Card(WifiRadio.BuildCards(new([Adapter([], sw: false, connected: false)], AirplaneMode: true)), WifiRadio.RadioCardId).Headline);
        Assert.Equal("Wi-Fi is turned off in Windows", Card(WifiRadio.BuildCards(new([Adapter([], sw: false, connected: false)], AirplaneMode: false)), WifiRadio.RadioCardId).Headline);
        var only24 = Card(WifiRadio.BuildCards(new([Adapter([Net("N", -50, 2412, connected: true)], dual: false)])), WifiRadio.RadioCardId);
        Assert.Equal(AreaLevel.Warning, only24.Level);
        Assert.Equal("Radio on · 2.4 GHz only", only24.Headline);
    }

    [Fact]
    public void A_card_with_a_driver_problem_fails_even_without_a_Wi_Fi_interface()
    {
        var radio = Card(WifiRadio.BuildCards(new([]), [new("Intel(R) Wi-Fi 6 AX201 160MHz", 43)]), WifiRadio.RadioCardId);

        Assert.Equal(AreaLevel.Error, radio.Level);
        Assert.Equal("Wi-Fi card has a driver problem (code 43)", radio.Headline);
        Assert.Contains("Windows stopped it", radio.Rows[0].Values[1]);
    }

    [Fact]
    public void A_PC_without_Wi_Fi_gets_no_cards_even_when_WlanSvc_is_stopped_but_a_PC_with_Wi_Fi_hardware_fails()
    {
        Assert.Empty(WifiRadio.BuildCards(new([])));
        Assert.Empty(WifiRadio.BuildCards(new([], ServiceRunning: false)));
        var radio = Card(WifiRadio.BuildCards(new([], ServiceRunning: false), hasWifiHardware: true), WifiRadio.RadioCardId);
        Assert.Equal(AreaLevel.Error, radio.Level);
        Assert.Equal("The WLAN AutoConfig service isn't running", radio.Headline);
    }

    [Fact]
    public void Multi_adapter_mixed_hardware_and_software_radio_off_reports_radio_off()
    {
        var reading = new WifiRadioReading([
            Adapter([], sw: true, hw: false, connected: false),
            Adapter([], sw: false, hw: true, connected: false) with { Id = "{2}", Description = "USB Wi-Fi" },
        ]);

        var radio = Card(WifiRadio.BuildCards(reading), WifiRadio.RadioCardId);
        Assert.Equal(AreaLevel.Warning, radio.Level);
        Assert.Equal("Wi-Fi radio is off", radio.Headline);
    }

    [Fact]
    public async Task An_Ethernet_only_desktop_with_WlanSvc_stopped_stays_green_in_the_Network_check()
    {
        var ethernetOnly = new FakeNetworkSource(problems: [], adapters:
            [new NetworkAdapter("Ethernet", "Realtek PCIe GbE Family Controller", "Realtek", "aa:bb", "2", true, true, null, null, null, null, null, null, null)]);
        var module = new NetworkModule(ethernetOnly, includeWifiAndIpConfig: true, offline: true,
            radio: new FakeRadio(new([], ServiceRunning: false)));

        var r = await module.RefreshAsync(null);

        var rep = Assert.IsType<AreaReport>(r.Payload);
        Assert.DoesNotContain(rep.Cards, c => c.Id == WifiRadio.RadioCardId);
        Assert.DoesNotContain(rep.Cards, c => c.Id == WifiRadio.ScanCardId);
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
    }

    [Theory]
    [InlineData(2412, "2.4 GHz", 1)]
    [InlineData(2484, "2.4 GHz", 14)]
    [InlineData(5180, "5 GHz", 36)]
    [InlineData(5825, "5 GHz", 165)]
    [InlineData(5955, "6 GHz", 1)]
    [InlineData(6415, "6 GHz", 93)]
    public void Frequencies_map_to_band_and_channel(int mhz, string band, int channel)
    {
        Assert.Equal(band, WifiRadio.BandOf(mhz));
        Assert.Equal(channel, WifiRadio.ChannelOf(mhz));
    }

    [Fact]
    public void Networks_are_joined_by_name_with_the_strongest_access_point()
    {
        var joined = WlanRadioSource.Join(
            [("Shop", "WPA2-Personal", 60, false, false, "", 2), ("Shop", "WPA2-Personal", 60, true, true, "Shop", 2), ("Guest", "Open", 30, false, false, "", 1)],
            [("Shop", -71, 2437), ("Shop", -52, 5500), ("Guest", -83, 2462)]);

        var shop = joined.Single(n => n.Ssid == "Shop");
        Assert.Equal(-52, shop.Rssi);
        Assert.Equal(100, shop.Channel);
        Assert.True(shop.Connected);
        Assert.True(shop.HasProfile);
        Assert.Equal("Shop", shop.ProfileName);
        Assert.Equal(["2.4 GHz", "5 GHz"], shop.Bands);
        Assert.True(joined.Single(n => n.Ssid == "Guest").CanTypePassword);
    }

    [Theory]
    [InlineData(7, 4, true, "WPA2-Personal")]
    [InlineData(9, 4, true, "WPA3-Personal")]
    [InlineData(6, 4, true, "WPA2-Enterprise")]
    [InlineData(1, 0, false, "Open")]
    [InlineData(1, 1, true, "WEP")]
    [InlineData(10, 4, false, "Enhanced Open")]
    public void Security_names(int auth, int cipher, bool enabled, string name) => Assert.Equal(name, WifiRadio.SecurityName(auth, cipher, enabled));

    [Fact]
    public void A_reading_survives_JSON_and_recordings_keep_no_network_names()
    {
        var reading = new WifiRadioReading([Adapter([Net("Bud's home", -48, saved: true, connected: true), Net("Neighbour", -77)])], AirplaneMode: false);

        Assert.Equal(reading.ToJson(), WifiRadioReading.FromJson(reading.ToJson()).ToJson());
        var call = RecordedCall.FromWifi(reading);
        Assert.Equal(RecordedCall.WifiKind, call.Kind);
        Assert.DoesNotContain("Bud", call.StdOut);
        Assert.DoesNotContain("Neighbour", call.StdOut);
        var replayed = WifiRadioReading.FromJson(call.StdOut);
        Assert.Equal(["Network 1", "Network 2"], replayed.Interfaces[0].Networks.Select(n => n.Ssid));
        Assert.Equal("Network 1", replayed.Interfaces[0].ConnectedSsid);
        Assert.Equal("Network 1", replayed.Interfaces[0].ConnectedProfile);
    }

    [Fact]
    public async Task The_replay_answers_with_the_recorded_reading()
    {
        var reading = new WifiRadioReading([Adapter([], hw: false, connected: false)]);
        var rec = new MachineRecording { Calls = [RecordedCall.FromWifi(reading)] };

        var replayed = await new RecordingReplay(rec).Wifi.ReadAsync(scan: true, default);

        Assert.False(replayed.Interfaces.Single().HardwareOn);
    }

    [Fact]
    public async Task The_Network_check_adds_the_radio_cards_and_a_radio_fault_leads_its_summary()
    {
        var source = new FakeNetworkSource(problems: []);
        var module = new NetworkModule(source, includeWifiAndIpConfig: true, offline: true,
            radio: new FakeRadio(new([Adapter([], connected: false)])));

        var r = await module.RefreshAsync(null);

        var rep = Assert.IsType<AreaReport>(r.Payload);
        Assert.Contains(rep.Cards, c => c.Id == WifiRadio.RadioCardId);
        Assert.Equal(AreaLevel.Error, rep.Cards.Single(c => c.Id == WifiRadio.ScanCardId).Level);
        Assert.StartsWith("No networks found · ", rep.Summary);
        Assert.Equal(DiagnosticStatus.Error, r.Status);
        Assert.True(source.ProblemsAsked);
    }

    [Fact]
    public async Task Without_a_radio_source_the_Network_check_doesnt_ask_for_device_problems()
    {
        var source = new FakeNetworkSource(problems: []);
        await new NetworkModule(source, includeWifiAndIpConfig: true, offline: true).RefreshAsync(null);
        Assert.False(source.ProblemsAsked);
    }

    [Fact]
    public async Task Device_problems_come_from_WMI_for_Wi_Fi_cards_only()
    {
        var wmi = new FakeWmi(new()
        {
            [WmiNetworkSource.ProblemDevicesSql] = [Row(("Name", "Intel(R) Wi-Fi 6 AX201 160MHz"), ("ConfigManagerErrorCode", 10)), Row(("Name", "Realtek PCIe GbE Family Controller"), ("ConfigManagerErrorCode", 22))],
        });

        var problems = await new WmiNetworkSource(wmi, new FakeRegistry()).ReadWifiDeviceProblemsAsync(default);

        Assert.Equal([new WifiDeviceProblem("Intel(R) Wi-Fi 6 AX201 160MHz", 10)], problems);
    }

    [Fact]
    public void The_Interactive_tests_export_lists_the_networks_but_never_a_password()
    {
        var page = new InteractiveExport.PageState("wifi", ["wifi"], false, false, true, false);
        var nets = new[] { Net("Shop", -50, saved: true, connected: true), Net("Office", -60, security: "WPA2-Enterprise") };
        var report = new WifiConnectReport(WifiConnectOutcome.Passed, "Shop", "Saved profile", "Intel", 3.5, "192.168.1.1",
            new PingStats("Router", 30, 30, 2.1, 9), new PingStats("Internet", 30, 29, 14, 40), -55, -49, -51.2, WifiRestoreOutcome.Restored, "Shop");
        var result = WifiConnect.ToResult(report);
        var notRun = new InteractiveExport.ModuleState(DiagnosticResult.NotRun("x"), false);

        var json = InteractiveExport.ToJson(page, new PhysicalBenchQaSnapshot(), notRun, notRun, notRun, wifi: result,
            wifiPane: new(nets, "Shop", PasswordTyped: true, DropsRemoteSession: true, Scanning: false));
        using var doc = JsonDocument.Parse(json);
        var wifi = doc.RootElement.GetProperty("tests").EnumerateArray().Single(t => t.GetProperty("id").GetString() == "wifi");

        Assert.Equal("done", wifi.GetProperty("state").GetString());
        Assert.Equal("passed", wifi.GetProperty("result").GetString());
        Assert.True(wifi.GetProperty("dropsRemoteSession").GetBoolean());
        Assert.False(wifi.GetProperty("networks")[1].GetProperty("canTest").GetBoolean());
        Assert.False(wifi.GetProperty("networks")[1].GetProperty("needsPassword").GetBoolean());
        Assert.Equal(30, wifi.GetProperty("measured").GetProperty("routerPings").GetProperty("received").GetInt32());
        Assert.Equal("router", wifi.GetProperty("measured").GetProperty("gateway").GetString());
        Assert.DoesNotContain("\"password\"", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("192.168", json);
    }

    /// <summary>The WLAN API structures are read at fixed offsets; these C# mirrors of wlanapi.h lay out as MSVC does, so they pin them.</summary>
    [Fact]
    public void WLAN_structure_offsets_match_wlanapi_h()
    {
        Assert.Equal(WlanApi.BssEntrySize, Marshal.SizeOf<WlanLayout.BssEntry>());
        Assert.Equal(WlanApi.BssRssi, (int)Marshal.OffsetOf<WlanLayout.BssEntry>(nameof(WlanLayout.BssEntry.lRssi)));
        Assert.Equal(WlanApi.BssFrequencyKhz, (int)Marshal.OffsetOf<WlanLayout.BssEntry>(nameof(WlanLayout.BssEntry.ulChCenterFrequency)));
        Assert.Equal(WlanApi.AvailableNetworkSize, Marshal.SizeOf<WlanLayout.AvailableNetwork>());
        Assert.Equal(WlanApi.AnSsid, (int)Marshal.OffsetOf<WlanLayout.AvailableNetwork>(nameof(WlanLayout.AvailableNetwork.dot11Ssid)));
        Assert.Equal(WlanApi.AnBssCount, (int)Marshal.OffsetOf<WlanLayout.AvailableNetwork>(nameof(WlanLayout.AvailableNetwork.uNumberOfBssids)));
        Assert.Equal(WlanApi.AnSignal, (int)Marshal.OffsetOf<WlanLayout.AvailableNetwork>(nameof(WlanLayout.AvailableNetwork.wlanSignalQuality)));
        Assert.Equal(WlanApi.AnSecurityEnabled, (int)Marshal.OffsetOf<WlanLayout.AvailableNetwork>(nameof(WlanLayout.AvailableNetwork.bSecurityEnabled)));
        Assert.Equal(WlanApi.AnAuth, (int)Marshal.OffsetOf<WlanLayout.AvailableNetwork>(nameof(WlanLayout.AvailableNetwork.dot11DefaultAuthAlgorithm)));
        Assert.Equal(WlanApi.AnCipher, (int)Marshal.OffsetOf<WlanLayout.AvailableNetwork>(nameof(WlanLayout.AvailableNetwork.dot11DefaultCipherAlgorithm)));
        Assert.Equal(WlanApi.AnFlags, (int)Marshal.OffsetOf<WlanLayout.AvailableNetwork>(nameof(WlanLayout.AvailableNetwork.dwFlags)));
        Assert.Equal(WlanApi.CaProfile, (int)Marshal.OffsetOf<WlanLayout.ConnectionAttributes>(nameof(WlanLayout.ConnectionAttributes.strProfileName)));
        Assert.Equal(WlanApi.CaSsid, (int)Marshal.OffsetOf<WlanLayout.ConnectionAttributes>(nameof(WlanLayout.ConnectionAttributes.dot11Ssid)));
        Assert.Equal(WlanApi.CaSignal, (int)Marshal.OffsetOf<WlanLayout.ConnectionAttributes>(nameof(WlanLayout.ConnectionAttributes.wlanSignalQuality)));
        Assert.Equal(WlanApi.InterfaceInfoSize, Marshal.SizeOf<WlanLayout.InterfaceInfo>());
    }

    internal static Dictionary<string, JsonElement> Row(params (string Key, object Value)[] values) =>
        values.ToDictionary(v => v.Key, v => JsonSerializer.SerializeToElement(v.Value));

    internal sealed class FakeRadio(WifiRadioReading reading) : IWifiRadioSource
    {
        public int Scans { get; private set; }
        public Task<WifiRadioReading> ReadAsync(bool scan, CancellationToken ct) { if (scan) Scans++; return Task.FromResult(reading); }
    }

    private sealed class FakeNetworkSource(IReadOnlyList<WifiDeviceProblem>? problems, IReadOnlyList<NetworkAdapter>? adapters = null) : INetworkSource
    {
        public bool ProblemsAsked { get; private set; }
        public Task<IReadOnlyList<NetworkAdapter>?> ReadAdaptersAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<NetworkAdapter>?>(
            adapters ?? [new NetworkAdapter("Wi-Fi", "Intel(R) Wi-Fi 6E AX211", "Intel", "aa:bb", "7", true, true, null, null, null, null, null, null, null)]);
        public Task<IpConfigSnapshot?> ReadIpConfigAsync(CancellationToken ct) => Task.FromResult<IpConfigSnapshot?>(new([], false, ""));
        public Task<IReadOnlyList<WifiDeviceProblem>?> ReadWifiDeviceProblemsAsync(CancellationToken ct) { ProblemsAsked = true; return Task.FromResult(problems); }
    }

    private sealed class FakeWmi(Dictionary<string, List<Dictionary<string, JsonElement>>> answers) : IWmiSource
    {
        public Task<WmiQueryResult> QueryAsync(string wmiNamespace, string wql, CancellationToken ct = default) =>
            Task.FromResult(answers.TryGetValue(wql, out var rows) ? new WmiQueryResult(wmiNamespace, wql, rows.Select(r => new WmiRow(r)).ToList())
                : WmiQueryResult.Failed(wmiNamespace, wql, "not faked"));
    }

    private sealed class FakeRegistry : IRegistrySource
    {
        public Task<WmiQueryResult> ReadAsync(RegistryRead read, CancellationToken ct = default) => Task.FromResult(WmiQueryResult.Failed(read.Location, "", "not faked"));
    }
}

/// <summary>wlanapi.h structures, field for field (marshalled layout, as MSVC lays them out), to check the offsets the reader uses.</summary>
internal static class WlanLayout
{
    [StructLayout(LayoutKind.Sequential)]
    public struct Dot11Ssid { public uint uSSIDLength; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] public byte[] ucSSID; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct InterfaceInfo { public Guid InterfaceGuid; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string strInterfaceDescription; public int isState; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct AvailableNetwork
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string strProfileName;
        public Dot11Ssid dot11Ssid;
        public int dot11BssType;
        public uint uNumberOfBssids;
        public int bNetworkConnectable;
        public uint wlanNotConnectableReason;
        public uint uNumberOfPhyTypes;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] public int[] dot11PhyTypes;
        public int bMorePhyTypes;
        public uint wlanSignalQuality;
        public int bSecurityEnabled;
        public int dot11DefaultAuthAlgorithm;
        public int dot11DefaultCipherAlgorithm;
        public uint dwFlags;
        public uint dwReserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct BssEntry
    {
        public Dot11Ssid dot11Ssid;
        public uint uPhyId;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)] public byte[] dot11Bssid;
        public int dot11BssType;
        public int dot11BssPhyType;
        public int lRssi;
        public uint uLinkQuality;
        public byte bInRegDomain;
        public ushort usBeaconPeriod;
        public ulong ullTimestamp;
        public ulong ullHostTimestamp;
        public ushort usCapabilityInformation;
        public uint ulChCenterFrequency;
        public uint uRateSetLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 126)] public ushort[] usRateSet;
        public uint ulIeOffset;
        public uint ulIeSize;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct ConnectionAttributes
    {
        public int isState;
        public int wlanConnectionMode;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string strProfileName;
        public Dot11Ssid dot11Ssid;
        public int dot11BssType;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)] public byte[] dot11Bssid;
        public int dot11PhyType;
        public uint uDot11PhyIndex;
        public uint wlanSignalQuality;
        public uint ulRxRate;
        public uint ulTxRate;
        public int bSecurityEnabled;
        public int bOneXEnabled;
        public int dot11AuthAlgorithm;
        public int dot11CipherAlgorithm;
    }
}
