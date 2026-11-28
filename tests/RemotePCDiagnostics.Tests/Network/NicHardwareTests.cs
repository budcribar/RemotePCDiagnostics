using System.Net;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Recording;

namespace RemotePCDiagnostics.Tests.Network;

/// <summary>The Network check's adapter hardware card (#291): burned-in address, Device Manager status and interrupt, speed and duplex, pings.</summary>
public sealed class NicHardwareTests
{
    internal sealed class FakeWmi(Dictionary<string, List<Dictionary<string, object?>>?> answers) : IWmiSource
    {
        public List<string> Asked { get; } = [];
        public Task<WmiQueryResult> QueryAsync(string wmiNamespace, string wql, CancellationToken ct = default)
        {
            Asked.Add(wql);
            return Task.FromResult(answers.TryGetValue(wql, out var rows) && rows is not null
                ? new WmiQueryResult(wmiNamespace, wql, rows.Select(WmiRow.From).ToList())
                : WmiQueryResult.Failed(wmiNamespace, wql, "InvalidClass (0x80041010)"));
        }
    }

    internal static Dictionary<string, object?> Nic(string name = "Ethernet", string desc = "Intel(R) Ethernet Connection (16) I219-LM", long medium = 14,
        string permanent = "A0B1C2D3E4F5", long connect = 1, long duplex = 2, long speed = 1_000_000_000, string pnp = @"PCI\VEN_8086&DEV_1A1E&SUBSYS_8B5D103C\3&11583659&0&FE") => new()
    {
        ["Name"] = name, ["InterfaceDescription"] = desc, ["PnPDeviceID"] = pnp, ["NdisPhysicalMedium"] = medium, ["PermanentAddress"] = permanent,
        ["MacAddress"] = "A0-B1-C2-D3-E4-F5", ["MediaConnectState"] = connect, ["MediaDuplexState"] = duplex, ["ReceiveLinkSpeed"] = speed, ["TransmitLinkSpeed"] = speed,
    };

    internal static Dictionary<string, object?> Speed(string name = "Ethernet", string value = "0", string display = "Auto Negotiation") => new()
    {
        ["Name"] = name, ["RegistryValue"] = new[] { value }, ["DisplayValue"] = display,
        ["ValidRegistryValues"] = new[] { "0", "1", "2", "3", "4", "6" },
        ["ValidDisplayValues"] = new[] { "Auto Negotiation", "10 Mbps Half Duplex", "10 Mbps Full Duplex", "100 Mbps Half Duplex", "100 Mbps Full Duplex", "1.0 Gbps Full Duplex" },
    };

    internal static Dictionary<string, object?> Device(string id = @"PCI\VEN_8086&DEV_1A1E&SUBSYS_8B5D103C\3&11583659&0&FE", string name = "Intel(R) Ethernet Connection (16) I219-LM", long code = 0) =>
        new() { ["DeviceID"] = id, ["Name"] = name, ["ConfigManagerErrorCode"] = code };

    internal static Dictionary<string, object?> Irq(long irq, string id = @"PCI\VEN_8086&DEV_1A1E&SUBSYS_8B5D103C\3&11583659&0&FE") => new()
    {
        ["Antecedent"] = $@"\\BUDSLAPTOP\root\cimv2:Win32_IRQResource.IRQNumber={irq}",
        ["Dependent"] = $@"\\BUDSLAPTOP\root\cimv2:Win32_PnPEntity.DeviceID=""{id.Replace(@"\", @"\\")}""",
    };

    internal static FakeWmi Wmi(List<Dictionary<string, object?>>? adapters = null, List<Dictionary<string, object?>>? speed = null,
        List<Dictionary<string, object?>>? devices = null, List<Dictionary<string, object?>>? resources = null) => new(new()
    {
        [WmiNicHardwareSource.AdaptersSql] = adapters ?? [Nic()],
        [WmiNicHardwareSource.SpeedDuplexSql] = speed ?? [Speed()],
        [WmiNicHardwareSource.DevicesSql] = devices ?? [Device()],
        [WmiNicHardwareSource.ResourcesSql] = resources ?? [Irq(16), Irq(9, @"ACPI\PNP0C0A\1")],
    });

    private static async Task<AreaCard> CardAsync(FakeWmi wmi, Dictionary<string, IReadOnlyList<NicPing>>? pings = null) =>
        NicHardware.Build(await new WmiNicHardwareSource(wmi).ReadAsync(TestContext.Current.CancellationToken), pings)!;

    private static AreaRow RowFor(AreaCard c, string check) => c.Rows.Single(r => r.Values[1] == check);

    [Theory]
    [InlineData("A0-B1-C2-D3-E4-F5", MacProblem.None)]
    [InlineData("a0b1c2d3e4f5", MacProblem.None)]
    [InlineData("02:11:22:AA:BB:CC", MacProblem.None)]   // locally administered (random Wi-Fi addresses): fine
    [InlineData("00-00-00-00-00-00", MacProblem.AllZero)]
    [InlineData("FFFFFFFFFFFF", MacProblem.AllOnes)]
    [InlineData("01:00:5E:00:00:01", MacProblem.Multicast)]
    [InlineData("00:E0:4C:68:00:01", MacProblem.Placeholder)]
    [InlineData("", MacProblem.Missing)]
    [InlineData("12-34", MacProblem.Missing)]
    [InlineData("<serial:a1b2c3>", MacProblem.None)]     // a recording's placeholder was a real address
    public void JudgesTheHardwareAddress(string mac, MacProblem expected) => Assert.Equal(expected, NicAddress.Check(mac));

    [Fact]
    public void ReadsInterruptsFromTheAllocatedResourceReferences()
    {
        var map = WmiNicHardwareSource.Interrupts([WmiRow.From(Irq(16)), WmiRow.From(Irq(4294967286)), WmiRow.From(Irq(16)),
            WmiRow.From(new Dictionary<string, object?> { ["Antecedent"] = @"\\PC\root\cimv2:Win32_DeviceMemoryAddress.StartingAddress=""4026531840""", ["Dependent"] = "x" })]);
        var irqs = Assert.Single(map).Value;
        Assert.Equal([16L, 4294967286L], irqs);
        Assert.Equal(@"PCI\VEN_8086&DEV_1A1E&SUBSYS_8B5D103C\3&11583659&0&FE", map.Keys.Single());
    }

    [Fact]
    public async Task AHealthyGigabitPortPasses()
    {
        var c = await CardAsync(Wmi());
        Assert.Equal(NicHardware.CardId, c.Id);
        Assert.Equal(AreaLevel.Ok, c.Level);
        Assert.Equal("Hardware OK", c.Headline);
        Assert.Equal("A0:B1:C2:D3:E4:F5 · valid", RowFor(c, "Hardware address").Values[2]);
        Assert.Equal("Working · interrupt 16", RowFor(c, "Device status").Values[2]);
        Assert.Equal("1 Gbps", RowFor(c, "Link speed").Values[2]);
        Assert.Equal("Full duplex", RowFor(c, "Duplex").Values[2]);
        Assert.Equal(NicHardware.EthernetTestPage, c.OpenPage?.Path);
    }

    [Theory]
    [InlineData("000000000000", "All zeros")]
    [InlineData("FFFFFFFFFFFF", "All FF (blank memory)")]
    [InlineData("00E04C680001", "A default placeholder, not a real address")]
    public async Task ACorruptBurnedInAddressFails(string mac, string text)
    {
        var c = await CardAsync(Wmi(adapters: [Nic(permanent: mac)]));
        Assert.Equal(AreaLevel.Error, c.Level);
        Assert.EndsWith(text, RowFor(c, "Hardware address").Values[2]);
        Assert.Contains("Ethernet: hardware address", c.Headline);
    }

    [Fact]
    public async Task AResourceConflictFailsAndAnotherProblemCodeWarns()
    {
        var conflict = await CardAsync(Wmi(devices: [Device(code: 12)]));
        Assert.Equal(AreaLevel.Error, RowFor(conflict, "Device status").Level);
        Assert.Contains("resource conflict", RowFor(conflict, "Device status").Values[2]);

        var cantStart = await CardAsync(Wmi(devices: [Device(code: 10)]));
        Assert.Equal(AreaLevel.Warning, RowFor(cantStart, "Device status").Level);
        Assert.Contains("can't start (code 10)", RowFor(cantStart, "Device status").Values[2]);
    }

    [Fact]
    public async Task APciCardWithNoInterruptWarns()
    {
        var c = await CardAsync(Wmi(resources: [Irq(9, @"ACPI\PNP0C0A\1")]));
        Assert.Equal(AreaLevel.Warning, RowFor(c, "Interrupt").Level);
        // Not when the resource table couldn't be read at all.
        var unread = await CardAsync(new FakeWmi(new()
        {
            [WmiNicHardwareSource.AdaptersSql] = [Nic()], [WmiNicHardwareSource.SpeedDuplexSql] = [Speed()], [WmiNicHardwareSource.DevicesSql] = [Device()],
        }));
        Assert.Equal("Working", RowFor(unread, "Device status").Values[2]);
    }

    [Fact]
    public async Task A100MbpsLinkOnAGigabitCardWarns()
    {
        var c = await CardAsync(Wmi(adapters: [Nic(speed: 100_000_000)]));
        var row = RowFor(c, "Link speed");
        Assert.Equal(AreaLevel.Warning, row.Level);
        Assert.Equal("100 Mbps on a gigabit card", row.Values[2]);
        Assert.Contains("cable", row.Detail);

        var forced = RowFor(await CardAsync(Wmi(adapters: [Nic(speed: 100_000_000)], speed: [Speed(value: "4", display: "100 Mbps Full Duplex")])), "Link speed");
        Assert.Equal("100 Mbps · set by hand to 100 Mbps Full Duplex on a gigabit card", forced.Values[2]);
        Assert.Contains("Auto Negotiation", forced.Detail);

        // A Fast Ethernet card at 100 Mbps is as fast as it goes.
        var feSpeed = Speed();
        feSpeed["ValidRegistryValues"] = new[] { "0", "1", "2", "3", "4" };
        feSpeed["ValidDisplayValues"] = new[] { "Auto Negotiation", "100 Mbps Full Duplex" };
        var fast = await CardAsync(Wmi(adapters: [Nic(desc: "Realtek PCIe FE Family Controller", speed: 100_000_000)], speed: [feSpeed]));
        Assert.Equal(AreaLevel.Ok, RowFor(fast, "Link speed").Level);
    }

    [Fact]
    public async Task HalfDuplexWarns()
    {
        var row = RowFor(await CardAsync(Wmi(adapters: [Nic(duplex: 1)])), "Duplex");
        Assert.Equal(AreaLevel.Warning, row.Level);
        Assert.Equal("Half duplex", row.Values[2]);
    }

    [Fact]
    public async Task AnUnpluggedPortAsksForACable()
    {
        var c = await CardAsync(Wmi(adapters: [Nic(connect: 2)]));
        Assert.Equal("No cable plugged in", RowFor(c, "Cable").Values[2]);
        Assert.DoesNotContain(c.Rows, r => r.Values[1] == "Link speed");
        Assert.Equal("Hardware OK · plug a cable into Ethernet to test the wired link", c.Headline);
    }

    [Fact]
    public async Task WiFiGetsTheAddressAndDeviceChecksButNoSpeedRow()
    {
        var c = await CardAsync(Wmi(adapters: [Nic(name: "Wi-Fi", desc: "Intel(R) Wi-Fi 6E AX211 160MHz", medium: 9, speed: 54_000_000, pnp: @"PCI\VEN_8086&DEV_51F0")],
            devices: [Device(id: @"PCI\VEN_8086&DEV_51F0", name: "Intel(R) Wi-Fi 6E AX211 160MHz")], resources: [Irq(4294967280, @"PCI\VEN_8086&DEV_51F0")]));
        Assert.Equal(["Hardware address", "Device status"], c.Rows.Select(r => r.Values[1]));
        Assert.Equal("Working · interrupt MSI", RowFor(c, "Device status").Values[2]);
        Assert.Null(c.OpenPage);
    }

    [Fact]
    public async Task NoReplyFromItsOwnAddressFails()
    {
        var c = await CardAsync(Wmi(), new() { ["Ethernet"] = [new("Own address", "192.168.1.20", 4, 0), new("DHCP server", "192.168.1.1", 4, 4)] });
        Assert.Equal(AreaLevel.Error, RowFor(c, "Ping own address").Level);
        Assert.Equal(AreaLevel.Ok, RowFor(c, "Ping dhcp server").Level);
        var quiet = await CardAsync(Wmi(), new() { ["Ethernet"] = [new("Own address", "192.168.1.20", 4, 4), new("DHCP server", "192.168.1.1", 4, 0)] });
        Assert.Equal(AreaLevel.Neutral, RowFor(quiet, "Ping dhcp server").Level);
    }

    [Fact]
    public async Task TheNetworkCheckAddsTheCardAfterTheAdaptersAndLeadsWithAProblem()
    {
        var adapters = new List<NetworkAdapter> { new("Ethernet", "Intel(R) Ethernet Connection (16) I219-LM", "Intel", "A0:B1:C2:D3:E4:F5", "2", true, true, 1_000_000_000, 10, 10, 0, 0, 0, 0) };
        var module = new NetworkModule(new StubNetwork(adapters), hardware: new WmiNicHardwareSource(Wmi(adapters: [Nic(permanent: "000000000000")])),
            linkProbe: new StubProbe());
        var r = await module.RefreshAsync(null, TestContext.Current.CancellationToken);
        var report = Assert.IsType<AreaReport>(r.Payload);
        Assert.Equal(["nic0", NicHardware.CardId], report.Cards.Select(c => c.Id));
        Assert.Equal(DiagnosticStatus.Error, report.Status);
        Assert.StartsWith("Ethernet: hardware address · ", report.Summary);
        Assert.Contains(report.Cards[1].Rows, x => x.Values[1] == "Ping own address");
    }

    [Fact]
    public async Task OfflineTheCheckDoesntPing()
    {
        var adapters = new List<NetworkAdapter> { new("Ethernet", "I219", "Intel", "A0:B1:C2:D3:E4:F5", "2", true, true, 1_000_000_000, 10, 10, 0, 0, 0, 0) };
        var probe = new StubProbe();
        var module = new NetworkModule(new StubNetwork(adapters), hardware: new WmiNicHardwareSource(Wmi()), linkProbe: probe, offline: true);
        var report = (AreaReport)(await module.RefreshAsync(null, TestContext.Current.CancellationToken)).Payload!;
        Assert.Equal(0, probe.Calls);
        Assert.Equal(DiagnosticStatus.Ok, report.Status);
    }

    [Fact]
    public async Task ABlankAddressSurvivesRecordingAndReplaysToTheSameVerdict()
    {
        var wmi = Wmi(adapters: [Nic(permanent: "000000000000"), Nic(name: "Ethernet 2", permanent: "A0B1C2D3E4F6", pnp: @"USB\VID_0BDA&PID_8153\000001")]);
        var source = new WmiNicHardwareSource(wmi);
        var ct = TestContext.Current.CancellationToken;
        await source.ReadAsync(ct);
        var scrubber = new RecordingScrubber("BUDSLAPTOP", ["bud"]);
        var calls = new List<RecordedCall>();
        foreach (var q in wmi.Asked.ToList())
            calls.Add(scrubber.Scrub(RecordedCall.FromWmi(await wmi.QueryAsync(q.Contains("Win32_", StringComparison.Ordinal) ? WmiHardwareInventorySource.Cimv2 : WmiNetworkSource.StandardCimv2, q, ct))));
        var adapterRows = calls.Single(c => c.Query == WmiNicHardwareSource.AdaptersSql).Rows!;
        Assert.Equal("000000000000", adapterRows[0]["PermanentAddress"].GetString());
        Assert.StartsWith("<serial:", adapterRows[1]["PermanentAddress"].GetString());

        var replay = new RecordingReplay(calls);
        var card = NicHardware.Build(await new WmiNicHardwareSource(replay.Wmi).ReadAsync(ct))!;
        Assert.Empty(replay.Misses);
        Assert.Equal(AreaLevel.Error, card.Rows.First(r => r.Values[0] == "Ethernet" && r.Values[1] == "Hardware address").Level);
        Assert.Equal(AreaLevel.Ok, card.Rows.First(r => r.Values[0] == "Ethernet 2" && r.Values[1] == "Hardware address").Level);
    }

    internal sealed class StubNetwork(IReadOnlyList<NetworkAdapter> adapters) : INetworkSource
    {
        public Task<IReadOnlyList<NetworkAdapter>?> ReadAdaptersAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<NetworkAdapter>?>(adapters);
        public Task<IpConfigSnapshot?> ReadIpConfigAsync(CancellationToken ct) => Task.FromResult<IpConfigSnapshot?>(null);
    }

    internal sealed class StubProbe(params NicPing[] pings) : INicLinkProbe
    {
        public int Calls { get; private set; }
        public Task<IReadOnlyList<NicPing>> ProbeAsync(string adapterName, CancellationToken ct)
        {
            Calls++;
            return Task.FromResult<IReadOnlyList<NicPing>>(pings.Length > 0 ? pings : [new("Own address", "192.168.1.20", 4, 4), new("DHCP server", "192.168.1.1", 4, 4)]);
        }
    }
}
