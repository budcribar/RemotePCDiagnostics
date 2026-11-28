using System.Text.Json;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Recording;
using RemotePCDiagnostics.Core.Usb;
using RemotePCDiagnostics.Modules.UsbPortCheck;
using RemotePCDiagnostics.Modules.UsbPorts;

namespace RemotePCDiagnostics.Tests;

public class UsbPortsTests
{
    private const string Xhci = @"PCI\VEN_8086&DEV_A0ED&SUBSYS_00000000&REV_20\3&11583659&0&A0";
    private const string Root = @"USB\ROOT_HUB30\4&1A2B3C4D&0&0";
    private const string Dock = @"USB\VID_17EF&PID_A391\5&2B3C4D5E&0&3";
    private const string Mouse = @"USB\VID_046D&PID_C52B\6&3C4D5E6F&0&2";
    private const string Stick = @"USB\VID_0781&PID_5583\4C530001230815115453";
    private const string Nic = @"USB\VID_0BDA&PID_8153\000001000000";
    private const string DockAudio = @"USB\VID_17EF&PID_A396\7&4D5E6F70&0&4";

    private static UsbPortInfo Port(int n, string status = UsbPortStatus.Connected, UsbSpeed speed = UsbSpeed.High, bool? ssCap = false, bool? atSs = false,
        bool hub = false, bool typeC = false) =>
        new(n, status, speed, hub, ssCap, atSs, false, false, true, typeC);

    private static UsbNode Controller(string name = "Intel(R) USB 3.20 eXtensible Host Controller - 1.20 (Microsoft)", int problem = 0) =>
        new(Xhci, null, UsbNodeKind.Controller, name, "USB", ProblemCode: problem);

    /// <summary>A laptop: root hub with a mouse on port 2, a USB stick on port 5 and a dock on port 3 (network adapter and audio behind it).</summary>
    private static UsbSnapshot Laptop(UsbPortInfo? stickPort = null, int stickProblem = 0, bool withDockDevices = true, IEnumerable<UsbPortInfo>? extraRootPorts = null)
    {
        UsbPortInfo[] rootPorts =
        [
            Port(2, speed: UsbSpeed.Full),
            Port(3, speed: UsbSpeed.Super, ssCap: true, atSs: true, hub: true, typeC: true),
            stickPort ?? Port(5, speed: UsbSpeed.Super, ssCap: true, atSs: true),
            .. extraRootPorts ?? [],
        ];
        var nodes = new List<UsbNode>
        {
            Controller(),
            new(Root, Xhci, UsbNodeKind.RootHub, "USB Root Hub (USB 3.0)", "USB", Ports: rootPorts, HubType: 1),
            new(Mouse, Root, UsbNodeKind.Device, "USB Receiver", "USB", "046D", "C52B", Port: 2),
            new(Mouse + @"\HID", Mouse, UsbNodeKind.Function, "HID-compliant mouse", "Mouse"),
            new(Stick, Root, UsbNodeKind.Device, "SanDisk Ultra USB 3.0", "USB", "0781", "5583", stickProblem, Port: 5),
            new(Dock, Root, UsbNodeKind.Hub, "Generic SuperSpeed USB Hub", "USB", "17EF", "A391", Port: 3, ContainerId: "{dock}",
                Ports: [Port(1, speed: UsbSpeed.Super, ssCap: true, atSs: true), Port(4)], HubType: 3),
        };
        if (withDockDevices)
        {
            nodes.Add(new(Nic, Dock, UsbNodeKind.Device, "Realtek USB GbE Family Controller", "Net", "0BDA", "8153", Port: 1, ContainerId: "{dock}"));
            nodes.Add(new(DockAudio, Dock, UsbNodeKind.Device, "ThinkPad Dock USB Audio", "MEDIA", "17EF", "A396", Port: 4, ContainerId: "{dock}"));
        }
        return new UsbSnapshot(nodes);
    }

    private static AreaCard Card(AreaReport r, string id) => r.Cards.Single(c => c.Id == id);

    private static AreaReport Build(UsbSnapshot tree, IReadOnlyList<WinEvent>? events = null, UsbFirmwareReading? firmware = null, IReadOnlyList<UsbDrop>? drops = null) =>
        UsbAnalysis.Build(tree, events ?? [], firmware ?? new UsbFirmwareReading("HP", []), drops);

    [Fact]
    public void Healthy_tree_passes_with_every_device_its_port_and_speed()
    {
        var r = Build(Laptop());
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        var devices = Card(r, "devices");
        Assert.Equal("4 USB devices, all working", devices.Headline);
        var stick = devices.Rows.Single(x => x.Key == Stick);
        Assert.Equal(["SanDisk Ultra USB 3.0", "PC · port 5", "SuperSpeed, USB 3 (5 Gbps)", "0781:5583", "Working"], stick.Values);
        Assert.Equal("Generic SuperSpeed USB Hub · port 1", devices.Rows.Single(x => x.Key == Nic).Values[1]);
        Assert.Equal("PC · port 3 · USB-C", devices.Rows.Single(x => x.Key == Dock).Values[1]);
        Assert.Equal(AreaLevel.Ok, Card(r, "speed").Level);
        Assert.DoesNotContain(r.Cards, c => c.Id == "drops");
    }

    [Fact]
    public void Device_with_a_problem_code_fails_with_Device_Managers_restart()
    {
        var r = Build(Laptop(stickProblem: 43));
        Assert.Equal(DiagnosticStatus.Error, r.Status);
        var row = Card(r, "devices").Rows.Single(x => x.Key == Stick);
        Assert.Equal(AreaLevel.Error, row.Level);
        var fix = Assert.Single(row.Actions!);
        Assert.Equal((RemediationKind.RestartDevice, Stick), (fix.Kind, fix.Target));
        Assert.StartsWith("1 USB device with a problem", Card(r, "devices").Headline);

        var disabled = Build(Laptop(stickProblem: 22));
        Assert.Equal(DiagnosticStatus.Ok, disabled.Status); // turned off on purpose: shown, with Enable
        Assert.Equal(RemediationKind.EnableDevice, Card(disabled, "devices").Rows.Single(x => x.Key == Stick).Actions![0].Kind);
    }

    [Fact]
    public void Usb3_device_on_a_usb2_link_is_a_speed_warning()
    {
        var r = Build(Laptop(stickPort: Port(5, speed: UsbSpeed.High, ssCap: true, atSs: false)));
        Assert.Equal(DiagnosticStatus.Warning, r.Status);
        var speed = Card(r, "speed");
        Assert.Equal(AreaLevel.Warning, speed.Level);
        var row = Assert.Single(speed.Rows);
        Assert.Equal(["SanDisk Ultra USB 3.0", "PC · port 5", "High speed, USB 2 (480 Mbps)", "SuperSpeed (5 Gbps)"], row.Values);
        Assert.Equal("Running below its speed", Card(r, "devices").Rows.Single(x => x.Key == Stick).Values[4]);
    }

    private const string Dock2 = @"USB\VID_17EF&PID_A392\5&2B3C4D5E&0&13";

    /// <summary>The dock's USB 2 half: a USB 2 hub on root port 13 (the companion of port 3), reporting the dock as SuperSpeed capable.</summary>
    private static UsbSnapshot WithDockUsb2Half(bool usb3HalfPresent, string? containerId = "{dock}")
    {
        var tree = Laptop();
        var nodes = tree.Nodes.ToList();
        var root = nodes.Single(n => n.Id == Root);
        var ports = root.Ports!.Select(p => p.Number == 3 ? p with { CompanionPort = 13 } : p).ToList();
        ports.Add(Port(13, speed: UsbSpeed.High, ssCap: true, atSs: false, hub: true) with { CompanionPort = 3 });
        nodes[nodes.IndexOf(root)] = root with { Ports = ports };
        if (!usb3HalfPresent) nodes.RemoveAll(n => n.Id is Dock or Nic or DockAudio);
        nodes.Add(new(Dock2, Root, UsbNodeKind.Hub, "Generic USB Hub", "USB", "17EF", "A392", Port: 13, ContainerId: containerId, Ports: [Port(1, UsbPortStatus.NoDevice, UsbSpeed.Unknown)], HubType: 2));
        return new UsbSnapshot(nodes);
    }

    [Theory]
    [InlineData("{dock}")]
    [InlineData(null)] // no container ID: the companion port still pairs the two halves
    public void The_usb2_half_of_a_usb3_hub_is_not_a_slow_link(string? containerId)
    {
        var r = Build(WithDockUsb2Half(usb3HalfPresent: true, containerId));
        Assert.Equal(AreaLevel.Ok, Card(r, "speed").Level);
        Assert.Empty(Card(r, "speed").Rows);
        Assert.Equal("Working", Card(r, "devices").Rows.Single(x => x.Key == Dock2).Values[4]);
        Assert.Equal(DiagnosticStatus.Ok, r.Status);
    }

    [Fact]
    public void A_usb3_hub_whose_usb3_half_is_missing_is_still_a_slow_link()
    {
        var r = Build(WithDockUsb2Half(usb3HalfPresent: false));
        Assert.Equal(AreaLevel.Warning, Card(r, "speed").Level);
        Assert.Equal("Generic USB Hub", Assert.Single(Card(r, "speed").Rows).Values[0]);
    }

    [Fact]
    public void Failed_port_without_a_device_shows_as_its_own_row()
    {
        var r = Build(Laptop(extraRootPorts: [Port(7, UsbPortStatus.Overcurrent, UsbSpeed.Unknown), Port(8, UsbPortStatus.FailedEnumeration, UsbSpeed.Unknown)]));
        var rows = Card(r, "devices").Rows.Where(x => x.Values[0] == "Device that didn't start").ToList();
        Assert.Equal(2, rows.Count);
        Assert.Contains(rows, x => x.Level == AreaLevel.Warning && x.Values[4].Contains("over-current"));
        Assert.Contains(rows, x => x.Level == AreaLevel.Error && x.Values[4].Contains("failed enumeration"));
        Assert.Equal(DiagnosticStatus.Error, r.Status);
    }

    [Fact]
    public void Docks_group_the_devices_behind_them()
    {
        var docks = Card(Build(Laptop()), "docks");
        var row = Assert.Single(docks.Rows);
        Assert.Equal(["Generic SuperSpeed USB Hub", "PC · port 3 · USB-C", "2 devices", "network, audio", "Working"], row.Values);
        Assert.DoesNotContain(Build(Laptop() with { Nodes = [.. Laptop().Nodes.Where(n => n.Kind != UsbNodeKind.Hub && n.ParentId != Dock)] }).Cards, c => c.Id == "docks");
    }

    [Fact]
    public void Several_devices_dropping_behind_a_dock_at_once_is_a_dock_warning()
    {
        var before = Laptop();
        var after = Laptop(withDockDevices: false);
        var drop = Assert.Single(UsbAnalysis.Drops(before, after, DateTimeOffset.UnixEpoch));
        Assert.Equal("Generic SuperSpeed USB Hub", drop.HubName);
        Assert.Equal(["Realtek USB GbE Family Controller", "ThinkPad Dock USB Audio"], drop.Devices);

        var r = Build(after, drops: [drop]);
        Assert.Equal(AreaLevel.Warning, Card(r, "drops").Level);
        Assert.Equal(DiagnosticStatus.Warning, r.Status);

        // Unplugging the dock itself takes everything with it: the person did that, not a drop.
        var unplugged = after with { Nodes = [.. after.Nodes.Where(n => n.Id != Dock)] };
        Assert.Empty(UsbAnalysis.Drops(before, unplugged, DateTimeOffset.UnixEpoch));
        // One device going away is just one device unplugged.
        var one = before with { Nodes = [.. before.Nodes.Where(n => n.Id != Nic)] };
        Assert.Empty(UsbAnalysis.Drops(before, one, DateTimeOffset.UnixEpoch));
    }

    private static WinEvent Event(string provider, string message, int id = 1, string[]? data = null) =>
        new(DateTimeOffset.UnixEpoch, "System", provider, id, 2, message, data ?? [], new Dictionary<string, string>());

    [Fact]
    public void Hub_and_controller_errors_in_the_system_log_are_a_warning()
    {
        var r = Build(Laptop(), events:
        [
            Event("Microsoft-Windows-USB-USBHUB3", "A USB device on port 3 drew too much current and the port was turned off (over-current)."),
            Event("Microsoft-Windows-USB-USBXHCI", "The port was reset."),
            Event("Microsoft-Windows-Kernel-PnP", @"The driver \Driver\WudfRd failed to load for the device SWD\WPDBUSENUM\{abc}.", 219),
            Event("Microsoft-Windows-Kernel-PnP", "The driver failed to load.", 219, [@"USB\VID_1234&PID_5678\1"]),
        ]);
        var events = Card(r, "events");
        Assert.Equal(AreaLevel.Warning, events.Level);
        Assert.Equal(3, events.EventCount);
        Assert.Contains("over-current", events.Meta);
        Assert.Contains("port reset", events.Meta);
        Assert.Contains("Provider[@Name='Microsoft-Windows-USB-USBHUB3']", UsbAnalysis.EventQuery());
        Assert.Contains("timediff(@SystemTime) <= 604800000", UsbAnalysis.EventQuery());
    }

    [Fact]
    public void Unreadable_tree_still_reports_the_rest_and_is_not_a_pass()
    {
        var r = Build(UsbSnapshot.Unavailable("no cfgmgr32"));
        Assert.NotNull(Card(r, "devices").ErrorText);
        Assert.Equal(DiagnosticStatus.Warning, r.Status);
        Assert.Equal(DiagnosticStatus.Error, UsbAnalysis.Build(UsbSnapshot.Unavailable("x"), null, new(null, [], "other maker")).Status);
    }

    // ---------------------------------------------------------------- BIOS

    [Theory]
    [InlineData("USB Port", true)]
    [InlineData("Rear USB Ports", true)]
    [InlineData("USBPortAccess", true)]
    [InlineData("UsbPortsFront", true)]
    [InlineData("Thunderbolt Type-C Ports", true)]
    [InlineData("ThunderboltAccess", true)]
    [InlineData("USB Wake Support", false)]
    [InlineData("USB Legacy Port Charging", false)]
    [InlineData("USB Storage Boot", false)]
    [InlineData("UsbPowerShare", false)]
    [InlineData("Network Boot", false)]
    public void Only_settings_that_turn_ports_off_count(string name, bool expected) => Assert.Equal(expected, UsbFirmwarePorts.IsPortSetting(name));

    private static WmiRow Row(params (string Key, object Value)[] values) =>
        new(values.ToDictionary(v => v.Key, v => JsonSerializer.SerializeToElement(v.Value)));

    private static FakeRegistry Maker(string m) => new(m);

    [Fact]
    public async Task Hp_ports_turned_off_in_the_bios_are_named()
    {
        var wmi = new FakeWmi((ns, q) =>
        {
            Assert.Equal(UsbFirmwarePorts.HpNamespace, ns);
            Assert.Null(WmiQueryPolicy.Problem(ns, q)); // the Agent will run it
            return new(ns, q, [Row(("Name", "Rear USB Ports"), ("CurrentValue", "Disable")), Row(("Name", "USB Port"), ("CurrentValue", "Enable")),
                Row(("Name", "USB Wake Support"), ("CurrentValue", "Disable")), Row(("Name", "USB Type-C Connector"), ("CurrentValue", "Disabled"))]);
        });
        var f = await UsbFirmwarePorts.ReadAsync(wmi, Maker("HP"), default);
        Assert.Equal(["Rear USB Ports", "USB Type-C Connector"], f.Disabled.Select(s => s.Name));
        var card = Card(Build(Laptop(), firmware: f), "firmware");
        Assert.Equal(AreaLevel.Warning, card.Level);
        Assert.Equal("USB ports disabled in BIOS: Rear USB Ports, USB Type-C Connector", card.Headline);
    }

    [Fact]
    public async Task Lenovo_and_dell_settings_are_parsed()
    {
        var lenovo = await UsbFirmwarePorts.ReadAsync(new FakeWmi((ns, q) => new(ns, q,
            [Row(("CurrentSetting", "USBPortAccess,Disable;[Optional:Enable,Disable]")), Row(("CurrentSetting", "AlwaysOnUSB,Enable")), Row(("CurrentSetting", "junk"))])),
            Maker("LENOVO"), default);
        Assert.Equal("Lenovo", lenovo.Maker);
        var s = Assert.Single(lenovo.Settings);
        Assert.Equal(("USBPortAccess", "Disable", true), (s.Name, s.Value, s.Disabled));

        var dell = await UsbFirmwarePorts.ReadAsync(new FakeWmi((ns, q) =>
        {
            Assert.Equal(UsbFirmwarePorts.DellNamespace, ns);
            Assert.Null(WmiQueryPolicy.Problem(ns, q));
            return new(ns, q, [Row(("AttributeName", "UsbPortsRear"), ("DisplayName", "Enable Rear USB Ports"), ("CurrentValue", new[] { "Disabled" }))]);
        }), Maker("Dell Inc."), default);
        Assert.Equal(["Enable Rear USB Ports"], dell.Disabled.Select(x => x.Name));
    }

    [Fact]
    public async Task Other_makers_and_no_agent_are_not_failures()
    {
        var other = await UsbFirmwarePorts.ReadAsync(new FakeWmi((_, _) => throw new InvalidOperationException("not asked")), Maker("ASUSTeK COMPUTER INC."), default);
        Assert.False(other.Read);
        Assert.Contains("only HP, Lenovo and Dell", other.Reason);
        Assert.Equal(AreaLevel.Neutral, Card(Build(Laptop(), firmware: other), "firmware").Level);

        var noAgent = await UsbFirmwarePorts.ReadAsync(new FakeWmi((ns, q) => WmiQueryResult.Failed(ns, q, AgentWmiSource.NotConnected)), Maker("HP"), default);
        Assert.True(noAgent.NeedsAgent);
        var card = Card(Build(Laptop(), firmware: noAgent), "firmware");
        Assert.Equal(("Needs the Agent", AreaLevel.Neutral), (card.Headline, card.Level));
        Assert.Equal(DiagnosticStatus.Ok, Build(Laptop(), firmware: noAgent).Status);
    }

    // ---------------------------------------------------------------- the module, host query, recording

    [Fact]
    public async Task Module_reads_the_tree_the_log_and_the_bios()
    {
        var host = new FakeHost([Event("Microsoft-Windows-USB-USBHUB3", "Port reset failed.")]);
        var module = new UsbPortsModule(new FakeUsb(Laptop()), new SystemCommandRunner(new NoProcesses()), new FakeWmi((ns, q) => new(ns, q, [])),
            Maker("HP"), host, dropWatch: TimeSpan.Zero);
        var result = await module.RefreshAsync(null);
        var report = Assert.IsType<AreaReport>(result.Payload);
        Assert.Equal(DiagnosticStatus.Warning, result.Status);
        Assert.Equal(1, Card(report, "events").EventCount);
        Assert.Equal("System", host.Log);
        Assert.Equal(ModuleSlugs.UsbPorts, module.Name);
        var d = BuiltInModules.Descriptors.Single(x => x.Id == ModuleIds.UsbPorts);
        Assert.Equal((ModuleKind.Check, ModuleGroups.Hardware), (d.Kind, d.Group));
    }

    [Fact]
    public async Task Tree_crosses_the_host_query_and_a_recording_unchanged()
    {
        var tree = Laptop();
        var json = JsonSerializer.SerializeToElement(tree, Core.Plugins.HostCapabilities.Json);
        var back = json.Deserialize<UsbSnapshot>(Core.Plugins.HostCapabilities.Json)!;
        Assert.Equal(tree.Nodes.Count, back.Nodes.Count);
        Assert.Equal(UsbSpeed.Super, back.Nodes.Single(n => n.Id == Root).Ports![1].Speed);
        Assert.Contains(Core.Plugins.HostCapabilities.UsbTree, Core.Plugins.HostCapabilities.All);
        Assert.False((await new HostUsbTreeSource(new FakeHost([])).ReadAsync()).Nodes.Any()); // a host without it says so

        var call = RecordedCall.FromUsb(tree);
        Assert.Equal(RecordedCall.UsbKind, call.Kind);
        var replay = new RecordingReplay(new MachineRecording { Calls = [call] });
        var replayed = await replay.Usb.ReadAsync();
        Assert.Equal(UsbAnalysis.Build(tree, [], null).Summary, UsbAnalysis.Build(replayed, [], null).Summary);
        Assert.Equal("Not in the recording.", (await new RecordingReplay(new MachineRecording { Calls = [] }).Usb.ReadAsync()).Error);
        Assert.NotNull(UsbSnapshot.FromJson("{garbage").Error);
    }

    [Fact]
    public void Scrubber_replaces_usb_serials_in_the_tree_and_keeps_the_links()
    {
        var usbStor = @"USBSTOR\DISK&VEN_SANDISK&PROD_ULTRA&REV_1.00\4C530001230815115453&0";
        var withStor = Laptop() with
        {
            Nodes = [.. Laptop().Nodes, new(usbStor, Stick, UsbNodeKind.Function, "SanDisk Ultra USB Device", "DiskDrive")],
        };
        var scrubbed = new RecordingScrubber("PC1", ["bud"]).Scrub(RecordedCall.FromUsb(withStor));
        Assert.DoesNotContain("4C530001230815115453", scrubbed.StdOut);
        var tree = UsbSnapshot.FromJson(scrubbed.StdOut);
        var stick = tree.Nodes.Single(n => n.Name == "SanDisk Ultra USB 3.0");
        var disk = tree.Nodes.Single(n => n.Name == "SanDisk Ultra USB Device");
        var root = tree.Nodes.Single(n => n.Kind == UsbNodeKind.RootHub);
        Assert.Equal(root.Id, stick.ParentId);
        Assert.Equal(stick.Id, disk.ParentId);
        Assert.StartsWith("<device:", disk.Id);
        Assert.Equal(Xhci, root.ParentId); // a PCI path holds no serial
        Assert.Equal(DiagnosticStatus.Ok, UsbAnalysis.Build(tree, [], null).Status);
    }

    [Fact]
    public void SuperSpeedPlus_device_on_5Gbps_port_is_not_flagged_as_downgraded()
    {
        var port5Gbps = new UsbPortInfo(5, UsbPortStatus.Connected, UsbSpeed.Super, false,
            SuperSpeedCapable: true, AtSuperSpeed: true, SuperSpeedPlusCapable: true, AtSuperSpeedPlus: false);
        Assert.False(port5Gbps.SpeedDowngraded);
        var ok = Build(Laptop(stickPort: port5Gbps));
        Assert.Equal(DiagnosticStatus.Ok, ok.Status);
        Assert.Empty(Card(ok, "speed").Rows);

        var portUsb2 = new UsbPortInfo(5, UsbPortStatus.Connected, UsbSpeed.High, false,
            SuperSpeedCapable: false, AtSuperSpeed: false, SuperSpeedPlusCapable: true, AtSuperSpeedPlus: false);
        Assert.True(portUsb2.SpeedDowngraded);
        var slow = Build(Laptop(stickPort: portUsb2));
        Assert.Equal(DiagnosticStatus.Warning, slow.Status);
        Assert.Single(Card(slow, "speed").Rows);
    }

    [Fact]
    public void Cyclic_hubs_and_duplicate_node_ids_do_not_throw_or_hang()
    {
        var hubA = @"USB\VID_1111&PID_0001\HUBA";
        var hubB = @"USB\VID_1111&PID_0002\HUBB";
        var dev = @"USB\VID_1111&PID_0003\DEV1";
        var cyclic = new UsbSnapshot([
            Controller(),
            new(hubA, hubB, UsbNodeKind.Hub, "Hub A", "USB"),
            new(hubB, hubA, UsbNodeKind.Hub, "Hub B", "USB"),
            new(hubA, hubB, UsbNodeKind.Hub, "Hub A duplicate", "USB"),
            new(dev, hubA, UsbNodeKind.Device, "Device behind cycle", "USB"),
        ]);

        var report = Build(cyclic);
        Assert.Equal(DiagnosticStatus.Ok, report.Status);
        Assert.Single(Card(report, "docks").Rows);
        Assert.Empty(UsbAnalysis.Drops(cyclic, cyclic, DateTimeOffset.UnixEpoch));

        var failedController = Build(new UsbSnapshot([Controller(problem: 43)]));
        Assert.Equal(DiagnosticStatus.Error, failedController.Status);
        Assert.Contains("1 controller or hub with a problem", failedController.Summary);
    }

    // ---------------------------------------------------------------- the interactive port check

    [Fact]
    public void Arrivals_name_the_port_and_speed()
    {
        var before = Laptop() with { Nodes = [.. Laptop().Nodes.Where(n => n.Id != Stick)] };
        var a = Assert.Single(UsbPortCheck.Arrivals(before, Laptop(stickPort: Port(5, speed: UsbSpeed.High, ssCap: true, atSs: false)), DateTimeOffset.UnixEpoch));
        Assert.Equal(("SanDisk Ultra USB 3.0", "PC · port 5", UsbSpeed.High, true, true), (a.Name, a.Where, a.Speed, a.Downgraded, a.Works));
        Assert.Empty(UsbPortCheck.Arrivals(Laptop(), Laptop(), DateTimeOffset.UnixEpoch));
    }

    private static UsbArrival Arrived(string port, bool slow = false, int problem = 0) =>
        new(DateTimeOffset.UnixEpoch, "id" + port, "Stick", port, port, UsbSpeed.Super, false, slow, problem, null);

    [Fact]
    public void Port_check_verdicts()
    {
        UsbPortCheckReport R(bool? answer, params UsbArrival[] a) => new(a, [], answer, false);
        Assert.Equal(DiagnosticStatus.Warning, UsbPortCheck.Outcome(R(null, Arrived("p1"))).Status); // waiting for the answer
        Assert.Contains("Did every device work?", UsbPortCheck.Outcome(R(null, Arrived("p1"))).Message);
        Assert.Equal(DiagnosticStatus.Ok, UsbPortCheck.Outcome(R(true, Arrived("p1"), Arrived("p2"), Arrived("p1"))).Status);
        Assert.Contains("2 ports tested", UsbPortCheck.Outcome(R(true, Arrived("p1"), Arrived("p2"), Arrived("p1"))).Message);
        Assert.Equal(DiagnosticStatus.Error, UsbPortCheck.Outcome(R(false, Arrived("p1"))).Status); // the person says a port is broken
        Assert.Equal(DiagnosticStatus.Error, UsbPortCheck.Outcome(R(true, Arrived("p1", problem: 43))).Status);
        Assert.Equal(DiagnosticStatus.Warning, UsbPortCheck.Outcome(R(true, Arrived("p1", slow: true))).Status);
        Assert.Equal(DiagnosticStatus.Warning, UsbPortCheck.Outcome(R(true)).Status); // nothing tested isn't a pass

        var answered = UsbPortCheck.Answer(UsbPortCheck.ToResult(R(null, Arrived("p1"))), true)!;
        Assert.Equal(DiagnosticStatus.Ok, answered.Status);
        Assert.Null(UsbPortCheck.Answer(DiagnosticResult.NotRun(ModuleSlugs.UsbPortCheck), true));
    }

    [Fact]
    public async Task Port_check_follows_arrivals_live_until_finish()
    {
        var without = Laptop() with { Nodes = [.. Laptop().Nodes.Where(n => n.Id != Stick)] };
        var source = new SequenceUsb(without, without, Laptop());
        var module = new UsbPortCheckModule(source, poll: TimeSpan.FromMilliseconds(5));
        var changed = new TaskCompletionSource();
        module.Changed += (_, _) => changed.TrySetResult();
        var run = module.RefreshAsync(null);
        await changed.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.True(module.Live.Watching);
        Assert.Equal("SanDisk Ultra USB 3.0", Assert.Single(module.Live.PortsTested).Name);
        module.Finish();
        var result = await run.WaitAsync(TimeSpan.FromSeconds(10));
        var rep = Assert.IsType<UsbPortCheckReport>(result.Payload);
        Assert.False(rep.Watching);
        Assert.Equal(DiagnosticStatus.Warning, result.Status);
        Assert.Equal(DiagnosticStatus.Ok, UsbPortCheck.Answer(result, true)!.Status);

        var cancelled = new UsbPortCheckModule(new SequenceUsb(without), poll: TimeSpan.FromMilliseconds(5));
        var running = cancelled.RefreshAsync(null);
        await Task.Delay(30);
        cancelled.Cancel();
        Assert.True((await running.WaitAsync(TimeSpan.FromSeconds(10))).Cancelled);
    }

    [Fact]
    public void Interactive_export_lists_the_usb_port_check()
    {
        var page = new InteractiveExport.PageState("usbports", ["usbports"], false, false, false, false);
        var live = new UsbPortCheckReport([Arrived("PC · port 1", slow: true)], [], null, true);
        var json = InteractiveExport.ToJson(page, new Core.Workflow.PhysicalBenchQaSnapshot(),
            new(DiagnosticResult.NotRun(ModuleSlugs.Webcam), false), new(DiagnosticResult.NotRun(ModuleSlugs.SpeakerToMic), false),
            new(DiagnosticResult.NotRun(ModuleSlugs.MicToSpeaker), false),
            usbPortCheck: new(new(new DiagnosticResult(ModuleSlugs.UsbPortCheck, DiagnosticStatus.Running, "", DateTimeOffset.UnixEpoch), false), live));
        using var doc = JsonDocument.Parse(json);
        var usb = doc.RootElement.GetProperty("tests").EnumerateArray().Single(t => t.GetProperty("id").GetString() == "usbports");
        Assert.Equal("in-progress", usb.GetProperty("state").GetString());
        Assert.True(usb.GetProperty("open").GetBoolean());
        var port = usb.GetProperty("measured").GetProperty("ports")[0];
        Assert.True(port.GetProperty("belowItsSpeed").GetBoolean());
        Assert.Equal("PC · port 1", port.GetProperty("port").GetString());
    }

    // ---------------------------------------------------------------- fakes

    private sealed class FakeUsb(UsbSnapshot tree) : IUsbTreeSource
    {
        public Task<UsbSnapshot> ReadAsync(CancellationToken ct = default) => Task.FromResult(tree);
    }

    /// <summary>Gives each snapshot in turn, then the last one again.</summary>
    private sealed class SequenceUsb(params UsbSnapshot[] trees) : IUsbTreeSource
    {
        private int _next;
        public Task<UsbSnapshot> ReadAsync(CancellationToken ct = default) => Task.FromResult(trees[Math.Min(Interlocked.Increment(ref _next) - 1, trees.Length - 1)]);
    }

    private sealed class FakeWmi(Func<string, string, WmiQueryResult> answer) : IWmiSource
    {
        public Task<WmiQueryResult> QueryAsync(string wmiNamespace, string wql, CancellationToken ct = default) => Task.FromResult(answer(wmiNamespace, wql));
    }

    private sealed class FakeRegistry(string manufacturer) : IRegistrySource
    {
        public Task<WmiQueryResult> ReadAsync(RegistryRead read, CancellationToken ct = default) =>
            Task.FromResult(new WmiQueryResult(read.Location, read.Describe(), [Row(("SystemManufacturer", manufacturer))]));
    }

    private sealed class NoProcesses : IProcessLauncher
    {
        public Task<ProcessResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken) =>
            Task.FromResult(new ProcessResult(1, "", "no processes in tests"));
    }

    private sealed class FakeHost(IReadOnlyList<WinEvent> events) : Core.Plugins.IHostQueries
    {
        public string? Log { get; private set; }
        public Task<ModuleAvailability> SensorsAvailabilityAsync(CancellationToken ct = default) => throw new NotSupportedException();
        public Task<Core.Sensors.SensorSnapshot> ReadSensorsAsync(CancellationToken ct = default) => throw new NotSupportedException();
        public Task<DriveList?> ReadDrivesAsync(CancellationToken ct = default) => throw new NotSupportedException();
        public Task<IReadOnlyDictionary<char, RetrimRecord>> ReadRetrimsAsync(CancellationToken ct = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<WinEvent>?> QueryEventsAsync(string log, string xpath, int max, CancellationToken ct = default)
        {
            Log = log;
            return Task.FromResult<IReadOnlyList<WinEvent>?>(events);
        }
        public Task<IReadOnlyCollection<string>> ReadEventReviewsAsync(CancellationToken ct = default) => throw new NotSupportedException();
    }
}
