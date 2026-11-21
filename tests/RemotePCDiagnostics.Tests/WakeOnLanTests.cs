using System.Net.NetworkInformation;
using RemotePCDiagnostics.Agent;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Wake;
using RemotePCDiagnostics.Modules.WakeReadiness;
using PeakSWC.RemoteWebView.Agent;

namespace RemotePCDiagnostics.Tests;

/// <summary>Wake-on-LAN packet, subnet matching, the readiness check, and the relay payload. No datagram leaves the machine.</summary>
public class WakeOnLanTests
{
    private const string S3States =
        "The following sleep states are available on this system:\r\n" +
        "    Standby (S3)\r\n    Hibernate\r\n    Fast Startup\r\n\r\n" +
        "The following sleep states are not available on this system:\r\n" +
        "    Standby (S0 Low Power Idle)\r\n\tThe system firmware does not support this standby state.\r\n";

    private const string ModernStandby =
        "The following sleep states are available on this system:\r\n" +
        "    Standby (S0 Low Power Idle) Network Connected\r\n    Hibernate\r\n\r\n" +
        "The following sleep states are not available on this system:\r\n" +
        "    Standby (S3)\r\n        This standby state is disabled when S0 low power idle is supported.\r\n";

    private static readonly byte[] Mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

    [Fact]
    public void Magic_packet_is_six_ff_bytes_then_the_mac_sixteen_times()
    {
        var packet = WakeAddresses.MagicPacket(Mac);
        Assert.Equal(102, packet.Length);
        Assert.All(packet.Take(6), b => Assert.Equal(0xFF, b));
        for (var i = 0; i < 16; i++)
            Assert.Equal(Mac, packet.AsSpan(6 + i * 6, 6).ToArray());
    }

    [Theory]
    [InlineData("00:11:22:33:44:55")]
    [InlineData("00-11-22-33-44-55")]
    [InlineData("001122334455")]
    public void Mac_parser_accepts_the_usual_forms(string text)
    {
        Assert.True(WakeAddresses.TryParseMac(text, out var mac));
        Assert.Equal(Mac, mac);
        Assert.Equal("00:11:22:33:44:55", WakeAddresses.FormatMac(mac));
    }

    [Theory]
    [InlineData("")]
    [InlineData("00:11:22:33:44")]
    [InlineData("00:00:00:00:00:00")]
    [InlineData("FF:FF:FF:FF:FF:FF")]
    [InlineData("01:00:5E:00:00:01")]
    public void Mac_parser_rejects_a_target_that_cannot_be_woken(string text) =>
        Assert.False(WakeAddresses.TryParseMac(text, out _));

    [Fact]
    public void Subnet_broadcast_follows_the_prefix()
    {
        Assert.True(WakeAddresses.TryIPv4("192.168.1.50", out var ip));
        Assert.True(WakeAddresses.TrySubnet(ip, 24, out var network, out var broadcast));
        Assert.Equal("192.168.1.0", network.ToString());
        Assert.Equal("192.168.1.255", broadcast.ToString());

        Assert.True(WakeAddresses.TryIPv4("10.1.2.3", out var slash23));
        Assert.True(WakeAddresses.TrySubnet(slash23, 23, out var net23, out var bcast23));
        Assert.Equal("10.1.2.0", net23.ToString());
        Assert.Equal("10.1.3.255", bcast23.ToString());

        Assert.True(WakeAddresses.TryIPv4("172.16.5.9", out var slash16));
        Assert.True(WakeAddresses.TrySubnet(slash16, 16, out var net16, out var bcast16));
        Assert.Equal("172.16.0.0", net16.ToString());
        Assert.Equal("172.16.255.255", bcast16.ToString());

        Assert.False(WakeAddresses.TryIPv4("192.168.1", out _));
        Assert.False(WakeAddresses.TryIPv4("192.168.1.256", out _));
        Assert.True(WakeAddresses.IsLinkLocal(System.Net.IPAddress.Parse("169.254.1.1")));
        Assert.Equal(24, WakeAddresses.PrefixOf(System.Net.IPAddress.Parse("255.255.255.0")));
    }

    [Fact]
    public void Plan_sends_ports_9_and_7_to_the_matching_subnet_and_the_global_broadcast()
    {
        var plan = WakeOnLan.Plan(
            ["00-11-22-33-44-55"],
            ["192.168.001.255"],
            [
                new WakeEndpoint("Wi-Fi", "192.168.1.20", "192.168.1.255", 24),
                new WakeEndpoint("Ethernet", "10.0.0.5", "10.0.0.255", 24),
            ]);

        Assert.False(plan.Refused);
        Assert.Equal(4, plan.Packets.Count);
        Assert.All(plan.Packets, p => Assert.Equal("Wi-Fi", p.InterfaceName));
        Assert.Contains(plan.Packets, p => p.Destination == "192.168.1.255" && p.Port == 9);
        Assert.Contains(plan.Packets, p => p.Destination == "192.168.1.255" && p.Port == 7);
        Assert.Contains(plan.Packets, p => p.Destination == "255.255.255.255" && p.Port == 9);
        Assert.Contains(plan.Packets, p => p.Destination == "255.255.255.255" && p.Port == 7);
        Assert.Equal(Mac, plan.Packets[0].Payload.AsSpan(6, 6).ToArray());
    }

    [Fact]
    public void Plan_does_not_treat_the_global_broadcast_as_a_subnet_match()
    {
        var plan = WakeOnLan.Plan(
            ["00:11:22:33:44:55"],
            ["255.255.255.255"],
            [new WakeEndpoint("Wi-Fi", "192.168.1.20", "192.168.1.255", 24)]);
        Assert.True(plan.Refused);
        Assert.Empty(plan.Packets);
        Assert.Contains("subnet", plan.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_command_that_is_too_large_sends_nothing()
    {
        var transport = new RecordingTransport();
        var macs = Enumerable.Range(0, 17).Select(i => $"02:00:00:00:00:{i:X2}").ToList();
        var attempt = WakeOnLan.Execute(macs, ["192.168.1.255"], [new WakeEndpoint("Wi-Fi", "192.168.1.20", "192.168.1.255", 24)], transport);
        Assert.False(attempt.Ok);
        Assert.Empty(transport.Sent);
        Assert.Contains("16", attempt.Detail);
    }

    [Fact]
    public void A_bad_mac_is_reported_and_the_valid_one_is_still_sent()
    {
        var transport = new RecordingTransport();
        var attempt = WakeOnLan.Execute(
            ["not-a-mac", "00:11:22:33:44:55"],
            ["192.168.1.255"],
            [new WakeEndpoint("Wi-Fi", "192.168.1.20", "192.168.1.255", 24)],
            transport);
        Assert.True(attempt.Ok);
        Assert.Equal(4, transport.Sent.Count);
        Assert.Contains(attempt.Sent, row => !row.Sent && row.Mac == "not-a-mac");
        Assert.Contains("skipped", attempt.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_transport_error_is_one_row_and_the_other_packets_still_go()
    {
        var transport = new RecordingTransport { FailPort = 7 };
        var attempt = WakeOnLan.Execute(
            ["00:11:22:33:44:55"],
            ["192.168.1.255"],
            [new WakeEndpoint("Wi-Fi", "192.168.1.20", "192.168.1.255", 24)],
            transport);
        Assert.True(attempt.Ok);
        Assert.Equal(2, transport.Sent.Count(s => s.Port == 9));
        Assert.Equal(2, attempt.Sent.Count(s => s.Port == 7 && !s.Sent));
        Assert.Contains("failed", attempt.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void S3_output_is_not_modern_standby_just_because_s0_is_listed_as_missing()
    {
        var s3 = WakePowerInfo.Parse(S3States);
        Assert.NotNull(s3);
        Assert.False(s3.ModernStandby);
        Assert.True(s3.S3);
        Assert.True(s3.Hibernate);

        var modern = WakePowerInfo.Parse(ModernStandby);
        Assert.NotNull(modern);
        Assert.True(modern.ModernStandby);
        Assert.False(modern.S3);
        Assert.Equal("connected", modern.StandbyNetwork);

        var disconnected = WakePowerInfo.Parse(
            "The following sleep states are available on this system:\r\n    Standby (S0 Low Power Idle) Network Disconnected\r\n");
        Assert.Equal("disconnected", disconnected!.StandbyNetwork);
        Assert.Null(WakePowerInfo.Parse(""));
    }

    [Fact]
    public void The_star_keyword_wins_and_an_absent_keyword_is_unsupported()
    {
        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
        {
            ["*WakeOnMagicPacket"] = "0",
            ["WakeOnMagicPacket"] = "1",
            ["*PMARPOffload"] = "Enabled",
        };
        var setting = WakeNicSetting.FromValues(values);
        Assert.Equal("Disabled", setting.MagicPacket);
        Assert.Equal("Enabled", setting.ArpOffload);
        Assert.Equal("Unsupported", setting.Pattern);
        Assert.Equal("Unsupported", setting.NsOffload);
        Assert.Equal(WakeNicSetting.Unknown, WakeNicSetting.FromValues(null));
    }

    [Fact]
    public void Compose_marks_the_adapter_windows_listed_and_skips_a_virtual_one()
    {
        var guid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
        var snap = WakeSnapshot.Compose(
            WakePowerInfo.Parse(ModernStandby),
            powerRead: true,
            armed: ["Qualcomm FastConnect 7800", "HID Keyboard Device"],
            settings: new Dictionary<string, WakeNicSetting> { [guid] = new("Enabled", "Disabled", "Enabled", "Enabled") },
            registryRead: true,
            adapters:
            [
                new("Wi-Fi", "Qualcomm FastConnect 7800", "Wi-Fi", "A0:B1:C2:D3:E4:F5", "192.168.1.42", 24, guid),
                new("vEthernet (Default Switch)", "Hyper-V Virtual Ethernet Adapter", "Ethernet", "00:15:5D:01:02:03", "172.22.0.1", 20, guid),
            ]);

        var wifi = Assert.Single(snap.Adapters);
        Assert.Equal("A0:B1:C2:D3:E4:F5", wifi.Mac);
        Assert.Equal("192.168.1.0", wifi.Subnet);
        Assert.Equal("192.168.1.255", wifi.Broadcast);
        Assert.Equal("yes", wifi.WakeArmed);
        Assert.Equal("Enabled", wifi.MagicPacket);
        Assert.True(snap.ModernStandby);
        Assert.False(WakeSnapshot.IncludeInReport("vEthernet (Default Switch)", "Hyper-V Virtual Ethernet Adapter", "Ethernet"));
        Assert.True(WakeSnapshot.IncludeInReport("Wi-Fi", "Qualcomm FastConnect 7800", "Wi-Fi"));
    }

    [Fact]
    public void The_relay_payload_carries_the_addresses_and_the_wake_flags()
    {
        var msg = WakeRelay.ToReadiness(WifiSnapshot());
        Assert.True(msg.ModernStandby);
        Assert.True(msg.PowerRead);
        Assert.Equal("connected", msg.StandbyNetwork);
        var adapter = Assert.Single(msg.Adapters);
        Assert.Equal("Wi-Fi", adapter.AdapterType);
        Assert.Equal("A0:B1:C2:D3:E4:F5", adapter.Mac);
        Assert.Equal("192.168.1.0", adapter.Subnet);
        Assert.Equal("192.168.1.255", adapter.Broadcast);
        Assert.Equal(24, adapter.PrefixLength);
        Assert.Equal("yes", adapter.WakeArmed);
        Assert.Equal("Enabled", adapter.MagicPacket);
    }

    [Fact]
    public void Send_maps_the_attempt_without_opening_a_real_socket()
    {
        var transport = new RecordingTransport();
        var command = new SendWakeCommand { RequestId = "wake-9" };
        command.TargetMac.Add("00:11:22:33:44:55");
        command.Broadcast.Add("192.168.1.255");
        var report = WakeRelay.Send(command, [new WakeEndpoint("Wi-Fi", "192.168.1.20", "192.168.1.255", 24)], transport);
        Assert.True(report.Ok);
        Assert.Equal("wake-9", report.RequestId);
        Assert.Equal(4, report.Sent.Count);
        Assert.All(report.Sent, row => Assert.True(row.Sent));
        Assert.Contains(report.Sent, row => row.Destination == "255.255.255.255" && row.Port == 7);
    }

    [Fact]
    public void A_modern_standby_wi_fi_adapter_that_is_armed_reports_ready_and_changes_nothing()
    {
        var report = WakeReadinessModule.Build(WifiSnapshot());
        Assert.Equal(DiagnosticStatus.Ok, report.Status);
        Assert.Contains("Modern Standby", report.Summary);
        Assert.Contains("192.168.1.255", report.Summary);
        var card = report.Cards.Single(c => c.Id == "readiness");
        Assert.Equal(AreaLevel.Ok, card.Level);
        Assert.Contains("does not change", card.Note, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("ports 9 and 7", card.Note);
        Assert.Contains("administrator", card.Note, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("hibernate", card.Note, StringComparison.OrdinalIgnoreCase);
        AssertNoActions(report);
        Assert.Contains(report.Cards.Single(c => c.Id == "adapters").Rows, r => r.Values.Contains("A0:B1:C2:D3:E4:F5"));
    }

    [Fact]
    public void A_disabled_magic_packet_is_a_warning_that_names_the_setting()
    {
        var report = WakeReadinessModule.Build(WifiSnapshot() with
        {
            Adapters =
            [
                WifiSnapshot().Adapters[0] with { MagicPacket = "Disabled", WakeArmed = "no" },
            ],
        });
        Assert.Equal(DiagnosticStatus.Warning, report.Status);
        Assert.Contains("Wake on Magic Packet", report.Cards.Single(c => c.Id == "readiness").Note);
        Assert.Contains("Allow this device to wake", report.Cards.Single(c => c.Id == "readiness").Note);
        Assert.Contains("powercfg /devicequery wake_armed", report.Cards.Single(c => c.Id == "readiness").Note);
        AssertNoActions(report);
    }

    [Fact]
    public void Wi_fi_on_s3_is_not_reported_as_ready()
    {
        var report = WakeReadinessModule.Build(new WakeSnapshot(true, false, true, true, "",
        [
            new("Wi-Fi", "Intel(R) Wi-Fi 6 AX201", "Wi-Fi", "A0:B1:C2:D3:E4:F5", "192.168.1.42", 24, "192.168.1.0", "192.168.1.255", "yes", "Enabled", "Disabled", "Enabled", "Enabled"),
        ]));
        Assert.Equal(DiagnosticStatus.Warning, report.Status);
        Assert.Contains("S3", report.Cards.Single(c => c.Id == "readiness").Note);
    }

    [Fact]
    public void Disconnected_modern_standby_cannot_be_woken_over_wi_fi()
    {
        var report = WakeReadinessModule.Build(WifiSnapshot() with { StandbyNetwork = "disconnected" });
        Assert.Equal(DiagnosticStatus.Warning, report.Status);
        Assert.Contains("disconnected", report.Cards.Single(c => c.Id == "readiness").Note, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_wired_s3_adapter_that_is_armed_reports_ready()
    {
        var report = WakeReadinessModule.Build(new WakeSnapshot(true, false, true, true, "",
        [
            new("Ethernet", "Realtek PCIe GbE Family Controller", "Ethernet", "00:11:22:33:44:55", "10.0.0.8", 24, "10.0.0.0", "10.0.0.255", "yes", "Enabled", "Disabled", "Enabled", "Enabled"),
        ]));
        Assert.Equal(DiagnosticStatus.Ok, report.Status);
        Assert.Contains("wired", report.Summary, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("BIOS", report.Cards.Single(c => c.Id == "readiness").Note);
        AssertNoActions(report);
    }

    [Fact]
    public void Nothing_read_is_could_not_run_rather_than_a_failed_pc()
    {
        var report = WakeReadinessModule.Build(WakeSnapshot.Empty);
        Assert.Equal(DiagnosticStatus.Error, report.Status);
        Assert.NotNull(report.CouldNotRunReason);
    }

    [Fact]
    public async Task The_check_asks_powercfg_for_sleep_states_and_wake_armed_devices()
    {
        var launcher = new ScriptedLauncher((file, args) =>
        {
            Assert.Equal("powercfg.exe", file, ignoreCase: true);
            return args[0] switch
            {
                "/a" => ScriptedLauncher.Ok(S3States),
                "/devicequery" => ScriptedLauncher.Ok("NONE\r\n"),
                _ => ScriptedLauncher.Fail(),
            };
        });
        var module = new WakeReadinessModule(new SystemCommandRunner(launcher, isProcessElevated: () => true));
        var result = await module.RefreshAsync(null);
        Assert.Contains(launcher.Calls, c => c.Args[0] == "/a");
        Assert.Contains(launcher.Calls, c => c.Args.Count >= 2 && c.Args[0] == "/devicequery" && c.Args[1] == "wake_armed");
        Assert.IsType<AreaReport>(result.Payload);
        AssertNoActions((AreaReport)result.Payload!);
    }

    [Fact]
    public void Reading_send_endpoints_does_not_throw()
    {
        var endpoints = WakeInventory.ReadSendEndpoints();
        foreach (var nic in endpoints)
        {
            Assert.False(string.IsNullOrWhiteSpace(nic.Name));
            Assert.True(WakeAddresses.TryIPv4(nic.LocalAddress, out _));
            Assert.True(WakeAddresses.TryIPv4(nic.Broadcast, out _));
            Assert.InRange(nic.PrefixLength, 1, 31);
        }
        Assert.Equal("Wi-Fi", WakeInventory.AdapterKind(NetworkInterfaceType.Wireless80211));
        Assert.Equal("Ethernet", WakeInventory.AdapterKind(NetworkInterfaceType.Ethernet));
    }

    private static WakeSnapshot WifiSnapshot() => new(true, true, false, true, "connected",
    [
        new("Wi-Fi", "Qualcomm FastConnect 7800", "Wi-Fi", "A0:B1:C2:D3:E4:F5", "192.168.1.42", 24, "192.168.1.0", "192.168.1.255", "yes", "Enabled", "Disabled", "Enabled", "Enabled"),
    ]);

    private static void AssertNoActions(AreaReport report)
    {
        Assert.All(report.Cards, c => Assert.True(c.Actions is null || c.Actions.Count == 0));
        Assert.All(report.Cards.SelectMany(c => c.Rows), r => Assert.True(r.Actions is null || r.Actions.Count == 0));
    }

    private sealed class RecordingTransport : IWakeTransport
    {
        public int FailPort { get; init; }
        public List<(string Local, string Destination, int Port, byte[] Payload)> Sent { get; } = [];

        public void Send(string localAddress, string destination, int port, byte[] payload)
        {
            if (port == FailPort) throw new System.Net.Sockets.SocketException(10051);
            Assert.Equal(102, payload.Length);
            Sent.Add((localAddress, destination, port, payload));
        }
    }
}
