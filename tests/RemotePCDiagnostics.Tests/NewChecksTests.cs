using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Tests;

public class NewChecksTests
{
    [Fact]
    public async Task ResourceHogs_GroupsProcessesAndChecksUptime()
    {
        const string uptimeJson = """[{"days":"18","hours":"4","minutes":"12","total_seconds":"1570320"}]""";
        const string procsJson = """
        [
          {"pid":"100","name":"chrome.exe","resident_size":"2684354560","user_time":"120000","system_time":"30000","disk_bytes_read":"10485760","disk_bytes_written":"5242880"},
          {"pid":"101","name":"chrome.exe","resident_size":"2147483648","user_time":"60000","system_time":"15000","disk_bytes_read":"1048576","disk_bytes_written":"0"},
          {"pid":"200","name":"code.exe","resident_size":"536870912","user_time":"40000","system_time":"10000","disk_bytes_read":"2097152","disk_bytes_written":"1048576"}
        ]
        """;
        const string psJson = """{"FastStartup":"1"}""";

        var launcher = new ScriptedLauncher((file, args) =>
        {
            if (file.StartsWith("osqueryi", StringComparison.OrdinalIgnoreCase))
            {
                var sql = args[^1];
                return ScriptedLauncher.Ok(sql.Contains("uptime") ? uptimeJson : procsJson);
            }
            return ScriptedLauncher.Ok(psJson);
        });

        var module = new ResourceHogsModule(ScriptedLauncher.Osquery(launcher), new SystemCommandRunner(launcher));
        var res = await module.RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Warning, res.Status);
        var rep = Assert.IsType<AreaReport>(res.Payload);
        Assert.Equal(3, rep.Cards.Count);

        var upCard = rep.Cards.Single(c => c.Id == "uptime");
        Assert.Equal(AreaLevel.Warning, upCard.Level);
        Assert.Equal("Up 18d 4h", upCard.Headline);
        Assert.Contains("Fast Startup is on", upCard.Meta);

        var memCard = rep.Cards.Single(c => c.Id == "memory");
        Assert.Equal(AreaLevel.Warning, memCard.Level); // 4.5 GB combined chrome.exe >= 4 GB threshold
        Assert.Equal("chrome.exe", memCard.Rows[0].Values[0]);
        Assert.Equal("2", memCard.Rows[0].Values[1]);

        // Verify numeric SortKeys on Memory column (col 2)
        var sortedAsc = AreaSort.Sort(memCard.Rows, 2, descending: false);
        Assert.Equal("code.exe", sortedAsc[0].Values[0]);
        Assert.Equal("chrome.exe", sortedAsc[1].Values[0]);
    }

    [Fact]
    public void DeviceDrivers_FlagsErrorDevicesAndUnsignedDrivers()
    {
        var problems = new List<ProblemDevice>
        {
            new("NVIDIA GeForce RTX 4070", "Display", "PCI\\VEN_10DE", 43, "Error"),
            new("Legacy Serial Port", "Ports", "ACPI\\PNP0501", 22, "Error"),
        };
        var drivers = new List<DriverEntry>
        {
            new("NVIDIA GeForce RTX 4070", "Display", "NVIDIA", "31.0.15.5222", new DateOnly(2026, 2, 10), true),
            new("Custom USB Filter", "USB", "Unknown", "1.0.0.0", new DateOnly(2024, 5, 1), false),
        };

        var rep = DeviceDriversModule.Build(problems, drivers);
        Assert.Equal(DiagnosticStatus.Warning, rep.Status);

        var probCard = rep.Cards.Single(c => c.Id == "problems");
        Assert.Equal(AreaLevel.Warning, probCard.Level);
        Assert.Contains("Code 43", probCard.Rows[0].Values[2]);
        Assert.Equal(AreaLevel.Neutral, probCard.Rows[1].Level); // Code 22 disabled is neutral

        var drvCard = rep.Cards.Single(c => c.Id == "drivers");
        Assert.Equal(AreaLevel.Warning, drvCard.Level); // 1 unsigned driver
        Assert.Contains("1 unsigned driver", drvCard.Meta);
        Assert.Contains(drvCard.Rows, r => r.Level == AreaLevel.Warning && r.Values[0] == "Custom USB Filter");
    }

    [Fact]
    public void BsodHistory_DetectsRecentBugChecksAndMinidumps()
    {
        var now = new DateTimeOffset(2026, 10, 30, 12, 0, 0, TimeSpan.Zero);
        var events = new List<WinEvent>
        {
            new(now.AddDays(-1), "System", "Microsoft-Windows-WER-SystemErrorReporting", 1001, 2,
                "The computer has rebooted from a bugcheck. The bugcheck was: 0x0000007e.", [], new Dictionary<string, string>()),
            new(now.AddDays(-2), "System", "Microsoft-Windows-WER-SystemErrorReporting", 1001, 2,
                "The computer has rebooted from a bugcheck. The bugcheck was: 0x00000116.", [], new Dictionary<string, string>()),
            new(now.AddDays(-10), "System", "Microsoft-Windows-Kernel-Power", 41, 1,
                "The system has rebooted without cleanly shutting down first.", [], new Dictionary<string, string>()),
        };
        var dumps = new List<MinidumpFile>
        {
            new("102926-12345-01.dmp", now.AddDays(-1), 1_048_576),
        };

        var rep = BsodHistoryModule.Build(events, dumps, now);
        Assert.Equal(DiagnosticStatus.Error, rep.Status); // 2 BSODs in last 7 days => Error

        var bsodCard = rep.Cards.Single(c => c.Id == "bsods");
        Assert.Equal(AreaLevel.Error, bsodCard.Level);
        Assert.Equal("2 blue screens", bsodCard.Headline);
        Assert.Contains("0x0000007e", bsodCard.Rows[0].Values[2]);

        var powerCard = rep.Cards.Single(c => c.Id == "power");
        Assert.Equal(AreaLevel.Neutral, powerCard.Level); // 10 days ago (> 7 days) is neutral

        var dumpCard = rep.Cards.Single(c => c.Id == "minidumps");
        Assert.Single(dumpCard.Rows);
        Assert.Equal("102926-12345-01.dmp", dumpCard.Rows[0].Values[1]);
    }

    [Fact]
    public void BatteryPower_CalculatesWearAndFlagsPowerSaver()
    {
        var wornBattery = new BatteryStatus("L20M3PF0", "SMP", "LiP", "Discharging", 64, 45000, 27000, 410);
        Assert.Equal(60, wornBattery.HealthPercent);
        Assert.Equal(40, wornBattery.WearPercent);

        var plan = BatteryPowerModule.ParsePowerPlan("Power Scheme GUID: a1841308-3541-4fab-bc81-f71556f20b4a  (Power saver)");
        Assert.Equal("Power saver", plan);

        var rep = BatteryPowerModule.Build([wornBattery], plan);
        Assert.Equal(DiagnosticStatus.Warning, rep.Status);
        Assert.Equal(AreaLevel.Warning, rep.Cards.Single(c => c.Id == "battery").Level);
        Assert.Equal(AreaLevel.Warning, rep.Cards.Single(c => c.Id == "plan").Level);

        // Desktop with no battery and Balanced plan
        var desktopRep = BatteryPowerModule.Build([], "Balanced");
        Assert.Equal(DiagnosticStatus.Ok, desktopRep.Status);
        Assert.Equal("No battery (desktop / AC only)", desktopRep.Cards.Single(c => c.Id == "battery").Headline);
    }

    [Fact]
    public void WifiConfig_ParsesNetshAndIpSnapshot()
    {
        const string netshOut = """
        There is 1 interface on the system:

            Name                   : Wi-Fi
            Description            : MediaTek Wi-Fi 6 MT7921 Wireless LAN Card
            GUID                   : 12345678-1234-1234-1234-1234567890ab
            Physical address       : aa:bb:cc:dd:ee:ff
            State                  : connected
            SSID                   : OfficeNet-5G
            BSSID                  : 11:22:33:44:55:66
            Network type           : Infrastructure
            Radio type             : 802.11ax
            Band                   : 5 GHz
            Channel                : 36
            Receive rate (Mbps)    : 866.7
            Transmit rate (Mbps)   : 866.7
            Signal                 : 42%
        """;

        const string ipJson = """
        {"Adapters":[{"Alias":"Wi-Fi","Description":"MediaTek Wi-Fi 6 MT7921","IPv4":"192.168.1.50","Gateway":"192.168.1.1","Dns":"1.1.1.1, 8.8.8.8"}],"ProxyEnabled":false,"ProxyServer":""}
        """;

        var wifi = WifiConfigModule.ParseNetshWlan(netshOut);
        Assert.NotNull(wifi);
        Assert.True(wifi!.Connected);
        Assert.Equal("OfficeNet-5G", wifi.Ssid);
        Assert.Equal(42, wifi.SignalPercent);
        Assert.Equal("5 GHz", wifi.Band);

        var snap = WifiConfigModule.ParseIpSnapshot(ipJson);
        Assert.Single(snap.Adapters);
        Assert.False(snap.ProxyEnabled);

        var rep = WifiConfigModule.Build(wifi, wlanOk: true, snap);
        Assert.Equal(DiagnosticStatus.Warning, rep.Status); // 42% signal < 50% threshold
        Assert.Equal(AreaLevel.Warning, rep.Cards.Single(c => c.Id == "wifi").Level);
        Assert.Equal(AreaLevel.Ok, rep.Cards.Single(c => c.Id == "ipdns").Level);
    }
}
