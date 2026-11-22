using System.Net.NetworkInformation;
using RemotePCDiagnostics.Host;

namespace RemotePCDiagnostics.Host.Tests;

/// <summary>The in-process registry and WMI reads, for real on this PC (category WindowsReadOnly). Nothing here writes.</summary>
[Trait("Category", "WindowsReadOnly")]
public class WindowsSettingsReadTests
{
    [Fact]
    public void Fast_startup_and_proxy_read_without_PowerShell()
    {
        var settings = new WindowsSystemSettings();
        Assert.True(settings.GetFastStartup() is null or 0 or 1);
        Assert.True(settings.GetUserProxyEnable() is null or 0 or 1);
    }

    [Fact]
    public void Adapter_dns_reads_for_a_real_adapter_and_is_null_for_an_unknown_one()
    {
        var settings = new WindowsSystemSettings();
        Assert.Null(settings.GetAdapterDns("No such adapter " + Guid.NewGuid().ToString("N")));
        Assert.Null(settings.GetAdapterDns("Wi-Fi*"));                                 // wildcards are never a name
        var adapter = NetworkInterface.GetAllNetworkInterfaces()
            .FirstOrDefault(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType is NetworkInterfaceType.Ethernet or NetworkInterfaceType.Wireless80211);
        if (adapter is null) return; // no connected adapter on this PC
        var dns = settings.GetAdapterDns(adapter.Name);
        Assert.NotNull(dns);
        if (dns.Length > 0)
            Assert.All(dns.Split(',', StringSplitOptions.RemoveEmptyEntries), s => Assert.True(System.Net.IPAddress.TryParse(s, out _), s));
    }

    [Fact]
    public void Running_services_process_ids_come_from_the_service_control_manager()
    {
        // The Windows Event Log service always runs, in its own svchost.
        var pids = WindowsMemorySystem.RunningServicePids();
        Assert.True(pids.TryGetValue("EventLog", out var pid), string.Join(", ", pids.Keys.Take(20)));
        Assert.True(pid > 4);
    }

    [Fact]
    public async Task Page_file_settings_read_through_WMI_in_the_journal_format()
    {
        var b64 = await new WindowsMemorySystem().ReadPageFileSettingsAsync(CancellationToken.None);
        if (b64 is null) return; // Windows manages the page file size: nothing custom to record
        var json = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(b64));
        using var doc = System.Text.Json.JsonDocument.Parse(json);
        Assert.All(doc.RootElement.EnumerateArray(), e =>
        {
            Assert.Contains(".sys", e.GetProperty("Name").GetString(), StringComparison.OrdinalIgnoreCase);
            var initial = e.GetProperty("InitialSize").GetUInt32();
            var max = e.GetProperty("MaximumSize").GetUInt32();
            Assert.True(max >= initial, $"MaximumSize ({max}) < InitialSize ({initial})");
        });
    }
}
