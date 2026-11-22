using System.Text.Json;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Recording;
using RemotePCDiagnostics.Legacy;

namespace RemotePCDiagnostics.Tests.Replay;

/// <summary>
/// The Network check, replayed from recorded PCs: its adapters and IP configuration moved from osquery and two PowerShell scripts to WMI (and
/// two registry values). Recorded as the recorder runs it: without netsh and the event logs, and offline (no probes, no DNS timing). A
/// recording made before the recorder knew the check skips these tests.
/// </summary>
public sealed class NetworkReplayTests
{
    public static TheoryData<string> Recordings => RecordingLibrary.Names();

    // A damaged answer can make "connected, but no IP configuration": the check then waits before reading again.
    static NetworkReplayTests() => NetworkModule.IpConfigRetryDelay = TimeSpan.Zero;

    internal static NetworkModule Network(ReplayedPc pc) =>
        new(new WmiNetworkSource(pc.Wmi, pc.Registry), includeWifiAndIpConfig: true, offline: true);
    /// <summary>The Store edition without an Agent: osquery interface_details and the NetAdapterStatistics and IpConfig scripts.</summary>
    internal static NetworkModule NetworkOld(ReplayedPc pc) =>
        new(new OsqueryNetworkSource(pc.Osquery, pc.Commands), includeWifiAndIpConfig: true, offline: true);

    // v6 recordings were made while this check was being written, before it asked MSFT_NetAdapter: they count as not knowing the check.
    private static bool HasNew(ReplayedPc pc) => pc.HasWmi(WmiNetworkSource.AdaptersSql) && pc.HasWmi(WmiNetworkSource.NetAdaptersSql);
    // Older recordings hold interface_details too (for the hardware inventory), but not the IP configuration script.
    private static bool HasOld(ReplayedPc pc) => pc.HasOsquery(OsqueryNetworkSource.Sql)
        && pc.Has(c => c.Kind == RecordedCall.ProcessKind && c.Args?.LastOrDefault() == OsqueryNetworkSource.IpConfigScript);

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task MatchesApprovedSnapshot(string name)
    {
        var pc = new ReplayedPc(RecordingLibrary.Load(name));
        Assert.SkipUnless(HasNew(pc), "This recording has no WMI network answers.");
        var result = await Network(pc).RefreshAsync(null, TestContext.Current.CancellationToken);
        Assert.Empty(pc.Replay.Misses);
        Snapshot.Match(RecordingLibrary.Folder(name), "Network", result);
    }

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task WmiAndLegacyAgree(string name)
    {
        var rec = RecordingLibrary.Load(name);
        var pc = new ReplayedPc(rec);
        Assert.SkipUnless(HasNew(pc) && HasOld(pc), "This recording doesn't hold both the WMI and the osquery + PowerShell network answers.");
        var ct = TestContext.Current.CancellationToken;
        var now = WithoutGains((AreaReport)(await Network(pc).RefreshAsync(null, ct)).Payload!);
        var oldPc = new ReplayedPc(rec);
        var old = WithoutGains((AreaReport)(await NetworkOld(oldPc).RefreshAsync(null, ct)).Payload!);
        Assert.Empty(oldPc.Replay.Misses);
        // An adapter that is up but that Win32_NetworkAdapter (so osquery) doesn't name is shown only on the WMI path, without a hardware
        // address (the HP OmniBook X's Wi-Fi). Cards are compared by adapter name, as that card moves the others' order.
        var oldTitles = old.Cards.Select(c => c.Title).ToHashSet(StringComparer.Ordinal);
        now = ByTitle(now with { Cards = now.Cards.Where(c => !IsNic(c) || oldTitles.Contains(c.Title) || c.Rows.Any(x => x.Values[0] == "Hardware address")).ToList() });
        old = ByTitle(old);
        var diffs = ReportDiff.Between(old, now, Live);
        Assert.True(diffs.Count == 0, $"{diffs.Count} differences:\n" + string.Join("\n", diffs));
    }

    /// <summary>
    /// Left out of both before comparing: a connected adapter's link speed, which WMI reports and osquery doesn't (0 on both test PCs; the
    /// headline's " · 1.2 Gbps" and the Speed row); and the DNS servers, scrubbed one placeholder per value: WMI lists them one by one, the
    /// script joins them into one value first, so two or more servers get different placeholders on the two paths.
    /// </summary>
    private static AreaReport WithoutGains(AreaReport r) => r with
    {
        Cards = r.Cards.Select(c => c.Id switch
        {
            "ipdns" => c with { Rows = c.Rows.Select(x => x.Values.Count > 3 ? x with { Values = x.Values.Select((v, i) => i == 3 ? "" : v).ToList() } : x).ToList() },
            _ when c.Id.StartsWith("nic", StringComparison.Ordinal) => c with
            {
                Headline = c.Headline.Split(" · ")[0],
                Rows = c.Rows.Where(x => x.Values.Count == 0 || x.Values[0] != "Speed").ToList(),
            },
            _ => c,
        }).ToList(),
    };

    private static bool IsNic(AreaCard c) => c.Id.StartsWith("nic", StringComparison.Ordinal);
    private static AreaReport ByTitle(AreaReport r) => r with { Cards = r.Cards.Select(c => IsNic(c) ? c with { Id = "nic:" + c.Title } : c).ToList() };

    /// <summary>Traffic keeps flowing between the two reads, so the packet counts differ by a little.</summary>
    private static bool Live(AreaCard card, AreaRow row) =>
        card.Id.StartsWith("nic", StringComparison.Ordinal) && row.Values.Count > 0 && row.Values[0].StartsWith("Packets", StringComparison.Ordinal);

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task SurvivesDamagedAnswers(string name)
    {
        var rec = RecordingLibrary.Load(name);
        Assert.SkipUnless(HasNew(new ReplayedPc(rec)), "This recording has no WMI network answers.");
        await DamagedRuns.AssertSurvivesAsync(rec, r => r.Payload is AreaReport a ? DamagedRuns.CommonProblems(a) : ["no report"], maxRows: 3,
            ("WMI", pc => Network(pc)), ("osquery + PowerShell", pc => NetworkOld(pc)));
    }

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task ManyReceiveErrors_Warn(string name)
    {
        var rec = RecordingLibrary.Load(name);
        Assert.SkipUnless(HasNew(new ReplayedPc(rec)), "This recording has no WMI network answers.");
        var connected = await ConnectedAsync(rec);
        Assert.SkipWhen(connected.Count == 0, "No adapter was connected when this PC was recorded.");
        var bad = rec.SetWmi("MSFT_NetAdapterStatisticsSettingData", "ReceivedPacketErrors", 5_000_000);
        var r = await Network(new ReplayedPc(bad)).RefreshAsync(null, TestContext.Current.CancellationToken);
        Assert.Equal(DiagnosticStatus.Warning, r.Status);
        Assert.Contains("with errors", r.Message);
        var report = (AreaReport)r.Payload!;
        Assert.Contains(report.Cards, c => c.Title == connected[0] && c.Level == AreaLevel.Warning && c.Meta.Contains("errors", StringComparison.Ordinal));
    }

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task EveryAdapterUnplugged_SaysNotConnected(string name)
    {
        var rec = RecordingLibrary.Load(name);
        Assert.SkipUnless(HasNew(new ReplayedPc(rec)), "This recording has no WMI network answers.");
        var unplugged = rec.SetWmi(WmiNetworkSource.AdaptersSql, "NetConnectionStatus", 7)
            .SetWmi(WmiNetworkSource.NetAdaptersSql, "InterfaceOperationalStatus", 2);
        var r = await Network(new ReplayedPc(unplugged)).RefreshAsync(null, TestContext.Current.CancellationToken);
        Assert.Contains("Not connected to a network", r.Message);
        // No adapter is up, so no IP configuration is listed either.
        Assert.DoesNotContain(((AreaReport)r.Payload!).Cards, c => c.Id == "ipdns" && c.Rows.Count > 0);
    }

    [Theory]
    [MemberData(nameof(Recordings))]
    public async Task ProxyTurnedOn_Warns(string name)
    {
        var rec = RecordingLibrary.Load(name);
        Assert.SkipUnless(HasNew(new ReplayedPc(rec)), "This recording has no WMI network answers.");
        Assert.SkipWhen((await ConnectedAsync(rec)).Count == 0, "No adapter was connected when this PC was recorded.");
        var proxied = WithProxy(rec, "proxy.example:8080");
        var r = await Network(new ReplayedPc(proxied)).RefreshAsync(null, TestContext.Current.CancellationToken);
        var ip = Assert.Single(((AreaReport)r.Payload!).Cards, c => c.Id == "ipdns");
        // A missing gateway or DNS is reported first; on a PC that has both, the proxy shows.
        if (ip.Headline is "No default gateway" or "No DNS servers configured") return;
        Assert.Equal("System proxy enabled", ip.Headline);
        Assert.Contains("proxy.example:8080", ip.Meta);
    }

    /// <summary>The connected adapters the check shows, by card title.</summary>
    private static async Task<List<string>> ConnectedAsync(MachineRecording rec)
    {
        var r = await Network(new ReplayedPc(rec)).RefreshAsync(null, TestContext.Current.CancellationToken);
        return ((AreaReport)r.Payload!).Cards.Where(c => c.Id.StartsWith("nic", StringComparison.Ordinal) && c.Headline.StartsWith("Connected", StringComparison.Ordinal))
            .Select(c => c.Title).ToList();
    }

    private static MachineRecording WithProxy(MachineRecording rec, string server) => new()
    {
        Schema = rec.Schema, Machine = rec.Machine, CapturedAt = rec.CapturedAt,
        Calls = rec.Calls.Select(c => c.Kind == RecordedCall.RegistryKind && c.Query == WmiNetworkSource.ProxyRead.Describe()
            ? c with { Rows = [new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase)
                { ["ProxyEnable"] = JsonSerializer.SerializeToElement(1), ["ProxyServer"] = JsonSerializer.SerializeToElement(server) }] }
            : c).ToList(),
    };
}
