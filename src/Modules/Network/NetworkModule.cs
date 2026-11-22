using System.Globalization;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// Network adapters and their error counters, with (<paramref name="includeWifiAndIpConfig"/>) Wi-Fi signal, IP configuration, a DNS speed
/// comparison, recent network events and reachability probes. The adapters and IP configuration come from <paramref name="source"/>: WMI
/// through the Agent, or osquery and PowerShell in the Store edition without an Agent. Wi-Fi (netsh) and the event history (wevtutil) need
/// <paramref name="commands"/>; <paramref name="offline"/> leaves out what asks the live network (the DNS comparison and the probes), for
/// recordings and their replays.
/// </summary>
public sealed class NetworkModule(INetworkSource source, SystemCommandRunner? commands = null, bool includeWifiAndIpConfig = false, DnsSpeedTest? dnsTest = null,
    ILogger? log = null, bool offline = false) : AreaModuleBase(log ?? commands?.Log)
{
    public const string ModuleName = ModuleSlugs.Network;
    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.Network;
    public override string DisplayName => includeWifiAndIpConfig ? "Network & Wi-Fi" : "Network adapters";
    protected override string FailedMessage => "Couldn't read network adapter details on this PC.";

    public override Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken = default) => source.CheckAvailabilityAsync(cancellationToken);

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        var total = includeWifiAndIpConfig ? 4 : 1;
        progress.ReportStep(1, total, "Checking network adapters…");
        if (await source.ReadAdaptersAsync(ct).ConfigureAwait(false) is not { } adapters) return AreaReport.Failed(FailedMessage);
        var baseReport = Build(adapters);
        if (!includeWifiAndIpConfig)
            return baseReport;

        progress.ReportStep(2, total, "Checking Wi-Fi signal and IP configuration…");
        var connectedAdapters = ConnectedCount(adapters);
        var (wlanRes, ipSnap) = await ReadWifiAndIpAsync(ct).ConfigureAwait(false);
        if (connectedAdapters > 0 && ipSnap is not { Adapters.Count: > 0 })
        {
            // The adapter list says we're connected but the IP read came back empty: usually the network stack was mid-change
            // (resume, roaming, adapter reset). Read once more before reporting it, so the check doesn't claim the PC is offline.
            Log($"{Name}: {connectedAdapters} adapter(s) connected but no IP configuration was read; retrying in {IpConfigRetryDelay.TotalSeconds:0.#} s");
            await Task.Delay(IpConfigRetryDelay, ct).ConfigureAwait(false);
            (wlanRes, ipSnap) = await ReadWifiAndIpAsync(ct).ConfigureAwait(false);
        }
        var wlanOk = wlanRes is { ExitCode: 0 };
        var ipOk = ipSnap is { Adapters.Count: > 0 };
        var gateway = ipSnap is null ? null : WifiConfigModule.PrimaryAdapter(ipSnap)?.Gateway;
        // Measure the current DNS against Cloudflare/Google (a few seconds; nothing changed) so switching is only suggested when it's faster.
        DnsComparison? dns = null;
        if (!offline && ipSnap is not null && WifiConfigModule.PrimaryAdapter(ipSnap) is { } primary && !DnsSpeedTest.IsPublicAlready(primary.Dns))
        {
            progress.ReportStep(3, total, "Comparing DNS speed…");
            try { dns = await (dnsTest ?? new DnsSpeedTest(log: Logger)).CompareAsync(primary.Dns, ct).ConfigureAwait(false); }
            catch (Exception ex) when (ex is not OperationCanceledException) { LogWarn($"DNS speed test failed: {ex.Message}"); }
        }
        progress.ReportStep(4, total, "Checking recent network events and reachability.");
        var history = commands is null ? Task.FromResult<AreaCard?>(null) : Nullable(NetworkDiagnostics.ReadHistoryAsync(commands, ct));
        var probes = offline ? Task.FromResult<AreaCard?>(null) : Nullable(NetworkDiagnostics.ProbeAsync(gateway, ct));
        await Task.WhenAll(history, probes).ConfigureAwait(false);
        var wifiRep = wlanOk || ipOk ? WifiConfigModule.Build(
            wlanOk ? WifiConfigModule.ParseNetshWlan(wlanRes!.StdOut) : null, wlanOk, ipSnap, dns, connectedAdapters) : null;
        // Without commands netsh wasn't asked, so there is no Wi-Fi card to show (rather than one saying it couldn't be read).
        var combinedCards = (wifiRep?.Cards ?? []).Where(c => commands is not null || c.Id != "wifi").Concat(baseReport.Cards)
            .Concat(new[] { await history.ConfigureAwait(false), await probes.ConfigureAwait(false) }.OfType<AreaCard>()).ToList();
        var combinedStatus = AreaReport.Worst(combinedCards.Select(c => c.ErrorText is not null ? AreaLevel.Warning : c.Level));
        var combinedSummary = wifiRep is null ? baseReport.Summary : $"{wifiRep.Summary} · {baseReport.Summary}";
        return new(combinedCards, combinedSummary, combinedStatus);
    }

    private static async Task<AreaCard?> Nullable(Task<AreaCard> card) => await card.ConfigureAwait(false);

    /// <summary>Wait before re-reading IP configuration when it came back empty while an adapter is connected.</summary>
    public static TimeSpan IpConfigRetryDelay { get; set; } = TimeSpan.FromSeconds(2);

    private async Task<(ProcessResult? Wlan, IpConfigSnapshot? Ip)> ReadWifiAndIpAsync(CancellationToken ct)
    {
        var wlanRes = commands is null ? null : await commands.RunAsync(WifiConfigModule.Netsh, ["wlan", "show", "interfaces"], ct).ConfigureAwait(false);
        return (wlanRes, await source.ReadIpConfigAsync(ct).ConfigureAwait(false));
    }

    /// <summary>The adapters the report shows: real network cards when Windows says which are physical, else any with a MAC or link.</summary>
    private static List<NetworkAdapter> Shown(IReadOnlyList<NetworkAdapter> all) =>
        all.Any(a => a.Physical == true) ? all.Where(a => a.Physical == true).ToList() : all.Where(a => a.Mac.Length > 0 || a.IsConnected).ToList();

    /// <summary>How many of the shown adapters are connected (the "N of M adapters connected" count).</summary>
    public static int ConnectedCount(IReadOnlyList<NetworkAdapter> all) => Shown(all).Count(a => a.IsConnected);

    private static string N(long? v) => v?.ToString("N0", CultureInfo.InvariantCulture) ?? "Not reported";

    public static AreaReport Build(IReadOnlyList<NetworkAdapter> all)
    {
        // Prefer real network cards; hide virtual/loopback adapters when Windows tells us which are physical.
        var list = Shown(all);
        if (list.Count == 0) return new([], "No network adapters were found.", DiagnosticStatus.Warning);
        list = list.OrderByDescending(a => a.IsConnected).ThenBy(a => a.Name, StringComparer.CurrentCultureIgnoreCase).ToList();

        var cards = list.Select((a, i) =>
        {
            var meta = !a.HasCounters ? "Error counts aren't reported for this adapter"
                : a.Errors == 0 && a.Drops == 0 ? "No errors"
                : string.Join(" · ", new[] { a.Errors > 0 ? AreaModuleBase.Plural((int)Math.Min(a.Errors, int.MaxValue), "error") : null,
                                             a.Drops > 0 ? $"{a.Drops:N0} dropped" : null }.Where(x => x is not null));
            var head = a.FriendlyConnection + (a.IsConnected && NetworkAdapter.FormatSpeed(a.SpeedBps) is { Length: > 0 } s ? $" · {s}" : "");
            var rows = new List<AreaRow>();
            void Add(string l, string v, AreaLevel lv = AreaLevel.Neutral) { if (v.Length > 0) rows.Add(new(lv, [l, v])); }
            Add("Status", a.FriendlyConnection, a.IsConnected ? AreaLevel.Ok : AreaLevel.Neutral);
            Add("Adapter", a.Description); Add("Manufacturer", a.Manufacturer); Add("Speed", NetworkAdapter.FormatSpeed(a.SpeedBps)); Add("Hardware address", a.Mac);
            if (a.HasCounters)
            {
                Add("Packets received", N(a.PacketsIn)); Add("Packets sent", N(a.PacketsOut));
                Add("Receive errors", N(a.ErrorsIn), a.ErrorsIn is > 0 ? a.Level : AreaLevel.Neutral);
                Add("Send errors", N(a.ErrorsOut), a.ErrorsOut is > 0 ? a.Level : AreaLevel.Neutral);
                Add("Incoming packets dropped", N(a.DropsIn)); Add("Outgoing packets dropped", N(a.DropsOut));
            }
            return new AreaCard($"nic{i}", a.Name.Length > 0 ? a.Name : $"Adapter {i + 1}", a.Level, head, meta, ["Detail", "Value"], rows,
                Note: "Counts are since the adapter was last started. A few dropped packets are normal.");
        }).ToList();

        var connected = list.Count(a => a.IsConnected);
        var errored = list.Count(a => a.Level == AreaLevel.Warning);
        var summary = (connected == 0 ? "Not connected to a network" : $"{connected} of {AreaModuleBase.Plural(list.Count, "adapter")} connected")
            + (errored > 0 ? $" · {errored} with errors"
               : list.Any(a => a.Errors > 0) ? " · errors within normal range"
               : list.Any(a => a.HasCounters) ? " · no errors" : "");
        var status = errored > 0 || connected == 0 ? DiagnosticStatus.Warning : DiagnosticStatus.Ok;
        return new(cards, summary, status);
    }
}
