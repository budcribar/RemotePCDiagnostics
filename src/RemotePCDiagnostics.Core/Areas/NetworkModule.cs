using System.Globalization;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>One network adapter with traffic and error counters (osquery <c>interface_details</c>; all values strings).</summary>
public sealed record NetworkAdapter(
    string Name, string Description, string Manufacturer, string Mac, string ConnectionStatus, bool? Enabled, bool? Physical,
    long? SpeedBps, long? PacketsIn, long? PacketsOut, long? ErrorsIn, long? ErrorsOut, long? DropsIn, long? DropsOut)
{
    public static NetworkAdapter FromRow(IReadOnlyDictionary<string, string> r) => new(
        FirstNonEmpty(r.Str("connection_id"), r.Str("friendly_name"), r.Str("description"), r.Str("interface")),
        r.Str("description"), r.Str("manufacturer"), r.Str("mac"), r.Str("connection_status"), Bool(r.Str("enabled")), Bool(r.Str("physical_adapter")),
        Positive(r.Long("speed")) ?? Positive(r.Long("link_speed")) * 1_000_000,
        r.Long("ipackets"), r.Long("opackets"), r.Long("ierrors"), r.Long("oerrors"), r.Long("idrops"), r.Long("odrops"));

    private static string FirstNonEmpty(params string[] s) => s.FirstOrDefault(x => x.Length > 0) ?? "";
    private static bool? Bool(string s) => s switch { "1" or "true" or "True" => true, "0" or "false" or "False" => false, _ => null };
    private static long? Positive(long? v) => v is > 0 and < long.MaxValue / 1_000_000 ? v : null;

    /// <summary>Win32_NetworkAdapter NetConnectionStatus codes (osquery reports the number).</summary>
    public string FriendlyConnection => ConnectionStatus switch
    {
        "2" => "Connected", "7" => "Cable unplugged / no signal", "0" => "Disconnected", "1" => "Connecting", "3" => "Disconnecting",
        "4" => "Hardware not present", "5" => "Hardware disabled", "6" => "Hardware problem", "8" => "Authenticating", "9" => "Authenticated",
        "10" => "Authentication failed", "11" => "Invalid address", "12" => "Credentials required",
        "" => Enabled == false ? "Turned off" : "Unknown",
        _ => ConnectionStatus,
    };

    public bool IsConnected => ConnectionStatus is "2" or "9";
    public bool HasCounters => PacketsIn is not null || ErrorsIn is not null || ErrorsOut is not null;
    public long Errors => (ErrorsIn ?? 0) + (ErrorsOut ?? 0);
    public long Drops => (DropsIn ?? 0) + (DropsOut ?? 0);
    public long Packets => (PacketsIn ?? 0) + (PacketsOut ?? 0);

    /// <summary>Errors (not drops) above 1% of traffic, or any errors with almost no traffic, are flagged.</summary>
    public const double ErrorRateWarning = 0.01;

    public AreaLevel Level
    {
        get
        {
            if (!HasCounters) return IsConnected ? AreaLevel.Ok : AreaLevel.Neutral;
            if (Errors > 0 && (Packets == 0 || (double)Errors / Packets >= ErrorRateWarning)) return AreaLevel.Warning;
            return IsConnected ? AreaLevel.Ok : AreaLevel.Neutral;
        }
    }

    public static string FormatSpeed(long? bps) => bps switch
    {
        null or <= 0 => "",
        >= 1_000_000_000 => $"{bps / 1_000_000_000.0:0.#} Gbps",
        >= 1_000_000 => $"{bps / 1_000_000.0:0.#} Mbps",
        _ => $"{bps / 1000.0:0.#} Kbps",
    };
}

/// <summary>
/// Network adapters via osquery <c>interface_details</c>. osquery 5.24 on Windows leaves the packet/error counters
/// blank, so when none are reported they are filled from Windows' Get-NetAdapterStatistics (matched by adapter name).
/// </summary>
public sealed class NetworkModule(OsqueryRunner runner, SystemCommandRunner? commands = null, bool includeWifiAndIpConfig = false, DnsSpeedTest? dnsTest = null) : OsqueryAreaModuleBase(runner)
{
    public const string StatsScript =
        "$ErrorActionPreference='SilentlyContinue';" +
        "$s=@(Get-NetAdapterStatistics | ForEach-Object { [pscustomobject]@{Name=[string]$_.Name;" +
        "ipackets=[string]($_.ReceivedUnicastPackets+$_.ReceivedMulticastPackets+$_.ReceivedBroadcastPackets);" +
        "opackets=[string]($_.SentUnicastPackets+$_.SentMulticastPackets+$_.SentBroadcastPackets);" +
        "ierrors=[string]$_.ReceivedPacketErrors;oerrors=[string]$_.OutboundPacketErrors;" +
        "idrops=[string]$_.ReceivedDiscardedPackets;odrops=[string]$_.OutboundDiscardedPackets } });" +
        "ConvertTo-Json -InputObject $s -Compress";

    public const string ModuleName = "Network";
    public const string Sql = "SELECT * FROM interface_details;";
    public override string Name => ModuleName;
    public override string DisplayName => includeWifiAndIpConfig ? "Network & Wi-Fi" : "Network adapters";
    protected override string FailedMessage => "Couldn't read network adapter details on this PC.";

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        var total = includeWifiAndIpConfig && commands is not null ? 3 : 1;
        progress.ReportStep(1, total, "Checking network adapters…");
        var q = await QueryAsync(Sql, ct).ConfigureAwait(false);
        if (!q.Success) return AreaReport.Failed(FailedMessage);
        var adapters = q.Rows!.Select(NetworkAdapter.FromRow).ToList();
        if (adapters.Count > 0 && !adapters.Any(a => a.HasCounters) && commands is not null)
        {
            Log($"{Name}: interface_details reported no traffic/error counters; using Get-NetAdapterStatistics");
            var pr = await commands.RunAsync(SystemCommandRunner.PowerShell,
                ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", StatsScript], ct).ConfigureAwait(false);
            if (pr is { ExitCode: 0 })
            {
                try { adapters = MergeStatistics(adapters, OsqueryJson.ParseRows(pr.StdOut)); }
                catch (FormatException ex) { Log($"{Name}: adapter statistics unreadable: {ex.Message}"); }
            }
        }
        var baseReport = Build(adapters);
        if (!includeWifiAndIpConfig || commands is null)
            return baseReport;

        progress.ReportStep(2, total, "Checking Wi-Fi signal and IP configuration…");
        var wlanTask = commands.RunAsync(WifiConfigModule.Netsh, ["wlan", "show", "interfaces"], ct);
        var ipTask = commands.RunAsync(SystemCommandRunner.PowerShell, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", WifiConfigModule.IpConfigScript], ct);
        await Task.WhenAll(wlanTask, ipTask).ConfigureAwait(false);
        var wlanRes = await wlanTask.ConfigureAwait(false);
        var ipRes = await ipTask.ConfigureAwait(false);
        var wlanOk = wlanRes is { ExitCode: 0 };
        var ipOk = ipRes is { ExitCode: 0 };
        if (!wlanOk && !ipOk)
            return baseReport;

        var ipSnap = ipOk ? WifiConfigModule.ParseIpSnapshot(ipRes!.StdOut) : null;
        // Measure the current DNS against Cloudflare/Google (a few seconds; nothing changed) so switching is only suggested when it's faster.
        DnsComparison? dns = null;
        if (ipSnap is not null && WifiConfigModule.PrimaryAdapter(ipSnap) is { } primary && !DnsSpeedTest.IsPublicAlready(primary.Dns))
        {
            progress.ReportStep(3, total, "Comparing DNS speed…");
            try { dns = await (dnsTest ?? new DnsSpeedTest(log: commands.Log)).CompareAsync(primary.Dns, ct).ConfigureAwait(false); }
            catch (Exception ex) when (ex is not OperationCanceledException) { commands.Log?.Invoke($"DNS speed test failed: {ex.Message}"); }
        }
        var wifiRep = WifiConfigModule.Build(
            wlanOk ? WifiConfigModule.ParseNetshWlan(wlanRes!.StdOut) : null,
            wlanOk,
            ipSnap, dns);
        var combinedCards = wifiRep.Cards.Concat(baseReport.Cards).ToList();
        var combinedStatus = AreaReport.Worst(combinedCards.Select(c => c.ErrorText is not null ? AreaLevel.Warning : c.Level));
        var combinedSummary = $"{wifiRep.Summary} · {baseReport.Summary}";
        return new(combinedCards, combinedSummary, combinedStatus);
    }

    /// <summary>Fills blank counters from Get-NetAdapterStatistics rows (matched on adapter name = connection name).</summary>
    public static List<NetworkAdapter> MergeStatistics(IReadOnlyList<NetworkAdapter> adapters, IReadOnlyList<IReadOnlyDictionary<string, string>> stats)
    {
        var byName = stats.GroupBy(r => r.Str("Name"), StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
        return adapters.Select(a => a.HasCounters || !byName.TryGetValue(a.Name, out var r) ? a : a with
        {
            PacketsIn = r.Long("ipackets"), PacketsOut = r.Long("opackets"), ErrorsIn = r.Long("ierrors"), ErrorsOut = r.Long("oerrors"),
            DropsIn = r.Long("idrops"), DropsOut = r.Long("odrops"),
        }).ToList();
    }

    private static string N(long? v) => v?.ToString("N0", CultureInfo.InvariantCulture) ?? "Not reported";

    public static AreaReport Build(IReadOnlyList<NetworkAdapter> all)
    {
        // Prefer real network cards; hide virtual/loopback adapters when Windows tells us which are physical.
        var list = all.Any(a => a.Physical == true) ? all.Where(a => a.Physical == true).ToList() : all.Where(a => a.Mac.Length > 0 || a.IsConnected).ToList();
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
