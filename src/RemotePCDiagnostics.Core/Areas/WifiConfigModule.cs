using System.Text.Json;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// Wi-Fi signal/band/link rate (via <c>netsh wlan show interfaces</c>) and active IP, gateway, DNS, and proxy configuration.
/// Complements the Network module (which checks adapter packet error/drop counters).
/// </summary>
public sealed class WifiConfigModule(SystemCommandRunner commands) : AreaModuleBase(commands.Log)
{
    public const string ModuleName = ModuleSlugs.WifiConfig;
    public const int WeakSignalPercent = 50;

    public static string IpConfigScript => Scripts.PowerShellScripts.Get("IpConfig");

    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.WifiConfig;
    public override string DisplayName => "Wi-Fi & network config";
    protected override string FailedMessage => "Couldn't read Wi-Fi and IP network configuration on this PC.";

    public static string Netsh => SystemCommandRunner.SystemTool("netsh.exe");
    public const double SlowLinkRateMbps = 150;

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        progress?.Report("Checking Wi-Fi signal and IP configuration…");
        var wlanRes = await commands.RunAsync(Netsh, ["wlan", "show", "interfaces"], ct).ConfigureAwait(false);
        var wlanOk = wlanRes is { ExitCode: 0 };
        var wifi = wlanOk ? ParseNetshWlan(wlanRes!.StdOut) : null;
        var bandContext = wifi is { Connected: true } && Is24Ghz(wifi)
            ? await ReadBandContextAsync(commands, wifi.Ssid, ct).ConfigureAwait(false)
            : null;
        IpConfigSnapshot? ipSnap = null;
        if (commands.IsScripted)
        {
            var ipRes = await commands.RunPowerShellAsync(IpConfigScript, ct).ConfigureAwait(false);
            if (ipRes is { ExitCode: 0 })
                ipSnap = ParseIpSnapshot(ipRes.StdOut);
        }
        else
        {
            ipSnap = Platform.NetworkInfoReader.ReadIpConfig();
        }

        if (!wlanOk && (ipSnap is null || ipSnap.Adapters.Count == 0))
            return AreaReport.Failed(FailedMessage);

        return Build(wifi, wlanOk, ipSnap, bandContext: bandContext);
    }

    /// <summary>Reads <c>netsh wlan show networks mode=bssid</c> and <c>netsh wlan show drivers</c> when connected on 2.4 GHz.</summary>
    public static async Task<WifiBandContext?> ReadBandContextAsync(SystemCommandRunner commands, string connectedSsid, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(connectedSsid)) return null;
        var networksTask = commands.RunAsync(Netsh, ["wlan", "show", "networks", "mode=bssid"], ct);
        var driversTask = commands.RunAsync(Netsh, ["wlan", "show", "drivers"], ct);
        await Task.WhenAll(networksTask, driversTask).ConfigureAwait(false);
        var networksRes = await networksTask.ConfigureAwait(false);
        var driversRes = await driversTask.ConfigureAwait(false);
        if (networksRes is not { ExitCode: 0 } || driversRes is not { ExitCode: 0 })
            return null;
        return new WifiBandContext(
            HasSameSsidOn5Or6Ghz(networksRes.StdOut, connectedSsid),
            ParseNetshDriversSupports5Or6Ghz(driversRes.StdOut));
    }

    /// <param name="connectedAdapters">
    /// How many adapters Windows' adapter list (osquery) reports as connected, when known. An empty IP snapshot alongside a
    /// connected adapter means the IP read failed or caught the stack mid-change, not that the PC is offline.
    /// </param>
    public static AreaReport Build(WifiInterfaceInfo? wifi, bool wlanOk, IpConfigSnapshot? ipSnap, DnsComparison? dns = null, int connectedAdapters = 0, WifiBandContext? bandContext = null)
    {
        if (!wlanOk && ipSnap is null)
            return AreaReport.Failed("Couldn't read Wi-Fi and IP network configuration on this PC.");

        var cards = new List<AreaCard> { BuildWifiCard(wifi, wlanOk, bandContext), BuildIpDnsCard(ipSnap, dns, connectedAdapters) };
        string summary;
        if (wifi is { Connected: true })
        {
            var sigText = wifi.SignalPercent is int s ? $"{s}% signal" : "connected";
            var bandText = !string.IsNullOrWhiteSpace(wifi.Band) ? $", {wifi.Band}" : "";
            summary = $"Wi-Fi: {wifi.Ssid} ({sigText}{bandText})";
        }
        else if (ipSnap is { Adapters.Count: > 0 })
        {
            var primary = ipSnap.Adapters.FirstOrDefault(a => !string.IsNullOrWhiteSpace(a.Gateway)) ?? ipSnap.Adapters[0];
            summary = $"Active: {primary.Alias} ({(string.IsNullOrWhiteSpace(primary.IPv4) ? "no IPv4" : primary.IPv4)})";
        }
        else if (connectedAdapters > 0)
        {
            summary = "Connected, but IP details couldn't be read";
        }
        else
        {
            summary = "No active network connection";
        }

        if (ipSnap is { ProxyEnabled: true })
            summary += $" · Proxy on ({(string.IsNullOrWhiteSpace(ipSnap.ProxyServer) ? "configured" : ipSnap.ProxyServer)})";

        var status = AreaReport.Worst(cards.Select(c => c.ErrorText is not null ? AreaLevel.Warning : c.Level));
        return new(cards, summary, status);
    }

    private static AreaCard BuildWifiCard(WifiInterfaceInfo? wifi, bool wlanOk, WifiBandContext? bandContext)
    {
        if (!wlanOk && wifi is null)
            return AreaCard.Failed("wifi", "Wi-Fi signal & link", "Couldn't read wireless adapter status.");

        if (wifi is null)
        {
            return new("wifi", "Wi-Fi signal & link", AreaLevel.Neutral, "No Wi-Fi adapter",
                "Desktop / Ethernet-only or wireless service stopped",
                ["Detail", "Value"],
                [new(AreaLevel.Neutral, ["Wi-Fi status", "No wireless interface reported by Windows"])]);
        }

        if (!wifi.Connected)
        {
            return new("wifi", "Wi-Fi signal & link", AreaLevel.Neutral, "Not connected",
                string.IsNullOrWhiteSpace(wifi.Description) ? wifi.Name : wifi.Description,
                ["Detail", "Value"],
                [
                    new(AreaLevel.Neutral, ["Adapter", string.IsNullOrWhiteSpace(wifi.Description) ? wifi.Name : wifi.Description]),
                    new(AreaLevel.Neutral, ["State", string.IsNullOrWhiteSpace(wifi.State) ? "Disconnected" : wifi.State]),
                ]);
        }

        var weak = wifi.SignalPercent is int sig && sig < WeakSignalPercent;
        var warn24Ghz = Is24Ghz(wifi) && bandContext is { SameSsidOn5Or6Ghz: true, AdapterSupports5Or6Ghz: true };
        var level = weak || warn24Ghz ? AreaLevel.Warning : AreaLevel.Ok;
        var headline = wifi.SignalPercent is int s
            ? $"{wifi.Ssid} · {s}% signal"
            : wifi.Ssid;
        var metaParts = new List<string>();
        if (!string.IsNullOrWhiteSpace(wifi.Band)) metaParts.Add(wifi.Band);
        if (!string.IsNullOrWhiteSpace(wifi.RadioType)) metaParts.Add(wifi.RadioType);
        var linkSpeed = FormatLinkSpeed(wifi.ReceiveRateMbps, wifi.TransmitRateMbps);
        if (linkSpeed != "—") metaParts.Add(linkSpeed);

        var rows = new List<AreaRow>
        {
            new(AreaLevel.Ok, ["SSID (network)", string.IsNullOrWhiteSpace(wifi.Ssid) ? "—" : wifi.Ssid]),
            new(weak ? AreaLevel.Warning : AreaLevel.Ok, ["Signal quality", wifi.SignalPercent is int sp ? $"{sp}%" : "—"]),
            new(warn24Ghz ? AreaLevel.Warning : AreaLevel.Neutral, ["Band / channel", FormatBandChannel(wifi.Band, wifi.Channel)]),
            new(AreaLevel.Neutral, ["Wi-Fi standard", string.IsNullOrWhiteSpace(wifi.RadioType) ? "—" : wifi.RadioType]),
            new(AreaLevel.Neutral, ["Link speed (RX / TX)", linkSpeed]),
        };

        var minLinkMbps = MinLinkRateMbps(wifi.ReceiveRateMbps, wifi.TransmitRateMbps);
        if (minLinkMbps is > 0 and < SlowLinkRateMbps)
            rows.Add(new(AreaLevel.Neutral, ["Link speed note", "Wi-Fi link is slower than most internet plans"]));

        rows.Add(new(AreaLevel.Neutral, ["Adapter", string.IsNullOrWhiteSpace(wifi.Description) ? wifi.Name : wifi.Description]));

        var notes = new List<string>();
        if (weak) notes.Add("Signal below 50% can cause packet drops, high latency, and reduced throughput.");
        if (warn24Ghz) notes.Add("Connected on 2.4 GHz, but the same network is visible on 5 or 6 GHz and this Wi-Fi adapter supports it.");

        return new("wifi", "Wi-Fi signal & link", level, headline, string.Join(" · ", metaParts),
            ["Detail", "Value"], rows,
            Note: notes.Count > 0 ? string.Join(" ", notes) : null);
    }

    /// <summary>The adapter whose DNS gets compared: the one with a gateway (normally the one in use).</summary>
    public static ActiveAdapterIp? PrimaryAdapter(IpConfigSnapshot snap) =>
        snap.Adapters.FirstOrDefault(a => !string.IsNullOrWhiteSpace(a.Gateway)) ?? snap.Adapters.FirstOrDefault();

    private static AreaCard BuildIpDnsCard(IpConfigSnapshot? snap, DnsComparison? dns, int connectedAdapters)
    {
        if (snap is null)
            return AreaCard.Failed("ipdns", "IP, gateway, DNS & proxy", "Couldn't read IP and DNS configuration.");

        var primary = snap.Adapters.FirstOrDefault(a => !string.IsNullOrWhiteSpace(a.Gateway))
                      ?? snap.Adapters.FirstOrDefault();

        var hasGateway = snap.Adapters.Any(a => !string.IsNullOrWhiteSpace(a.Gateway));
        var hasDns = snap.Adapters.Any(a => !string.IsNullOrWhiteSpace(a.Dns));
        var vpnAdapter = snap.Adapters.FirstOrDefault(IsLikelyVpn);

        var level = AreaLevel.Ok;
        string headline;
        string meta;
        if (snap.Adapters.Count == 0 && connectedAdapters > 0)
        {
            level = AreaLevel.Warning;
            headline = "IP details couldn't be read";
            meta = $"Windows reports {Plural(connectedAdapters, "adapter")} connected but returned no IP configuration. Run the check again.";
        }
        else if (snap.Adapters.Count == 0)
        {
            level = AreaLevel.Warning;
            headline = "No active IP configuration";
            meta = "No network adapters are currently up";
        }
        else if (!hasGateway)
        {
            level = AreaLevel.Warning;
            headline = "No default gateway";
            meta = primary is not null ? $"{primary.Alias} ({primary.IPv4})" : "";
        }
        else if (!hasDns)
        {
            level = AreaLevel.Warning;
            headline = "No DNS servers configured";
            meta = primary is not null ? $"Gateway {primary.Gateway}" : "";
        }
        else if (snap.ProxyEnabled)
        {
            level = AreaLevel.Warning;
            headline = "System proxy enabled";
            meta = string.IsNullOrWhiteSpace(snap.ProxyServer) ? "Proxy active in Windows settings" : $"Proxy: {snap.ProxyServer}";
        }
        else
        {
            headline = primary is not null ? $"{primary.IPv4} ({primary.Alias})" : $"{Plural(snap.Adapters.Count, "active adapter")}";
            meta = primary is not null ? $"Gateway {primary.Gateway} · DNS {DnsSpeedTest.FormatServers(primary.Dns)}" : "";
        }

        var rows = new List<AreaRow>();
        foreach (var a in snap.Adapters)
        {
            var adpLevel = string.IsNullOrWhiteSpace(a.IPv4) ? AreaLevel.Warning : AreaLevel.Neutral;
            rows.Add(new(adpLevel, [
                a.Alias,
                string.IsNullOrWhiteSpace(a.IPv4) ? "None" : a.IPv4,
                string.IsNullOrWhiteSpace(a.Gateway) ? "None" : a.Gateway,
                string.IsNullOrWhiteSpace(a.Dns) ? "None" : DnsSpeedTest.FormatServers(a.Dns),
                a.Description
            ],
            Key: a.Alias,
            Actions: a.Alias.Length > 0 && DnsActions(a, a == primary ? dns : null) is { Count: > 0 } acts ? acts : null));
        }

        var cardActions = new List<AreaAction>();
        if (snap.ProxyEnabled)
            cardActions.Add(new(RemediationKind.DisableSystemProxy, "Disable system proxy"));
        cardActions.Add(new(RemediationKind.FlushDnsAndRenewIp, "Flush DNS & renew IP"));

        var noteParts = new List<string>();
        if (dns is not null) noteParts.Add(dns.Text);
        if (snap.ProxyEnabled)
            noteParts.Add($"System HTTP proxy is ON ({(string.IsNullOrWhiteSpace(snap.ProxyServer) ? "no address set" : snap.ProxyServer)}) — can block internet access if unexpected.");
        if (vpnAdapter is not null)
            noteParts.Add($"VPN / tunnel adapter active: {vpnAdapter.Alias} ({vpnAdapter.Description}).");

        return new("ipdns", "IP, gateway, DNS & proxy", level, headline, meta,
            ["Interface", "IPv4 address", "Gateway", "DNS servers", "Adapter"], rows,
            EmptyText: snap.Adapters.Count == 0 ? (connectedAdapters > 0 ? "Windows returned no IP configuration for the connected adapter." : "No active IP configurations.") : null,
            Note: noteParts.Count > 0 ? string.Join(" ", noteParts) : null,
            Actions: cardActions);
    }

    /// <summary>
    /// Public DNS is only offered when it measured clearly faster than this adapter's current DNS (never untested, and not when the
    /// adapter already uses it); "Reset DNS to automatic" only when the DNS servers were set by hand.
    /// </summary>
    private static IReadOnlyList<AreaAction> DnsActions(ActiveAdapterIp a, DnsComparison? dns)
    {
        var list = new List<AreaAction>();
        if (dns is { PublicIsFaster: true } d && !DnsSpeedTest.IsPublicAlready(a.Dns))
            list.Add(new(RemediationKind.SetPublicDns, $"Use Cloudflare & Google DNS ({d.Best!.MedianMs:0} ms vs {d.Current.MedianMs:0} ms now)", a.Alias, a.Alias));
        // Only useful when DNS was set by hand; on automatic there's nothing to reset.
        if (a.DnsManual == true && !DnsSpeedTest.IsPublicAlready(a.Dns))
            list.Add(new(RemediationKind.ResetDhcpDns, "Reset DNS to automatic", a.Alias, a.Alias,
                CurrentSetting: string.IsNullOrWhiteSpace(a.Dns) ? null : DnsSpeedTest.FormatServers(a.Dns)));
        return list;
    }

    private static bool IsLikelyVpn(ActiveAdapterIp a)
    {
        var text = $"{a.Alias} {a.Description}";
        return text.Contains("VPN", StringComparison.OrdinalIgnoreCase)
            || text.Contains("WireGuard", StringComparison.OrdinalIgnoreCase)
            || text.Contains("Tailscale", StringComparison.OrdinalIgnoreCase)
            || text.Contains("ZeroTier", StringComparison.OrdinalIgnoreCase)
            || text.Contains("TAP-Windows", StringComparison.OrdinalIgnoreCase)
            || text.Contains("Wintun", StringComparison.OrdinalIgnoreCase)
            || text.Contains("Cisco AnyConnect", StringComparison.OrdinalIgnoreCase)
            || text.Contains("GlobalProtect", StringComparison.OrdinalIgnoreCase)
            || text.Contains("Fortinet", StringComparison.OrdinalIgnoreCase);
    }

    private static string FormatBandChannel(string band, string channel) =>
        (string.IsNullOrWhiteSpace(band), string.IsNullOrWhiteSpace(channel)) switch
        {
            (false, false) => $"{band} (ch {channel})",
            (false, true) => band,
            (true, false) => $"Channel {channel}",
            _ => "—",
        };

    private static string FormatLinkSpeed(string rx, string tx) =>
        (string.IsNullOrWhiteSpace(rx), string.IsNullOrWhiteSpace(tx)) switch
        {
            (false, false) => $"{rx} / {tx} Mbps",
            (false, true) => $"{rx} Mbps",
            (true, false) => $"{tx} Mbps",
            _ => "—",
        };

    public static WifiInterfaceInfo? ParseNetshWlan(string stdout)
    {
        if (string.IsNullOrWhiteSpace(stdout))
            return null;
        if (stdout.Contains("There is no wireless interface on the system", StringComparison.OrdinalIgnoreCase)
            || stdout.Contains("The Wireless AutoConfig Service (wlansvc) is not running", StringComparison.OrdinalIgnoreCase))
            return null;

        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rawLine in stdout.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var colon = rawLine.IndexOf(':');
            if (colon <= 0) continue;
            var key = rawLine[..colon].Trim();
            var val = rawLine[(colon + 1)..].Trim();
            if (key.Length > 0 && !fields.ContainsKey(key))
                fields[key] = val;
        }

        if (!fields.TryGetValue("Name", out var name) && !fields.TryGetValue("State", out _))
            return null;

        fields.TryGetValue("Description", out var desc);
        fields.TryGetValue("State", out var state);
        fields.TryGetValue("SSID", out var ssid);
        fields.TryGetValue("Band", out var band);
        fields.TryGetValue("Channel", out var channel);
        fields.TryGetValue("Radio type", out var radio);
        fields.TryGetValue("Receive rate (Mbps)", out var rx);
        fields.TryGetValue("Transmit rate (Mbps)", out var tx);

        int? sigPct = null;
        if (fields.TryGetValue("Signal", out var sigRaw))
        {
            sigPct = ParsePercent(sigRaw);
        }

        var connected = string.Equals(state, "connected", StringComparison.OrdinalIgnoreCase);
        return new(
            name ?? "Wi-Fi",
            desc ?? "",
            state ?? "",
            connected,
            ssid ?? "",
            band ?? "",
            channel ?? "",
            radio ?? "",
            rx ?? "",
            tx ?? "",
            sigPct);
    }

    /// <summary>Reads the number in front of '%' ("69%", "69 %"); null when there is none.</summary>
    public static int? ParsePercent(string text)
    {
        var pct = text.IndexOf('%');
        if (pct < 0) return null;
        var digits = text[..pct].TrimEnd();
        var start = digits.Length;
        while (start > 0 && char.IsAsciiDigit(digits[start - 1])) start--;
        return start < digits.Length && int.TryParse(digits[start..], out var parsed) ? Math.Clamp(parsed, 0, 100) : null;
    }

    public static IpConfigSnapshot ParseIpSnapshot(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
            return new([], false, "");
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return new([], false, "");

            var adapters = new List<ActiveAdapterIp>();
            if (root.TryGetProperty("Adapters", out var adpEl))
            {
                if (adpEl.ValueKind == JsonValueKind.Array)
                {
                    foreach (var el in adpEl.EnumerateArray())
                        adapters.Add(ReadAdapter(el));
                }
                else if (adpEl.ValueKind == JsonValueKind.Object)
                {
                    adapters.Add(ReadAdapter(adpEl));
                }
            }

            var proxyEnabled = root.TryGetProperty("ProxyEnabled", out var pe) && pe.ValueKind == JsonValueKind.True;
            var proxyServer = root.TryGetProperty("ProxyServer", out var ps) && ps.ValueKind == JsonValueKind.String
                ? ps.GetString() ?? ""
                : "";

            return new(adapters, proxyEnabled, proxyServer);
        }
        catch
        {
            return new([], false, "");
        }
    }

    private static ActiveAdapterIp ReadAdapter(JsonElement el) => new(
        Str(el, "Alias"),
        Str(el, "Description"),
        Str(el, "IPv4"),
        Str(el, "Gateway"),
        Str(el, "Dns"),
        el.TryGetProperty("DnsManual", out _) ? Str(el, "DnsManual").Length > 0 : null);

    public static bool Is24Ghz(WifiInterfaceInfo? wifi)
    {
        if (wifi is null || !wifi.Connected) return false;
        if (!string.IsNullOrWhiteSpace(wifi.Band))
        {
            if (wifi.Band.Contains("2.4", StringComparison.OrdinalIgnoreCase)) return true;
            if (wifi.Band.Contains("5 GHz", StringComparison.OrdinalIgnoreCase) || wifi.Band.Contains("6 GHz", StringComparison.OrdinalIgnoreCase))
                return false;
        }
        return int.TryParse(wifi.Channel?.Trim(), out var ch) && ch is >= 1 and <= 14;
    }

    public static double? ParseLinkRateMbps(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        return double.TryParse(text.Trim(), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var v) && v > 0
            ? v
            : null;
    }

    public static double? MinLinkRateMbps(string? rx, string? tx)
    {
        var r = ParseLinkRateMbps(rx);
        var t = ParseLinkRateMbps(tx);
        return (r, t) switch
        {
            (not null, not null) => Math.Min(r.Value, t.Value),
            (not null, null) => r.Value,
            (null, not null) => t.Value,
            _ => null,
        };
    }

    /// <summary>Parses <c>netsh wlan show networks mode=bssid</c> by line and key to see if <paramref name="connectedSsid"/> is also visible on 5 or 6 GHz.</summary>
    public static bool HasSameSsidOn5Or6Ghz(string? stdout, string? connectedSsid)
    {
        if (string.IsNullOrWhiteSpace(stdout) || string.IsNullOrWhiteSpace(connectedSsid))
            return false;

        var target = connectedSsid.Trim();
        var matchingSsid = false;
        foreach (var rawLine in stdout.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var colon = rawLine.IndexOf(':');
            if (colon <= 0) continue;
            var key = rawLine[..colon].Trim();
            var val = rawLine[(colon + 1)..].Trim();

            if (key.StartsWith("SSID ", StringComparison.OrdinalIgnoreCase))
            {
                matchingSsid = string.Equals(val, target, StringComparison.Ordinal);
                continue;
            }
            if (!matchingSsid) continue;

            if (string.Equals(key, "Band", StringComparison.OrdinalIgnoreCase))
            {
                if (val.Contains("5 GHz", StringComparison.OrdinalIgnoreCase) || val.Contains("6 GHz", StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            else if (string.Equals(key, "Channel", StringComparison.OrdinalIgnoreCase))
            {
                if (int.TryParse(val, out var ch) && ch >= 32)
                    return true;
            }
            else if (string.Equals(key, "Radio type", StringComparison.OrdinalIgnoreCase))
            {
                if (val.Contains("802.11a", StringComparison.OrdinalIgnoreCase) && !val.Contains("802.11ax", StringComparison.OrdinalIgnoreCase))
                    return true;
                if (val.Contains("802.11ac", StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }
        return false;
    }

    /// <summary>Parses <c>netsh wlan show drivers</c> by line and key to check whether the adapter supports 5 or 6 GHz radio types.</summary>
    public static bool ParseNetshDriversSupports5Or6Ghz(string? stdout)
    {
        if (string.IsNullOrWhiteSpace(stdout)) return false;
        foreach (var rawLine in stdout.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var colon = rawLine.IndexOf(':');
            if (colon <= 0) continue;
            var key = rawLine[..colon].Trim();
            if (!string.Equals(key, "Radio types supported", StringComparison.OrdinalIgnoreCase)) continue;
            var val = rawLine[(colon + 1)..].Trim();
            foreach (var token in val.Split([' ', '\t', ','], StringSplitOptions.RemoveEmptyEntries))
            {
                if (string.Equals(token, "802.11a", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(token, "802.11ac", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(token, "802.11ax", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(token, "802.11be", StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }
        return false;
    }

    private static string Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString()?.Trim() ?? "" : "";
}

public sealed record WifiBandContext(bool SameSsidOn5Or6Ghz, bool AdapterSupports5Or6Ghz);

public sealed record WifiInterfaceInfo(
    string Name,
    string Description,
    string State,
    bool Connected,
    string Ssid,
    string Band,
    string Channel,
    string RadioType,
    string ReceiveRateMbps,
    string TransmitRateMbps,
    int? SignalPercent);

/// <param name="DnsManual">True = DNS servers entered by hand; false = automatic (DHCP); null = unknown.</param>
public sealed record ActiveAdapterIp(string Alias, string Description, string IPv4, string Gateway, string Dns, bool? DnsManual = null);

public sealed record IpConfigSnapshot(IReadOnlyList<ActiveAdapterIp> Adapters, bool ProxyEnabled, string ProxyServer);
