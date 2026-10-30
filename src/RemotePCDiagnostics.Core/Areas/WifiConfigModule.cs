using System.Text.Json;
using System.Text.RegularExpressions;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// Wi-Fi signal/band/link rate (via <c>netsh wlan show interfaces</c>) and active IP, gateway, DNS, and proxy configuration.
/// Complements <see cref="NetworkModule"/> (which checks adapter packet error/drop counters).
/// </summary>
public sealed class WifiConfigModule(SystemCommandRunner commands) : AreaModuleBase(commands.Log)
{
    public const string ModuleName = "WifiConfig";
    public const int WeakSignalPercent = 50;

    public const string IpConfigScript =
        "$ErrorActionPreference='SilentlyContinue'; " +
        "$cfg = @(Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq 'Up' } | ForEach-Object { " +
        "[pscustomobject]@{ " +
        "Alias = [string]$_.InterfaceAlias; " +
        "Description = [string]$_.InterfaceDescription; " +
        "IPv4 = [string]($_.IPv4Address | Select-Object -First 1 -ExpandProperty IPAddress); " +
        "Gateway = [string]($_.IPv4DefaultGateway | Select-Object -First 1 -ExpandProperty NextHop); " +
        "Dns = [string](($_.DnsServer | Where-Object AddressFamily -eq 2 | Select-Object -ExpandProperty ServerAddresses) -join ', ') " +
        "} }); " +
        "$p = Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -ErrorAction SilentlyContinue; " +
        "$proxyOn = ($null -ne $p -and $p.ProxyEnable -eq 1); " +
        "$proxySrv = if ($proxyOn) { [string]$p.ProxyServer } else { '' }; " +
        "[pscustomobject]@{ Adapters = $cfg; ProxyEnabled = $proxyOn; ProxyServer = $proxySrv } | ConvertTo-Json -Compress -Depth 4";

    public override string Name => ModuleName;
    public override string DisplayName => "Wi-Fi & network config";
    protected override string FailedMessage => "Couldn't read Wi-Fi and IP network configuration on this PC.";

    public static string Netsh => SystemCommandRunner.SystemTool("netsh.exe");

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        progress?.Report("Checking Wi-Fi signal and IP configuration…");
        var wlanTask = commands.RunAsync(Netsh, ["wlan", "show", "interfaces"], ct);
        var ipTask = commands.RunAsync(SystemCommandRunner.PowerShell, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", IpConfigScript], ct);
        await Task.WhenAll(wlanTask, ipTask).ConfigureAwait(false);

        var wlanRes = await wlanTask.ConfigureAwait(false);
        var ipRes = await ipTask.ConfigureAwait(false);

        var wlanOk = wlanRes is { ExitCode: 0 };
        var ipOk = ipRes is { ExitCode: 0 };
        if (!wlanOk && !ipOk)
            return AreaReport.Failed(FailedMessage);

        var wifi = wlanOk ? ParseNetshWlan(wlanRes!.StdOut) : null;
        var ipSnap = ipOk ? ParseIpSnapshot(ipRes!.StdOut) : null;
        return Build(wifi, wlanOk, ipSnap);
    }

    public static AreaReport Build(WifiInterfaceInfo? wifi, bool wlanOk, IpConfigSnapshot? ipSnap)
    {
        if (!wlanOk && ipSnap is null)
            return AreaReport.Failed("Couldn't read Wi-Fi and IP network configuration on this PC.");

        var cards = new List<AreaCard> { BuildWifiCard(wifi, wlanOk), BuildIpDnsCard(ipSnap) };
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
        else
        {
            summary = "No active network connection";
        }

        if (ipSnap is { ProxyEnabled: true })
            summary += $" · Proxy on ({(string.IsNullOrWhiteSpace(ipSnap.ProxyServer) ? "configured" : ipSnap.ProxyServer)})";

        var status = AreaReport.Worst(cards.Select(c => c.ErrorText is not null ? AreaLevel.Warning : c.Level));
        return new(cards, summary, status);
    }

    private static AreaCard BuildWifiCard(WifiInterfaceInfo? wifi, bool wlanOk)
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
        var level = weak ? AreaLevel.Warning : AreaLevel.Ok;
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
            new(level, ["Signal quality", wifi.SignalPercent is int sp ? $"{sp}%" : "—"]),
            new(AreaLevel.Neutral, ["Band / channel", FormatBandChannel(wifi.Band, wifi.Channel)]),
            new(AreaLevel.Neutral, ["Wi-Fi standard", string.IsNullOrWhiteSpace(wifi.RadioType) ? "—" : wifi.RadioType]),
            new(AreaLevel.Neutral, ["Link speed (RX / TX)", linkSpeed]),
            new(AreaLevel.Neutral, ["Adapter", string.IsNullOrWhiteSpace(wifi.Description) ? wifi.Name : wifi.Description]),
        };

        return new("wifi", "Wi-Fi signal & link", level, headline, string.Join(" · ", metaParts),
            ["Detail", "Value"], rows,
            Note: weak ? "Signal below 50% can cause packet drops, high latency, and reduced throughput." : null);
    }

    private static AreaCard BuildIpDnsCard(IpConfigSnapshot? snap)
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
        if (snap.Adapters.Count == 0)
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
            meta = primary is not null ? $"Gateway {primary.Gateway} · DNS {primary.Dns}" : "";
        }

        var rows = new List<AreaRow>();
        foreach (var a in snap.Adapters)
        {
            var adpLevel = string.IsNullOrWhiteSpace(a.IPv4) ? AreaLevel.Warning : AreaLevel.Neutral;
            rows.Add(new(adpLevel, [
                a.Alias,
                string.IsNullOrWhiteSpace(a.IPv4) ? "None" : a.IPv4,
                string.IsNullOrWhiteSpace(a.Gateway) ? "None" : a.Gateway,
                string.IsNullOrWhiteSpace(a.Dns) ? "None" : a.Dns,
                a.Description
            ]));
        }

        var noteParts = new List<string>();
        if (snap.ProxyEnabled)
            noteParts.Add($"System HTTP proxy is ON ({(string.IsNullOrWhiteSpace(snap.ProxyServer) ? "no address set" : snap.ProxyServer)}) — can block internet access if unexpected.");
        if (vpnAdapter is not null)
            noteParts.Add($"VPN / tunnel adapter active: {vpnAdapter.Alias} ({vpnAdapter.Description}).");

        return new("ipdns", "IP, gateway, DNS & proxy", level, headline, meta,
            ["Interface", "IPv4 address", "Gateway", "DNS servers", "Adapter"], rows,
            EmptyText: snap.Adapters.Count == 0 ? "No active IP configurations." : null,
            Note: noteParts.Count > 0 ? string.Join(" ", noteParts) : null);
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
            var m = Regex.Match(sigRaw, @"(\d+)\s*%");
            if (m.Success && int.TryParse(m.Groups[1].Value, out var parsed))
                sigPct = Math.Clamp(parsed, 0, 100);
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
        Str(el, "Dns"));

    private static string Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString()?.Trim() ?? "" : "";
}

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

public sealed record ActiveAdapterIp(string Alias, string Description, string IPv4, string Gateway, string Dns);

public sealed record IpConfigSnapshot(IReadOnlyList<ActiveAdapterIp> Adapters, bool ProxyEnabled, string ProxyServer);
