using System.Globalization;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>What the person picked on the Wi-Fi connect pane. <see cref="Password"/> is cleared once the test has used it.</summary>
public sealed class WifiConnectSettings
{
    /// <summary>The adapter (interface GUID); null uses the first adapter whose radio is on.</summary>
    public string? InterfaceId { get; set; }
    /// <summary>The network to join; null reconnects to the network the PC is on now.</summary>
    public string? Ssid { get; set; }
    /// <summary>Typed for a network without a saved profile. Never saved, logged or exported.</summary>
    public string? Password { get; set; }
}

public enum WifiConnectOutcome
{
    /// <summary>Connected, got an address, and under 10 % of pings were lost.</summary>
    Passed,
    /// <summary>Passed, but the signal averaged weaker than −75 dBm.</summary>
    WeakSignal,
    /// <summary>The router answered, but more than 10 % of pings to the internet were lost: the internet connection, not the Wi-Fi.</summary>
    InternetLoss,
    /// <summary>More than 10 % of pings over the Wi-Fi link were lost.</summary>
    HighLoss,
    /// <summary>Windows didn't connect in time: a wrong password, or a weak or faulty radio.</summary>
    CouldNotConnect,
    /// <summary>Windows refused the connect request outright.</summary>
    ConnectRefused,
    /// <summary>Connected to the access point, but no IP address or router came.</summary>
    NoAddress,
    /// <summary>No Wi-Fi adapter with its radio on.</summary>
    NoAdapter,
    /// <summary>No network was picked and the PC isn't on one.</summary>
    NoNetwork,
    /// <summary>The network has no saved profile and needs a password, or is an enterprise network (needs a saved profile).</summary>
    NeedsPassword,
}

public enum WifiRestoreOutcome
{
    /// <summary>The PC ended on the network it was on before (or the test's network was that one).</summary>
    Restored,
    /// <summary>The PC wasn't on Wi-Fi before, so it was disconnected again.</summary>
    Disconnected,
    /// <summary>Reconnecting to the original network didn't finish in time; Windows keeps trying by itself.</summary>
    Failed,
    /// <summary>Nothing was changed (the test stopped before connecting).</summary>
    NotNeeded,
}

/// <param name="Sent">Pings sent.</param>
/// <param name="Received">Replies.</param>
public sealed record PingStats(string Target, int Sent, int Received, double? AverageMs, double? MaxMs)
{
    public double LossPercent => Sent == 0 ? 0 : Math.Round(100.0 * (Sent - Received) / Sent, 1);
    public static PingStats From(string target, IReadOnlyList<long?> replies)
    {
        var ok = replies.Where(r => r is not null).Select(r => (double)r!.Value).ToList();
        return new(target, replies.Count, ok.Count, ok.Count > 0 ? Math.Round(ok.Average(), 1) : null, ok.Count > 0 ? ok.Max() : null);
    }
}

/// <param name="Mode">"Saved profile", "Typed password" or "Open network".</param>
/// <param name="ConnectSeconds">How long Windows took to connect.</param>
/// <param name="OriginalSsid">The network the PC was on before the test (null: none).</param>
/// <param name="ErrorCode">The WLAN API error when Windows refused the connect request.</param>
public sealed record WifiConnectReport(WifiConnectOutcome Outcome, string? Ssid, string? Mode, string? Adapter, double? ConnectSeconds,
    string? Gateway, PingStats? GatewayPings, PingStats? InternetPings, int? RssiMin, int? RssiMax, double? RssiAverage,
    WifiRestoreOutcome Restore, string? OriginalSsid, uint? ErrorCode = null) : IRunEnd
{
    public RunEnd RunEnd => Outcome is WifiConnectOutcome.NoAdapter or WifiConnectOutcome.NoNetwork or WifiConnectOutcome.NeedsPassword
        ? RunEnd.CouldNotRun : RunEnd.Finished;
}

/// <summary>
/// The Wi-Fi connect test's rules (DiagnosticTest #289; the module is RemotePCDiagnostics.Modules.WifiConnect): join a saved network, or one
/// the person types the password for (a temporary profile, so the password is never saved), get an address, then ping the router and the
/// internet every second for <see cref="PingTime"/>, sampling the signal. Afterwards the PC goes back to the network it was on.
/// <para>It disconnects the Wi-Fi first, so a remote session over Wi-Fi drops for about a minute. The test runs in the app and doesn't
/// need the session, and a marker file (<see cref="WifiRestoreMarker"/>) lets the app restore the original network even after a crash.</para>
/// <para>Failed: can't connect, no address, more than <see cref="MaxLossPercent"/> % of pings over the Wi-Fi lost. Warning: the signal
/// averaged weaker than <see cref="WifiRadio.WeakRssiDbm"/>, or only the internet lost pings.</para>
/// </summary>
public static class WifiConnect
{
    public static readonly TimeSpan DisconnectWindow = TimeSpan.FromSeconds(8);
    public static readonly TimeSpan ConnectWindow = TimeSpan.FromSeconds(25);
    public static readonly TimeSpan AddressWindow = TimeSpan.FromSeconds(15);
    public static readonly TimeSpan PingTime = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan PingInterval = TimeSpan.FromSeconds(1);
    public static readonly TimeSpan PingTimeout = TimeSpan.FromSeconds(1);
    public static readonly TimeSpan RestoreWindow = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan Poll = TimeSpan.FromMilliseconds(500);
    public const double MaxLossPercent = 10;
    public const string InternetHost = "1.1.1.1";

    public static (DiagnosticStatus Status, string Message) Outcome(WifiConnectReport r)
    {
        var ssid = r.Ssid ?? "the network";
        var restore = r.Restore switch
        {
            WifiRestoreOutcome.Failed => $" Reconnecting to {r.OriginalSsid ?? "the original network"} didn't finish in time; Windows keeps trying by itself.",
            WifiRestoreOutcome.Restored when r.OriginalSsid is { } o && o != r.Ssid => $" Back on {o}.",
            _ => "",
        };
        var pings = r.GatewayPings is { } g ? $" {g.LossPercent:0.#}% of router pings lost" + (g.AverageMs is { } a ? $", {a:0} ms average" : "") : "";
        return r.Outcome switch
        {
            WifiConnectOutcome.Passed => (DiagnosticStatus.Ok, $"Passed: connected to {ssid} in {r.ConnectSeconds:0.#} s.{pings}{Signal(r)}.{restore}"),
            WifiConnectOutcome.WeakSignal => (DiagnosticStatus.Warning,
                $"Connected to {ssid}, but the signal averaged {r.RssiAverage:0} dBm, weaker than {WifiRadio.WeakRssiDbm} dBm. Move closer to the router; if other devices get a strong signal here, the antenna may be loose or damaged.{restore}"),
            WifiConnectOutcome.InternetLoss => (DiagnosticStatus.Warning,
                $"Connected to {ssid} and the router answered, but {r.InternetPings!.LossPercent:0.#}% of internet pings were lost. The Wi-Fi works; the internet connection or the router's uplink is dropping.{restore}"),
            WifiConnectOutcome.HighLoss => (DiagnosticStatus.Error,
                $"Connected to {ssid}, but {LinkPings(r)!.LossPercent:0.#}% of pings over the Wi-Fi were lost (more than {MaxLossPercent:0}%).{Signal(r)}. If the signal is strong, the Wi-Fi card or its driver may be faulty.{restore}"),
            WifiConnectOutcome.CouldNotConnect => (DiagnosticStatus.Error,
                $"Couldn't connect to {ssid} within {ConnectWindow.TotalSeconds:0} seconds. Check the password; if it is right and other devices connect, the Wi-Fi card or its driver may be faulty.{restore}"),
            WifiConnectOutcome.ConnectRefused => (DiagnosticStatus.Error, $"Windows refused to connect to {ssid} (WLAN error {r.ErrorCode}).{restore}"),
            WifiConnectOutcome.NoAddress => (DiagnosticStatus.Error,
                $"Connected to {ssid}, but no IP address or router came within {AddressWindow.TotalSeconds:0} seconds. The router's DHCP may be full or blocking this PC.{restore}"),
            WifiConnectOutcome.NoAdapter => (DiagnosticStatus.Warning, "Not supported: no Wi-Fi adapter with its radio on. Run the Network check to see why."),
            WifiConnectOutcome.NoNetwork => (DiagnosticStatus.Warning, "Pick a network to connect to: this PC isn't on Wi-Fi now."),
            _ => (DiagnosticStatus.Warning, $"{ssid} has no saved profile on this PC. Type its password to test it (enterprise networks need a saved profile)."),
        };
    }

    private static string Signal(WifiConnectReport r) => r.RssiMin is { } lo && r.RssiMax is { } hi ? $", signal {lo} to {hi} dBm" : "";

    /// <summary>The pings that judge the Wi-Fi link: the router's, unless it never answers ICMP while the internet does.</summary>
    public static PingStats? LinkPings(WifiConnectReport r) =>
        r.GatewayPings is { Received: 0 } && r.InternetPings is { Received: > 0 } ? r.InternetPings : r.GatewayPings ?? r.InternetPings;

    /// <summary>The outcome once connected and pinged.</summary>
    public static WifiConnectOutcome Judge(PingStats? gateway, PingStats? internet, double? rssiAverage)
    {
        var link = gateway is { Received: 0 } && internet is { Received: > 0 } ? internet : gateway ?? internet;
        if (link is null || link.LossPercent > MaxLossPercent) return WifiConnectOutcome.HighLoss;
        if (rssiAverage is { } a && a < WifiRadio.WeakRssiDbm) return WifiConnectOutcome.WeakSignal;
        if (internet is { } i && link != internet && i.LossPercent > MaxLossPercent) return WifiConnectOutcome.InternetLoss;
        return WifiConnectOutcome.Passed;
    }

    public static DiagnosticResult ToResult(WifiConnectReport r)
    {
        var (status, msg) = Outcome(r);
        return new DiagnosticResult<WifiConnectReport>(ModuleSlugs.WifiConnect, status, msg, DateTimeOffset.Now, r);
    }

    /// <summary>
    /// A WLAN profile for a personal or open network, built as XML (so any SSID or password is escaped), for a temporary connection.
    /// Returns null for security the test can't join with a password alone (enterprise, WEP).
    /// </summary>
    public static string? ProfileXml(string ssid, string security, string? password)
    {
        (string Auth, string Cipher)? sec = security switch
        {
            WifiRadio.Open => ("open", "none"),
            WifiRadio.Owe => ("OWE", "AES"),
            "WPA-Personal" => ("WPAPSK", "TKIP"),
            "WPA2-Personal" => ("WPA2PSK", "AES"),
            "WPA3-Personal" => ("WPA3SAE", "AES"),
            _ => null,
        };
        if (sec is not { } s) return null;
        var needsKey = s.Auth is not ("open" or "OWE");
        if (needsKey && !IsValidPassphrase(password)) return null;
        XNamespace ns = "http://www.microsoft.com/networking/WLAN/profile/v1";
        var auth = new XElement(ns + "authEncryption", new XElement(ns + "authentication", s.Auth), new XElement(ns + "encryption", s.Cipher),
            new XElement(ns + "useOneX", "false"));
        if (s.Auth == "WPA3SAE") auth.Add(new XElement(XNamespace.Get("http://www.microsoft.com/networking/WLAN/profile/v4") + "transitionMode", "true"));
        var keys = new XElement(ns + "security", auth);
        if (needsKey)
            keys.Add(new XElement(ns + "sharedKey", new XElement(ns + "keyType", "passPhrase"), new XElement(ns + "protected", "false"),
                new XElement(ns + "keyMaterial", password)));
        var doc = new XElement(ns + "WLANProfile",
            new XElement(ns + "name", ssid),
            new XElement(ns + "SSIDConfig", new XElement(ns + "SSID", new XElement(ns + "hex", Convert.ToHexString(Encoding.UTF8.GetBytes(ssid))), new XElement(ns + "name", ssid))),
            new XElement(ns + "connectionType", "ESS"),
            new XElement(ns + "connectionMode", "manual"),
            new XElement(ns + "MSM", keys));
        return doc.ToString(SaveOptions.DisableFormatting);
    }

    /// <summary>A WPA passphrase: 8 to 63 printable ASCII characters, or 64 hex digits.</summary>
    public static bool IsValidPassphrase(string? p) =>
        p is { Length: >= 8 and <= 63 } && p.All(c => c is >= ' ' and <= '~')
        || p is { Length: 64 } && p.All(char.IsAsciiHexDigit);

    /// <summary>
    /// Whether this Wi-Fi adapter carries the PC's only route out (no other adapter that is up has a gateway), so disconnecting it drops a
    /// remote session for the length of the test.
    /// </summary>
    public static bool IsOnlyRoute(string interfaceId)
    {
        if (!Guid.TryParse(interfaceId, out var id)) return false;
        try
        {
            var routed = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType is not (NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel))
                .Where(n => n.GetIPProperties().GatewayAddresses.Any(g => g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork))
                .Select(n => Guid.TryParse(n.Id, out var g) ? g : Guid.Empty).ToList();
            return routed.Count == 0 || routed.All(g => g == id);
        }
        catch (NetworkInformationException) { return true; }
    }

    /// <summary>One ping: the round trip in ms, or null when it timed out or failed.</summary>
    public static async Task<long?> PingAsync(string host, TimeSpan timeout, CancellationToken ct)
    {
        try
        {
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(System.Net.IPAddress.Parse(host), timeout, cancellationToken: ct).ConfigureAwait(false);
            return reply.Status == IPStatus.Success ? reply.RoundtripTime : null;
        }
        catch (PingException) { return null; }
        catch (System.Net.Sockets.SocketException) { return null; }
    }

    public static string Format(double? v) => v?.ToString("0.#", CultureInfo.InvariantCulture) ?? "";
}

/// <summary>
/// Where the connect test notes the network to go back to before it changes anything, and clears it once the PC is back. When the app
/// stopped mid-test (a crash, or the PC was shut down), the next start finds it and reconnects. Holds the adapter and profile name only.
/// </summary>
public sealed class WifiRestoreMarker(string? path = null)
{
    public static string DefaultPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RemotePCDiagnostics", "wifi-connect-restore.json");
    public static readonly TimeSpan MaxAge = TimeSpan.FromDays(1);
    private string FilePath => path ?? DefaultPath;

    /// <param name="Profile">The profile to reconnect to; null when the adapter was disconnected before the test.</param>
    public sealed record Entry(string InterfaceId, string? Profile, string? Ssid, DateTimeOffset SavedAt);

    public void Save(Entry e)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        File.WriteAllText(FilePath, JsonSerializer.Serialize(e));
    }

    public Entry? Load()
    {
        try { return File.Exists(FilePath) ? JsonSerializer.Deserialize<Entry>(File.ReadAllText(FilePath)) : null; }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException) { return null; }
    }

    public void Clear()
    {
        try { File.Delete(FilePath); } catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }
}

/// <summary>What the Interactive tests page uses of the Wi-Fi connect module (which lives in its own module assembly).</summary>
public interface IWifiConnectModule
{
    WifiConnectSettings Settings { get; }
    /// <summary>A fresh scan for the pane's network list.</summary>
    Task<WifiRadioReading> ScanAsync(CancellationToken ct);
    /// <summary>Whether starting the test would drop a remote session (the Wi-Fi adapter is the PC's only way out).</summary>
    bool DropsSession(string interfaceId);
}
