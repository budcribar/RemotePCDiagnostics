using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>One Wi-Fi network a scan saw: its strongest access point's signal, band and channel, and whether Windows has a saved profile for it.</summary>
/// <param name="Ssid">The network's name; empty for a hidden network.</param>
/// <param name="Security">"Open", "WPA2-Personal", "WPA3-Personal", "WPA2-Enterprise" and so on.</param>
/// <param name="Rssi">The strongest access point's received signal, in dBm (null when the driver didn't say).</param>
/// <param name="SignalPercent">Windows' signal quality, 0 to 100.</param>
/// <param name="FrequencyMhz">The strongest access point's centre frequency.</param>
/// <param name="ProfileName">The saved profile's name when <paramref name="HasProfile"/>.</param>
/// <param name="AccessPoints">How many access points (BSSIDs) broadcast it.</param>
/// <param name="Bands">Every band any of its access points is on ("2.4 GHz", "5 GHz", "6 GHz").</param>
public sealed record WifiNetworkSeen(string Ssid, string Security, int? Rssi, int? SignalPercent, int? FrequencyMhz, bool HasProfile, bool Connected,
    string? ProfileName = null, int AccessPoints = 1, IReadOnlyList<string>? Bands = null)
{
    [JsonIgnore] public string Band => WifiRadio.BandOf(FrequencyMhz);
    [JsonIgnore] public int? Channel => WifiRadio.ChannelOf(FrequencyMhz);
    /// <summary>A WPA/WPA2/WPA3-Personal or open network, which the connect test can join with a typed password (enterprise ones need a saved profile).</summary>
    [JsonIgnore] public bool CanTypePassword => Security is WifiRadio.Open or WifiRadio.Owe || Security.EndsWith("-Personal", StringComparison.Ordinal);
}

/// <summary>One Wi-Fi adapter as the WLAN service sees it.</summary>
/// <param name="Id">The interface GUID ("{…}"), the same as the network adapter's.</param>
/// <param name="State">"Connected", "Disconnected", "Associating" and so on.</param>
/// <param name="SoftwareOn">The radio's software switch (Windows' Wi-Fi toggle); null when not reported.</param>
/// <param name="HardwareOn">The radio's hardware switch (a key or slider on the PC, or the BIOS); null when not reported.</param>
/// <param name="Rssi">The connected access point's signal in dBm.</param>
/// <param name="Networks">What the scan saw; empty when the radio is off or the scan was refused.</param>
/// <param name="Supports5Ghz">Whether the adapter can use 5 or 6 GHz (from its supported PHY types); null when not known.</param>
/// <param name="ScanRefused">Windows refused to list networks (Windows 11 24H2 and later: location access for desktop apps is off).</param>
public sealed record WifiRadioInterface(string Id, string Description, string State, bool? SoftwareOn, bool? HardwareOn,
    string? ConnectedSsid, string? ConnectedProfile, int? Rssi, IReadOnlyList<WifiNetworkSeen> Networks, bool? Supports5Ghz = null,
    bool ScanRefused = false, int? ConnectedFrequencyMhz = null)
{
    [JsonIgnore] public bool RadioOn => SoftwareOn != false && HardwareOn != false;
    [JsonIgnore] public bool IsConnected => State == "Connected";
}

/// <summary>
/// What the Wi-Fi radio check reads: every Wi-Fi adapter's radio switches, connection and a fresh scan, plus airplane mode. Kept as one JSON
/// value so a recording can hold it (<see cref="Recording.RecordedCall.WifiKind"/>).
/// </summary>
/// <param name="ServiceRunning">False when the WLAN AutoConfig service isn't running (nothing else can be read then).</param>
/// <param name="AirplaneMode">Airplane mode, from the radio manager's registry value; null when not known.</param>
/// <param name="Error">Why the WLAN service couldn't be read, when it couldn't.</param>
public sealed record WifiRadioReading(IReadOnlyList<WifiRadioInterface> Interfaces, bool ServiceRunning = true, bool? AirplaneMode = null, string? Error = null)
{
    private static readonly JsonSerializerOptions Json = new() { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };

    public static WifiRadioReading Unavailable(string error) => new([], Error: error);

    public string ToJson() => JsonSerializer.Serialize(this, Json);

    public static WifiRadioReading FromJson(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return Unavailable("No Wi-Fi reading.");
        try { return JsonSerializer.Deserialize<WifiRadioReading>(json, Json) ?? Unavailable("No Wi-Fi reading."); }
        catch (JsonException ex) { return Unavailable($"The Wi-Fi reading couldn't be read: {ex.Message}"); }
    }

    /// <summary>The reading with network names replaced by "Network 1", "Network 2"… (the same name gets the same number), for recordings.</summary>
    public WifiRadioReading Scrubbed()
    {
        var names = new Dictionary<string, string>(StringComparer.Ordinal);
        string? Name(string? ssid) => string.IsNullOrEmpty(ssid) ? ssid
            : names.TryGetValue(ssid, out var n) ? n : names[ssid] = $"Network {names.Count + 1}";
        return this with
        {
            Interfaces = Interfaces.Select(i => i with
            {
                ConnectedSsid = Name(i.ConnectedSsid),
                ConnectedProfile = Name(i.ConnectedProfile),
                Networks = i.Networks.Select(n => n with { Ssid = Name(n.Ssid) ?? "", ProfileName = Name(n.ProfileName) }).ToList(),
            }).ToList(),
        };
    }
}

/// <summary>Reads <see cref="WifiRadioReading"/>: the WLAN API in the app (no administrator rights needed), or a recording.</summary>
public interface IWifiRadioSource
{
    /// <param name="scan">Ask each radio for a fresh scan first (a few seconds; the connection stays up).</param>
    Task<WifiRadioReading> ReadAsync(bool scan, CancellationToken ct);
}

/// <summary>A Wi-Fi card's driver problem that Device Manager shows (from Win32_PnPEntity through the Agent).</summary>
public sealed record WifiDeviceProblem(string Name, int Code);

/// <summary>
/// The Wi-Fi radio and scan cards of the Network check (DiagnosticTest #289): the adapter is there and its radio on (not by the hardware
/// switch, not airplane mode), Device Manager shows no driver problem, scanning is allowed (location access on Windows 11 24H2+), and a
/// fresh scan sees networks. The strongest network's RSSI is reported so the shop can compare PCs.
/// <para>Failed: the radio is off by its hardware switch, the card has a driver problem, or the radio is on but sees no network.
/// Warning: airplane mode or the Wi-Fi toggle is off, the strongest network is weaker than <see cref="WeakRssiDbm"/>, the adapter is
/// 2.4 GHz only, or Windows refused the scan.</para>
/// </summary>
public static class WifiRadio
{
    public const int WeakRssiDbm = -75;
    public const string Open = "Open";
    public const string Owe = "Enhanced Open";
    public const string RadioCardId = "wifi-radio";
    public const string ScanCardId = "wifi-scan";
    /// <summary>The Interactive tests page with the Wi-Fi connect test showing.</summary>
    public const string ConnectTestPath = "interactive?test=wifi";
    public const int MaxNetworksShown = 40;

    public static string BandOf(int? mhz) => mhz switch { null or <= 0 => "", < 3000 => "2.4 GHz", < 5925 => "5 GHz", _ => "6 GHz" };

    /// <summary>The channel number for a centre frequency (2.4 GHz: 1–14, 5 GHz: 32–177, 6 GHz: 1–233).</summary>
    public static int? ChannelOf(int? mhz) => mhz switch
    {
        null or <= 0 => null,
        2484 => 14,
        < 3000 => (mhz.Value - 2407) / 5,
        < 5925 => (mhz.Value - 5000) / 5,
        _ => (mhz.Value - 5950) / 5,
    };

    /// <summary>Windows' signal quality (0–100) from dBm: −100 dBm is 0, −50 dBm and stronger is 100, linear in between.</summary>
    public static int QualityOf(int dbm) => Math.Clamp(2 * (dbm + 100), 0, 100);

    public static string FormatRssi(int? dbm) => dbm is { } d ? $"{d.ToString(CultureInfo.InvariantCulture)} dBm" : "Not reported";

    /// <summary>Both cards, or none when no Wi-Fi adapter exists and none has a driver problem (a desktop on Ethernet).</summary>
    public static IReadOnlyList<AreaCard> BuildCards(WifiRadioReading reading, IReadOnlyList<WifiDeviceProblem>? problems = null)
    {
        problems ??= [];
        if (reading.Error is { } error && reading.Interfaces.Count == 0 && reading.ServiceRunning)
            return [AreaCard.Failed(RadioCardId, "Wi-Fi radio", $"Couldn't read the Wi-Fi radio: {error}")];
        if (reading.Interfaces.Count == 0 && problems.Count == 0 && reading.ServiceRunning)
            return [];
        return [BuildRadioCard(reading, problems), BuildScanCard(reading)];
    }

    public static AreaCard BuildRadioCard(WifiRadioReading reading, IReadOnlyList<WifiDeviceProblem> problems)
    {
        var rows = new List<AreaRow>();
        foreach (var p in problems)
            rows.Add(new(AreaLevel.Error, ["Driver problem", $"{p.Name}: Device Manager code {p.Code} ({DeviceProblemText(p.Code)})"]));
        if (!reading.ServiceRunning)
            rows.Add(new(AreaLevel.Error, ["WLAN AutoConfig service", "Not running, so Windows can't use Wi-Fi"]));
        if (reading.AirplaneMode is { } airplane)
            rows.Add(new(airplane ? AreaLevel.Warning : AreaLevel.Ok, ["Airplane mode", airplane ? "On" : "Off"]));
        foreach (var i in reading.Interfaces)
        {
            var name = reading.Interfaces.Count > 1 ? $"{i.Description}: " : "";
            if (reading.Interfaces.Count == 1) rows.Add(new(AreaLevel.Neutral, ["Adapter", i.Description]));
            rows.Add(new(i.HardwareOn == false ? AreaLevel.Error : i.HardwareOn == true ? AreaLevel.Ok : AreaLevel.Neutral,
                [$"{name}Hardware radio switch", i.HardwareOn switch { true => "On", false => "Off (a key, slider or the BIOS turned the radio off)", null => "Not reported" }]));
            rows.Add(new(i.SoftwareOn == false ? AreaLevel.Warning : i.SoftwareOn == true ? AreaLevel.Ok : AreaLevel.Neutral,
                [$"{name}Wi-Fi in Windows", i.SoftwareOn switch { true => "On", false => "Off (turned off in Windows settings or quick settings)", null => "Not reported" }]));
            rows.Add(new(AreaLevel.Neutral, [$"{name}State", i.IsConnected && i.ConnectedSsid is { Length: > 0 } ssid ? $"Connected to {ssid}" : i.State]));
            if (i.IsConnected)
                rows.Add(new(RssiLevel(i.Rssi), [$"{name}Connected signal", i.Rssi is { } r ? $"{FormatRssi(r)} ({QualityOf(r)}%)" : "Not reported"]));
            if (i.Supports5Ghz is { } dual)
                rows.Add(new(dual ? AreaLevel.Ok : AreaLevel.Warning, [$"{name}Bands", dual ? "2.4 GHz and 5 GHz" : "2.4 GHz only"]));
            if (i.ScanRefused)
                rows.Add(new(AreaLevel.Warning, [$"{name}Scanning", "Refused by Windows: turn on Location services and \"Let desktop apps access your location\""]));
        }

        var (level, headline) = RadioVerdict(reading, problems);
        var note = reading.Interfaces.Any(i => i.ScanRefused)
            ? "Windows 11 24H2 and later only let apps list Wi-Fi networks when location access is on for desktop apps (Settings > Privacy & security > Location)."
            : null;
        return new(RadioCardId, "Wi-Fi radio", level, headline,
            reading.Interfaces.Count == 0 ? "No Wi-Fi adapter is working" : string.Join(" · ", reading.Interfaces.Select(i => i.Description)),
            ["Detail", "Value"], rows, Note: note)
        { OpenPage = reading.Interfaces.Any(i => i.RadioOn) ? new AreaPageLink(ConnectTestPath, "Test connecting") : null };
    }

    private static (AreaLevel, string) RadioVerdict(WifiRadioReading reading, IReadOnlyList<WifiDeviceProblem> problems)
    {
        if (problems.Count > 0) return (AreaLevel.Error, $"Wi-Fi card has a driver problem (code {problems[0].Code})");
        if (!reading.ServiceRunning) return (AreaLevel.Error, "The WLAN AutoConfig service isn't running");
        if (reading.Interfaces.Count == 0) return (AreaLevel.Error, "No Wi-Fi adapter is working");
        if (reading.Interfaces.All(i => i.HardwareOn == false)) return (AreaLevel.Error, "Wi-Fi radio is off by its hardware switch");
        if (reading.AirplaneMode == true) return (AreaLevel.Warning, "Airplane mode is on");
        if (reading.Interfaces.All(i => i.SoftwareOn == false)) return (AreaLevel.Warning, "Wi-Fi is turned off in Windows");
        if (reading.Interfaces.Any(i => i.Supports5Ghz == false) && reading.Interfaces.All(i => i.Supports5Ghz != true))
            return (AreaLevel.Warning, "Radio on · 2.4 GHz only");
        return (AreaLevel.Ok, "Radio on");
    }

    public static AreaCard BuildScanCard(WifiRadioReading reading)
    {
        var on = reading.Interfaces.Where(i => i.RadioOn).ToList();
        var networks = on.SelectMany(i => i.Networks)
            .GroupBy(n => n.Ssid, StringComparer.Ordinal)
            .Select(g => g.OrderByDescending(n => n.Rssi ?? int.MinValue).First())
            .OrderByDescending(n => n.Connected).ThenByDescending(n => n.Rssi ?? (n.SignalPercent is { } p ? p / 2 - 100 : int.MinValue))
            .ToList();
        var rows = networks.Take(MaxNetworksShown).Select(n => new AreaRow(n.Connected ? AreaLevel.Ok : RssiLevel(n.Rssi) == AreaLevel.Warning ? AreaLevel.Warning : AreaLevel.Neutral,
        [
            n.Ssid.Length > 0 ? n.Ssid : "(hidden network)",
            n.Security,
            string.Join(", ", n.Bands is { Count: > 0 } b ? b : [n.Band]),
            n.Channel?.ToString(CultureInfo.InvariantCulture) ?? "",
            FormatRssi(n.Rssi),
            n.Connected ? "Connected" : n.HasProfile ? "Saved" : "",
        ], [null, null, null, n.Channel?.ToString("D3", CultureInfo.InvariantCulture), n.Rssi is { } r ? (r + 200).ToString("D3", CultureInfo.InvariantCulture) : null, null],
            Key: n.Ssid)).ToList();

        var strongest = networks.Where(n => n.Rssi is not null).Select(n => n.Rssi).Max();
        AreaLevel level; string headline; string? empty = null;
        if (on.Count == 0)
        {
            level = AreaLevel.Neutral;
            headline = reading.Interfaces.Count == 0 ? "Not scanned: no working Wi-Fi adapter" : "Not scanned: the radio is off";
            empty = "Turn the Wi-Fi radio on to scan for networks.";
        }
        else if (on.All(i => i.ScanRefused))
        {
            level = AreaLevel.Warning;
            headline = "Windows refused the scan (location access is off)";
            empty = "Turn on location access for desktop apps, then run the check again.";
        }
        else if (networks.Count == 0)
        {
            level = AreaLevel.Error;
            headline = "No networks found";
            empty = "The radio is on but saw no Wi-Fi network. If other devices nearby see networks, the Wi-Fi card or its antenna may be faulty.";
        }
        else
        {
            level = strongest is { } s && s < WeakRssiDbm ? AreaLevel.Warning : AreaLevel.Ok;
            headline = $"{AreaModuleBase.Plural(networks.Count, "network")} found" + (strongest is { } st ? $" · strongest {FormatRssi(st)}" : "");
        }

        var meta = strongest is { } strong && strong < WeakRssiDbm
            ? $"The strongest network is weaker than {WeakRssiDbm} dBm: move closer to the router, or the antenna may be loose or damaged"
            : "Fresh scan · strongest access point per network";
        return new(ScanCardId, "Wi-Fi networks nearby", level, headline, meta,
            ["Network", "Security", "Band", "Channel", "Signal", "Status"], rows, EmptyText: empty,
            Note: networks.Count > MaxNetworksShown ? $"The {MaxNetworksShown} strongest of {networks.Count} networks are shown." : "Signal is the strongest access point's RSSI. Above −67 dBm is good, below −75 dBm is weak.",
            PreserveRowOrder: true);
    }

    /// <summary>The strongest RSSI the scan saw (the number Admin compares across the shop's PCs), or null.</summary>
    public static int? StrongestRssi(WifiRadioReading reading) =>
        reading.Interfaces.Where(i => i.RadioOn).SelectMany(i => i.Networks).Where(n => n.Rssi is not null).Select(n => n.Rssi).Max();

    private static AreaLevel RssiLevel(int? dbm) => dbm is { } d && d < WeakRssiDbm ? AreaLevel.Warning : AreaLevel.Neutral;

    /// <summary>Device Manager's problem codes that a Wi-Fi card shows most.</summary>
    public static string DeviceProblemText(int code) => code switch
    {
        10 => "the device can't start",
        12 => "not enough free resources",
        18 or 28 => "the driver isn't installed",
        19 => "registry information is damaged",
        22 => "the device is disabled",
        31 => "the driver didn't load",
        39 => "the driver is missing or corrupted",
        43 => "the device reported a problem and Windows stopped it",
        45 => "the device isn't connected",
        52 => "the driver's signature can't be verified",
        _ => "see Device Manager",
    };

    /// <summary>The WLAN API's default authentication and cipher algorithms as a name (DOT11_AUTH_ALGORITHM, DOT11_CIPHER_ALGORITHM).</summary>
    public static string SecurityName(int auth, int cipher, bool securityEnabled) => auth switch
    {
        1 => securityEnabled || cipher is 1 or 5 ? "WEP" : Open,
        2 => "WEP",
        3 => "WPA-Enterprise",
        4 => "WPA-Personal",
        6 => "WPA2-Enterprise",
        7 => "WPA2-Personal",
        8 or 11 => "WPA3-Enterprise",
        9 => "WPA3-Personal",
        10 => Owe,
        _ => securityEnabled ? "Secured" : Open,
    };
}
