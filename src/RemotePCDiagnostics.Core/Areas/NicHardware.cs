using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using RemotePCDiagnostics.Core.DataSources;

namespace RemotePCDiagnostics.Core.Areas;

// The Network check's adapter hardware card (DiagnosticTest #291): the burned-in hardware address, the card's Device Manager status and
// interrupt, the wired link's speed and duplex, and (live only) pings of the adapter's own address and its DHCP server. Everything here
// is read without administrator rights: WMI goes through the Agent when it is connected (the Store edition reads it as the user), and the
// pings are ordinary ICMP from the app.

/// <summary>What kind of link an adapter has (MSFT_NetAdapter NdisPhysicalMedium).</summary>
public enum NicMedium { Other, Ethernet, WiFi }

/// <summary>Why a hardware address can't be a card's own (a corrupt or blank EEPROM), or <see cref="None"/> when it can.</summary>
public enum MacProblem { None, Missing, AllZero, AllOnes, Multicast, Placeholder }

/// <summary>One physical network adapter as MSFT_NetAdapter (Get-NetAdapter) describes it.</summary>
/// <param name="PermanentAddress">The address burned into the card (its EEPROM or firmware), as Windows reads it at start.</param>
/// <param name="CurrentAddress">The address in use, which software can change (Wi-Fi random addresses, a "Network Address" override).</param>
/// <param name="Connected">MediaConnectState: true connected (cable in, or Wi-Fi associated), false disconnected, null unknown.</param>
/// <param name="FullDuplex">Null when Windows doesn't say (MediaDuplexState unknown).</param>
public sealed record NicAdapter(string Name, string Description, string PnpDeviceId, NicMedium Medium, string PermanentAddress, string CurrentAddress,
    bool? Connected, bool? FullDuplex, long? ReceiveBps, long? TransmitBps);

/// <summary>An adapter's "Speed &amp; Duplex" driver setting (the <c>*SpeedDuplex</c> keyword) and the values the driver offers.</summary>
/// <param name="Value">The setting's registry value: "0" is auto-negotiation, others force one speed (NDIS standard values).</param>
public sealed record NicSpeedSetting(string Adapter, string Value, string DisplayValue, IReadOnlyList<string> ValidValues, IReadOnlyList<string> ValidDisplayValues);

/// <summary>A network device as Device Manager has it: its problem code (0 = working) and the interrupts assigned to it.</summary>
public sealed record NicDevice(string DeviceId, string Name, int ProblemCode, IReadOnlyList<long> Interrupts);

/// <summary>What <see cref="INicHardwareSource"/> read. A null list wasn't read (that part of the card says so).</summary>
public sealed record NicHardwareSnapshot(IReadOnlyList<NicAdapter> Adapters, IReadOnlyList<NicSpeedSetting>? SpeedSettings, IReadOnlyList<NicDevice>? Devices,
    bool InterruptsRead);

/// <summary>Where the adapter hardware card reads from (WMI; recorded and replayed like the rest of the Network check).</summary>
public interface INicHardwareSource
{
    /// <summary>The physical adapters and what's known about their hardware; null when the adapters couldn't be read.</summary>
    Task<NicHardwareSnapshot?> ReadAsync(CancellationToken ct);
}

/// <summary>
/// The adapters' hardware from WMI: MSFT_NetAdapter (only hardware interfaces), their <c>*SpeedDuplex</c> setting
/// (MSFT_NetAdapterAdvancedPropertySettingData), the network devices' Device Manager problem codes (Win32_PnPEntity) and their interrupts
/// (Win32_PnPAllocatedResource, which links each device to its Win32_IRQResource).
/// </summary>
public sealed class WmiNicHardwareSource(IWmiSource wmi) : INicHardwareSource
{
    public const string AdaptersSql =
        "SELECT Name, InterfaceDescription, PnPDeviceID, NdisPhysicalMedium, PermanentAddress, MacAddress, MediaConnectState, MediaDuplexState, " +
        "ReceiveLinkSpeed, TransmitLinkSpeed FROM MSFT_NetAdapter WHERE HardwareInterface = TRUE";
    public const string SpeedDuplexSql =
        "SELECT Name, RegistryValue, DisplayValue, ValidRegistryValues, ValidDisplayValues FROM MSFT_NetAdapterAdvancedPropertySettingData " +
        "WHERE RegistryKeyword = '*SpeedDuplex'";
    public const string DevicesSql = "SELECT DeviceID, Name, ConfigManagerErrorCode FROM Win32_PnPEntity WHERE PNPClass = 'Net'";
    public const string ResourcesSql = "SELECT Antecedent, Dependent FROM Win32_PnPAllocatedResource";

    public async Task<NicHardwareSnapshot?> ReadAsync(CancellationToken ct)
    {
        var adaptersTask = wmi.QueryAsync(WmiNetworkSource.StandardCimv2, AdaptersSql, ct);
        var speedTask = wmi.QueryAsync(WmiNetworkSource.StandardCimv2, SpeedDuplexSql, ct);
        var devicesTask = wmi.QueryAsync(WmiHardwareInventorySource.Cimv2, DevicesSql, ct);
        var resourcesTask = wmi.QueryAsync(WmiHardwareInventorySource.Cimv2, ResourcesSql, ct);
        var adapters = await adaptersTask.ConfigureAwait(false);
        var speed = await speedTask.ConfigureAwait(false);
        var devices = await devicesTask.ConfigureAwait(false);
        var resources = await resourcesTask.ConfigureAwait(false);
        if (!adapters.Success) return null;

        var irqs = resources.Success ? Interrupts(resources.Rows!) : null;
        return new NicHardwareSnapshot(
            adapters.Rows!.Select(Adapter).ToList(),
            speed.Success ? speed.Rows!.Select(Speed).ToList() : null,
            devices.Success ? devices.Rows!.Select(d => new NicDevice(d.Str("DeviceID"), d.Str("Name"), (int)(d.Long("ConfigManagerErrorCode") ?? 0),
                irqs is not null && irqs.TryGetValue(d.Str("DeviceID"), out var list) ? list : [])).ToList() : null,
            irqs is { Count: > 0 });
    }

    public static NicAdapter Adapter(WmiRow r) => new(
        r.Str("Name"), r.Str("InterfaceDescription"), r.Str("PnPDeviceID"),
        r.Long("NdisPhysicalMedium") switch { 14 => NicMedium.Ethernet, 9 => NicMedium.WiFi, _ => NicMedium.Other },
        r.Str("PermanentAddress"), r.Str("MacAddress"),
        r.Long("MediaConnectState") switch { 1 => true, 2 => false, _ => null },
        r.Long("MediaDuplexState") switch { 2 => true, 1 => false, _ => null },
        NetworkAdapter.Positive(r.Long("ReceiveLinkSpeed")), NetworkAdapter.Positive(r.Long("TransmitLinkSpeed")));

    public static NicSpeedSetting Speed(WmiRow r) => new(r.Str("Name"), First(r, "RegistryValue"), r.Str("DisplayValue"), Strings(r, "ValidRegistryValues"),
        Strings(r, "ValidDisplayValues"));

    /// <summary>A property that is a list of text (one text is a list of one).</summary>
    private static IReadOnlyList<string> Strings(WmiRow r, string name)
    {
        if (!r.Values.TryGetValue(name, out var v)) return [];
        return v.ValueKind switch
        {
            JsonValueKind.Array => v.EnumerateArray().Select(e => e.ValueKind == JsonValueKind.String ? e.GetString()!.Trim() : e.GetRawText()).ToList(),
            JsonValueKind.String => [v.GetString()!.Trim()],
            JsonValueKind.Number => [v.GetRawText()],
            _ => [],
        };
    }

    private static string First(WmiRow r, string name) => Strings(r, name).FirstOrDefault() ?? "";

    /// <summary>
    /// The interrupts of each device, by device id, from Win32_PnPAllocatedResource's references:
    /// Antecedent <c>\\PC\root\cimv2:Win32_IRQResource.IRQNumber=16</c> and Dependent <c>\\PC\root\cimv2:Win32_PnPEntity.DeviceID="PCI\\VEN_8086&amp;..."</c>
    /// (backslashes doubled inside the quotes). Message-signalled interrupts show as large numbers; they count the same.
    /// </summary>
    public static Dictionary<string, IReadOnlyList<long>> Interrupts(IEnumerable<WmiRow> rows)
    {
        var map = new Dictionary<string, List<long>>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in rows)
        {
            if (IrqNumber(r.Str("Antecedent")) is not { } irq || DeviceIdOf(r.Str("Dependent")) is not { } id) continue;
            if (!map.TryGetValue(id, out var list)) map[id] = list = [];
            if (!list.Contains(irq)) list.Add(irq);
        }
        return map.ToDictionary(p => p.Key, p => (IReadOnlyList<long>)p.Value, StringComparer.OrdinalIgnoreCase);
    }

    private const string IrqKey = "Win32_IRQResource.IRQNumber=";
    private const string DeviceKey = "Win32_PnPEntity.DeviceID=\"";

    public static long? IrqNumber(string reference)
    {
        var at = reference.IndexOf(IrqKey, StringComparison.OrdinalIgnoreCase);
        if (at < 0) return null;
        var text = reference[(at + IrqKey.Length)..].Trim('"', ' ');
        return long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) ? n : null;
    }

    public static string? DeviceIdOf(string reference)
    {
        var at = reference.IndexOf(DeviceKey, StringComparison.OrdinalIgnoreCase);
        if (at < 0) return null;
        var rest = reference[(at + DeviceKey.Length)..];
        var end = rest.LastIndexOf('"');
        if (end >= 0) rest = rest[..end];
        return rest.Replace(@"\\", @"\", StringComparison.Ordinal);
    }
}

/// <summary>Hardware address rules: what a card's burned-in address must not be.</summary>
public static class NicAddress
{
    /// <summary>
    /// Addresses that show up when a card's EEPROM was blanked or never programmed, or a driver fell back to a built-in default (Realtek's
    /// 00:E0:4C:68:00:01 test address and the 00:00:00:00:00:01-style counters are the usual ones).
    /// </summary>
    public static readonly IReadOnlySet<string> Placeholders = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "000000000001", "000000000002", "001122334455", "010203040506", "123456789ABC", "00E04C680001", "AABBCCDDEEFF", "DEADBEEFCAFE",
    };

    /// <summary>The address as 12 hex digits with no separators ("" when it isn't six bytes of hex).</summary>
    public static string Normalize(string address)
    {
        var hex = new string(address.Where(c => c is not (':' or '-' or '.' or ' ')).ToArray()).ToUpperInvariant();
        return hex.Length == 12 && hex.All(Uri.IsHexDigit) ? hex : "";
    }

    /// <summary>"00:E0:4C:68:00:01" from any of Windows' spellings; the text as it was when it isn't an address.</summary>
    public static string Format(string address)
    {
        var hex = Normalize(address);
        return hex.Length == 0 ? address : string.Join(":", Enumerable.Range(0, 6).Select(i => hex.Substring(i * 2, 2)));
    }

    /// <summary>
    /// Why <paramref name="address"/> can't be a card's own. A placeholder from a recording (<c>&lt;serial:…&gt;</c>) was a real address
    /// there, so it passes. A locally administered address (second bit of the first byte) is fine: Windows uses one for random Wi-Fi
    /// addresses and a technician can set one by hand.
    /// </summary>
    public static MacProblem Check(string address)
    {
        var a = address.Trim();
        if (a.StartsWith('<')) return MacProblem.None;
        var hex = Normalize(a);
        if (hex.Length == 0) return MacProblem.Missing;
        if (hex.All(c => c == '0')) return MacProblem.AllZero;
        if (hex.All(c => c == 'F')) return MacProblem.AllOnes;
        if ((Convert.ToByte(hex[..2], 16) & 1) != 0) return MacProblem.Multicast;
        return Placeholders.Contains(hex) ? MacProblem.Placeholder : MacProblem.None;
    }

    public static string Describe(MacProblem p) => p switch
    {
        MacProblem.Missing => "No hardware address",
        MacProblem.AllZero => "All zeros",
        MacProblem.AllOnes => "All FF (blank memory)",
        MacProblem.Multicast => "A group (multicast) address, which a card can't own",
        MacProblem.Placeholder => "A default placeholder, not a real address",
        _ => "Valid",
    };
}

/// <summary>One ping series from <see cref="INicLinkProbe"/>: what was pinged, how many were sent and how many came back.</summary>
public sealed record NicPing(string Target, string Address, int Sent, int Replies);

/// <summary>Pings an adapter's own address and its DHCP server (or its router when the address was set by hand). Live only, never replayed.</summary>
public interface INicLinkProbe
{
    Task<IReadOnlyList<NicPing>> ProbeAsync(string adapterName, CancellationToken ct);
}

/// <summary>
/// <see cref="INicLinkProbe"/> with ordinary ICMP from the app (no administrator rights). The adapter's own address answering proves the
/// network stack sends and receives on it; the DHCP server answering proves frames cross the cable and come back.
/// </summary>
public sealed class NicLinkProbe(Func<IPAddress, TimeSpan, CancellationToken, Task<bool>>? ping = null) : INicLinkProbe
{
    public const int Count = 4;
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(1);
    private readonly Func<IPAddress, TimeSpan, CancellationToken, Task<bool>> _ping = ping ?? PingAsync;

    public async Task<IReadOnlyList<NicPing>> ProbeAsync(string adapterName, CancellationToken ct)
    {
        if (Addresses(adapterName) is not { } a) return [];
        var list = new List<NicPing>();
        if (a.Own is not null) list.Add(await SeriesAsync("Own address", a.Own, ct).ConfigureAwait(false));
        if (a.Dhcp is not null) list.Add(await SeriesAsync("DHCP server", a.Dhcp, ct).ConfigureAwait(false));
        else if (a.Gateway is not null) list.Add(await SeriesAsync("Router", a.Gateway, ct).ConfigureAwait(false));
        return list;
    }

    private async Task<NicPing> SeriesAsync(string target, IPAddress address, CancellationToken ct)
    {
        var replies = 0;
        for (var i = 0; i < Count; i++)
            if (await _ping(address, Timeout, ct).ConfigureAwait(false)) replies++;
        return new NicPing(target, address.ToString(), Count, replies);
    }

    /// <summary>The adapter's IPv4 address, DHCP server and router (null each when it has none), by its connection name ("Ethernet").</summary>
    public static (IPAddress? Own, IPAddress? Dhcp, IPAddress? Gateway)? Addresses(string adapterName)
    {
        try
        {
            var nic = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => n.Name.Equals(adapterName, StringComparison.OrdinalIgnoreCase));
            if (nic is null) return null;
            var p = nic.GetIPProperties();
            static bool V4(IPAddress x) => x.AddressFamily == AddressFamily.InterNetwork && !x.Equals(IPAddress.Any);
            var own = p.UnicastAddresses.Select(u => u.Address).FirstOrDefault(V4);
            var dhcp = OperatingSystem.IsWindows() ? p.DhcpServerAddresses.FirstOrDefault(V4) : null;
            var gateway = p.GatewayAddresses.Select(g => g.Address).FirstOrDefault(V4);
            return (own, dhcp, gateway);
        }
        catch (NetworkInformationException) { return null; }
    }

    private static async Task<bool> PingAsync(IPAddress address, TimeSpan timeout, CancellationToken ct)
    {
        try
        {
            using var p = new Ping();
            return (await p.SendPingAsync(address, timeout, cancellationToken: ct).ConfigureAwait(false)).Status == IPStatus.Success;
        }
        catch (PingException) { return false; }
        catch (SocketException) { return false; }
    }
}

/// <summary>The adapter hardware card ("nic-hardware") of the Network check.</summary>
public static class NicHardware
{
    public const string CardId = "nic-hardware";
    public const string EthernetTestPage = "interactive?test=ethernet";

    /// <summary>Device Manager problem codes that mean the card didn't get the resources (memory range, interrupt) it needs.</summary>
    public static readonly IReadOnlySet<int> ResourceCodes = new HashSet<int> { 12, 16, 29, 33, 34, 35, 36 };

    /// <summary>NDIS <c>*SpeedDuplex</c> values for 1 Gbps and faster (6 = 1 Gbps full, 7 = 10 Gbps, 8 = 20, 9 = 40, 10 = 50, 11 = 100 Gbps);
    /// some drivers add 2.5 and 5 Gbps under their own numbers, which their display text names.</summary>
    private static readonly IReadOnlySet<string> GigabitValues = new HashSet<string> { "6", "7", "8", "9", "10", "11" };

    public static string ProblemText(int code) => code switch
    {
        1 => "isn't configured correctly",
        3 => "driver may be corrupted, or Windows is low on memory",
        10 => "can't start",
        12 => "can't find enough free resources (a resource conflict)",
        14 => "needs a restart to work",
        16 => "Windows can't identify all the resources it uses",
        18 => "drivers need to be reinstalled",
        19 => "its registry settings are damaged",
        21 => "is being removed",
        22 => "is turned off in Device Manager",
        24 => "isn't present or isn't working",
        28 => "has no driver installed",
        29 => "is turned off because the firmware didn't give it the resources it needs",
        31 => "isn't working properly",
        32 => "its driver is turned off",
        33 => "Windows can't work out which resources it needs",
        34 => "Windows can't work out its settings",
        35 => "the firmware doesn't say how to configure its resources",
        36 => "asks for a PCI interrupt but is set up for an ISA one (an interrupt conflict)",
        37 => "its driver failed to start",
        39 => "its driver is missing or corrupted",
        43 => "Windows stopped it because it reported problems",
        45 => "isn't connected",
        52 => "its driver isn't signed",
        _ => $"has a problem (code {code})",
    };

    /// <summary>Whether the card can run at 1 Gbps or more: the speeds its driver offers, else its name.</summary>
    public static bool IsGigabitCapable(NicAdapter a, NicSpeedSetting? s)
    {
        if (s is not null && (s.ValidValues.Any(GigabitValues.Contains)
                              || s.ValidDisplayValues.Any(v => v.Contains("Gbps", StringComparison.OrdinalIgnoreCase) || v.Contains("Gb ", StringComparison.OrdinalIgnoreCase))))
            return true;
        return new[] { "Gigabit", "GbE", "2.5G", "1000" }.Any(k => a.Description.Contains(k, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>The card, or null when <paramref name="snapshot"/> wasn't read (the Network check then shows no hardware card).</summary>
    /// <param name="pings">Each connected wired adapter's pings by its name; null when they weren't run (a recording, or offline).</param>
    public static AreaCard? Build(NicHardwareSnapshot? snapshot, IReadOnlyDictionary<string, IReadOnlyList<NicPing>>? pings = null)
    {
        if (snapshot is null) return null;
        var adapters = snapshot.Adapters.Where(a => a.Medium is NicMedium.Ethernet or NicMedium.WiFi || a.PnpDeviceId.Length > 0)
            .OrderBy(a => a.Medium == NicMedium.Ethernet ? 0 : a.Medium == NicMedium.WiFi ? 1 : 2).ThenBy(a => a.Name, StringComparer.CurrentCultureIgnoreCase).ToList();
        if (adapters.Count == 0)
            return new AreaCard(CardId, "Adapter hardware", AreaLevel.Neutral, "No network card found", "", ["Adapter", "Check", "Result"], [],
                EmptyText: "Windows lists no physical network adapter.");

        var rows = new List<AreaRow>();
        var problems = new List<string>();
        var warnings = new List<string>();
        var unplugged = new List<string>();
        void Row(NicAdapter a, AreaLevel level, string check, string result, string? detail = null)
        {
            rows.Add(new AreaRow(level, [a.Name, check, result], Detail: detail));
            if (level == AreaLevel.Error) problems.Add($"{a.Name}: {check.ToLowerInvariant()}");
            else if (level == AreaLevel.Warning) warnings.Add($"{a.Name}: {check.ToLowerInvariant()}");
        }

        foreach (var a in adapters)
        {
            // 1. The burned-in address: what the card's own memory holds, whatever address software set on top of it.
            var burned = a.PermanentAddress.Length > 0 ? a.PermanentAddress : a.CurrentAddress;
            var mac = NicAddress.Check(burned);
            Row(a, mac == MacProblem.None ? AreaLevel.Ok : AreaLevel.Error, "Hardware address",
                mac == MacProblem.None ? $"{NicAddress.Format(burned)} · valid" : $"{(burned.Length > 0 ? NicAddress.Format(burned) + " · " : "")}{NicAddress.Describe(mac)}",
                mac == MacProblem.None ? null
                    : "A card's own address is programmed into it at the factory. A blank, all-zero or placeholder address usually means its memory "
                      + "(EEPROM) is corrupt: the card can clash with other PCs on the network or not work at all. Replace the card, or the board it's on.");

            // 2. Device Manager: a problem code, and the interrupt a PCI card needs.
            if (snapshot.Devices is { } devices)
            {
                var device = devices.FirstOrDefault(d => d.DeviceId.Equals(a.PnpDeviceId, StringComparison.OrdinalIgnoreCase))
                             ?? devices.FirstOrDefault(d => d.Name.Equals(a.Description, StringComparison.OrdinalIgnoreCase));
                if (device is null)
                    Row(a, AreaLevel.Neutral, "Device status", "Not found in Device Manager");
                else if (device.ProblemCode != 0)
                    Row(a, ResourceCodes.Contains(device.ProblemCode) ? AreaLevel.Error : AreaLevel.Warning, "Device status",
                        $"The card {ProblemText(device.ProblemCode)} (code {device.ProblemCode})",
                        ResourceCodes.Contains(device.ProblemCode)
                            ? "Windows couldn't give the card the memory range or interrupt it needs. Update the BIOS, reseat or move the card, and turn off devices it may clash with."
                            : null);
                else if (snapshot.InterruptsRead && IsPci(device.DeviceId) && device.Interrupts.Count == 0)
                    Row(a, AreaLevel.Warning, "Interrupt", "No interrupt assigned",
                        "A PCI network card needs an interrupt to tell Windows a frame arrived. Device Manager shows none for this one: check its Resources tab.");
                else
                    Row(a, AreaLevel.Ok, "Device status", device.Interrupts.Count > 0
                        ? $"Working · interrupt {string.Join(", ", device.Interrupts.Select(Irq))}"
                        : "Working");
            }

            // 3. The wired link: cable, speed and duplex.
            if (a.Medium != NicMedium.Ethernet) continue;
            if (a.Connected == false)
            {
                unplugged.Add(a.Name);
                Row(a, AreaLevel.Neutral, "Cable", "No cable plugged in",
                    "Plug a network cable into this port and run the check again, or use the Ethernet port test on the Interactive tests page.");
                continue;
            }
            var setting = snapshot.SpeedSettings?.FirstOrDefault(s => s.Adapter.Equals(a.Name, StringComparison.OrdinalIgnoreCase));
            var speed = Math.Max(a.ReceiveBps ?? 0, a.TransmitBps ?? 0);
            if (speed > 0)
            {
                var forced = setting is { Value.Length: > 0 } && setting.Value != "0";
                var slow = speed < 1_000_000_000 && IsGigabitCapable(a, setting);
                var text = NetworkAdapter.FormatSpeed(speed) + (forced ? $" · set by hand to {setting!.DisplayValue}" : "");
                Row(a, slow ? AreaLevel.Warning : AreaLevel.Ok, "Link speed", slow ? $"{text} on a gigabit card" : text,
                    slow ? forced
                            ? "The card's Speed & Duplex setting holds it below gigabit. Set it back to Auto Negotiation unless the switch needs it."
                            : "The card can run at 1 Gbps or more but agreed a slower link. Usually the cable (a damaged pair, or an old Cat 5 one), the wall socket or the switch port: try another cable and port."
                        : null);
            }
            if (a.FullDuplex is { } full)
                Row(a, full ? AreaLevel.Ok : AreaLevel.Warning, "Duplex", full ? "Full duplex" : "Half duplex",
                    full ? null : "Half duplex sends and receives in turn, with collisions and slow transfers. Usually a speed setting forced on one end only, or a hub.");

            // 4. Live pings: the card's own address, then its DHCP server (the far end of the cable).
            if (pings is not null && pings.TryGetValue(a.Name, out var series))
            {
                foreach (var p in series)
                {
                    var own = p.Target == "Own address";
                    var pingLevel = p.Replies == p.Sent ? AreaLevel.Ok : own && p.Replies == 0 ? AreaLevel.Error : p.Replies == 0 ? AreaLevel.Neutral : AreaLevel.Warning;
                    Row(a, pingLevel, $"Ping {p.Target.ToLowerInvariant()}", $"{p.Address} · {p.Replies} of {p.Sent} replied",
                        own && p.Replies == 0 ? "The PC didn't answer a ping to its own address on this card: its network stack can't send and receive here. Reset the adapter or reinstall its driver."
                        : !own && p.Replies == 0 ? "No reply. Some routers don't answer ping; compare with the Reachability card." : null);
                }
            }
        }

        var level = rows.Count == 0 ? AreaLevel.Neutral : rows.Max(r => r.Level);
        var headline = problems.Count > 0 ? string.Join("; ", problems)
            : warnings.Count > 0 ? string.Join("; ", warnings)
            : unplugged.Count > 0 && adapters.All(a => a.Medium != NicMedium.Ethernet || a.Connected == false)
                ? $"Hardware OK · plug a cable into {string.Join(", ", unplugged)} to test the wired link"
                : "Hardware OK";
        var meta = $"{AreaModuleBase.Plural(adapters.Count, "adapter")}" + (snapshot.Devices is null ? " · Device Manager not read" : "")
                   + (pings is null ? "" : " · pings live");
        return new AreaCard(CardId, "Adapter hardware", level, headline, meta, ["Adapter", "Check", "Result"], rows,
            Note: "The hardware address is the one burned into the card, not one software set. Link speed and duplex are what the card agreed with the switch. "
                  + "To test a port with a loopback plug, or to wait while a cable is plugged in, use the Ethernet port test.",
            PreserveRowOrder: true)
        {
            OpenPage = adapters.Any(a => a.Medium == NicMedium.Ethernet) ? new AreaPageLink(EthernetTestPage, "Ethernet port test") : null,
        };
    }

    private static bool IsPci(string deviceId) => deviceId.StartsWith(@"PCI\", StringComparison.OrdinalIgnoreCase);

    /// <summary>A message-signalled interrupt is listed with a number above 2^31 (its two's complement); it is shown as "MSI".</summary>
    private static string Irq(long n) => n is < 0 or > int.MaxValue ? "MSI" : n.ToString(CultureInfo.InvariantCulture);
}
