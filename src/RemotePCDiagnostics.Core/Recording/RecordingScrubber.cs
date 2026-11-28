using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml.Linq;

namespace RemotePCDiagnostics.Core.Recording;

/// <summary>
/// Replaces personal details in a recording before it is saved, with the same placeholders the Admin uses: <c>&lt;pc:1a2b3c&gt;</c> for the
/// PC's name, <c>&lt;user:1a2b3c&gt;</c> for a Windows user, <c>&lt;serial:1a2b3c&gt;</c> for a serial number or other per-unit ID. The same
/// value always gets the same placeholder within one recording (an HMAC under a key that is never saved), so answers still line up.
/// Plain string handling only.
/// </summary>
public sealed class RecordingScrubber
{
    /// <summary>Property names (WMI or osquery columns) whose values identify one unit or one person, compared ignoring case.</summary>
    public static readonly IReadOnlySet<string> SensitiveNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "SerialNumber", "serial_number", "serial", "hardware_serial", "board_serial", "UniqueID", "IdentifyingNumber",
        "MACAddress", "mac", "PermanentAddress", "CSName", "__SERVER", "UserName", "RegisteredUser", "PrimaryOwnerName",
        "computer_name", "hostname", "local_hostname", "ComputerName",
        "Id", // the DriveHealth script's name for a disk's UniqueId (its WWN / EUI)
        "UUID", // the SMBIOS UUID (Win32_ComputerSystemProduct, osquery system_info), per unit on most makers
        "guid", "pnp_device_id", "PNPDeviceID", // a network adapter's GUID; device instance paths can hold a USB serial
        "dhcp_server", "dns_server_search_order", "dns_domain", "dns_domain_suffix_search_order", // the local network's servers and domain
        "DNSServerSearchOrder", "Dns", "ProxyServer", // the same for the Network check (WMI, the IpConfig script, the proxy setting)
        "NameServer", "DnsManual", // DNS servers entered by hand (the registry, the IpConfig script)
    };

    /// <summary>
    /// Columns that hold IP addresses (WMI <c>Win32_NetworkAdapterConfiguration</c>, the IpConfig script). An IPv6 address (a link-local or
    /// unique local one names the interface and the network) or a public IPv4 address is replaced by a placeholder that keeps its family
    /// (<see cref="RecordingPlaceholders"/>); a private IPv4 address (192.168.x.x, 10.x.x.x) is kept, as it is the same on most home networks.
    /// </summary>
    public static readonly IReadOnlySet<string> AddressNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "IPAddress", "DefaultIPGateway", "IPv4", "Gateway",
    };

    /// <summary>Device instance paths of Bluetooth and USB devices hold the device's MAC address or serial (<c>BTHENUM\...\8&amp;..._A0B1C2D3E4F5</c>,
    /// <c>USB\VID_...\SERIAL</c>): replaced by a placeholder, the same one wherever the same path appears, so joins still work.
    /// <c>parentInstanceId</c> is the USB tree's link to a node's parent (<see cref="Usb.UsbNode"/>).</summary>
    public static readonly IReadOnlySet<string> DeviceIdNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "DeviceID", "InstanceId", "ParentInstanceId" };

    private static readonly IReadOnlySet<string> MacNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "MACAddress", "mac", "PermanentAddress" };
    private static readonly IReadOnlySet<string> ReferenceNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Antecedent", "Dependent" };

    private static bool IsPersonalDeviceId(string s) =>
        s.StartsWith("BTH", StringComparison.OrdinalIgnoreCase)
        || s.StartsWith(@"USB\", StringComparison.OrdinalIgnoreCase)
        || s.StartsWith(@"USBSTOR\", StringComparison.OrdinalIgnoreCase);

    /// <summary>One string value under property <paramref name="name"/>, scrubbed.</summary>
    private string Scalar(string name, string s) =>
        // A blank or placeholder hardware address (a corrupt card's EEPROM) names no one and is what the adapter hardware card judges.
        MacNames.Contains(name) && Areas.NicAddress.Check(s) is Areas.MacProblem.AllZero or Areas.MacProblem.AllOnes or Areas.MacProblem.Placeholder ? s
        : SensitiveNames.Contains(name) ? Placeholder("serial", s)
        // Win32_PnPAllocatedResource links a device by its instance path, which for a USB or Bluetooth device holds its serial.
        : ReferenceNames.Contains(name) && (s.Contains(@"DeviceID=""USB", StringComparison.OrdinalIgnoreCase) || s.Contains(@"DeviceID=""BTH", StringComparison.OrdinalIgnoreCase))
            ? Placeholder("device", s)
        : AddressNames.Contains(name) ? Address(s)
        : DeviceIdNames.Contains(name) && IsPersonalDeviceId(s) ? Placeholder("device", s)
        : Text(s);

    private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
    private readonly List<(string Value, string Kind)> _names = [];
    private readonly Dictionary<string, int> _counts = new(StringComparer.Ordinal);

    /// <param name="machineName">This PC's name.</param>
    /// <param name="userNames">Windows user names on this PC (the signed-in user at least).</param>
    public RecordingScrubber(string machineName, IEnumerable<string> userNames)
    {
        if (machineName.Trim().Length >= 2) _names.Add((machineName.Trim(), "pc"));
        foreach (var u in userNames.Select(u => u.Trim()).Where(u => u.Length >= 2).Distinct(StringComparer.OrdinalIgnoreCase))
            _names.Add((u, "user"));
        // Longest first, so "BUDSLAPTOP" is replaced before "bud".
        _names.Sort((a, b) => b.Value.Length.CompareTo(a.Value.Length));
    }

    /// <summary>What was replaced, and how many times.</summary>
    public IReadOnlyDictionary<string, int> Counts => _counts;

    public MachineRecording Scrub(MachineRecording recording) => new()
    {
        Schema = recording.Schema,
        // The SMBIOS UUID is per unit on most makers (the product id names the model), so it is replaced like a serial.
        Machine = recording.Machine with
        {
            Notes = recording.Machine.Notes is { } n ? Text(n) : null,
            SmbiosUuid = Placeholder("serial", recording.Machine.SmbiosUuid),
        },
        CapturedAt = recording.CapturedAt,
        Calls = recording.Calls.Select(Scrub).ToList(),
    };

    public RecordedCall Scrub(RecordedCall c) => c with
    {
        Args = c.Args?.Select(Text).ToList(),
        // A query can hold the PC's name (a disk's ObjectId does); scrubbed the same way as the rows, so replay still finds it.
        Query = c.Query is { } q ? Text(q) : null,
        StdOut = c.StdOut is { } o ? Output(o) : null,
        StdErr = c.StdErr is { } e ? Text(e) : null,
        Error = c.Error is { } err ? Text(err) : null,
        Rows = c.Rows?.Select(r => r.ToDictionary(p => p.Key, p => Value(p.Key, p.Value), StringComparer.OrdinalIgnoreCase)).ToList(),
    };

    /// <summary>Command output: JSON (osquery) and an XML document (the battery report) have their sensitive fields replaced too; any text
    /// has names replaced.</summary>
    private string Output(string stdout)
    {
        var t = stdout.TrimStart();
        if (t.StartsWith('<') && (Xml(stdout) ?? XmlList(stdout)) is { } xml) return xml;
        if (t.StartsWith('[') || t.StartsWith('{'))
        {
            try
            {
                if (JsonNode.Parse(stdout) is { } node)
                {
                    ScrubNode(node);
                    return node.ToJsonString(MachineRecording.Json);
                }
            }
            catch (JsonException) { /* not JSON after all: treat as text */ }
        }
        return Text(stdout);
    }

    /// <summary>An XML document with its sensitive elements (<see cref="SensitiveNames"/>) replaced and names replaced in all other text;
    /// null when it isn't one document.</summary>
    private string? Xml(string text)
    {
        XDocument doc;
        try { doc = XDocument.Parse(text, LoadOptions.PreserveWhitespace); }
        catch (System.Xml.XmlException) { return null; }
        ScrubXml(doc.Root!);
        return (doc.Declaration is { } d ? d + "\n" : "") + doc.ToString(SaveOptions.DisableFormatting);
    }

    /// <summary>
    /// A list of XML elements with no root (wevtutil's events), each scrubbed as <see cref="Xml"/> does; null when it isn't one. Scrubbed as
    /// plain text instead, a placeholder such as &lt;pc:1a2b3c&gt; in an element would break the XML.
    /// </summary>
    private string? XmlList(string text)
    {
        var settings = new System.Xml.XmlReaderSettings
        {
            ConformanceLevel = System.Xml.ConformanceLevel.Fragment, CheckCharacters = false,
            DtdProcessing = System.Xml.DtdProcessing.Prohibit, XmlResolver = null, IgnoreWhitespace = false,
        };
        var parts = new List<XNode>();
        try
        {
            using var reader = System.Xml.XmlReader.Create(new StringReader(text), settings);
            reader.MoveToContent();
            while (!reader.EOF)
            {
                if (reader.NodeType == System.Xml.XmlNodeType.Element) parts.Add(XNode.ReadFrom(reader));
                else if (reader.NodeType is System.Xml.XmlNodeType.Whitespace or System.Xml.XmlNodeType.SignificantWhitespace) { parts.Add(new XText(reader.Value)); reader.Read(); }
                else if (!reader.Read()) break;
            }
        }
        catch (System.Xml.XmlException) { return null; }
        var sb = new StringBuilder();
        foreach (var node in parts)
        {
            if (node is XElement e) { ScrubXml(e); sb.Append(e.ToString(SaveOptions.DisableFormatting)); }
            else sb.Append(((XText)node).Value);
        }
        return sb.ToString();
    }

    private void ScrubXml(XElement root)
    {
        foreach (var e in root.DescendantsAndSelf().ToList())
        {
            foreach (var a in e.Attributes().Where(a => !a.IsNamespaceDeclaration)) a.Value = Text(a.Value);
            if (e.HasElements) continue;
            e.Value = SensitiveNames.Contains(e.Name.LocalName) ? Placeholder("serial", e.Value) : Text(e.Value);
        }
    }

    private void ScrubNode(JsonNode node)
    {
        switch (node)
        {
            case JsonObject o:
                // An audio endpoint on Bluetooth is named after the headset, which people often name after themselves ("Bud's AirPods").
                var bluetooth = o.Any(p => p.Key.Equals("bus", StringComparison.OrdinalIgnoreCase) && p.Value is JsonValue b
                                           && b.TryGetValue<string>(out var bus) && bus == "Bluetooth");
                foreach (var (name, child) in o.ToList())
                {
                    if (child is JsonValue v && v.TryGetValue<string>(out var s))
                        // A window title names the open document or page ("Budget 2027.xlsx - Excel"): kept out of recordings.
                        o[name] = bluetooth && name.Equals("name", StringComparison.OrdinalIgnoreCase) ? Placeholder("bluetooth", s)
                            : name.Equals("windowTitle", StringComparison.OrdinalIgnoreCase) ? Placeholder("window", s) : Scalar(name, s);
                    else if (child is not null) ScrubNode(child);
                }
                break;
            case JsonArray a:
                for (var i = 0; i < a.Count; i++)
                {
                    if (a[i] is JsonValue v && v.TryGetValue<string>(out var s)) a[i] = Text(s);
                    else if (a[i] is { } child) ScrubNode(child);
                }
                break;
        }
    }

    private JsonElement Value(string name, JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.String)
        {
            var s = value.GetString()!;
            return JsonSerializer.SerializeToElement(Scalar(name, s));
        }
        if (value.ValueKind == JsonValueKind.Array)
            return JsonSerializer.SerializeToElement(value.EnumerateArray().Select(e => Value(name, e)).ToList());
        if (SensitiveNames.Contains(name) && value.ValueKind == JsonValueKind.Number)
            return JsonSerializer.SerializeToElement(Placeholder("serial", value.GetRawText()));
        return value;
    }

    /// <summary>An IP address as <see cref="AddressNames"/> says; anything else as other text.</summary>
    public string Address(string value)
    {
        if (!System.Net.IPAddress.TryParse(value.Trim(), out var ip)) return Text(value);
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6) return Placeholder(RecordingPlaceholders.Ipv6Kind, value);
        var b = ip.GetAddressBytes();
        var isPrivate = b[0] == 10 || b[0] == 127 || (b[0] == 172 && b[1] is >= 16 and <= 31) || (b[0] == 192 && b[1] == 168)
                        || (b[0] == 169 && b[1] == 254) || (b[0] == 100 && b[1] is >= 64 and <= 127) || b.All(x => x == 0);
        return isPrivate ? value : Placeholder(RecordingPlaceholders.Ipv4Kind, value);
    }

    private string Placeholder(string kind, string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return value;
        _counts[kind] = _counts.GetValueOrDefault(kind) + 1;
        var mac = HMACSHA256.HashData(_key, Encoding.UTF8.GetBytes(kind + "\n" + value.Trim().ToUpperInvariant()));
        return $"<{kind}:{Convert.ToHexString(mac, 0, 3).ToLowerInvariant()}>";
    }

    private const string SidPrefix = "S-1-5-21-";

    private string Sids(string s)
    {
        var at = 0;
        while ((at = s.IndexOf(SidPrefix, at, StringComparison.OrdinalIgnoreCase)) >= 0)
        {
            var end = at + SidPrefix.Length;
            while (end < s.Length && (char.IsAsciiDigit(s[end]) || s[end] == '-')) end++;
            // A domain or machine SID has three sub-authorities after S-1-5-21 (and a user's a fourth, the RID).
            if (end - at < SidPrefix.Length + 5 || (at > 0 && char.IsLetterOrDigit(s[at - 1]))) { at = end; continue; }
            var p = Placeholder("sid", s[at..end].TrimEnd('-'));
            s = string.Concat(s.AsSpan(0, at), p, s.AsSpan(end));
            at += p.Length;
        }
        return s;
    }

    /// <summary>
    /// Replaces the PC's name and user names where they stand as a whole word (not inside a longer word), and account SIDs
    /// (<c>S-1-5-21-…</c>, which name one user on one PC: the HKEY_USERS subkeys).
    /// </summary>
    public string Text(string s)
    {
        s = Sids(s);
        foreach (var (value, kind) in _names)
        {
            var at = 0;
            while ((at = s.IndexOf(value, at, StringComparison.OrdinalIgnoreCase)) >= 0)
            {
                var end = at + value.Length;
                var wordStart = at == 0 || !char.IsLetterOrDigit(s[at - 1]);
                var wordEnd = end == s.Length || !char.IsLetterOrDigit(s[end]);
                if (!wordStart || !wordEnd) { at = end; continue; }
                var p = Placeholder(kind, value);
                s = string.Concat(s.AsSpan(0, at), p, s.AsSpan(end));
                at += p.Length;
            }
        }
        return s;
    }
}

/// <summary>The beginnings of the placeholders an IP address is replaced with, so a reader can still tell IPv4 from IPv6.</summary>
public static class RecordingPlaceholders
{
    public const string Ipv4Kind = "ipv4", Ipv6Kind = "ipv6";
    public const string Ipv4 = "<" + Ipv4Kind + ":", Ipv6 = "<" + Ipv6Kind + ":";
}
