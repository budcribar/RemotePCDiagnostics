namespace RemotePCDiagnostics.Core.Wake;

/// <summary>
/// One adapter's wake settings, as Windows stores them. <c>Enabled</c>, <c>Disabled</c>, <c>Unsupported</c> (the driver does not
/// offer the setting) or <c>Unknown</c> (it could not be read).
/// </summary>
public sealed record WakeNicSetting(string MagicPacket, string Pattern, string ArpOffload, string NsOffload)
{
    public static readonly WakeNicSetting Unknown = new("Unknown", "Unknown", "Unknown", "Unknown");
    public static readonly WakeNicSetting Unsupported = new("Unsupported", "Unsupported", "Unsupported", "Unsupported");

    /// <summary>
    /// The NIC advanced-property keywords, in the order Windows shows them. The first keyword that is present wins.
    /// An absent keyword is <c>Unsupported</c>.
    /// </summary>
    public static WakeNicSetting FromValues(IReadOnlyDictionary<string, string?>? values)
    {
        if (values is null) return Unknown;
        return new(
            Pick(values, "*WakeOnMagicPacket", "WakeOnMagicPacket", "*ModernStandbyWoLMagicPacket"),
            Pick(values, "*WakeOnPattern", "WakeOnPattern"),
            Pick(values, "*PMARPOffload", "*ARPOffload"),
            Pick(values, "*PMNSOffload", "*NSOffload"));
    }

    /// <summary>A registry value: <c>1</c>/<c>Enabled</c> or <c>0</c>/<c>Disabled</c>. Null means the keyword is absent.</summary>
    public static string StateOf(string? raw)
    {
        if (raw is null) return "Unsupported";
        raw = raw.Trim();
        if (raw.Length == 0) return "Unknown";
        if (raw.Equals("1", StringComparison.OrdinalIgnoreCase)
            || raw.Equals("Enabled", StringComparison.OrdinalIgnoreCase)
            || raw.Equals("Enable", StringComparison.OrdinalIgnoreCase)
            || raw.Equals("On", StringComparison.OrdinalIgnoreCase))
            return "Enabled";
        if (raw.Equals("0", StringComparison.OrdinalIgnoreCase)
            || raw.Equals("Disabled", StringComparison.OrdinalIgnoreCase)
            || raw.Equals("Disable", StringComparison.OrdinalIgnoreCase)
            || raw.Equals("Off", StringComparison.OrdinalIgnoreCase))
            return "Disabled";
        return "Unknown";
    }

    private static string Pick(IReadOnlyDictionary<string, string?> values, params string[] names)
    {
        foreach (var name in names)
            if (values.TryGetValue(name, out var raw)) return StateOf(raw);
        return "Unsupported";
    }
}

/// <summary>What <c>powercfg /a</c> said about the sleep states a network adapter can wake.</summary>
public sealed record WakePowerInfo(bool ModernStandby, bool S3, bool Hibernate, string StandbyNetwork)
{
    /// <summary>
    /// The available section only. A state listed under "not available" does not count, so an S3 PC is not reported as
    /// Modern Standby just because the firmware names S0 as missing.
    /// </summary>
    public static WakePowerInfo? Parse(string? stdout)
    {
        if (string.IsNullOrWhiteSpace(stdout)) return null;
        var available = new List<string>();
        var section = 0;
        int? stateIndent = null;
        foreach (var raw in stdout.Replace("\r", "").Split('\n'))
        {
            if (raw.Trim().Length == 0) continue;
            var indent = raw.Length - raw.TrimStart().Length;
            var text = raw.Trim();
            if (indent == 0)
            {
                if (text.Contains("not available", StringComparison.OrdinalIgnoreCase)) section = 2;
                else if (text.Contains("available", StringComparison.OrdinalIgnoreCase)) section = 1;
                else section = 0;
                stateIndent = null;
                continue;
            }
            if (section != 1) continue;
            var hasTab = raw[..indent].Contains('\t');
            stateIndent ??= hasTab ? null : indent;
            var isState = !hasTab && stateIndent is { } si && indent <= si;
            if (isState) available.Add(text);
        }
        if (section == 0 && available.Count == 0) return null;

        string network = "";
        var modern = false;
        foreach (var line in available)
        {
            if (!line.Contains("S0 Low Power Idle", StringComparison.OrdinalIgnoreCase)) continue;
            modern = true;
            if (line.Contains("Disconnected", StringComparison.OrdinalIgnoreCase)) network = "disconnected";
            else if (line.Contains("Connected", StringComparison.OrdinalIgnoreCase)) network = "connected";
        }
        return new(
            modern,
            available.Any(s => s.Contains("(S3)", StringComparison.OrdinalIgnoreCase)),
            available.Any(s => s.Equals("Hibernate", StringComparison.OrdinalIgnoreCase) || s.StartsWith("Hibernate ", StringComparison.OrdinalIgnoreCase)),
            network);
    }
}

/// <summary>An adapter as the inventory read it, before subnet math and wake matching.</summary>
public sealed record WakeAdapterFacts(
    string Name,
    string Description,
    string AdapterType,
    string Mac,
    string Ipv4,
    int PrefixLength,
    string InstanceId);

/// <summary>One Ethernet or Wi-Fi adapter the relay can store. <see cref="WakeArmed"/> is <c>yes</c>, <c>no</c> or <c>unknown</c>.</summary>
public sealed record WakeAdapter(
    string Name,
    string Description,
    string AdapterType,
    string Mac,
    string Ipv4,
    int PrefixLength,
    string Subnet,
    string Broadcast,
    string WakeArmed,
    string MagicPacket,
    string Pattern,
    string ArpOffload,
    string NsOffload);

/// <summary>What the agent reports, and what the Wake readiness check reads. No user names, paths or keys.</summary>
public sealed record WakeSnapshot(
    bool PowerRead,
    bool ModernStandby,
    bool S3,
    bool Hibernate,
    string StandbyNetwork,
    IReadOnlyList<WakeAdapter> Adapters)
{
    public static WakeSnapshot Empty { get; } = new(false, false, false, false, "", []);

    /// <summary>
    /// Ethernet and Wi-Fi adapters worth storing. Virtual, VPN, Bluetooth and tunnel adapters are left out: they cannot wake the PC.
    /// </summary>
    public static bool IncludeInReport(string? name, string? description, string? adapterType)
    {
        if (adapterType is not ("Ethernet" or "Wi-Fi")) return false;
        var text = (name ?? "") + " " + (description ?? "");
        string[] skip =
        [
            "virtual", "hyper-v", "vethernet", "wsl", "bluetooth", "vpn", "tap-windows", "wan miniport",
            "loopback", "pseudo", "isatap", "teredo", "virtualbox", "vmware", "vmxnet", "host-only",
            "npcap", "tunnel", "kernel debug", "wi-fi direct", "wifi direct",
        ];
        return !skip.Any(w => text.Contains(w, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>True when <paramref name="armed"/> names this adapter. Null <paramref name="armed"/> means powercfg did not run.</summary>
    public static string ArmedState(IReadOnlyList<string>? armed, string? name, string? description)
    {
        if (armed is null) return "unknown";
        return Matches(armed, description) || Matches(armed, name) ? "yes" : "no";
    }

    public static WakeSnapshot Compose(
        WakePowerInfo? power,
        bool powerRead,
        IReadOnlyList<string>? armed,
        IReadOnlyDictionary<string, WakeNicSetting>? settings,
        bool registryRead,
        IReadOnlyList<WakeAdapterFacts>? adapters)
    {
        var rows = new List<WakeAdapter>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var fact in adapters ?? [])
        {
            if (!IncludeInReport(fact.Name, fact.Description, fact.AdapterType)) continue;
            var (subnet, broadcast, prefix) = SubnetOf(fact.Ipv4, fact.PrefixLength);
            var key = (fact.Mac ?? "") + "|" + broadcast + "|" + (fact.Name ?? "");
            if (!seen.Add(key)) continue;
            var setting = SettingFor(settings, registryRead, fact.InstanceId);
            rows.Add(new(
                fact.Name ?? "",
                fact.Description ?? "",
                fact.AdapterType ?? "",
                fact.Mac ?? "",
                string.IsNullOrEmpty(broadcast) ? "" : fact.Ipv4 ?? "",
                string.IsNullOrEmpty(broadcast) ? 0 : prefix,
                subnet,
                broadcast,
                ArmedState(armed, fact.Name, fact.Description),
                setting.MagicPacket,
                setting.Pattern,
                setting.ArpOffload,
                setting.NsOffload));
        }
        return new(
            powerRead && power is not null,
            power?.ModernStandby ?? false,
            power?.S3 ?? false,
            power?.Hibernate ?? false,
            power?.StandbyNetwork ?? "",
            rows);
    }

    private static WakeNicSetting SettingFor(IReadOnlyDictionary<string, WakeNicSetting>? settings, bool registryRead, string? instanceId)
    {
        if (!registryRead || settings is null) return WakeNicSetting.Unknown;
        var id = NormalizeGuid(instanceId);
        return id.Length > 0 && settings.TryGetValue(id, out var found) ? found : WakeNicSetting.Unsupported;
    }

    private static (string Subnet, string Broadcast, int Prefix) SubnetOf(string? ipv4, int prefixLength)
    {
        if (!WakeAddresses.TryIPv4(ipv4, out var ip) || WakeAddresses.IsLinkLocal(ip) || System.Net.IPAddress.IsLoopback(ip))
            return ("", "", 0);
        if (prefixLength is <= 0 or > 32) return ("", "", 0);
        if (!WakeAddresses.TrySubnet(ip, prefixLength, out var network, out var broadcast)) return ("", "", 0);
        if (prefixLength == 32 || ip.Equals(broadcast)) return ("", "", 0);
        return (network.ToString(), broadcast.ToString(), prefixLength);
    }

    /// <summary>A GUID with or without braces, compared the same way the registry and <c>NetworkInterface.Id</c> write it.</summary>
    public static string NormalizeGuid(string? id)
    {
        if (string.IsNullOrWhiteSpace(id)) return "";
        var trimmed = id.Trim().Trim('{', '}');
        return Guid.TryParse(trimmed, out var guid) ? guid.ToString("D") : trimmed;
    }

    private static bool Matches(IReadOnlyList<string> armed, string? candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate)) return false;
        foreach (var line in armed)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            if (string.Equals(line.Trim(), candidate.Trim(), StringComparison.OrdinalIgnoreCase)) return true;
            if (candidate.Trim().Length >= 8 && line.Contains(candidate.Trim(), StringComparison.OrdinalIgnoreCase)) return true;
            if (line.Trim().Length >= 8 && candidate.Contains(line.Trim(), StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }
}
