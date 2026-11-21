using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Wake;

namespace RemotePCDiagnostics.Modules.WakeReadiness;

/// <summary>
/// Whether another computer on the same subnet can wake this one with a magic packet. Read-only: it does not change the BIOS,
/// the NIC, or the devices Windows will arm.
/// </summary>
public sealed class WakeReadinessModule(SystemCommandRunner commands) : AreaModuleBase(commands.Log)
{
    public const string ModuleName = ModuleSlugs.WakeReadiness;

    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.WakeReadiness;
    public override string DisplayName => "Wake readiness";
    protected override string FailedMessage => "Couldn't read whether this PC can be woken.";

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        progress.ReportStep(1, 2, "Reading sleep states and wake-armed devices…");
        var snapshot = await WakeInventory.ReadAsync(commands, ct).ConfigureAwait(false);
        progress.ReportStep(2, 2, "Reading adapter wake settings…");
        return Build(snapshot);
    }

    public static AreaReport Build(WakeSnapshot snap)
    {
        if (!snap.PowerRead && snap.Adapters.Count == 0)
        {
            const string Why = "Couldn't read this PC's adapters or its sleep states, so wake readiness is unknown.";
            return new AreaReport([], Why, DiagnosticStatus.Error) { CouldNotRunReason = Why };
        }

        var ethernet = snap.Adapters.Where(a => EthernetReady(snap, a)).ToList();
        var wifi = snap.Adapters.Where(a => WifiReady(snap, a)).ToList();
        var ready = ethernet.Count > 0 || wifi.Count > 0;
        var level = ready ? AreaLevel.Ok : AreaLevel.Warning;
        var headline = Headline(ethernet, wifi, snap);
        var rows = new List<AreaRow> { SleepRow(snap) };
        if (snap.Adapters.Count == 0)
            rows.Add(new(AreaLevel.Warning, ["Network adapter", "No Ethernet or Wi-Fi adapter was found"]));
        else
            rows.AddRange(snap.Adapters.Select(a => AdapterVerdictRow(snap, a)));
        rows.Add(new(AreaLevel.Neutral, ["Who can send it", "An awake computer on the same subnet. A router will not forward it."]));

        var note = string.Join(" ", NoteSentences(snap, ethernet, wifi));
        var readiness = new AreaCard("readiness", "Can this PC be woken", level, headline, SleepMeta(snap),
            ["What", "State"], rows, Note: note, PreserveRowOrder: true);

        var addressRows = snap.Adapters.Select(a =>
        {
            var rowLevel = EthernetReady(snap, a) || WifiReady(snap, a) ? AreaLevel.Ok
                : a.WakeArmed == "unknown" && a.MagicPacket == "Unknown" ? AreaLevel.Neutral
                : AreaLevel.Warning;
            return new AreaRow(rowLevel,
                [Label(a), a.AdapterType, MacText(a.Mac), AddressText(a), BroadcastText(a), ArmedText(a.WakeArmed), MagicText(a.MagicPacket)],
                Detail: Detail(a));
        }).ToList();
        var addresses = new AreaCard("adapters", "Addresses for a wake packet", AreaLevel.Neutral,
            snap.Adapters.Count == 0 ? "Nothing to address" : Plural(snap.Adapters.Count, "adapter"),
            "MAC address, subnet and broadcast",
            ["Adapter", "Type", "MAC address", "IPv4", "Broadcast", "Wake armed", "Magic packet"],
            addressRows,
            EmptyText: "No Ethernet or Wi-Fi adapter was found. Virtual and VPN adapters are not listed.",
            PreserveRowOrder: true);

        var summary = Summary(ethernet, wifi, snap);
        var status = level == AreaLevel.Ok ? DiagnosticStatus.Ok : DiagnosticStatus.Warning;
        return new([readiness, addresses], summary, status);
    }

    private static bool EthernetReady(WakeSnapshot snap, WakeAdapter a) =>
        a.AdapterType == "Ethernet" && a.WakeArmed == "yes" && a.MagicPacket == "Enabled"
        && snap.PowerRead && (snap.S3 || snap.ModernStandby);

    private static bool WifiReady(WakeSnapshot snap, WakeAdapter a) =>
        a.AdapterType == "Wi-Fi" && a.WakeArmed == "yes" && a.MagicPacket == "Enabled"
        && snap.PowerRead && snap.ModernStandby
        && !string.Equals(snap.StandbyNetwork, "disconnected", StringComparison.OrdinalIgnoreCase);

    private static string Headline(IReadOnlyList<WakeAdapter> ethernet, IReadOnlyList<WakeAdapter> wifi, WakeSnapshot snap)
    {
        if (ethernet.Count > 0 && wifi.Count > 0) return "Yes, on the wired network and from Modern Standby over Wi-Fi";
        if (ethernet.Count > 0) return snap.ModernStandby && !snap.S3 ? "Yes, from Modern Standby on the wired network" : "Yes, from sleep on the wired network";
        if (wifi.Count > 0) return "Yes, from Modern Standby over Wi-Fi";
        if (!snap.PowerRead) return "Couldn't confirm";
        return "No";
    }

    private static string Summary(IReadOnlyList<WakeAdapter> ethernet, IReadOnlyList<WakeAdapter> wifi, WakeSnapshot snap)
    {
        var headline = Headline(ethernet, wifi, snap);
        if (headline.StartsWith("Yes", StringComparison.Ordinal))
        {
            var broadcast = (wifi.Count > 0 ? wifi : ethernet).Select(a => a.Broadcast).FirstOrDefault(b => b.Length > 0);
            return broadcast is { Length: > 0 } ? $"{headline}. Broadcast {broadcast}." : headline + ".";
        }
        if (!snap.PowerRead) return "Couldn't read sleep states, so wake readiness is not confirmed.";
        if (snap.Adapters.Count == 0) return "No Ethernet or Wi-Fi adapter another computer can wake.";
        return "Not set to wake on a network packet.";
    }

    private static AreaRow SleepRow(WakeSnapshot snap)
    {
        if (!snap.PowerRead) return new(AreaLevel.Warning, ["Sleep", "Couldn't read powercfg /a"]);
        if (snap.ModernStandby)
        {
            var net = snap.StandbyNetwork switch
            {
                "connected" => "network connected",
                "disconnected" => "network disconnected",
                _ => "network mode not stated",
            };
            var level = snap.StandbyNetwork == "disconnected" ? AreaLevel.Warning : AreaLevel.Ok;
            return new(level, ["Sleep", $"Modern Standby ({net})"]);
        }
        if (snap.S3) return new(AreaLevel.Ok, ["Sleep", "S3 sleep"]);
        return new(AreaLevel.Warning, ["Sleep", snap.Hibernate ? "Hibernate only, no S3 or Modern Standby" : "No sleep state"]);
    }

    private static string SleepMeta(WakeSnapshot snap)
    {
        if (!snap.PowerRead) return "Sleep states were not read";
        if (snap.ModernStandby) return "Modern Standby";
        if (snap.S3) return "S3 sleep";
        return "No network sleep";
    }

    private static AreaRow AdapterVerdictRow(WakeSnapshot snap, WakeAdapter a)
    {
        if (EthernetReady(snap, a))
            return new(AreaLevel.Ok, [Label(a), "Wake on Magic Packet is on, and Windows will arm it"]);
        if (WifiReady(snap, a))
            return new(AreaLevel.Ok, [Label(a), "Wake on Magic Packet is on, and Windows will arm it for Modern Standby"]);
        return new(AreaLevel.Warning, [Label(a), WhyNot(snap, a)]);
    }

    private static string WhyNot(WakeSnapshot snap, WakeAdapter a)
    {
        if (a.AdapterType == "Wi-Fi" && snap.PowerRead && snap.S3 && !snap.ModernStandby)
            return "Wi-Fi is usually off in S3 sleep, so a magic packet will not reach it";
        if (a.AdapterType == "Wi-Fi" && snap.PowerRead && snap.ModernStandby && snap.StandbyNetwork == "disconnected")
            return "Modern Standby is network disconnected, so the radio is not kept associated";
        if (a.MagicPacket == "Disabled")
            return "Wake on Magic Packet is off";
        if (a.WakeArmed == "no")
            return "Windows is not arming it to wake the PC";
        if (a.WakeArmed == "unknown" || a.MagicPacket == "Unknown" || !snap.PowerRead)
            return "Wake readiness could not be read";
        if (a.MagicPacket == "Unsupported")
            return "The driver does not offer Wake on Magic Packet";
        if (!snap.S3 && !snap.ModernStandby)
            return "This PC has no sleep state a network adapter can wake";
        return "Not ready for a magic packet";
    }

    private static IEnumerable<string> NoteSentences(WakeSnapshot snap, IReadOnlyList<WakeAdapter> ethernet, IReadOnlyList<WakeAdapter> wifi)
    {
        yield return "This check only reads. It does not change the BIOS or the adapter.";
        yield return "Another awake RPCD agent on the same subnet sends the magic packet as a UDP broadcast to ports 9 and 7. Sending it does not need administrator rights. Routers do not forward 255.255.255.255, and most drop a directed broadcast, so a computer on another subnet cannot wake this one. Client isolation on the access point blocks it too.";

        if (wifi.Count > 0)
            yield return "Wi-Fi can wake this PC only from Modern Standby, while the radio stays associated with the access point. That holds on AC power. On battery, Windows often disconnects the network. Hibernate and a full shutdown turn the radio off, so they cannot be woken this way.";
        else if (snap.Adapters.Any(a => a.AdapterType == "Wi-Fi"))
            yield return "A Wi-Fi adapter cannot wake this PC from hibernate or a full shutdown. From S3 the radio is usually off. Modern Standby can work only while the radio stays associated, which is much more reliable on AC power than on battery.";

        if (ethernet.Count > 0 || snap.Adapters.Any(a => a.AdapterType == "Ethernet"))
            yield return "A wired adapter can wake the PC from S3 sleep when it is armed and Wake on Magic Packet is on. Waking from hibernate or a full shutdown also needs Wake on LAN (or Wake on PCI Express) turned on in the BIOS, and ErP or Deep Sleep turned off so the port keeps standby power. This check cannot see the BIOS.";

        if (snap.PowerRead && snap.ModernStandby && snap.StandbyNetwork == "disconnected")
            yield return "Modern Standby is network disconnected, so the adapter is not kept connected and a magic packet cannot reach it.";

        foreach (var a in snap.Adapters)
        {
            if (a.MagicPacket == "Disabled")
                yield return $"On {Label(a)}, in Device Manager open the adapter, Advanced, and set Wake on Magic Packet to Enabled. Get-NetAdapterPowerManagement shows the same value as WakeOnMagicPacket.";
            if (a.WakeArmed == "no")
                yield return $"On {Label(a)}, in Device Manager open the adapter, Power Management, and tick Allow this device to wake the computer. Then run powercfg /devicequery wake_armed and confirm \"{ArmedName(a)}\" is on the list.";
            if (a.MagicPacket == "Unsupported" && a.WakeArmed == "yes")
                yield return $"{Label(a)} is armed, but the driver does not show a Wake on Magic Packet setting. A packet might still work. The way to know is to try it from another computer on this subnet.";
            if (snap.ModernStandby && (a.ArpOffload == "Disabled" || a.NsOffload == "Disabled"))
                yield return $"On {Label(a)}, set ARP offload and NS offload to Enabled in the adapter's advanced properties so it can answer address lookups while the PC sleeps.";
        }

        yield return "Ticking Only allow a magic packet to wake the computer stops ordinary traffic (Wake on pattern) from waking the PC. Leave Wake on Magic Packet enabled. This check does not change that tick.";
    }

    private static string Detail(WakeAdapter a) =>
        $"Wake on pattern: {MagicText(a.Pattern)}. ARP offload: {MagicText(a.ArpOffload)}. NS offload: {MagicText(a.NsOffload)}.";

    private static string Label(WakeAdapter a) =>
        a.Description.Length > 0 ? a.Description : a.Name.Length > 0 ? a.Name : a.AdapterType;

    private static string ArmedName(WakeAdapter a) => a.Description.Length > 0 ? a.Description : a.Name;

    private static string MacText(string mac) => mac.Length > 0 ? mac : "No MAC address";
    private static string AddressText(WakeAdapter a) =>
        a.Ipv4.Length == 0 ? "No IPv4 address" : a.PrefixLength > 0 ? $"{a.Ipv4}/{a.PrefixLength}" : a.Ipv4;
    private static string BroadcastText(WakeAdapter a) => a.Broadcast.Length > 0 ? a.Broadcast : "No subnet broadcast";
    private static string ArmedText(string state) => state switch { "yes" => "Yes", "no" => "No", _ => "Couldn't read" };
    private static string MagicText(string state) => state switch
    {
        "Enabled" => "On",
        "Disabled" => "Off",
        "Unsupported" => "Not offered",
        _ => "Couldn't read",
    };
}
