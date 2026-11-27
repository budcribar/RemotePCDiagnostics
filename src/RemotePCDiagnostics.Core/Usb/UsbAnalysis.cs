using System.Globalization;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Usb;

/// <summary>A device as the USB check shows it: the node, the hub port it's on (when the hub reported it) and the hub.</summary>
public sealed record UsbDeviceView(UsbNode Node, UsbNode? Hub, UsbPortInfo? Port, bool Usb4)
{
    public string Where => UsbAnalysis.PortLabel(Hub, Port, Node.Port);
    public UsbSpeed Speed => Port?.Speed ?? UsbSpeed.Unknown;
    public bool Downgraded => Port?.SpeedDowngraded == true;
}

/// <summary>Several devices behind the same hub or dock that went away within a couple of seconds of each other.</summary>
public sealed record UsbDrop(string HubId, string HubName, IReadOnlyList<string> Devices, DateTimeOffset At);

/// <summary>Builds the USB ports &amp; devices report and the parts of it the interactive port check reuses.</summary>
public static class UsbAnalysis
{
    /// <summary>USB errors in the System log: the hub and host controller drivers, and Plug and Play for a USB device.</summary>
    public static readonly IReadOnlyList<string> EventProviders =
    [
        "Microsoft-Windows-USB-USBHUB3", "Microsoft-Windows-USB-USBXHCI", "Microsoft-Windows-USB-USBHUB", "Microsoft-Windows-USB-USBPORT",
        "USBHUB3", "USBXHCI", "usbhub", "USBHUB", "usbport", "Microsoft-Windows-Kernel-PnP",
    ];

    public const int EventDays = 7;

    /// <summary>Warnings and errors from <see cref="EventProviders"/> in the last <paramref name="days"/> days.</summary>
    public static string EventQuery(int days = EventDays) =>
        "*[System[(" + string.Join(" or ", EventProviders.Select(p => $"Provider[@Name='{p}']")) + ")"
        + " and (Level=1 or Level=2 or Level=3)"
        + $" and TimeCreated[timediff(@SystemTime) <= {(long)days * 86_400_000}]]]";

    /// <summary>Only the Plug and Play events about a USB device count; the hub and controller drivers' all do.</summary>
    public static bool IsUsbEvent(WinEvent e) =>
        !e.Provider.Equals("Microsoft-Windows-Kernel-PnP", StringComparison.OrdinalIgnoreCase)
        || e.Message.Contains(@"USB\", StringComparison.OrdinalIgnoreCase)
        || e.Data.Any(d => d.StartsWith(@"USB\", StringComparison.OrdinalIgnoreCase));

    public static string SpeedText(UsbSpeed speed, bool usb4 = false) => speed switch
    {
        UsbSpeed.Low => "Low speed (1.5 Mbps)",
        UsbSpeed.Full => "Full speed (12 Mbps)",
        UsbSpeed.High => "High speed, USB 2 (480 Mbps)",
        UsbSpeed.Super => usb4 ? "SuperSpeed over USB4 (5 Gbps)" : "SuperSpeed, USB 3 (5 Gbps)",
        UsbSpeed.SuperPlus => usb4 ? "SuperSpeed+ over USB4 (10 Gbps or more)" : "SuperSpeed+, USB 3 (10 Gbps or more)",
        _ => "Unknown",
    };

    /// <summary>The fastest the device could run, for a downgraded port.</summary>
    public static string CapableText(UsbPortInfo p) =>
        p.SuperSpeedPlusCapable == true ? "SuperSpeed+ (10 Gbps or more)" : p.SuperSpeedCapable == true ? "SuperSpeed (5 Gbps)" : "Unknown";

    public static string PortLabel(UsbNode? hub, UsbPortInfo? port, int? number)
    {
        var n = port?.Number ?? number;
        var where = hub is null ? "" : hub.Kind == UsbNodeKind.RootHub ? "PC" : hub.Name;
        var parts = new List<string>();
        if (where.Length > 0) parts.Add(where);
        if (n is { } x) parts.Add("port " + x.ToString(CultureInfo.InvariantCulture));
        if (port?.TypeC == true) parts.Add("USB-C");
        return parts.Count == 0 ? "Unknown port" : string.Join(" · ", parts);
    }

    /// <summary>The USB devices (not their functions, the controllers or the root hubs), each with its hub port.</summary>
    public static IReadOnlyList<UsbDeviceView> Devices(UsbSnapshot tree)
    {
        var byId = tree.Nodes.ToDictionary(n => n.Id, StringComparer.OrdinalIgnoreCase);
        return [.. tree.Nodes.Where(n => n.Kind is UsbNodeKind.Device or UsbNodeKind.Hub).Select(n =>
        {
            var hub = n.ParentId is { } p && byId.TryGetValue(p, out var h) && h.IsHub ? h : null;
            var port = hub?.Ports?.FirstOrDefault(x => x.Number == n.Port);
            return new UsbDeviceView(n, hub, port, IsUsb4(n, byId));
        })];
    }

    private static bool IsUsb4(UsbNode n, Dictionary<string, UsbNode> byId)
    {
        UsbNode? cur = n;
        for (var i = 0; cur is not null && i < 20; i++)
        {
            if (cur.Kind == UsbNodeKind.Controller) return cur.Name.Contains("USB4", StringComparison.OrdinalIgnoreCase);
            cur = cur.ParentId is { } p && byId.TryGetValue(p, out var parent) ? parent : null;
        }
        return false;
    }

    /// <summary>The nearest hub between a node and the PC that isn't a root hub (a dock or USB hub), or null.</summary>
    public static UsbNode? ExternalHub(UsbNode n, IReadOnlyDictionary<string, UsbNode> byId)
    {
        var cur = n.ParentId is { } p && byId.TryGetValue(p, out var parent) ? parent : null;
        for (var i = 0; cur is not null && i < 20; i++)
        {
            if (cur.Kind == UsbNodeKind.Hub) return cur;
            if (cur.Kind is UsbNodeKind.RootHub or UsbNodeKind.Controller) return null;
            cur = cur.ParentId is { } pp && byId.TryGetValue(pp, out var next) ? next : null;
        }
        return null;
    }

    /// <summary>Hub ports reporting a failure with no device in the tree to show it (the device never came up).</summary>
    public static IReadOnlyList<(UsbNode Hub, UsbPortInfo Port)> FailedPorts(UsbSnapshot tree)
    {
        var taken = tree.Nodes.Where(n => n.ParentId is not null && n.Port is not null).Select(n => (n.ParentId!.ToUpperInvariant(), n.Port!.Value)).ToHashSet();
        return [.. tree.Nodes.Where(n => n.IsHub).SelectMany(h => (h.Ports ?? []).Where(p => UsbPortStatus.IsFailure(p.Status)
            && !taken.Contains((h.Id.ToUpperInvariant(), p.Number))).Select(p => (h, p)))];
    }

    /// <summary>
    /// Devices behind the same hub that were in <paramref name="before"/> and gone from <paramref name="after"/>: two or more at once from
    /// one hub or dock points at the dock, its cable or its power, not at the devices. Each USB device counts once (a dock's network
    /// adapter and audio device are USB devices too).
    /// </summary>
    public static IReadOnlyList<UsbDrop> Drops(UsbSnapshot before, UsbSnapshot after, DateTimeOffset at)
    {
        if (before.Error is not null || after.Error is not null) return [];
        var still = after.Nodes.Select(n => n.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var byId = before.Nodes.ToDictionary(n => n.Id, StringComparer.OrdinalIgnoreCase);
        var gone = before.Nodes.Where(n => n.Kind == UsbNodeKind.Device && !still.Contains(n.Id)).ToList();
        // The hub itself still there: unplugging a hub or dock takes its devices with it, and that's the person, not a drop.
        return [.. gone.Select(n => (Node: n, Hub: ExternalHub(n, byId)))
            .Where(x => x.Hub is not null && still.Contains(x.Hub.Id))
            .GroupBy(x => x.Hub!.Id, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count(x => x.Node.Kind == UsbNodeKind.Device) >= 2)
            .Select(g => new UsbDrop(g.Key, g.First().Hub!.Name, [.. g.Where(x => x.Node.Kind == UsbNodeKind.Device).Select(x => x.Node.Name).Distinct(StringComparer.CurrentCultureIgnoreCase)], at))];
    }

    private static string Plural(int n, string what) => n == 1 ? $"1 {what}" : $"{n} {what}s";

    public static AreaReport Build(UsbSnapshot tree, IReadOnlyList<WinEvent>? events, UsbFirmwareReading? firmware, IReadOnlyList<UsbDrop>? drops = null)
    {
        if (tree.Error is not null && events is null && firmware is not { Read: true })
            return AreaReport.Failed("Couldn't check the USB ports and devices: " + tree.Error);
        var cards = new List<AreaCard>();
        var parts = new List<string>();

        if (tree.Error is { } err)
            cards.Add(AreaCard.Failed("devices", "USB devices", "The USB devices couldn't be read: " + err));
        else
        {
            var devices = Devices(tree);
            var failedPorts = FailedPorts(tree);
            AddDevices(cards, parts, devices, failedPorts);
            AddSpeed(cards, parts, devices);
            AddHubs(cards, tree);
            AddDocks(cards, tree);
        }
        if (drops is { Count: > 0 }) AddDrops(cards, parts, drops);
        AddEvents(cards, parts, events);
        AddFirmware(cards, parts, firmware);

        var status = AreaReport.Worst(cards.Select(c => c.ErrorText is not null ? AreaLevel.Warning : c.Level));
        return new(cards, string.Join(" · ", parts), status);
    }

    private static void AddDevices(List<AreaCard> cards, List<string> parts, IReadOnlyList<UsbDeviceView> devices, IReadOnlyList<(UsbNode Hub, UsbPortInfo Port)> failedPorts)
    {
        var rows = new List<AreaRow>();
        var problems = 0;
        var disabled = 0;
        foreach (var d in devices.OrderBy(d => d.Node.ProblemCode == 0 && !(d.Port is { } p && UsbPortStatus.IsFailure(p.Status)))
                     .ThenBy(d => d.Node.Kind == UsbNodeKind.Hub).ThenBy(d => d.Node.Name, StringComparer.CurrentCultureIgnoreCase))
        {
            var n = d.Node;
            var portFailure = d.Port is { } port && UsbPortStatus.IsFailure(port.Status) ? port.Status : null;
            var problem = n.ProblemCode != 0 ? new ProblemDevice(n.Name, "USB", n.Id, n.ProblemCode, "") : null;
            var level = problem is { IsDisabledOnly: true } ? AreaLevel.Neutral
                : problem is not null || portFailure is UsbPortStatus.FailedEnumeration or UsbPortStatus.GeneralFailure ? AreaLevel.Error
                : portFailure is not null || d.Downgraded ? AreaLevel.Warning
                : AreaLevel.Ok;
            if (problem is { IsDisabledOnly: true }) disabled++;
            else if (level == AreaLevel.Error) problems++;
            var state = problem?.FriendlyError ?? (portFailure is not null ? UsbPortStatus.Describe(portFailure) : d.Downgraded ? "Running below its speed" : "Working");
            var id = n.Vid is not null && n.Pid is not null ? $"{n.Vid}:{n.Pid}" : "";
            rows.Add(new AreaRow(level,
                [n.Kind == UsbNodeKind.Hub ? n.Name + " (hub)" : n.Name, d.Where, SpeedText(d.Speed, d.Usb4), id, state],
                Key: n.Id,
                Actions: problem is not null
                    ? [new AreaAction(problem.IsDisabledOnly ? RemediationKind.EnableDevice : RemediationKind.RestartDevice,
                        problem.IsDisabledOnly ? "Enable device" : "Restart device", n.Id, n.Name)]
                    : null));
        }
        foreach (var (hub, port) in failedPorts)
        {
            var level = port.Status is UsbPortStatus.FailedEnumeration or UsbPortStatus.GeneralFailure ? AreaLevel.Error : AreaLevel.Warning;
            if (level == AreaLevel.Error) problems++;
            rows.Add(new AreaRow(level, ["Device that didn't start", PortLabel(hub, port, null), SpeedText(port.Speed),
                port.Vid is not null ? $"{port.Vid}:{port.Pid}" : "", UsbPortStatus.Describe(port.Status)], Key: hub.Id + "#" + port.Number.ToString(CultureInfo.InvariantCulture)));
        }

        var warnings = rows.Count(r => r.Level == AreaLevel.Warning);
        var count = devices.Count(d => d.Node.Kind == UsbNodeKind.Device);
        var headline = problems > 0 ? $"{Plural(problems, "USB device")} with a problem"
            : warnings > 0 ? $"{Plural(warnings, "USB device")} to look at"
            : count == 0 ? "No USB devices connected" : $"{Plural(count, "USB device")}, all working";
        if (disabled > 0) headline += $" · {disabled} disabled";
        var meta = rows.Where(r => r.Level >= AreaLevel.Warning).Take(3).Select(r => $"{r.Values[0]} ({r.Values[4]})").ToList();
        cards.Add(new("devices", "USB devices", AreaReport.Worst(rows.Select(r => r.Level)) switch
            {
                DiagnosticStatus.Error => AreaLevel.Error, DiagnosticStatus.Warning => AreaLevel.Warning, _ => AreaLevel.Ok,
            },
            headline, meta.Count > 0 ? string.Join(" · ", meta) : "Every USB device Windows sees, the port it's on and its speed",
            ["Device", "Connected to", "Speed", "ID", "Status"], rows,
            EmptyText: "No USB devices are connected."));
        parts.Add(problems > 0 ? $"{Plural(problems, "USB problem")}" : $"{Plural(count, "USB device")}");
    }

    private static void AddSpeed(List<AreaCard> cards, List<string> parts, IReadOnlyList<UsbDeviceView> devices)
    {
        var slow = devices.Where(d => d.Downgraded).ToList();
        var known = devices.Count(d => d.Port?.SuperSpeedCapable is not null);
        cards.Add(new("speed", "USB 3 speed", slow.Count > 0 ? AreaLevel.Warning : AreaLevel.Ok,
            slow.Count > 0 ? $"{Plural(slow.Count, "device")} running below its speed" : known > 0 ? "Every device runs at its full speed" : "No speed limits found",
            slow.Count > 0 ? "A USB 3 device on a USB 2 link: try another port or cable, or plug it in directly instead of through a hub" : "USB 3 devices on USB 3 links",
            ["Device", "Connected to", "Runs at", "Can run at"],
            [.. slow.Select(d => new AreaRow(AreaLevel.Warning, [d.Node.Name, d.Where, SpeedText(d.Speed, d.Usb4), CapableText(d.Port!)], Key: d.Node.Id))],
            EmptyText: "No device is running below the speed it can do."));
        if (slow.Count > 0) parts.Add($"{Plural(slow.Count, "slow USB link")}");
    }

    private static void AddHubs(List<AreaCard> cards, UsbSnapshot tree)
    {
        var rows = new List<AreaRow>();
        foreach (var c in tree.Nodes.Where(n => n.Kind is UsbNodeKind.Controller or UsbNodeKind.RootHub or UsbNodeKind.Hub))
        {
            var ports = c.Ports ?? [];
            var used = ports.Count(p => p.HasDevice);
            var problem = c.ProblemCode != 0 ? new ProblemDevice(c.Name, "USB", c.Id, c.ProblemCode, "") : null;
            var kind = c.Kind switch { UsbNodeKind.Controller => "Host controller", UsbNodeKind.RootHub => "Root hub", _ => "Hub" };
            var type = c.HubType switch { 3 => "USB 3", 2 => "USB 2", _ => c.Kind == UsbNodeKind.Controller && c.Name.Contains("USB4", StringComparison.OrdinalIgnoreCase) ? "USB4" : "" };
            rows.Add(new AreaRow(problem is null ? AreaLevel.Neutral : problem.IsDisabledOnly ? AreaLevel.Neutral : AreaLevel.Error,
                [c.Name, kind, type, c.IsHub ? $"{used} of {ports.Count}" : "", problem?.FriendlyError ?? "Working"], Key: c.Id,
                Actions: problem is null ? null : [new AreaAction(problem.IsDisabledOnly ? RemediationKind.EnableDevice : RemediationKind.RestartDevice,
                    problem.IsDisabledOnly ? "Enable device" : "Restart device", c.Id, c.Name)]));
        }
        var bad = rows.Count(r => r.Level == AreaLevel.Error);
        var controllers = tree.Nodes.Count(n => n.Kind == UsbNodeKind.Controller);
        cards.Add(new("controllers", "Controllers & hubs", bad > 0 ? AreaLevel.Error : AreaLevel.Ok,
            bad > 0 ? $"{Plural(bad, "controller or hub")} with a problem" : $"{Plural(controllers, "USB controller")} working",
            "Ports in use counts the hub's ports with a device on them, including the hidden USB 2 half of each USB 3 port",
            ["Controller or hub", "Kind", "Type", "Ports in use", "Status"], rows, EmptyText: "No USB controllers were found.", PreserveRowOrder: true));
    }

    private static readonly (string Word, string Kind)[] FunctionKinds =
        [("Net", "network"), ("MEDIA", "audio"), ("AudioEndpoint", "audio"), ("Monitor", "display"), ("Display", "display"), ("HIDClass", "input"),
         ("Keyboard", "input"), ("Mouse", "input"), ("DiskDrive", "storage"), ("Camera", "camera"), ("Image", "camera"), ("Bluetooth", "Bluetooth")];

    private static void AddDocks(List<AreaCard> cards, UsbSnapshot tree)
    {
        var byId = tree.Nodes.ToDictionary(n => n.Id, StringComparer.OrdinalIgnoreCase);
        // The top-most external hub of each chain: a dock's own hubs sit under it.
        var groups = tree.Nodes.Where(n => n.Kind is UsbNodeKind.Device or UsbNodeKind.Function)
            .Select(n => (Node: n, Hub: TopHub(n, byId)))
            .Where(x => x.Hub is not null).GroupBy(x => x.Hub!.Id, StringComparer.OrdinalIgnoreCase).ToList();
        if (groups.Count == 0) return;
        var rows = groups.Select(g =>
        {
            var hub = byId[g.Key];
            var devices = g.Where(x => x.Node.Kind == UsbNodeKind.Device).Select(x => x.Node).ToList();
            var kinds = g.Select(x => FunctionKinds.FirstOrDefault(k => string.Equals(k.Word, x.Node.Class, StringComparison.OrdinalIgnoreCase)).Kind)
                .OfType<string>().Distinct().ToList();
            var bad = g.Count(x => x.Node.ProblemCode != 0 && x.Node.ProblemCode != 22);
            var where = PortLabel(hub.ParentId is { } p && byId.TryGetValue(p, out var ph) ? ph : null,
                hub.ParentId is { } pp && byId.TryGetValue(pp, out var phub) ? phub.Ports?.FirstOrDefault(x => x.Number == hub.Port) : null, hub.Port);
            return new AreaRow(bad > 0 ? AreaLevel.Warning : AreaLevel.Neutral,
                [hub.Name, where, Plural(devices.Count, "device"), kinds.Count > 0 ? string.Join(", ", kinds) : "", bad > 0 ? $"{Plural(bad, "device")} with a problem" : "Working"],
                Key: hub.Id, Detail: string.Join("\n", devices.Select(d => d.Name)));
        }).ToList();
        cards.Add(new("docks", "Docks & USB hubs", rows.Any(r => r.Level == AreaLevel.Warning) ? AreaLevel.Warning : AreaLevel.Ok,
            Plural(rows.Count, "dock or hub") + " connected",
            "Devices grouped by the dock or hub they sit behind. Several of them dropping at once points at the dock or its cable",
            ["Dock or hub", "Connected to", "Devices", "Also has", "Status"], rows));
    }

    private static UsbNode? TopHub(UsbNode n, IReadOnlyDictionary<string, UsbNode> byId)
    {
        UsbNode? top = null;
        for (var hub = ExternalHub(n, byId); hub is not null; hub = ExternalHub(hub, byId)) top = hub;
        return top;
    }

    private static void AddDrops(List<AreaCard> cards, List<string> parts, IReadOnlyList<UsbDrop> drops)
    {
        cards.Add(new("drops", "Devices dropping together", AreaLevel.Warning,
            $"{Plural(drops.Count, "dock or hub")} lost several devices at once",
            "When everything behind one dock or hub goes at the same moment, suspect the dock, its cable or its power, not the devices",
            ["Dock or hub", "Devices that dropped", "When"],
            [.. drops.Select(d => new AreaRow(AreaLevel.Warning, [d.HubName, string.Join(", ", d.Devices), d.At.ToLocalTime().ToString("g", CultureInfo.CurrentCulture)], Key: d.HubId))]));
        parts.Add($"{Plural(drops.Count, "dock drop")}");
    }

    private static void AddEvents(List<AreaCard> cards, List<string> parts, IReadOnlyList<WinEvent>? events)
    {
        if (events is null)
        {
            cards.Add(AreaCard.Failed("events", "USB errors in the System log", "The System log couldn't be read."));
            return;
        }
        var usb = events.Where(IsUsbEvent).ToList();
        var overcurrent = usb.Count(e => e.Message.Contains("current", StringComparison.OrdinalIgnoreCase) || e.Message.Contains("surge", StringComparison.OrdinalIgnoreCase));
        var resets = usb.Count(e => e.Message.Contains("reset", StringComparison.OrdinalIgnoreCase));
        var meta = new List<string>();
        if (overcurrent > 0) meta.Add($"{overcurrent} power surge or over-current");
        if (resets > 0) meta.Add($"{Plural(resets, "port reset")}");
        cards.Add(new("events", "USB errors in the System log", usb.Count > 0 ? AreaLevel.Warning : AreaLevel.Ok,
            usb.Count > 0 ? $"{Plural(usb.Count, "USB error")} in the last {EventDays} days" : $"No USB errors in the last {EventDays} days",
            meta.Count > 0 ? string.Join(" · ", meta) : "Hub and USB controller warnings and errors Windows logged",
            ["When", "Source", "Event", "Message"],
            [.. usb.Take(100).Select(e => new AreaRow(AreaLevel.Warning,
                [e.Time.ToLocalTime().ToString("g", CultureInfo.CurrentCulture), e.Source, e.EventId.ToString(CultureInfo.InvariantCulture), e.ShortMessage],
                [e.Time.UtcTicks.ToString("D20", CultureInfo.InvariantCulture), null, null, null], Detail: e.Message))],
            EmptyText: "Windows logged no USB hub or controller errors.") { EventCount = usb.Count });
        if (usb.Count > 0) parts.Add($"{Plural(usb.Count, "USB error")} logged");
    }

    private static void AddFirmware(List<AreaCard> cards, List<string> parts, UsbFirmwareReading? firmware)
    {
        if (firmware is null) return;
        if (!firmware.Read)
        {
            cards.Add(new("firmware", "USB ports in the BIOS", AreaLevel.Neutral, firmware.NeedsAgent ? "Needs the Agent" : "Not read",
                firmware.Reason!, [], [], Note: firmware.Reason));
            return;
        }
        var off = firmware.Disabled;
        cards.Add(new("firmware", "USB ports in the BIOS", off.Count > 0 ? AreaLevel.Warning : AreaLevel.Ok,
            off.Count > 0 ? "USB ports disabled in BIOS: " + string.Join(", ", off.Select(s => s.Name)) : firmware.Settings.Count > 0 ? "No USB ports turned off in the BIOS" : "The BIOS has no USB port switches",
            off.Count > 0 ? "Turned off in the PC's firmware setup: those ports can't work until they're turned back on there (read only)" : $"{firmware.Maker} BIOS settings, read only",
            ["Setting", "Value"],
            [.. firmware.Settings.OrderByDescending(s => s.Disabled).Select(s => new AreaRow(s.Disabled ? AreaLevel.Warning : AreaLevel.Ok, [s.Name, s.Value], Key: s.Name))],
            EmptyText: $"{firmware.Maker}'s BIOS lists no setting that turns USB ports off."));
        if (off.Count > 0) parts.Add($"{Plural(off.Count, "port setting")} off in BIOS");
    }
}
