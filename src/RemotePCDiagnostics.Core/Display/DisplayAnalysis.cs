using System.Globalization;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Display;

/// <summary>Words and numbers for displays: connector names, modes, and what's wrong with a monitor.</summary>
public static class Displays
{
    /// <summary><c>DISPLAYCONFIG_VIDEO_OUTPUT_TECHNOLOGY</c> to a connector kind.</summary>
    public static DisplayConnector ConnectorOf(int technology) => technology switch
    {
        int.MinValue or 6 or 11 or 13 => DisplayConnector.Internal, // INTERNAL (0x80000000), LVDS, embedded DisplayPort, embedded UDI
        5 => DisplayConnector.Hdmi,
        10 => DisplayConnector.DisplayPort,
        18 => DisplayConnector.UsbC,                               // DisplayPort tunnelled over USB4 / Thunderbolt
        0 => DisplayConnector.Vga,
        4 => DisplayConnector.Dvi,
        15 => DisplayConnector.Wireless,                           // Miracast
        16 => DisplayConnector.UsbAdapter,                         // indirect wired: a USB display adapter or dock (DisplayLink)
        17 => DisplayConnector.Virtual,                            // indirect virtual: remote desktop, a virtual display driver
        -1 or 1 or 2 or 3 or 8 or 9 or 12 or 14 => DisplayConnector.Other,
        _ => DisplayConnector.Unknown,
    };

    public static string ConnectorText(DisplayConnector c) => c switch
    {
        DisplayConnector.Internal => "Built-in screen",
        DisplayConnector.Hdmi => "HDMI",
        // DisplayPort over a USB-C port (alt mode) reports as DisplayPort too; only a USB4/Thunderbolt tunnel is told apart.
        DisplayConnector.DisplayPort => "DisplayPort (or USB-C)",
        DisplayConnector.UsbC => "USB-C (USB4/Thunderbolt)",
        DisplayConnector.Vga => "VGA",
        DisplayConnector.Dvi => "DVI",
        DisplayConnector.Wireless => "Wireless (Miracast)",
        DisplayConnector.UsbAdapter => "USB display adapter",
        DisplayConnector.Virtual => "Virtual display",
        DisplayConnector.Other => "Other connector",
        _ => "Unknown connector",
    };

    /// <summary>A physical connector the person can plug a cable into (not the built-in screen, wireless or virtual).</summary>
    public static bool IsExternalPort(DisplayConnector c) =>
        c is DisplayConnector.Hdmi or DisplayConnector.DisplayPort or DisplayConnector.UsbC or DisplayConnector.Vga or DisplayConnector.Dvi
            or DisplayConnector.UsbAdapter or DisplayConnector.Other or DisplayConnector.Unknown;

    public static string Name(DisplayOutput o)
    {
        if (!string.IsNullOrWhiteSpace(o.MonitorName)) return o.MonitorName!.Trim();
        if (o.Edid?.Name is { } n) return n;
        // A laptop panel's maker (BOE, AU Optronics) means little to the person; it's in the row's details.
        if (o.Connector == DisplayConnector.Internal) return "Built-in screen";
        if (Edid.MakerName(o.Edid?.Manufacturer ?? o.EdidManufacturer) is { } maker) return maker + " monitor";
        return "Monitor";
    }

    /// <summary>The connector and its number when the adapter has more than one of that kind ("HDMI 2").</summary>
    public static string Where(DisplayOutput o, DisplaySnapshot? all = null)
    {
        var text = ConnectorText(o.Connector);
        if (all is null || o.Connector is DisplayConnector.Internal or DisplayConnector.Virtual or DisplayConnector.Wireless) return text;
        var same = all.Outputs.Where(x => x.AdapterId == o.AdapterId && x.Connector == o.Connector).Select(x => x.TargetId).Distinct().Count();
        return same > 1 ? $"{text} #{o.ConnectorInstance.ToString(CultureInfo.InvariantCulture)}" : text;
    }

    public static string Mode(int? w, int? h) => w is > 0 && h is > 0 ? $"{w}×{h}" : "";

    public static string Hz(double? hz) => hz is > 0 ? Math.Round(hz.Value, hz.Value % 1 is > 0.05 and < 0.95 ? 2 : 0).ToString(CultureInfo.InvariantCulture) + " Hz" : "";

    /// <summary>The monitor's native resolution: the driver's preferred mode (supports 5K/6K/8K DisplayID/CTA-861), else the base EDID's preferred timing.</summary>
    public static (int? W, int? H) Native(DisplayOutput o) =>
        o.PreferredWidth is > 0 && o.PreferredHeight is > 0 ? (o.PreferredWidth, o.PreferredHeight)
        : o.Edid is { Valid: true, PreferredWidth: > 0, PreferredHeight: > 0 } e ? (e.PreferredWidth, e.PreferredHeight) : (null, null);

    /// <summary>Running at fewer pixels than the monitor's native mode (rotation allowed for).</summary>
    public static bool BelowNative(DisplayOutput o)
    {
        if (!o.Active || o.Width is not > 0 || o.Height is not > 0) return false;
        var (nw, nh) = Native(o);
        if (nw is null || nh is null) return false;
        var rotated = o.Rotation is 90 or 270;
        var (w, h) = rotated ? (o.Height.Value, o.Width.Value) : (o.Width.Value, o.Height.Value);
        return (long)w * h < (long)nw.Value * nh.Value;
    }

    /// <summary>Running at a slower refresh than the fastest one the monitor offers at this resolution (more than 1 Hz below).</summary>
    public static bool BelowMaxRefresh(DisplayOutput o) =>
        o.Active && o.RefreshHz is > 0 && o.MaxRefreshHz is > 0 && o.RefreshHz.Value < o.MaxRefreshHz.Value - 1;

    /// <summary>Why a connected monitor's EDID is a problem, or null. A built-in screen without one isn't flagged.</summary>
    public static string? EdidProblem(DisplayOutput o)
    {
        if (!o.Available || o.Connector is DisplayConnector.Virtual or DisplayConnector.Wireless) return null;
        if (o.Edid is { } e) return e.Problem;
        return o.Connector == DisplayConnector.Internal ? null : "The monitor didn't send its identity (no EDID): often the cable, an adapter or a KVM switch";
    }

    /// <summary>Connected but inactive is a warning, except for a laptop's built-in screen while another display is active (clamshell / lid closed).</summary>
    public static bool IsInactiveWarning(DisplayOutput o, bool anotherActive = false) =>
        o.Available && !o.Active && !(o.Connector == DisplayConnector.Internal && anotherActive);

    /// <summary>What to look at on one monitor, most important first; empty when nothing.</summary>
    public static IReadOnlyList<string> Problems(DisplayOutput o, bool anotherActive = false)
    {
        var list = new List<string>();
        if (IsInactiveWarning(o, anotherActive)) list.Add("Connected, but Windows isn't showing anything on it");
        if (EdidProblem(o) is { } edid) list.Add(edid);
        if (BelowNative(o))
        {
            var (nw, nh) = Native(o);
            list.Add($"Running at {Mode(o.Width, o.Height)}, below its native {Mode(nw, nh)}");
        }
        if (BelowMaxRefresh(o)) list.Add($"Running at {Hz(o.RefreshHz)}, it can do {Hz(o.MaxRefreshHz)}");
        return list;
    }

    public static string Hdr(DisplayOutput o) => o.HdrSupported switch
    {
        true => o.HdrEnabled == true ? "On" : "Off (supported)",
        false => "Not supported",
        _ => "",
    };

    public static string Scale(DisplayOutput o) => o.ScalePercent is > 0 ? o.ScalePercent.Value.ToString(CultureInfo.InvariantCulture) + "%" : "";

    /// <summary>The graphics vendor a display driver service belongs to (nvlddmkm is NVIDIA), to tie a driver reset to an adapter.</summary>
    public static bool AdapterMatches(string? service, string? adapterName)
    {
        if (service is null || adapterName is null) return false;
        bool Has(string w) => adapterName.Contains(w, StringComparison.OrdinalIgnoreCase);
        return service.StartsWith("nv", StringComparison.OrdinalIgnoreCase) ? Has("NVIDIA")
            : service.StartsWith("amd", StringComparison.OrdinalIgnoreCase) ? Has("AMD") || Has("Radeon")
            : service.StartsWith("igfx", StringComparison.OrdinalIgnoreCase) && Has("Intel");
    }
}

/// <summary>Builds the Displays &amp; video outputs report.</summary>
public static class DisplayAnalysis
{
    /// <summary>Two or more display driver resets in <see cref="GraphicsDriverCrashes.Days"/> days are flagged as repeated.</summary>
    public const int RepeatedResets = 2;

    private static string Plural(int n, string what) => n == 1 ? $"1 {what}" : $"{n} {what}s";

    public static AreaReport Build(DisplaySnapshot snapshot, IReadOnlyList<WinEvent>? events, DisplayFirmwareReading? firmware)
    {
        if (snapshot.Error is not null && events is null && firmware is not { Read: true })
            return AreaReport.Failed("Couldn't check the displays: " + snapshot.Error);
        var cards = new List<AreaCard>();
        var parts = new List<string>();
        if (snapshot.Error is { } err)
            cards.Add(AreaCard.Failed("displays", "Displays", "The displays couldn't be read: " + err));
        else
        {
            AddDisplays(cards, parts, snapshot);
            AddEdid(cards, parts, snapshot);
            AddOutputs(cards, parts, snapshot);
        }
        AddResets(cards, parts, snapshot, events);
        AddFirmware(cards, parts, firmware);
        var status = AreaReport.Worst(cards.Select(c => c.ErrorText is not null ? AreaLevel.Warning : c.Level));
        return new(cards, string.Join(" · ", parts), status);
    }

    private static void AddDisplays(List<AreaCard> cards, List<string> parts, DisplaySnapshot s)
    {
        var monitors = s.Monitors.OrderByDescending(o => o.Primary).ThenByDescending(o => o.Active).ThenBy(o => o.X ?? int.MaxValue).ToList();
        var anyActive = monitors.Any(o => o.Active);
        var rows = new List<AreaRow>();
        foreach (var o in monitors)
        {
            var problems = Displays.Problems(o, anyActive);
            var (nw, nh) = Displays.Native(o);
            var resolution = o.Active ? Displays.Mode(o.Width, o.Height) : "Not in use";
            if (o.Active && nw is not null && Displays.Mode(nw, nh) is { Length: > 0 } native && native != Displays.Mode(o.Width, o.Height)
                && !(o.Rotation is 90 or 270 && Displays.Mode(o.Height, o.Width) == native))
                resolution += $" (native {native})";
            var refresh = o.Active ? Displays.Hz(o.RefreshHz) : "";
            if (o.Active && o.MaxRefreshHz is > 0 && Displays.BelowMaxRefresh(o)) refresh += $" (up to {Displays.Hz(o.MaxRefreshHz)})";
            var detail = new List<string>();
            if (Edid.MakerName(o.Edid?.Manufacturer ?? o.EdidManufacturer) is { } maker) detail.Add("Maker: " + maker);
            if ((o.Edid?.ProductCode ?? o.EdidProductCode) is { } pc and > 0) detail.Add("Model code: " + (o.Edid?.Manufacturer ?? o.EdidManufacturer) + pc.ToString("X4", CultureInfo.InvariantCulture));
            if (o.Edid?.Serial is { } serial) detail.Add("Serial: " + serial);
            if (o.Edid?.DiagonalInches is { } inches) detail.Add($"Size: {inches.ToString(CultureInfo.InvariantCulture)} in ({o.Edid.WidthCm}×{o.Edid.HeightCm} cm)");
            if (o.Edid?.Year is { } year) detail.Add("Made: " + year.ToString(CultureInfo.InvariantCulture));
            if (o.MaxWidth is > 0) detail.Add("Largest mode: " + Displays.Mode(o.MaxWidth, o.MaxHeight));
            if (o.Rotation != 0) detail.Add($"Rotated {o.Rotation}°");
            if (o.BitsPerColor is > 0) detail.Add($"Colour depth: {o.BitsPerColor} bits per channel");
            if (o.Active && o.X is not null) detail.Add($"Position: {o.X}, {o.Y}" + (o.Primary ? " (primary)" : ""));
            if (o.GdiName is { } gdi) detail.Add("Windows name: " + gdi);
            foreach (var p in problems) detail.Add("Look at: " + p);
            rows.Add(new AreaRow(problems.Count > 0 ? AreaLevel.Warning : AreaLevel.Ok,
                [Displays.Name(o) + (o.Primary ? " (primary)" : ""), Displays.Where(o, s), resolution, refresh, Displays.Scale(o), Displays.Hdr(o),
                 o.AdapterName ?? "", problems.Count > 0 ? problems[0] : o.Active ? "Working" : "Connected"],
                Key: o.Key, Detail: string.Join("\n", detail)));
        }
        var warn = rows.Count(r => r.Level == AreaLevel.Warning);
        var active = monitors.Count(o => o.Active);
        var primary = monitors.FirstOrDefault(o => o.Primary);
        var headline = monitors.Count == 0 ? "No display connected"
            : warn > 0 ? $"{Plural(warn, "display")} to look at"
            : $"{Plural(monitors.Count, "display")}, all working";
        var meta = primary is not null
            ? $"Primary: {Displays.Name(primary)} at {Displays.Mode(primary.Width, primary.Height)} {Displays.Hz(primary.RefreshHz)}"
              + (primary.ScalePercent is > 0 ? $", {Displays.Scale(primary)} scaling" : "")
            : "Every monitor Windows sees, its connector, mode, scaling and HDR";
        cards.Add(new("displays", "Displays", warn > 0 ? AreaLevel.Warning : AreaLevel.Ok, headline, meta,
            ["Display", "Connected by", "Resolution", "Refresh rate", "Scaling", "HDR", "Graphics", "Status"], rows,
            EmptyText: "Windows sees no display. On a PC with no monitor, the checks still run; plug one in to test its outputs.", PreserveRowOrder: true));
        parts.Add(monitors.Count == 0 ? "No display" : active == monitors.Count ? Plural(monitors.Count, "display") : $"{active} of {Plural(monitors.Count, "display")} in use");
        if (warn > 0) parts.Add(Plural(warn, "display issue"));
    }

    private static void AddEdid(List<AreaCard> cards, List<string> parts, DisplaySnapshot s)
    {
        var monitors = s.Monitors.Where(o => o.Connector is not (DisplayConnector.Virtual or DisplayConnector.Wireless)).ToList();
        if (monitors.Count == 0) return;
        var rows = monitors.Select(o =>
        {
            var problem = Displays.EdidProblem(o);
            var state = problem ?? (o.Edid is null ? "Not found (normal for some built-in screens)" : "Valid");
            var e = o.Edid;
            return new AreaRow(problem is not null ? AreaLevel.Warning : e is null ? AreaLevel.Neutral : AreaLevel.Ok,
                [Displays.Name(o), Displays.Where(o, s), e?.Version is { } v ? "EDID " + v : "", e is null ? "" : Plural(e.Blocks, "block"), state], Key: o.Key);
        }).ToList();
        var bad = rows.Count(r => r.Level == AreaLevel.Warning);
        cards.Add(new("edid", "Monitor identity (EDID)", bad > 0 ? AreaLevel.Warning : AreaLevel.Ok,
            bad > 0 ? $"{Plural(bad, "monitor")} with a missing or damaged EDID" : "Every monitor identifies itself correctly",
            bad > 0 ? "A missing or damaged EDID usually means a bad cable, adapter or KVM switch: Windows may pick the wrong resolution"
                : "The identity block each monitor sends over the cable: its name, native mode and checksum",
            ["Display", "Connected by", "Version", "Size", "EDID"], rows));
        if (bad > 0) parts.Add(Plural(bad, "EDID problem"));
    }

    private static void AddOutputs(List<AreaCard> cards, List<string> parts, DisplaySnapshot s)
    {
        var outputs = s.Outputs.Where(o => o.Connector != DisplayConnector.Virtual || o.Available).ToList();
        if (outputs.Count == 0) return;
        var anyActive = s.Monitors.Any(o => o.Active);
        var rows = outputs.OrderBy(o => o.AdapterName, StringComparer.CurrentCultureIgnoreCase).ThenBy(o => o.Connector).ThenBy(o => o.ConnectorInstance)
            .Select(o => new AreaRow(Displays.IsInactiveWarning(o, anyActive) ? AreaLevel.Warning : AreaLevel.Neutral,
                [o.AdapterName ?? "Graphics adapter", Displays.Where(o, s), o.Available ? Displays.Name(o) : "",
                 o.Active ? "In use" : o.Available ? "Monitor connected, not in use" : "Nothing connected"], Key: o.Key)).ToList();
        var inactive = outputs.Count(o => Displays.IsInactiveWarning(o, anyActive));
        var adapters = outputs.Select(o => o.AdapterId).Distinct().Count();
        var inUse = outputs.Count(o => o.Active);
        cards.Add(new("outputs", "Video outputs", inactive > 0 ? AreaLevel.Warning : AreaLevel.Ok,
            inactive > 0 ? $"{Plural(inactive, "monitor")} connected but not in use"
                : $"{Plural(outputs.Count, "video output")} on {Plural(adapters, "graphics adapter")}, {inUse} in use",
            inactive > 0 ? "Windows sees the monitor but shows nothing on it: check Settings > Display (Extend or Duplicate), or the monitor's input"
                : "Each connector the graphics drivers report, and what's plugged into it. Use the Video output check to try each port",
            ["Graphics", "Connector", "Monitor", "State"], rows, PreserveRowOrder: true)
            { OpenPage = new AreaPageLink("interactive?test=displayoutputs", "Video output check") });
        if (inactive > 0) parts.Add(Plural(inactive, "monitor") + " not in use");
    }

    private static void AddResets(List<AreaCard> cards, List<string> parts, DisplaySnapshot s, IReadOnlyList<WinEvent>? events)
    {
        if (events is null)
        {
            cards.Add(AreaCard.Failed("resets", "Display driver resets", "The System log couldn't be read."));
            return;
        }
        var incidents = GraphicsDriverCrashes.Incidents(events.Where(GraphicsDriverCrashes.IsResetEvent).ToList(), [], [], []);
        var adapters = s.Outputs.Select(o => o.AdapterName).OfType<string>().Distinct().ToList();
        var rows = incidents.Take(100).Select(i =>
        {
            var adapter = adapters.FirstOrDefault(a => Displays.AdapterMatches(i.Service, a)) ?? (adapters.Count == 1 ? adapters[0] : "");
            var on = s.Monitors.Where(o => adapter.Length > 0 && o.AdapterName == adapter).Select(Displays.Name).ToList();
            return new AreaRow(AreaLevel.Warning,
                [i.Time.ToLocalTime().ToString("g", CultureInfo.CurrentCulture), i.What, adapter, on.Count > 0 ? string.Join(", ", on) : ""],
                [i.Time.UtcTicks.ToString("D20", CultureInfo.InvariantCulture), null, null, null],
                Detail: string.Join("\n", i.Evidence), ReviewKeys: i.ReviewKeys);
        }).ToList();
        var repeated = incidents.Count >= RepeatedResets;
        cards.Add(new("resets", "Display driver resets", repeated ? AreaLevel.Warning : incidents.Count > 0 ? AreaLevel.Neutral : AreaLevel.Ok,
            incidents.Count == 0 ? $"No display driver resets in the last {GraphicsDriverCrashes.Days} days"
                : $"{Plural(incidents.Count, "display driver reset")} in the last {GraphicsDriverCrashes.Days} days",
            incidents.Count == 0 ? "The screen going black for a moment and coming back is a driver reset; none were logged"
                : "Each reset with the graphics adapter and the displays on it. Crashes & unexpected restarts ties them to the driver version",
            ["When", "What", "Graphics", "Displays on it"], rows,
            EmptyText: "Windows logged no display driver resets.") { EventCount = incidents.Count, WindowDays = GraphicsDriverCrashes.Days });
        if (incidents.Count > 0) parts.Add(Plural(incidents.Count, "driver reset"));
    }

    private static void AddFirmware(List<AreaCard> cards, List<string> parts, DisplayFirmwareReading? firmware)
    {
        if (firmware is null) return;
        if (!firmware.Read)
        {
            cards.Add(new("firmware", "Video ports in the BIOS", AreaLevel.Neutral, firmware.NeedsAgent ? "Needs the Agent" : "Not read",
                firmware.Reason!, [], [], Note: firmware.Reason));
            return;
        }
        var off = firmware.Disabled;
        cards.Add(new("firmware", "Video ports in the BIOS", off.Count > 0 ? AreaLevel.Warning : AreaLevel.Ok,
            off.Count > 0 ? "Video outputs disabled in BIOS: " + string.Join(", ", off.Select(x => x.Name))
                : firmware.Settings.Count > 0 ? "No video outputs turned off in the BIOS" : "The BIOS has no video output switches",
            off.Count > 0 ? "Turned off in the PC's firmware setup: those ports show no picture until they're turned back on there (read only)"
                : $"{firmware.Maker} BIOS settings, read only",
            ["Setting", "Value"],
            [.. firmware.Settings.OrderByDescending(x => x.Disabled).Select(x => new AreaRow(x.Disabled ? AreaLevel.Warning : AreaLevel.Ok, [x.Name, x.Value], Key: x.Name))],
            EmptyText: $"{firmware.Maker}'s BIOS lists no setting that turns video outputs off."));
        if (off.Count > 0) parts.Add(Plural(off.Count, "video port") + " off in BIOS");
    }
}
