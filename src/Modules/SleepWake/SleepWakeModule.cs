using System.Globalization;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>One wake from sleep (Power-Troubleshooter event 1): when it slept, when it woke and what woke it.</summary>
public sealed record WakeEvent(DateTimeOffset SleepTime, DateTimeOffset WakeTime, string Source, string TimerOwner)
{
    public TimeSpan Slept => WakeTime > SleepTime ? WakeTime - SleepTime : TimeSpan.Zero;
    public bool ByTimer => TimerOwner.Length > 0;
    /// <summary>Woken by a network adapter (Wake on LAN, or traffic the adapter is set to wake on).</summary>
    public bool ByNetwork => SleepWakeModule.IsNetworkDevice(Source);
    /// <summary>Nobody touched the PC: a wake timer or a network adapter woke it.</summary>
    public bool Unexpected => ByTimer || ByNetwork;

    public static WakeEvent? From(WinEvent e)
    {
        if (SleepWakeParsers.Time(e.DataAt(0, "SleepTime")) is not { } sleep || SleepWakeParsers.Time(e.DataAt(1, "WakeTime")) is not { } wake) return null;
        return new(sleep, wake, e.NamedData.GetValueOrDefault("WakeSourceText", "").Trim(), e.NamedData.GetValueOrDefault("WakeTimerOwner", "").Trim());
    }

    public string Because => ByTimer ? $"Wake timer: {TimerOwner}" : Source.Length > 0 ? Source : "Unknown (Windows didn't record the source)";
}

/// <summary>What the sleep check read. Null fields couldn't be read (a tool failed or needs administrator rights).</summary>
public sealed record SleepWakeFacts(
    SleepStates? States,
    IReadOnlyList<PowerRequest>? Requests,
    IReadOnlyList<WakeTimer>? Timers,
    IReadOnlyList<string>? WakeArmed,
    IReadOnlyList<LastWakeSource>? LastWake,
    IReadOnlyList<WinEvent>? Events,
    IReadOnlyList<StandbySession>? Standby,
    IReadOnlyList<SleepPeriod>? Sleeps = null);

/// <summary>
/// Sleep, wake and standby battery drain: the sleep states the PC has (Modern Standby or S3), what keeps it awake now, wake timers,
/// the devices allowed to wake it, recent wakes and failed resumes from the System log, and how much battery each sleep on battery
/// used (from the battery report). Each wake-armed device carries a fix that stops it waking the PC (<see cref="RemediationKind.DisableDeviceWake"/>, undoable).
/// </summary>
public sealed class SleepWakeModule(SystemCommandRunner commands, Plugins.IHostQueries? host = null) : AreaModuleBase(commands.Log)
{
    public const string ModuleName = ModuleSlugs.SleepWake;
    public const int EventDays = 14;
    /// <summary>Unexpected wakes (timers, network) in <see cref="EventDays"/> days at which the wakes card warns.</summary>
    public const int UnexpectedWakesWarn = 1;

    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.SleepWake;
    public override string DisplayName => "Sleep, wake & standby drain";
    protected override string FailedMessage => "Couldn't read this PC's sleep and wake settings.";

    public static string PowerCfg => DeviceWake.PowerCfg;

    /// <summary>Kernel-Power 41 (restarted without a clean shutdown), 42 (entering sleep), 107 (resumed), 506/507 (Modern Standby
    /// entry/exit) and Power-Troubleshooter 1 (woke, with the wake source), in the last <paramref name="days"/> days.</summary>
    public static string EventQuery(int days) =>
        "*[System[((Provider[@Name='Microsoft-Windows-Kernel-Power'] and (EventID=41 or EventID=42 or EventID=107 or EventID=506 or EventID=507))"
        + " or (Provider[@Name='Microsoft-Windows-Power-Troubleshooter'] and EventID=1))"
        + $" and TimeCreated[timediff(@SystemTime) <= {(long)days * 86_400_000}]]]";

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        const int total = 7;
        async Task<string?> Run(int step, string what, params string[] args)
        {
            progress.ReportStep(step, total, what);
            var pr = await commands.RunAsync(PowerCfg, args, ct).ConfigureAwait(false);
            return pr is { ExitCode: 0 } ? pr.StdOut : null;
        }

        var states = SleepWakeParsers.ParseSleepStates(await Run(1, "Checking sleep states…", "/a").ConfigureAwait(false));
        var requestsOut = await Run(2, "Checking what keeps the PC awake…", "/requests").ConfigureAwait(false);
        var timersOut = await Run(3, "Checking wake timers…", "/waketimers").ConfigureAwait(false);
        var armedOut = await Run(4, "Checking devices that can wake the PC…", "/devicequery", "wake_armed").ConfigureAwait(false);
        var lastOut = await Run(5, "Checking what woke the PC last…", "/lastwake").ConfigureAwait(false);

        progress.ReportStep(6, total, "Reading sleep and wake events…");
        var events = await new WindowsEventLog(commands, host, ModuleName).QueryAsync("System", EventQuery(EventDays), 500, ct).ConfigureAwait(false);

        progress.ReportStep(7, total, "Measuring battery drain while asleep…");
        var report = await ReadBatteryReportAsync(ct).ConfigureAwait(false);
        var standby = StandbyDrain.Parse(report);

        var facts = new SleepWakeFacts(states,
            SleepWakeParsers.ParseRequests(requestsOut),
            timersOut is null ? null : SleepWakeParsers.ParseWakeTimers(timersOut),
            armedOut is null ? null : DeviceWake.ParseArmed(armedOut),
            lastOut is null ? null : SleepWakeParsers.ParseLastWake(lastOut),
            events, standby, StandbyDrain.ParseSleeps(report));
        if (states is null && facts.WakeArmed is null && events is null && standby is null) return AreaReport.Failed(FailedMessage);
        return Build(facts, DateTimeOffset.Now);
    }

    /// <summary>The battery report XML; null when it couldn't be made (a PC without a battery has none).</summary>
    private async Task<string?> ReadBatteryReportAsync(CancellationToken ct)
    {
        var path = Path.Combine(Path.GetTempPath(), $"rpcd-battery-{Guid.NewGuid():N}.xml");
        try
        {
            var pr = await commands.RunAsync(PowerCfg, StandbyDrain.Args(path), ct).ConfigureAwait(false);
            if (pr is not { ExitCode: 0 } || !File.Exists(path)) return null;
            return await File.ReadAllTextAsync(path, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { LogWarn($"{Name}: battery report unreadable: {ex.Message}"); return null; }
        finally { try { File.Delete(path); } catch { } }
    }

    private static readonly string[] NetworkWords = ["ethernet", "wi-fi", "wifi", "wireless", "wlan", "network", "gbe", "lan "];

    /// <summary>A network adapter by its usual names ("Intel(R) Ethernet Controller I225-V", "Realtek PCIe GbE Family Controller", "Intel(R) Wi-Fi 6 AX201").</summary>
    public static bool IsNetworkDevice(string? name) =>
        !string.IsNullOrWhiteSpace(name) && NetworkWords.Any(w => (name + " ").Contains(w, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// A USB host controller or hub ("AMD USB 3.10 eXtensible Host Controller - 1.10 (Microsoft)", "USB Root Hub (USB 3.0)"). When a USB
    /// keyboard or mouse wakes the PC, Windows often names the controller it hangs off instead of the device.
    /// </summary>
    public static bool IsUsbController(string? name) =>
        !string.IsNullOrWhiteSpace(name) && name.Contains("USB", StringComparison.OrdinalIgnoreCase)
        && (name.Contains("Host Controller", StringComparison.OrdinalIgnoreCase) || name.Contains("xHCI", StringComparison.OrdinalIgnoreCase)
            || name.Contains("Hub", StringComparison.OrdinalIgnoreCase));

    /// <summary>A keyboard, mouse or other input device that usually sits behind a USB controller (HID devices).</summary>
    public static bool IsUsbInput(string? name) =>
        !string.IsNullOrWhiteSpace(name) && (name.Contains("HID", StringComparison.OrdinalIgnoreCase) || name.Contains("USB", StringComparison.OrdinalIgnoreCase)
            || name.Contains("keyboard", StringComparison.OrdinalIgnoreCase) || name.Contains("mouse", StringComparison.OrdinalIgnoreCase));

    /// <summary>How close a battery-report sleep's end must be to a logged wake to count as the same sleep.</summary>
    public static readonly TimeSpan SameWake = TimeSpan.FromMinutes(3);

    public static AreaReport Build(SleepWakeFacts f, DateTimeOffset now)
    {
        var cards = new List<AreaCard>();
        var parts = new List<string>();
        var wakes = (f.Events ?? []).Where(e => e.EventId == 1 && e.Provider.EndsWith("Power-Troubleshooter", StringComparison.OrdinalIgnoreCase))
            .Select(WakeEvent.From).OfType<WakeEvent>().OrderByDescending(w => w.WakeTime).ToList();

        cards.Add(StatesCard(f.States, parts));
        cards.Add(DrainCard(f, parts));
        cards.Add(WakesCard(f, wakes, now, parts));
        cards.Add(DevicesCard(f, wakes, parts));
        cards.Add(TimersCard(f.Timers, wakes));
        cards.Add(BlockersCard(f.Requests, parts));

        var status = AreaReport.Worst(cards.Select(c => c.ErrorText is not null ? AreaLevel.Neutral : c.Level));
        return new(cards, string.Join(" · ", parts), status);
    }

    private static AreaCard StatesCard(SleepStates? s, List<string> parts)
    {
        if (s is null) return AreaCard.Failed("states", "Sleep states", "Couldn't read which sleep states this PC has.");
        var kind = s.ModernStandby ? "Modern Standby (S0 Low Power Idle)" : s.S3 ? "Sleep (S3)" : s.AnyStandby ? s.Available.First(a => a.StartsWith("Standby", StringComparison.OrdinalIgnoreCase)) : "No sleep available";
        var level = s.AnyStandby ? AreaLevel.Ok : AreaLevel.Warning;
        var rows = s.Available.Select(a => new AreaRow(AreaLevel.Ok, [a, "Available"]))
            .Concat(s.Unavailable.Select(u => new AreaRow(AreaLevel.Neutral, [u.State, u.Reason.Length > 0 ? $"Not available: {u.Reason}" : "Not available"])))
            .ToList();
        parts.Add(s.ModernStandby ? "Modern Standby" : s.S3 ? "S3 sleep" : "No sleep");
        return new("states", "Sleep states", level, kind,
            s.Hibernate ? "Hibernate available" : "Hibernate not available", ["Sleep state", "Status"], rows,
            Note: !s.AnyStandby
                ? "This PC can't sleep. That is usually a missing or basic display driver, or a firmware setting; install the PC maker's graphics and chipset drivers."
                : s.ModernStandby
                    ? "Modern Standby keeps the PC connected while asleep, like a phone. Apps, updates and devices can keep it busy, so battery drain while asleep is worth watching."
                    : null,
            PreserveRowOrder: true);
    }

    private static AreaCard DrainCard(SleepWakeFacts f, List<string> parts)
    {
        const string Title = "Battery drain while asleep";
        string[] cols = ["Went to sleep", "Asleep for", "Battery used", "Per hour"];
        if (f.Standby is null) return AreaCard.Failed("drain", Title, "Couldn't read the battery report (a PC without a battery has none).");

        var rows = f.Standby.OrderByDescending(s => s.Start).Select(s =>
        {
            var rated = s.Duration >= StandbyDrain.MinSession;
            var lv = rated ? StandbyDrain.LevelOf(s.PercentPerHour) : AreaLevel.Neutral;
            return new AreaRow(lv,
                [WindowsEventLog.FormatTime(s.Start), SleepWakeParsers.Duration(s.Duration), $"{Pct(s.DrainPercent)} ({s.DischargeMwh.ToString("N0", CultureInfo.InvariantCulture)} mWh)",
                 rated ? $"{Pct(s.PercentPerHour)} / h" : "Too short to rate"],
                SortKeys: [s.Start.ToString("O", CultureInfo.InvariantCulture), s.Duration.Ticks.ToString("D20", CultureInfo.InvariantCulture), null, null]);
        }).ToList();

        var avg = StandbyDrain.AveragePercentPerHour(f.Standby);
        if (avg is null)
            return new("drain", Title, AreaLevel.Neutral, f.Standby.Count == 0 ? "No sleep on battery this week" : "Sleeps too short to rate",
                $"Last {StandbyDrain.ReportDays} days", cols, rows,
                EmptyText: "The PC didn't sleep on battery in the last week, so there's nothing to measure. Unplug it, let it sleep for an hour or more, then run this check again.");

        var level = StandbyDrain.LevelOf(avg.Value);
        var overnight = Math.Min(100, avg.Value * 8);
        parts.Add($"{Pct(avg.Value)}/h asleep");
        return new("drain", Title, level, $"{Pct(avg.Value)} of the battery per hour asleep",
            $"About {Pct(overnight)} over an 8-hour night · {AreaModuleBase.Plural(StandbyDrain.Rated(f.Standby).Count, "sleep")} on battery, last {StandbyDrain.ReportDays} days", cols, rows,
            Note: level == AreaLevel.Ok ? null
                : $"A sleeping PC should lose well under {Pct(StandbyDrain.WarnPercentPerHour)} an hour. Look at the devices and wake timers below, and at what keeps the PC awake; "
                  + "on Modern Standby PCs, 'powercfg /sleepstudy' (as administrator) names the apps and devices that were active.");
    }

    private static AreaCard WakesCard(SleepWakeFacts f, IReadOnlyList<WakeEvent> wakes, DateTimeOffset now, List<string> parts)
    {
        const string Title = "Recent wakes";
        string[] cols = ["Woke at", "Asleep for", "Woke because"];
        if (f.Events is null && f.LastWake is null) return AreaCard.Failed("wakes", Title, "Couldn't read the sleep and wake events.");

        // Kernel-Power 41 with SleepInProgress set: the PC went down while going to sleep or resuming (it "didn't wake up").
        var failedResumes = (f.Events ?? []).Where(e => e.EventId == 41 && e.Provider.EndsWith("Kernel-Power", StringComparison.OrdinalIgnoreCase)
            && int.TryParse(e.NamedData.GetValueOrDefault("SleepInProgress", "0"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var sip) && sip != 0).ToList();

        var rows = new List<AreaRow>();
        foreach (var e in failedResumes)
            rows.Add(new(AreaLevel.Error, [WindowsEventLog.FormatTime(e.Time, now), "", "Didn't resume: the PC restarted while sleeping or waking up"],
                SortKeys: [e.Time.UtcDateTime.ToString("O", CultureInfo.InvariantCulture), null, null]));
        foreach (var w in wakes)
            rows.Add(new(w.Unexpected ? AreaLevel.Warning : AreaLevel.Neutral, [WindowsEventLog.FormatTime(w.WakeTime, now), SleepWakeParsers.Duration(w.Slept), w.Because],
                SortKeys: [w.WakeTime.UtcDateTime.ToString("O", CultureInfo.InvariantCulture), w.Slept.Ticks.ToString("D20", CultureInfo.InvariantCulture), null]));
        // Sleeps the battery report has but the System log doesn't (no Power-Troubleshooter event for that wake).
        var unlogged = (f.Sleeps ?? []).Where(p => p.End <= now && !wakes.Any(w => (w.WakeTime - p.End).Duration() <= SameWake)).ToList();
        foreach (var p in unlogged)
            rows.Add(new(AreaLevel.Neutral, [WindowsEventLog.FormatTime(p.End, now), SleepWakeParsers.Duration(p.Duration),
                    "Not recorded in the event log (from the battery report)" + (p.OnBattery ? ", on battery" : "")],
                SortKeys: [p.End.UtcDateTime.ToString("O", CultureInfo.InvariantCulture), p.Duration.Ticks.ToString("D20", CultureInfo.InvariantCulture), null]));
        rows = rows.OrderByDescending(r => r.SortKeys![0], StringComparer.Ordinal).ToList();

        var unexpected = wakes.Count(w => w.Unexpected);
        var total = wakes.Count + unlogged.Count;
        var level = failedResumes.Count > 0 ? AreaLevel.Error : unexpected >= UnexpectedWakesWarn ? AreaLevel.Warning : AreaLevel.Ok;
        var headline = failedResumes.Count > 0 ? $"{AreaModuleBase.Plural(failedResumes.Count, "failed resume")} from sleep"
            : total == 0 ? "No wakes from sleep recorded"
            : unexpected > 0 ? $"{AreaModuleBase.Plural(unexpected, "wake")} by a timer or the network"
            : wakes.Count == 0 ? $"{AreaModuleBase.Plural(total, "wake")}, cause not recorded"
            : unlogged.Count == 0 ? $"{AreaModuleBase.Plural(total, "wake")}, all by a person or device"
            : $"{AreaModuleBase.Plural(total, "wake")}, none by a timer or the network";
        var last = f.LastWake is { Count: > 0 } lw ? $"Last wake: {string.Join(", ", lw.Select(s => s.Text))}" : $"Last {EventDays} days";
        if (failedResumes.Count > 0) parts.Add(AreaModuleBase.Plural(failedResumes.Count, "failed resume"));
        else if (unexpected > 0) parts.Add(AreaModuleBase.Plural(unexpected, "unexpected wake"));
        return new("wakes", Title, level, headline, last, cols, rows,
            EmptyText: $"The PC didn't wake from sleep in the last {EventDays} days.",
            Note: failedResumes.Count > 0
                ? "The PC lost power or was forced off while sleeping or waking. Update the BIOS, chipset and graphics drivers; check Crashes & unexpected restarts for a blue screen at the same time."
                : unexpected > 0 ? "A wake timer (often Windows Update or a scheduled task) or a network adapter woke the PC with nobody using it. That is the usual cause of a laptop that is hot or flat after a night in a bag." : null)
        {
            EventCount = total + failedResumes.Count, WindowDays = EventDays,
        };
    }

    private static AreaCard DevicesCard(SleepWakeFacts f, IReadOnlyList<WakeEvent> wakes, List<string> parts)
    {
        const string Title = "Devices that can wake the PC";
        if (f.WakeArmed is null) return AreaCard.Failed("devices", Title, "Couldn't read which devices can wake the PC.");
        // The event log has one entry per wake; /lastwake repeats the newest, so it only counts when the log has none.
        var recent = wakes.Count > 0 ? wakes.Select(w => w.Source).Where(s => s.Length > 0).ToList()
            : (f.LastWake ?? []).Select(s => s.Name).Where(s => s.Length > 0).ToList();
        var viaUsb = recent.Count(IsUsbController);
        var rows = f.WakeArmed.Select(d =>
        {
            var woke = recent.Count(r => string.Equals(r, d, StringComparison.OrdinalIgnoreCase));
            var usb = woke == 0 && viaUsb > 0 && IsUsbInput(d) && !IsNetworkDevice(d);
            var network = IsNetworkDevice(d);
            var lv = woke > 0 && network ? AreaLevel.Warning : AreaLevel.Neutral;
            var role = network ? "Network adapter" : d.Contains("keyboard", StringComparison.OrdinalIgnoreCase) ? "Keyboard"
                : d.Contains("mouse", StringComparison.OrdinalIgnoreCase) ? "Mouse" : "Device";
            var wokeText = woke > 0 ? $"Woke the PC {AreaModuleBase.Plural(woke, "time")}"
                : usb ? $"Maybe: the USB controller it's on woke the PC {AreaModuleBase.Plural(viaUsb, "time")}"
                : "No recent wakes";
            return new AreaRow(lv, [d, role, wokeText], Key: d,
                Actions: DeviceWake.IsSafeName(d) ? [new AreaAction(RemediationKind.DisableDeviceWake, "Stop it waking the PC", d, d)] : null);
        }).ToList();
        var networkArmed = f.WakeArmed.Count(IsNetworkDevice);
        var level = rows.Any(r => r.Level == AreaLevel.Warning) ? AreaLevel.Warning : AreaLevel.Ok;
        if (f.WakeArmed.Count > 0) parts.Add(AreaModuleBase.Plural(f.WakeArmed.Count, "wake device"));
        return new("devices", Title, level,
            f.WakeArmed.Count == 0 ? "Only the power button wakes the PC" : AreaModuleBase.Plural(f.WakeArmed.Count, "device") + " can wake the PC",
            networkArmed > 0 ? $"{AreaModuleBase.Plural(networkArmed, "network adapter")} among them" : "Keyboard, mouse and other devices",
            ["Device", "Kind", "Recent wakes"], rows,
            EmptyText: "No device is allowed to wake this PC.",
            Note: f.WakeArmed.Count == 0 ? null
                : "A mouse moved in a bag or a network adapter can wake a sleeping PC. Stopping a device from waking it is undoable; the power button still wakes the PC."
                  + (viaUsb > 0 ? " Windows names the USB controller, not the keyboard or mouse on it, so \"Maybe\" means one of the USB devices here woke the PC." : ""));
    }

    private static AreaCard TimersCard(IReadOnlyList<WakeTimer>? timers, IReadOnlyList<WakeEvent> wakes)
    {
        const string Title = "Wake timers";
        string[] cols = ["Set by", "Wakes the PC at", "Why"];
        if (timers is null) return AreaCard.Failed("timers", Title, "Couldn't read wake timers (this needs administrator rights).");
        var byTimer = wakes.Count(w => w.ByTimer);
        var level = byTimer > 0 ? AreaLevel.Warning : timers.Count > 0 ? AreaLevel.Neutral : AreaLevel.Ok;
        return new("timers", Title, level,
            timers.Count == 0 ? "No wake timers set" : AreaModuleBase.Plural(timers.Count, "wake timer") + " set",
            byTimer > 0 ? $"Timers woke the PC {AreaModuleBase.Plural(byTimer, "time")} in {EventDays} days" : "Scheduled tasks and apps can set timers that wake the PC",
            cols, timers.Select(t => new AreaRow(AreaLevel.Neutral, [SleepWakeParsers.ShortRequester(t.Owner), t.Expires, t.Reason])).ToList(),
            EmptyText: "Nothing has asked Windows to wake the PC.",
            Note: byTimer > 0 ? "To stop timers waking the PC on battery: Control Panel > Power Options > Change plan settings > Change advanced power settings > Sleep > Allow wake timers > On battery: Disable." : null);
    }

    private static AreaCard BlockersCard(IReadOnlyList<PowerRequest>? requests, List<string> parts)
    {
        const string Title = "What keeps the PC awake";
        string[] cols = ["Keeps awake", "Requested by", "Why"];
        if (requests is null) return AreaCard.Failed("blockers", Title, "Couldn't read what keeps the PC awake (this needs administrator rights).");
        var blocking = requests.Count(r => r.BlocksSleep);
        var rows = requests.Select(r => new AreaRow(r.BlocksSleep ? AreaLevel.Warning : AreaLevel.Neutral,
            [What(r.Category), $"{SleepWakeParsers.ShortRequester(r.Requester)} ({r.RequesterType.ToLowerInvariant()})", Why(r)])).ToList();
        if (blocking > 0) parts.Add(AreaModuleBase.Plural(blocking, "sleep blocker"));
        return new("blockers", Title, blocking > 0 ? AreaLevel.Warning : AreaLevel.Ok,
            blocking > 0 ? $"{AreaModuleBase.Plural(blocking, "app or driver", "apps or drivers")} keeping the PC or screen awake" : "Nothing is stopping the PC from sleeping",
            "Right now", cols, rows,
            EmptyText: "No app, driver or service is asking Windows to stay awake.",
            Note: blocking > 0 ? "Media playing, a download, a remote session or a driver holding an audio stream open stops the PC from sleeping on its timer. Close the app or end its task, then check again." : null);
    }

    /// <summary>
    /// The request's reason in plain words. Apps write their own reason text; many give only a framework or app name ("Electron",
    /// "Chromium"), which says nothing to a customer, so a reason without a space is shown after what the request does.
    /// </summary>
    public static string Why(PowerRequest r)
    {
        var detail = r.Detail.Trim();
        if (detail.Contains(' ')) return detail;
        var plain = r.Category switch
        {
            "DISPLAY" => "Asked Windows to keep the screen on",
            "SYSTEM" => "Asked Windows not to sleep",
            "AWAYMODE" => "Asked Windows for away mode (sleep with the screen off but keep running)",
            "EXECUTION" => "Asked Windows to keep it running in the background",
            "PERFBOOST" => "Asked Windows for full processor speed",
            "ACTIVELOCKSCREEN" => "Asked Windows to keep the lock screen active",
            _ => "Asked Windows to stay awake",
        };
        return detail.Length > 0 ? $"{plain} (the app says \"{detail}\")" : plain;
    }

    private static string What(string category) => category switch
    {
        "DISPLAY" => "Screen on",
        "SYSTEM" => "PC awake",
        "AWAYMODE" => "Away mode",
        "EXECUTION" => "App running",
        "PERFBOOST" => "Performance boost",
        "ACTIVELOCKSCREEN" => "Lock screen",
        _ => category,
    };

    private static string Pct(double v) => v.ToString(v < 10 ? "0.0" : "0", CultureInfo.InvariantCulture) + "%";
}
