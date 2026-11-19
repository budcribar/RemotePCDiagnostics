using System.Globalization;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>A graphics driver installed on this PC (osquery <c>drivers</c>, Display class).</summary>
public sealed record GpuDriver(string Device, string Provider, string Version, DateOnly? Date)
{
    public static GpuDriver FromRow(IReadOnlyDictionary<string, string> r) => new(
        r.Str("device_name").Length > 0 ? r.Str("device_name") : r.Str("description"),
        r.Str("provider").Length > 0 ? r.Str("provider") : r.Str("manufacturer"),
        r.Str("version"), OsqueryDates.Parse(r.Str("date")));

    public string Label => string.Join(" ", new[] { Device, Version, Date is { } d ? $"({OsqueryDates.Format(d)})" : null }
        .Where(s => !string.IsNullOrWhiteSpace(s)));
}

/// <summary>A graphics driver install Windows recorded (Microsoft-Windows-UserPnp event 20001 for a Display class device).</summary>
public sealed record GpuDriverInstall(DateTimeOffset Time, string Device, string Provider, string Version, string DriverDate);

/// <summary>
/// Graphics driver crashes and resets over the last 30 days, shown as one card of Crashes &amp; unexpected restarts: display driver
/// timeouts Windows recovered from (Display event 4101, TDR), errors from the NVIDIA, AMD and Intel display drivers, live kernel reports
/// for graphics hangs (LiveKernelEvent 117/141/1a1 in Windows Error Reporting, dump files in <c>C:\Windows\LiveKernelReports</c>), and
/// graphics blue screens (bugchecks 0x116, 0x117, 0x119, 0x10e, 0x113). Each reset is tied to the graphics driver installed at the time,
/// from the driver install history (UserPnp event 20001) and the current drivers, to tell a bad driver from a failing GPU.
/// </summary>
public static class GraphicsDriverCrashes
{
    public const string CardId = "graphics";
    public const string Title = "Graphics driver crashes & resets";
    public const int Days = 30, RecentDays = 7, MaxEvents = 300, RepeatedResets = 5, UpdateLeadDays = 14;
    public const string DisplayClassGuid = "{4d36e968-e325-11ce-bfc1-08002be10318}";

    /// <summary>Events closer together than this are one reset: one TDR logs Display 4101, a driver error, a WER report and a dump.</summary>
    public static readonly TimeSpan IncidentWindow = TimeSpan.FromMinutes(5);

    /// <summary>The display driver services that log their own events, longest first so "igfxn" wins over "igfx".</summary>
    public static readonly IReadOnlyList<string> DriverServices = ["nvlddmkm", "amdkmdag", "amdkmdap", "amdwddmg", "igfxnd", "igfxn", "igfx"];

    public const string DriversSql = "SELECT device_name, description, provider, manufacturer, version, date FROM drivers WHERE upper(class) = 'DISPLAY';";

    private static long WindowMs => (long)Days * 86_400_000;

    /// <summary>System log: Display 4101 and warnings or errors from the display drivers.</summary>
    public static string SystemQuery =>
        $"*[System[((Provider[@Name='Display'] and EventID=4101) or (Provider[{string.Join(" or ", DriverServices.Select(s => $"@Name='{s}'"))}] and (Level=1 or Level=2 or Level=3))) and TimeCreated[timediff(@SystemTime) <= {WindowMs}]]]";

    /// <summary>System log: driver installs (filtered to Display class devices in <see cref="ToInstall"/>).</summary>
    public static string InstallQuery =>
        $"*[System[Provider[@Name='Microsoft-Windows-UserPnp'] and EventID=20001 and TimeCreated[timediff(@SystemTime) <= {WindowMs}]]]";

    /// <summary>Application log: Windows Error Reporting live kernel reports.</summary>
    public static string ReportQuery =>
        $"*[System[Provider[@Name='Windows Error Reporting'] and EventID=1001 and TimeCreated[timediff(@SystemTime) <= {WindowMs}]]]";

    private static string? LiveKernelName(uint code) => code switch
    {
        0x117 => "Display driver stopped responding (live dump 0x117)",
        0x141 => "Graphics engine stopped responding (live dump 0x141)",
        0x1A1 => "Desktop stopped responding (live dump 0x1a1)",
        _ => null
    };

    private static string? BugCheckName(uint code) => code switch
    {
        0x116 => "Graphics driver couldn't recover (0x116)",
        0x117 => "Graphics driver timed out (0x117)",
        0x119 => "Graphics scheduler error (0x119)",
        0x10E => "Graphics memory error (0x10e)",
        0x113 => "DirectX graphics kernel error (0x113)",
        _ => null
    };

    public static bool IsResetEvent(WinEvent e) =>
        (e.EventId == 4101 && e.Provider.Equals("Display", StringComparison.OrdinalIgnoreCase)) || IsDriverEvent(e);

    /// <summary>A warning or error logged by an NVIDIA, AMD or Intel display driver.</summary>
    public static bool IsDriverEvent(WinEvent e) =>
        e.Level is >= 1 and <= 3 && DriverServices.Contains(e.Provider, StringComparer.OrdinalIgnoreCase);

    /// <summary>The graphics live kernel report a WER event 1001 describes, or null when it is another kind of report.</summary>
    public static uint? LiveKernelCode(WinEvent e)
    {
        if (e.EventId != 1001 || !e.Provider.Equals("Windows Error Reporting", StringComparison.OrdinalIgnoreCase)) return null;
        string p1;
        if (e.Data.Count > 5 && e.Data[2].Equals("LiveKernelEvent", StringComparison.OrdinalIgnoreCase)) p1 = e.Data[5];
        else
        {
            var at = e.Message.IndexOf("LiveKernelEvent", StringComparison.OrdinalIgnoreCase);
            var p = at < 0 ? -1 : e.Message.IndexOf("P1:", at, StringComparison.OrdinalIgnoreCase);
            if (p < 0) return null;
            p1 = new string(e.Message[(p + 3)..].TrimStart().TakeWhile(Uri.IsHexDigit).ToArray());
        }
        if (p1.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) p1 = p1[2..];
        return uint.TryParse(p1, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var code) && LiveKernelName(code) is not null ? code : null;
    }

    /// <summary>The graphics stop code of a blue screen event, or null.</summary>
    public static uint? GraphicsBugCheck(WinEvent e) =>
        BsodHistoryModule.IsBugCheckEvent(e) && BsodHistoryModule.BugCheckValue(e) is { } code && BugCheckName(code) is not null ? code : null;

    /// <summary>A Display class driver install, or null for any other UserPnp event.</summary>
    public static GpuDriverInstall? ToInstall(WinEvent e)
    {
        if (e.EventId != 20001 || !e.Provider.Contains("UserPnp", StringComparison.OrdinalIgnoreCase)) return null;
        var setupClass = e.NamedData.GetValueOrDefault("SetupClass", "");
        var status = e.NamedData.GetValueOrDefault("InstallStatus", "0x0");
        if (!setupClass.Trim().Equals(DisplayClassGuid, StringComparison.OrdinalIgnoreCase)) return null;
        if (status.Length > 0 && status != "0" && !status.Equals("0x0", StringComparison.OrdinalIgnoreCase)) return null;
        return new(e.Time, e.NamedData.GetValueOrDefault("DriverDescription", ""), e.NamedData.GetValueOrDefault("DriverProvider", ""),
            e.NamedData.GetValueOrDefault("DriverVersion", ""), e.NamedData.GetValueOrDefault("DriverDate", ""));
    }

    /// <summary>The display driver service an event or a dump folder names, or null.</summary>
    public static string? DriverService(string text) =>
        DriverServices.FirstOrDefault(s => text.Contains(s, StringComparison.OrdinalIgnoreCase));

    private static bool FromVendor(string? service, string provider, string device)
    {
        if (service is null) return true;
        var text = provider + " " + device;
        bool Has(string word) => text.Contains(word, StringComparison.OrdinalIgnoreCase);
        return service.StartsWith("nv", StringComparison.OrdinalIgnoreCase) ? Has("NVIDIA")
            : service.StartsWith("amd", StringComparison.OrdinalIgnoreCase) ? Has("AMD") || Has("Advanced Micro") || Has("Radeon")
            : Has("Intel");
    }

    /// <summary>Graphics hang dumps in <c>C:\Windows\LiveKernelReports</c>: WATCHDOG dumps and the display drivers' own folders.</summary>
    public static IReadOnlyList<MinidumpFile> ReadLiveKernelReports()
    {
        var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrEmpty(winDir)) return [];
        var root = new DirectoryInfo(Path.Combine(winDir, "LiveKernelReports"));
        if (!root.Exists) return [];
        var files = root.EnumerateFiles("*.dmp").Where(f => f.Name.StartsWith("WATCHDOG", StringComparison.OrdinalIgnoreCase)).ToList();
        foreach (var dir in root.EnumerateDirectories())
            if (dir.Name.Equals("WATCHDOG", StringComparison.OrdinalIgnoreCase) || DriverService(dir.Name) is not null)
                files.AddRange(dir.EnumerateFiles("*.dmp"));
        var cutoff = DateTime.UtcNow.AddDays(-Days);
        return files.Where(f => f.LastWriteTimeUtc >= cutoff).OrderByDescending(f => f.LastWriteTimeUtc).Take(50)
            .Select(f => new MinidumpFile(f.Name, new DateTimeOffset(f.LastWriteTimeUtc, TimeSpan.Zero), f.Length, f.FullName))
            .ToList();
    }

    /// <summary>One piece of evidence: an event or a dump file.</summary>
    private sealed record Clue(DateTimeOffset Time, string What, string? Service, string Line, string? ReviewKey, string? DumpPath, bool BlueScreen);

    /// <summary>One reset (or graphics blue screen) and the evidence logged for it, newest clue first.</summary>
    public sealed record Incident(DateTimeOffset Time, string What, bool BlueScreen, string? Service, IReadOnlyList<string> Evidence,
        IReadOnlyList<string> ReviewKeys, string? DumpPath)
    {
        /// <summary>The graphics driver installed when it happened ("version (date)"), or null when unknown.</summary>
        public string? Driver { get; init; }
    }

    private static IEnumerable<Clue> Clues(IReadOnlyList<WinEvent> events, IReadOnlyList<MinidumpFile> reports)
    {
        foreach (var e in events)
        {
            var message = e.Message.Length > 0 ? e.Message : e.ShortMessage;
            if (GraphicsBugCheck(e) is { } stop)
                yield return new(e.Time, BugCheckName(stop)!, null, $"{WindowsEventLog.FormatTime(e.Time)} · Blue screen · {message}", EventReviews.Key(e), null, true);
            else if (LiveKernelCode(e) is { } live)
                yield return new(e.Time, LiveKernelName(live)!, null, $"{WindowsEventLog.FormatTime(e.Time)} · Windows Error Reporting · {e.ShortMessage}", EventReviews.Key(e), null, false);
            else if (e.EventId == 4101 && e.Provider.Equals("Display", StringComparison.OrdinalIgnoreCase))
                yield return new(e.Time, "Display driver stopped responding and recovered (TDR)", DriverService(e.DataAt(0, "") + " " + e.Message),
                    $"{WindowsEventLog.FormatTime(e.Time)} · Display 4101 · {e.ShortMessage}", EventReviews.Key(e), null, false);
            else if (IsDriverEvent(e))
                yield return new(e.Time, $"{e.Provider} driver error (Event {e.EventId})", DriverService(e.Provider),
                    $"{WindowsEventLog.FormatTime(e.Time)} · {e.Provider} {e.EventId} · {e.ShortMessage}", EventReviews.Key(e), null, false);
        }
        foreach (var r in reports)
        {
            var folder = Path.GetFileName(Path.GetDirectoryName(r.FullPath ?? "") ?? "");
            yield return new(r.Created, "Graphics hang report (live kernel dump)", DriverService(folder + " " + r.FileName),
                $"{WindowsEventLog.FormatTime(r.Created)} · Live kernel report {r.FullPath ?? r.FileName} ({Osquery.HardwareInventory.FormatBytes(r.SizeBytes)})",
                null, r.FullPath, false);
        }
    }

    /// <summary>Groups the evidence into resets, newest first, and ties each to the driver installed at the time.</summary>
    public static IReadOnlyList<Incident> Incidents(IReadOnlyList<WinEvent> events, IReadOnlyList<MinidumpFile> reports,
        IReadOnlyList<GpuDriverInstall> installs, IReadOnlyList<GpuDriver> drivers)
    {
        var groups = new List<List<Clue>>();
        foreach (var clue in Clues(events, reports).OrderByDescending(c => c.Time))
        {
            var group = groups.LastOrDefault();
            // A blue screen is its own incident; resets within the window of each other are one.
            if (group is null || group[^1].Time - clue.Time > IncidentWindow || clue.BlueScreen || group[0].BlueScreen) groups.Add([clue]);
            else group.Add(clue);
        }
        return groups.Select(g =>
        {
            var main = g.FirstOrDefault(c => c.BlueScreen) ?? g.FirstOrDefault(c => c.What.StartsWith("Display driver stopped", StringComparison.Ordinal))
                ?? g.FirstOrDefault(c => c.What.StartsWith("Display driver", StringComparison.Ordinal) || c.What.StartsWith("Graphics engine", StringComparison.Ordinal)) ?? g[0];
            var service = g.Select(c => c.Service).FirstOrDefault(s => s is not null);
            var time = g[^1].Time;
            return new Incident(time, main.What, main.BlueScreen, service, g.OrderBy(c => c.Time).Select(c => c.Line).ToList(),
                g.Select(c => c.ReviewKey).OfType<string>().ToList(), g.Select(c => c.DumpPath).FirstOrDefault(p => p is not null))
            { Driver = DriverAt(time, service, installs, drivers) };
        }).ToList();
    }

    /// <summary>The driver installed at <paramref name="time"/>: the latest install before it, else today's driver when none came after.</summary>
    public static string? DriverAt(DateTimeOffset time, string? service, IReadOnlyList<GpuDriverInstall> installs, IReadOnlyList<GpuDriver> drivers)
    {
        var matching = installs.Where(i => FromVendor(service, i.Provider, i.Device)).ToList();
        if (matching.Where(i => i.Time <= time).MaxBy(i => i.Time) is { } before)
            return before.DriverDate.Length > 0 ? $"{before.Version} ({before.DriverDate})" : before.Version;
        if (matching.Any(i => i.Time > time)) return null;
        var current = drivers.Where(d => FromVendor(service, d.Provider, d.Device)).ToList();
        return current.Count == 1 || (service is null && current.Count > 0) ? string.Join(", ", current.Select(d =>
            d.Date is { } date ? $"{d.Version} ({OsqueryDates.Format(date)})" : d.Version)) : null;
    }

    /// <summary>The card. Ok: nothing in 30 days. Warning: a reset in the last 7 days. Error: a graphics blue screen, or
    /// <see cref="RepeatedResets"/>+ resets in 30 days. Resets only older than 7 days are shown neutral.</summary>
    public static AreaCard Build(IReadOnlyList<WinEvent> events, IReadOnlyList<MinidumpFile> reports, IReadOnlyList<GpuDriverInstall> installs,
        IReadOnlyList<GpuDriver>? drivers, DateTimeOffset? now = null)
    {
        var current = drivers ?? [];
        var cutoff = (now ?? DateTimeOffset.Now).AddDays(-RecentDays);
        var incidents = Incidents(events, reports, installs, current);
        var resets = incidents.Where(i => !i.BlueScreen).ToList();
        var bsods = incidents.Count(i => i.BlueScreen);
        var recent = incidents.Count(i => i.Time >= cutoff);
        var level = bsods > 0 || resets.Count >= RepeatedResets ? AreaLevel.Error
            : recent > 0 ? AreaLevel.Warning : incidents.Count > 0 ? AreaLevel.Neutral : AreaLevel.Ok;

        var rows = incidents.Select(i => new AreaRow(
            i.BlueScreen ? AreaLevel.Error : i.Time >= cutoff ? AreaLevel.Warning : AreaLevel.Neutral,
            [WindowsEventLog.FormatTime(i.Time), i.What, i.Driver ?? "Unknown"],
            [AreaSort.TimeKey(i.Time), null, null],
            Detail: string.Join("\n", i.Evidence.Prepend(i.Driver is null ? "Driver at the time: unknown" : $"Driver at the time: {i.Driver}")),
            DumpPath: i.DumpPath, ReviewKeys: i.ReviewKeys.Count > 0 ? i.ReviewKeys : null)).ToList();

        var headline = incidents.Count == 0 ? "None"
            : string.Join(", ", new[]
            {
                resets.Count > 0 ? AreaModuleBase.Plural(resets.Count, "driver reset") : null,
                bsods > 0 ? AreaModuleBase.Plural(bsods, "graphics blue screen") : null
            }.OfType<string>());
        var latest = incidents.FirstOrDefault();
        var meta = latest is null ? $"In the last {Days} days"
            : $"Latest: {WindowsEventLog.FormatTime(latest.Time)}" + (latest.Driver is { } d ? $" · driver {d}" : "");

        var currentText = current.Count == 0 ? null : $"Current graphics driver: {string.Join("; ", current.Select(g => g.Label))}.";
        var note = string.Join(" ", new[] { NextStep(incidents, installs, level), currentText }.OfType<string>());
        return new AreaCard(CardId, Title, level, headline, meta, ["When", "What happened", "Driver at the time"], rows,
            EmptyText: $"No graphics driver resets or graphics blue screens in the last {Days} days.", Note: note)
            { EventCount = incidents.Count, WindowDays = Days, RecentEventCount = recent, RecentWindowDays = RecentDays };
    }

    /// <summary>The install the resets started after: the latest one before the first reset, at most <see cref="UpdateLeadDays"/> days before it.</summary>
    public static GpuDriverInstall? StartedAfter(IReadOnlyList<Incident> incidents, IReadOnlyList<GpuDriverInstall> installs)
    {
        if (incidents.Count == 0) return null;
        var first = incidents[^1];
        return installs.Where(i => i.Time <= first.Time && first.Time - i.Time <= TimeSpan.FromDays(UpdateLeadDays)
            && FromVendor(first.Service, i.Provider, i.Device)).MaxBy(i => i.Time);
    }

    /// <summary>What to do next: roll back a driver the resets started after, test the GPU when they continued across drivers, else
    /// reinstall the driver cleanly.</summary>
    public static string NextStep(IReadOnlyList<Incident> incidents, IReadOnlyList<GpuDriverInstall> installs, AreaLevel level)
    {
        const string about = "Windows resets the graphics driver when the GPU stops responding for about 2 seconds (Event 4101, a TDR); the screen goes black or flickers and comes back.";
        if (incidents.Count == 0) return about;
        if (StartedAfter(incidents, installs) is { } update)
            return $"The resets started after the graphics driver update on {WindowsEventLog.FormatTime(update.Time)}"
                + (update.Version.Length > 0 ? $" (version {update.Version})" : "")
                + ". Roll the driver back in Device Manager, or do a clean reinstall of the previous version from the GPU maker.";
        var versions = incidents.Select(i => i.Driver).OfType<string>().Distinct(StringComparer.OrdinalIgnoreCase).Count();
        if (level == AreaLevel.Error && versions > 1)
            return "The resets continued across graphics driver versions, which points to the graphics card rather than the driver. Run the GPU stress test and watch GPU temperatures.";
        if (incidents.Any(i => i.BlueScreen))
            return "A graphics blue screen means the driver couldn't recover the GPU. Do a clean reinstall of the graphics driver from the GPU maker, then run the GPU stress test; if it fails or the GPU overheats, the graphics card is likely failing.";
        return level == AreaLevel.Error
            ? "Repeated resets with the same driver: do a clean reinstall of the graphics driver from the GPU maker. If the resets continue, run the GPU stress test to check the graphics card."
            : "A few resets can come from one game or app. If they continue, do a clean reinstall of the graphics driver, then run the GPU stress test.";
    }
}
