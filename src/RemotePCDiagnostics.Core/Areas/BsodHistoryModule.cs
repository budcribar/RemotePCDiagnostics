using System.Globalization;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>One crash dump file in <c>C:\Windows\Minidump</c>.</summary>
public sealed record MinidumpFile(string FileName, DateTimeOffset Created, long SizeBytes);

/// <summary>
/// Blue screens (BugChecks, WER-SystemErrorReporting event 1001), unexpected power losses (Kernel-Power event 41,
/// EventLog event 6008) from the Windows System log over the last 30 days, and crash dump files in <c>C:\Windows\Minidump</c>.
/// </summary>
public sealed class BsodHistoryModule(SystemCommandRunner commands, Func<IReadOnlyList<MinidumpFile>>? minidumpReader = null) : AreaModuleBase(commands.Log)
{
    public const string ModuleName = "BsodHistory";
    public const int Days = 30, RecentDays = 7, MaxEvents = 250;
    public override string Name => ModuleName;
    public override string DisplayName => "Blue screens & unexpected restarts";
    protected override string FailedMessage => "Couldn't read blue screen and shutdown history on this PC.";
    private readonly WindowsEventLog _log = new(commands);
    private readonly Func<IReadOnlyList<MinidumpFile>> _readDumps = minidumpReader ?? ReadSystemMinidumps;

    public static string Query =>
        $"*[System[(EventID=41 or EventID=1001 or EventID=6008) and TimeCreated[timediff(@SystemTime) <= {(long)Days * 86_400_000}]]]";

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        progress?.Report("Checking for blue screens and unexpected restarts…");
        var events = await _log.QueryAsync("System", Query, MaxEvents, ct).ConfigureAwait(false);
        IReadOnlyList<MinidumpFile> dumps = [];
        try { dumps = _readDumps(); }
        catch (Exception ex) { Log($"{Name}: minidump check failed: {ex.Message}"); }
        return events is null ? AreaReport.Failed(FailedMessage) : Build(events, dumps);
    }

    public static IReadOnlyList<MinidumpFile> ReadSystemMinidumps()
    {
        var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrEmpty(winDir)) return [];
        var dir = Path.Combine(winDir, "Minidump");
        if (!Directory.Exists(dir)) return [];
        return new DirectoryInfo(dir).EnumerateFiles("*.dmp")
            .OrderByDescending(f => f.LastWriteTimeUtc)
            .Take(50)
            .Select(f => new MinidumpFile(f.Name, new DateTimeOffset(f.LastWriteTimeUtc, TimeSpan.Zero), f.Length))
            .ToList();
    }

    public static bool IsBugCheckEvent(WinEvent e) =>
        e.EventId == 1001 && (e.Provider.Contains("WER-SystemErrorReporting", StringComparison.OrdinalIgnoreCase)
            || e.Provider.Contains("BugCheck", StringComparison.OrdinalIgnoreCase)
            || e.Message.Contains("bugcheck", StringComparison.OrdinalIgnoreCase));

    public static bool IsPowerLossEvent(WinEvent e) =>
        (e.EventId == 41 && e.Provider.Contains("Kernel-Power", StringComparison.OrdinalIgnoreCase))
        || (e.EventId == 6008 && e.Provider.Contains("EventLog", StringComparison.OrdinalIgnoreCase));

    public static AreaReport Build(IReadOnlyList<WinEvent> events, IReadOnlyList<MinidumpFile>? dumps = null, DateTimeOffset? now = null)
    {
        var dmpList = dumps ?? [];
        var cutoff = (now ?? DateTimeOffset.Now).AddDays(-RecentDays);
        var bsods = events.Where(IsBugCheckEvent).OrderByDescending(e => e.Time).ToList();
        var powerLosses = events.Where(IsPowerLossEvent).OrderByDescending(e => e.Time).ToList();

        bool Recent(DateTimeOffset t) => t >= cutoff;
        var recentBsods = bsods.Count(e => Recent(e.Time));
        // One bad shutdown logs both Event 41 (at the next boot) and Event 6008: count incidents, not events.
        var incidents = PowerLossIncidents(powerLosses);
        var recentPower = incidents.Count(t => Recent(t));

        var bsodLevel = recentBsods >= 2 ? AreaLevel.Error : recentBsods == 1 ? AreaLevel.Warning : bsods.Count > 0 ? AreaLevel.Neutral : AreaLevel.Ok;
        var powerLevel = recentPower > 0 ? AreaLevel.Warning : powerLosses.Count > 0 ? AreaLevel.Neutral : AreaLevel.Ok;

        string[] eventCols = ["When", "Type", "Details"];
        var cards = new List<AreaCard>
        {
            new("bsods", "Blue screen crashes (BSOD)", bsodLevel,
                bsods.Count == 0 ? "None" : Plural(bsods.Count, "blue screen"),
                bsods.FirstOrDefault() is { } b ? $"Latest: {WindowsEventLog.FormatTime(b.Time)}" : $"In the last {Days} days",
                eventCols,
                bsods.Select(e => new AreaRow(Recent(e.Time) ? AreaLevel.Warning : AreaLevel.Neutral,
                    [WindowsEventLog.FormatTime(e.Time), "Blue screen (BugCheck)", e.ShortMessage],
                    [AreaSort.TimeKey(e.Time), null, null])).ToList(),
                EmptyText: $"No blue screen crashes were recorded in the last {Days} days."),

            new("power", "Unexpected power losses & resets", powerLevel,
                incidents.Count == 0 ? "None" : Plural(incidents.Count, "unexpected restart"),
                powerLosses.FirstOrDefault() is { } p ? $"Latest: {WindowsEventLog.FormatTime(p.Time)}" : $"In the last {Days} days",
                eventCols,
                powerLosses.Select(e => new AreaRow(Recent(e.Time) ? AreaLevel.Warning : AreaLevel.Neutral,
                    [WindowsEventLog.FormatTime(e.Time), e.EventId == 41 ? "Kernel-Power (Event 41)" : "Unexpected shutdown (Event 6008)", e.ShortMessage],
                    [AreaSort.TimeKey(e.Time), null, null])).ToList(),
                EmptyText: $"All shutdowns and restarts in the last {Days} days were clean.",
                Note: "Event 41 happens when the PC loses power, is forced off by holding the power button, or resets before Windows can write a crash log."),

            new("minidumps", "Crash dump files (Minidump)", dmpList.Count > 0 ? AreaLevel.Neutral : AreaLevel.Ok,
                dmpList.Count == 0 ? "None on disk" : Plural(dmpList.Count, "dump file"),
                dmpList.FirstOrDefault() is { } d ? $"Latest: {d.FileName} ({WindowsEventLog.FormatTime(d.Created)})" : @"C:\Windows\Minidump",
                ["When", "File", "Size"],
                dmpList.Select(f => new AreaRow(AreaLevel.Neutral,
                    [WindowsEventLog.FormatTime(f.Created), f.FileName, Osquery.HardwareInventory.FormatBytes(f.SizeBytes)],
                    [AreaSort.TimeKey(f.Created), null, f.SizeBytes.ToString(CultureInfo.InvariantCulture)])).ToList(),
                EmptyText: @"No crash dump files (.dmp) were found in C:\Windows\Minidump."),
        };

        string summary;
        if (bsods.Count == 0 && powerLosses.Count == 0)
            summary = $"No blue screens or unexpected restarts in the last {Days} days";
        else
        {
            var parts = new List<string>();
            if (bsods.Count > 0) parts.Add(Plural(bsods.Count, "blue screen"));
            if (incidents.Count > 0) parts.Add(Plural(incidents.Count, "unexpected restart"));
            summary = $"{string.Join(", ", parts)} in the last {Days} days" + (recentBsods == 0 && recentPower == 0 ? $" (none in the last {RecentDays} days)" : "");
        }

        var status = bsodLevel == AreaLevel.Error ? DiagnosticStatus.Error
            : (bsodLevel == AreaLevel.Warning || powerLevel == AreaLevel.Warning) ? DiagnosticStatus.Warning
            : DiagnosticStatus.Ok;
        return new(cards, summary, status);
    }

    /// <summary>Events logged within this window of each other belong to the same unexpected shutdown.</summary>
    public static readonly TimeSpan IncidentWindow = TimeSpan.FromMinutes(10);

    /// <summary>Times of distinct unexpected-shutdown incidents (newest first): Event 41 and 6008 from the same boot are one incident.</summary>
    public static IReadOnlyList<DateTimeOffset> PowerLossIncidents(IEnumerable<WinEvent> powerLossEvents)
    {
        var result = new List<DateTimeOffset>();
        foreach (var t in powerLossEvents.Select(e => e.Time).OrderByDescending(t => t))
            if (result.Count == 0 || result[^1] - t > IncidentWindow) result.Add(t);
        return result;
    }
}
