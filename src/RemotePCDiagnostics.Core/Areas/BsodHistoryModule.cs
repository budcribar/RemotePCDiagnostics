using System.Globalization;
using System.Text.RegularExpressions;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>One crash dump file in <c>C:\Windows\Minidump</c>.</summary>
public sealed record MinidumpFile(string FileName, DateTimeOffset Created, long SizeBytes, string? FullPath = null);

/// <summary>
/// Blue screens (BugChecks, WER-SystemErrorReporting event 1001), unexpected power losses (Kernel-Power event 41,
/// EventLog event 6008), and hardware error events (Microsoft-Windows-WHEA-Logger) from the Windows System log over
/// the last 30 days, plus crash dump files in <c>C:\Windows\Minidump</c>.
/// </summary>
public sealed class BsodHistoryModule(SystemCommandRunner commands, Func<IReadOnlyList<MinidumpFile>>? minidumpReader = null) : AreaModuleBase(commands.Log)
{
    public const string ModuleName = ModuleSlugs.BsodHistory;
    public const int Days = 30, RecentDays = 7, MaxEvents = 250;
    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.BsodHistory;
    public override string DisplayName => "Blue screens & unexpected restarts";
    protected override string FailedMessage => "Couldn't read blue screen and shutdown history on this PC.";
    private readonly WindowsEventLog _log = new(commands);
    private readonly Func<IReadOnlyList<MinidumpFile>> _readDumps = minidumpReader ?? ReadSystemMinidumps;

    public static string Query =>
        $"*[System[((EventID=41 or EventID=1001 or EventID=6008) or Provider[@Name='Microsoft-Windows-WHEA-Logger']) and TimeCreated[timediff(@SystemTime) <= {(long)Days * 86_400_000}]]]";

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        progress?.Report("Checking for blue screens and unexpected restarts…");
        var events = await _log.QueryAsync("System", Query, MaxEvents, ct).ConfigureAwait(false);
        IReadOnlyList<MinidumpFile> dumps = [];
        try { dumps = _readDumps(); }
        catch (Exception ex) { LogWarn($"{Name}: minidump check failed: {ex.Message}"); }
        return events is null ? AreaReport.Failed(FailedMessage) : BuildReviewed(events, dumps);
    }

    internal static AreaReport BuildReviewed(IReadOnlyList<WinEvent> events, IReadOnlyList<MinidumpFile> dumps)
    {
        var reviewed = EventReviews.Read();
        var report = Build(events.Where(e => !reviewed.Contains(EventReviews.Key(e))).ToList(), dumps);
        return report with { ReviewedCards = Build(events.Where(e => reviewed.Contains(EventReviews.Key(e))).ToList(), dumps).Cards };
    }

    private static IEnumerable<List<WinEvent>> RestartGroups(IEnumerable<WinEvent> events)
    {
        List<WinEvent>? group = null;
        foreach (var e in events.OrderByDescending(e => e.Time))
        {
            if (group is null || group[0].Time - e.Time > IncidentWindow)
            {
                group = [];
                yield return group;
            }
            group.Add(e);
        }
    }

    public static IReadOnlyList<MinidumpFile> ReadSystemMinidumps()
    {
        var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrEmpty(winDir)) return [];
        var dir = Path.Combine(winDir, "Minidump");
        var files = Directory.Exists(dir) ? new DirectoryInfo(dir).EnumerateFiles("*.dmp")
            .OrderByDescending(f => f.LastWriteTimeUtc).Take(50).ToList() : [];
        var memory = new FileInfo(Path.Combine(winDir, "MEMORY.DMP"));
        if (memory.Exists) files.Add(memory);
        return files.OrderByDescending(f => f.LastWriteTimeUtc)
            .Select(f => new MinidumpFile(f.Name, new DateTimeOffset(f.LastWriteTimeUtc, TimeSpan.Zero), f.Length, f.FullName))
            .ToList();
    }

    internal static string FormatStopCode(uint code) => StopCode(code);

    private static string StopCode(uint code) => $"0x{code:x8}" + (code switch
    {
        0xA => " · Invalid memory access at elevated priority",
        0x1A => " · Memory management error",
        0x3B => " · System service exception",
        0x50 => " · Invalid reference to nonpaged memory",
        0x7E => " · Unhandled system thread exception",
        0x9F => " · Driver power state failure",
        0x116 => " · Graphics driver recovery failed",
        0x124 => " · Uncorrectable hardware error",
        0x133 => " · Driver work exceeded its time limit",
        0xD1 => " · Driver accessed invalid memory at elevated priority",
        0xEF => " · Critical system process stopped",
        _ => ""
    });

    private static string? BugCheckCode(WinEvent e) => BugCheckValue(e) is { } code ? StopCode(code) : null;

    /// <summary>The stop code a blue screen event records, or null.</summary>
    public static uint? BugCheckValue(WinEvent e)
    {
        var match = Regex.Match(e.DataAt(0, "param1") + " " + e.Message, @"\b0x([0-9a-fA-F]{1,8})\b", RegexOptions.None, TimeSpan.FromSeconds(2));
        return match.Success && uint.TryParse(match.Groups[1].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var code)
            ? code : null;
    }

    private static bool SameDump(MinidumpFile dump, string path) =>
        dump.FullPath is not null && string.Equals(dump.FullPath, path, StringComparison.OrdinalIgnoreCase);

    private static AreaRow BlueScreenRow(WinEvent e, bool recent, IReadOnlyList<MinidumpFile> dumps)
    {
        var code = BugCheckCode(e);
        var path = e.DataAt(1, "param2");
        var report = e.DataAt(2, "param3");
        var parameters = Regex.Match(e.DataAt(0, "param1") + " " + e.Message, @"\((0x[0-9a-fA-F]+(?:,\s*0x[0-9a-fA-F]+){3})\)", RegexOptions.None, TimeSpan.FromSeconds(2)).Groups[1].Value;
        var found = dumps.Any(d => MatchesEvent(d, e));
        var details = string.Join("\n", new[]
        {
            code is null ? null : $"Stop code: {code}",
            parameters.Length == 0 ? null : $"Bugcheck parameters: {parameters}",
            path.Length == 0 ? null : $"Dump path: {path} ({(dumps.Any(d => SameDump(d, path)) ? "on disk" : "not in the dump inventory")})",
            report.Length == 0 ? null : $"Report ID: {report}",
            e.Message.Length > 0 ? e.Message : e.ShortMessage
        }.OfType<string>());
        return new(recent ? AreaLevel.Warning : AreaLevel.Neutral,
            [WindowsEventLog.FormatTime(e.Time), "Blue screen (BugCheck)", code ?? e.ShortMessage],
            [AreaSort.TimeKey(e.Time), null, null], Detail: details, DumpPath: found ? path : null, ReviewKeys: [EventReviews.Key(e)]);
    }

    private static AreaRow RestartRow(WinEvent e, bool recent, IReadOnlyList<string> keys)
    {
        var code = e.EventId == 41 && e.NamedData.TryGetValue("BugcheckCode", out var raw)
            && uint.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out var value) && value != 0
            ? StopCode(value) : null;
        var message = e.Message.Length > 0 ? e.Message : e.ShortMessage;
        return new(recent ? AreaLevel.Warning : AreaLevel.Neutral,
            [WindowsEventLog.FormatTime(e.Time), e.EventId == 41 ? "Kernel-Power (Event 41)" : "Unexpected shutdown (Event 6008)", code ?? e.ShortMessage],
            [AreaSort.TimeKey(e.Time), null, null], Detail: code is null ? message : $"Stop code: {code}\n{message}", ReviewKeys: keys);
    }

    private static bool MatchesEvent(MinidumpFile dump, WinEvent e) =>
        SameDump(dump, e.DataAt(1, "param2")) && (e.Time - dump.Created).Duration() <= TimeSpan.FromMinutes(10);

    private static AreaRow DumpRow(MinidumpFile dump, IReadOnlyList<WinEvent> events)
    {
        var related = events.FirstOrDefault(e => MatchesEvent(dump, e));
        var parsed = CrashDumpDebugger.IsLocalDump(dump.FullPath) ? CrashDumpParser.TryReadFile(dump.FullPath) : null;
        var detail = dump.FullPath ?? dump.FileName;
        if (related is not null)
            detail += $"\nBlue screen recorded: {WindowsEventLog.FormatTime(related.Time)} · {BugCheckCode(related) ?? related.ShortMessage}";
        if (parsed is not null)
            detail += "\n" + parsed.FormatText();
        return new(AreaLevel.Neutral,
            [WindowsEventLog.FormatTime(dump.Created), dump.FileName, Osquery.HardwareInventory.FormatBytes(dump.SizeBytes)],
            [AreaSort.TimeKey(dump.Created), null, dump.SizeBytes.ToString(CultureInfo.InvariantCulture)],
            Detail: detail, DumpPath: dump.FullPath);
    }

    public static bool IsBugCheckEvent(WinEvent e) =>
        e.EventId == 1001 && (e.Provider.Contains("WER-SystemErrorReporting", StringComparison.OrdinalIgnoreCase)
            || e.Provider.Contains("BugCheck", StringComparison.OrdinalIgnoreCase)
            || e.Message.Contains("bugcheck", StringComparison.OrdinalIgnoreCase));

    public static bool IsPowerLossEvent(WinEvent e) =>
        (e.EventId == 41 && e.Provider.Contains("Kernel-Power", StringComparison.OrdinalIgnoreCase))
        || (e.EventId == 6008 && e.Provider.Contains("EventLog", StringComparison.OrdinalIgnoreCase));

    public static bool IsWheaEvent(WinEvent e) =>
        e.Provider.Contains("WHEA-Logger", StringComparison.OrdinalIgnoreCase);

    public static bool IsUncorrectedWheaEvent(WinEvent e)
    {
        if (!IsWheaEvent(e)) return false;
        if (e.EventId is 1 or 18 or 20 or 46) return true;
        if (e.EventId is 17 or 19) return false;
        var text = e.Message + " " + string.Join(" ", e.NamedData.Values);
        var fatalOrUncorrected = text.Contains("uncorrected", StringComparison.OrdinalIgnoreCase)
            || text.Contains("uncorrectable", StringComparison.OrdinalIgnoreCase)
            || text.Contains("fatal", StringComparison.OrdinalIgnoreCase);
        var correctedOnly = !fatalOrUncorrected && text.Contains("corrected", StringComparison.OrdinalIgnoreCase);
        if (e.EventId == 47) return !correctedOnly;
        if (correctedOnly) return false;
        return e.Level == 1 || (e.Level == 2 && (fatalOrUncorrected || text.Trim().Length == 0));
    }

    public static string? WheaComponentHint(WinEvent e)
    {
        var text = e.Message + " " + string.Join(" ", e.NamedData.Select(kv => $"{kv.Key}:{kv.Value}"));
        if (ContainsIgnoreCase(text, "PCI Express Root Port")) return "PCI Express Root Port";
        if (ContainsIgnoreCase(text, "PCI Express") || ContainsIgnoreCase(text, "PCIe")) return "PCI Express Device";
        if (ContainsIgnoreCase(text, "NVMe")) return "NVMe Storage";
        if (ContainsIgnoreCase(text, "Memory") || e.EventId == 46) return "Memory";
        if (ContainsIgnoreCase(text, "Processor Core") || e.EventId is 18 or 19)
            return ContainsIgnoreCase(text, "Cache") ? "Processor Core / Cache" : "Processor Core";
        if (ContainsIgnoreCase(text, "Cache")) return "Processor Cache";
        if (ContainsIgnoreCase(text, "Northbridge") || e.EventId == 20) return "Processor / Northbridge";
        return e.NamedData.TryGetValue("Component", out var comp) && !string.IsNullOrWhiteSpace(comp) ? comp.Trim() : null;
    }

    private static bool ContainsIgnoreCase(string text, string token) =>
        text.Contains(token, StringComparison.OrdinalIgnoreCase);

    private static AreaRow WheaRow(WinEvent e, bool recent)
    {
        var uncorrected = IsUncorrectedWheaEvent(e);
        var level = uncorrected ? AreaLevel.Error : recent ? AreaLevel.Warning : AreaLevel.Neutral;
        var severity = uncorrected ? "Uncorrected (fatal)" : "Corrected warning";
        var comp = WheaComponentHint(e);
        var summary = comp is not null
            ? $"{comp} (Event {e.EventId}) · {e.ShortMessage}"
            : $"Event {e.EventId} · {e.ShortMessage}";
        var detailLines = new List<string>
        {
            $"Severity: {severity} (Event ID {e.EventId})",
        };
        if (comp is not null) detailLines.Add($"Component: {comp}");
        if (e.NamedData.TryGetValue("ProcessorAPICID", out var apic) && apic.Length > 0)
            detailLines.Add($"Processor APIC ID: {apic}");
        if (e.NamedData.TryGetValue("ErrorType", out var errType) && errType.Length > 0)
            detailLines.Add($"Error type: {errType}");
        detailLines.Add(e.Message.Length > 0 ? e.Message : e.ShortMessage);

        return new AreaRow(
            level,
            [WindowsEventLog.FormatTime(e.Time), severity, summary],
            [AreaSort.TimeKey(e.Time), uncorrected ? "2" : "1", null],
            Detail: string.Join("\n", detailLines),
            ReviewKeys: [EventReviews.Key(e)]);
    }

    public static AreaReport Build(IReadOnlyList<WinEvent> events, IReadOnlyList<MinidumpFile>? dumps = null, DateTimeOffset? now = null)
    {
        var dmpList = dumps ?? [];
        var cutoff = (now ?? ReportClock.Now).AddDays(-RecentDays);
        var bsods = events.Where(IsBugCheckEvent).OrderByDescending(e => e.Time).ToList();
        var powerLosses = events.Where(IsPowerLossEvent).OrderByDescending(e => e.Time).ToList();
        var wheaEvents = events.Where(IsWheaEvent).OrderByDescending(e => e.Time).ToList();

        var recentBsods = bsods.Count(e => e.Time >= cutoff);
        // One bad shutdown logs both Event 41 (at the next boot) and Event 6008: count incidents, not events.
        var incidents = PowerLossIncidents(powerLosses);
        var recentPower = incidents.Count(t => t >= cutoff);
        var uncorrectedWhea = wheaEvents.Count(IsUncorrectedWheaEvent);
        var recentWhea = wheaEvents.Count(e => e.Time >= cutoff);

        var bsodLevel = EvaluateBsodLevel(bsods.Count, recentBsods);
        var powerLevel = EvaluatePowerLevel(powerLosses.Count, recentPower);
        var wheaLevel = EvaluateWheaLevel(wheaEvents.Count, recentWhea, uncorrectedWhea);

        var cards = new List<AreaCard>
        {
            BuildBsodCard(bsods, bsodLevel, cutoff, dmpList),
            BuildPowerLossCard(powerLosses, incidents, powerLevel, cutoff),
            BuildWheaCard(wheaEvents, uncorrectedWhea, wheaLevel, cutoff),
            BuildMinidumpsCard(dmpList, bsods),
        };

        var summary = BuildSummary(bsods.Count, powerLosses.Count, incidents.Count, wheaEvents.Count, uncorrectedWhea, recentBsods, recentPower, recentWhea);
        var status = DetermineOverallStatus(bsodLevel, powerLevel, wheaLevel);
        return new(cards, summary, status);
    }

    private static AreaLevel EvaluateBsodLevel(int total, int recent)
    {
        if (recent >= 2) return AreaLevel.Error;
        if (recent == 1) return AreaLevel.Warning;
        return total > 0 ? AreaLevel.Neutral : AreaLevel.Ok;
    }

    private static AreaLevel EvaluatePowerLevel(int total, int recent)
    {
        if (recent > 0) return AreaLevel.Warning;
        return total > 0 ? AreaLevel.Neutral : AreaLevel.Ok;
    }

    private static AreaLevel EvaluateWheaLevel(int total, int recent, int uncorrected)
    {
        if (uncorrected > 0) return AreaLevel.Error;
        if (recent > 0) return AreaLevel.Warning;
        return total > 0 ? AreaLevel.Neutral : AreaLevel.Ok;
    }

    private static AreaCard BuildBsodCard(List<WinEvent> bsods, AreaLevel level, DateTimeOffset cutoff, IReadOnlyList<MinidumpFile> dmpList) =>
        new("bsods", "Blue screen crashes (BSOD)", level,
            bsods.Count == 0 ? "None" : Plural(bsods.Count, "blue screen"),
            LatestMeta(bsods),
            ["When", "Type", "Details"],
            bsods.Select(e => BlueScreenRow(e, e.Time >= cutoff, dmpList)).ToList(),
            EmptyText: $"No blue screen crashes were recorded in the last {Days} days.");

    private static AreaCard BuildPowerLossCard(List<WinEvent> powerLosses, IReadOnlyList<DateTimeOffset> incidents, AreaLevel level, DateTimeOffset cutoff) =>
        new("power", "Unexpected power losses & resets", level,
            incidents.Count == 0 ? "None" : Plural(incidents.Count, "unexpected restart"),
            LatestMeta(powerLosses),
            ["When", "Type", "Details"],
            RestartGroups(powerLosses).ToList().SelectMany(group =>
            {
                var keys = group.Select(EventReviews.Key).ToList();
                return group.Select(e => RestartRow(e, e.Time >= cutoff, keys));
            }).ToList(),
            EmptyText: $"All shutdowns and restarts in the last {Days} days were clean.",
            Note: "Event 41 happens when the PC loses power, is forced off by holding the power button, or resets before Windows can write a crash log.");

    private static AreaCard BuildWheaCard(List<WinEvent> wheaEvents, int uncorrectedWhea, AreaLevel level, DateTimeOffset cutoff)
    {
        var headline = wheaEvents.Count == 0
            ? "None"
            : uncorrectedWhea > 0
                ? Plural(uncorrectedWhea, "uncorrected error") + (wheaEvents.Count > uncorrectedWhea ? $" ({wheaEvents.Count} total)" : "")
                : Plural(wheaEvents.Count, "corrected warning");

        return new("whea", "Hardware error events (WHEA)", level,
            headline,
            LatestMeta(wheaEvents),
            ["When", "Severity", "Details"],
            wheaEvents.Select(e => WheaRow(e, e.Time >= cutoff)).ToList(),
            EmptyText: $"No WHEA hardware error events were recorded in the last {Days} days.",
            Note: "WHEA-Logger records CPU core/cache, memory, and PCIe hardware faults reported directly by the processor or chipset.");
    }

    private static AreaCard BuildMinidumpsCard(IReadOnlyList<MinidumpFile> dmpList, List<WinEvent> bsods) =>
        new("minidumps", "Crash dump files", dmpList.Count > 0 ? AreaLevel.Neutral : AreaLevel.Ok,
            dmpList.Count == 0 ? "None on disk" : Plural(dmpList.Count, "dump file"),
            dmpList.FirstOrDefault() is { } d ? $"Latest: {d.FileName} ({WindowsEventLog.FormatTime(d.Created)})" : @"C:\Windows\Minidump",
            ["When", "File", "Size"],
            dmpList.Select(f => DumpRow(f, bsods)).ToList(),
            EmptyText: @"No dumps were found in C:\Windows\Minidump or at C:\Windows\MEMORY.DMP.",
            Note: "Expand a dump and choose Analyze dump to run Windows Debugging Tools. Analysis may download public symbols from Microsoft.");

    private static string LatestMeta(IReadOnlyList<WinEvent> list) =>
        list.FirstOrDefault() is { } e ? $"Latest: {WindowsEventLog.FormatTime(e.Time)}" : $"In the last {Days} days";

    private static string BuildSummary(int bsodCount, int powerCount, int incidentCount, int wheaCount, int uncorrectedWhea, int recentBsods, int recentPower, int recentWhea)
    {
        if (bsodCount == 0 && powerCount == 0 && wheaCount == 0)
            return $"No blue screens or unexpected restarts in the last {Days} days";

        var parts = new List<string>();
        if (bsodCount > 0) parts.Add(Plural(bsodCount, "blue screen"));
        if (incidentCount > 0) parts.Add(Plural(incidentCount, "unexpected restart"));
        if (wheaCount > 0)
            parts.Add(uncorrectedWhea > 0
                ? Plural(uncorrectedWhea, "uncorrected WHEA hardware error")
                : Plural(wheaCount, "WHEA hardware warning"));
        var noneRecent = recentBsods == 0 && recentPower == 0 && recentWhea == 0 && uncorrectedWhea == 0;
        return $"{string.Join(", ", parts)} in the last {Days} days" + (noneRecent ? $" (none in the last {RecentDays} days)" : "");
    }

    private static DiagnosticStatus DetermineOverallStatus(AreaLevel bsodLevel, AreaLevel powerLevel, AreaLevel wheaLevel)
    {
        if (bsodLevel == AreaLevel.Error || wheaLevel == AreaLevel.Error) return DiagnosticStatus.Error;
        if (bsodLevel == AreaLevel.Warning || powerLevel == AreaLevel.Warning || wheaLevel == AreaLevel.Warning) return DiagnosticStatus.Warning;
        return DiagnosticStatus.Ok;
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
