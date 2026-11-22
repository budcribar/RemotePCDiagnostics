using RemotePCDiagnostics.Core.Osquery;
using System.Globalization;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// Top resource hogs (memory, CPU, disk I/O), system uptime, memory in use and Windows Fast Startup, read from <paramref name="source"/>: WMI
/// through the Agent (Fast Startup from the registry in the app), osquery and PowerShell in the Store edition without an Agent.
/// </summary>
/// <param name="sampleWindow">How long to wait between the two process snapshots used for CPU % and disk rate. Zero takes one snapshot and
/// reports cumulative CPU time and disk I/O only.</param>
/// <param name="timer">Times that wait (<see cref="SampleTimer.Instant"/> in replays).</param>
/// <param name="restartPending">Whether a clean restart this app scheduled is pending (default: its state file exists).</param>
public sealed class ResourceHogsModule(IResourceHogsSource source, TimeSpan? sampleWindow = null, SampleTimer? timer = null,
    Func<bool>? restartPending = null, ILogger? log = null) : AreaModuleBase(log), IHasAreaPanels
{
    public static readonly TimeSpan DefaultSampleWindow = TimeSpan.FromSeconds(2);
    private readonly TimeSpan _sampleWindow = sampleWindow ?? DefaultSampleWindow;
    private readonly SampleTimer _timer = timer ?? SampleTimer.Real;
    private readonly Func<bool> _restartPending = restartPending ?? (() => RebootResumeCoordinator.TryReadPendingStateFile() is not null);

    public AreaPanels Panels => AreaPanels.MemorySuggestions;
    public const string ModuleName = ModuleSlugs.ResourceHogs;

    /// <summary>RAM in use at or above this percentage makes the check a warning (matches the "Memory is almost full" suggestion).</summary>
    public const int HighMemoryPercent = 85;

    public const int LongUptimeDays = 14;
    public const int RecommendedRestartDays = 3;
    public const long FastStartupRestartSeconds = 4 * 3600;
    public const long HighSingleAppMemoryBytes = 4L * 1024 * 1024 * 1024;
    public const long HighTotalProcessMemoryBytes = 6L * 1024 * 1024 * 1024;
    public const int HighProcessCount = 150;
    public const int TopCount = 15;
    /// <summary>An app using at least this share of the whole PC's CPU during the sample makes the apps card a warning.</summary>
    public const double HighAppCpuPercent = 50;
    /// <summary>Commit charge at or above this share of the commit limit makes the commit card a warning (Windows is close to "out of memory").</summary>
    public const int HighCommitPercent = 90;

    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.ResourceHogs;
    public override string DisplayName => "Resource hogs & uptime";
    protected override string FailedMessage => "Couldn't read running processes and uptime on this PC.";

    public override Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken cancellationToken = default) => source.CheckAvailabilityAsync(cancellationToken);

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        const int totalSteps = 3;
        progress.ReportStep(1, totalSteps, "Checking system uptime…");
        var uptime = await source.ReadUptimeAsync(ct).ConfigureAwait(false);
        progress.ReportStep(2, totalSteps, "Checking running processes…");
        var procs = await source.ReadProcessesAsync(ct).ConfigureAwait(false);
        if (uptime is null && procs is null) return AreaReport.Failed(FailedMessage);

        // Second snapshot after a short wait: the difference gives CPU % and disk rate right now, not totals since each app started.
        Dictionary<int, ProcessRate>? rates = null;
        if (procs is not null && _sampleWindow > TimeSpan.Zero)
        {
            progress.ReportStep(2, totalSteps, "Measuring CPU and disk activity…");
            var started = _timer.Now;
            await _timer.DelayAsync(_sampleWindow, ct).ConfigureAwait(false);
            var again = await source.ReadProcessesAsync(ct).ConfigureAwait(false);
            var elapsed = _timer.Now - started;
            if (again is not null)
            {
                var cores = await source.ReadLogicalProcessorsAsync(ct).ConfigureAwait(false);
                rates = ProcessTree.Rates(procs, again, elapsed, cores);
                procs = again;
            }
        }

        progress.ReportStep(3, totalSteps, "Checking memory use and Fast Startup…");
        var (memory, fastStartup) = await source.ReadMemoryAsync(ct).ConfigureAwait(false);
        if (uptime is not null) uptime = uptime with { FastStartupEnabled = fastStartup };
        return Build(uptime, procs, memory, _restartPending(), rates);
    }

    public static List<ProcessGroupUsage> GroupProcesses(IEnumerable<ProcessResourceRow> rows) => ResourceUsage.GroupProcesses(rows);

    /// <summary>True when a clean restart makes sense to reduce memory/process usage (extended uptime, Fast Startup kernel hibernation, or heavy process footprint).</summary>
    public static bool ShouldRecommendRestart(SystemUptimeInfo uptime, IReadOnlyList<ProcessResourceRow>? processes)
    {
        if (uptime.Days >= RecommendedRestartDays) return true;
        if (uptime.FastStartupEnabled == true && uptime.TotalSeconds >= FastStartupRestartSeconds) return true;
        if (processes is not null)
        {
            var totalMem = processes.Sum(p => Math.Max(0, p.ResidentBytes));
            if (totalMem >= HighTotalProcessMemoryBytes || processes.Count >= HighProcessCount)
                return true;
        }
        return false;
    }

    public static string FormatCpuTime(long ms)
    {
        if (ms <= 0) return "0 s";
        var ts = TimeSpan.FromMilliseconds(ms);
        if (ts.TotalHours >= 1) return $"{(int)ts.TotalHours}h {ts.Minutes}m";
        if (ts.TotalMinutes >= 1) return $"{ts.Minutes}m {ts.Seconds}s";
        return $"{ts.TotalSeconds:0.#} s";
    }

    private static string NumKey(long v) => v.ToString(CultureInfo.InvariantCulture);

    public static string FormatPercent(double pct) => pct >= 10 ? $"{pct:0}%" : pct >= 0.05 ? $"{pct:0.0}%" : "0%";

    /// <summary>Card with commit charge vs installed RAM and page file use, or null when Windows didn't report the commit charge.</summary>
    public static AreaCard? CommitCard(MemoryUse mu)
    {
        if (!mu.HasCommit) return null;
        var used = mu.CommitUsedBytes!.Value;
        var limit = mu.CommitLimitBytes!.Value;
        var ram = mu.InstalledBytes ?? mu.TotalBytes;
        var high = mu.CommitPercent >= HighCommitPercent;
        var overRam = used > ram;
        var rows = new List<AreaRow>
        {
            new(high ? AreaLevel.Warning : AreaLevel.Neutral, ["Committed", $"{HardwareInventory.FormatBytes(used)} ({mu.CommitPercent}% of the limit)"]),
            new(AreaLevel.Neutral, ["Commit limit (RAM + page file)", HardwareInventory.FormatBytes(limit)]),
            new(AreaLevel.Neutral, [mu.InstalledBytes is null ? "Usable RAM" : "Installed RAM", HardwareInventory.FormatBytes(ram)]),
        };
        if (mu.PagefileSizeBytes is > 0 && mu.PagefileUsedBytes is { } pfUsed)
            rows.Add(new(AreaLevel.Neutral, ["Page file in use", $"{HardwareInventory.FormatBytes(pfUsed)} of {HardwareInventory.FormatBytes(mu.PagefileSizeBytes.Value)}"]));
        else if (mu.PagefileSizeBytes == 0)
            rows.Add(new(AreaLevel.Neutral, ["Page file", "None"]));
        rows.Add(new(high ? AreaLevel.Warning : AreaLevel.Neutral, ["What this means", high
            ? "Windows is close to its memory limit. Apps may fail to open or crash with \"out of memory\". Close apps you don't need, or restart."
            : overRam
                ? "Apps have reserved more memory than the PC has RAM, so Windows keeps some of it in the page file on disk. That's slower; more RAM or fewer open apps helps."
                : "Apps' reserved memory fits in RAM."]));
        return new("commit", "Memory commitments", high ? AreaLevel.Warning : AreaLevel.Ok,
            $"{HardwareInventory.FormatBytes(used)} committed",
            $"{mu.CommitPercent}% of the {HardwareInventory.FormatBytes(limit)} limit · {HardwareInventory.FormatBytes(ram)} RAM",
            ["Detail", "Value"], rows,
            Note: "Committed memory is what apps and Windows have reserved. It's backed by RAM and, when RAM runs short, by the page file.");
    }

    /// <summary>Card listing top-level apps with their helper processes rolled in (process-tree rollup).</summary>
    public static AreaCard AppsCard(IReadOnlyList<ProcessResourceRow> processes, IReadOnlyDictionary<int, ProcessRate>? rates)
    {
        var apps = ProcessTree.RollUp(processes, rates);
        var sampled = rates is not null;
        var top = apps.OrderByDescending(a => a.WorkingSetBytes).Take(TopCount).ToList();
        if (sampled)
        {
            // Make sure the busiest apps right now are listed even if they use little memory.
            foreach (var busy in apps.Where(a => a.CpuPercent >= 1).OrderByDescending(a => a.CpuPercent).Take(5))
                if (!top.Contains(busy)) top.Add(busy);
        }
        var topMem = top.FirstOrDefault();
        var topCpu = sampled ? apps.OrderByDescending(a => a.CpuPercent).FirstOrDefault(a => a.CpuPercent > 0) : null;
        var warn = topMem is not null && topMem.WorkingSetBytes >= HighSingleAppMemoryBytes || topCpu?.CpuPercent >= HighAppCpuPercent;

        string[] cols = sampled
            ? ["App", "Processes", "CPU now", "Memory", "Private memory", "Disk now"]
            : ["App", "Processes", "Memory", "Private memory", "CPU time", "Disk I/O"];
        var rows = top.Select(a =>
        {
            var level = a.WorkingSetBytes >= HighSingleAppMemoryBytes || a.CpuPercent >= HighAppCpuPercent ? AreaLevel.Warning : AreaLevel.Neutral;
            var count = a.ProcessCount.ToString(CultureInfo.InvariantCulture);
            var mem = HardwareInventory.FormatBytes(a.WorkingSetBytes);
            var priv = HardwareInventory.FormatBytes(a.PrivateBytes);
            IReadOnlyList<string> values = sampled
                ? [a.Name, count, FormatPercent(a.CpuPercent ?? 0), mem, priv, (a.DiskBytesPerSecond is > 0 and var rate ? HardwareInventory.FormatBytes(rate) + "/s" : "0 B/s")]
                : [a.Name, count, mem, priv, FormatCpuTime(a.CpuTimeMs), HardwareInventory.FormatBytes(a.DiskBytes)];
            IReadOnlyList<string?> keys = sampled
                ? [null, NumKey(a.ProcessCount), ((long)Math.Round((a.CpuPercent ?? 0) * 100)).ToString(CultureInfo.InvariantCulture), NumKey(a.WorkingSetBytes), NumKey(a.PrivateBytes), NumKey(a.DiskBytesPerSecond ?? 0)]
                : [null, NumKey(a.ProcessCount), NumKey(a.WorkingSetBytes), NumKey(a.PrivateBytes), NumKey(a.CpuTimeMs), NumKey(a.DiskBytes)];
            return new AreaRow(level, values, keys, Key: "app:" + a.Name, Detail: a.HelpersText,
                Actions: ProcessProtection.IsProtected(a.Name) ? null : [new(RemediationKind.EndProcessGroup, "End task", a.Name, a.DisplayName)]);
        }).ToList();

        var headline = topMem is null ? "No apps" : $"{topMem.Name} ({HardwareInventory.FormatBytes(topMem.WorkingSetBytes)})";
        var meta = topMem is null ? "" : topCpu is not null
            ? $"Busiest now: {topCpu.Name} ({FormatPercent(topCpu.CpuPercent ?? 0)} CPU) · {Plural(apps.Count, "app")}"
            : $"{Plural(apps.Count, "app")} · {Plural(processes.Count, "process", "processes")} total";
        return new("apps", "Top apps (with their helper processes)", warn ? AreaLevel.Warning : AreaLevel.Ok, headline, meta, cols, rows,
            EmptyText: "No apps running.",
            Note: (sampled ? $"CPU and disk are measured over {DefaultSampleWindow.TotalSeconds:0} seconds; CPU % is of the whole PC. " : "")
                + "Each app includes the helper processes it started (for example browser tabs, or the web views inside an app). "
                + "Memory is the working set; private memory is what the app has reserved for itself.");
    }

    public static AreaReport Build(SystemUptimeInfo? uptime, IReadOnlyList<ProcessResourceRow>? processes, MemoryUse? memory = null, bool restartPending = false,
        IReadOnlyDictionary<int, ProcessRate>? rates = null)
    {
        if (uptime is null && processes is null) return AreaReport.Failed("Couldn't read running processes and uptime on this PC.");
        var cards = new List<AreaCard>();
        var parts = new List<string>();

        if (memory is { } mu)
        {
            var high = mu.UsedPercent >= HighMemoryPercent;
            cards.Add(new("ram", "Memory in use", high ? AreaLevel.Warning : AreaLevel.Ok,
                $"{mu.UsedPercent}% in use",
                $"{HardwareInventory.FormatBytes(mu.AvailableBytes)} free of {HardwareInventory.FormatBytes(mu.TotalBytes)} usable",
                ["Detail", "Value"],
                [
                    new(AreaLevel.Neutral, ["In use", $"{HardwareInventory.FormatBytes(mu.UsedBytes)} ({mu.UsedPercent}%)"]),
                    new(AreaLevel.Neutral, ["Free", HardwareInventory.FormatBytes(mu.AvailableBytes)]),
                    new(AreaLevel.Neutral, ["Usable by Windows", HardwareInventory.FormatBytes(mu.TotalBytes)]),
                    new(high ? AreaLevel.Warning : AreaLevel.Neutral, ["What this means", high
                        ? "Memory is almost full, so Windows is using the much slower page file. Closing apps you don't need helps (see the suggestions below)."
                        : "There's enough free memory."]),
                ],
                Note: "\"Usable\" can be less than the installed memory: Windows sets some aside, for example for built-in graphics."));
            parts.Add($"RAM {mu.UsedPercent}% in use");
            if (CommitCard(mu) is { } commit) cards.Add(commit);
        }

        if (uptime is null)
            cards.Add(AreaCard.Failed("uptime", "System uptime", "Couldn't read system uptime."));
        else
        {
            var longUp = uptime.Days >= LongUptimeDays;
            var recommendRestart = ShouldRecommendRestart(uptime, processes);
            var level = longUp ? AreaLevel.Warning : AreaLevel.Ok;
            var meta = uptime.FastStartupEnabled == true
                ? (longUp ? "Fast Startup is on — Shut Down hibernates the kernel; use Restart for a clean reboot" : "Fast Startup is enabled")
                : uptime.FastStartupEnabled == false ? "Fast Startup is off (clean shutdowns)" : "Time since last full restart";
            var rows = new List<AreaRow>
            {
                new(level, ["Time since last restart", $"{uptime.Days} days, {uptime.Hours} hours, {uptime.Minutes} minutes"]),
                new(AreaLevel.Neutral, ["Fast Startup", uptime.FastStartupEnabled switch { true => "Enabled (Shut Down does not fully reset the kernel)", false => "Disabled", _ => "Not reported" }]),
            };
            if (longUp)
            {
                rows.Add(new(AreaLevel.Warning, ["Recommendation", $"This PC hasn't been restarted in {uptime.Days} days. Restarting clears stuck background processes and applies pending updates."]));
            }
            else if (recommendRestart)
            {
                var baseline = ResourceBaselineSnapshot.From(uptime, processes);
                var usageDetail = baseline.UsedMemoryBytes > 0
                    ? $" ({HardwareInventory.FormatBytes(baseline.UsedMemoryBytes)} across {baseline.ProcessCount} processes)"
                    : "";
                rows.Add(new(AreaLevel.Neutral, ["Recommendation", $"A clean restart will clear accumulated background processes{usageDetail} and automatically resume this session after sign-in."]));
            }

            var uptimeActions = new List<AreaAction>();
            if (longUp && uptime.FastStartupEnabled == true)
                uptimeActions.Add(new(RemediationKind.DisableFastStartup, "Turn off Fast Startup"));
            if (restartPending) uptimeActions.Add(new(RemediationKind.CancelScheduledRestart, "Cancel restart"));
            else if (recommendRestart) uptimeActions.Add(new(RemediationKind.ScheduleCleanRestart, "Restart PC in 60s", ResourceBaselineSnapshot.From(uptime, processes).Encode(), "Clean PC restart"));
            cards.Add(new("uptime", "System uptime", level, $"Up {uptime.FriendlyDuration}", meta, ["Detail", "Value"], rows,
                Actions: uptimeActions.Count > 0 ? uptimeActions : null));
            parts.Add($"Up {uptime.FriendlyDuration}" + (longUp ? " (needs restart)" : ""));
        }

        if (processes is null)
        {
            cards.Add(AreaCard.Failed("memory", "Top memory consumers", "Couldn't read running processes."));
        }
        else
        {
            cards.Add(AppsCard(processes, rates));
            var groups = GroupProcesses(processes);
            var byMem = groups.OrderByDescending(g => g.MemoryBytes).Take(TopCount).ToList();
            var byCpu = groups.OrderByDescending(g => g.CpuTimeMs).Take(TopCount).ToList();
            var topMem = byMem.FirstOrDefault();
            var memWarn = topMem is not null && topMem.MemoryBytes >= HighSingleAppMemoryBytes;

            string[] cols = ["App", "Instances", "Memory", "CPU time", "Disk I/O"];
            AreaRow Row(ProcessGroupUsage g, bool warnHighMem = false) => new(
                warnHighMem && g.MemoryBytes >= HighSingleAppMemoryBytes ? AreaLevel.Warning : AreaLevel.Neutral,
                [g.Name, g.Instances.ToString(CultureInfo.InvariantCulture), HardwareInventory.FormatBytes(g.MemoryBytes), FormatCpuTime(g.CpuTimeMs), HardwareInventory.FormatBytes(g.DiskBytes)],
                [null, NumKey(g.Instances), NumKey(g.MemoryBytes), NumKey(g.CpuTimeMs), NumKey(g.DiskBytes)],
                Key: g.Name,
                Actions: ProcessProtection.IsProtected(g.Name) ? null : [new(RemediationKind.EndProcessGroup, "End task", g.Name, g.DisplayName)]);

            cards.Add(new("memory", "Top memory consumers", memWarn ? AreaLevel.Warning : AreaLevel.Ok,
                topMem is null ? "No apps" : $"{topMem.Name} ({HardwareInventory.FormatBytes(topMem.MemoryBytes)})",
                topMem is null ? "" : $"{Plural(groups.Count, "active app")} · {Plural(processes.Count, "process", "processes")} total",
                cols, byMem.Select(g => Row(g, true)).ToList(),
                Note: "Apps with multiple background processes (like browsers) are grouped together."));

            var topCpu = byCpu.FirstOrDefault();
            cards.Add(new("cpu", "Most CPU & disk activity", AreaLevel.Neutral,
                topCpu is null ? "No apps" : topCpu.Name,
                topCpu is null ? "" : $"{FormatCpuTime(topCpu.CpuTimeMs)} CPU time · {HardwareInventory.FormatBytes(topCpu.DiskBytes)} disk I/O",
                cols, byCpu.Select(g => Row(g)).ToList(),
                Note: "Cumulative CPU time and disk read/write since each app started."));

            if (topMem is not null)
                parts.Add($"top memory: {topMem.Name} ({HardwareInventory.FormatBytes(topMem.MemoryBytes)})");
        }

        var status = AreaReport.Worst(cards.Select(c => c.ErrorText is not null ? AreaLevel.Warning : c.Level));
        // Tracked over time: memory in use rising as junk piles up, and how long the PC goes between restarts.
        var metrics = new List<KeyMetric>();
        if (memory is { } m2) metrics.Add(CheckKeyMetrics.MemoryUsed(m2.UsedPercent));
        if (uptime is not null) metrics.Add(CheckKeyMetrics.Uptime(TimeSpan.FromDays(uptime.Days) + TimeSpan.FromHours(uptime.Hours)));
        return new(cards, parts.Count > 0 ? string.Join(" · ", parts) : "No process details available.", status) { KeyMetrics = metrics.Count > 0 ? metrics : null };
    }
}
