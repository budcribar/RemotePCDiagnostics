using System.Globalization;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// Top resource hogs (memory, CPU time, disk I/O) and system uptime via osquery <c>uptime</c> and <c>processes</c>,
/// plus Windows Fast Startup (<c>HiberbootEnabled</c>) via PowerShell.
/// </summary>
/// <summary>Physical memory: what Windows can use and what's free right now.</summary>
public sealed record MemoryUse(long TotalBytes, long AvailableBytes)
{
    public long UsedBytes => Math.Max(0, TotalBytes - AvailableBytes);
    public int UsedPercent => TotalBytes > 0 ? (int)Math.Round(100.0 * UsedBytes / TotalBytes) : 0;
}

public sealed class ResourceHogsModule(OsqueryRunner runner, SystemCommandRunner? commands = null) : OsqueryAreaModuleBase(runner), IHasAreaPanels
{
    public AreaPanels Panels => AreaPanels.MemorySuggestions;
    public const string ModuleName = ModuleSlugs.ResourceHogs;
    public const string UptimeSql = ResourceUsage.UptimeSql;
    public const string ProcessesSql = ResourceUsage.ProcessesSql;
    public static string FastStartupScript => Scripts.PowerShellScripts.Get("FastStartupState");

    /// <summary>RAM in use at or above this percentage makes the check a warning (matches the "Memory is almost full" suggestion).</summary>
    public const int HighMemoryPercent = 85;

    public const int LongUptimeDays = 14;
    public const int RecommendedRestartDays = 3;
    public const long FastStartupRestartSeconds = 4 * 3600;
    public const long HighSingleAppMemoryBytes = 4L * 1024 * 1024 * 1024;
    public const long HighTotalProcessMemoryBytes = 6L * 1024 * 1024 * 1024;
    public const int HighProcessCount = 150;
    public const int TopCount = 15;

    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.ResourceHogs;
    public override string DisplayName => "Resource hogs & uptime";
    protected override string FailedMessage => "Couldn't read running processes and uptime on this PC.";

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        var totalSteps = commands is not null ? 3 : 2;
        progress.ReportStep(1, totalSteps, "Checking system uptime…");
        var upQ = await QueryAsync(UptimeSql, ct).ConfigureAwait(false);
        progress.ReportStep(2, totalSteps, "Checking running processes…");
        var procQ = await QueryAsync(ProcessesSql, ct).ConfigureAwait(false);
        if (!upQ.Success && !procQ.Success) return AreaReport.Failed(FailedMessage);

        bool? fastStartup = null;
        MemoryUse? memory = null;
        if (commands is not null)
        {
            progress.ReportStep(3, totalSteps, "Checking memory use and Fast Startup…");
            var pr = await commands.RunPowerShellAsync(FastStartupScript, ct).ConfigureAwait(false);
            if (pr is { ExitCode: 0 } && !string.IsNullOrWhiteSpace(pr.StdOut))

            {
                try
                {
                    var row = OsqueryJson.ParseRows("[" + pr.StdOut.Trim().TrimStart('[').TrimEnd(']') + "]").FirstOrDefault();
                    fastStartup = row?.Str("FastStartup") switch { "1" => true, "0" => false, _ => null };
                    if (row?.Long("TotalBytes") is long total && total > 0 && row.Long("FreeBytes") is long free && free >= 0) memory = new MemoryUse(total, free);
                }
                catch (FormatException) { }
            }
        }

        var uptime = upQ.Success && upQ.Rows!.Count > 0 ? SystemUptimeInfo.FromRow(upQ.Rows[0], fastStartup) : null;
        var procs = procQ.Success ? procQ.Rows!.Select(ProcessResourceRow.FromRow).ToList() : null;
        var restartPending = RebootResumeCoordinator.TryReadPendingStateFile() is not null;
        return Build(uptime, procs, memory, restartPending);
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

    public static AreaReport Build(SystemUptimeInfo? uptime, IReadOnlyList<ProcessResourceRow>? processes, MemoryUse? memory = null, bool restartPending = false)
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
                var baseline = ResourceBaselineSnapshot.FromOsquery(uptime, processes);
                var usageDetail = baseline.UsedMemoryBytes > 0
                    ? $" ({HardwareInventory.FormatBytes(baseline.UsedMemoryBytes)} across {baseline.ProcessCount} processes)"
                    : "";
                rows.Add(new(AreaLevel.Neutral, ["Recommendation", $"A clean restart will clear accumulated background processes{usageDetail} and automatically resume this session after sign-in."]));
            }

            var uptimeActions = new List<AreaAction>();
            if (longUp && uptime.FastStartupEnabled == true)
                uptimeActions.Add(new(RemediationKind.DisableFastStartup, "Turn off Fast Startup"));
            if (restartPending) uptimeActions.Add(new(RemediationKind.CancelScheduledRestart, "Cancel restart"));
            else if (recommendRestart) uptimeActions.Add(new(RemediationKind.ScheduleCleanRestart, "Restart PC in 60s", ResourceBaselineSnapshot.FromOsquery(uptime, processes).Encode(), "Clean PC restart"));
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
        return new(cards, parts.Count > 0 ? string.Join(" · ", parts) : "No process details available.", status);
    }
}
