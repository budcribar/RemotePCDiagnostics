using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.History;

public sealed record FixHistoryItem(
    DateTimeOffset TimeUtc,
    string Category,
    string Actor,
    bool Success,
    string Summary,
    string? ImpactBadge);

public sealed record HistoryImpactSummary(
    long DiskReclaimedBytes,
    int TempFilesCleaned,
    long MemorySavedBytes,
    int MemoryFixesCount,
    int TotalFixesCount,
    int SuccessfulFixesCount,
    int UpdatesInstalledCount,
    int DevicesResetCount,
    int ServicesAdjustedCount,
    int TotalRunsCount,
    int PassedRunsCount,
    int WarningRunsCount,
    int CriticalRunsCount,
    IReadOnlyList<FixHistoryItem> Fixes)
{
    public string DiskHeadline => DiskReclaimedBytes > 0 ? HardwareInventory.FormatBytes(DiskReclaimedBytes) : "0 B";
    public string DiskMeta => TempFilesCleaned > 0
        ? $"{TempFilesCleaned.ToString("N0", CultureInfo.InvariantCulture)} temp file(s) & Recycle Bin cleaned"
        : DiskReclaimedBytes > 0 ? "Reclaimed from temporary files & cache" : "No disk cleanup run in this range";

    public string MemoryHeadline => MemorySavedBytes > 0 ? HardwareInventory.FormatBytes(MemorySavedBytes) : "0 B";
    public string MemoryMeta => MemoryFixesCount > 0
        ? $"{AreaModuleBase.Plural(MemoryFixesCount, "memory optimization")} applied"
        : "No memory actions run in this range";

    public string FixesHeadline => AreaModuleBase.Plural(SuccessfulFixesCount, "fix", "fixes") + " applied";
    public string FixesMeta
    {
        get
        {
            if (TotalFixesCount == 0) return "No automated fixes run in this range";
            var parts = new List<string>();
            if (UpdatesInstalledCount > 0) parts.Add(AreaModuleBase.Plural(UpdatesInstalledCount, "update"));
            if (DevicesResetCount > 0) parts.Add(AreaModuleBase.Plural(DevicesResetCount, "device reset"));
            if (ServicesAdjustedCount > 0) parts.Add(AreaModuleBase.Plural(ServicesAdjustedCount, "service action"));
            if (MemoryFixesCount > 0) parts.Add(AreaModuleBase.Plural(MemoryFixesCount, "memory fix", "memory fixes"));
            return parts.Count > 0 ? string.Join(" · ", parts) : $"{SuccessfulFixesCount} of {TotalFixesCount} succeeded";
        }
    }

    public string RunsHeadline => AreaModuleBase.Plural(TotalRunsCount, "diagnostic run");
    public string RunsMeta => TotalRunsCount == 0
        ? "No checks or tests recorded"
        : $"{PassedRunsCount} passed · {WarningRunsCount} warning · {CriticalRunsCount} critical";
}

/// <summary>
/// Builds the cumulative impact summary (disk space reclaimed, system memory saved, fixes applied, and test outcomes)
/// from persisted Event Log entries plus in-session remediation, memory suggestion, and service control records.
/// </summary>
public static class HistorySummary
{
    public const string RemediationModuleId = "Remediation";
    public const string ServiceFixModuleId = "ServiceAction";
    public const string MemoryFixModuleId = "MemoryOptimization";

    public static bool IsFixEntry(HistoryEntry e) =>
        string.Equals(e.Module, RemediationModuleId, StringComparison.OrdinalIgnoreCase)
        || string.Equals(e.Module, ServiceFixModuleId, StringComparison.OrdinalIgnoreCase)
        || string.Equals(e.Module, MemoryFixModuleId, StringComparison.OrdinalIgnoreCase);

    public static HistoryImpactSummary Build(
        IReadOnlyList<HistoryEntry> entries,
        RemediationService? remediation = null,
        MemorySuggestionService? memory = null,
        ServiceActionService? services = null,
        HistoryRange range = HistoryRange.All,
        DateTimeOffset? now = null)
    {
        var currentNow = now ?? DateTimeOffset.UtcNow;
        var span = HistoryQuery.RangeSpan(range);
        bool InRange(DateTimeOffset t) => span is null || t >= currentNow - span.Value;

        var filteredEntries = entries.Where(e => InRange(e.TimeUtc)).ToList();
        var diagnosticEntries = filteredEntries.Where(e => !IsFixEntry(e)).ToList();
        var persistedFixEntries = filteredEntries.Where(IsFixEntry).ToList();

        long diskBytes = 0;
        int tempFiles = 0;
        long memBytes = 0;
        int memFixes = 0;
        int totalFixes = 0;
        int okFixes = 0;
        int updatesInstalled = 0;
        int devicesReset = 0;
        int servicesAdjusted = 0;

        var fixList = new List<FixHistoryItem>();
        var seenKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var memEntries = new List<(DateTimeOffset TimeUtc, string Summary)>();
        foreach (var e in persistedFixEntries)
        {
            if (string.Equals(e.Module, MemoryFixModuleId, StringComparison.OrdinalIgnoreCase))
                memEntries.Add((e.TimeUtc, e.Summary.Trim()));
        }
        if (memory is not null)
        {
            foreach (var m in memory.Recent)
            {
                var tUtc = new DateTimeOffset(m.When).ToUniversalTime();
                if (InRange(tUtc))
                    memEntries.Add((tUtc, m.Message.Trim()));
            }
        }

        bool IsDuplicateOfMemoryFix(DateTimeOffset svcTime, string svcSummary)
        {
            var s = svcSummary.Trim();
            if (s.Length == 0) return false;
            var donePrefix = "Done: " + s + " until the next restart";
            foreach (var (memTime, memSummary) in memEntries)
            {
                if (Math.Abs((memTime - svcTime).TotalSeconds) <= 15 &&
                    (string.Equals(memSummary, s, StringComparison.OrdinalIgnoreCase) ||
                     memSummary.StartsWith(donePrefix, StringComparison.OrdinalIgnoreCase)))
                {
                    return true;
                }
            }
            return false;
        }

        // 1. Persisted fix entries from the Event Log
        foreach (var e in persistedFixEntries)
        {
            if (string.Equals(e.Module, ServiceFixModuleId, StringComparison.OrdinalIgnoreCase) &&
                IsDuplicateOfMemoryFix(e.TimeUtc, e.Summary))
            {
                continue;
            }

            var ok = string.Equals(e.Outcome, "OK", StringComparison.OrdinalIgnoreCase);
            totalFixes++;
            if (ok) okFixes++;

            var fb = LongMeas(e, "FreedDiskBytes");
            var rf = (int)LongMeas(e, "RemovedFiles");
            var mb = LongMeas(e, "FreedMemoryBytes");
            var up = (int)LongMeas(e, "UpdatesInstalled");
            var actor = e.Measurement("Actor") ?? "Local user";
            var kind = e.Measurement("Kind") ?? e.Module;

            diskBytes += fb;
            tempFiles += rf;
            memBytes += mb;
            updatesInstalled += up;

            if (mb > 0 || string.Equals(e.Module, MemoryFixModuleId, StringComparison.OrdinalIgnoreCase) || kind.Equals(nameof(RemediationKind.EndProcessGroup), StringComparison.OrdinalIgnoreCase))
                if (ok) memFixes++;
            if (kind is nameof(RemediationKind.RestartDevice) or nameof(RemediationKind.EnableDevice) && ok)
                devicesReset++;
            if (string.Equals(e.Module, ServiceFixModuleId, StringComparison.OrdinalIgnoreCase) && ok)
                servicesAdjusted++;

            var badge = FormatImpactBadge(fb, mb, up, rf);
            fixList.Add(new(e.TimeUtc, e.Test, actor, ok, e.Summary, badge));
            seenKeys.Add(DedupKey(e.TimeUtc, e.Summary));
        }

        // 2. Live in-session RemediationService records (if not already persisted in the Event Log list)
        if (remediation is not null)
        {
            foreach (var r in remediation.Recent)
            {
                var tUtc = new DateTimeOffset(r.When).ToUniversalTime();
                if (!InRange(tUtc)) continue;
                if (!seenKeys.Add(DedupKey(tUtc, r.Message))) continue;

                totalFixes++;
                if (r.Success) okFixes++;
                diskBytes += r.FreedDiskBytes;
                tempFiles += r.RemovedFiles;
                memBytes += r.FreedMemoryBytes;
                updatesInstalled += r.UpdatesInstalled;

                if (r.Success && (r.FreedMemoryBytes > 0 || r.Kind == RemediationKind.EndProcessGroup))
                    memFixes++;
                if (r.Success && r.Kind is RemediationKind.RestartDevice or RemediationKind.EnableDevice)
                    devicesReset++;

                var badge = FormatImpactBadge(r.FreedDiskBytes, r.FreedMemoryBytes, r.UpdatesInstalled, r.RemovedFiles);
                fixList.Add(new(tUtc, FriendlyKind(r.Kind), r.Actor, r.Success, r.Message, badge));
            }
        }

        // 3. Live in-session MemorySuggestionService records
        if (memory is not null)
        {
            long parsedMemFromRecent = 0;
            foreach (var m in memory.Recent)
            {
                var tUtc = new DateTimeOffset(m.When).ToUniversalTime();
                if (!InRange(tUtc)) continue;
                if (!seenKeys.Add(DedupKey(tUtc, m.Message))) continue;

                totalFixes++;
                if (m.Success)
                {
                    okFixes++;
                    memFixes++;
                }
                var freed = ParseFreedBytesFromText(m.Message);
                parsedMemFromRecent += freed;
                memBytes += freed;

                var badge = freed > 0 ? $"+{HardwareInventory.FormatBytes(freed)} RAM" : null;
                fixList.Add(new(tUtc, "Memory optimization", memory.Actor, m.Success, m.Message, badge));
            }
            if (memory.TotalFreedBytes > parsedMemFromRecent)
                memBytes += memory.TotalFreedBytes - parsedMemFromRecent;
        }

        // 4. Live in-session ServiceActionService records
        if (services is not null)
        {
            foreach (var s in services.Recent)
            {
                var tUtc = new DateTimeOffset(s.When).ToUniversalTime();
                if (!InRange(tUtc)) continue;
                if (IsDuplicateOfMemoryFix(tUtc, s.Message)) continue;
                if (!seenKeys.Add(DedupKey(tUtc, s.Message))) continue;

                totalFixes++;
                if (s.Success)
                {
                    okFixes++;
                    servicesAdjusted++;
                }
                fixList.Add(new(tUtc, $"Service ({s.Action})", s.Actor, s.Success, s.Message, null));
            }
        }

        var passed = diagnosticEntries.Count(e => string.Equals(e.Outcome, "OK", StringComparison.OrdinalIgnoreCase));
        var warn = diagnosticEntries.Count(e => string.Equals(e.Outcome, "Warning", StringComparison.OrdinalIgnoreCase));
        var crit = diagnosticEntries.Count(e => string.Equals(e.Outcome, "Critical", StringComparison.OrdinalIgnoreCase));

        return new(
            diskBytes,
            tempFiles,
            memBytes,
            memFixes,
            totalFixes,
            okFixes,
            updatesInstalled,
            devicesReset,
            servicesAdjusted,
            diagnosticEntries.Count,
            passed,
            warn,
            crit,
            fixList.OrderByDescending(f => f.TimeUtc).ToList());
    }

    public static string FriendlyKind(RemediationKind kind) => kind switch
    {
        RemediationKind.CheckAndInstallDriverUpdates => "Driver updates",
        RemediationKind.CheckAndInstallWindowsUpdates => "Windows updates",
        RemediationKind.RestartDevice => "Device reset",
        RemediationKind.EnableDevice => "Device enabled",
        RemediationKind.ScanHardwareChanges => "Hardware scan",
        RemediationKind.SetBalancedPowerPlan => "Power plan",
        RemediationKind.DisableFastStartup => "Fast Startup",
        RemediationKind.ScheduleCleanRestart or RemediationKind.CancelScheduledRestart => "System restart",
        RemediationKind.EndProcessGroup => "Memory / process",
        RemediationKind.DisableSystemProxy => "System proxy",
        RemediationKind.FlushDnsAndRenewIp or RemediationKind.SetPublicDns or RemediationKind.ResetDhcpDns => "DNS & network",
        RemediationKind.CleanTempFiles => "Disk cleanup",
        RemediationKind.OptimizeSsd => "SSD optimization",
        _ => "Automated fix",
    };

    /// <summary>Formats a <see cref="RemediationRecord"/> as an Event 1100 payload (current format) so it persists in Event Log history.</summary>
    public static string FormatRemediationEvent(RemediationRecord rec, string? machine, string? appVersion)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Test result: {RemediationModuleId}");
        sb.AppendLine($"Module id: {HistoryIds.Remediation:D}");
        sb.AppendLine($"Test: {FriendlyKind(rec.Kind)}");
        sb.AppendLine($"Outcome: {(rec.Success ? "OK" : "Warning")}");
        sb.AppendLine($"Summary: {rec.Message.Replace("\r", " ").Replace("\n", " ").Trim()}");
        sb.AppendLine($"Finished: {new DateTimeOffset(rec.When).ToString("O", CultureInfo.InvariantCulture)}");
        if (!string.IsNullOrWhiteSpace(machine)) sb.AppendLine($"Machine: {machine}");
        if (!string.IsNullOrWhiteSpace(appVersion)) sb.AppendLine($"App version: {appVersion}");
        sb.AppendLine($"Format: {ResultEventLogger.FormatVersion}");
        sb.AppendLine("Measurements:");
        sb.AppendLine($"  Kind={rec.Kind}");
        sb.AppendLine($"  Actor={rec.Actor}");
        if (rec.FreedDiskBytes > 0) sb.AppendLine($"  FreedDiskBytes={rec.FreedDiskBytes.ToString(CultureInfo.InvariantCulture)}");
        if (rec.RemovedFiles > 0) sb.AppendLine($"  RemovedFiles={rec.RemovedFiles.ToString(CultureInfo.InvariantCulture)}");
        if (rec.FreedMemoryBytes > 0) sb.AppendLine($"  FreedMemoryBytes={rec.FreedMemoryBytes.ToString(CultureInfo.InvariantCulture)}");
        if (rec.UpdatesInstalled > 0) sb.AppendLine($"  UpdatesInstalled={rec.UpdatesInstalled.ToString(CultureInfo.InvariantCulture)}");
        return sb.ToString().TrimEnd();
    }

    /// <summary>Formats a <see cref="ServiceActionRecord"/> as an Event 1100 payload (current format) so it persists in Event Log history.</summary>
    public static string FormatServiceEvent(ServiceActionRecord rec, string? machine, string? appVersion)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Test result: {ServiceFixModuleId}");
        sb.AppendLine($"Module id: {HistoryIds.ServiceAction:D}");
        sb.AppendLine($"Test: Service ({rec.Action})");
        sb.AppendLine($"Outcome: {(rec.Success ? "OK" : "Warning")}");
        sb.AppendLine($"Summary: {rec.Message.Replace("\r", " ").Replace("\n", " ").Trim()}");
        sb.AppendLine($"Finished: {new DateTimeOffset(rec.When).ToString("O", CultureInfo.InvariantCulture)}");
        if (!string.IsNullOrWhiteSpace(machine)) sb.AppendLine($"Machine: {machine}");
        if (!string.IsNullOrWhiteSpace(appVersion)) sb.AppendLine($"App version: {appVersion}");
        sb.AppendLine($"Format: {ResultEventLogger.FormatVersion}");
        sb.AppendLine("Measurements:");
        sb.AppendLine($"  Action={rec.Action}");
        sb.AppendLine($"  Actor={rec.Actor}");
        sb.AppendLine($"  Service={rec.ServiceName}");
        return sb.ToString().TrimEnd();
    }

    private static long LongMeas(HistoryEntry e, string name) =>
        long.TryParse(e.Measurement(name), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? Math.Max(0, v) : 0;

    private static string? FormatImpactBadge(long diskBytes, long memBytes, int updates, int files)
    {
        if (diskBytes > 0) return $"+{HardwareInventory.FormatBytes(diskBytes)} disk";
        if (memBytes > 0) return $"+{HardwareInventory.FormatBytes(memBytes)} RAM";
        if (updates > 0) return $"{AreaModuleBase.Plural(updates, "update")}";
        if (files > 0) return $"{AreaModuleBase.Plural(files, "file")} cleaned";
        return null;
    }

    private static string DedupKey(DateTimeOffset tUtc, string summary) =>
        $"{tUtc.UtcDateTime:yyyy-MM-ddTHH:mm}|{summary.Trim()}";

    public static long ParseFreedBytesFromText(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return 0;
        var m = Regex.Match(text, @"Freed about\s+([\d.]+)\s*(GB|MB|KB)", RegexOptions.IgnoreCase);
        if (!m.Success || !double.TryParse(m.Groups[1].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out var val))
            return 0;
        return m.Groups[2].Value.ToUpperInvariant() switch
        {
            "GB" => (long)(val * 1024 * 1024 * 1024),
            "MB" => (long)(val * 1024 * 1024),
            "KB" => (long)(val * 1024),
            _ => 0,
        };
    }
}
