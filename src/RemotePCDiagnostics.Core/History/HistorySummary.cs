using System.Globalization;
using System.Text;
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

public sealed record FixDayGroup(
    DateOnly Date,
    string Label,
    IReadOnlyList<FixHistoryItem> Fixes,
    int AppliedCount,
    int FailedCount)
{
    public string CountText => Fixes.Count == 1 ? "1 fix" : $"{Fixes.Count} fixes";
}

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
    int AppsRemovedCount,
    int StorageFixesCount,
    int TotalRunsCount,
    int PassedRunsCount,
    int WarningRunsCount,
    int CriticalRunsCount,
    IReadOnlyList<FixHistoryItem> Fixes)
{
    public string DiskHeadline => DiskReclaimedBytes > 0 ? HardwareInventory.FormatBytes(DiskReclaimedBytes) : "0 B";
    public string DiskMeta => TempFilesCleaned > 0
        ? $"{TempFilesCleaned.ToString("N0", CultureInfo.InvariantCulture)} file(s) cleaned"
        : DiskReclaimedBytes > 0 ? "Reclaimed from temp files, cache, etc." : "No disk cleanup run in this range";

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
            if (AppsRemovedCount > 0) parts.Add(AreaModuleBase.Plural(AppsRemovedCount, "app removal"));
            if (StorageFixesCount > 0) parts.Add(AreaModuleBase.Plural(StorageFixesCount, "storage fix", "storage fixes"));
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
    private const string DiskCleanupCategory = "Disk cleanup";
    private const string AppRemovalCategory = "App removal";
    private const string StorageCategory = "Storage optimization";
    private const string MemoryCategory = "Memory optimization";

    /// <summary>Removing apps frees disk space, not memory: listed and counted on its own.</summary>
    private static bool IsAppRemoval(MemoryActionType? action) =>
        action is MemoryActionType.RemoveApp or MemoryActionType.RemoveXboxApps or MemoryActionType.RemoveNarratorAddons;

    /// <summary>Shrinking the hibernation file frees disk space, not memory: a storage fix.</summary>
    private static bool IsStorageFix(MemoryActionType? action) => action is MemoryActionType.ReduceHibernateFile;

    /// <summary>The History category of a memory-suggestion action; the live record and its logged copy both go through here.</summary>
    private static string MemoryActionCategory(MemoryActionType? action) =>
        action is MemoryActionType.CleanStorage ? DiskCleanupCategory
        : IsAppRemoval(action) ? AppRemovalCategory
        : IsStorageFix(action) ? StorageCategory
        : MemoryCategory;

    public static bool IsFixEntry(HistoryEntry e) =>
        string.Equals(e.Module, RemediationModuleId, StringComparison.OrdinalIgnoreCase)
        || string.Equals(e.Module, ServiceFixModuleId, StringComparison.OrdinalIgnoreCase)
        || string.Equals(e.Module, MemoryFixModuleId, StringComparison.OrdinalIgnoreCase);

    public static IReadOnlyList<FixDayGroup> GroupFixesByDay(IEnumerable<FixHistoryItem> fixes, DateTimeOffset localNow) =>
        fixes.GroupBy(f => DateOnly.FromDateTime(f.TimeUtc.ToLocalTime().Date))
            .OrderByDescending(g => g.Key)
            .Select(g =>
            {
                var list = g.ToList();
                var applied = list.Count(f => f.Success);
                return new FixDayGroup(
                    g.Key,
                    HistoryQuery.DayLabel(list[0].TimeUtc.ToLocalTime(), localNow),
                    list,
                    applied,
                    list.Count - applied);
            }).ToList();

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
        int appsRemoved = 0;
        int storageFixes = 0;

        var fixList = new List<FixHistoryItem>();
        // Fixes and undos of memory suggestions, logged or live, so an undo can take back what its fix had counted.
        var memActs = new List<(DateTimeOffset TimeUtc, string Suggestion, MemoryActionType? Action, bool Undone, bool DiskRestored, bool Ok, long DiskBytes, int FixIdx)>();
        var persistedUnmatched = new List<(DateTimeOffset TimeUtc, string Summary)>();

        static string NormalizeSummary(string? s) => (s ?? "").Replace("\r", " ").Replace("\n", " ").Trim();

        IReadOnlyList<(T Item, DateTimeOffset TimeUtc)> ExcludeAlreadyPersisted<T>(IEnumerable<T> items, Func<T, (DateTimeOffset TimeUtc, string Summary)> project)
        {
            var candidates = new List<(T Item, DateTimeOffset TimeUtc, string Summary)>();
            foreach (var item in items)
            {
                var (tUtc, summary) = project(item);
                if (InRange(tUtc)) candidates.Add((item, tUtc, NormalizeSummary(summary)));
            }
            if (candidates.Count == 0 || persistedUnmatched.Count == 0)
                return candidates.Select(c => (c.Item, c.TimeUtc)).ToList();

            var pairs = new List<(int PersistedIdx, int CandidateIdx, double DiffSeconds)>();
            for (var pIdx = 0; pIdx < persistedUnmatched.Count; pIdx++)
            {
                var (pTime, pSummary) = persistedUnmatched[pIdx];
                for (var cIdx = 0; cIdx < candidates.Count; cIdx++)
                {
                    if (!string.Equals(pSummary, candidates[cIdx].Summary, StringComparison.OrdinalIgnoreCase)) continue;
                    var diff = Math.Abs((pTime - candidates[cIdx].TimeUtc).TotalSeconds);
                    if (diff <= 60) pairs.Add((pIdx, cIdx, diff));
                }
            }
            pairs.Sort((a, b) => a.DiffSeconds.CompareTo(b.DiffSeconds));
            var usedPersisted = new HashSet<int>();
            var matchedCandidates = new HashSet<int>();
            foreach (var (pIdx, cIdx, _) in pairs)
            {
                if (usedPersisted.Contains(pIdx) || matchedCandidates.Contains(cIdx)) continue;
                usedPersisted.Add(pIdx);
                matchedCandidates.Add(cIdx);
            }
            foreach (var pIdx in usedPersisted.OrderByDescending(i => i))
                persistedUnmatched.RemoveAt(pIdx);

            var remaining = new List<(T Item, DateTimeOffset TimeUtc)>(candidates.Count - matchedCandidates.Count);
            for (var i = 0; i < candidates.Count; i++)
                if (!matchedCandidates.Contains(i)) remaining.Add((candidates[i].Item, candidates[i].TimeUtc));
            return remaining;
        }

        var memEntries = new List<(DateTimeOffset TimeUtc, string Summary)>();
        foreach (var e in persistedFixEntries)
        {
            if (string.Equals(e.Module, MemoryFixModuleId, StringComparison.OrdinalIgnoreCase))
                memEntries.Add((e.TimeUtc, NormalizeSummary(e.Summary)));
        }
        if (memory is not null)
        {
            foreach (var m in memory.Recent)
            {
                var tUtc = new DateTimeOffset(m.When).ToUniversalTime();
                if (InRange(tUtc))
                    memEntries.Add((tUtc, NormalizeSummary(m.Message)));
            }
        }

        bool IsDuplicateOfMemoryFix(DateTimeOffset svcTime, string svcSummary)
        {
            var s = NormalizeSummary(svcSummary);
            if (s.Length == 0) return false;
            var donePrefix = "Done: " + s + " until the next restart";
            foreach (var (memTime, memSummary) in memEntries)
            {
                if (Math.Abs((memTime - svcTime).TotalSeconds) <= 30 &&
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
            var isMemoryModule = string.Equals(e.Module, MemoryFixModuleId, StringComparison.OrdinalIgnoreCase);
            MemoryActionType? action = isMemoryModule && Enum.TryParse<MemoryActionType>(kind, ignoreCase: true, out var parsed) ? parsed : null;
            var isStorageCleanup = action is MemoryActionType.CleanStorage;
            if (isStorageCleanup) mb = 0; // disk, not memory
            var isAppRemoval = IsAppRemoval(action);
            var isStorageFix = IsStorageFix(action);
            var undone = isMemoryModule && e.Measurement("Undone") == "1";
            var counts = ok && !undone; // an undo is listed, but it isn't a fix of its action's kind

            diskBytes += fb;
            tempFiles += rf;
            memBytes += mb;
            updatesInstalled += up;

            if (isAppRemoval && counts) appsRemoved++;
            if ((isStorageFix || isStorageCleanup || kind.Equals(nameof(RemediationKind.CleanTempFiles), StringComparison.OrdinalIgnoreCase)) && counts) storageFixes++;
            if (!isStorageCleanup && !isAppRemoval && !isStorageFix && (mb > 0 || isMemoryModule || kind.Equals(nameof(RemediationKind.EndProcessGroup), StringComparison.OrdinalIgnoreCase)))
                if (counts) memFixes++;
            if (kind is nameof(RemediationKind.RestartDevice) or nameof(RemediationKind.EnableDevice) && ok)
                devicesReset++;
            if (string.Equals(e.Module, ServiceFixModuleId, StringComparison.OrdinalIgnoreCase) && ok)
                servicesAdjusted++;

            var badge = FormatImpactBadge(fb, mb, up, rf);
            if (isMemoryModule) memActs.Add((e.TimeUtc, e.Measurement("Suggestion") ?? "", action, undone, e.Measurement("DiskRestored") == "1", ok, fb, fixList.Count));
            fixList.Add(new(e.TimeUtc, action is null ? e.Test : MemoryActionCategory(action), actor, ok, e.Summary, badge));
            persistedUnmatched.Add((e.TimeUtc, NormalizeSummary(e.Summary)));
        }

        // 2. Live in-session RemediationService records (if not already persisted in the Event Log list)
        if (remediation is not null)
        {
            foreach (var (r, tUtc) in ExcludeAlreadyPersisted(remediation.Recent, r => (new DateTimeOffset(r.When).ToUniversalTime(), r.Message)))
            {
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
                if (r.Success && r.Kind == RemediationKind.CleanTempFiles)
                    storageFixes++;

                var badge = FormatImpactBadge(r.FreedDiskBytes, r.FreedMemoryBytes, r.UpdatesInstalled, r.RemovedFiles);
                fixList.Add(new(tUtc, FriendlyKind(r.Kind), r.Actor, r.Success, r.Message, badge));
            }
        }

        // 3. Live in-session MemorySuggestionService records
        if (memory is not null)
        {
            foreach (var (m, tUtc) in ExcludeAlreadyPersisted(memory.Recent, m => (new DateTimeOffset(m.When).ToUniversalTime(), m.Message)))
            {
                totalFixes++;
                if (m.Success) okFixes++;

                if (m.Action is MemoryActionType.CleanStorage)
                {
                    var bytes = m.FreedDiskBytes;
                    var files = (int)Math.Min(m.RemovedFiles, int.MaxValue);
                    diskBytes += bytes;
                    tempFiles += files;
                    if (m.Success) storageFixes++;
                    var diskBadge = FormatImpactBadge(bytes, 0, 0, files);
                    fixList.Add(new(tUtc, DiskCleanupCategory, memory.Actor, m.Success, m.Message, diskBadge));
                    continue;
                }

                // An undo is listed under its action's category, but it isn't a fix of that kind.
                if (m.Success && !m.Undone)
                {
                    if (IsAppRemoval(m.Action)) appsRemoved++;
                    else if (IsStorageFix(m.Action)) storageFixes++;
                    else memFixes++;
                }
                var freed = m.FreedMemoryBytes;
                memBytes += freed;
                diskBytes += m.FreedDiskBytes; // an app removal, or the hibernation file shrunk

                var badge = FormatImpactBadge(m.FreedDiskBytes, freed, 0, 0);
                memActs.Add((tUtc, m.SuggestionId, m.Action, m.Undone, m.DiskRestored, m.Success, m.FreedDiskBytes, fixList.Count));
                fixList.Add(new(tUtc, MemoryActionCategory(m.Action), memory.Actor, m.Success, m.Message, badge));
            }
            // Only amounts carried on a record are counted, the same as its logged copy: History never adds the session total,
            // whose gains under the measurable threshold the card reports as "No measurable change".
        }

        // An undo that put the files back (the app reinstalled, the hibernation file full size again) takes the fix's bytes and its
        // count out of the totals. An undo that only turned settings back on (the program stays uninstalled) changes nothing.
        // It pairs with the latest fix of the same suggestion before it; with none in range, nothing changes.
        var reversed = new HashSet<int>();
        foreach (var undo in memActs.Where(a => a.Undone && a.DiskRestored && a.Ok && a.Suggestion.Length > 0 && (IsAppRemoval(a.Action) || IsStorageFix(a.Action))).OrderBy(a => a.TimeUtc))
        {
            var fix = memActs.Where(a => !a.Undone && a.Ok && a.Action == undo.Action && a.TimeUtc <= undo.TimeUtc && !reversed.Contains(a.FixIdx) &&
                string.Equals(a.Suggestion, undo.Suggestion, StringComparison.OrdinalIgnoreCase)).OrderByDescending(a => a.TimeUtc).Cast<(DateTimeOffset TimeUtc, string Suggestion, MemoryActionType? Action, bool Undone, bool DiskRestored, bool Ok, long DiskBytes, int FixIdx)?>().FirstOrDefault();
            if (fix is not { } f) continue;
            reversed.Add(f.FixIdx);
            diskBytes -= f.DiskBytes;
            if (IsAppRemoval(f.Action)) appsRemoved--; else storageFixes--;
            if (f.DiskBytes > 0) fixList[undo.FixIdx] = fixList[undo.FixIdx] with { ImpactBadge = $"-{HardwareInventory.FormatBytes(f.DiskBytes)} disk" };
        }

        // 4. Live in-session ServiceActionService records
        if (services is not null)
        {
            var nonMemServices = services.Recent.Where(s => !IsDuplicateOfMemoryFix(new DateTimeOffset(s.When).ToUniversalTime(), s.Message));
            foreach (var (s, tUtc) in ExcludeAlreadyPersisted(nonMemServices, s => (new DateTimeOffset(s.When).ToUniversalTime(), s.Message)))
            {
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
            appsRemoved,
            storageFixes,
            diagnosticEntries.Count,
            passed,
            warn,
            crit,
            fixList.OrderByDescending(f => f.TimeUtc).ToList());
    }

    public static string FriendlyKind(RemediationKind kind) => kind switch
    {
        RemediationKind.CheckAndInstallDriverUpdates => "Driver updates",
        RemediationKind.CheckAndInstallWindowsUpdates or RemediationKind.InstallUpdate => "Windows updates",
        RemediationKind.AnalyzeComponentStore or RemediationKind.CleanUpComponentStore or RemediationKind.RepairComponentStore
            or RemediationKind.RepairComponentStoreFromImage or RemediationKind.RepairSystemFiles => "Windows repair",
        RemediationKind.RestartDevice => "Device reset",
        RemediationKind.EnableDevice => "Device enabled",
        RemediationKind.ScanHardwareChanges => "Hardware scan",
        RemediationKind.SetBalancedPowerPlan => "Power plan",
        RemediationKind.DisableFastStartup => "Fast Startup",
        RemediationKind.ScheduleCleanRestart or RemediationKind.CancelScheduledRestart => "System restart",
        RemediationKind.EndProcessGroup => "Memory / process",
        RemediationKind.DisableSystemProxy => "System proxy",
        RemediationKind.FlushDnsAndRenewIp or RemediationKind.SetPublicDns or RemediationKind.ResetDhcpDns => "DNS & network",
        RemediationKind.CleanTempFiles => DiskCleanupCategory,
        RemediationKind.OptimizeSsd => "SSD optimization",
        RemediationKind.DisableDeviceWake => "Device wake",
        RemediationKind.InstallBiosUpdate => "BIOS update",
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

}
