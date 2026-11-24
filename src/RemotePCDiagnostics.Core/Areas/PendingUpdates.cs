using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.Json;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>One update Windows Update offers this PC and hasn't installed. <see cref="Id"/> is its Windows Update ID.</summary>
public sealed record PendingUpdate(
    string Id, string Title, string Kb, bool Driver, string Category, long SizeBytes, bool Downloaded, bool MayNeedRestart,
    string Severity, string DriverModel);

/// <summary>One raw entry from Windows Update's local installation history (<c>IUpdateSearcher.QueryHistory</c>).</summary>
public sealed record UpdateHistoryEntry(
    string Id, string Title, DateTimeOffset Date, int Operation, int ResultCode, int HResult);

/// <summary>A Windows Update installation whose most recent attempt failed within the history window.</summary>
public sealed record FailedUpdate(
    string Id, string Title, DateTimeOffset LastFailed, int HResult, int FailedAttempts);

/// <summary>The updates waiting on this PC, whether Windows waits for a restart, and any recently failed updates.</summary>
public sealed record PendingUpdateList(
    IReadOnlyList<PendingUpdate> Updates,
    bool RebootRequired,
    IReadOnlyList<FailedUpdate>? FailedUpdates = null);

/// <summary>
/// Reads pending updates and recent failed update history directly from Windows Update Agent's local COM cache
/// (<c>Microsoft.Update.Session</c>, <c>Online = false</c>) without spawning PowerShell or going online.
/// Each pending update gets its own Install button; the cards keep the button that checks online and installs everything.
/// </summary>
public static class PendingUpdates
{
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);
    /// <summary>The Programs and Device drivers checks both ask; one answer serves both when they run together.</summary>
    public static readonly TimeSpan CacheFor = TimeSpan.FromSeconds(60);
    public const int MaxRows = 50;
    public const int MaxHistoryEntries = 100;
    public const int FailedHistoryDays = 30;
    public const int RepeatFailureCount = 3;
    public const int OperationInstallation = 1;
    public const int ResultCodeFailed = 4;
    public const string SoftwareCardId = "pending-updates", DriverCardId = "pending-driver-updates", FailedCardId = "failed-updates";

    private static readonly object Gate = new();
    private static Task<PendingUpdateList?>? _read;
    private static DateTimeOffset _readAt;

    /// <summary>Forget the cached list (after an install changed it).</summary>
    public static void Invalidate()
    {
        lock (Gate) _read = null;
    }

    /// <summary>The pending updates and recent failed update history, or null when Windows couldn't be asked. Coalesces concurrent
    /// in-flight reads without caching completed results across refreshes, so out-of-process modules immediately see updates installed
    /// by RemediationService.</summary>
    public static Task<PendingUpdateList?> ReadAsync(SystemCommandRunner commands, CancellationToken ct)
    {
        if (commands.IsScripted || !OperatingSystem.IsWindows())
            return Task.FromResult<PendingUpdateList?>(null);

        lock (Gate)
        {
            if (_read is { IsCompleted: false }) return _read;
            _readAt = DateTimeOffset.UtcNow;
            return _read = ReadOnceWindowsAsync(ct);
        }
    }

    [SupportedOSPlatform("windows")]
    private static async Task<PendingUpdateList?> ReadOnceWindowsAsync(CancellationToken ct)
    {
        var acquired = false;
        try
        {
            acquired = await Session.AgentWindowsUpdate.WuaSearchLock.WaitAsync(Timeout, ct).ConfigureAwait(false);
            if (!acquired)
            {
                Invalidate();
                return null;
            }

            var list = await Task.Run(() => ReadWindows(DateTimeOffset.UtcNow), CancellationToken.None)
                .WaitAsync(Timeout, ct)
                .ConfigureAwait(false);
            if (list is null) Invalidate();
            return list;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            Invalidate();
            throw;
        }
        catch (TimeoutException)
        {
            Invalidate();
            return null;
        }
        catch (Exception)
        {
            Invalidate();
            return null;
        }
        finally
        {
            if (acquired)
                Session.AgentWindowsUpdate.WuaSearchLock.Release();
        }
    }

    [SupportedOSPlatform("windows")]
    private static PendingUpdateList? ReadWindows(DateTimeOffset now)
    {
        object? sessionObj = null;
        object? searcherObj = null;
        object? searchResultObj = null;
        object? updatesObj = null;
        object? sysInfoObj = null;

        try
        {
            var sessionType = Type.GetTypeFromProgID("Microsoft.Update.Session", throwOnError: true)!;
            sessionObj = Activator.CreateInstance(sessionType)!;
            dynamic session = sessionObj;
            try { session.ClientApplicationID = "Remote PC Diagnostics"; }
            catch (COMException) { }

            searcherObj = session.CreateUpdateSearcher();
            dynamic searcher = searcherObj;
            try { searcher.Online = false; }
            catch (COMException) { }

            searchResultObj = searcher.Search("IsInstalled=0 and IsHidden=0");
            dynamic searchResult = searchResultObj;
            updatesObj = searchResult.Updates;
            dynamic updates = updatesObj;

            var count = (int)updates.Count;
            var pending = new List<PendingUpdate>(count);
            for (var i = 0; i < count; i++)
            {
                object? updateObj = null;
                object? identityObj = null;
                object? kbObj = null;
                object? categoriesObj = null;
                object? behaviorObj = null;
                try
                {
                    updateObj = updates.Item(i);
                    dynamic u = updateObj;

                    identityObj = u.Identity;
                    dynamic? identity = identityObj;
                    var rawId = identity is not null ? (string?)identity.UpdateID ?? "" : "";
                    if (!Guid.TryParse(rawId, out var id)) continue;

                    var title = TryReadCom(() => (string?)u.Title) ?? "";
                    var driver = TryReadCom(() => Convert.ToInt32(u.Type, CultureInfo.InvariantCulture)) == 2;
                    var sizeBytes = TryReadCom(() => Convert.ToInt64(u.MaxDownloadSize, CultureInfo.InvariantCulture));
                    var downloaded = TryReadCom(() => (bool)u.IsDownloaded);
                    var severity = TryReadCom(() => (string?)u.MsrcSeverity) ?? "";
                    var driverModel = TryReadCom(() => (string?)u.DriverModel) ?? "";

                    var mayNeedRestart = false;
                    try
                    {
                        behaviorObj = u.InstallationBehavior;
                        if (behaviorObj is not null)
                            mayNeedRestart = Convert.ToInt32(((dynamic)behaviorObj).RebootBehavior, CultureInfo.InvariantCulture) != 0;
                    }
                    catch { }

                    var kbs = new List<string>();
                    try
                    {
                        kbObj = u.KBArticleIDs;
                        if (kbObj is not null)
                        {
                            dynamic kbColl = kbObj;
                            var kbCount = (int)kbColl.Count;
                            for (var j = 0; j < kbCount; j++)
                            {
                                var kb = (string?)kbColl.Item(j);
                                if (!string.IsNullOrWhiteSpace(kb)) kbs.Add("KB" + kb.Trim());
                            }
                        }
                    }
                    catch { }

                    var cats = new List<string>();
                    try
                    {
                        categoriesObj = u.Categories;
                        if (categoriesObj is not null)
                        {
                            dynamic catColl = categoriesObj;
                            var catCount = Math.Min((int)catColl.Count, 2);
                            for (var j = 0; j < catCount; j++)
                            {
                                object? catObj = null;
                                try
                                {
                                    catObj = catColl.Item(j);
                                    var name = (string?)((dynamic)catObj).Name;
                                    if (!string.IsNullOrWhiteSpace(name)) cats.Add(name.Trim());
                                }
                                finally { SafeReleaseCom(catObj); }
                            }
                        }
                    }
                    catch { }

                    pending.Add(new(id.ToString("D"), title, string.Join(", ", kbs), driver, string.Join(", ", cats),
                        Math.Max(0, sizeBytes), downloaded, mayNeedRestart, severity, driverModel));
                }
                finally
                {
                    SafeReleaseCom(behaviorObj);
                    SafeReleaseCom(categoriesObj);
                    SafeReleaseCom(kbObj);
                    SafeReleaseCom(identityObj);
                    SafeReleaseCom(updateObj);
                }
            }

            var failed = ReadFailedHistoryWindows(searcher, now);

            var rebootRequired = false;
            try
            {
                var sysInfoType = Type.GetTypeFromProgID("Microsoft.Update.SystemInfo", throwOnError: false);
                if (sysInfoType is not null)
                {
                    sysInfoObj = Activator.CreateInstance(sysInfoType);
                    if (sysInfoObj is not null)
                        rebootRequired = (bool)((dynamic)sysInfoObj).RebootRequired;
                }
            }
            catch { }

            return new(pending, rebootRequired, failed);
        }
        finally
        {
            SafeReleaseCom(sysInfoObj);
            SafeReleaseCom(updatesObj);
            SafeReleaseCom(searchResultObj);
            SafeReleaseCom(searcherObj);
            SafeReleaseCom(sessionObj);
        }
    }

    [SupportedOSPlatform("windows")]
    private static IReadOnlyList<FailedUpdate> ReadFailedHistoryWindows(dynamic searcher, DateTimeOffset now)
    {
        object? historyObj = null;
        try
        {
            var total = (int)searcher.GetTotalHistoryCount();
            if (total <= 0) return [];
            var take = Math.Min(total, MaxHistoryEntries);
            historyObj = searcher.QueryHistory(0, take);
            dynamic history = historyObj;
            var count = (int)history.Count;
            var entries = new List<UpdateHistoryEntry>(count);
            for (var i = 0; i < count; i++)
            {
                object? entryObj = null;
                object? identityObj = null;
                try
                {
                    entryObj = history.Item(i);
                    dynamic e = entryObj;
                    var title = TryReadCom(() => (string?)e.Title) ?? "";
                    if (string.IsNullOrWhiteSpace(title)) continue;

                    var operation = TryReadCom(() => Convert.ToInt32(e.Operation, CultureInfo.InvariantCulture));
                    var resultCode = TryReadCom(() => Convert.ToInt32(e.ResultCode, CultureInfo.InvariantCulture));
                    var hresult = TryReadCom(() => Convert.ToInt32(e.HResult, CultureInfo.InvariantCulture));
                    var date = TryReadComDate(() => (object?)e.Date);
                    if (date is null) continue;

                    var id = "";
                    try
                    {
                        identityObj = e.UpdateIdentity;
                        if (identityObj is not null)
                            id = (string?)((dynamic)identityObj).UpdateID ?? "";
                    }
                    catch { }

                    entries.Add(new(id.Trim(), title.Trim(), date.Value, operation, resultCode, hresult));
                }
                finally
                {
                    SafeReleaseCom(identityObj);
                    SafeReleaseCom(entryObj);
                }
            }
            return SummarizeFailedHistory(entries, now);
        }
        catch
        {
            // History failure must never break pending-update detection.
            return [];
        }
        finally
        {
            SafeReleaseCom(historyObj);
        }
    }

    /// <summary>
    /// Filters raw WUA history entries down to updates whose <em>most recent</em> installation attempt failed within the last
    /// <see cref="FailedHistoryDays"/> days. Updates that later succeeded are excluded, as are single transient Defender
    /// Security Intelligence definition failures.
    /// </summary>
    public static IReadOnlyList<FailedUpdate> SummarizeFailedHistory(IEnumerable<UpdateHistoryEntry> history, DateTimeOffset? now = null)
    {
        var cutoff = (now ?? ReportClock.Now).AddDays(-FailedHistoryDays);
        var failed = new List<FailedUpdate>();

        var groups = history
            .Where(e => e.Operation == OperationInstallation && !string.IsNullOrWhiteSpace(e.Title))
            .GroupBy(e => !string.IsNullOrWhiteSpace(e.Id) ? e.Id : e.Title, StringComparer.OrdinalIgnoreCase);

        foreach (var group in groups)
        {
            var ordered = group.OrderByDescending(e => e.Date).ToList();
            var latest = ordered[0];
            if (latest.ResultCode != ResultCodeFailed || latest.Date < cutoff)
                continue;

            // Count consecutive failed attempts since the most recent non-failed (e.g. succeeded) entry, within the window.
            var attempts = 0;
            foreach (var entry in ordered)
            {
                if (entry.ResultCode != ResultCodeFailed) break;
                if (entry.Date >= cutoff) attempts++;
            }
            if (attempts == 0) continue;

            // Defender signature updates run several times a day; ignore one-off transient failures.
            if (IsDefenderDefinition(latest.Title) && attempts < RepeatFailureCount)
                continue;

            failed.Add(new(latest.Id, latest.Title, latest.Date, latest.HResult, attempts));
        }

        return failed.OrderByDescending(f => f.LastFailed).ThenBy(f => f.Title, StringComparer.CurrentCultureIgnoreCase).ToList();
    }

    private static bool IsDefenderDefinition(string title) =>
        title.Contains("KB2267602", StringComparison.OrdinalIgnoreCase)
        || title.Contains("Security Intelligence Update for Microsoft Defender", StringComparison.OrdinalIgnoreCase);

    /// <summary>Formats a Windows Update <c>HRESULT</c> as hex with a plain-English hint for common failure codes.</summary>
    public static string DescribeHResult(int hresult)
    {
        if (hresult == 0) return "Unknown error";
        var code = $"0x{unchecked((uint)hresult):X8}";
        var hint = unchecked((uint)hresult) switch
        {
            0x80070643 => "Installer error (often WinRE partition or .NET)",
            0x800F081F or 0x800F0988 or 0x800F0922 or 0x800F0900 or 0x80073701 => "Servicing or component store error (try DISM / SFC)",
            0x80070070 => "Not enough free disk space",
            0x80070005 => "Access denied",
            0x8024001E or 0x80240030 => "Restart required or update service interrupted",
            0x80072EE2 or 0x80072EFD or 0x8024402C or 0x80244022 => "Network or Windows Update server unreachable",
            0x8024200B or 0x80240022 => "Update package failed to install",
            _ => null
        };
        return hint is null ? code : $"{code} ({hint})";
    }

    private static T? TryReadCom<T>(Func<T> read)
    {
        try { return read(); }
        catch { return default; }
    }

    private static DateTimeOffset? TryReadComDate(Func<object?> read)
    {
        try
        {
            var raw = read();
            if (raw is DateTime dt && dt != default)
                return new DateTimeOffset(dt.Kind == DateTimeKind.Unspecified ? DateTime.SpecifyKind(dt, DateTimeKind.Utc) : dt);
            if (raw is DateTimeOffset dto && dto != default)
                return dto;
            return null;
        }
        catch { return null; }
    }

    [SupportedOSPlatform("windows")]
    private static void SafeReleaseCom(object? obj)
    {
        if (obj is null) return;
        try
        {
            if (Marshal.IsComObject(obj))
                Marshal.FinalReleaseComObject(obj);
        }
        catch { }
    }

    /// <summary>Parses the JSON shape previously emitted by PendingUpdates.ps1; kept for tests and offline fixtures.</summary>
    public static PendingUpdateList? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !Bool(root, "Ok")) return null;
            var updates = new List<PendingUpdate>();
            if (root.TryGetProperty("Updates", out var list))
            {
                // Windows PowerShell writes a one-item list as the item itself.
                var items = list.ValueKind == JsonValueKind.Array ? list.EnumerateArray().ToList()
                    : list.ValueKind == JsonValueKind.Object ? [list] : [];
                foreach (var u in items)
                {
                    if (u.ValueKind != JsonValueKind.Object || !Guid.TryParse(Str(u, "Id"), out var id)) continue;
                    updates.Add(new(id.ToString("D"), Str(u, "Title"), Str(u, "Kb"), Bool(u, "Driver"), Str(u, "Category"),
                        long.TryParse(Str(u, "SizeBytes"), NumberStyles.Float, CultureInfo.InvariantCulture, out var size) ? size
                            : decimal.TryParse(Str(u, "SizeBytes"), NumberStyles.Float, CultureInfo.InvariantCulture, out var big) ? (long)Math.Min(big, long.MaxValue) : 0,
                        Bool(u, "Downloaded"), Bool(u, "MayNeedRestart"), Str(u, "Severity"), Str(u, "DriverModel")));
                }
            }
            return new(updates, Bool(root, "RebootRequired"));
        }
        catch (JsonException) { return null; }
    }

    private static string Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) ? v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : v.ValueKind == JsonValueKind.Number ? v.GetRawText() : "" : "";

    private static bool Bool(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.True;

    /// <summary>
    /// The card listing the pending Windows updates (<paramref name="drivers"/> false) or driver updates (true), one Install button per
    /// update. A list that couldn't be read gives a neutral card that says so: it doesn't change the check's result.
    /// </summary>
    public static AreaCard Card(PendingUpdateList? list, bool drivers)
    {
        var id = drivers ? DriverCardId : SoftwareCardId;
        var title = drivers ? "Pending driver updates" : "Pending Windows updates";
        var word = drivers ? "driver update" : "update";
        string[] columns = drivers ? ["Driver update", "Device", "Size", "Restart"] : ["Update", "Category", "Size", "Restart"];
        if (list is null)
            return new(id, title, AreaLevel.Neutral, "Not available", "", columns, [],
                EmptyText: "Windows couldn't be asked which updates are waiting. Use \"Check & install\" to check with Windows Update.");

        var mine = list.Updates.Where(u => u.Driver == drivers).OrderByDescending(u => u.Severity.Length > 0).ThenBy(u => u.Title, StringComparer.CurrentCultureIgnoreCase).ToList();
        var rows = mine.Take(MaxRows).Select(u => new AreaRow(AreaLevel.Neutral,
            [u.Title, drivers ? u.DriverModel : string.Join(" · ", new[] { u.Kb, u.Severity, u.Category }.Where(x => x.Length > 0)),
                u.SizeBytes > 0 ? Osquery.HardwareInventory.FormatBytes(u.SizeBytes) : "", u.MayNeedRestart ? "May be needed" : "No"],
            [null, null, u.SizeBytes.ToString("D20"), null], Key: u.Id,
            Actions: [new AreaAction(RemediationKind.InstallUpdate, "Install", u.Id, u.Title)])).ToList();

        var actions = new List<AreaAction>();
        if (mine.Count > 1)
            actions.Add(new(drivers ? RemediationKind.CheckAndInstallDriverUpdates : RemediationKind.CheckAndInstallWindowsUpdates,
                drivers ? "Check & install all driver updates" : "Check & install all updates"));
        if (list.RebootRequired) actions.Add(RestartAction);
        var headline = mine.Count == 0 ? (drivers ? "No driver updates waiting" : "No updates waiting") : AreaModuleBase.Plural(mine.Count, word) + " waiting";
        var meta = list.RebootRequired ? "Windows is waiting for a restart to finish installing updates"
            : mine.Count == 0 ? "As of Windows' last check with Windows Update" : "Install one at a time, or all at once";
        return new(id, title, mine.Count == 0 && !list.RebootRequired ? AreaLevel.Ok : AreaLevel.Neutral, headline, meta, columns, rows,
            EmptyText: mine.Count == 0 ? "Windows lists nothing waiting. \"Check & install\" asks Windows Update for anything newer." : null,
            Note: "From Windows' last check with Windows Update. \"Check & install\" checks again online.",
            Actions: actions.Count > 0 ? actions : null);
    }

    /// <summary>
    /// The card listing Windows updates whose most recent installation attempt failed in the last <see cref="FailedHistoryDays"/> days.
    /// Returns null when there are no failed updates to report.
    /// </summary>
    public static AreaCard? FailedCard(PendingUpdateList? list)
    {
        var failed = list?.FailedUpdates;
        if (failed is null || failed.Count == 0) return null;

        string[] columns = ["Update", "Last failed", "Attempts", "Error"];
        var rows = failed.Take(MaxRows).Select(f =>
        {
            var err = DescribeHResult(f.HResult);
            var detail = string.Join("\n", new[]
            {
                f.Title,
                $"Last failed: {WindowsEventLog.FormatTime(f.LastFailed)}",
                $"Failed attempts (last {FailedHistoryDays} days): {f.FailedAttempts}",
                $"Error: {err}",
                string.IsNullOrWhiteSpace(f.Id) ? null : $"Update ID: {f.Id}"
            }.Where(line => line is not null));
            return new AreaRow(
                f.FailedAttempts >= RepeatFailureCount ? AreaLevel.Error : AreaLevel.Warning,
                [f.Title, WindowsEventLog.FormatTime(f.LastFailed), f.FailedAttempts.ToString(CultureInfo.InvariantCulture), err],
                [null, AreaSort.TimeKey(f.LastFailed), f.FailedAttempts.ToString("D6", CultureInfo.InvariantCulture), null],
                Detail: detail,
                Key: string.IsNullOrWhiteSpace(f.Id) ? null : f.Id);
        }).ToList();

        var latest = failed[0];
        var actions = new List<AreaAction>
        {
            new(RemediationKind.CheckAndInstallWindowsUpdates, "Check & install updates")
        };
        if (list!.RebootRequired) actions.Add(RestartAction);

        return new(
            FailedCardId,
            "Failed Windows updates",
            AreaLevel.Warning,
            AreaModuleBase.Plural(failed.Count, "failed update"),
            $"Latest: {latest.Title}, {WindowsEventLog.FormatTime(latest.LastFailed)}",
            columns,
            rows,
            Note: $"From Windows Update history over the last {FailedHistoryDays} days. Updates that later succeeded are not shown.",
            Actions: actions);
    }

    /// <summary>The restart step offered next to fixes that can leave Windows waiting for a restart.</summary>
    public static AreaAction RestartAction => new(RemediationKind.ScheduleCleanRestart, "Restart Windows in 60s", "", "Restart to finish");
}
