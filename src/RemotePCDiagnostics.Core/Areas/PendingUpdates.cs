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
    IReadOnlyList<FailedUpdate>? FailedUpdates = null,
    IReadOnlyList<string>? RebootReasons = null,
    bool CheckedOnline = false);

/// <summary>
/// Reads pending updates and recent failed update history directly from Windows Update Agent's local COM cache
/// (<c>Microsoft.Update.Session</c>, <c>Online = false</c>) without spawning PowerShell or going online.
/// Each pending update gets its own Install button; the cards keep the button that checks online and installs everything.
/// </summary>
public static class PendingUpdates
{
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);
    /// <summary>How long the Device drivers check waits for Windows Update's online driver search before it uses the cached list.</summary>
    public static readonly TimeSpan OnlineTimeout = TimeSpan.FromSeconds(90);
    /// <summary>Online search for driver updates only (what "Check & install driver updates" installs).</summary>
    public const string OnlineDriverCriteria = "IsInstalled=0 and Type='Driver' and IsHidden=0";
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
            return _read = ReadOnceWindowsAsync(ct);
        }
    }

    [SupportedOSPlatform("windows")]
    private static async Task<PendingUpdateList?> ReadOnceWindowsAsync(CancellationToken ct)
    {
        try
        {
            // Waits behind an online driver search (which fills the same cache) instead of giving up on it.
            var list = await Session.AgentWindowsUpdate.RunSerializedSearchAsync(() => ReadWindows(DateTimeOffset.UtcNow, online: false), Timeout, ct,
                gateWait: OnlineTimeout + Timeout).ConfigureAwait(false);
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
    }

    /// <summary>
    /// Asks Windows Update online for driver updates (the Device drivers check), so the card doesn't depend on when Windows last checked.
    /// Null when it couldn't be asked in <see cref="OnlineTimeout"/> (offline, Windows Update off or busy): callers fall back to
    /// <see cref="ReadAsync"/>. The list holds driver updates only and no failed history.
    /// </summary>
    public static async Task<PendingUpdateList?> ReadDriversOnlineAsync(SystemCommandRunner commands, CancellationToken ct)
    {
        if (commands.IsScripted || !OperatingSystem.IsWindows()) return null;
        try
        {
            return await Session.AgentWindowsUpdate.RunSerializedSearchAsync(
                () => OperatingSystem.IsWindows() ? ReadWindows(DateTimeOffset.UtcNow, online: true) : null, OnlineTimeout, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception) { return null; }
    }

    [SupportedOSPlatform("windows")]
    private static PendingUpdateList? ReadWindows(DateTimeOffset now, bool online)
    {
        object? sessionObj = null;
        object? searcherObj = null;
        object? searchResultObj = null;
        object? updatesObj = null;

        try
        {
            var sessionType = Type.GetTypeFromProgID("Microsoft.Update.Session", throwOnError: true)!;
            sessionObj = Activator.CreateInstance(sessionType)!;
            dynamic session = sessionObj;
            TryRunCom(() => session.ClientApplicationID = "Remote PC Diagnostics");

            searcherObj = session.CreateUpdateSearcher();
            dynamic searcher = searcherObj;
            TryRunCom(() => searcher.Online = online);

            searchResultObj = searcher.Search(online ? OnlineDriverCriteria : "IsInstalled=0 and IsHidden=0");
            dynamic searchResult = searchResultObj;
            updatesObj = searchResult.Updates;
            dynamic updates = updatesObj;

            var pending = ReadPendingUpdatesCom(updates);
            var failed = online ? null : ReadFailedHistoryWindows(searcher, now);
            var (rebootRequired, rebootReasons) = ReadRebootStateWindows();

            return new(pending, rebootRequired, failed, rebootReasons.Count > 0 ? rebootReasons : null, CheckedOnline: online);
        }
        finally
        {
            SafeReleaseCom(updatesObj);
            SafeReleaseCom(searchResultObj);
            SafeReleaseCom(searcherObj);
            SafeReleaseCom(sessionObj);
        }
    }

    private static void TryRunCom(Action action)
    {
        try { action(); }
        catch (COMException) { }
    }

    [SupportedOSPlatform("windows")]
    private static List<PendingUpdate> ReadPendingUpdatesCom(dynamic updates)
    {
        var count = (int)updates.Count;
        var pending = new List<PendingUpdate>(count);
        for (var i = 0; i < count; i++)
        {
            if (ReadSingleUpdateCom(updates, i) is { } item)
                pending.Add(item);
        }
        return pending;
    }

    [SupportedOSPlatform("windows")]
    private static PendingUpdate? ReadSingleUpdateCom(dynamic updates, int index)
    {
        object? updateObj = null;
        object? identityObj = null;
        try
        {
            updateObj = updates.Item(index);
            dynamic u = updateObj;

            identityObj = u.Identity;
            dynamic? identity = identityObj;
            var rawId = identity is not null ? (string?)identity.UpdateID ?? "" : "";
            if (!Guid.TryParse(rawId, out var id)) return null;

            var title = TryReadCom(() => (string?)u.Title) ?? "";
            var driver = TryReadCom(() => Convert.ToInt32(u.Type, CultureInfo.InvariantCulture)) == 2;
            var sizeBytes = TryReadCom(() => Convert.ToInt64(u.MaxDownloadSize, CultureInfo.InvariantCulture));
            var downloaded = TryReadCom(() => (bool)u.IsDownloaded);
            var severity = TryReadCom(() => (string?)u.MsrcSeverity) ?? "";
            var driverModel = TryReadCom(() => (string?)u.DriverModel) ?? "";
            var mayNeedRestart = ReadMayNeedRestartCom(u);
            var kbs = ReadKbArticlesCom(u);
            var cats = ReadCategoriesCom(u);

            return new(id.ToString("D"), title, string.Join(", ", kbs), driver, string.Join(", ", cats),
                Math.Max(0, sizeBytes), downloaded, mayNeedRestart, severity, driverModel);
        }
        finally
        {
            SafeReleaseCom(identityObj);
            SafeReleaseCom(updateObj);
        }
    }

    [SupportedOSPlatform("windows")]
    private static bool ReadMayNeedRestartCom(dynamic u)
    {
        object? behaviorObj = null;
        try
        {
            behaviorObj = u.InstallationBehavior;
            return behaviorObj is not null && Convert.ToInt32(((dynamic)behaviorObj).RebootBehavior, CultureInfo.InvariantCulture) != 0;
        }
        catch { return false; }
        finally { SafeReleaseCom(behaviorObj); }
    }

    [SupportedOSPlatform("windows")]
    private static List<string> ReadKbArticlesCom(dynamic u)
    {
        var kbs = new List<string>();
        object? kbObj = null;
        try
        {
            kbObj = u.KBArticleIDs;
            if (kbObj is null) return kbs;
            dynamic kbColl = kbObj;
            var kbCount = (int)kbColl.Count;
            for (var j = 0; j < kbCount; j++)
            {
                var kb = (string?)kbColl.Item(j);
                if (!string.IsNullOrWhiteSpace(kb)) kbs.Add("KB" + kb.Trim());
            }
        }
        catch { }
        finally { SafeReleaseCom(kbObj); }
        return kbs;
    }

    [SupportedOSPlatform("windows")]
    private static List<string> ReadCategoriesCom(dynamic u)
    {
        var cats = new List<string>();
        object? categoriesObj = null;
        try
        {
            categoriesObj = u.Categories;
            if (categoriesObj is null) return cats;
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
        catch { }
        finally { SafeReleaseCom(categoriesObj); }
        return cats;
    }

    [SupportedOSPlatform("windows")]
    private static (bool RebootRequired, List<string> Reasons) ReadRebootStateWindows()
    {
        var rebootReasons = new List<string>();
        var rebootRequired = false;
        object? sysInfoObj = null;
        try
        {
            var sysInfoType = Type.GetTypeFromProgID("Microsoft.Update.SystemInfo", throwOnError: false);
            if (sysInfoType is not null)
            {
                sysInfoObj = Activator.CreateInstance(sysInfoType);
                if (sysInfoObj is not null && (bool)((dynamic)sysInfoObj).RebootRequired)
                {
                    rebootRequired = true;
                    rebootReasons.Add("Windows Update Agent");
                }
            }
        }
        catch { }
        finally { SafeReleaseCom(sysInfoObj); }

        foreach (var reason in ReadRegistryRebootReasons())
        {
            rebootRequired = true;
            if (!rebootReasons.Contains(reason, StringComparer.OrdinalIgnoreCase))
                rebootReasons.Add(reason);
        }
        return (rebootRequired, rebootReasons);
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
            if (TryBuildFailedUpdate(group, cutoff) is { } item)
                failed.Add(item);
        }

        return failed.OrderByDescending(f => f.LastFailed).ThenBy(f => f.Title, StringComparer.CurrentCultureIgnoreCase).ToList();
    }

    private static FailedUpdate? TryBuildFailedUpdate(IEnumerable<UpdateHistoryEntry> group, DateTimeOffset cutoff)
    {
        var ordered = group.OrderByDescending(e => e.Date).ToList();
        var latest = ordered[0];
        if (latest.ResultCode != ResultCodeFailed || latest.Date < cutoff)
            return null;

        // Count consecutive failed attempts since the most recent non-failed (e.g. succeeded) entry, within the window.
        var attempts = CountConsecutiveFailures(ordered, cutoff);
        if (attempts == 0) return null;
        // Defender signature updates run several times a day; ignore one-off transient failures.
        if (IsDefenderDefinition(latest.Title) && attempts < RepeatFailureCount)
            return null;

        return new(latest.Id, latest.Title, latest.Date, latest.HResult, attempts);
    }

    private static int CountConsecutiveFailures(List<UpdateHistoryEntry> ordered, DateTimeOffset cutoff)
    {
        var attempts = 0;
        foreach (var entry in ordered)
        {
            if (entry.ResultCode != ResultCodeFailed) break;
            if (entry.Date >= cutoff) attempts++;
        }
        return attempts;
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
            var updates = ParseJsonUpdates(root);
            return new(updates, Bool(root, "RebootRequired"));
        }
        catch (JsonException) { return null; }
    }

    private static List<PendingUpdate> ParseJsonUpdates(JsonElement root)
    {
        var updates = new List<PendingUpdate>();
        if (!root.TryGetProperty("Updates", out var list)) return updates;

        // Windows PowerShell writes a one-item list as the item itself.
        var items = list.ValueKind == JsonValueKind.Array ? list.EnumerateArray().ToList()
            : list.ValueKind == JsonValueKind.Object ? [list] : [];
        foreach (var u in items)
        {
            if (TryParseJsonUpdate(u) is { } parsed)
                updates.Add(parsed);
        }
        return updates;
    }

    private static PendingUpdate? TryParseJsonUpdate(JsonElement u)
    {
        if (u.ValueKind != JsonValueKind.Object || !Guid.TryParse(Str(u, "Id"), out var id))
            return null;
        return new(id.ToString("D"), Str(u, "Title"), Str(u, "Kb"), Bool(u, "Driver"), Str(u, "Category"),
            ParseSizeBytes(Str(u, "SizeBytes")),
            Bool(u, "Downloaded"), Bool(u, "MayNeedRestart"), Str(u, "Severity"), Str(u, "DriverModel"));
    }

    private static long ParseSizeBytes(string raw)
    {
        if (long.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var size))
            return size;
        return decimal.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var big)
            ? (long)Math.Min(big, long.MaxValue)
            : 0;
    }

    private static string Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) ? v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : v.ValueKind == JsonValueKind.Number ? v.GetRawText() : "" : "";

    private static bool Bool(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.True;

    public const string CbsRebootPendingKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending";
    public const string WuRebootRequiredKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired";
    public const string SessionManagerKey = @"SYSTEM\CurrentControlSet\Control\Session Manager";
    public const string PendingFileRenameValue = "PendingFileRenameOperations";

    /// <summary>Reads standard HKLM pending-restart markers: CBS RebootPending, WU RebootRequired, and PendingFileRenameOperations.</summary>
    public static IReadOnlyList<string> ReadRegistryRebootReasons(
        Func<string, bool>? hklmKeyExists = null,
        Func<string, string, bool>? hklmNonEmptyMultiString = null)
    {
        var keyExists = hklmKeyExists ?? (path =>
        {
            if (!OperatingSystem.IsWindows()) return false;
            try { using var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(path, writable: false); return k is not null; }
            catch { return false; }
        });
        var hasMulti = hklmNonEmptyMultiString ?? ((path, name) =>
        {
            if (!OperatingSystem.IsWindows()) return false;
            try
            {
                using var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(path, writable: false);
                return k?.GetValue(name) is string[] arr && arr.Any(s => !string.IsNullOrWhiteSpace(s));
            }
            catch { return false; }
        });

        var reasons = new List<string>();
        if (keyExists(CbsRebootPendingKey)) reasons.Add("Component-Based Servicing (CBS)");
        if (keyExists(WuRebootRequiredKey)) reasons.Add("Windows Update");
        if (hasMulti(SessionManagerKey, PendingFileRenameValue)) reasons.Add("Pending file rename operations");
        return reasons;
    }

    /// <summary>
    /// The card listing the pending Windows updates (<paramref name="drivers"/> false) or driver updates (true), one Install button per
    /// update. A list that couldn't be read gives a neutral card that says so: it doesn't change the check's result.
    /// </summary>
    public static AreaCard Card(PendingUpdateList? list, bool drivers, Drivers.VendorDriverScan? vendor = null)
    {
        var id = drivers ? DriverCardId : SoftwareCardId;
        var title = drivers ? "Pending driver updates" : "Pending Windows updates";
        var word = drivers ? "driver update" : "update";
        string[] columns = drivers ? ["Driver update", "Device", "Size", "Restart"] : ["Update", "Category", "Size", "Restart"];
        if (drivers && vendor is not null) return DriverCard(list, vendor, columns);
        if (list is null)
            return new(id, title, AreaLevel.Neutral, "Not available", "", columns, [],
                EmptyText: "Windows couldn't be asked which updates are waiting. Use \"Check & install\" to check with Windows Update.");

        var mine = list.Updates.Where(u => u.Driver == drivers)
            .OrderByDescending(u => u.Severity.Length > 0)
            .ThenBy(u => u.Title, StringComparer.CurrentCultureIgnoreCase)
            .ToList();
        var rows = mine.Take(MaxRows).Select(u => BuildUpdateRow(u, drivers)).ToList();
        var actions = BuildCardActions(mine.Count, drivers, list.RebootRequired);
        var headline = BuildCardHeadline(mine.Count, drivers, word);
        var meta = BuildCardMeta(mine.Count, list);

        return new(id, title, mine.Count == 0 && !list.RebootRequired ? AreaLevel.Ok : AreaLevel.Neutral, headline, meta, columns, rows,
            EmptyText: mine.Count == 0 ? "Windows lists nothing waiting. \"Check & install\" asks Windows Update for anything newer." : null,
            Note: list.CheckedOnline ? "Windows Update was checked online just now."
                : "From Windows' last check with Windows Update. \"Check & install\" checks again online.",
            Actions: actions.Count > 0 ? actions : null);
    }

    /// <summary>
    /// The driver-updates card with the PC maker's newer packages after Windows Update's: one card for every out-of-date driver. The
    /// maker's rows have no Install button (they're downloaded from the maker's site); Windows Update's keep theirs.
    /// </summary>
    private static AreaCard DriverCard(PendingUpdateList? list, Drivers.VendorDriverScan vendor, string[] columns)
    {
        var wu = list?.Updates.Where(u => u.Driver).OrderByDescending(u => u.Severity.Length > 0)
            .ThenBy(u => u.Title, StringComparer.CurrentCultureIgnoreCase).ToList() ?? [];
        var maker = vendor.Updates.OrderBy(u => u.Title, StringComparer.CurrentCultureIgnoreCase).ToList();
        var rows = wu.Select(u => BuildUpdateRow(u, drivers: true)).Concat(maker.Select(u => VendorRow(vendor.Vendor, u))).Take(MaxRows).ToList();
        var total = wu.Count + maker.Count;

        var headline = total == 0 ? "No driver updates waiting" : AreaModuleBase.Plural(total, "driver update") + " waiting";
        var parts = new List<string>();
        if (list is null) parts.Add("Windows Update couldn't be asked");
        else if (list.RebootRequired) parts.Add(BuildCardMeta(wu.Count, list));
        else if (wu.Count > 0) parts.Add($"{wu.Count} from Windows Update");
        if (maker.Count > 0) parts.Add($"{maker.Count} newer from {vendor.Vendor}");
        if (parts.Count == 0) parts.Add(list!.CheckedOnline ? $"Checked online with Windows Update and {vendor.Vendor} just now" : $"Checked with Windows Update and {vendor.Vendor}");

        var notes = new List<string>
        {
            list is null ? "Windows Update couldn't be asked: \"Check & install\" checks again online."
                : list.CheckedOnline ? "Windows Update was checked online just now."
                : "Windows Update: from Windows' last check. \"Check & install\" checks again online.",
        };
        notes.Add(vendor.Problem is { } problem
            ? $"{vendor.Vendor}: {problem}"
            : $"{vendor.Vendor}: from {vendor.Vendor}'s driver catalog for this model ({AreaModuleBase.Plural(vendor.Compared, "package")} matched this PC). Download and run them from {vendor.Vendor}. When Windows Update also offers that driver, install Windows Update's first and check again.");

        var actions = new List<AreaAction>();
        if (wu.Count > 0) actions.Add(new(RemediationKind.CheckAndInstallDriverUpdates, wu.Count > 1 ? "Check & install all driver updates" : "Check & install driver updates"));
        if (list?.RebootRequired == true) actions.Add(RestartAction);

        return new(DriverCardId, "Pending driver updates", total == 0 && list is { RebootRequired: false } ? AreaLevel.Ok : AreaLevel.Neutral,
            headline, string.Join(" · ", parts), columns, rows,
            EmptyText: total == 0 ? $"Neither Windows Update nor {vendor.Vendor} lists a newer driver. \"Check & install\" asks Windows Update again." : null,
            Note: string.Join(" ", notes),
            Actions: actions.Count > 0 ? actions : null,
            PreserveRowOrder: false);
    }

    private static AreaRow VendorRow(string vendor, Drivers.VendorDriverUpdate u)
    {
        var size = u.SizeBytes > 0 ? Osquery.HardwareInventory.FormatBytes(u.SizeBytes) : "";
        var detail = string.Join("\n", new[]
        {
            $"{u.Title} ({u.Category})",
            $"Installed: {u.InstalledVersion} · {vendor}: {u.AvailableVersion}",
            u.Released is { } d ? $"Released: {d.ToString("d", CultureInfo.CurrentCulture)}" : null,
            u.PackageId.Length > 0 ? $"Package: {u.PackageId}" : null,
            $"Download: {u.DownloadUrl}",
            u.DetailsUrl is { } notes ? $"Release notes: {notes}" : null,
        }.Where(l => l is not null));
        return new(AreaLevel.Neutral,
            [$"{u.Title} {u.AvailableVersion}", $"Newer from {vendor} (installed {u.InstalledVersion})", size, "May be needed"],
            [null, null, u.SizeBytes.ToString("D20", CultureInfo.InvariantCulture), null],
            Key: $"{vendor.ToLowerInvariant()}:{u.PackageId}",
            Detail: detail,
            LinkUri: u.DownloadUrl,
            LinkText: $"Download from {vendor}");
    }

    private static AreaRow BuildUpdateRow(PendingUpdate u, bool drivers)
    {
        var category = drivers ? u.DriverModel : string.Join(" · ", new[] { u.Kb, u.Severity, u.Category }.Where(x => x.Length > 0));
        var size = u.SizeBytes > 0 ? Osquery.HardwareInventory.FormatBytes(u.SizeBytes) : "";
        return new(AreaLevel.Neutral,
            [u.Title, category, size, u.MayNeedRestart ? "May be needed" : "No"],
            [null, null, u.SizeBytes.ToString("D20"), null], Key: u.Id,
            Actions: [new AreaAction(RemediationKind.InstallUpdate, "Install", u.Id, u.Title)]);
    }

    private static List<AreaAction> BuildCardActions(int count, bool drivers, bool rebootRequired)
    {
        var actions = new List<AreaAction>();
        if (drivers && count > 0)
            actions.Add(new(RemediationKind.CheckAndInstallDriverUpdates,
                count > 1 ? "Check & install all driver updates" : "Check & install driver updates"));
        else if (!drivers && count > 1)
            actions.Add(new(RemediationKind.CheckAndInstallWindowsUpdates, "Check & install all updates"));
        if (rebootRequired) actions.Add(RestartAction);
        return actions;
    }

    private static string BuildCardHeadline(int count, bool drivers, string word)
    {
        if (count == 0) return drivers ? "No driver updates waiting" : "No updates waiting";
        return AreaModuleBase.Plural(count, word) + " waiting";
    }

    private static string BuildCardMeta(int count, PendingUpdateList list)
    {
        if (list.RebootRequired)
        {
            var rebootSuffix = list.RebootReasons is { Count: > 0 } ? $" ({string.Join(", ", list.RebootReasons)})" : "";
            return $"Windows is waiting for a restart to finish installing updates{rebootSuffix}";
        }
        if (count > 0) return "Install one at a time, or all at once";
        return list.CheckedOnline ? "Checked online with Windows Update just now" : "As of Windows' last check with Windows Update";
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
