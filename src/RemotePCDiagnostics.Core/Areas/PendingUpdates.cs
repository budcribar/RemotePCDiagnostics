using System.Text.Json;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>One update Windows Update offers this PC and hasn't installed. <see cref="Id"/> is its Windows Update ID.</summary>
public sealed record PendingUpdate(
    string Id, string Title, string Kb, bool Driver, string Category, long SizeBytes, bool Downloaded, bool MayNeedRestart,
    string Severity, string DriverModel);

/// <summary>The updates waiting on this PC, and whether Windows already waits for a restart to finish earlier ones.</summary>
public sealed record PendingUpdateList(IReadOnlyList<PendingUpdate> Updates, bool RebootRequired);

/// <summary>
/// Reads the pending updates from Windows' own list (the result of its last check with Windows Update), without going online: that
/// takes seconds, where a new online check can take minutes. Each update gets its own Install button; the cards keep the button
/// that checks online and installs everything.
/// </summary>
public static class PendingUpdates
{
    public static string Script => Scripts.PowerShellScripts.Get("PendingUpdates");
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);
    /// <summary>The Programs and Device drivers checks both ask; one answer serves both when they run together.</summary>
    public static readonly TimeSpan CacheFor = TimeSpan.FromSeconds(60);
    public const int MaxRows = 50;
    public const string SoftwareCardId = "pending-updates", DriverCardId = "pending-driver-updates";

    private static readonly object Gate = new();
    private static Task<PendingUpdateList?>? _read;
    private static DateTimeOffset _readAt;

    /// <summary>Forget the cached list (after an install changed it).</summary>
    public static void Invalidate()
    {
        lock (Gate) _read = null;
    }

    /// <summary>The pending updates, or null when Windows couldn't be asked.</summary>
    public static Task<PendingUpdateList?> ReadAsync(SystemCommandRunner commands, CancellationToken ct)
    {
        lock (Gate)
        {
            if (_read is { IsFaulted: false, IsCanceled: false } && DateTimeOffset.UtcNow - _readAt < CacheFor) return _read;
            _readAt = DateTimeOffset.UtcNow;
            return _read = ReadOnceAsync(commands, ct);
        }
    }

    private static async Task<PendingUpdateList?> ReadOnceAsync(SystemCommandRunner commands, CancellationToken ct)
    {
        try
        {
            var pr = await commands.RunPowerShellAsync(Script, Timeout, ct).ConfigureAwait(false);
            var list = pr is { ExitCode: 0 } ? Parse(pr.StdOut) : null;
            if (list is null) Invalidate();
            return list;
        }
        catch (OperationCanceledException)
        {
            Invalidate();
            throw;
        }
    }

    /// <summary>The script's JSON → the list; null when it reports failure or can't be read.</summary>
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
                        long.TryParse(Str(u, "SizeBytes"), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var size) ? size
                            : decimal.TryParse(Str(u, "SizeBytes"), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var big) ? (long)Math.Min(big, long.MaxValue) : 0,
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

    /// <summary>The restart step offered next to fixes that can leave Windows waiting for a restart.</summary>
    public static AreaAction RestartAction => new(RemediationKind.ScheduleCleanRestart, "Restart Windows in 60s", "", "Restart to finish");
}
