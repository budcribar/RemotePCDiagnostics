using System.Text.Json;
using RemotePCDiagnostics.Core.Memory;

namespace RemotePCDiagnostics.Core.Changes;

/// <summary>
/// Registry keys this app created only to hold a value it wrote (they didn't exist before), so undo can delete them again.
/// An empty policy key left behind (Software\Policies\Google\Chrome, …\Office\16.0\Common\Privacy) is clutter, and for Chrome / Edge it can keep
/// "Managed by your organization" showing. Only the allowlisted value's own key and its ancestors are ever touched, deepest first, and only while
/// each one has no values and no subkeys.
/// </summary>
public static class RegistryKeyCleanup
{
    /// <summary>Never record or delete a key shallower than this ("SOFTWARE", "Software", "SYSTEM").</summary>
    public const int MinDepth = 2;

    /// <summary>The key and its ancestors, shallowest first: "SOFTWARE", "SOFTWARE\Policies", "SOFTWARE\Policies\Google", …</summary>
    public static IReadOnlyList<string> Chain(string key)
    {
        var parts = key.Split('\\', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var list = new List<string>(parts.Length);
        for (var i = 1; i <= parts.Length; i++) list.Add(string.Join('\\', parts.Take(i)));
        return list;
    }

    /// <summary>
    /// What to record before writing a value under <paramref name="key"/>: the topmost key in its path that doesn't exist yet (writing creates it and
    /// everything below it). Null when <paramref name="key"/> already exists. Never shallower than <see cref="MinDepth"/>.
    /// </summary>
    public static string? TopmostMissing(string key, Func<string, bool> exists)
    {
        var chain = Chain(key);
        if (chain.Count < MinDepth || exists(chain[^1])) return null;
        foreach (var k in chain.Skip(MinDepth - 1))
            if (!exists(k)) return k;
        return null;
    }

    /// <summary>Same, never throws: a key that can't be checked counts as existing (nothing is recorded, so nothing is ever deleted for it).</summary>
    public static string? TopmostMissing(IRegistryTweaks sys, RegistryRoot root, string key, ILogger? log = null)
    {
        try
        {
            return TopmostMissing(key, k =>
            {
                try { return sys.RegistryKeyExists(root, k); }
                catch (Exception ex) when (ex is not OperationCanceledException) { log.Info($"Key check {k}: {ex.Message}"); return true; }
            });
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.Info($"Key check {key}: {ex.Message}"); return null; }
    }

    /// <summary>
    /// The keys undo tries to delete, deepest first: <paramref name="key"/> and its ancestors up to <paramref name="createdTop"/>.
    /// Empty when nothing was created, or when <paramref name="createdTop"/> isn't <paramref name="key"/> or one of its ancestors (a journal
    /// edited by hand), or is shallower than <see cref="MinDepth"/>.
    /// </summary>
    public static IReadOnlyList<string> DeleteOrder(string key, string? createdTop)
    {
        if (string.IsNullOrWhiteSpace(createdTop)) return [];
        var chain = Chain(key);
        var top = string.Join('\\', createdTop.Split('\\', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        var i = -1;
        for (var n = 0; n < chain.Count; n++)
            if (chain[n].Equals(top, StringComparison.OrdinalIgnoreCase)) { i = n; break; }
        if (i < 0 || i + 1 < MinDepth) return [];
        return chain.Skip(i).Reverse().ToList();
    }

    /// <summary>
    /// A key the Host may delete when it's empty: an allowlisted value's key (<see cref="RegistryAllowlist"/>, the browsers' extension blocklists)
    /// or one of its ancestors, at least <see cref="MinDepth"/> deep.
    /// </summary>
    public static bool IsCleanupKey(RegistryRoot root, string? key)
    {
        if (string.IsNullOrWhiteSpace(key)) return false;
        var chain = Chain(key);
        if (chain.Count < MinDepth) return false;
        var k = chain[^1];
        return AllowedKeys(root).Any(a => a.Equals(k, StringComparison.OrdinalIgnoreCase) || a.StartsWith(k + "\\", StringComparison.OrdinalIgnoreCase));
    }

    private static IEnumerable<string> AllowedKeys(RegistryRoot root)
    {
        foreach (var s in RegistryAllowlist.All) if (s.Root == root) yield return s.Key;
        if (root == RegistryRoot.LocalMachine)
            foreach (var b in new[] { BrowserKind.Chrome, BrowserKind.Edge }) yield return BrowserExtensions.BlocklistKey(b);
    }

    /// <summary>
    /// After undo removed the value: deletes <paramref name="key"/> and the ancestors this app created (<paramref name="createdTop"/>), deepest first,
    /// each only if it has no values and no subkeys. Stops at the first key that is kept (its parents aren't empty either). Never throws: a key
    /// Windows won't delete is logged and left. Returns the keys deleted (or already gone).
    /// </summary>
    public static IReadOnlyList<string> Remove(IRegistryTweaks sys, RegistryRoot root, string key, string? createdTop, ILogger? log = null)
    {
        var deleted = new List<string>();
        foreach (var k in DeleteOrder(key, createdTop))
        {
            bool gone;
            try { gone = sys.DeleteRegistryKeyIfEmpty(root, k); }
            catch (Exception ex) when (ex is not OperationCanceledException) { log.Warn($"Couldn't remove the empty key {k}: {ex.Message}"); break; }
            if (!gone) break;
            deleted.Add(k);
        }
        if (deleted.Count > 0) log.Info($"Removed keys this app had created: {string.Join(", ", deleted)}");
        return deleted;
    }
}

/// <summary>
/// DWORD values a change touches as a side effect, recorded before it (<see cref="ChangeRecord.PreviousExtra"/>) so undo can put them back exactly.
/// JSON object name → value; a null value means the value didn't exist (undo deletes it).
/// </summary>
public static class PreviousDwords
{
    public static string Encode(IReadOnlyDictionary<string, int?> values) => JsonSerializer.Serialize(values);

    /// <summary>Null when nothing was recorded (older journal) or the text isn't a recorded set.</summary>
    public static IReadOnlyDictionary<string, int?>? Decode(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try { return JsonSerializer.Deserialize<Dictionary<string, int?>>(json) is { } d ? new Dictionary<string, int?>(d, StringComparer.OrdinalIgnoreCase) : null; }
        catch (JsonException) { return null; }
    }
}

/// <summary>
/// A service's DelayedAutostart value around a start-type change. Windows' Services console writes DelayedAutostart=0 when it sets "Automatic",
/// but many services never have the value at all, so undo must delete it again when it was absent instead of leaving 0 behind.
/// </summary>
public static class ServiceDelayedStart
{
    public const string ValueName = "DelayedAutostart";

    /// <summary>Recorded before a start-type change (journal form); null when it couldn't be read (undo then leaves it alone). Never throws.</summary>
    public static string? Record(IServiceConfig sys, string service, ILogger? log = null)
    {
        try
        {
            var (known, value) = sys.ReadServiceValue(service, ValueName);
            return known ? PreviousDwords.Encode(new Dictionary<string, int?> { [ValueName] = value }) : null;
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.Warn($"{service} {ValueName} read failed: {ex.Message}"); return null; }
    }

    /// <summary>What undo does: (false, _) = not recorded, leave it; (true, null) = delete it (it didn't exist); (true, v) = set it back to v.</summary>
    public static (bool Restore, int? Value) Plan(string? previousExtra) =>
        PreviousDwords.Decode(previousExtra) is { } d && d.TryGetValue(ValueName, out var v) ? (true, v) : (false, null);

    /// <summary>Runs after the start type is restored (which may write DelayedAutostart). Never throws: a failure is logged.</summary>
    public static void Restore(IServiceConfig sys, string service, string? previousExtra, ILogger? log = null)
    {
        var (restore, value) = Plan(previousExtra);
        if (!restore) return;
        try { sys.RestoreServiceValue(service, ValueName, value); }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.Warn($"{service} {ValueName} restore failed: {ex.Message}"); }
    }
}
