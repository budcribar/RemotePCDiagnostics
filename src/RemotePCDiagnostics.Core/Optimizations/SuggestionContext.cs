using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;

namespace RemotePCDiagnostics.Core.Optimizations;

/// <summary>
/// What each suggestion family (<see cref="BrowserSuggestions"/>, <see cref="OfficeSuggestions"/>, …) needs from
/// <see cref="MemorySuggestionService"/>: the system, the latest scan, the change journal, the per-click undo list, the allowlisted
/// registry write and logging. The service owns the state; the families only act through this.
/// </summary>
internal sealed class SuggestionContext(IMemorySystem sys, IChangeJournal? journal, Func<MemorySnapshot?> snapshot, Func<string> actor,
    Action<UndoEntry> addUndo, ILogger? log, ServiceActionService? serviceActions, RemediationService? remediation, Func<DateTime> now)
{
    public IMemorySystem Sys => sys;
    public IChangeJournal? JournalStore => journal;
    public MemorySnapshot? Snapshot => snapshot();
    public string Actor => actor();
    public ILogger? Logger => log;
    public ServiceActionService? ServiceActions => serviceActions;
    public RemediationService? Remediation => remediation;
    /// <summary>The clock (UTC) for values that record when a change was made.</summary>
    public Func<DateTime> Now => now;

    public void Log(string m) => log.Info("[memory] " + m);
    public void LogWarn(string m) => log.Warn("[memory] " + m);
    public void LogError(string m) => log.Error("[memory] " + m);

    public void AddUndo(UndoEntry u) => addUndo(u);

    public void Journal(ChangeKind kind, string target, string? previous, string label, bool restart = false, string? createdKey = null, string? extra = null)
    {
        try { journal?.Add(ChangeRecord.New(kind, target, previous, label, Actor, restart, createdKey, extra)); } catch (Exception ex) { Log("journal: " + ex.Message); }
    }

    /// <summary>Result of one allowlisted DWORD write. <see cref="Changed"/> = written (and journaled); false when it was already that value.
    /// <see cref="CreatedKey"/> = the topmost key the write created (journaled, so undo deletes it again while empty).</summary>
    public sealed record DwordWrite(bool Ok, bool Changed, string Target, string? Previous, string? CreatedKey = null)
    {
        public RegistryUndo.Item Item => new(Target, Previous, CreatedKey);
    }

    /// <summary>
    /// Sets an allowlisted DWORD, reads it back, and journals the old value (null = absent) only when the new value stuck.
    /// Never throws: access denied, UCPD or an organization policy is reported as not Ok, with nothing journaled.
    /// </summary>
    public DwordWrite SetDword(RegistrySetting setting, int value, Func<string, string> label, bool restart = true)
    {
        if (RegistryAllowlist.Find(setting.Target) is not { } r) return new(false, false, setting.Target, null);
        string? created = null;
        try
        {
            var before = sys.ReadDword(r);
            if (before == value) return new(true, false, r.Target, RegistryAllowlist.Encode(before));
            created = RegistryKeyCleanup.TopmostMissing(sys, r.Root, r.Key, Logger);
            sys.WriteDword(r, value);
            if (sys.ReadDword(r) != value)
            {
                Log($"{r.Target} = {value} didn't stick");
                RegistryKeyCleanup.Remove(sys, r.Root, r.Key, created, Logger);
                return new(false, false, r.Target, null);
            }
            var previous = RegistryAllowlist.Encode(before);
            Journal(ChangeKind.RegistryValue, r.Target, previous, label(RegistryAllowlist.Describe(before)), restart, created);
            return new(true, true, r.Target, previous, created);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogWarn($"{r.Target} = {value} failed: {ex.Message}");
            // The Host already tries this when SetValue fails; again here for keys created before a later failure. Never throws.
            RegistryKeyCleanup.Remove(sys, r.Root, r.Key, created, Logger);
            return new(false, false, r.Target, null);
        }
    }

    public const string PolicyRefused = "(administrator rights needed, or your organization manages this setting). Nothing was changed.";

    /// <summary>Per-item undo: restores every value this click changed (allowlisted only) and drops their journal records.</summary>
    public ActionOutcome UndoRegistry(UndoEntry u, string? done = null)
    {
        var items = RegistryUndo.Decode(u.Previous);
        if (items.Count == 0) return new(false, "The original setting wasn't recorded.");
        var remaining = new List<RegistryUndo.Item>();
        for (var i = items.Count - 1; i >= 0; i--) // last written first: the first write is the one that created any keys
        {
            var item = items[i];
            bool ok;
            try { ok = RegistryAllowlist.Restore(sys, item.Target, item.Previous, item.CreatedKey, Logger).Ok; }
            catch (Exception ex) when (ex is not OperationCanceledException) { Log($"Undo {item.Target}: {ex.Message}"); ok = false; }
            if (ok) { try { journal?.RemoveLatest(ChangeKind.RegistryValue, item.Target); } catch { } }
            else remaining.Insert(0, item);
        }
        if (remaining.Count > 0 && remaining.Count < items.Count)
            AddUndo(u with { Previous = RegistryUndo.Encode(remaining) });
        return remaining.Count == 0
            ? new(true, done ?? $"{u.Label} turned back on. Takes full effect after a restart.")
            : new(false, $"Windows didn't allow turning {u.Label} back on (administrator rights needed).");
    }
}
