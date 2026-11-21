using RemotePCDiagnostics.Core.Changes;

namespace RemotePCDiagnostics.Core.Workflow;

/// <summary>How a report line is colour-coded. Each one always comes with its text label, so print-outs and colour-blind readers get it too.</summary>
public enum ReportTag
{
    /// <summary>Green: undo puts it back exactly.</summary>
    Undoable,
    /// <summary>Blue: a removed app that undo reinstalls from the Microsoft Store.</summary>
    Reinstallable,
    /// <summary>Red: permanent (installed updates, deleted files, removed apps without a Store listing).</summary>
    Permanent,
    /// <summary>Gray: nothing lasting was changed, so there's nothing to undo.</summary>
    NothingToUndo,
    /// <summary>Gray: skipped by the service.</summary>
    Skipped,
    /// <summary>Gray: this change was undone afterwards (from the report box).</summary>
    Undone,
}

/// <summary>One line of the "What we fixed" list: either one journaled change, or the whole fix when it journaled nothing.</summary>
/// <param name="JournalId">The undo-journal entry, when there is one (only those get Undo / Reinstall buttons).</param>
/// <param name="CanReapply">Undone, and the fix can run again ("Apply again" / "Remove again").</param>
public sealed record ReportItem(string FixId, string FixTitle, string Text, ReportTag Tag, Guid? JournalId, DateTimeOffset? UndoneUtc, bool WasReinstall, bool CanReapply)
{
    public bool CanUndo => JournalId is not null && Tag is ReportTag.Undoable or ReportTag.Reinstallable;
}

public static class ReportItems
{
    /// <summary>Short label shown next to the colour.</summary>
    public static string Label(ReportTag t, bool wasReinstall = false) => t switch
    {
        ReportTag.Undoable => "Can be undone",
        ReportTag.Reinstallable => "Can be reinstalled",
        ReportTag.Permanent => "Permanent",
        ReportTag.NothingToUndo => "Nothing to undo",
        ReportTag.Skipped => "Skipped",
        ReportTag.Undone => wasReinstall ? "Reinstalled" : "Undone",
        _ => "",
    };

    /// <summary>CSS class suffix, shared by the saved report and the app (tag-undo, tag-reinstall, tag-perm, tag-none).</summary>
    public static string Css(ReportTag t) => t switch
    {
        ReportTag.Undoable => "undo",
        ReportTag.Reinstallable => "reinstall",
        ReportTag.Permanent => "perm",
        _ => "none",
    };

    public static ReportTag Of(UndoSupport u) => u switch
    {
        UndoSupport.Full => ReportTag.Undoable,
        UndoSupport.Reinstall => ReportTag.Reinstallable,
        UndoSupport.None or UndoSupport.PlaceholdersOnly => ReportTag.Permanent,
        _ => ReportTag.NothingToUndo,
    };

    /// <summary>
    /// The undo tag for a fix that journaled nothing. Tracked runs journal every lasting change, so an empty list then means nothing was
    /// changed for good; untracked (older) runs fall back to what the fix type says.
    /// </summary>
    public static ReportTag OfUntracked(WorkflowState s, FixOutcome o)
    {
        var u = s.Fixes.FirstOrDefault(f => f.Id == o.FixId)?.Undo ?? UndoSupport.Full;
        return u switch
        {
            UndoSupport.Full => s.ChangesTracked ? ReportTag.NothingToUndo : ReportTag.Undoable,
            UndoSupport.PlaceholdersOnly => ReportTag.Permanent,
            UndoSupport.None or UndoSupport.Reinstall when s.ChangesTracked => ReportTag.NothingToUndo,
            UndoSupport.None => ReportTag.Permanent,
            UndoSupport.Reinstall => ReportTag.Reinstallable,
            _ => ReportTag.NothingToUndo,
        };
    }

    /// <summary>Every line for the applied (successful, not skipped) fixes, in the order they ran.</summary>
    public static IReadOnlyList<ReportItem> Applied(WorkflowState s) => [.. s.Outcomes.Where(o => o.Success && !o.Skipped).SelectMany(o => For(s, o))];

    /// <summary>
    /// The lines for one fix: one per journaled change; when it journaled nothing, one line for the whole fix if it succeeded (a failed fix
    /// that recorded nothing changed nothing).
    /// </summary>
    public static IReadOnlyList<ReportItem> For(WorkflowState s, FixOutcome o)
    {
        if (o.Skipped) return [];
        if (o.Changes is { Count: > 0 } ch)
        {
            var reapply = CanReapply(s, o);
            return [.. ch.Select(c => new ReportItem(o.FixId, o.Title, c.Text, c.UndoneUtc is not null ? ReportTag.Undone : Of(c.Undo), c.JournalId, c.UndoneUtc,
                c.Undo == UndoSupport.Reinstall, reapply && c.UndoneUtc is not null))];
        }
        return o.Success ? [new(o.FixId, o.Title, o.Title, OfUntracked(s, o), null, null, false, false)] : [];
    }

    /// <summary>
    /// A fix can run again once every change it can put back has been put back (a partly undone fix would only redo the rest), and only for
    /// fixes the app can run outside the workflow's restarts: the same fix id, still in the review list.
    /// </summary>
    public static bool CanReapply(WorkflowState s, FixOutcome o) =>
        o.Changes is { Count: > 0 } ch
        && ch.Any(c => c.UndoneUtc is not null)
        && ch.All(c => c.UndoneUtc is not null || c.Undo is not (UndoSupport.Full or UndoSupport.Reinstall))
        && s.Fixes.Any(f => f.Id == o.FixId);
}
