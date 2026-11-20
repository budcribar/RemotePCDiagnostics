using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Optimizations;

/// <summary>Defender exclusions for build folders and tools: add the missing ones, read them back, journal each.</summary>
internal sealed class DefenderSuggestions(SuggestionContext c)
{
    /// <summary>Adds only the missing exclusions, confirms them by reading back, journals each one for Undo all.</summary>
    internal async Task<ActionOutcome> AddDefenderExclusionsAsync(MemorySuggestion s, CancellationToken ct)
    {
        if (c.Snapshot?.Defender is not { HasWork: true } d) return new(false, "Nothing left to exclude.");
        bool ok; string? output;
        try { (ok, output) = await c.Sys.AddDefenderExclusionsAsync(d.MissingFolders, d.MissingProcesses, ct).ConfigureAwait(false); }
        catch (AdminRequiredException ex) { return new(false, ex.Message); }
        if (!ok) return new(false, "Windows didn't allow adding Defender exclusions (your organization may manage Defender). Nothing was changed.");
        var (folders, procs) = DefenderProbe.Confirmed(output, d.MissingFolders, d.MissingProcesses);
        foreach (var f in folders) c.Journal(ChangeKind.DefenderExclusion, "path|" + f, null, $"Defender no longer scans {f}");
        foreach (var p in procs) c.Journal(ChangeKind.DefenderExclusion, "process|" + p, null, $"Defender no longer scans files opened by {Path.GetFileName(p)} ({p})");
        if (folders.Count + procs.Count > 0) c.AddUndo(new(s.Id, "Defender exclusions", MemoryActionType.AddDefenderExclusions, "", DefenderProbe.Encode(folders, procs)));
        var missed = d.MissingFolders.Count + d.MissingProcesses.Count - folders.Count - procs.Count;
        if (folders.Count + procs.Count == 0) return new(false, "Defender didn't keep the exclusions; your organization's policy probably controls them.");
        return new(true, $"Defender no longer scans {DefenderProbe.Describe(folders.Count, procs.Count)}."
            + (missed > 0 ? $" {missed} weren't kept (organization policy)." : "") + " Builds speed up from the next one.");
    }

    internal async Task<ActionOutcome> UndoExclusionsAsync(UndoEntry u, CancellationToken ct)
    {
        var (df, dp) = DefenderProbe.Decode(u.Previous);
        bool ok;
        try { ok = await c.Sys.RemoveDefenderExclusionsAsync(df, dp, ct).ConfigureAwait(false); }
        catch (AdminRequiredException ex) { return new(false, ex.Message); }
        if (ok)
            foreach (var t in df.Select(f => "path|" + f).Concat(dp.Select(x => "process|" + x)))
                try { c.JournalStore?.RemoveLatest(ChangeKind.DefenderExclusion, t); } catch { }
        return ok ? new(true, "Defender scans those folders and build tools again.") : new(false, "Windows didn't allow removing the exclusions.");
    }
}
