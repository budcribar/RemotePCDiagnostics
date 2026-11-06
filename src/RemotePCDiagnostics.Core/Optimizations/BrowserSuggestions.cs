using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Optimizations;

/// <summary>Browsers: block an allowlisted extension, and stop the non-default browser running in the background.</summary>
internal sealed class BrowserSuggestions(SuggestionContext c)
{
    /// <summary>
    /// #22: adds one allowlisted extension ID to the browser's machine blocklist as the next numbered entry, reads it back, and
    /// journals the value name it added. Nothing else in the list is touched; nothing is journaled when it doesn't stick.
    /// </summary>
    internal ActionOutcome BlockBrowserExtension(MemoryAction a)
    {
        if (!BrowserExtensions.TryParseTarget(a.Target, out var browser, out var id) || BrowserExtensions.Known(browser, id) is not { } known)
            return new(false, "That extension isn't one this app may block.");
        var label = BrowserPrefs.Label(browser);
        try
        {
            if (c.Sys.ReadExtensionBlocklist(browser) is not { } list) return new(false, $"Couldn't read {label}'s extension blocklist; nothing was changed.");
            if (BrowserExtensions.IsBlocked(list, id)) return new(true, $"{known.Name} is already blocked in {label}.");
            if (BrowserExtensions.NextName(list) is not { } name)
                return new(false, $"{label}'s extension blocklist isn't numbered 1, 2, 3… (your organization may manage it), so it was left as is.");
            var created = RegistryKeyCleanup.TopmostMissing(c.Sys, RegistryRoot.LocalMachine, BrowserExtensions.BlocklistKey(browser), c.Logger);
            c.Sys.AddExtensionBlock(browser, name, id);
            var after = c.Sys.ReadExtensionBlocklist(browser);
            if (after?.FirstOrDefault(e => e.Name == name)?.Data?.Trim().Equals(id, StringComparison.OrdinalIgnoreCase) != true)
            {
                c.Log($"{label} blocklist {name} = {id} didn't stick");
                // Best effort: the name was free before, and the Host deletes it only if it holds this ID.
                try { c.Sys.RemoveExtensionBlock(browser, name, id); } catch (Exception ex) when (ex is not OperationCanceledException) { c.Log("cleanup: " + ex.Message); }
                RegistryKeyCleanup.Remove(c.Sys, RegistryRoot.LocalMachine, BrowserExtensions.BlocklistKey(browser), created, c.Logger);
                return new(false, $"Windows didn't keep {known.Name} on {label}'s blocklist " + SuggestionContext.PolicyRefused);
            }
            var target = BrowserExtensions.Target(browser, id);
            c.Journal(ChangeKind.ExtensionBlock, target, name, $"{known.Name} turned off in {label} for everyone on this PC (blocklist entry {name} added; was not blocked)", createdKey: created);
            c.AddUndo(new(BrowserExtensions.SuggestionId(browser, id), $"{known.Name} ({label})", MemoryActionType.BlockBrowserExtension, target, name, CreatedKey: created));
            return new(true, $"{known.Name} is turned off in {label} for everyone on this PC and can't be turned back on or reinstalled until you undo this. {label} now shows \"Managed by your organization\".");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            c.LogWarn($"Block {a.Target} failed: {ex.Message}");
            return new(false, $"Windows didn't allow blocking {known.Name} in {label} " + SuggestionContext.PolicyRefused);
        }
    }

    /// <summary>
    /// #19: for the non-default browser only. Ends its windowless background processes (never a window), then turns off
    /// background_mode.enabled in its Local State (read back), then for Edge sets the Startup Boost policy (read back).
    /// Each value that sticks is journaled with its old value; if a browser window is open, nothing is changed.
    /// </summary>
    internal async Task<ActionOutcome> StopBrowserBackgroundAsync(MemorySuggestion s, MemoryAction a, CancellationToken ct)
    {
        if (!Enum.TryParse<BrowserKind>(a.Target, out var kind) || c.Snapshot is not { } snap || BrowserBackground.Secondary(snap) != kind
            || BrowserBackground.For(snap, kind) is not { } info)
            return new(false, "That browser is your default browser now (or couldn't be checked), so it was left as is.");
        var name = BrowserPrefs.Label(kind);
        var doPref = BrowserBackground.BackgroundModeOn(info);
        var doBoost = BrowserBackground.StartupBoostChangeable(info);
        if (!doPref && !doBoost) return new(false, $"{name} is already set not to run in the background.");

        var ended = false;
        if (c.Sys.IsBrowserRunning(kind))
        {
            var end = await c.Sys.EndBrowserBackgroundAsync(kind, ct).ConfigureAwait(false);
            ended = end.Success && !c.Sys.IsBrowserRunning(kind);
            if (!ended && doPref) return new(false, $"{name} is open (or couldn't be closed in the background). Close its windows and try again. Nothing was changed.");
        }

        string? prefPrevious = null;
        var prefChanged = false;
        if (doPref)
        {
            var json = c.Sys.ReadBrowserLocalState(kind);
            if (!BrowserBackground.TryReadBackgroundMode(json, out var before) || BrowserBackground.SetBackgroundMode(json, false) is not { } updated)
                return new(false, $"Couldn't read {name}'s settings file. Nothing was changed.");
            if (before != false)
            {
                c.Sys.WriteBrowserLocalState(kind, updated);
                if (!BrowserBackground.TryReadBackgroundMode(c.Sys.ReadBrowserLocalState(kind), out var after) || after != false)
                {
                    c.Log($"{kind} background_mode.enabled = false didn't stick");
                    return new(false, $"{name} didn't keep the setting. Nothing was changed.");
                }
                prefPrevious = BrowserBackground.Encode(before);
                prefChanged = true;
                c.Journal(ChangeKind.BrowserLocalStateValue, BrowserBackground.Target(kind), prefPrevious,
                    $"{name} no longer runs background apps when it's closed (\"Continue running background apps\" {BrowserBackground.Describe(before)})");
            }
        }

        var registry = new List<RegistryUndo.Item>();
        var boostFailed = false;
        if (doBoost)
        {
            var w = c.SetDword(BrowserBackground.StartupBoostSetting, 0, was => $"Microsoft Edge Startup Boost turned off for everyone on this PC (policy was {was})", restart: false);
            if (!w.Ok) boostFailed = true;
            else if (w.Changed) registry.Add(w.Item);
        }

        if (!prefChanged && registry.Count == 0)
            return boostFailed
                ? new(false, "Windows didn't keep the Startup Boost policy " + SuggestionContext.PolicyRefused)
                : new(false, $"{name} is already set not to run in the background.");
        c.AddUndo(new(s.Id, name, MemoryActionType.StopBrowserBackground, kind.ToString(), BrowserBackground.EncodeUndo(new(prefChanged, prefPrevious, registry))));
        var parts = new List<string>();
        if (prefChanged) parts.Add("background apps off");
        if (registry.Count > 0) parts.Add("Startup Boost off for everyone on this PC (Edge will say \"managed by your organization\")");
        return new(true, $"{name} won't run in the background: {string.Join("; ", parts)}."
            + (ended ? $" Its background processes were ended." : "")
            + (boostFailed ? " Startup Boost couldn't be turned off (administrator rights needed, or your organization manages Edge)." : "")
            + " Takes full effect the next time you sign in.");
    }

    /// <summary>#19 per-item undo: puts back the Local State value and the Startup Boost policy this click changed, and drops their journal records.</summary>
    internal async Task<ActionOutcome> UndoBrowserBackgroundAsync(UndoEntry u, CancellationToken ct)
    {
        if (!Enum.TryParse<BrowserKind>(u.Target, out var kind) || BrowserBackground.DecodeUndo(u.Previous) is not { } undo)
            return new(false, "The original setting wasn't recorded.");
        var name = BrowserPrefs.Label(kind);
        var failed = new List<string>();
        foreach (var item in undo.Registry ?? [])
        {
            bool ok;
            try { ok = RegistryAllowlist.Restore(c.Sys, item.Target, item.Previous, item.CreatedKey, c.Logger).Ok; }
            catch (Exception ex) when (ex is not OperationCanceledException) { c.Log($"Undo {item.Target}: {ex.Message}"); ok = false; }
            if (ok) { try { c.JournalStore?.RemoveLatest(ChangeKind.RegistryValue, item.Target); } catch { } }
            else failed.Add("Startup Boost");
        }
        if (undo.LocalStateChanged)
        {
            var target = BrowserBackground.Target(kind);
            var (ok, message) = await BrowserBackground.RestoreAsync(c.Sys, target, undo.LocalStatePrevious, ct).ConfigureAwait(false);
            if (ok) { try { c.JournalStore?.RemoveLatest(ChangeKind.BrowserLocalStateValue, target); } catch { } }
            else return new(false, message + (failed.Count > 0 ? " Startup Boost couldn't be turned back on either (administrator rights needed)." : ""));
        }
        return failed.Count == 0
            ? new(true, $"{name} may run in the background again" + (undo.Registry?.Count > 0 ? " (Startup Boost policy removed; Edge is no longer \"managed\")" : "") + ". Takes full effect the next time you sign in.")
            : new(false, "Windows didn't allow turning Startup Boost back on (administrator rights needed).");
    }

    internal ActionOutcome EnableMemorySaver(MemorySuggestion s, MemoryAction a)
    {
        var kind = Enum.Parse<BrowserKind>(a.Target);
        if (c.Sys.IsBrowserRunning(kind)) return new(false, $"{BrowserPrefs.Label(kind)} is open. Use its settings page instead, or close it and try again.");
        var json = c.Sys.ReadBrowserLocalState(kind);
        var updated = BrowserPrefs.EnableMemorySaver(json, kind);
        if (updated is null) return new(false, $"Couldn't find the {BrowserPrefs.FeatureName(kind)} setting; use {BrowserPrefs.Label(kind)}'s settings page.");
        c.Sys.WriteBrowserLocalState(kind, updated);
        c.AddUndo(new(s.Id, BrowserPrefs.Label(kind), a.Type, a.Target, json));
        c.Journal(ChangeKind.BrowserSettings, a.Target, json, $"{BrowserPrefs.FeatureName(kind)} turned on in {BrowserPrefs.Label(kind)}");
        return new(true, $"{BrowserPrefs.FeatureName(kind)} turned on for {BrowserPrefs.Label(kind)}.");
    }

    internal ActionOutcome UndoMemorySaver(UndoEntry u)
    {
        var kind = Enum.Parse<BrowserKind>(u.Target);
        if (c.Sys.IsBrowserRunning(kind)) return new(false, $"Close {BrowserPrefs.Label(kind)} first, then undo.");
        c.Sys.WriteBrowserLocalState(kind, u.Previous!);
        return new(true, $"{BrowserPrefs.FeatureName(kind)} setting restored for {BrowserPrefs.Label(kind)}.");
    }

    internal ActionOutcome UndoExtensionBlock(UndoEntry u)
    {
        var (extOk, extMessage) = BrowserExtensions.RemoveBlock(c.Sys, u.Target, u.Previous, u.CreatedKey, c.Logger);
        if (extOk) try { c.JournalStore?.RemoveLatest(ChangeKind.ExtensionBlock, u.Target); } catch { }
        return new(extOk, extMessage);
    }
}
