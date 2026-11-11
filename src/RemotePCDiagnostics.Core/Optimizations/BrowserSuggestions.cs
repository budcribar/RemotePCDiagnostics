using System.Text.Json;
using System.Text.Json.Nodes;
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
        var regItems = undo.Registry ?? [];
        var remRegistry = new List<RegistryUndo.Item>();
        var failed = new List<string>();
        var succeeded = 0;
        foreach (var item in regItems)
        {
            bool ok;
            try { ok = RegistryAllowlist.Restore(c.Sys, item.Target, item.Previous, item.CreatedKey, c.Logger).Ok; }
            catch (Exception ex) when (ex is not OperationCanceledException) { c.Log($"Undo {item.Target}: {ex.Message}"); ok = false; }
            if (ok) { succeeded++; try { c.JournalStore?.RemoveLatest(ChangeKind.RegistryValue, item.Target); } catch { } }
            else { remRegistry.Add(item); failed.Add("Startup Boost"); }
        }
        var remLocalState = undo.LocalStateChanged;
        string? localStateError = null;
        if (undo.LocalStateChanged)
        {
            var target = BrowserBackground.Target(kind);
            var (ok, message) = await BrowserBackground.RestoreAsync(c.Sys, target, undo.LocalStatePrevious, ct).ConfigureAwait(false);
            if (ok)
            {
                remLocalState = false;
                succeeded++;
                try { c.JournalStore?.RemoveLatest(ChangeKind.BrowserLocalStateValue, target); } catch { }
            }
            else localStateError = message;
        }
        if (localStateError is not null || failed.Count > 0)
        {
            if (succeeded > 0)
                c.AddUndo(u with { Previous = BrowserBackground.EncodeUndo(new(remLocalState, remLocalState ? undo.LocalStatePrevious : null, remRegistry)) });
            if (localStateError is not null)
                return new(false, localStateError + (failed.Count > 0 ? " Startup Boost couldn't be turned back on either (administrator rights needed)." : ""));
            return new(false, "Windows didn't allow turning Startup Boost back on (administrator rights needed).");
        }
        return new(true, $"{name} may run in the background again" + (regItems.Count > 0 ? " (Startup Boost policy removed; Edge is no longer \"managed\")" : "") + ". Takes full effect the next time you sign in.");
    }

    internal static string? CaptureMemorySaverPrevious(string? json, BrowserKind kind)
    {
        if (string.IsNullOrWhiteSpace(json)) return json;
        try
        {
            if (JsonNode.Parse(json) is not JsonObject root || root["performance_tuning"] is not JsonObject perf)
                return json;
            if (kind == BrowserKind.Chrome)
            {
                if (perf["high_efficiency_mode"] is { } he)
                    return new JsonObject { ["high_efficiency_mode"] = he.DeepClone() }.ToJsonString();
            }
            else
            {
                if (perf["sleeping_tabs"] is JsonObject st && st["enabled"] is not null)
                    return new JsonObject { ["sleeping_tabs"] = st.DeepClone() }.ToJsonString();
                if (perf["efficiency_mode"] is JsonObject em && em["state"] is not null)
                    return new JsonObject { ["efficiency_mode"] = em.DeepClone() }.ToJsonString();
            }
            return json;
        }
        catch (JsonException) { return json; }
    }

    /// <summary>
    /// Restores only the memory-saver section inside the current <c>Local State</c> JSON without overwriting sibling settings
    /// (such as <c>background_mode.enabled</c>, profiles, or encryption keys). Accepts both section-only snapshots and legacy
    /// full-file <c>Local State</c> snapshots with a root <c>performance_tuning</c> object.
    /// </summary>
    internal static bool TryRestoreMemorySaver(IMemorySystem sys, BrowserKind kind, string? previous)
    {
        if (string.IsNullOrWhiteSpace(previous)) return false;
        JsonObject prevObj;
        try
        {
            if (JsonNode.Parse(previous) is not JsonObject parsed) return false;
            prevObj = parsed;
        }
        catch (JsonException) { return false; }

        string? sectionKey = null;
        JsonNode? sectionNode = null;
        if (kind == BrowserKind.Chrome)
        {
            if (prevObj["high_efficiency_mode"] is { } he) { sectionKey = "high_efficiency_mode"; sectionNode = he.DeepClone(); }
            else if (prevObj["performance_tuning"] is JsonObject lp && lp["high_efficiency_mode"] is { } lhe) { sectionKey = "high_efficiency_mode"; sectionNode = lhe.DeepClone(); }
            else if (prevObj["state"] is not null || prevObj["enabled"] is not null) { sectionKey = "high_efficiency_mode"; sectionNode = prevObj.DeepClone(); }
        }
        else
        {
            if (prevObj["sleeping_tabs"] is { } st) { sectionKey = "sleeping_tabs"; sectionNode = st.DeepClone(); }
            else if (prevObj["efficiency_mode"] is { } em) { sectionKey = "efficiency_mode"; sectionNode = em.DeepClone(); }
            else if (prevObj["performance_tuning"] is JsonObject lp)
            {
                if (lp["sleeping_tabs"] is { } lst) { sectionKey = "sleeping_tabs"; sectionNode = lst.DeepClone(); }
                else if (lp["efficiency_mode"] is { } lem) { sectionKey = "efficiency_mode"; sectionNode = lem.DeepClone(); }
            }
        }
        if (sectionKey is null || sectionNode is null) return false;

        var currentJson = sys.ReadBrowserLocalState(kind);
        JsonObject currentRoot;
        if (string.IsNullOrWhiteSpace(currentJson))
        {
            currentRoot = new JsonObject();
        }
        else
        {
            try
            {
                if (JsonNode.Parse(currentJson) is not JsonObject parsedCurrent) return false;
                currentRoot = parsedCurrent;
            }
            catch (JsonException) { return false; }
        }

        if (currentRoot["performance_tuning"] is not JsonObject curPerf)
        {
            curPerf = new JsonObject();
            currentRoot["performance_tuning"] = curPerf;
        }
        if (curPerf[sectionKey] is JsonObject curSec && sectionNode is JsonObject prevSec)
        {
            foreach (var kv in prevSec)
                curSec[kv.Key] = kv.Value?.DeepClone();
        }
        else
        {
            curPerf[sectionKey] = sectionNode;
        }

        sys.WriteBrowserLocalState(kind, currentRoot.ToJsonString());
        return true;
    }

    internal ActionOutcome EnableMemorySaver(MemorySuggestion s, MemoryAction a)
    {
        var kind = Enum.Parse<BrowserKind>(a.Target);
        if (c.Sys.IsBrowserRunning(kind)) return new(false, $"{BrowserPrefs.Label(kind)} is open. Use its settings page instead, or close it and try again.");
        var json = c.Sys.ReadBrowserLocalState(kind);
        var updated = BrowserPrefs.EnableMemorySaver(json, kind);
        if (updated is null) return new(false, $"Couldn't find the {BrowserPrefs.FeatureName(kind)} setting; use {BrowserPrefs.Label(kind)}'s settings page.");
        var previous = CaptureMemorySaverPrevious(json, kind);
        c.Sys.WriteBrowserLocalState(kind, updated);
        c.AddUndo(new(s.Id, BrowserPrefs.Label(kind), a.Type, a.Target, previous));
        c.Journal(ChangeKind.BrowserSettings, a.Target, previous, $"{BrowserPrefs.FeatureName(kind)} turned on in {BrowserPrefs.Label(kind)}");
        return new(true, $"{BrowserPrefs.FeatureName(kind)} turned on for {BrowserPrefs.Label(kind)}.");
    }

    internal ActionOutcome UndoMemorySaver(UndoEntry u)
    {
        if (!Enum.TryParse<BrowserKind>(u.Target, out var kind)) return new(false, "The browser wasn't recognized.");
        if (c.Sys.IsBrowserRunning(kind)) return new(false, $"Close {BrowserPrefs.Label(kind)} first, then undo.");
        if (!TryRestoreMemorySaver(c.Sys, kind, u.Previous))
            return new(false, $"Couldn't restore the {BrowserPrefs.FeatureName(kind)} setting for {BrowserPrefs.Label(kind)}.");
        return new(true, $"{BrowserPrefs.FeatureName(kind)} setting restored for {BrowserPrefs.Label(kind)}.");
    }

    internal ActionOutcome UndoExtensionBlock(UndoEntry u)
    {
        var (extOk, extMessage) = BrowserExtensions.RemoveBlock(c.Sys, u.Target, u.Previous, u.CreatedKey, c.Logger);
        if (extOk) try { c.JournalStore?.RemoveLatest(ChangeKind.ExtensionBlock, u.Target); } catch { }
        return new(extOk, extMessage);
    }
}
