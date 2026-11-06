using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Optimizations;

/// <summary>Windows shell extras that use memory: Widgets and Search highlights (allowlisted policies).</summary>
internal sealed class WindowsShellSuggestions(SuggestionContext c)
{
    internal async Task<ActionOutcome> DisableWidgetsAsync(MemorySuggestion s, CancellationToken ct)
    {
        if (c.Snapshot?.Feeds is { WidgetsPolicyBlocked: true })
            return new(false, "This version of Windows blocks the Widgets policy (User Choice Protection), so nothing was changed. Hide Widgets from Settings > Personalization > Taskbar instead.");
        var w = c.SetDword(RegistryAllowlist.WidgetsPolicy, 0, was => $"Widgets turned off for everyone on this PC (policy was {was})");
        if (!w.Ok) return new(false, "Windows didn't keep the Widgets policy " + SuggestionContext.PolicyRefused);
        if (w.Changed) c.AddUndo(new(s.Id, "Widgets", MemoryActionType.DisableWidgets, "", RegistryUndo.Encode([w.Item])));
        var ended = 0;
        foreach (var name in WindowsFeeds.WidgetProcesses)
        {
            if (c.Snapshot?.App(name) is null) continue;
            try { if ((await c.Sys.ForceCloseAppAsync(name, ct).ConfigureAwait(false)).Success) ended++; }
            catch (Exception ex) when (ex is not OperationCanceledException) { c.Log($"End {name}: {ex.Message}"); }
        }
        return new(true, "Widgets turned off for everyone on this PC" + (ended > 0 ? " and its background processes ended" : "") + ". Takes full effect after a restart.");
    }

    /// <summary>#17: the Search highlights policy (must stick), plus this account's Settings toggle (best effort). Never DisableSearchBoxSuggestions.</summary>
    internal ActionOutcome DisableSearchHighlights(MemorySuggestion s)
    {
        var policy = c.SetDword(RegistryAllowlist.SearchHighlightsPolicy, 0, was => $"Search highlights turned off for everyone on this PC (policy was {was})");
        if (!policy.Ok) return new(false, "Windows didn't keep the Search highlights policy " + SuggestionContext.PolicyRefused);
        var toggle = c.SetDword(RegistryAllowlist.SearchHighlightsToggle, 0, was => $"Search highlights setting turned off for this account (was {was})");
        var changed = new[] { policy, toggle }.Where(x => x.Changed).Select(x => x.Item).ToList();
        if (changed.Count > 0) c.AddUndo(new(s.Id, "Search highlights", MemoryActionType.DisableSearchHighlights, "", RegistryUndo.Encode(changed)));
        return new(true, "Search highlights turned off" + (toggle.Ok ? "" : " (this account's Settings toggle couldn't be changed; the policy still applies)") + ". Takes full effect after a restart.");
    }

    internal ActionOutcome DisableTransparency(MemorySuggestion s, MemoryAction a)
    {
        var before = c.Sys.GetTransparency();
        if (before == false) return new(true, "Transparency effects are already off.");
        c.Sys.SetTransparency(false);
        c.AddUndo(new(s.Id, "Transparency effects", a.Type, "", before == false ? "0" : "1"));
        c.Journal(ChangeKind.Transparency, "", before == false ? "0" : "1", "Transparency effects turned off");
        return new(true, "Transparency effects turned off (this account).");
    }

    internal ActionOutcome UndoTransparency(UndoEntry u)
    {
        c.Sys.SetTransparency(u.Previous != "0");
        return new(true, u.Previous != "0" ? "Transparency effects turned back on." : "Transparency effects left off (they were off before).");
    }
}
