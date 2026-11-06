using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Optimizations;

/// <summary>Background services and VMs: the Claude / Codex VM services to Manual, and shutting down an idle WSL.</summary>
internal sealed class ServiceSuggestions(SuggestionContext c)
{
    /// <summary>
    /// #14: Claude / Codex VM service to Manual. Only from Automatic; read back, and journaled (with the old start type) only when Manual stuck.
    /// </summary>
    internal ActionOutcome SetAiVmServiceManual(MemorySuggestion s, MemoryAction a, ServiceInfo info, string original, string? delayed)
    {
        if (a.Type != MemoryActionType.SetServiceManual) return new(false, "Only \"start only when needed\" (Manual) is offered for this service.");
        if (original is not ("Automatic" or "AutomaticDelayed")) return new(true, $"{info.Label} already starts only when needed ({original}).");
        c.Sys.SetServiceStartType(info.Name, "Manual");
        string after;
        try { after = c.Sys.GetServiceStartType(info.Name); }
        catch (Exception ex) when (ex is not OperationCanceledException) { c.Log($"Read back {info.Name}: {ex.Message}"); after = "unknown"; }
        if (after != "Manual") return new(false, $"Windows didn't keep {info.Label} on Manual (it's {after}). Nothing was changed.");
        c.AddUndo(new(s.Id, info.Label, a.Type, info.Name, original, PreviousExtra: delayed));
        c.Journal(ChangeKind.ServiceStartType, info.Name, original, $"{MemorySuggestionService.ServiceLabel(info.Label, "Manual", original)}; starts only when {AiVmServices.AppName(info.Name)} needs it", extra: delayed);
        return new(true, $"{info.Label} now starts only when {AiVmServices.AppName(info.Name)} needs it (was {original}). Takes effect after the next restart.");
    }

    /// <summary>
    /// #14: wsl --shutdown (allowlisted path and argument only). Re-checks just before running that Linux still looks idle, since the
    /// card may be minutes old. Nothing is journaled: there's nothing to undo (Linux starts again when it's used).
    /// </summary>
    internal async Task<ActionOutcome> ShutdownWslAsync(CancellationToken ct)
    {
        if (c.Snapshot is not { } snap || WslShutdown.IdleVm(snap) is null) return new(false, "WSL isn't running, or Linux is in use now.");
        IReadOnlyList<string>? names = null;
        try { names = c.Sys.RunningProcessNames(); } catch (Exception ex) when (ex is not OperationCanceledException) { c.Log("process list: " + ex.Message); }
        var busy = (names ?? []).Where(WslShutdown.IsBusyName).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (busy.Count > 0) return new(false, $"Linux is in use now ({string.Join(", ", busy)}), so WSL was left running.");
        var cmd = MemoryCommandAllowlist.WslShutdown;
        if (!MemoryCommandAllowlist.IsAllowed(cmd.FileName, cmd.Arguments)) return new(false, "Not allowed.");
        return await c.Sys.RunCommandAsync(cmd.FileName, cmd.Arguments, ct).ConfigureAwait(false);
    }

    /// <summary>Stops a suggested service, or sets its start type (protected services and Windows' own are refused).</summary>
    internal async Task<ActionOutcome> ChangeServiceAsync(MemorySuggestion s, MemoryAction a, CancellationToken ct)
    {
        var info = c.Snapshot?.Services?.FirstOrDefault(x => x.Info.Name.Equals(a.Target, StringComparison.OrdinalIgnoreCase))?.Info;
        if (info is null) return new(false, "That service is no longer listed.");
        if (ServiceProtection.IsProtected(info.Name) || ServiceProtection.IsSelfComponent(info.Name) || MemorySuggestionEngine.CandidateFor(info) is null)
            return new(false, $"{info.Label} is protected and can't be changed from here.");
        if (a.Type == MemoryActionType.StopService)
        {
            if (MemorySuggestionEngine.IsVisualStudioCollector(info.Name))
                return new(false, "Only changing the startup type to Manual is offered for the Visual Studio diagnostics collector.");
            if (c.ServiceActions is null) return new(false, "Service control isn't available.");
            var r = await c.ServiceActions.ExecuteAsync(info, ServiceAction.Stop, ct).ConfigureAwait(false);
            if (r.Success) c.Journal(ChangeKind.ServiceRunning, info.Name, "Running", $"{info.Label} stopped");
            return new(r.Success, r.Success ? $"{info.Label} stopped until the next restart." : r.Message);
        }
        var target = a.Type == MemoryActionType.SetServiceManual ? "Manual" : "Disabled";
        var original = c.Sys.GetServiceStartType(info.Name);
        var delayed = ServiceDelayedStart.Record(c.Sys, info.Name, c.Logger); // undo puts DelayedAutostart back exactly (absent stays absent)
        if (AiVmServices.Is(info.Name)) return SetAiVmServiceManual(s, a, info, original, delayed);
        c.Sys.SetServiceStartType(info.Name, target);
        c.AddUndo(new(s.Id, info.Label, a.Type, info.Name, original, PreviousExtra: delayed));
        c.Journal(ChangeKind.ServiceStartType, info.Name, original, MemorySuggestionService.ServiceLabel(info.Label, target, original), extra: delayed);
        return new(true, $"{info.Label} set to {target} (was {original}).");
    }

    internal ActionOutcome UndoStartType(UndoEntry u)
    {
        if (!MemorySuggestionService.StartTypes.Contains(u.Previous)) return new(false, "The original setting wasn't recorded.");
        c.Sys.SetServiceStartType(u.Target, u.Previous!);
        ServiceDelayedStart.Restore(c.Sys, u.Target, u.PreviousExtra, c.Logger);
        return new(true, $"{u.Label} start-up setting restored to {u.Previous}.");
    }
}
