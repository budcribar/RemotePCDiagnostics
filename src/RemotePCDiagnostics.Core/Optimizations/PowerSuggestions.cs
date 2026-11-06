using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Optimizations;

/// <summary>Power and disk: the hibernation file size.</summary>
internal sealed class PowerSuggestions(SuggestionContext c)
{
    /// <summary>#16: the Widgets machine policy (HKCU TaskbarDa is blocked by UCPD, so it's never written), then ends the Widgets processes.</summary>
    /// <summary>powercfg /h /type reduced, then reads it back. Journals "full" so Undo all can put the full file back.</summary>
    internal async Task<ActionOutcome> ReduceHibernateFileAsync(MemorySuggestion s, CancellationToken ct)
    {
        if (c.Snapshot?.Hibernate is not { OfferReduce: true } before) return new(false, "The hibernation file is already reduced or turned off.");
        var values = Hibernation.RecordValues(c.Sys, c.Logger); // HiberFileType / HibernateEnabled: undo removes the ones powercfg adds
        var r = await c.Sys.SetHibernateTypeAsync(true, ct).ConfigureAwait(false);
        if (!r.Success) return r;
        var after = c.Sys.ReadHibernate();
        if (after?.Reduced == false) return new(false, "Windows didn't shrink the hibernation file; nothing was changed.");
        c.AddUndo(new(s.Id, "Hibernation file", MemoryActionType.ReduceHibernateFile, "", "full", PreviousExtra: values));
        c.Journal(ChangeKind.HiberFileType, "", "full", "Hibernation file (hiberfil.sys) shrunk to the Fast Startup size (was full size)", extra: values);
        var freed = before.FileBytes is { } b && after?.FileBytes is { } a && b > a ? $" Freed {MemoryText.Size(b - a)} on the system drive." : "";
        return new(true, "hiberfil.sys now holds only what Fast Startup needs." + freed + " Fast Startup still works; Hibernate is no longer in the power menu.");
    }

    internal async Task<ActionOutcome> UndoHibernateAsync(UndoEntry u, CancellationToken ct)
    {
        var full = await c.Sys.SetHibernateTypeAsync(false, ct).ConfigureAwait(false);
        if (full.Success) Hibernation.RemoveAddedValues(c.Sys, u.PreviousExtra, c.Logger);
        return full.Success ? new(true, "The hibernation file is full size again; Hibernate is back in the power menu.") : full;
    }

    /// <summary>Lets Windows manage the page file size; journals the custom sizes it had (undo puts them back).</summary>
    internal async Task<ActionOutcome> AutoManagePageFileAsync(CancellationToken ct)
    {
        var pageFileBefore = await c.Sys.ReadPageFileSettingsAsync(ct).ConfigureAwait(false);
        var pf = await c.Sys.EnableAutoPageFileAsync(ct).ConfigureAwait(false);
        if (pf.Success && pageFileBefore is not null) c.Journal(ChangeKind.PageFile, "", pageFileBefore, "Page file managed by Windows", restart: true);
        return pf;
    }

    /// <summary>Restart (with auto-resume after sign-in) or Fast Startup off: the same audited path as the Remediation buttons.</summary>
    internal async Task<ActionOutcome> RestartOrFastStartupAsync(MemoryAction a, CancellationToken ct)
    {
        if (c.Remediation is null) return new(false, "Restarting isn't available from here.");
        var kindR = a.Type == MemoryActionType.RestartPc ? RemediationKind.ScheduleCleanRestart : RemediationKind.DisableFastStartup;
        var rr = await c.Remediation.ExecuteAsync(new AreaAction(kindR, a.Label), ct).ConfigureAwait(false);
        return new(rr.Success, rr.Message);
    }
}
