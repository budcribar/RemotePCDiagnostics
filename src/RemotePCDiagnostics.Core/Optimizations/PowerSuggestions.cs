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
        var freedBytes = before.FileBytes is { } b && after?.FileBytes is { } a && b > a ? b - a : 0;
        var freed = freedBytes > 0 ? $" Freed {MemoryText.Size(freedBytes)} on the system drive." : "";
        return new(true, "hiberfil.sys now holds only what Fast Startup needs." + freed + " Fast Startup still works; Hibernate is no longer in the power menu.", FreedDiskBytes: freedBytes);
    }

    internal async Task<ActionOutcome> UndoHibernateAsync(UndoEntry u, CancellationToken ct)
    {
        var full = await c.Sys.SetHibernateTypeAsync(false, ct).ConfigureAwait(false);
        if (full.Success) Hibernation.RemoveAddedValues(c.Sys, u.PreviousExtra, c.Logger);
        return full.Success ? new(true, "The hibernation file is full size again; Hibernate is back in the power menu.", DiskRestored: true) : full;
    }

    /// <summary>Lets Windows manage the page file size; journals the custom sizes it had (undo puts them back).</summary>
    internal async Task<ActionOutcome> AutoManagePageFileAsync(MemorySuggestion s, CancellationToken ct)
    {
        var pageFileBefore = await c.Sys.ReadPageFileSettingsAsync(ct).ConfigureAwait(false);
        var pf = await c.Sys.EnableAutoPageFileAsync(ct).ConfigureAwait(false);
        if (pf.Success && pageFileBefore is not null)
        {
            c.AddUndo(new(s.Id, "Page file size", MemoryActionType.AutoManagePageFile, "", pageFileBefore));
            c.Journal(ChangeKind.PageFile, "", pageFileBefore, "Page file managed by Windows", restart: true);
        }
        return pf;
    }

    internal async Task<ActionOutcome> UndoAutoManagePageFileAsync(UndoEntry u, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(u.Previous)) return new(false, "The original page file size wasn't recorded.");
        var r = await c.Sys.RestorePageFileAsync(u.Previous, ct).ConfigureAwait(false);
        if (r.Success) try { c.JournalStore?.RemoveLatest(ChangeKind.PageFile, ""); } catch { }
        return r;
    }

    /// <summary>Sets a larger custom page file on the system drive and journals "auto" so Undo returns it to Windows-managed.</summary>
    internal async Task<ActionOutcome> IncreasePageFileAsync(MemorySuggestion s, MemoryAction a, CancellationToken ct)
    {
        var parts = (a.Target ?? "").Split(':');
        if (parts.Length != 2 || !uint.TryParse(parts[0], out var initialMb) || !uint.TryParse(parts[1], out var maxMb)
            || initialMb < 4096 || maxMb < initialMb || maxMb > 131072)
            return new(false, "The requested page file size isn't valid.");

        var root = Path.GetPathRoot(Environment.SystemDirectory);
        if (string.IsNullOrEmpty(root) || root.Length < 2 || root[1] != ':') root = @"C:\";
        try
        {
            var drive = new DriveInfo(root);
            if (drive.IsReady)
            {
                var neededBytes = ((long)initialMb + 10240L) * 1024L * 1024L;
                if (drive.AvailableFreeSpace < neededBytes)
                    return new(false, $"Not enough free space on {root} to increase the page file safely.");
            }
        }
        catch { }

        var pageFilePath = Path.Combine(root, "pagefile.sys");
        var encoded = PageFileSettings.Encode([new PageFileSettings.Size(pageFilePath, initialMb, maxMb)]);
        var r = await c.Sys.RestorePageFileAsync(encoded, ct).ConfigureAwait(false);
        if (!r.Success) return r;

        var initialGb = (int)Math.Round(initialMb / 1024.0);
        var maxGb = (int)Math.Round(maxMb / 1024.0);
        c.Journal(ChangeKind.PageFile, "", PageFileSettings.AutoMarker, $"Page file set to {initialGb}–{maxGb} GB (was managed by Windows)", restart: true);
        c.AddUndo(new(s.Id, "Page file size", MemoryActionType.IncreasePageFile, "", PageFileSettings.AutoMarker));
        return new(true, $"Page file set to {initialGb}–{maxGb} GB on {root}. Takes effect after the next restart.");
    }

    internal async Task<ActionOutcome> UndoIncreasePageFileAsync(CancellationToken ct)
    {
        var r = await c.Sys.EnableAutoPageFileAsync(ct).ConfigureAwait(false);
        if (r.Success) try { c.JournalStore?.RemoveLatest(ChangeKind.PageFile, ""); } catch { }
        return r;
    }

    /// <summary>Restart (with auto-resume after sign-in) or Fast Startup off: the same audited path as the Remediation buttons.</summary>
    internal async Task<ActionOutcome> RestartOrFastStartupAsync(MemorySuggestion s, MemoryAction a, CancellationToken ct)
    {
        if (c.Remediation is null) return new(false, "Restarting isn't available from here.");
        var kindR = a.Type == MemoryActionType.RestartPc ? RemediationKind.ScheduleCleanRestart : RemediationKind.DisableFastStartup;
        var rr = await c.Remediation.ExecuteAsync(new AreaAction(kindR, a.Label), ct).ConfigureAwait(false);
        if (rr.Success && a.Type == MemoryActionType.DisableFastStartup)
            c.AddUndo(new(s.Id, "Fast Startup", MemoryActionType.DisableFastStartup, "", "1"));
        return new(rr.Success, rr.Message);
    }

    internal ActionOutcome UndoDisableFastStartup()
    {
        if (c.Remediation is null) return new(false, "Fast Startup control isn't available from here.");
        var r = c.Remediation.RestoreFastStartup(1);
        return new(r.Success, r.Message);
    }
}
