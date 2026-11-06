using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Changes;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Optimizations;

/// <summary>Office: skip the start screen, turn off the optional online extras, and a local default printer instead of a slow network one.</summary>
internal sealed class OfficeSuggestions(SuggestionContext c)
{
    /// <summary>
    /// #23: DisableBootToOfficeStart = 1 for each installed Office 16 app whose start screen is still on (HKCU: the account this app runs as).
    /// Each value that reads back is journaled with its old value; one that doesn't stick is left out (nothing journaled for it).
    /// </summary>
    internal ActionOutcome SkipOfficeStartScreen(MemorySuggestion s)
    {
        IReadOnlyList<OfficeStartApp> apps = c.Snapshot is { } snap ? OfficeStartScreen.StillOn(snap) : [];
        if (apps.Count == 0) return new(false, "The Office start screen is already off.");
        var done = new List<string>();
        var failed = new List<string>();
        var changed = new List<RegistryUndo.Item>();
        foreach (var app in apps)
        {
            if (OfficeStartScreen.Setting(app.App) is not { } setting) continue;
            var w = c.SetDword(setting, 1, was => $"{app.App} start screen turned off for this account (was {was})", restart: false);
            if (!w.Ok) { failed.Add(app.App); continue; }
            done.Add(app.App);
            if (w.Changed) changed.Add(w.Item);
        }
        if (done.Count == 0) return new(false, $"Windows didn't keep the start screen setting for {OfficeStartScreen.Join(failed)} (your organization may manage Office settings). Nothing was changed.");
        if (changed.Count > 0) c.AddUndo(new(s.Id, "Office start screen", MemoryActionType.SkipOfficeStartScreen, OfficeStartScreen.Join(done), RegistryUndo.Encode(changed)));
        return new(true, $"{OfficeStartScreen.Join(done)} will open straight to a blank document (this account)."
            + (failed.Count > 0 ? $" {OfficeStartScreen.Join(failed)} couldn't be changed (your organization may manage Office settings)." : "")
            + " Takes effect the next time each app opens.");
    }

    /// <summary>
    /// #24: LegacyDefaultPrinterMode = 1 (so Windows stops switching the default), then Microsoft Print to PDF as this account's default,
    /// read back. Journals the old mode (RegistryValue) and the old printer's name (DefaultPrinter). If the printer doesn't change,
    /// the mode is put back and nothing is journaled.
    /// </summary>
    internal ActionOutcome SetPdfDefaultPrinter(MemorySuggestion s)
    {
        var live = c.Sys.ReadDefaultPrinter();
        if (live is not { Offer: true } || !DefaultPrinter.IsSafeName(live.CurrentName))
            return new(false, live is { HasPrintToPdf: false } ? $"{DefaultPrinter.PdfPrinter} isn't installed on this PC." : "The default printer isn't a network printer any more; nothing was changed.");
        var old = live.CurrentName!;
        var mode = c.SetDword(RegistryAllowlist.LegacyDefaultPrinterMode, 1,
            was => $"\"Let Windows manage my default printer\" turned off for this account (LegacyDefaultPrinterMode was {was})", restart: false);
        if (!mode.Ok) return new(false, "Windows didn't keep the default printer setting (your organization may manage printers). Nothing was changed.");
        ActionOutcome set;
        try { set = c.Sys.SetDefaultPrinter(DefaultPrinter.PdfPrinter); }
        catch (Exception ex) when (ex is not OperationCanceledException) { c.Log("SetDefaultPrinter: " + ex.Message); set = new(false, "Windows didn't allow changing the default printer."); }
        string? now = null;
        if (set.Success) try { now = c.Sys.ReadDefaultPrinter()?.CurrentName; } catch (Exception ex) when (ex is not OperationCanceledException) { c.Log("default printer read back: " + ex.Message); }
        if (!set.Success || !DefaultPrinter.IsPdf(now))
        {
            if (mode.Changed)
            {
                try { if (RegistryAllowlist.Restore(c.Sys, mode.Target, mode.Previous, mode.CreatedKey, c.Logger).Ok) c.JournalStore?.RemoveLatest(ChangeKind.RegistryValue, mode.Target); }
                catch (Exception ex) when (ex is not OperationCanceledException) { c.Log("LegacyDefaultPrinterMode rollback: " + ex.Message); }
            }
            return new(false, $"Windows didn't make {DefaultPrinter.PdfPrinter} the default printer (your organization may manage printers). Nothing was changed.");
        }
        c.Journal(ChangeKind.DefaultPrinter, DefaultPrinter.JournalTarget, old, $"Default printer for this account set to {DefaultPrinter.PdfPrinter} (was \"{old}\")");
        c.AddUndo(new(s.Id, "Default printer", MemoryActionType.SetPdfDefaultPrinter, old,
            RegistryUndo.Encode(mode.Changed ? new List<RegistryUndo.Item> { mode.Item } : new List<RegistryUndo.Item>())));
        return new(true, $"{DefaultPrinter.PdfPrinter} is now the default printer for this account (was \"{old}\"). When you print, pick \"{old}\" in the print dialog."
            + " Word and Excel no longer wait for the network printer when they open.");
    }

    /// <summary>Per-item undo for #24: the old default printer (if still installed), then the old LegacyDefaultPrinterMode.</summary>
    internal ActionOutcome UndoPdfDefaultPrinter(UndoEntry u)
    {
        (bool Ok, string Message) printer;
        try { printer = DefaultPrinter.Restore(c.Sys, DefaultPrinter.JournalTarget, u.Target); }
        catch (Exception ex) when (ex is not OperationCanceledException) { c.Log("Undo default printer: " + ex.Message); printer = (false, "Windows didn't allow changing the default printer back."); }
        if (printer.Ok) try { c.JournalStore?.RemoveLatest(ChangeKind.DefaultPrinter, DefaultPrinter.JournalTarget); } catch { }
        var modeOk = true;
        foreach (var item in RegistryUndo.Decode(u.Previous))
        {
            bool ok;
            try { ok = RegistryAllowlist.Restore(c.Sys, item.Target, item.Previous, item.CreatedKey, c.Logger).Ok; }
            catch (Exception ex) when (ex is not OperationCanceledException) { c.Log($"Undo {item.Target}: {ex.Message}"); ok = false; }
            if (ok) { try { c.JournalStore?.RemoveLatest(ChangeKind.RegistryValue, item.Target); } catch { } }
            else modeOk = false;
        }
        if (!printer.Ok) return new(false, printer.Message + (modeOk ? "" : " The \"Let Windows manage my default printer\" setting couldn't be put back either."));
        return modeOk
            ? new(true, printer.Message + " The \"Let Windows manage my default printer\" setting is back as it was.")
            : new(false, printer.Message + " But the \"Let Windows manage my default printer\" setting couldn't be put back.");
    }

    /// <summary>
    /// #18: ControllerConnectedServicesEnabled = 2 (the Office policy "Allow the use of additional optional connected experiences in Office"
    /// set to disabled) for this account. Read back and journaled with its old value; nothing is journaled when it doesn't stick.
    /// </summary>
    internal ActionOutcome DisableOfficeOptionalExperiences(MemorySuggestion s)
    {
        if (c.Snapshot is { } snap && !OfficePrivacy.Offer(snap)) return new(false, "Office's optional online extras are already off or managed by your organization.");
        var w = c.SetDword(OfficePrivacy.Setting, OfficePrivacy.Disabled, was => $"Office optional connected experiences turned off for this account (policy was {was})", restart: false);
        if (!w.Ok) return new(false, "Windows didn't keep the Office setting (administrator rights needed, or your organization manages Office settings). Nothing was changed.");
        if (w.Changed) c.AddUndo(new(s.Id, "Office optional online extras", MemoryActionType.DisableOfficeOptionalExperiences, "", RegistryUndo.Encode([w.Item])));
        return new(true, "Office's optional online extras are off for this account (online pictures, Smart Lookup, Outlook weather, the Office Store for add-ins). OneDrive, SharePoint and co-authoring keep working. Takes effect the next time each Office app opens.");
    }
}
