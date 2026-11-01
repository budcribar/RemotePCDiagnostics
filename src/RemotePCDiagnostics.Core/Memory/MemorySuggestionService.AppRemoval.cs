using RemotePCDiagnostics.Core.Changes;

namespace RemotePCDiagnostics.Core.Memory;

/// <summary>#3 / #8 / #10: removing allowlisted apps (permanent, journaled as NotUndoable) and the reversible settings that go with it.</summary>
public sealed partial class MemorySuggestionService
{
    private void JournalPermanent(string target, string label)
    {
        try { journal?.Add(Undoability.Permanent($"{target}|{Guid.NewGuid():N}", label, Actor)); } catch (Exception ex) { Log("journal: " + ex.Message); }
    }

    /// <summary>One app from the allowlist: a Store package (Remove-AppxPackage -AllUsers + Remove-AppxProvisionedPackage) or a vendor program (its own uninstaller).</summary>
    private async Task<ActionOutcome> RemoveAppAsync(MemorySuggestion s, MemoryAction a, CancellationToken ct)
    {
        if (Snapshot is not { } snap) return new(false, "Scan the PC first.");
        if (AppRemoval.PackageById(a.Target) is { Group: not (AppGroup.Xbox or AppGroup.Narrator) } pkg)
        {
            if (AppRemoval.FoundPackages(snap).FirstOrDefault(f => f.App == pkg) is not { } found) return new(false, $"{pkg.Label} is no longer installed.");
            var left = await sys.RemoveAppxPackagesAsync([pkg], ct).ConfigureAwait(false);
            if (left is null) return new(false, $"Windows didn't allow removing {pkg.Label} (administrator rights needed). Nothing was changed.");
            if (left.Contains(pkg.FamilyName, StringComparer.OrdinalIgnoreCase))
                return new(false, $"{pkg.Label} is still installed after trying to remove it (Windows or your organization may protect it). Nothing was recorded as removed.");
            JournalPermanent("appx|" + pkg.FamilyName, AppRemoval.RemovedLabel(pkg, found.Installed.SizeBytes));
            return new(true, $"{pkg.Label} removed for every account on this PC."
                + (found.Installed.SizeBytes is > 0 ? $" Freed about {MemoryText.Size(found.Installed.SizeBytes.Value)}." : "")
                + $" {AppRemoval.StoreGetBack}");
        }
        if (AppRemoval.ProgramById(a.Target) is { } prog)
            return await UninstallProgramAsync(s, snap, prog, ct).ConfigureAwait(false);
        return new(false, "That app isn't one this app may remove.");
    }

    private async Task<ActionOutcome> UninstallProgramAsync(MemorySuggestion s, MemorySnapshot snap, RemovableProgram prog, CancellationToken ct)
    {
        if (AppRemoval.FoundPrograms(snap).FirstOrDefault(f => f.App == prog) is not { } found) return new(false, $"{prog.Label} is no longer installed.");
        var removed = new List<UninstallEntry>();
        var failed = new List<string>();
        foreach (var e in found.Entries)
        {
            if (AppRemoval.CommandFor(prog, e) is not { } cmd || !AppRemoval.IsAllowedCommand(cmd)) { failed.Add(e.DisplayName); continue; }
            var r = await sys.RunUninstallerAsync(cmd, ct).ConfigureAwait(false);
            // Read back: the Uninstall entry must be gone.
            var after = sys.ReadRemovableApps();
            var still = after is null || after.Programs.Any(p => p.Hive == e.Hive && p.KeyName.Equals(e.KeyName, StringComparison.OrdinalIgnoreCase));
            if (still)
            {
                Log($"Uninstall {e.DisplayName} ({cmd.Display}): {(r.Success ? "ran" : r.Message)}; still installed");
                failed.Add(e.DisplayName);
                continue;
            }
            removed.Add(e);
            JournalPermanent($"program|{prog.Id}|{e.KeyName}", AppRemoval.UninstalledLabel(prog, e));
        }

        // Its scheduled tasks (vendor uninstallers usually remove them; turn off whatever is left).
        var tasks = new List<string>();
        foreach (var t in found.Tasks)
            if (await DisableTaskAsync(t, ct).ConfigureAwait(false)) tasks.Add(t);
        if (tasks.Count > 0) AddUndo(new(s.Id, $"{prog.Label} scheduled tasks", MemoryActionType.RemoveApp, prog.Id, new AppRemoval.Undo([], [], tasks).Encode()));

        var reinstall = AppRemoval.VendorGetBack(prog.ReinstallFrom);
        var freed = removed.Sum(e => e.SizeBytes ?? 0);
        var taskText = tasks.Count > 0 ? $" Turned off {MemoryText.Plural(tasks.Count, "scheduled task")} ({string.Join(", ", tasks)}); undo turns them back on." : "";
        if (removed.Count == 0)
            return new(false, $"{prog.Label} is still installed: its uninstaller didn't finish (administrator rights needed, or it needs someone at the PC).{taskText}");
        return new(true, $"{string.Join(" and ", removed.Select(e => e.DisplayName).Distinct(StringComparer.OrdinalIgnoreCase))} uninstalled."
            + (freed > 0 ? $" Freed about {MemoryText.Size(freed)}." : "")
            + (failed.Count > 0 ? $" {string.Join(", ", failed)} couldn't be uninstalled." : "")
            + taskText + $" {reinstall}");
    }

    /// <summary>Disables an allowlisted task that's on, reads it back, journals it. False when it's missing, already off, unreadable or didn't stick.</summary>
    private async Task<bool> DisableTaskAsync(string path, CancellationToken ct)
    {
        if (!ScheduledTaskAllowlist.IsAllowed(path)) return false;
        try
        {
            var state = await sys.GetScheduledTaskStateAsync(path, ct).ConfigureAwait(false);
            if (!ScheduledTaskAllowlist.IsEnabledState(state)) return false;
            var after = await sys.SetScheduledTaskEnabledAsync(path, false, ct).ConfigureAwait(false);
            if (after != "Disabled") { Log($"Task {path} didn't turn off (state {after ?? "unknown"})"); return false; }
            Journal(ChangeKind.ScheduledTask, path, "Enabled", AppRemoval.TaskLabel(path));
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { Log($"Task {path}: {ex.Message}"); return false; }
    }

    /// <summary>#8: the Xbox packages (permanent), plus Game DVR off, Xbox services to Manual and the cloud-save task off (all undoable).</summary>
    private async Task<ActionOutcome> RemoveXboxAppsAsync(MemorySuggestion s, CancellationToken ct)
    {
        if (Snapshot is not { } snap) return new(false, "Scan the PC first.");
        var found = AppRemoval.FoundPackages(snap).Where(f => f.App.Group == AppGroup.Xbox).ToList();
        if (found.Count == 0) return new(false, "The Xbox apps are no longer installed.");

        var left = await sys.RemoveAppxPackagesAsync(found.Select(f => f.App).ToList(), ct).ConfigureAwait(false);
        var removed = left is null ? new List<AppRemoval.FoundPackage>() : found.Where(f => !left.Contains(f.App.FamilyName, StringComparer.OrdinalIgnoreCase)).ToList();
        foreach (var f in removed) JournalPermanent("appx|" + f.App.FamilyName, AppRemoval.RemovedLabel(f.App, f.Installed.SizeBytes));

        var registry = new List<RegistryUndo.Item>();
        foreach (var (setting, what) in new[] { (RegistryAllowlist.GameDvrEnabled, "Game DVR"), (RegistryAllowlist.AppCaptureEnabled, "Background game recording") })
        {
            var w = SetDword(setting, 0, was => $"{what} turned off for this account (was {was})", restart: false);
            if (w.Changed) registry.Add(new(w.Target, w.Previous));
        }

        var services = new List<RegistryUndo.Item>();
        foreach (var name in AppRemoval.XboxServices)
        {
            try
            {
                var original = sys.GetServiceStartType(name);
                if (original is not ("Automatic" or "AutomaticDelayed")) continue;
                sys.SetServiceStartType(name, "Manual");
                if (sys.GetServiceStartType(name) != "Manual") { Log($"{name} didn't stay Manual"); continue; }
                Journal(ChangeKind.ServiceStartType, name, original, $"{name} set to Manual (was {original})");
                services.Add(new(name, original));
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { Log($"Service {name}: {ex.Message}"); } // not installed / protected
        }

        var tasks = new List<string>();
        var xblTask = ScheduledTaskAllowlist.XblGameSave.Folder + ScheduledTaskAllowlist.XblGameSave.Name;
        if (await DisableTaskAsync(xblTask, ct).ConfigureAwait(false)) tasks.Add(xblTask);

        var undo = new AppRemoval.Undo(registry, services, tasks);
        if (!undo.IsEmpty) AddUndo(new(s.Id, "Game DVR, Xbox services and the cloud-save task", MemoryActionType.RemoveXboxApps, "", undo.Encode()));

        var freed = removed.Sum(f => f.Installed.SizeBytes ?? 0);
        var notRemoved = found.Count - removed.Count;
        var parts = new List<string>();
        if (removed.Count > 0) parts.Add($"Removed {string.Join(", ", removed.Select(f => f.App.Label))}" + (freed > 0 ? $" (about {MemoryText.Size(freed)} freed)" : "") + $"; {AppRemoval.StoreGetBackMany}");
        if (notRemoved > 0) parts.Add($"{MemoryText.Plural(notRemoved, "Xbox app")} couldn't be removed ({string.Join(", ", found.Except(removed).Select(f => f.App.Label))}).");
        if (registry.Count > 0) parts.Add("Game DVR and background recording turned off.");
        if (services.Count > 0) parts.Add($"{string.Join(", ", services.Select(x => x.Target))} set to start only when needed.");
        if (tasks.Count > 0) parts.Add("Xbox cloud-save task turned off.");
        if (!undo.IsEmpty) parts.Add("Undo turns those settings back on.");
        if (removed.Count == 0 && undo.IsEmpty)
            return new(false, "Windows didn't allow removing the Xbox apps (administrator rights needed, or your organization protects them). Nothing was changed.");
        return new(removed.Count > 0, string.Join(" ", parts));
    }

    /// <summary>#3: Narrator's Office add-ons (permanent) and the accidental Win+Ctrl+Enter shortcut off (undoable). Only while Narrator isn't used.</summary>
    private async Task<ActionOutcome> RemoveNarratorAddonsAsync(MemorySuggestion s, CancellationToken ct)
    {
        if (Snapshot is not { } snap) return new(false, "Scan the PC first.");
        var found = AppRemoval.FoundNarrator(snap);
        if (found.Count == 0) return new(false, "Narrator's add-ons are no longer installed, or Narrator is in use.");
        var left = await sys.RemoveAppxPackagesAsync(found.Select(f => f.App).ToList(), ct).ConfigureAwait(false);
        var removed = left is null ? new List<AppRemoval.FoundPackage>() : found.Where(f => !left.Contains(f.App.FamilyName, StringComparer.OrdinalIgnoreCase)).ToList();
        foreach (var f in removed) JournalPermanent("appx|" + f.App.FamilyName, AppRemoval.RemovedLabel(f.App, f.Installed.SizeBytes));

        var registry = new List<RegistryUndo.Item>();
        var w = SetDword(RegistryAllowlist.NarratorWinEnterLaunch, 0, was => $"Win+Ctrl+Enter Narrator shortcut turned off for this account (was {was})", restart: false);
        if (w.Changed) registry.Add(new(w.Target, w.Previous));
        var undo = new AppRemoval.Undo(registry, [], []);
        if (!undo.IsEmpty) AddUndo(new(s.Id, "The Win+Ctrl+Enter Narrator shortcut", MemoryActionType.RemoveNarratorAddons, "", undo.Encode()));

        if (removed.Count == 0 && undo.IsEmpty)
            return new(false, "Windows didn't allow removing Narrator's add-ons (administrator rights needed, or Windows protects them). Nothing was changed.");
        var freed = removed.Sum(f => f.Installed.SizeBytes ?? 0);
        var parts = new List<string>();
        if (removed.Count > 0) parts.Add($"Removed {string.Join(", ", removed.Select(f => f.App.Label))}" + (freed > 0 ? $" (about {MemoryText.Size(freed)} freed)" : "") + $"; {AppRemoval.StoreGetBackMany}");
        if (removed.Count < found.Count) parts.Add($"{MemoryText.Plural(found.Count - removed.Count, "add-on")} couldn't be removed ({string.Join(", ", found.Except(removed).Select(f => f.App.Label))}).");
        if (w.Changed) parts.Add("The Win+Ctrl+Enter shortcut no longer starts Narrator; undo turns it back on.");
        return new(removed.Count > 0, string.Join(" ", parts));
    }

    private static readonly IReadOnlyDictionary<string, string> ContentDeliveryNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        [RegistryAllowlist.SilentInstalledApps.Target] = "Silent installs of promoted apps",
        [RegistryAllowlist.OemPreInstalledApps.Target] = "PC-maker app suggestions",
        [RegistryAllowlist.PreInstalledApps.Target] = "Pre-installed app suggestions",
        [RegistryAllowlist.SoftLanding.Target] = "Windows tips and suggestions",
        [RegistryAllowlist.SystemPaneSuggestions.Target] = "Suggested apps in Start",
    };

    /// <summary>#3: the five ContentDeliveryManager values set to 0 (HKCU). Each that reads back is journaled with its old value.</summary>
    private ActionOutcome StopSilentAppInstalls(MemorySuggestion s)
    {
        var changed = new List<RegistryUndo.Item>();
        var ok = 0;
        foreach (var setting in AppRemoval.ContentDeliverySettings)
        {
            var name = ContentDeliveryNames[setting.Target];
            var w = SetDword(setting, 0, was => $"{name} turned off for this account (was {was})", restart: false);
            if (!w.Ok) continue;
            ok++;
            if (w.Changed) changed.Add(new(w.Target, w.Previous));
        }
        if (ok == 0) return new(false, "Windows didn't keep these settings (your organization may manage them). Nothing was changed.");
        if (changed.Count > 0) AddUndo(new(s.Id, "Promoted app installs", MemoryActionType.StopSilentAppInstalls, "", RegistryUndo.Encode(changed)));
        return new(true, "Windows won't install promoted apps or show app suggestions for this account"
            + (ok < AppRemoval.ContentDeliverySettings.Count ? $" ({AppRemoval.ContentDeliverySettings.Count - ok} of the settings couldn't be changed)" : "") + ". Undo turns them back on.");
    }

    /// <summary>Per-item undo for app removal: puts back the settings, services and tasks (allowlisted only). Removed apps stay removed.</summary>
    private async Task<ActionOutcome> UndoAppRemovalAsync(UndoEntry u, CancellationToken ct)
    {
        var undo = AppRemoval.Undo.Decode(u.Previous);
        if (undo.IsEmpty) return new(false, "The original settings weren't recorded.");
        var failed = 0;
        foreach (var item in undo.Registry)
        {
            bool ok;
            try { ok = RegistryAllowlist.Restore(sys, item.Target, item.Previous).Ok; }
            catch (Exception ex) when (ex is not OperationCanceledException) { Log($"Undo {item.Target}: {ex.Message}"); ok = false; }
            if (ok) { try { journal?.RemoveLatest(ChangeKind.RegistryValue, item.Target); } catch { } } else failed++;
        }
        foreach (var svc in undo.Services)
        {
            if (!AppRemoval.XboxServices.Contains(svc.Target, StringComparer.OrdinalIgnoreCase) || !StartTypes.Contains(svc.Previous)) { failed++; continue; }
            try { sys.SetServiceStartType(svc.Target, svc.Previous!); try { journal?.RemoveLatest(ChangeKind.ServiceStartType, svc.Target); } catch { } }
            catch (Exception ex) when (ex is not OperationCanceledException) { Log($"Undo {svc.Target}: {ex.Message}"); failed++; }
        }
        foreach (var t in undo.Tasks)
        {
            if (!ScheduledTaskAllowlist.IsAllowed(t)) { failed++; continue; }
            try
            {
                var state = await sys.GetScheduledTaskStateAsync(t, ct).ConfigureAwait(false);
                var on = state == ScheduledTaskAllowlist.Missing || ScheduledTaskAllowlist.IsEnabledState(state)
                    || ScheduledTaskAllowlist.IsEnabledState(await sys.SetScheduledTaskEnabledAsync(t, true, ct).ConfigureAwait(false));
                if (on) { try { journal?.RemoveLatest(ChangeKind.ScheduledTask, t); } catch { } } else failed++;
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { Log($"Undo task {t}: {ex.Message}"); failed++; }
        }
        var apps = u.Type switch
        {
            MemoryActionType.RemoveXboxApps => $" The removed Xbox apps stay removed. {AppRemoval.StoreGetBackMany}",
            MemoryActionType.RemoveNarratorAddons => $" The removed Narrator add-ons stay removed. {AppRemoval.StoreGetBackMany}",
            _ => " The uninstalled app stays uninstalled; reinstall it from its maker to get it back.",
        };
        return failed == 0
            ? new(true, $"{u.Label} turned back on.{apps}")
            : new(false, $"Windows didn't allow turning everything back on (administrator rights needed).{apps}");
    }
}
