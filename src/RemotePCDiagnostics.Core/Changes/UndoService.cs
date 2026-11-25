using System.Text.RegularExpressions;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Changes;

/// <param name="Skipped">A permanent change (installed updates, removed apps): reported, not attempted, not a failure.</param>
public sealed record UndoItemResult(ChangeRecord Change, bool Success, string Message, bool Skipped = false);

public sealed record UndoAllResult(IReadOnlyList<UndoItemResult> Items)
{
    public int Succeeded => Items.Count(i => i.Success);
    public int Failed => Items.Count(i => !i.Success && !i.Skipped);
    public int Skipped => Items.Count(i => i.Skipped);
    public IEnumerable<UndoItemResult> Permanent => Items.Where(i => i.Skipped);
    public bool NeedsRestart => Items.Any(i => i.Success && i.Change.NeedsRestart);
    /// <summary>Short names of the undone changes that finish after a restart ("Widgets", "page file"), each once, in undo order.</summary>
    public IReadOnlyList<string> RestartItems => Items.Where(i => i.Success && i.Change.NeedsRestart)
        .Select(i => RestartName(i.Change)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    private int Attempted => Items.Count - Skipped;
    public string Summary => Items.Count == 0 ? "Nothing to undo."
        : (Attempted == 0 ? "Nothing that can be undone"
            : $"Undid {Succeeded} of {Attempted} change{(Attempted == 1 ? "" : "s")}" + (Failed > 0 ? $"; {Failed} couldn't be undone" : ""))
          + (Skipped > 0 ? $"; {Skipped} permanent change{(Skipped == 1 ? " was" : "s were")} left as is (can't be reversed)" : "")
          + (RestartItems.Count > 0 ? $". Restart to finish ({string.Join(", ", RestartItems)})." : ".");

    /// <summary>What a restart finishes, in a few words, for the summary line.</summary>
    public static string RestartName(ChangeRecord c)
    {
        switch (c.Kind)
        {
            case ChangeKind.FastStartup: return "Fast Startup";
            case ChangeKind.PageFile: return "page file";
            case ChangeKind.HiberFileType: return "hibernation file";
            case ChangeKind.RegistryValue:
                var t = RegistryAllowlist.Find(c.Target);
                if (t == RegistryAllowlist.WidgetsPolicy) return "Widgets";
                if (t == RegistryAllowlist.SearchHighlightsPolicy || t == RegistryAllowlist.SearchHighlightsToggle) return "Search highlights";
                if (t == RegistryAllowlist.EdgeStartupBoostPolicy) return "Edge Startup Boost";
                if (t == RegistryAllowlist.StorageSenseEnabled) return "Storage Sense";
                break;
            case ChangeKind.PowerSetting: return "maximum processor state";
            case ChangeKind.UserEnvironmentVariable: return $"{c.Target} cache path";
        }
        var label = c.Label.Trim();
        var cut = label.IndexOf(" (", StringComparison.Ordinal);
        return cut > 0 ? label[..cut] : label;
    }
}

/// <summary>
/// Reverts the journaled changes, newest first. Only puts back settings this app changed. Permanent changes (installed updates,
/// removed apps) and deleted temporary files are reported as skipped; deleted files are never recreated.
/// </summary>
public sealed class UndoService(IChangeJournal journal, SystemCommandRunner commands, IMemorySystem? memory = null, IServiceControlBackend? services = null,
    Action<LogLevel, string>? events = null, ILogger? log = null, ISystemSettings? settings = null,
    IPowerSettingController? powerSettings = null, IUserEnvironmentStore? userEnv = null, Audio.AudioFixService? audio = null)
{
    public const string NotUndoableNote = "Installed updates, uninstalled programs, removed apps without a Microsoft Store listing, and deleted temporary files, caches or Recycle Bin items can't be put back; undo lists them as left as is. "
        + "Removed Microsoft Store apps marked \"undo reinstalls from Store\" are reinstalled from the Store for the signed-in account (needs internet; their settings and data aren't restored).";
    private void Log(string m) => log.Info("[undo] " + m);
    private void LogError(string m) => log.Error("[undo] " + m);

    public IReadOnlyList<ChangeRecord> Pending => journal.All;

    public async Task<UndoAllResult> UndoAllAsync(string actor, CancellationToken ct = default)
    {
        // An RPCD update waits while this runs (see UpdateBusyLock).
        using var busy = RemotePCDiagnostics.Agent.Core.UpdateBusyHold.App.Enter();
        var results = new List<UndoItemResult>();
        // Newest first; records from one click share a time, so the later-written goes first (the first write is the one that created any keys).
        foreach (var c in journal.All.Select((x, i) => (x, i)).OrderByDescending(p => p.x.TimeUtc).ThenByDescending(p => p.i).Select(p => p.x).ToList())
        {
            ct.ThrowIfCancellationRequested();
            UndoItemResult r;
            try { r = await UndoOneAsync(c, ct).ConfigureAwait(false); }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                LogError($"{c.Kind} '{c.Target}' failed: {ex}");
                r = new(c, false, AdminRequiredException.MessageOr(ex, "Windows didn't allow undoing it."));
            }
            // Permanent changes are reported once, then forgotten (there's nothing to retry).
            if (r.Success || r.Skipped) journal.Remove(c.Id);
            results.Add(r);
            Log($"{c.Kind} '{c.Target}': {(r.Success ? "undone" : r.Skipped ? "permanent, skipped" : "failed")} — {r.Message}");
        }
        var all = new UndoAllResult(results);
        try
        {
            events?.Invoke(all.Failed > 0 ? LogLevel.Warning : LogLevel.Information,
                $"Undo all changes\r\nActor: {actor}\r\nResult: {all.Summary}\r\n" + string.Join("\r\n", results.Select(i => $"  {(i.Success ? "OK" : i.Skipped ? "LEFT AS IS" : "FAILED")}: {i.Change.Label} — {i.Message}")));
        }
        catch { }
        return all;
    }

    /// <summary>
    /// Undoes one journaled change (the report box's Undo / Reinstall). Same rules as "Undo all": the admin parts run in the Agent, and the
    /// entry is forgotten once it's undone (or turns out to be permanent). Null = no such entry (already undone, or the journal isn't read yet).
    /// </summary>
    public async Task<UndoItemResult?> UndoChangeAsync(Guid id, string actor, CancellationToken ct = default)
    {
        // An RPCD update waits while this runs (see UpdateBusyLock).
        using var busy = RemotePCDiagnostics.Agent.Core.UpdateBusyHold.App.Enter();
        if (journal.All.FirstOrDefault(x => x.Id == id) is not { } c) return null;
        UndoItemResult r;
        try { r = await UndoOneAsync(c, ct).ConfigureAwait(false); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogError($"{c.Kind} '{c.Target}' failed: {ex}");
            r = new(c, false, AdminRequiredException.MessageOr(ex, "Windows didn't allow undoing it."));
        }
        if (r.Success || r.Skipped) journal.Remove(c.Id);
        Log($"{c.Kind} '{c.Target}': {(r.Success ? "undone" : r.Skipped ? "permanent, skipped" : "failed")} — {r.Message}");
        try
        {
            events?.Invoke(r.Success ? LogLevel.Information : LogLevel.Warning,
                $"Undo one change\r\nActor: {actor}\r\n  {(r.Success ? "OK" : r.Skipped ? "LEFT AS IS" : "FAILED")}: {c.Label} — {r.Message}");
        }
        catch { }
        return r;
    }

    private async Task<UndoItemResult> UndoOneAsync(ChangeRecord c, CancellationToken ct)
    {
        UndoItemResult Ok(string m) => new(c, true, m);
        UndoItemResult Fail(string m) => new(c, false, m);
        switch (c.Kind)
        {
            case ChangeKind.NotUndoable:
                return new(c, false, "Permanent change; Windows has no way to put it back.", Skipped: true);

            case ChangeKind.StoreReinstall:
                // Allowlisted family name only; the Store id comes from the allowlist and must match the journal's. Failure keeps the entry (retry later).
                if (memory is null) return Fail(StoreReinstall.FindByFamily(c.Target) is { } a ? StoreReinstall.FailedMessage(a.Label) : "Not available.");
                var reinstall = await StoreReinstall.ReinstallAsync(memory, c.Target, c.Previous, ct, log).ConfigureAwait(false);
                return new(c, reinstall.Success, reinstall.Message);

            case ChangeKind.DefenderExclusion:
                var sep = c.Target.IndexOf('|');
                if (sep <= 0) return Fail("The exclusion wasn't recorded.");
                var (kindD, value) = (c.Target[..sep], c.Target[(sep + 1)..]);
                if (memory is null) return Fail("Not available.");
                // The Agent removes it (it needs administrator rights) and checks it's a folder or build tool this app excludes.
                var removed = kindD == "process"
                    ? await memory.RemoveDefenderExclusionsAsync([], [value], ct).ConfigureAwait(false)
                    : await memory.RemoveDefenderExclusionsAsync([value], [], ct).ConfigureAwait(false);
                return removed
                    ? Ok($"Defender scans {(kindD == "process" ? "files opened by " + Path.GetFileName(value) : value)} again.")
                    : Fail("Windows didn't allow removing the exclusion.");

            case ChangeKind.SecuritySetting:
                if (Security.SecurityFixes.Find(c.Target) is not { } sf || Security.SecurityFixes.ParsePrevious(sf.Key, c.Previous) is null)
                    return Fail("The original setting wasn't recorded, so it was left as is.");
                // The Agent rebuilds the restore from the key and the journaled value (it checks both again).
                return await AgentScript(AgentScripts.Of(AgentScripts.SecurityRestore, sf.Key, c.Previous ?? ""), c, sf.UndoDone, ct).ConfigureAwait(false);

            case ChangeKind.HiberFileType:
                if (memory is not null)
                {
                    var hm = await memory.SetHibernateTypeAsync(false, ct).ConfigureAwait(false);
                    if (!hm.Success) return Fail(hm.Message);
                    Hibernation.RemoveAddedValues(memory, c.PreviousExtra, log);
                    return Ok("Hibernation file back to full size; Hibernate is available again.");
                }
                var hr = await commands.RunAdminToolAsync(SystemCommandRunner.SystemTool("powercfg.exe"), ["/h", "/type", "full"], ct).ConfigureAwait(false);
                if (hr is not { ExitCode: 0 }) return Fail(SystemCommandRunner.AgentFailure(hr) ?? "Windows didn't allow changing the hibernation file back.");
                return Ok("Hibernation file back to full size; Hibernate is available again.");

            case ChangeKind.RegistryValue:
                if (memory is null) return Fail("Not available.");
                var (regOk, regMessage) = RegistryAllowlist.Restore(memory, c.Target, c.Previous, c.CreatedKey, log);
                return new(c, regOk, regMessage);

            case ChangeKind.DefaultPrinter:
                if (memory is null) return Fail("Not available.");
                var (prOk, prMessage) = DefaultPrinter.Restore(memory, c.Target, c.Previous);
                return new(c, prOk, prMessage);

            case ChangeKind.ExtensionBlock:
                if (memory is null) return Fail("Not available.");
                var (extOk, extMessage) = BrowserExtensions.RemoveBlock(memory, c.Target, c.Previous, c.CreatedKey, log);
                return new(c, extOk, extMessage);

            case ChangeKind.StartupApp:
                if (memory is null) return Fail("Not available.");
                memory.SetStartupApproved(c.Target, c.Previous is null ? null : Convert.FromBase64String(c.Previous));
                return Ok("Starts with Windows again.");

            case ChangeKind.ServiceStartType:
                if (memory is null || !MemorySuggestionService.StartTypes.Contains(c.Previous)) return Fail("The original setting wasn't recorded.");
                if (ServiceProtection.IsProtected(c.Target) || ServiceProtection.IsSelfComponent(c.Target))
                    return Fail("That service is protected and cannot be changed.");
                memory.SetServiceStartType(c.Target, c.Previous!);
                ServiceDelayedStart.Restore(memory, c.Target, c.PreviousExtra, log);
                return Ok($"Start-up type restored to {c.Previous}.");

            case ChangeKind.ServiceRunning:
                if (services is null) return Fail("Service control isn't available.");
                if (c.Previous != "Running" && (ServiceProtection.IsProtected(c.Target) || ServiceProtection.IsSelfComponent(c.Target) || services.IsDriver(c.Target)))
                    return Fail("That service is protected and cannot be stopped.");
                var targetState = c.Previous == "Running" ? ServiceState.Running : ServiceState.Stopped;
                if (services.GetState(c.Target) == targetState) return Ok(c.Previous == "Running" ? "Already running." : "Already stopped.");
                if (c.Previous == "Running") services.Start(c.Target); else services.Stop(c.Target);
                var target = c.Previous == "Running" ? ServiceState.Running : ServiceState.Stopped;
                return await services.WaitForStateAsync(c.Target, target, TimeSpan.FromSeconds(30), ct).ConfigureAwait(false)
                    ? Ok(c.Previous == "Running" ? "Started again." : "Stopped again.") : Fail("Windows didn't confirm the service changed in time.");

            case ChangeKind.BrowserSettings:
                if (memory is null || c.Previous is null) return Fail("The original setting wasn't recorded.");
                if (!Enum.TryParse<BrowserKind>(c.Target, out var kind)) return Fail("The browser wasn't recognized.");
                if (memory.IsBrowserRunning(kind)) return Fail($"Close {BrowserPrefs.Label(kind)} first, then undo.");
                if (!BrowserSuggestions.TryRestoreMemorySaver(memory, kind, c.Previous))
                    return Fail($"Couldn't restore the {BrowserPrefs.FeatureName(kind)} setting in {BrowserPrefs.Label(kind)}.");
                return Ok("Browser setting restored.");

            case ChangeKind.BrowserLocalStateValue:
                if (memory is null) return Fail("Not available.");
                var (bgOk, bgMessage) = await BrowserBackground.RestoreAsync(memory, c.Target, c.Previous, ct).ConfigureAwait(false);
                return new(c, bgOk, bgMessage);

            case ChangeKind.Transparency:
                if (memory is null) return Fail("Not available.");
                memory.SetTransparency(c.Previous != "0");
                return Ok(c.Previous != "0" ? "Transparency effects back on." : "Transparency effects left off.");

            case ChangeKind.FastStartup:
                return Set(c, s => s.SetFastStartup(Dword(c.Previous)), "Fast Startup setting restored (full effect after the next restart).");

            case ChangeKind.PowerPlan:
                if (c.Previous is null || !Guid.TryParse(c.Previous, out var g)) return Fail("The original power plan wasn't recorded.");
                var pr = await commands.RunAsync(SystemCommandRunner.SystemTool("powercfg.exe"), ["/setactive", g.ToString()], ct).ConfigureAwait(false);
                return pr is { ExitCode: 0 } ? Ok("Previous power plan active again.") : Fail("Couldn't switch the power plan back.");

            case ChangeKind.PowerSetting:
                if (!PowerSettingTarget.TryParse(c.Target, out var psTarget))
                    return Fail("That power setting isn't on the allowlist, so it was left as is.");
                if (c.Previous is null || !int.TryParse(c.Previous, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var prevPct) || prevPct is < 0 or > 100)
                    return Fail("The previous processor state value wasn't recorded.");
                var psCtrl = powerSettings ?? new WindowsPowerSettingController(commands.ElevatedBridge, log);
                // Restore on the recorded scheme without activating it if the user has switched to a different plan.
                var psRes = await psCtrl.WriteAcMaxProcessorStateAsync(psTarget.SchemeGuid, prevPct, activateIfActive: true, ct).ConfigureAwait(false);
                return psRes.Success ? Ok($"Maximum processor state on AC restored to {prevPct}%.") : Fail(psRes.Message);

            case ChangeKind.UserEnvironmentVariable:
                if (!DevDrivePackageCaches.IsAllowlisted(c.Target))
                    return Fail($"Environment variable '{c.Target}' isn't on the allowlist, so it was left as is.");
                var envStore = userEnv ?? new WindowsUserEnvironmentStore();
                if (c.Previous is null)
                {
                    envStore.Delete(c.Target);
                    return Ok($"Removed user environment variable {c.Target} (reverts to default cache location).");
                }
                envStore.Write(c.Target, c.Previous);
                return Ok($"Restored {c.Target} to {c.Previous}.");

            case ChangeKind.AudioEndpoint or ChangeKind.AudioSession or ChangeKind.CapturePrivacy:
                return audio is null ? Fail("Sound settings can't be changed in this session.") : await audio.UndoAsync(c, ct).ConfigureAwait(false);

            case ChangeKind.DeviceWake:
                if (!DeviceWake.IsSafeName(c.Target)) return Fail("The device wasn't recorded, so it was left as is.");
                var wr = await commands.RunAdminToolAsync(DeviceWake.PowerCfg, ["/deviceenablewake", c.Target], ct).ConfigureAwait(false);
                return wr is { ExitCode: 0 } ? Ok($"{c.Target} can wake the PC again.")
                    : Fail("Windows didn't allow it (administrator rights needed, or the device is no longer connected).");

            case ChangeKind.WakeTimer:
                if (!DeviceWake.IsSafeTaskPath(c.Target)) return Fail("The scheduled task wasn't recorded, so it was left as is.");
                var tr = await commands.RunAgentScriptAsync(Session.AgentScripts.Of(Session.AgentScripts.TaskWakeToRun, c.Target, "true"), null, ct).ConfigureAwait(false);
                return tr is { ExitCode: 0 } ? Ok($"{DeviceWake.ShortTaskName(c.Target)} can wake the PC again.")
                    : Fail("Windows didn't allow it (administrator rights needed, or the scheduled task no longer exists).");

            case ChangeKind.SystemProxy:
                return Set(c, s => s.SetUserProxyEnable(Dword(c.Previous)), "System proxy setting restored.");

            case ChangeKind.AdapterDns:
                if (!SystemSettingsRules.IsAdapterName(c.Target)) return Fail("Invalid network adapter name.");
                var servers = SystemSettingsRules.Ipv4Servers(c.Previous); // anything that isn't an address counts as automatic
                return Set(c, s => s.SetAdapterDns(c.Target, servers), servers.Count == 0 ? "DNS back to automatic." : $"DNS back to {string.Join(", ", servers)}.");

            case ChangeKind.TempFiles:
                return new(c, false, "Deleted temporary files and emptied Recycle Bin items cannot be restored.", Skipped: true);

            case ChangeKind.ScheduledTask:
                if (memory is null) return Fail("Not available.");
                if (!ScheduledTaskAllowlist.IsAllowed(c.Target)) return Fail("That scheduled task isn't one this app changes, so it was left as is.");
                var taskState = await memory.GetScheduledTaskStateAsync(c.Target, ct).ConfigureAwait(false);
                if (taskState == ScheduledTaskAllowlist.Missing) return Ok("The task no longer exists (it was removed with its app); nothing to turn back on.");
                if (ScheduledTaskAllowlist.IsEnabledState(taskState)) return Ok("The task is already on.");
                return ScheduledTaskAllowlist.IsEnabledState(await memory.SetScheduledTaskEnabledAsync(c.Target, true, ct).ConfigureAwait(false))
                    ? Ok("Scheduled task turned back on.") : Fail("The task wasn't turned back on. " + ElevationService.AdminRepairHint);

            case ChangeKind.PageFile:
                if (memory is null || c.Previous is null) return Fail("The original page file size wasn't recorded.");
                var o = string.Equals(c.Previous, PageFileSettings.AutoMarker, StringComparison.OrdinalIgnoreCase)
                    ? await memory.EnableAutoPageFileAsync(ct).ConfigureAwait(false)
                    : await memory.RestorePageFileAsync(c.Previous, ct).ConfigureAwait(false);
                return new(c, o.Success, o.Message);
        }
        return Fail("Unknown change.");
    }

    private static int Dword(string? v) => int.TryParse(v, out var i) && i is >= 0 and <= 1 ? i : 1;

    /// <summary>Puts a setting back in process (<see cref="ISystemSettings"/>); a refusal from Windows keeps the entry for a later try.</summary>
    private UndoItemResult Set(ChangeRecord c, Action<ISystemSettings> restore, string ok)
    {
        if (settings is null) return new(c, false, "Not available.");
        try { restore(settings); return new(c, true, ok); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogError($"{c.Kind} {c.Target}: {ex.GetType().Name}: {ex.Message}");
            return new(c, false, AdminRequiredException.MessageOr(ex, "Couldn't put it back (administrator rights required)."));
        }
    }

    private async Task<UndoItemResult> AgentScript(AdminPipeScript script, ChangeRecord c, string ok, CancellationToken ct)
    {
        var pr = await commands.RunAgentScriptAsync(script, null, ct).ConfigureAwait(false);
        return pr is { ExitCode: 0 } ? new(c, true, ok)
            : new(c, false, SystemCommandRunner.AgentFailure(pr) ?? "Windows didn't allow putting it back.");
    }


    // ---- helpers used when recording "before" values ----

    /// <summary>Scheme GUID from "powercfg /getactivescheme" output.</summary>
    public static string? ParseSchemeGuid(string? output) =>
        output is null ? null : Regex.Match(output, "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}") is { Success: true } m ? m.Value : null;
}
