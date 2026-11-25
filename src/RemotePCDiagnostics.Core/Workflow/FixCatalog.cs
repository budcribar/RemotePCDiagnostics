using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Optimizations;

namespace RemotePCDiagnostics.Core.Workflow;

/// <summary>Turns check results and memory suggestions into one de-duplicated, ordered list of fixes the workflow can apply unattended.</summary>
public static class FixCatalog
{
    /// <summary>
    /// Not offered: the workflow restarts the PC anyway (which closes apps, ends processes, and forces a full clean kernel reboot
    /// regardless of Fast Startup). Analyzing the component store only reads, so it isn't a fix to apply either.
    /// </summary>
    public static readonly IReadOnlySet<RemediationKind> SkippedRemediation = new HashSet<RemediationKind>
        { RemediationKind.ScheduleCleanRestart, RemediationKind.CancelScheduledRestart, RemediationKind.EndProcessGroup, RemediationKind.DisableFastStartup,
          RemediationKind.AnalyzeComponentStore, RemediationKind.DeleteDuplicateFiles, RemediationKind.OpenSettings,
          // Need a person: a device to pick, consent for the privacy switches, an app to close (the restart closes it anyway).
          RemediationKind.SetDefaultAudioEndpoint, RemediationKind.AllowCapturePrivacy, RemediationKind.CloseAudioHolder };

    /// <summary>
    /// Offered on a check's own card but listed differently here: the repairs come from <see cref="RepairFixes"/> (with the scan's
    /// reason and their order), and single updates are covered by the workflow's "install all updates" fixes.
    /// </summary>
    private static bool ListedElsewhere(RemediationKind k) =>
        k is RemediationKind.RepairComponentStore or RemediationKind.RepairSystemFiles or RemediationKind.InstallUpdate;

    /// <summary>Single repair steps a technician picks on purpose: listed, but not ticked to start with.
    /// Stopping a device from waking the PC changes how the customer wakes it, so it is listed but left for the technician to tick.</summary>
    private static bool OptIn(RemediationKind k) => k is RemediationKind.CleanUpComponentStore or RemediationKind.RepairComponentStoreFromImage
        or RemediationKind.DisableDeviceWake or RemediationKind.DisableWakeTimer or RemediationKind.InstallBiosUpdate
        // Audio enhancements change how everything sounds: listed for the technician to tick.
        or RemediationKind.ToggleAudioEnhancements;

    /// <summary>Memory actions that persist across a restart and need nobody at the keyboard.</summary>
    public static readonly IReadOnlySet<MemoryActionType> UnattendedMemoryActions = new HashSet<MemoryActionType>
    {
        MemoryActionType.DisableStartup, MemoryActionType.EnableBrowserMemorySaver, MemoryActionType.SetServiceManual, MemoryActionType.SetServiceDisabled,
        MemoryActionType.DisableTransparency, MemoryActionType.AutoManagePageFile, MemoryActionType.IncreasePageFile,
        MemoryActionType.AddDefenderExclusions,
        MemoryActionType.DisableWidgets, MemoryActionType.DisableSearchHighlights, MemoryActionType.ReduceHibernateFile,
        MemoryActionType.SkipOfficeStartScreen,
        MemoryActionType.SetPdfDefaultPrinter,
        MemoryActionType.DisableOfficeOptionalExperiences,
        MemoryActionType.BlockBrowserExtension,
        MemoryActionType.StopBrowserBackground,
        MemoryActionType.RemoveApp, MemoryActionType.RemoveXboxApps, MemoryActionType.StopSilentAppInstalls, MemoryActionType.RemoveNarratorAddons,
        MemoryActionType.CleanStorage,
    };

    public const string NotNeededNote = "Closing apps, ending tasks and restarting aren't listed: the workflow restarts the PC itself, which does the same.";

    private static readonly Lazy<ModuleCatalog> BuiltInCatalog = new(() => new ModuleCatalog());

    private static readonly Dictionary<string, string> AreaNames = new(StringComparer.OrdinalIgnoreCase)
    {
        [ModuleSlugs.DeviceDrivers] = "Drivers & devices", [ModuleSlugs.BiosFirmware] = "BIOS & firmware", [ModuleSlugs.Programs] = "Windows updates", [ModuleSlugs.ResourceHogs] = "Performance & power",
        [ModuleSlugs.BatteryPower] = "Performance & power", [ModuleSlugs.SleepWake] = "Performance & power", [ModuleSlugs.Network] = "Network", [ModuleSlugs.DriveHealth] = "Storage", [ModuleSlugs.Services] = "Services",
        [ModuleSlugs.SecurityEssentials] = "Security",
        [ModuleSlugs.DismScanHealth] = RepairArea, [ModuleSlugs.SfcVerifyOnly] = RepairArea,
        [ModuleSlugs.Sound] = "Sound",
    };

    /// <summary>Order groups: quick settings first, cleanup next, network renew near the end, long downloads last.</summary>
    private static int OrderOf(RemediationKind k) => k switch
    {
        RemediationKind.SetBalancedPowerPlan or RemediationKind.ResetMaxProcessorState or RemediationKind.DisableFastStartup or RemediationKind.DisableSystemProxy
            or RemediationKind.DisableDeviceWake or RemediationKind.DisableWakeTimer => 10,
        // Sound, in the order that makes a silent device play: turn it on, unmute, volume, format, enhancements.
        RemediationKind.EnableAudioEndpoint => 24,
        RemediationKind.UnmuteAudioEndpoint or RemediationKind.UnmuteAudioSession => 25,
        RemediationKind.RaiseAudioVolume => 26,
        RemediationKind.ResetAudioFormat => 27,
        RemediationKind.ToggleAudioEnhancements => 28,
        RemediationKind.EnableDevice or RemediationKind.RestartDevice or RemediationKind.ScanHardwareChanges => 30,
        RemediationKind.CleanTempFiles or RemediationKind.DeleteDuplicateFiles or RemediationKind.OptimizeSsd or RemediationKind.EnableStorageSense => 40,
        RemediationKind.SetPublicDns or RemediationKind.ResetDhcpDns or RemediationKind.FlushDnsAndRenewIp => 60,
        RemediationKind.CleanUpComponentStore => CleanupOrder,
        RemediationKind.RepairComponentStoreFromImage => DismRepairOrder,
        RemediationKind.CheckAndInstallDriverUpdates or RemediationKind.CheckAndInstallWindowsUpdates => 90,
        RemediationKind.InstallBiosUpdate => 95,
        _ => 50,
    };

    public static SuggestionRisk RiskOf(RemediationKind k) => k switch
    {
        RemediationKind.CheckAndInstallDriverUpdates or RemediationKind.CheckAndInstallWindowsUpdates or RemediationKind.InstallUpdate
            or RemediationKind.RepairComponentStore or RemediationKind.RepairSystemFiles or RemediationKind.SetPublicDns
            or RemediationKind.ResetDhcpDns or RemediationKind.DisableSystemProxy or RemediationKind.RestartDevice or RemediationKind.EnableDevice
            or RemediationKind.CleanUpComponentStore or RemediationKind.RepairComponentStoreFromImage or RemediationKind.InstallBiosUpdate => SuggestionRisk.Medium,
        _ => SuggestionRisk.Low,
    };

    private static bool RequiresAdmin(RemediationKind k) => k is
        RemediationKind.ApplySecuritySetting or RemediationKind.CleanUpComponentStore or RemediationKind.RepairComponentStore
        or RemediationKind.RepairComponentStoreFromImage or RemediationKind.RepairSystemFiles or RemediationKind.AnalyzeComponentStore
        or RemediationKind.DisableFastStartup or RemediationKind.SetPublicDns or RemediationKind.ResetDhcpDns
        or RemediationKind.OptimizeSsd or RemediationKind.RestartDevice or RemediationKind.EnableDevice
        or RemediationKind.DisableDeviceWake or RemediationKind.DisableWakeTimer or RemediationKind.InstallBiosUpdate;

    /// <summary>Stable fix ids (remembered ticks use them): fixed type keys from <see cref="FixKeys"/>, never display text.</summary>
    public static string RemediationId(AreaAction a) => $"rem:{FixKeys.Of(a.Kind)}:{a.Target}".ToLowerInvariant();
    public static string MemoryId(string suggestionId, MemoryActionType t, string target) => $"mem:{suggestionId}:{FixKeys.Of(t)}:{target}".ToLowerInvariant();

    private static bool CanRunUnattended(MemoryAction action) => UnattendedMemoryActions.Contains(action.Type);

    /// <param name="catalog">Names a fix's area when it isn't one of the fixed areas; defaults to the built-in modules.</param>
    /// <param name="appliedChanges">Changes already applied and still in the undo journal; matching fixes are omitted from Review (shown only for Undo).</param>
    public static IReadOnlyList<WorkflowFix> Build(IEnumerable<DiagnosticResult> results, IEnumerable<MemorySuggestion> suggestions, RemediationService? plans = null,
        ModuleCatalog? catalog = null, IReadOnlyList<Changes.ChangeRecord>? appliedChanges = null)
    {
        var list = new List<WorkflowFix>();
        var seen = new HashSet<string>();

        foreach (var r in results)
        {
            if (r.Report() is not AreaReport rep) continue;
            var area = AreaNames.GetValueOrDefault(r.ModuleName) ?? (catalog ?? BuiltInCatalog.Value).DisplayName(r.ModuleName);
            foreach (var card in rep.Cards)
            {
                var actions = (card.Actions ?? []).Concat(card.Rows.SelectMany(row => row.Actions ?? []));
                foreach (var a in actions)
                {
                    if (SkippedRemediation.Contains(a.Kind) || ListedElsewhere(a.Kind)) continue;
                    var id = RemediationId(a);
                    if (!seen.Add(id)) continue;
                    var plan = plans?.Plan(a);
                    if (plan is { Allowed: false }) continue;
                    var title = plan?.Title.TrimEnd('?') ?? a.ButtonText;
                    var why = plan?.WhatItIs ?? card.Headline;
                    if (a.Kind == RemediationKind.SetPublicDns)
                        why += $" {a.ButtonText}. {card.Note} Measured during the network scan at {r.Timestamp:O}.";
                    list.Add(new(id, title, why, area, RiskOf(a.Kind), FixSource.Remediation, OrderOf(a.Kind), Remediation: a,
                        NeedsAdmin: RequiresAdmin(a.Kind) || plan?.Warning?.Contains("administrator", StringComparison.OrdinalIgnoreCase) == true,
                        Slow: a.Kind is RemediationKind.CheckAndInstallDriverUpdates or RemediationKind.CheckAndInstallWindowsUpdates || (OptIn(a.Kind) && a.Kind is not (RemediationKind.DisableDeviceWake or RemediationKind.DisableWakeTimer)),
                        Undo: Changes.Undoability.Of(a.Kind), AreaKey: area,
                        DefaultOn: !OptIn(a.Kind) && (a.Kind != RemediationKind.ApplySecuritySetting || Security.SecurityFixes.Find(a.Target)?.DefaultOn != false)));
                }
            }
        }

        foreach (var f in RepairFixes(results, plans)) if (seen.Add(f.Id)) list.Add(f);

        foreach (var s in suggestions)
        {
            if (s.Kind != SuggestionKind.Automated) continue;
            // One action per suggestion: the first unattended one (e.g. "Don't start automatically" rather than "Stop now").
            var a = s.Actions.FirstOrDefault(CanRunUnattended);
            if (a is null) continue;
            var id = MemoryId(s.Id, a.Type, a.Target);
            if (!seen.Add(id)) continue;
            var order = a.Type switch { MemoryActionType.DisableStartup => 20, MemoryActionType.SetServiceManual or MemoryActionType.SetServiceDisabled => 22, MemoryActionType.AutoManagePageFile or MemoryActionType.IncreasePageFile => 12, MemoryActionType.CleanStorage => 40, _ => 15 };

            var manual = a.Type == MemoryActionType.SetServiceManual;
            var disabled = a.Type == MemoryActionType.SetServiceDisabled;

            // Suggestion titles can say Stop; describe the selected action rather than reusing that title.
            var serviceLabel = s.Title.StartsWith("Stop ", StringComparison.OrdinalIgnoreCase) ? s.Title[5..] : a.Target;
            var title = manual ? $"Set {serviceLabel} to Manual" : disabled ? $"Disable {serviceLabel}" : s.Title;
            var why = manual ? $"{s.Why} Only the startup type changes; a running service is left running."
                : disabled ? $"{s.Why} Disables the service (Start = 4) so it cannot be started on demand or reset its own startup type."
                : s.Why;
            list.Add(new(id, title, why, s.Category, s.Risk, FixSource.Memory, order,
                SuggestionId: s.Id, MemoryAction: a.Type, MemoryTarget: a.Target,
                NeedsAdmin: a.Type is MemoryActionType.AutoManagePageFile or MemoryActionType.IncreasePageFile or MemoryActionType.SetServiceManual or MemoryActionType.SetServiceDisabled or MemoryActionType.StopService or MemoryActionType.AddDefenderExclusions
                    or MemoryActionType.DisableWidgets or MemoryActionType.DisableSearchHighlights or MemoryActionType.ReduceHibernateFile or MemoryActionType.DisableOfficeOptionalExperiences or MemoryActionType.BlockBrowserExtension
                    or MemoryActionType.RemoveApp or MemoryActionType.RemoveXboxApps or MemoryActionType.RemoveNarratorAddons
                    || (a.Type == MemoryActionType.StopBrowserBackground && a.Target == nameof(BrowserKind.Edge)),
                Undo: s.Undo ?? Changes.Undoability.Of(a.Type), DefaultOn: s.DefaultOn, UndoChip: s.UndoChip, AreaKey: s.Category, Details: s.DetailItems));
        }

        if (appliedChanges is { Count: > 0 })
            list = list.Where(f => !IsAlreadyApplied(f, appliedChanges)).ToList();

        return list.OrderBy(f => f.Order).ThenBy(f => f.Area).ThenBy(f => f.Title, StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>
    /// True when this one-time fix is already recorded as active in the undo journal (not yet undone), so Review does not offer it again.
    /// Repeatable maintenance/repairs (temp cleanup, storage caches, SSD trim, updates, DISM/SFC repairs) are never suppressed.
    /// </summary>
    public static bool IsAlreadyApplied(WorkflowFix fix, IReadOnlyList<Changes.ChangeRecord> applied)
    {
        if (applied.Count == 0) return false;
        bool HasKind(Changes.ChangeKind kind) => applied.Any(c => c.Kind == kind);
        bool Has(Changes.ChangeKind kind, string? target) =>
            !string.IsNullOrWhiteSpace(target)
            && applied.Any(c => c.Kind == kind && string.Equals(c.Target, target, StringComparison.OrdinalIgnoreCase));

        if (fix.Source == FixSource.Remediation && fix.Remediation is { } a)
        {
            return a.Kind switch
            {
                RemediationKind.SetBalancedPowerPlan => HasKind(Changes.ChangeKind.PowerPlan),
                RemediationKind.DisableSystemProxy => HasKind(Changes.ChangeKind.SystemProxy),
                RemediationKind.SetPublicDns or RemediationKind.ResetDhcpDns => Has(Changes.ChangeKind.AdapterDns, a.Target),
                RemediationKind.ApplySecuritySetting => Has(Changes.ChangeKind.SecuritySetting, a.Target),
                RemediationKind.DisableDeviceWake => Has(Changes.ChangeKind.DeviceWake, a.Target),
                RemediationKind.DisableWakeTimer => Has(Changes.ChangeKind.WakeTimer, a.Target),
                RemediationKind.EnableStorageSense => Has(Changes.ChangeKind.RegistryValue, Changes.RegistryAllowlist.StorageSenseEnabled.Target),
                RemediationKind.ResetMaxProcessorState => HasKind(Changes.ChangeKind.PowerSetting),
                RemediationKind.MovePackageCacheToDevDrive => Has(Changes.ChangeKind.UserEnvironmentVariable, DevDrivePackageCaches.TargetEnvVar(a.Target)),
                RemediationKind.CreatePersistentDevDrive => HasKind(Changes.ChangeKind.PersistentDevDrive),
                RemediationKind.UnmuteAudioEndpoint => Has(Changes.ChangeKind.AudioEndpoint, $"{a.Target}|{Audio.AudioTargets.Mute}"),
                RemediationKind.RaiseAudioVolume => Has(Changes.ChangeKind.AudioEndpoint, $"{a.Target}|{Audio.AudioTargets.Volume}"),
                RemediationKind.EnableAudioEndpoint => Has(Changes.ChangeKind.AudioEndpoint, $"{a.Target}|{Audio.AudioTargets.State}"),
                RemediationKind.ResetAudioFormat => Has(Changes.ChangeKind.AudioEndpoint, $"{a.Target}|{Audio.AudioTargets.Format}"),
                RemediationKind.UnmuteAudioSession => Has(Changes.ChangeKind.AudioSession, a.Target),
                _ => false,
            };
        }

        if (fix.Source == FixSource.Memory && fix.MemoryAction is { } mt)
        {
            var target = fix.MemoryTarget;
            return mt switch
            {
                MemoryActionType.DisableStartup => Has(Changes.ChangeKind.StartupApp, target),
                MemoryActionType.SetServiceManual or MemoryActionType.SetServiceDisabled => Has(Changes.ChangeKind.ServiceStartType, target),
                MemoryActionType.EnableBrowserMemorySaver => Has(Changes.ChangeKind.BrowserSettings, target),
                MemoryActionType.DisableTransparency => HasKind(Changes.ChangeKind.Transparency),
                MemoryActionType.AutoManagePageFile or MemoryActionType.IncreasePageFile => HasKind(Changes.ChangeKind.PageFile),
                MemoryActionType.ReduceHibernateFile => HasKind(Changes.ChangeKind.HiberFileType),
                MemoryActionType.SetPdfDefaultPrinter => HasKind(Changes.ChangeKind.DefaultPrinter),
                MemoryActionType.BlockBrowserExtension => Has(Changes.ChangeKind.ExtensionBlock, target),
                MemoryActionType.StopBrowserBackground => !string.IsNullOrWhiteSpace(target)
                    && applied.Any(c => c.Kind == Changes.ChangeKind.BrowserLocalStateValue
                        && c.Target.StartsWith(target + "|", StringComparison.OrdinalIgnoreCase)),
                MemoryActionType.DisableWidgets => Has(Changes.ChangeKind.RegistryValue, Changes.RegistryAllowlist.WidgetsPolicy.Target),
                MemoryActionType.DisableSearchHighlights => Has(Changes.ChangeKind.RegistryValue, Changes.RegistryAllowlist.SearchHighlightsPolicy.Target),
                MemoryActionType.DisableOfficeOptionalExperiences => Has(Changes.ChangeKind.RegistryValue, Changes.RegistryAllowlist.OfficeOptionalConnectedExperiences.Target),
                MemoryActionType.RemoveApp => Has(Changes.ChangeKind.StoreReinstall, target),
                _ => false,
            };
        }

        return false;
    }

    public const string RepairArea = "Windows repair";
    /// <summary>Apply order: DISM RestoreHealth first, then SFC /scannow (SFC repairs from the store DISM just fixed). After settings, before long downloads.</summary>
    public const int DismRepairOrder = 85, SfcRepairOrder = 86;
    /// <summary>Component cleanup, when ticked, runs before the repairs.</summary>
    public const int CleanupOrder = 84;

    /// <summary>
    /// Windows repair fixes, only when the integrity scans found corruption: DISM RestoreHealth when ScanHealth reported a corrupt store
    /// (also when it says "cannot be repaired": then it needs Windows Update or a source, noted in the reason); SFC /scannow when SFC
    /// verify-only found violations or DISM repair runs. Cancelled, failed or clean scans offer nothing.
    /// </summary>
    public static IReadOnlyList<WorkflowFix> RepairFixes(IEnumerable<DiagnosticResult> results, RemediationService? plans = null)
    {
        var list = results.ToList();
        bool Corrupt(string module, out DiagnosticResult? r)
        {
            r = list.LastOrDefault(x => string.Equals(x.ModuleName, module, StringComparison.OrdinalIgnoreCase));
            return r is { Status: DiagnosticStatus.Warning } && !Cancellation.IsCancelled(r);
        }
        var fixes = new List<WorkflowFix>();
        var dism = Corrupt(DismScanHealthModule.ModuleName, out var dr);
        var sfc = Corrupt(SfcVerifyOnlyModule.ModuleName, out var sr);
        if (dism)
        {
            var needsSource = dr!.Message.Contains("cannot be repaired", StringComparison.OrdinalIgnoreCase);
            var a = new AreaAction(RemediationKind.RepairComponentStore, "Repair Windows component store", needsSource ? "needs-source" : "", "Windows component store");
            var why = $"DISM ScanHealth: {dr.Message} (scan {dr.Timestamp:O})."
                + (needsSource ? " Needs a repair source: Windows Update (internet) or matching installation media; it may still fail." : "")
                + " Runs before SFC; can take 10–30 minutes.";
            fixes.Add(new(RemediationId(a), WindowsRepair.DismTitle, why, RepairArea, SuggestionRisk.Medium, FixSource.Remediation, DismRepairOrder,
                Remediation: a, NeedsAdmin: true, Slow: true, Undo: Changes.Undoability.Of(a.Kind), DefaultOn: true, AreaKey: RepairArea));
        }
        if (dism || sfc)
        {
            var a = new AreaAction(RemediationKind.RepairSystemFiles, "Repair protected system files", "", "Protected system files");
            var why = (sfc ? $"SFC verify-only: {sr!.Message} (scan {sr.Timestamp:O})." : "Runs after the DISM repair so protected files are restored from the repaired store.")
                + " Can take 10–20 minutes.";
            fixes.Add(new(RemediationId(a), WindowsRepair.SfcTitle, why, RepairArea, SuggestionRisk.Medium, FixSource.Remediation, SfcRepairOrder,
                Remediation: a, NeedsAdmin: true, Slow: true, Undo: Changes.Undoability.Of(a.Kind), DefaultOn: true, AreaKey: RepairArea));
        }
        return fixes;
    }

    /// <summary>
    /// Fixes the checks found that the workflow leaves out, each with the reason (for the report): restarts and ending tasks
    /// (the workflow restarts the PC itself), changes this app isn't allowed to make, and memory fixes that only close apps.
    /// </summary>
    public static IReadOnlyList<string> NotOffered(IEnumerable<DiagnosticResult> results, IEnumerable<MemorySuggestion> suggestions, RemediationService? plans = null)
    {
        var list = new List<string>();
        void Add(string line) { if (!list.Contains(line)) list.Add(line); }
        foreach (var r in results)
        {
            if (r.Report() is not AreaReport rep) continue;
            foreach (var a in rep.Cards.SelectMany(c => (c.Actions ?? []).Concat(c.Rows.SelectMany(row => row.Actions ?? []))))
            {
                var what = string.IsNullOrWhiteSpace(a.TargetLabel) ? string.IsNullOrWhiteSpace(a.Target) ? a.ButtonText : $"{a.ButtonText} ({a.Target})" : $"{a.ButtonText} ({a.TargetLabel})";
                if (a.Kind is RemediationKind.ScheduleCleanRestart or RemediationKind.CancelScheduledRestart) Add($"{what}: not needed, the service restarts the PC itself.");
                else if (a.Kind == RemediationKind.EndProcessGroup) Add($"{what}: not needed, the restart closes it.");
                else if (a.Kind == RemediationKind.DisableFastStartup) Add($"{what}: left on; the service's restarts are full restarts either way, and Fast Startup keeps everyday start-up quick.");
                else if (plans?.Plan(a) is { Allowed: false } plan) Add($"{plan.Title.TrimEnd('?')}: {plan.Warning ?? "not allowed from here."}");
            }
        }
        foreach (var s in suggestions)
        {
            if (s.Kind != SuggestionKind.Automated || s.Actions.Any(x => UnattendedMemoryActions.Contains(x.Type))) continue;
            if (s.Actions.Any(a => a.Type is MemoryActionType.CloseApp or MemoryActionType.ShutdownBuildServers or MemoryActionType.RestartPc or MemoryActionType.DisableFastStartup or MemoryActionType.ShutdownWsl))
                Add($"{s.Title}: not needed, the restart closes apps and ends tasks.");
        }
        return list;
    }

    /// <summary>Things worth telling the client that need a person (not applied by the workflow).</summary>
    /// <remarks>
    /// Leaves out what a person can't usefully do either: closing apps, ending tasks and restarting (the service restarts the PC),
    /// and services that only offer "Stop now" (already started only when needed; stopping lasts until the next restart).
    /// </remarks>
    public static IReadOnlyList<string> Recommendations(IEnumerable<MemorySuggestion> suggestions) =>
        suggestions.Where(s => s.Kind is SuggestionKind.Guided or SuggestionKind.Info || (s.Kind == SuggestionKind.Automated && !s.Actions.Any(CanRunUnattended)
                && !s.Actions.Any(a => a.Type is MemoryActionType.CloseApp or MemoryActionType.ShutdownBuildServers or MemoryActionType.RestartPc or MemoryActionType.DisableFastStartup or MemoryActionType.ShutdownWsl)
                && !IsStopOnly(s)))
            .Select(s => $"{s.Title}: {s.Why}").ToList();

    /// <summary>A service suggestion whose only action is "Stop now": temporary, so the workflow neither applies nor mentions it.</summary>
    public static bool IsStopOnly(MemorySuggestion s) => s.Actions.Count > 0 && s.Actions.All(a => a.Type == MemoryActionType.StopService);
}
