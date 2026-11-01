using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Memory;

namespace RemotePCDiagnostics.Core.Workflow;

/// <summary>Turns check results and memory suggestions into one de-duplicated, ordered list of fixes the workflow can apply unattended.</summary>
public static class FixCatalog
{
    /// <summary>Not offered: the workflow restarts the PC anyway (which closes apps, ends processes, and forces a full clean kernel reboot regardless of Fast Startup).</summary>
    public static readonly IReadOnlySet<RemediationKind> SkippedRemediation = new HashSet<RemediationKind>
        { RemediationKind.ScheduleCleanRestart, RemediationKind.CancelScheduledRestart, RemediationKind.EndProcessGroup, RemediationKind.DisableFastStartup };

    /// <summary>Memory actions that persist across a restart and need nobody at the keyboard.</summary>
    public static readonly IReadOnlySet<MemoryActionType> UnattendedMemoryActions = new HashSet<MemoryActionType>
    {
        MemoryActionType.DisableStartup, MemoryActionType.EnableBrowserMemorySaver, MemoryActionType.SetServiceManual,
        MemoryActionType.DisableTransparency, MemoryActionType.AutoManagePageFile,
        MemoryActionType.AddDefenderExclusions,
        MemoryActionType.DisableWidgets, MemoryActionType.DisableSearchHighlights, MemoryActionType.ReduceHibernateFile,
        MemoryActionType.SkipOfficeStartScreen,
        MemoryActionType.BlockBrowserExtension,
    };

    public const string NotNeededNote = "Closing apps, ending tasks and restarting aren't listed: the workflow restarts the PC itself, which does the same.";

    private static readonly Dictionary<string, string> AreaNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ["DeviceDrivers"] = "Drivers & devices", ["Programs"] = "Windows updates", ["ResourceHogs"] = "Performance & power",
        ["BatteryPower"] = "Performance & power", ["Network"] = "Network", ["DriveHealth"] = "Storage", ["Services"] = "Services",
    };

    /// <summary>Order groups: quick settings first, cleanup next, network renew near the end, long downloads last.</summary>
    private static int OrderOf(RemediationKind k) => k switch
    {
        RemediationKind.SetBalancedPowerPlan or RemediationKind.DisableFastStartup or RemediationKind.DisableSystemProxy => 10,
        RemediationKind.EnableDevice or RemediationKind.RestartDevice or RemediationKind.ScanHardwareChanges => 30,
        RemediationKind.CleanTempFiles or RemediationKind.OptimizeSsd => 40,
        RemediationKind.SetPublicDns or RemediationKind.ResetDhcpDns or RemediationKind.FlushDnsAndRenewIp => 60,
        RemediationKind.CheckAndInstallDriverUpdates or RemediationKind.CheckAndInstallWindowsUpdates => 90,
        _ => 50,
    };

    private static SuggestionRisk RiskOf(RemediationKind k) => k switch
    {
        RemediationKind.CheckAndInstallDriverUpdates or RemediationKind.CheckAndInstallWindowsUpdates or RemediationKind.SetPublicDns
            or RemediationKind.ResetDhcpDns or RemediationKind.DisableSystemProxy or RemediationKind.RestartDevice or RemediationKind.EnableDevice => SuggestionRisk.Medium,
        _ => SuggestionRisk.Low,
    };

    public static string RemediationId(AreaAction a) => $"rem:{a.Kind}:{a.Target}".ToLowerInvariant();
    public static string MemoryId(string suggestionId, MemoryActionType t, string target) => $"mem:{suggestionId}:{t}:{target}".ToLowerInvariant();

    private static bool CanRunUnattended(MemoryAction action) => UnattendedMemoryActions.Contains(action.Type);

    public static IReadOnlyList<WorkflowFix> Build(IEnumerable<DiagnosticResult> results, IEnumerable<MemorySuggestion> suggestions, RemediationService? plans = null)
    {
        var list = new List<WorkflowFix>();
        var seen = new HashSet<string>();

        foreach (var r in results)
        {
            if (r.Payload is not AreaReport rep) continue;
            var area = AreaNames.GetValueOrDefault(r.ModuleName, r.ModuleName);
            foreach (var card in rep.Cards)
            {
                var actions = (card.Actions ?? []).Concat(card.Rows.SelectMany(row => row.Actions ?? []));
                foreach (var a in actions)
                {
                    if (SkippedRemediation.Contains(a.Kind)) continue;
                    var id = RemediationId(a);
                    if (!seen.Add(id)) continue;
                    var plan = plans?.Plan(a);
                    if (plan is { Allowed: false }) continue;
                    var title = plan?.Title.TrimEnd('?') ?? a.ButtonText;
                    list.Add(new(id, title, plan?.WhatItIs ?? card.Headline, area, RiskOf(a.Kind), FixSource.Remediation, OrderOf(a.Kind), Remediation: a,
                        NeedsAdmin: plan?.Warning?.Contains("administrator", StringComparison.OrdinalIgnoreCase) == true,
                        Slow: a.Kind is RemediationKind.CheckAndInstallDriverUpdates or RemediationKind.CheckAndInstallWindowsUpdates,
                        Undo: Changes.Undoability.Of(a.Kind)));
                }
            }
        }

        foreach (var s in suggestions)
        {
            if (s.Kind != SuggestionKind.Automated) continue;
            // One action per suggestion: the first unattended one (e.g. "Don't start automatically" rather than "Stop now").
            var a = s.Actions.FirstOrDefault(CanRunUnattended);
            if (a is null) continue;
            var id = MemoryId(s.Id, a.Type, a.Target);
            if (!seen.Add(id)) continue;
            var order = a.Type switch { MemoryActionType.DisableStartup => 20, MemoryActionType.SetServiceManual => 22, MemoryActionType.AutoManagePageFile => 12, _ => 15 };
            list.Add(new(id, a.Type == MemoryActionType.SetServiceManual && !MemorySuggestionEngine.IsVisualStudioCollector(a.Target) ? $"{s.Title}: start only when needed" : s.Title, s.Why, s.Category, s.Risk, FixSource.Memory, order,
                SuggestionId: s.Id, MemoryAction: a.Type, MemoryTarget: a.Target,
                NeedsAdmin: a.Type is MemoryActionType.AutoManagePageFile or MemoryActionType.SetServiceManual or MemoryActionType.StopService or MemoryActionType.AddDefenderExclusions
                    or MemoryActionType.DisableWidgets or MemoryActionType.DisableSearchHighlights or MemoryActionType.ReduceHibernateFile
                    or MemoryActionType.BlockBrowserExtension,
                Undo: Changes.Undoability.Of(a.Type), DefaultOn: s.DefaultOn));
        }

        return list.OrderBy(f => f.Order).ThenBy(f => f.Area).ThenBy(f => f.Title, StringComparer.OrdinalIgnoreCase).ToList();
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
            if (r.Payload is not AreaReport rep) continue;
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
            if (s.Actions.Any(a => a.Type is MemoryActionType.CloseApp or MemoryActionType.ShutdownBuildServers or MemoryActionType.RestartPc or MemoryActionType.DisableFastStartup))
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
                && !s.Actions.Any(a => a.Type is MemoryActionType.CloseApp or MemoryActionType.ShutdownBuildServers or MemoryActionType.RestartPc or MemoryActionType.DisableFastStartup)
                && !IsStopOnly(s)))
            .Select(s => $"{s.Title}: {s.Why}").ToList();

    /// <summary>A service suggestion whose only action is "Stop now": temporary, so the workflow neither applies nor mentions it.</summary>
    public static bool IsStopOnly(MemorySuggestion s) => s.Actions.Count > 0 && s.Actions.All(a => a.Type == MemoryActionType.StopService);
}
