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
            var a = s.Actions.FirstOrDefault(x => UnattendedMemoryActions.Contains(x.Type));
            if (a is null) continue;
            var id = MemoryId(s.Id, a.Type, a.Target);
            if (!seen.Add(id)) continue;
            var order = a.Type switch { MemoryActionType.DisableStartup => 20, MemoryActionType.SetServiceManual => 22, MemoryActionType.AutoManagePageFile => 12, _ => 15 };
            list.Add(new(id, a.Type == MemoryActionType.SetServiceManual ? $"{s.Title}: start only when needed" : s.Title, s.Why, s.Category, s.Risk, FixSource.Memory, order,
                SuggestionId: s.Id, MemoryAction: a.Type, MemoryTarget: a.Target,
                NeedsAdmin: a.Type is MemoryActionType.AutoManagePageFile or MemoryActionType.SetServiceManual or MemoryActionType.AddDefenderExclusions,
                Undo: Changes.Undoability.Of(a.Type)));
        }

        return list.OrderBy(f => f.Order).ThenBy(f => f.Area).ThenBy(f => f.Title, StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>Things worth telling the client that need a person (not applied by the workflow).</summary>
    public static IReadOnlyList<string> Recommendations(IEnumerable<MemorySuggestion> suggestions) =>
        suggestions.Where(s => s.Kind is SuggestionKind.Guided or SuggestionKind.Info || (s.Kind == SuggestionKind.Automated && !s.Actions.Any(a => UnattendedMemoryActions.Contains(a.Type)) && !s.Actions.Any(a => a.Type is MemoryActionType.CloseApp or MemoryActionType.ShutdownBuildServers or MemoryActionType.RestartPc or MemoryActionType.DisableFastStartup)))
            .Select(s => $"{s.Title}: {s.Why}").ToList();
}
