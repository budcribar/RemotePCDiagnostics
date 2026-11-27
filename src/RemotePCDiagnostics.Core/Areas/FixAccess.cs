namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// Which fixes need the Agent: they run with administrator rights, and the app itself never has them. Without a connected Agent (the
/// Microsoft Store app with no Agent installed) those buttons are left out, so the PC just offers fewer fixes instead of ones that fail
/// with "turn on Admin Repair Mode". Fixes that work as the signed-in user (Sound devices, the proxy, Storage Sense, Settings pages) stay.
/// </summary>
public static class FixAccess
{
    /// <summary>True when <paramref name="kind"/> only runs through the Agent (an Agent script, an admin tool, or an admin setting).</summary>
    public static bool NeedsAgent(RemediationKind kind) => kind is
        RemediationKind.CheckAndInstallDriverUpdates or RemediationKind.CheckAndInstallWindowsUpdates or RemediationKind.InstallUpdate
        or RemediationKind.RestartDevice or RemediationKind.EnableDevice or RemediationKind.ScanHardwareChanges
        or RemediationKind.DisableFastStartup or RemediationKind.SetPublicDns or RemediationKind.ResetDhcpDns
        or RemediationKind.EndProcessGroup or RemediationKind.CloseAudioHolder
        or RemediationKind.CleanTempFiles or RemediationKind.OptimizeSsd
        or RemediationKind.RepairComponentStore or RemediationKind.RepairSystemFiles or RemediationKind.AnalyzeComponentStore
        or RemediationKind.CleanUpComponentStore or RemediationKind.RepairComponentStoreFromImage
        or RemediationKind.ApplySecuritySetting
        or RemediationKind.DisableDeviceWake or RemediationKind.DisableWakeTimer
        or RemediationKind.InstallBiosUpdate or RemediationKind.CreatePersistentDevDrive or RemediationKind.InstallDotNetSdk
        or RemediationKind.StartAudioServices or RemediationKind.RestartAudioServices or RemediationKind.SetAudioServicesAutomatic
        or RemediationKind.SetHpBatteryChargeLimit;

    public static bool CanOffer(AreaAction action, bool agent) => agent || !NeedsAgent(action.Kind);

    /// <summary><paramref name="actions"/> without the ones that need the Agent when it isn't there; null when none are left.</summary>
    public static IReadOnlyList<AreaAction>? Offerable(IReadOnlyList<AreaAction>? actions, bool agent)
    {
        if (agent || actions is null || !actions.Any(a => NeedsAgent(a.Kind))) return actions;
        var left = actions.Where(a => !NeedsAgent(a.Kind)).ToList();
        return left.Count == 0 ? null : left;
    }

    /// <summary>
    /// <paramref name="report"/> with every card's and row's fixes that need the Agent left out when it isn't there. The same report
    /// (no copy) when nothing changes.
    /// </summary>
    public static AreaReport? Offerable(AreaReport? report, bool agent)
    {
        if (agent || report is null || !report.Cards.Any(HasAgentOnly)) return report;
        return report with { Cards = report.Cards.Select(c => Offerable(c, agent)).ToList() };
    }

    public static AreaCard Offerable(AreaCard card, bool agent)
    {
        if (agent || !HasAgentOnly(card)) return card;
        return card with
        {
            Actions = Offerable(card.Actions, agent),
            Rows = card.Rows.Select(r => r.Actions is { Count: > 0 } ? r with { Actions = Offerable(r.Actions, agent) } : r).ToList(),
        };
    }

    /// <summary>
    /// <paramref name="report"/> without the "Turn on Admin Repair Mode" hint in its cards when <paramref name="noAgent"/> (no Agent is
    /// installed, so there is nothing to turn on): a card that couldn't read something just says so. The same report when nothing changes.
    /// </summary>
    public static AreaReport? WithoutAgentHints(AreaReport? report, bool noAgent)
    {
        if (!noAgent || report is null || !report.Cards.Any(HasHint)) return report;
        return report with { Cards = report.Cards.Select(c => HasHint(c) ? c with { Meta = Strip(c.Meta)!, Note = Strip(c.Note) } : c).ToList() };
    }

    private static bool HasHint(AreaCard card) =>
        card.Meta.Contains(Session.ElevationService.AdminRepairHint, StringComparison.Ordinal)
        || card.Note?.Contains(Session.ElevationService.AdminRepairHint, StringComparison.Ordinal) == true;

    private static string? Strip(string? text) =>
        text?.Replace(Session.ElevationService.AdminRepairHint, "", StringComparison.Ordinal).Trim() is { Length: > 0 } t ? t
        : text is null ? null : "";

    private static bool HasAgentOnly(AreaCard card) =>
        card.Actions?.Any(a => NeedsAgent(a.Kind)) == true || card.Rows.Any(r => r.Actions?.Any(a => NeedsAgent(a.Kind)) == true);
}
