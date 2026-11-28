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
    /// <paramref name="report"/> for an install with no Agent (the Microsoft Store app without the companion Agent): omits cards and rows
    /// whose only content is "Needs the Agent", and drops "Turn on Admin Repair Mode" hints everywhere. The same report when nothing changes.
    /// </summary>
    public static AreaReport? WithoutAgentHints(AreaReport? report, bool noAgent)
    {
        if (!noAgent || report is null || !report.Cards.Any(NeedsCleanup)) return report;
        var cards = new List<AreaCard>(report.Cards.Count);
        foreach (var c in report.Cards)
        {
            if (IsAgentOnlyCard(c)) continue;
            cards.Add(NeedsCleanup(c) ? CleanCard(c) : c);
        }
        return report with { Cards = cards };
    }

    private static bool NeedsCleanup(AreaCard card) =>
        IsAgentOnlyCard(card) || HasHint(card) || card.Rows.Any(r => IsAgentOnlyRow(r) || RowHasHint(r));

    private static bool IsAgentOnlyCard(AreaCard card) =>
        card.Headline.StartsWith("Needs the Agent", StringComparison.OrdinalIgnoreCase)
        || card.Headline.StartsWith("Skipped: Needs the Agent", StringComparison.OrdinalIgnoreCase)
        || (card.Rows.Count == 0 && (card.EmptyText?.StartsWith("Needs the Agent", StringComparison.OrdinalIgnoreCase) == true
            || card.EmptyText?.StartsWith("Install the Agent", StringComparison.OrdinalIgnoreCase) == true));

    private static bool IsAgentOnlyRow(AreaRow row) =>
        row.Values.Any(v => v.Equals("Needs the Agent", StringComparison.OrdinalIgnoreCase)
            || v.StartsWith("Needs the Agent:", StringComparison.OrdinalIgnoreCase));

    private static bool RowHasHint(AreaRow row) =>
        row.Values.Any(v => v.Contains(Session.ElevationService.AdminRepairHint, StringComparison.Ordinal));

    private static bool HasHint(AreaCard card) =>
        card.Meta.Contains(Session.ElevationService.AdminRepairHint, StringComparison.Ordinal)
        || card.Note?.Contains(Session.ElevationService.AdminRepairHint, StringComparison.Ordinal) == true
        || card.EmptyText?.Contains(Session.ElevationService.AdminRepairHint, StringComparison.Ordinal) == true;

    private static AreaCard CleanCard(AreaCard card)
    {
        var rows = card.Rows.Where(r => !IsAgentOnlyRow(r))
            .Select(r => RowHasHint(r) ? r with { Values = r.Values.Select(v => Strip(v)!).ToList() } : r)
            .ToList();
        return card with
        {
            Meta = Strip(card.Meta)!,
            Note = Strip(card.Note),
            EmptyText = Strip(card.EmptyText),
            Rows = rows,
        };
    }

    private static string? Strip(string? text) =>
        text?.Replace(Session.ElevationService.AdminRepairHint, "", StringComparison.Ordinal).Trim() is { Length: > 0 } t ? t
        : text is null ? null : "";

    private static bool HasAgentOnly(AreaCard card) =>
        card.Actions?.Any(a => NeedsAgent(a.Kind)) == true || card.Rows.Any(r => r.Actions?.Any(a => NeedsAgent(a.Kind)) == true);
}
