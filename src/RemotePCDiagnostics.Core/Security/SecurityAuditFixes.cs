using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Security;

/// <summary>
/// The fix the app offers for a security audit finding that didn't pass: one of the Security essentials settings the Agent can change
/// (<see cref="SecurityFixes"/>), or the Windows Security / Settings page where the person changes it. Null when there is neither.
/// </summary>
public static class SecurityAuditFixes
{
    /// <summary>The Attack Surface Reduction rules in the baseline that the "Turn on 5 protection rules" fix turns on.</summary>
    public static readonly IReadOnlySet<string> AsrFindingIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "1916", "1917", "1921", "1925", "1932" };

    /// <summary>The firewall checks (on, and blocking unsolicited inbound connections) for the domain, private and public profiles.</summary>
    public static readonly IReadOnlySet<string> FirewallFindingIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "1418", "1419", "1424", "1425", "1430", "1431" };

    private static AreaAction Apply(string key)
    {
        var fix = SecurityFixes.Find(key) ?? throw new ArgumentException(key, nameof(key));
        return new(RemediationKind.ApplySecuritySetting, fix.ButtonText, fix.Key, fix.Label);
    }

    private static AreaAction Open(string button, string uri, string label) => new(RemediationKind.OpenSettings, button, uri, label);

    /// <summary>The fix for one finding ID, whatever its outcome.</summary>
    public static AreaAction? ForId(string? id)
    {
        id = id?.Trim() ?? "";
        if (AsrFindingIds.Contains(id)) return Apply(SecurityFixes.AsrRules);
        if (FirewallFindingIds.Contains(id)) return Open("Open Firewall settings", "windowsdefender://network", "Windows Security (Firewall & network protection)");
        return id switch
        {
            "1601" => Apply(SecurityFixes.Llmnr),
            "1602" => Apply(SecurityFixes.GuestLogons),
            "1704" => Apply(SecurityFixes.AutoRun),
            "1614" or "1620" => Open("Open Core isolation", "windowsdefender://coreisolation", "Windows Security (Core isolation)"),
            "1826" => Open("Open Windows Security", "windowsdefender://threatsettings", "Windows Security (Virus & threat protection settings)"),
            "1708" => Open("Open Device encryption", "ms-settings:deviceencryption", "Settings (Device encryption)"),
            _ => null,
        };
    }

    /// <summary>The fix for a finding that failed or has a warning; null for one that passed or wasn't checked.</summary>
    public static AreaAction? For(AuditFinding f) => f.Outcome is AuditOutcome.Failed or AuditOutcome.Warning ? ForId(f.Id) : null;

    /// <summary>The distinct fixes for the report's findings that need attention, in the order of those findings (the ASR fix once for all five rules).</summary>
    public static IReadOnlyList<(AreaAction Action, IReadOnlyList<AuditFinding> Findings)> ForReport(SecurityAuditReport report)
    {
        var list = new List<(AreaAction Action, List<AuditFinding> Findings)>();
        foreach (var f in report.NeedsAttention)
        {
            if (For(f) is not { } a) continue;
            var i = list.FindIndex(x => x.Action.Kind == a.Kind && string.Equals(x.Action.Target, a.Target, StringComparison.OrdinalIgnoreCase));
            if (i < 0) list.Add((a, [f]));
            else list[i].Findings.Add(f);
        }
        return list.Select(x => (x.Action, (IReadOnlyList<AuditFinding>)x.Findings)).ToList();
    }
}
