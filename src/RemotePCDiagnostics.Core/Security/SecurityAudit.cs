using System.Text;

namespace RemotePCDiagnostics.Core.Security;

/// <summary>End-user result of one check.</summary>
public enum AuditOutcome { Passed, Warning, Failed, NotChecked }

/// <summary>One HardeningKitty finding, already mapped to friendly fields.</summary>
public sealed record AuditFinding(
    string Id, string Category, string Name, string Severity, string CurrentValue, string RecommendedValue, AuditOutcome Outcome)
{
    public string OutcomeText => Outcome switch
    {
        AuditOutcome.Passed => "Passed",
        AuditOutcome.Warning => "Warning",
        AuditOutcome.Failed => "Failed",
        _ => "Not checked",
    };

    public string SeverityText => string.IsNullOrWhiteSpace(Severity) ? "—" : Severity;

    /// <summary>Worth a home user's attention (see <see cref="HomeAuditProfile"/>); the rest are enterprise-only settings.</summary>
    public bool HomeRelevant => HomeAuditProfile.IsRelevant(Id);

    public string Explanation => Outcome switch
    {
        AuditOutcome.Passed => "This setting matches the recommended value.",
        AuditOutcome.Warning => "This setting differs from the recommendation. The risk is low, but consider changing it.",
        AuditOutcome.Failed => "This setting differs from the recommendation and weakens this PC's security. Consider changing it.",
        _ => "This setting couldn't be checked on this PC.",
    };
}

/// <summary>Payload of the Security audit module.</summary>
/// <param name="Profile">Whether an organization manages this PC; null = not detected (nothing is hidden).</param>
public sealed record SecurityAuditReport(IReadOnlyList<AuditFinding> Findings, string? Notice = null, PcProfile? Profile = null)
{
    /// <summary>A home PC (detected as not managed): enterprise-only settings are left out of the counts and the list.</summary>
    public bool HomePc => Profile is { Managed: false };

    /// <summary>The findings the counts and the page show: on a home PC only the <see cref="AuditFinding.HomeRelevant"/> ones.</summary>
    public IReadOnlyList<AuditFinding> Shown => HomePc ? Findings.Where(f => f.HomeRelevant).ToList() : Findings;

    /// <summary>Enterprise-only findings left out on a home PC.</summary>
    public int Hidden => Findings.Count - Shown.Count;

    public int Passed => Shown.Count(f => f.Outcome == AuditOutcome.Passed);
    public int Warnings => Shown.Count(f => f.Outcome == AuditOutcome.Warning);
    public int Failed => Shown.Count(f => f.Outcome == AuditOutcome.Failed);
    public int NotChecked => Shown.Count(f => f.Outcome == AuditOutcome.NotChecked);

    /// <summary>Failed checks the baseline rates High or Critical: the ones that make this PC clearly less safe.</summary>
    public int HighRisk => Shown.Count(f => f.Outcome == AuditOutcome.Failed
        && (f.Severity.Equals("High", StringComparison.OrdinalIgnoreCase) || f.Severity.Equals("Critical", StringComparison.OrdinalIgnoreCase)));

    /// <summary>
    /// Critical only for high-risk failures. The baseline is strict (enterprise hardening), so a typical home PC fails
    /// many medium checks; those are a warning to review, not an alarm.
    /// </summary>
    public DiagnosticStatus Status => HighRisk > 0 ? DiagnosticStatus.Error : Failed > 0 || Warnings > 0 ? DiagnosticStatus.Warning : DiagnosticStatus.Ok;

    public string Summary => Findings.Count == 0
        ? "The audit finished but returned no results."
        : (HighRisk > 0 ? $"{HighRisk} high-risk · " : "")
          + $"{Failed} failed, {Warnings} {(Warnings == 1 ? "warning" : "warnings")}, {Passed} passed" + (NotChecked > 0 ? $", {NotChecked} not checked" : "")
          + (Hidden > 0 ? $" · {Hidden} enterprise-only settings hidden" : "");
}

/// <summary>Whether an organization manages this PC: joined to a domain or Microsoft Entra ID, enrolled in MDM, or an Enterprise/Education edition.</summary>
public sealed record PcProfile(bool Domain, bool EntraJoined, bool Mdm, string? Edition)
{
    public const string Marker = "RPD_PROFILE=";

    public bool EnterpriseEdition => Edition is { } e && (e.StartsWith("Enterprise", StringComparison.OrdinalIgnoreCase)
        || e.StartsWith("Education", StringComparison.OrdinalIgnoreCase) || e.StartsWith("Server", StringComparison.OrdinalIgnoreCase));

    public bool Managed => Domain || EntraJoined || Mdm || EnterpriseEdition;

    /// <summary>Plain words for the page, e.g. "joined to a domain".</summary>
    public string Reason => Domain ? "joined to a domain" : EntraJoined ? "joined to Microsoft Entra ID (work or school)" : Mdm ? "managed by an organization (MDM)"
        : EnterpriseEdition ? $"running Windows {Edition}" : "not managed by an organization";

    /// <summary>Read-only PowerShell that prints one <see cref="Marker"/> line; never throws.</summary>
    public const string DetectScript =
        @"try{$d=(Get-CimInstance Win32_ComputerSystem).PartOfDomain;" +
        @"$a=@(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo' -ErrorAction SilentlyContinue).Count -gt 0;" +
        @"$m=@(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction SilentlyContinue|Where-Object{(Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ProviderID -eq 'MS DM Server'}).Count -gt 0;" +
        @"$e=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID;" +
        @"Write-Output ('" + Marker + @"domain='+$d+';entra='+$a+';mdm='+$m+';edition='+$e)}catch{}";

    /// <summary>The profile from the <see cref="Marker"/> line in <paramref name="stdout"/>; null when it's missing or unreadable.</summary>
    public static PcProfile? Parse(string? stdout)
    {
        var line = (stdout ?? "").Split('\n').Select(l => l.Trim()).LastOrDefault(l => l.StartsWith(Marker, StringComparison.Ordinal));
        if (line is null) return null;
        var kv = line[Marker.Length..].Split(';').Select(p => p.Split('=', 2)).Where(p => p.Length == 2)
            .GroupBy(p => p[0].Trim(), StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.Last()[1].Trim(), StringComparer.OrdinalIgnoreCase);
        bool? B(string k) => kv.TryGetValue(k, out var v) && bool.TryParse(v, out var b) ? b : null;
        if (B("domain") is not { } domain || B("entra") is not { } entra || B("mdm") is not { } mdm) return null;
        return new(domain, entra, mdm, kv.TryGetValue("edition", out var ed) && ed.Length > 0 ? ed : null);
    }
}

/// <summary>
/// The audit items that matter on a home PC. Everything else in the baseline is an enterprise setting (user rights, audit policy, firewall
/// logging, Group Policy-only templates, NTLM/SMB signing, Credential Guard, ...) that a PC nobody manages never sets, so on a home PC it only
/// adds hundreds of "Failed" rows. Defender settings the baseline reads from Group Policy are left out too: Security essentials reads the real
/// values and can fix them.
/// </summary>
public static class HomeAuditProfile
{
    public static readonly IReadOnlySet<string> RelevantIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        // High severity: SMBv1, reversible passwords, LM hashes, plaintext WDigest credentials, drive encryption, PrintNightmare.
        "1000", "1103", "1326", "2203", "1708", "1764", "1765",
        // Account lockout after repeated wrong passwords.
        "1100",
        // Firewall on and blocking unsolicited inbound connections (the live settings, not the Group Policy copies).
        "1418", "1419", "1424", "1425", "1430", "1431",
        // Never sending SMB passwords unencrypted. (The UAC items are left out: the baseline wants stricter prompts than Windows' default.)
        "1329",
        // LLMNR and insecure guest logons (public Wi-Fi attacks); AutoRun off on all drives (what Security essentials sets).
        "1601", "1602", "1704",
        // Virtualization-based security and memory integrity (HVCI) running.
        "1614", "1620",
        // Defender Tamper Protection and the Attack Surface Reduction rules Security essentials can turn on.
        "1826", "1916", "1917", "1921", "1925", "1932",
    };

    public static bool IsRelevant(string? id) => id is not null && RelevantIds.Contains(id.Trim());
}

/// <summary>Parses the HardeningKitty report CSV (Export-Csv: ID,Category,Name,Severity,Result,Recommended,TestResult,SeverityFinding,DefaultValue,Filter).</summary>
public static class HardeningKittyCsv
{
    public static IReadOnlyList<AuditFinding> Parse(string csv)
    {
        var rows = ParseRows(csv);
        if (rows.Count == 0) return [];
        var header = rows[0].Select(h => h.Trim().TrimStart('\uFEFF')).ToList();
        int Col(string name) => header.FindIndex(h => h.Equals(name, StringComparison.OrdinalIgnoreCase));
        int id = Col("ID"), cat = Col("Category"), name = Col("Name"), sev = Col("Severity"), res = Col("Result"),
            rec = Col("Recommended"), test = Col("TestResult"), sevF = Col("SeverityFinding");
        if (id < 0 || name < 0 || (test < 0 && sev < 0))
            throw new FormatException("Report CSV is missing expected columns (ID, Name, TestResult/Severity). Header: " + string.Join(",", header));

        var list = new List<AuditFinding>();
        foreach (var r in rows.Skip(1))
        {
            if (r.Count == 1 && string.IsNullOrWhiteSpace(r[0])) continue;
            string Get(int i) => i >= 0 && i < r.Count ? r[i].Trim() : "";
            var severityField = Get(sev);
            var findingSeverity = Get(sevF);
            if (findingSeverity.Length == 0 && !severityField.Equals("Passed", StringComparison.OrdinalIgnoreCase)) findingSeverity = severityField;
            list.Add(new AuditFinding(Get(id), Get(cat), Get(name), findingSeverity, Get(res), Get(rec),
                Classify(Get(test), severityField, findingSeverity)));
        }
        return list;
    }

    /// <summary>Passed → Passed; failed Low → Warning; failed Medium/High/Critical → Failed; otherwise Not checked.</summary>
    public static AuditOutcome Classify(string testResult, string severity, string findingSeverity)
    {
        if (testResult.Equals("Passed", StringComparison.OrdinalIgnoreCase)) return AuditOutcome.Passed;
        if (testResult.Equals("Failed", StringComparison.OrdinalIgnoreCase))
            return findingSeverity.Equals("Low", StringComparison.OrdinalIgnoreCase) ? AuditOutcome.Warning : AuditOutcome.Failed;
        if (testResult.Length == 0)
        {
            if (severity.Equals("Passed", StringComparison.OrdinalIgnoreCase)) return AuditOutcome.Passed;
            if (severity.Equals("Low", StringComparison.OrdinalIgnoreCase)) return AuditOutcome.Warning;
            if (severity.Equals("Medium", StringComparison.OrdinalIgnoreCase)
                || severity.Equals("High", StringComparison.OrdinalIgnoreCase)
                || severity.Equals("Critical", StringComparison.OrdinalIgnoreCase))
                return AuditOutcome.Failed;
        }
        return AuditOutcome.NotChecked;
    }

    /// <summary>RFC 4180 reader: quoted fields, doubled quotes, embedded commas/newlines.</summary>
    public static List<List<string>> ParseRows(string text)
    {
        var rows = new List<List<string>>();
        var row = new List<string>();
        var field = new StringBuilder();
        bool inQuotes = false, any = false;
        for (int i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (inQuotes)
            {
                if (c == '"')
                {
                    if (i + 1 < text.Length && text[i + 1] == '"') { field.Append('"'); i++; }
                    else inQuotes = false;
                }
                else field.Append(c);
                continue;
            }
            switch (c)
            {
                case '"': inQuotes = true; any = true; break;
                case ',': row.Add(field.ToString()); field.Clear(); any = true; break;
                case '\r': break;
                case '\n':
                    row.Add(field.ToString()); field.Clear();
                    if (any || row.Count > 1 || row[0].Length > 0) rows.Add(row);
                    row = new List<string>(); any = false; break;
                default: field.Append(c); any = true; break;
            }
        }
        if (any || field.Length > 0) { row.Add(field.ToString()); rows.Add(row); }
        return rows;
    }
}
