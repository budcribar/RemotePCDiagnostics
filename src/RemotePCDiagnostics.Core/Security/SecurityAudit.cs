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

    public string Explanation => Outcome switch
    {
        AuditOutcome.Passed => "This setting matches the recommended value.",
        AuditOutcome.Warning => "This setting differs from the recommendation. The risk is low, but consider changing it.",
        AuditOutcome.Failed => "This setting differs from the recommendation and weakens this PC's security. Consider changing it.",
        _ => "This setting couldn't be checked on this PC.",
    };
}

/// <summary>Payload of the Security audit module.</summary>
public sealed record SecurityAuditReport(IReadOnlyList<AuditFinding> Findings, string? Notice = null)
{
    public int Passed => Findings.Count(f => f.Outcome == AuditOutcome.Passed);
    public int Warnings => Findings.Count(f => f.Outcome == AuditOutcome.Warning);
    public int Failed => Findings.Count(f => f.Outcome == AuditOutcome.Failed);
    public int NotChecked => Findings.Count(f => f.Outcome == AuditOutcome.NotChecked);

    public DiagnosticStatus Status => Failed > 0 ? DiagnosticStatus.Error : Warnings > 0 ? DiagnosticStatus.Warning : DiagnosticStatus.Ok;

    public string Summary => Findings.Count == 0
        ? "The audit finished but returned no results."
        : $"{Failed} failed, {Warnings} {(Warnings == 1 ? "warning" : "warnings")}, {Passed} passed" + (NotChecked > 0 ? $", {NotChecked} not checked" : "");
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

    /// <summary>Passed → Passed; failed Low → Warning; failed Medium/High → Failed; otherwise Not checked.</summary>
    public static AuditOutcome Classify(string testResult, string severity, string findingSeverity)
    {
        if (testResult.Equals("Passed", StringComparison.OrdinalIgnoreCase)) return AuditOutcome.Passed;
        if (testResult.Equals("Failed", StringComparison.OrdinalIgnoreCase))
            return findingSeverity.Equals("Low", StringComparison.OrdinalIgnoreCase) ? AuditOutcome.Warning : AuditOutcome.Failed;
        if (testResult.Length == 0)
        {
            if (severity.Equals("Passed", StringComparison.OrdinalIgnoreCase)) return AuditOutcome.Passed;
            if (severity.Equals("Low", StringComparison.OrdinalIgnoreCase)) return AuditOutcome.Warning;
            if (severity.Equals("Medium", StringComparison.OrdinalIgnoreCase) || severity.Equals("High", StringComparison.OrdinalIgnoreCase)) return AuditOutcome.Failed;
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
