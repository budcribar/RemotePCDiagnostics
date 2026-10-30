using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Security;

/// <summary>Sortable columns of the Security audit table.</summary>
public enum AuditColumn { Result, Id, Category, Setting, Severity, Current, Recommended }

/// <summary>Stable, logical sorting for Security audit findings (most important first by default).</summary>
public static class AuditSort
{
    public static readonly (AuditColumn Col, bool Desc) Default = (AuditColumn.Result, false);

    public static readonly IReadOnlyList<(AuditColumn Col, string Title)> Columns =
    [
        (AuditColumn.Result, "Result"), (AuditColumn.Id, "ID"), (AuditColumn.Category, "Category"), (AuditColumn.Setting, "Setting"),
        (AuditColumn.Severity, "Severity"), (AuditColumn.Current, "Current"), (AuditColumn.Recommended, "Recommended"),
    ];

    /// <summary>Ascending rank: Failed, Warning, Not checked, Passed.</summary>
    public static int OutcomeRank(AuditOutcome o) => o switch
    {
        AuditOutcome.Failed => 0, AuditOutcome.Warning => 1, AuditOutcome.NotChecked => 2, _ => 3,
    };

    /// <summary>Ascending rank: Critical, High, Medium, Low, then unknown/blank.</summary>
    public static int SeverityRank(string s) => s.Trim().ToLowerInvariant() switch
    {
        "critical" => 0, "high" => 1, "medium" => 2, "low" => 3, "" => 5, _ => 4,
    };

    private static int Text(string a, string b)
    {
        // Blanks always last in ascending order.
        bool ea = string.IsNullOrWhiteSpace(a), eb = string.IsNullOrWhiteSpace(b);
        if (ea || eb) return ea == eb ? 0 : ea ? 1 : -1;
        return AreaSort.Compare(a.Trim(), b.Trim());
    }

    public static int Compare(AuditFinding a, AuditFinding b, AuditColumn col) => col switch
    {
        AuditColumn.Result => OutcomeRank(a.Outcome).CompareTo(OutcomeRank(b.Outcome)) is var c and not 0 ? c
            : SeverityRank(a.Severity).CompareTo(SeverityRank(b.Severity)),
        AuditColumn.Severity => SeverityRank(a.Severity).CompareTo(SeverityRank(b.Severity)) is var c and not 0 ? c
            : OutcomeRank(a.Outcome).CompareTo(OutcomeRank(b.Outcome)),
        AuditColumn.Id => Text(a.Id, b.Id),
        AuditColumn.Category => Text(a.Category, b.Category),
        AuditColumn.Setting => Text(a.Name, b.Name),
        AuditColumn.Current => Text(a.CurrentValue, b.CurrentValue),
        AuditColumn.Recommended => Text(a.RecommendedValue, b.RecommendedValue),
        _ => 0,
    };

    /// <summary>Stable sort; ties keep the original (report) order.</summary>
    public static IReadOnlyList<AuditFinding> Sort(IEnumerable<AuditFinding> findings, AuditColumn col, bool descending)
    {
        var idx = findings.Select((f, i) => (f, i)).ToList();
        idx.Sort((p, q) =>
        {
            var c = Compare(p.f, q.f, col);
            if (descending) c = -c;
            return c != 0 ? c : p.i.CompareTo(q.i);
        });
        return idx.Select(p => p.f).ToList();
    }

    /// <summary>Clicking the active column flips direction; a new column starts ascending (logical columns: most important first).</summary>
    public static (AuditColumn Col, bool Desc) Toggle((AuditColumn Col, bool Desc) current, AuditColumn clicked) =>
        current.Col == clicked ? (clicked, !current.Desc) : (clicked, false);
}
