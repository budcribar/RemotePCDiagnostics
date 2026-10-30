using RemotePCDiagnostics.Core.Security;
using Xunit;

namespace RemotePCDiagnostics.Tests;

public sealed class AuditSortTests
{
    private static AuditFinding F(string id, AuditOutcome o, string sev = "", string cat = "", string name = "", string cur = "", string rec = "") =>
        new(id, cat, name.Length > 0 ? name : "n" + id, sev, cur, rec, o);

    private static readonly AuditFinding[] Sample =
    [
        F("10", AuditOutcome.Passed, "High", "B", "Zeta", "1", "1"),
        F("2", AuditOutcome.Warning, "Low", "A", "alpha", "0", "1"),
        F("100", AuditOutcome.Failed, "Medium", "C", "Beta", "", "2"),
        F("3", AuditOutcome.NotChecked, "", "A", "Gamma", "x", ""),
        F("4", AuditOutcome.Failed, "High", "B", "Delta", "5", "3"),
        F("5", AuditOutcome.Failed, "Critical", "", "Eps", "7", "4"),
    ];

    private static string Ids(IEnumerable<AuditFinding> f) => string.Join(",", f.Select(x => x.Id));

    [Fact]
    public void Default_IsFailuresFirst_MostSevereFirst()
    {
        var (col, desc) = AuditSort.Default;
        Assert.Equal("5,4,100,2,3,10", Ids(AuditSort.Sort(Sample, col, desc)));
    }

    [Fact]
    public void Result_Descending_PutsPassedFirst() =>
        Assert.Equal("10", AuditSort.Sort(Sample, AuditColumn.Result, true)[0].Id);

    [Fact]
    public void Severity_IsLogicalNotAlphabetical()
    {
        Assert.Equal("5,4,10,100,2,3", Ids(AuditSort.Sort(Sample, AuditColumn.Severity, false)));
        Assert.True(AuditSort.SeverityRank("Critical") < AuditSort.SeverityRank("High"));
        Assert.True(AuditSort.SeverityRank("high") < AuditSort.SeverityRank("Medium"));
        Assert.True(AuditSort.SeverityRank("Medium") < AuditSort.SeverityRank("Low"));
        Assert.True(AuditSort.SeverityRank("Low") < AuditSort.SeverityRank(""));
    }

    [Fact]
    public void Outcome_IsLogical()
    {
        Assert.True(AuditSort.OutcomeRank(AuditOutcome.Failed) < AuditSort.OutcomeRank(AuditOutcome.Warning));
        Assert.True(AuditSort.OutcomeRank(AuditOutcome.Warning) < AuditSort.OutcomeRank(AuditOutcome.Passed));
    }

    [Fact]
    public void Id_SortsNumerically() =>
        Assert.Equal("2,3,4,5,10,100", Ids(AuditSort.Sort(Sample, AuditColumn.Id, false)));

    [Fact]
    public void Text_CaseInsensitive_BlanksLast()
    {
        Assert.Equal("2,100,4,5,3,10", Ids(AuditSort.Sort(Sample, AuditColumn.Setting, false)));
        Assert.Equal("5", AuditSort.Sort(Sample, AuditColumn.Category, false)[^1].Id);
        Assert.Equal("100", AuditSort.Sort(Sample, AuditColumn.Current, false)[^1].Id);
        Assert.Equal("3", AuditSort.Sort(Sample, AuditColumn.Recommended, false)[^1].Id);
    }

    [Fact]
    public void Sort_IsStable()
    {
        // Category "A": 2 before 3; "B": 10 before 4 (original order kept) in both directions.
        Assert.Equal("2,3,10,4,100,5", Ids(AuditSort.Sort(Sample, AuditColumn.Category, false)));
        var desc = Ids(AuditSort.Sort(Sample, AuditColumn.Category, true));
        Assert.Contains("10,4", desc);
        Assert.Contains("2,3", desc);
    }

    [Fact]
    public void Toggle_FlipsSameColumn_NewColumnStartsAscending()
    {
        var s = AuditSort.Toggle(AuditSort.Default, AuditColumn.Result);
        Assert.Equal((AuditColumn.Result, true), s);
        Assert.Equal((AuditColumn.Result, false), AuditSort.Toggle(s, AuditColumn.Result));
        Assert.Equal((AuditColumn.Severity, false), AuditSort.Toggle(s, AuditColumn.Severity));
    }

    [Fact]
    public void EveryColumnHasTitle() =>
        Assert.Equal(Enum.GetValues<AuditColumn>().Length, AuditSort.Columns.Count);
}
