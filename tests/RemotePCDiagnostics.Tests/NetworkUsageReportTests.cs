using RemotePCDiagnostics.Core.NetworkUsage;

namespace RemotePCDiagnostics.Tests;

public class NetworkUsageReportTests
{
    private static readonly DateTimeOffset End = DateTimeOffset.Parse("2026-11-01T00:00:00Z");

    [Fact]
    public void AggregatesByIdentityAndUserWithoutCombiningDifferentExecutables()
    {
        var report = new NetworkUsageReport("test", End.AddDays(-7), End,
            [new("a", "Browser", "user1", "Wi-Fi", End.AddHours(-1), 10, 20),
             new("a", "Browser", "user1", "Ethernet", End.AddHours(-2), 30, 40),
             new("b", "Browser", "user1", "Wi-Fi", null, 1, 2),
             new("a", "Browser", "user2", "Wi-Fi", null, 3, 4)], []);
        Assert.Equal(3, report.TopApps().Count);
        Assert.Equal(100m, report.TopApps()[0].Total);
        Assert.Equal(40UL, report.TopApps()[0].Uploaded);
        Assert.Equal(60UL, report.TopApps()[0].Downloaded);
    }

    [Fact]
    public void MissingHistoryDoesNotImplyZeroUsageAndHtmlEscapesNames()
    {
        var empty = new NetworkUsageReport("test", End.AddDays(-1), End, [], ["<failed>"]);
        Assert.Contains("not evidence of zero", empty.ToHtml());
        Assert.Contains("&lt;failed&gt;", empty.ToHtml());
        var populated = empty with { Entries = [new("<script>", "<app>", "user", "adapter", null, 0, 3)] };
        Assert.DoesNotContain("<script>", populated.ToHtml());
        Assert.Contains("&lt;app&gt;", populated.ToHtml());
    }

    [Fact]
    public void CsvQuotesFieldsAndNeutralizesSpreadsheetFormulas()
    {
        var report = new NetworkUsageReport("test", End.AddDays(-1), End,
            [new("=formula", "app,\"name", "user", "adapter", null, 1, 2)], []);
        Assert.Contains("\"'=formula\"", report.ToCsv());
        Assert.Contains("\"app,\"\"name\"", report.ToCsv());
    }
}
