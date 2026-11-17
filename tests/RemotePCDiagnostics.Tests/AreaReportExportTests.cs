using System.Text.Json;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Tests;

public class AreaReportExportTests
{
    private static AreaRow Row(AreaLevel level, string name, string? detail = null, string? dump = null, string? copy = null) =>
        new(level, [name, "value"], Key: name, Detail: detail, DumpPath: dump, EventCopyText: copy);

    private static AreaReport Report(params AreaRow[] rows) => new(
        [new AreaCard("crashes", "Crashes", AreaLevel.Warning, "2 crashes", "most: chrome.exe", ["App", "Count"], rows)
            { EventCount = 2, WindowDays = 30, RecentEventCount = 1, RecentWindowDays = 7 }],
        "2 crashes in the last 30 days", DiagnosticStatus.Warning);

    [Fact]
    public void Exports_cards_and_attention_rows_worst_first_without_ok_rows()
    {
        var export = AreaReportExport.Build(Report(
            Row(AreaLevel.Ok, "fine.exe"),
            Row(AreaLevel.Warning, "warn-1.exe", detail: "Faulting module ntdll.dll"),
            Row(AreaLevel.Neutral, "info.exe", detail: "neutral detail"),
            Row(AreaLevel.Error, "bad.exe", detail: "Access violation"),
            Row(AreaLevel.Warning, "warn-2.exe")));

        Assert.Equal(AreaReportExport.SchemaVersion, export.Schema);
        Assert.Equal("warning", export.Status);
        var card = Assert.Single(export.Cards);
        Assert.Equal("crashes", card.Id);
        Assert.Equal("warning", card.Level);
        Assert.Equal("2 crashes", card.Headline);
        Assert.Equal(2, card.EventCount);
        Assert.Equal(7, card.RecentWindowDays);
        Assert.Equal(["App", "Count"], card.Columns);
        Assert.Equal(5, card.RowCount);
        Assert.Equal(4, card.AttentionRowCount);
        Assert.Equal(["bad.exe", "warn-1.exe", "warn-2.exe", "info.exe"], card.Rows.Select(r => r.Key));
        Assert.Equal("Access violation", card.Rows[0].Detail);
        Assert.Equal("Faulting module ntdll.dll", card.Rows[1].Detail);
        Assert.Null(card.Rows[3].Detail); // detail only for rows that need attention
    }

    [Fact]
    public void Leaves_out_dump_paths_and_copilot_text()
    {
        var json = AreaReportExport.ToJson(Report(Row(AreaLevel.Error, "bad.exe", "detail",
            dump: @"C:\ProgramData\dumps\bad.dmp", copy: "COPILOT-PROMPT-TEXT")));

        Assert.DoesNotContain("bad.dmp", json);
        Assert.DoesNotContain("COPILOT-PROMPT-TEXT", json);
        using var doc = JsonDocument.Parse(json);
        Assert.Equal("bad.exe", doc.RootElement.GetProperty("cards")[0].GetProperty("rows")[0].GetProperty("key").GetString());
    }

    [Fact]
    public void Caps_values_detail_and_row_count()
    {
        var rows = Enumerable.Range(0, AreaReportExport.MaxRowsPerCard + 10)
            .Select(i => Row(AreaLevel.Warning, $"app-{i:D3}" + new string('x', 400), detail: new string('d', 5000)))
            .ToArray();

        var card = Assert.Single(AreaReportExport.Build(Report(rows)).Cards);

        Assert.Equal(AreaReportExport.MaxRowsPerCard, card.Rows.Count);
        Assert.Equal(AreaReportExport.MaxRowsPerCard + 10, card.AttentionRowCount);
        Assert.All(card.Rows, r =>
        {
            Assert.True(r.Values[0].Length <= AreaReportExport.MaxValueLength);
            Assert.EndsWith("…", r.Values[0]);
            Assert.Equal(AreaReportExport.MaxTextLength, r.Detail!.Length);
        });
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("   ", null)]
    [InlineData("a\r\n\tb  c", "a b c")]
    [InlineData("\u0007bell\u0000", "bell")]
    [InlineData("short", "short")]
    public void Text_collapses_whitespace_and_controls(string? input, string? expected) =>
        Assert.Equal(expected, AreaReportExport.Text(input, 20));

    [Fact]
    public void Text_does_not_split_a_surrogate_pair()
    {
        var text = AreaReportExport.Text("abcd😀😀😀😀", 6)!;
        Assert.True(text.Length <= 6);
        Assert.False(char.IsHighSurrogate(text[^2]));
    }

    [Fact]
    public void Crashes_report_exports_app_names()
    {
        var report = CrashesModule.Build(WindowsEventLog.Parse(
            EventLogTests.Ev("Application Hang", 1002, 2, DateTime.UtcNow.AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ssZ"),
                "The program EXCEL.EXE stopped interacting with Windows", "Application", "<Data>EXCEL.EXE</Data><Data>16.0</Data>"),
            "Application"), DateTimeOffset.Now);

        var json = AreaReportExport.ToJson(report);

        Assert.Contains("EXCEL.EXE", json);
    }
}

public class AreaReportExportActionTests
{
    [Fact]
    public void Exports_card_and_row_fixes_including_ok_rows_that_have_one()
    {
        var fix = new AreaAction(RemediationKind.FlushDnsAndRenewIp, "Flush DNS", "Ethernet", "Adapter Ethernet", "DHCP");
        var rowFix = new AreaAction(RemediationKind.ApplySecuritySetting, "Turn on", "pua", "Block potentially unwanted apps", "Off");
        var report = new AreaReport(
        [
            new AreaCard("dns", "DNS", AreaLevel.Warning, "Slow lookups", "", ["Setting", "Value"],
                [new AreaRow(AreaLevel.Ok, ["PUA protection", "Off"], Key: "pua", Actions: [rowFix]), new AreaRow(AreaLevel.Ok, ["Other", "On"], Key: "other")],
                Actions: [fix]),
        ], "", DiagnosticStatus.Warning);

        var card = Assert.Single(AreaReportExport.Build(report).Cards);

        var cardAction = Assert.Single(card.Actions!);
        Assert.Equal("FlushDnsAndRenewIp", cardAction.Kind);
        Assert.Equal("Ethernet", cardAction.Target);
        Assert.Equal("DHCP", cardAction.CurrentSetting);
        var row = Assert.Single(card.Rows);
        Assert.Equal("pua", row.Key);
        Assert.Equal("ApplySecuritySetting", Assert.Single(row.Actions!).Kind);
    }

    [Fact]
    public void Exports_services_with_their_buttons()
    {
        var service = new ServiceInfo("Spooler", "Print Spooler", "STOPPED", "AUTO_START", "LocalSystem", "");
        var exported = AreaReportExport.Service(service, new ServiceControlOptions(true, false, false, false, null));
        var report = new AreaReport([], "", DiagnosticStatus.Ok);

        var json = AreaReportExport.ToJson(report, [exported]);
        using var doc = System.Text.Json.JsonDocument.Parse(json);
        var svc = doc.RootElement.GetProperty("services")[0];

        Assert.Equal("Spooler", svc.GetProperty("name").GetString());
        Assert.Equal("Print Spooler", svc.GetProperty("displayName").GetString());
        Assert.True(svc.GetProperty("canStart").GetBoolean());
        Assert.False(svc.GetProperty("canStop").GetBoolean());
        Assert.False(System.Text.Json.JsonDocument.Parse(AreaReportExport.ToJson(report)).RootElement.TryGetProperty("services", out _));
    }
}
