using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Plugins;

namespace RemotePCDiagnostics.Tests;

/// <summary>The app hands an unsigned module's latest result to its UI host (3.1): one JSON line per result over the UI host's stdin.</summary>
public class ModuleUiStateTests
{
    private static readonly AreaAction Fix = new(RemediationKind.RestartDevice, "Restart", "dev1", "Webcam");

    private static DiagnosticResult Result(DateTimeOffset when, string message = "Local time 10:42") =>
        new DiagnosticResult<AreaReport>("sample.clock", DiagnosticStatus.Warning, message, when,
            new AreaReport([new AreaCard("clock", "Clock", AreaLevel.Warning, "10:42", "Pacific", ["Zone"], [new AreaRow(AreaLevel.Warning, ["PST"], Actions: [Fix])], Actions: [Fix])],
                message, DiagnosticStatus.Warning));

    [Fact]
    public void A_result_crosses_as_one_line_with_its_time_report_and_no_actions()
    {
        var when = new DateTimeOffset(2026, 11, 5, 10, 42, 7, TimeSpan.FromHours(-8));
        var line = ModuleUiState.ToLine(Result(when));
        Assert.DoesNotContain('\n', line);
        var back = Assert.IsType<DiagnosticResult<AreaReport>>(ModuleUiState.FromLine("sample.clock", line));
        Assert.Equal("sample.clock", back.ModuleName);
        Assert.Equal(DiagnosticStatus.Warning, back.Status);
        Assert.Equal("Local time 10:42", back.Message);
        Assert.Equal(when, back.Timestamp);
        var card = Assert.Single(back.Data!.Cards);
        Assert.Equal("10:42", card.Headline);
        Assert.Null(card.Actions);                                   // one-click fixes never reach an unsigned module's UI
        Assert.Null(Assert.Single(card.Rows!).Actions);
        Assert.False(back.Cancelled);
    }

    [Fact]
    public void Not_run_and_cancelled_results_keep_what_they_are()
    {
        var notRun = ModuleUiState.FromLine("m", ModuleUiState.ToLine(DiagnosticResult.NotRun("m")))!;
        Assert.Equal(DiagnosticStatus.NotRun, notRun.Status);
        var cancelled = ModuleUiState.FromLine("m", ModuleUiState.ToLine(new DiagnosticResult("m", DiagnosticStatus.Warning, "Cancelled", DateTimeOffset.Now) { Cancelled = true }))!;
        Assert.True(cancelled.Cancelled);
    }

    [Fact]
    public async Task The_UI_host_keeps_the_latest_result_and_ignores_anything_else()
    {
        var first = new DateTimeOffset(2026, 11, 5, 9, 0, 0, TimeSpan.Zero);
        var second = first.AddMinutes(5);
        var input = string.Join("\n", ModuleUiState.ToLine(Result(first, "first")), "not json", """{"type":"progress","message":"x"}""", "",
            ModuleUiState.ToLine(Result(second, "second")));
        var receiver = new ModuleUiState.Receiver("sample.clock");
        Assert.Equal(DiagnosticStatus.NotRun, receiver.Current.Status); // blank until the app sends one
        var seen = new List<string>();
        receiver.Changed += r => seen.Add(r.Message);
        await receiver.ReadAsync(new StringReader(input));
        Assert.Equal(["first", "second"], seen);                     // once when the page opens, then after the next run
        Assert.Equal(second, receiver.Current.Timestamp);
        Assert.Equal("second", receiver.Current.Message);
    }
}
