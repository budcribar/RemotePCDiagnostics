using System.Text.Json;
using PeakSWC.RemoteBlazorWebView.RemoteComponents;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.ModuleUi;

namespace RemotePCDiagnostics.Tests;

/// <summary>The app hands an unsigned module's latest result to its UI process (3.1) through the IModuleUi contract: the module page's
/// ModuleUiFrame sends it as a "set" line over the process's stdin, and the process's ModuleUiReceiver holds it.</summary>
public class ModuleUiContractTests
{
    private static readonly AreaAction Fix = new(RemediationKind.RestartDevice, "Restart", "dev1", "Webcam");

    private static DiagnosticResult Result(DateTimeOffset when, string message = "Local time 10:42") =>
        new DiagnosticResult<AreaReport>("sample.clock", DiagnosticStatus.Warning, message, when,
            new AreaReport([new AreaCard("clock", "Clock", AreaLevel.Warning, "10:42", "Pacific", ["Zone"], [new AreaRow(AreaLevel.Warning, ["PST"], Actions: [Fix])], Actions: [Fix])],
                message, DiagnosticStatus.Warning));

    /// <summary>The line the frame sends for <paramref name="result"/> (as RemoteComponentFrameBase serializes a contract value).</summary>
    private static string SetLine(DiagnosticResult result) => new RemoteComponentMessage
    {
        Set = new() { [nameof(IModuleUi.LastResult)] = JsonSerializer.SerializeToElement(ModuleUiResult.From(result), typeof(ModuleUiResult), RemoteComponentJson.Options) },
    }.ToLine();

    private static async Task<ModuleUiReceiver> Receive(params string[] lines)
    {
        var receiver = new ModuleUiReceiver(new RemoteComponentConnection(null, null));
        foreach (var line in lines)
            if (RemoteComponentMessage.Parse(line) is { } m) await receiver.OnMessageAsync(m);
        return receiver;
    }

    [Fact]
    public async Task A_result_crosses_as_one_line_with_its_time_report_and_no_actions()
    {
        var when = new DateTimeOffset(2026, 11, 5, 10, 42, 7, TimeSpan.FromHours(-8));
        var line = SetLine(Result(when));
        Assert.DoesNotContain('\n', line);
        var receiver = await Receive(line);
        var back = Assert.IsType<DiagnosticResult<AreaReport>>(receiver.LastResult!.ToResult("sample.clock"));
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
    public async Task The_app_theme_reaches_the_module_ui()
    {
        var receiver = await Receive(new RemoteComponentMessage { Set = new() { [nameof(IModuleUi.Theme)] = JsonSerializer.SerializeToElement("dark") } }.ToLine());
        Assert.Equal("dark", receiver.Theme);
        Assert.Null(receiver.LastResult);
        // The UI host serves the app's stylesheet and applies the choice the way the app does.
        var dir = Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "src", "RemotePCDiagnostics.ModuleUiHost");
        var index = File.ReadAllText(Path.Combine(dir, "wwwroot", "index.html"));
        Assert.Contains("href=\"app.css\"", index);
        Assert.Contains("window.rpdTheme", index);
        Assert.Contains("RemotePCDiagnostics.UI\\wwwroot\\app.css", File.ReadAllText(Path.Combine(dir, "RemotePCDiagnostics.ModuleUiHost.csproj")));
    }

    [Fact]
    public async Task Not_run_and_cancelled_results_keep_what_they_are()
    {
        var notRun = (await Receive(SetLine(DiagnosticResult.NotRun("m")))).LastResult!.ToResult("m");
        Assert.Equal(DiagnosticStatus.NotRun, notRun.Status);
        var cancelled = (await Receive(SetLine(new DiagnosticResult("m", DiagnosticStatus.Warning, "Cancelled", DateTimeOffset.Now) { Cancelled = true })))
            .LastResult!.ToResult("m");
        Assert.True(cancelled.Cancelled);
    }

    [Fact]
    public async Task The_UI_process_keeps_the_latest_result_and_ignores_anything_else()
    {
        var first = new DateTimeOffset(2026, 11, 5, 9, 0, 0, TimeSpan.Zero);
        var second = first.AddMinutes(5);
        var receiver = new ModuleUiReceiver(new RemoteComponentConnection(null, null));
        Assert.False(receiver.HasValues);
        Assert.Null(receiver.LastResult);                            // blank (the root shows "not run") until the app sends one
        var seen = new List<string>();
        receiver.Changed += () => seen.Add(receiver.LastResult!.Message);
        var input = string.Join("\n", SetLine(Result(first, "first")), "not json", """{"call":"x"}""", """{"set":{"other":1}}""", "",
            SetLine(Result(second, "second")));
        await receiver.Connection.RunAsync(receiver.OnMessageAsync); // no input: returns at once
        await new RemoteComponentConnection(new StringReader(input), null).RunAsync(receiver.OnMessageAsync);
        Assert.Equal(["first", "second"], seen);                     // once when the page opens, then after the next run
        Assert.Equal(second, receiver.LastResult!.When);
        Assert.True(receiver.HasValues);
    }

    [Fact]
    public async Task A_result_that_doesnt_parse_keeps_the_last_one()
    {
        var receiver = await Receive(SetLine(Result(DateTimeOffset.Now, "good")));
        var bad = new List<string>();
        receiver.BadValue += (name, _) => bad.Add(name);
        await receiver.OnMessageAsync(RemoteComponentMessage.Parse("""{"set":{"LastResult":{"status":"NoSuchStatus"}}}""")!);
        Assert.Equal(["LastResult"], bad);
        Assert.Equal("good", receiver.LastResult!.Message);
    }
}
