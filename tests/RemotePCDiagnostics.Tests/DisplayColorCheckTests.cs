using System.Text.Json;
using Bunit;
using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Display;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;
using RemotePCDiagnostics.UI;
using RemotePCDiagnostics.UI.Shared;

namespace RemotePCDiagnostics.Tests;

/// <summary>The display test's color number check, every-monitor run and Screen off and on (#296).</summary>
public class DisplayColorCheckTests : BunitContext
{
    private static readonly ScreenInfo Laptop = new(@"\\.\DISPLAY1", "Screen 1: Built-in", true, 0, 0, 1920, 1200);
    private static readonly ScreenInfo Dell = new(@"\\.\DISPLAY2", "Screen 2: DELL U2720Q", false, 1920, 0, 3840, 2160);

    // ---- Core ----

    [Fact]
    public void New_numbers_are_three_different_two_digit_numbers()
    {
        for (var seed = 0; seed < 200; seed++)
        {
            var n = DisplayColorCheck.NewNumbers(new Random(seed));
            Assert.Equal(3, n.Count);
            Assert.All(n, x => Assert.InRange(x, 10, 99));
            Assert.Equal(3, n.Distinct().Count());
        }
    }

    [Theory]
    [InlineData("42", 42)]
    [InlineData(" 4 2 ", 42)]
    [InlineData("07", 7)]
    [InlineData("", null)]
    [InlineData("   ", null)]
    [InlineData(null, null)]
    [InlineData("4a", null)]
    [InlineData("-5", null)]
    [InlineData("1234567", null)]
    public void Answers_are_digits_only(string? typed, int? expected) => Assert.Equal(expected, DisplayColorCheck.ParseAnswer(typed));

    [Fact]
    public void A_wrong_or_empty_number_fails_only_that_channel()
    {
        var answers = DisplayColorCheck.Grade([12, 34, 56], ["12", "", "65"]);
        var screen = new DisplayScreenResult("s", "Screen 1", Answers: answers);
        Assert.Equal(ColorCheckState.Failed, screen.ColorCheck);
        Assert.Equal([ColorChannel.Green, ColorChannel.Blue], screen.FailedChannels);
        Assert.Equal("Green and blue channels failed on Screen 1", DisplayColorCheck.Summary(screen));
        Assert.Equal("Color channels OK on Screen 1",
            DisplayColorCheck.Summary(screen with { Answers = DisplayColorCheck.Grade([12, 34, 56], ["12", "34", "56"]) }));
        Assert.Equal("red, green and blue", DisplayColorCheck.Names(DisplayColorCheck.Channels));
    }

    [Fact]
    public void A_failed_channel_or_a_dark_screen_fails_whatever_was_pressed()
    {
        var failed = new DisplayScreenResult("s", "S", Answers: DisplayColorCheck.Grade([12, 34, 56], ["12", "34", "5"]));
        var passed = failed with { Answers = DisplayColorCheck.Grade([12, 34, 56], ["12", "34", "56"]) };
        Assert.Equal(PhysicalCheckOutcome.Failed, DisplayColorCheck.Effective(PhysicalCheckOutcome.Passed, [passed, failed], BlankScreenOutcome.Returned));
        Assert.Equal(PhysicalCheckOutcome.Failed, DisplayColorCheck.Effective(PhysicalCheckOutcome.PassedWithNote, [passed], BlankScreenOutcome.DidNotReturn));
        Assert.Equal(PhysicalCheckOutcome.PassedWithNote, DisplayColorCheck.Effective(PhysicalCheckOutcome.PassedWithNote, [passed], BlankScreenOutcome.NotSupported));
        Assert.Equal(PhysicalCheckOutcome.NotRun, DisplayColorCheck.Effective(PhysicalCheckOutcome.NotRun, [failed], BlankScreenOutcome.NotRun));
    }

    [Fact]
    public void Export_hides_the_numbers_until_answered_and_names_each_screen()
    {
        var waiting = new DisplayScreenResult(Dell.Id, Dell.Name, false, 3840, 2160, 6, ShownNumbers: [12, 34, 56]);
        var answered = new DisplayScreenResult(Laptop.Id, Laptop.Name, true, 1920, 1200, 6, [21, 43, 65], DisplayColorCheck.Grade([21, 43, 65], ["21", "", "65"]));
        var bench = new PhysicalBenchQaSnapshot(SolidColorsInspected: 6, DisplayScreens: [answered, waiting], BlankScreen: BlankScreenOutcome.Returned);
        var page = new InteractiveExport.PageState("display", ["display"], false, false, false, false);
        var notRun = new InteractiveExport.ModuleState(new DiagnosticResult("Webcam", DiagnosticStatus.NotRun, "", DateTimeOffset.UnixEpoch), false);

        var json = InteractiveExport.ToJson(page, bench, notRun, notRun, notRun);
        using var doc = JsonDocument.Parse(json);
        var display = doc.RootElement.GetProperty("tests").EnumerateArray().Single(t => t.GetProperty("id").GetString() == "display");
        Assert.Equal("waiting-for-person", display.GetProperty("state").GetString());
        var measured = display.GetProperty("measured");
        Assert.Equal("failed", measured.GetProperty("colorChannels").GetString());
        Assert.Equal("returned", measured.GetProperty("blankScreen").GetString());
        var screens = measured.GetProperty("screens").EnumerateArray().ToList();
        Assert.Equal(2, screens.Count);
        Assert.Equal("Screen 1: Built-in", screens[0].GetProperty("name").GetString());
        Assert.Equal("failed", screens[0].GetProperty("colorCheck").GetString());
        Assert.Equal(["green"], screens[0].GetProperty("failedChannels").EnumerateArray().Select(x => x.GetString()));
        var green = screens[0].GetProperty("answers").EnumerateArray().Single(a => a.GetProperty("channel").GetString() == "green");
        Assert.Equal(43, green.GetProperty("shown").GetInt32());
        Assert.False(green.TryGetProperty("entered", out _));
        Assert.Equal("waiting-for-answers", screens[1].GetProperty("colorCheck").GetString());
        Assert.False(screens[1].TryGetProperty("answers", out _));
        // The numbers on screen while the person types are never in the export.
        Assert.DoesNotContain("12", screens[1].GetRawText());
        Assert.DoesNotContain("56", screens[1].GetRawText());
    }

    [Fact]
    public void Certificate_names_the_failed_channel_and_screen()
    {
        var failed = new DisplayScreenResult(Dell.Id, Dell.Name, Answers: DisplayColorCheck.Grade([12, 34, 56], ["", "34", "56"]));
        var passed = new DisplayScreenResult(Laptop.Id, Laptop.Name, true, Answers: DisplayColorCheck.Grade([12, 34, 56], ["12", "34", "56"]));
        var qa = new PhysicalBenchQaSnapshot(DisplayOutcome: PhysicalCheckOutcome.Failed, SolidColorsInspected: 6, DisplayScreens: [passed, failed],
            BlankScreen: BlankScreenOutcome.Returned);
        var item = HardwareQaCertificate.Capture(new ResultStore(), "PC", physicalQa: qa).Items.Single(i => i.Id == "display");
        Assert.Equal(DiagnosticStatus.Error, item.Status);
        Assert.Contains("Red channel failed on Screen 2: DELL U2720Q", item.Summary);
        Assert.Contains("Color channels OK on 1 screen", item.Summary);
        Assert.Contains("Picture came back after screen off", item.Summary);
    }

    // ---- The pane and overlay ----

    private sealed class FakeScreens(params ScreenInfo[] screens) : IScreenControl
    {
        public string? BlankResult { get; set; }
        public int Blanks { get; private set; }
        public IReadOnlyList<ScreenInfo> ListScreens() => screens;
        public Task<string?> BlankScreensAsync(TimeSpan off, CancellationToken ct = default) { Blanks++; return Task.FromResult(BlankResult); }
    }

    private sealed class RecordingFullscreen : IFullscreenService
    {
        public List<(bool Enable, string? Screen)> Calls { get; } = [];
        public event Action<bool>? FullscreenChanged;
        public bool IsFullscreen { get; private set; }
        public string? ScreenId { get; private set; }
        public void RequestFullscreen(bool enable) => RequestFullscreen(enable, null);
        public void RequestFullscreen(bool enable, string? screenId)
        {
            Calls.Add((enable, screenId));
            IsFullscreen = enable;
            ScreenId = screenId;
            FullscreenChanged?.Invoke(enable);
        }
    }

    private (IRenderedComponent<PhysicalBenchQaCard> Card, PhysicalBenchQaService Qa, RecordingFullscreen Full) RenderCard(FakeScreens screens)
    {
        JSInterop.Mode = JSRuntimeMode.Loose;
        var qa = new PhysicalBenchQaService();
        var full = new RecordingFullscreen();
        Services.AddSingleton(new AppServices(PhysicalQa: qa, Fullscreen: full, Screens: screens));
        var card = Render<PhysicalBenchQaCard>(p => p
            .Add(c => c.Service, qa)
            .Add(c => c.FilterSection, "display")
            .Add(c => c.CardShell, false));
        return (card, qa, full);
    }

    /// <summary>Steps through every pattern on the current screen, then types the numbers (wrong for <paramref name="wrong"/>).</summary>
    private static void PassScreen(IRenderedComponent<PhysicalBenchQaCard> card, string? wrong = null)
    {
        card.Find("[data-testid='display-overlay-numbers']").Click();
        Assert.Equal("numbers", card.Find("[data-testid='display-test-overlay']").GetAttribute("data-step"));
        // Read each number by its position, as the person would.
        var numbers = card.FindAll(".display-qa-number").ToList();
        for (var pos = 0; pos < 3; pos++)
        {
            var channel = numbers[pos].GetAttribute("data-testid")!["display-number-".Length..];
            var value = channel == wrong ? "" : numbers[pos].TextContent.Trim();
            card.Find($"[data-testid='display-answer-{pos}']").Input(value);
        }
        card.Find("[data-testid='display-numbers-submit']").Click();
    }

    [Fact]
    public void Launch_runs_on_every_screen_in_turn_then_passes()
    {
        var (card, qa, full) = RenderCard(new FakeScreens(Laptop, Dell));
        Assert.Equal(2, card.FindAll("[data-testid='display-screen-row']").Count);

        card.Find("[data-testid='display-test-launch']").Click();
        Assert.Equal(Laptop.Id, card.Find("[data-testid='display-test-overlay']").GetAttribute("data-screen-id"));
        PassScreen(card);
        Assert.Equal(Dell.Id, card.Find("[data-testid='display-test-overlay']").GetAttribute("data-screen-id"));
        Assert.Equal("patterns", card.Find("[data-testid='display-test-overlay']").GetAttribute("data-step"));
        PassScreen(card);

        Assert.Empty(card.FindAll("[data-testid='display-test-overlay']"));
        Assert.Equal([(true, Laptop.Id), (true, Dell.Id), (false, null)], full.Calls);
        Assert.Equal(PhysicalCheckOutcome.Passed, qa.Current.DisplayOutcome);
        Assert.All(qa.Current.DisplayScreens!, s => Assert.Equal(ColorCheckState.Passed, s.ColorCheck));
        Assert.All(card.FindAll("[data-testid='display-screen-color']"), c => Assert.Equal("Colors OK", c.TextContent.Trim()));
    }

    [Fact]
    public void A_missing_number_fails_that_channel_and_Pass_cannot_override_it()
    {
        var (card, qa, _) = RenderCard(new FakeScreens(Laptop, Dell));
        card.FindAll("[data-testid='display-screen-test']")[1].Click();
        PassScreen(card, wrong: "blue");

        Assert.Equal(PhysicalCheckOutcome.Failed, qa.Current.DisplayOutcome);
        var dell = Assert.Single(qa.Current.DisplayScreens!);
        Assert.Equal(Dell.Id, dell.ScreenId);
        Assert.Equal([ColorChannel.Blue], dell.FailedChannels);
        Assert.Equal("Blue failed", card.FindAll("[data-testid='display-screen-color']")[1].TextContent.Trim());

        card.Find("[data-testid='display-pass']").Click();
        Assert.Equal(PhysicalCheckOutcome.Failed, qa.Current.DisplayOutcome);

        card.Find("[data-testid='display-reset']").Click();
        Assert.Null(qa.Current.DisplayScreens);
        Assert.Equal(PhysicalCheckOutcome.NotRun, qa.Current.DisplayOutcome);
    }

    [Fact]
    public void Exit_during_the_numbers_leaves_that_screen_not_checked()
    {
        var (card, qa, full) = RenderCard(new FakeScreens(Laptop));
        card.Find("[data-testid='display-test-launch']").Click();
        card.Find("[data-testid='display-overlay-numbers']").Click();
        Assert.Equal(ColorCheckState.WaitingForAnswers, qa.Current.DisplayScreens![0].ColorCheck);
        card.Find("[data-testid='display-overlay-exit']").Click();
        Assert.Equal(ColorCheckState.NotRun, qa.Current.DisplayScreens![0].ColorCheck);
        Assert.Equal(PhysicalCheckOutcome.NotRun, qa.Current.DisplayOutcome);
        Assert.Equal((false, null), full.Calls[^1]);
    }

    [Fact]
    public void Without_a_screen_list_the_test_uses_this_screen()
    {
        var (card, qa, full) = RenderCard(new FakeScreens());
        Assert.Equal("This screen", card.Find(".display-screen-name strong").TextContent.Trim());
        card.Find("[data-testid='display-test-launch']").Click();
        PassScreen(card);
        Assert.Equal((true, null), full.Calls[0]);
        Assert.Equal(PhysicalCheckOutcome.Passed, qa.Current.DisplayOutcome);
    }

    [Fact]
    public void Screen_off_and_on_asks_the_person_and_a_dark_screen_fails_the_test()
    {
        var screens = new FakeScreens(Laptop);
        var (card, qa, _) = RenderCard(screens);
        card.Find("[data-testid='display-pass']").Click();
        Assert.Equal(PhysicalCheckOutcome.Passed, qa.Current.DisplayOutcome);

        card.Find("[data-testid='display-blank-run']").Click();
        Assert.Equal(1, screens.Blanks);
        card.Find("[data-testid='display-blank-no']").Click();
        Assert.Equal(BlankScreenOutcome.DidNotReturn, qa.Current.BlankScreen);
        Assert.Equal(PhysicalCheckOutcome.Failed, qa.Current.DisplayOutcome);
        Assert.Equal("Stayed dark", card.Find("[data-testid='display-blank-status']").TextContent.Trim());
    }

    [Fact]
    public void Screen_off_and_on_that_cannot_run_is_not_supported_with_the_reason()
    {
        var (card, qa, _) = RenderCard(new FakeScreens(Laptop) { BlankResult = "Windows refused to turn the screens off (error 5)." });
        card.Find("[data-testid='display-blank-run']").Click();
        Assert.Equal(BlankScreenOutcome.NotSupported, qa.Current.BlankScreen);
        Assert.Contains("error 5", card.Find("[data-testid='display-blank']").TextContent);
        Assert.Empty(card.FindAll("[data-testid='display-blank-yes']"));
    }
}
