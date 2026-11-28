using Bunit;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Workflow;
using RemotePCDiagnostics.UI.Shared;

namespace RemotePCDiagnostics.Tests;

/// <summary>The shared results card and badge: every test and check shows pass / warn / fail with the same words, colours and layout.</summary>
public sealed class ResultCardTests : BunitContext
{
    private static DiagnosticResult Result(DiagnosticStatus s, string message = "fine") => new("Test", s, message, DateTimeOffset.Now);

    [Theory]
    [InlineData(DiagnosticStatus.Ok, "Passed", "chip-ok")]
    [InlineData(DiagnosticStatus.Warning, "Warning", "chip-warn")]
    [InlineData(DiagnosticStatus.Error, "Critical", "chip-err")]
    [InlineData(DiagnosticStatus.Running, "Running…", "chip-run")]
    [InlineData(DiagnosticStatus.NotRun, "Not run", "chip-na")]
    public void Badge_ForAStatus_SaysWhatTheChecksListSays(DiagnosticStatus status, string text, string chip)
    {
        var cut = Render<ResultBadge>(p => p.Add(c => c.Status, status).Add(c => c.TestId, "b"));

        var badge = cut.Find("[data-testid='b']");
        Assert.Equal(text, badge.TextContent);
        Assert.Contains("chip", badge.ClassList);
        Assert.Contains(chip, badge.ClassList);
    }

    [Fact]
    public void Badge_TakesThePagesOwnWordsAndColour()
    {
        var cut = Render<ResultBadge>(p => p.Add(c => c.Status, DiagnosticStatus.Ok).Add(c => c.Text, "Not applicable").Add(c => c.Kind, "na"));

        var badge = cut.Find(".chip");
        Assert.Equal("Not applicable", badge.TextContent);
        Assert.Contains("chip-na", badge.ClassList);
    }

    [Fact]
    public void Badge_ForAStressRun_NamesTheRunMode()
    {
        var cut = Render<ResultBadge>(p => p.Add(c => c.Row, RowKind.Passed).Add(c => c.RunLabel, "extended run"));

        Assert.Equal("Passed (extended run)", cut.Find(".chip").TextContent);
    }

    [Fact]
    public void Helpers_AreTheOneMappingTheOldChipsNowUse()
    {
        Assert.Equal("ok", ResultBadge.ChipFor(DiagnosticStatus.Ok));
        Assert.Equal("warn", ResultBadge.ChipFor(DiagnosticStatus.Warning));
        Assert.Equal("err", ResultBadge.ChipFor(DiagnosticStatus.Error));
        Assert.Equal("na", ResultBadge.ChipFor(RowKind.Cancelled));
        Assert.Equal("ok", ResultBadge.ChipFor(PhysicalCheckOutcome.Passed));
        Assert.Equal("warn", ResultBadge.ChipFor(PhysicalCheckOutcome.PassedWithNote));
        Assert.Equal("err", ResultBadge.ChipFor(PhysicalCheckOutcome.Failed));
        Assert.Equal("na", ResultBadge.ChipFor(PhysicalCheckOutcome.NotRun));
        Assert.Equal("error", ResultBadge.DotFor(DiagnosticStatus.Error));
        Assert.Equal("neutral", ResultBadge.DotFor(RowKind.Skipped));

        // The dashboard chip keeps its own words but takes its colour from the shared mapping.
        Assert.Equal("err", StatusChip.Kind(DiagnosticStatus.Error));
    }

    [Fact]
    public void Card_ForAWholeResult_ShowsDotBadgeHeadlineAndBody()
    {
        var cut = Render<ResultCard>(p => p
            .Add(c => c.Title, "Battery")
            .Add(c => c.Result, Result(DiagnosticStatus.Warning, "Worn"))
            .Add(c => c.Headline, "71% health")
            .Add(c => c.TestId, "battery-card")
            .AddChildContent("<p class='meta'>Replace soon</p>"));

        var card = cut.Find("[data-testid='battery-card']");
        Assert.Contains("card", card.ClassList);
        Assert.Contains("result-card", card.ClassList);
        Assert.Equal("Battery", card.QuerySelector(".card-head strong")!.TextContent);
        Assert.Contains("dot-warning", card.QuerySelector(".card-head .dot")!.ClassList);
        Assert.Equal("Warning", cut.Find("[data-testid='battery-card-badge']").TextContent);
        Assert.Equal("71% health", card.QuerySelector(".headline")!.TextContent);
        Assert.Equal("Replace soon", card.QuerySelector("p.meta")!.TextContent);
    }

    [Fact]
    public void Card_ForAPartOfAResult_ShowsTheDotOnly()
    {
        var cut = Render<ResultCard>(p => p.Add(c => c.Title, "Microphone level").Add(c => c.Status, DiagnosticStatus.Error).Add(c => c.TestId, "m"));

        Assert.Contains("dot-error", cut.Find(".dot").ClassList);
        Assert.Empty(cut.FindAll(".chip"));
        Assert.Empty(cut.FindAll(".headline"));
    }

    [Fact]
    public void Card_TakesAnExplicitDotClassesAndAttributes()
    {
        var cut = Render<ResultCard>(p => p
            .Add(c => c.Title, "Left")
            .Add(c => c.Dot, "running")
            .Add(c => c.Class, "is-running")
            .Add(c => c.BadgeText, "Listening")
            .Add(c => c.BadgeKind, "run")
            .Add(c => c.BadgeTestId, "left-state")
            .AddUnmatched("aria-label", "Left speaker"));

        var card = cut.Find(".result-card");
        Assert.Contains("is-running", card.ClassList);
        Assert.Equal("Left speaker", card.GetAttribute("aria-label"));
        Assert.Contains("dot-running", cut.Find(".dot").ClassList);
        var badge = cut.Find("[data-testid='left-state']");
        Assert.Equal("Listening", badge.TextContent);
        Assert.Contains("chip-run", badge.ClassList);
    }

    [Fact]
    public void Card_HidesTheBadgeWhenAsked()
    {
        var cut = Render<ResultCard>(p => p.Add(c => c.Title, "Disk").Add(c => c.Result, Result(DiagnosticStatus.Ok)).Add(c => c.Badge, false));

        Assert.Contains("dot-ok", cut.Find(".dot").ClassList);
        Assert.Empty(cut.FindAll(".chip"));
    }
}
