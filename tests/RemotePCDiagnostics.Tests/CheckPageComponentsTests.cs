using Bunit;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.UI.Shared;

namespace RemotePCDiagnostics.Tests;

/// <summary>The header pieces the check pages share (toolbar, status line, step progress) and SummaryCard's test id.</summary>
public class CheckPageComponentsTests : BunitContext
{
    [Fact]
    public void CheckToolbar_RendersOnlyTheToolbar_SoEmbeddedPagesStillHideIt()
    {
        var cut = Render<CheckToolbar>(p => p
            .Add(c => c.IconName, "hw")
            .Add(c => c.Title, "Hardware inventory")
            .Add(c => c.TitleTestId, "hw-title"));

        // app.css hides `.ct-detail-body > .toolbar` in the Checks pane: the toolbar has to be the component's root element.
        var root = Assert.Single(cut.Nodes.OfType<AngleSharp.Dom.IElement>());
        Assert.Equal("toolbar", root.ClassName);
        Assert.NotNull(root.QuerySelector(".icon-badge.page-icon svg.icon"));
        Assert.Equal("Hardware inventory", cut.Find("h1[data-testid='hw-title']").TextContent);
    }

    [Fact]
    public void CheckToolbar_ExtraClassAndButtons_FollowTheTitle()
    {
        var cut = Render<CheckToolbar>(p => p
            .Add(c => c.IconName, "sec")
            .Add(c => c.Title, "Security audit")
            .Add(c => c.Class, "toolbar-grouped")
            .AddChildContent("<button data-testid=\"go\">Start</button>"));

        Assert.Equal("toolbar toolbar-grouped", cut.Find(".toolbar").ClassName);
        Assert.Null(cut.Find("h1").GetAttribute("data-testid"));
        Assert.NotNull(cut.Find("h1 + button[data-testid='go']"));
    }

    [Fact]
    public void CheckStatusLine_Finished_ShowsMessageAndCheckAgain()
    {
        var cut = Render<CheckStatusLine>(p => p
            .Add(c => c.TestId, "area-status")
            .Add(c => c.Status, DiagnosticStatus.Ok)
            .Add(c => c.Message, "All good · 3 drives")
            .Add(c => c.ActionTestId, "area-requery"));

        var line = cut.Find("p[data-testid='area-status']");
        Assert.Equal("status-line", line.ClassName);
        Assert.NotNull(line.QuerySelector(".dot.dot-ok"));
        Assert.Equal(2, line.QuerySelectorAll(".status-text .card-list-strong li").Length);
        Assert.Equal("Check again", cut.Find("[data-testid='area-requery']").TextContent);
        Assert.Empty(cut.FindAll("[data-testid='running-badge']"));
    }

    [Fact]
    public void CheckStatusLine_Running_ShowsStripeBadgeAndNoButton()
    {
        var cut = Render<CheckStatusLine>(p => p
            .Add(c => c.TestId, "area-status")
            .Add(c => c.Status, DiagnosticStatus.Running)
            .Add(c => c.Message, "Running...")
            .Add(c => c.ActionTestId, "area-requery"));

        var line = cut.Find("p[data-testid='area-status']");
        Assert.Contains("is-running", line.ClassList);
        Assert.Equal("Checking…", line.QuerySelector(".status-text")!.TextContent.Trim());
        Assert.NotNull(line.QuerySelector("[data-testid='running-badge']"));
        Assert.Empty(cut.FindAll("[data-testid='area-requery']"));

        var withStep = Render<CheckStatusLine>(p => p
            .Add(c => c.TestId, "area-status")
            .Add(c => c.Status, DiagnosticStatus.Running)
            .Add(c => c.Message, "Reading drive 2 of 3"));
        Assert.Equal("Reading drive 2 of 3", withStep.Find(".status-text").TextContent.Trim());
    }

    [Fact]
    public void CheckStatusLine_NotRunAndError_UseTheSameWordsAndColours()
    {
        var notRun = Render<CheckStatusLine>(p => p
            .Add(c => c.TestId, "s")
            .Add(c => c.Status, DiagnosticStatus.NotRun)
            .Add(c => c.NotRunText, "Not run.")
            .Add(c => c.ActionTestId, "run"));
        Assert.Equal("Not run.", notRun.Find(".status-text").TextContent.Trim());
        Assert.Equal("Run check", notRun.Find("[data-testid='run']").TextContent);

        var error = Render<CheckStatusLine>(p => p
            .Add(c => c.TestId, "s")
            .Add(c => c.Status, DiagnosticStatus.Error)
            .Add(c => c.Message, "Couldn't read the drives"));
        Assert.Contains("error-text", error.Find(".status-line").ClassList);

        var notRed = Render<CheckStatusLine>(p => p
            .Add(c => c.TestId, "s")
            .Add(c => c.Status, DiagnosticStatus.Error)
            .Add(c => c.Error, false));
        Assert.DoesNotContain("error-text", notRed.Find(".status-line").ClassList);
    }

    [Fact]
    public void CheckStatusLine_PageCanHoldOrDisableTheButton()
    {
        var disabled = Render<CheckStatusLine>(p => p
            .Add(c => c.TestId, "lhm-status")
            .Add(c => c.Status, DiagnosticStatus.Ok)
            .Add(c => c.ActionTestId, "lhm-requery")
            .Add(c => c.ActionDisabled, true));
        Assert.True(disabled.Find("[data-testid='lhm-requery']").HasAttribute("disabled"));

        var clicks = 0;
        var enabled = Render<CheckStatusLine>(p => p
            .Add(c => c.TestId, "lhm-status")
            .Add(c => c.Status, DiagnosticStatus.Ok)
            .Add(c => c.ActionTestId, "lhm-requery")
            .Add(c => c.OnAction, () => { clicks++; }));
        Assert.False(enabled.Find("[data-testid='lhm-requery']").HasAttribute("disabled"));
        enabled.Find("[data-testid='lhm-requery']").Click();
        Assert.Equal(1, clicks);

        var hidden = Render<CheckStatusLine>(p => p
            .Add(c => c.TestId, "lhm-status")
            .Add(c => c.Status, DiagnosticStatus.Ok)
            .Add(c => c.ActionTestId, "lhm-requery")
            .Add(c => c.ShowAction, false));
        Assert.Empty(hidden.FindAll("[data-testid='lhm-requery']"));
    }

    [Fact]
    public void RunProgress_RendersOnlyWithSteps()
    {
        Assert.Empty(Render<RunProgress>(p => p.Add(c => c.TestId, "area-progress").Add(c => c.Progress, (CheckProgress?)null)).FindAll(".progress"));
        Assert.Empty(Render<RunProgress>(p => p.Add(c => c.TestId, "area-progress").Add(c => c.Progress, new CheckProgress(1, 1, ""))).FindAll(".progress"));

        var cut = Render<RunProgress>(p => p.Add(c => c.TestId, "area-progress").Add(c => c.Progress, new CheckProgress(1, 4, "Drive 1")));
        var bar = cut.Find(".progress.run-progress[data-testid='area-progress'] > .progress-bar");
        Assert.Equal("width:25%", bar.GetAttribute("style"));
    }

    [Fact]
    public void SummaryCard_KeepsItsDefaultTestId_AndTakesAPagesOwn()
    {
        var area = Render<SummaryCard>(p => p.Add(c => c.Id, "update").Add(c => c.Title, "Windows Update").Add(c => c.EmptyText, "Nothing found"));
        Assert.NotNull(area.Find("[data-testid='osquery-card-update']"));
        Assert.NotNull(area.Find("[data-testid='osquery-card-update-empty']"));

        var sensors = Render<SummaryCard>(p => p
            .Add(c => c.Id, "cpu")
            .Add(c => c.Title, "Processor")
            .Add(c => c.TestId, "lhm-card-cpu")
            .AddUnmatched("data-sensor-group", "cpu"));
        var card = sensors.Find("[data-testid='lhm-card-cpu']");
        Assert.Equal("cpu", card.GetAttribute("data-sensor-group"));
        Assert.Equal("Processor", card.QuerySelector(".card-head strong")!.GetAttribute("title"));
        Assert.Empty(sensors.FindAll("[data-testid='osquery-card-cpu']"));
    }
}
