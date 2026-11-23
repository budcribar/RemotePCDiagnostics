using Bunit;
using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.UI;
using RemotePCDiagnostics.UI.Pages;
using RemotePCDiagnostics.UI.Shared;

namespace RemotePCDiagnostics.Tests;

public class DashboardUiPolishTests : BunitContext
{
    private void RegisterDashboardServices(ResultStore store, params IDiagnosticModule[] modules)
    {
        JSInterop.Mode = JSRuntimeMode.Loose;
        var diagnostics = new DiagnosticsService(store, modules);
        Services.AddSingleton(store);
        Services.AddSingleton(diagnostics);
        Services.AddSingleton(new ChecksScreenState(diagnostics, store));
        Services.AddSingleton<ISessionContext>(new SessionContext(SessionMode.Local));
        Services.AddSingleton(new AppServices());
    }

    [Fact]
    public void Dashboard_DriveHealthNotRun_ShowsNotRunPillAndSingleRefreshAction()
    {
        var store = new ResultStore();
        var driveMod = new FakeModule(ModuleSlugs.DriveHealth, _ => Task.FromResult(FakeModule.Ok(ModuleSlugs.DriveHealth)));
        RegisterDashboardServices(store, driveMod);

        var cut = Render<Dashboard>();

        var card = cut.Find("[data-testid='dashboard-card-drivehealth']");
        Assert.Equal("Not run", card.QuerySelector(".chip")?.TextContent.Trim());
        Assert.DoesNotContain("Not checked yet", card.TextContent, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Updated ", card.TextContent, StringComparison.OrdinalIgnoreCase);

        // Verdict bar has single Refresh button and no 10-min QA / stress suite clutter.
        Assert.NotNull(cut.Find("[data-testid='dashboard-runall']"));
        Assert.Empty(cut.FindAll("[data-testid='dashboard-bench-qa']"));
        Assert.Empty(cut.FindAll("[data-testid='dashboard-runall-stress-short']"));
    }

    [Fact]
    public void Dashboard_Card_ExpandsInPlace_WithInlineRefreshButton()
    {
        var store = new ResultStore();
        var driveMod = new FakeModule(ModuleSlugs.DriveHealth, _ => Task.FromResult(FakeModule.Ok(ModuleSlugs.DriveHealth)));
        store.Set(new DiagnosticResult(ModuleSlugs.DriveHealth, DiagnosticStatus.Ok, "C: 164 GB free", DateTimeOffset.Now));
        RegisterDashboardServices(store, driveMod);

        var cut = Render<Dashboard>();
        Assert.Empty(cut.FindAll("[data-testid='dashboard-card-details-drivehealth']"));

        cut.Find("[data-testid='dashboard-card-drivehealth'] .dash-card-head").Click();
        Assert.NotNull(cut.Find("[data-testid='dashboard-card-details-drivehealth']"));
        Assert.NotNull(cut.Find("[data-testid='dashboard-card-refresh-drivehealth']"));
    }

    [Fact]
    public void NavRail_ShowsSeparateRedErrorAndYellowWarningBadges()
    {
        var store = new ResultStore();
        var m1 = new FakeModule(ModuleSlugs.DriveHealth, _ => Task.FromResult(FakeModule.Ok(ModuleSlugs.DriveHealth)));
        var m2 = new FakeModule(ModuleSlugs.Crashes, _ => Task.FromResult(FakeModule.Ok(ModuleSlugs.Crashes)));
        var m3 = new FakeModule(ModuleSlugs.EventLog, _ => Task.FromResult(FakeModule.Ok(ModuleSlugs.EventLog)));
        RegisterDashboardServices(store, m1, m2, m3); // registering a module resets its stored result, so register first
        store.Set(new DiagnosticResult(ModuleSlugs.DriveHealth, DiagnosticStatus.Error, "SMART failure", DateTimeOffset.Now));
        store.Set(new DiagnosticResult(ModuleSlugs.Crashes, DiagnosticStatus.Warning, "2 app faults", DateTimeOffset.Now));
        store.Set(new DiagnosticResult(ModuleSlugs.EventLog, DiagnosticStatus.Warning, "4 errors", DateTimeOffset.Now));

        var cut = Render<NavRail>();

        Assert.Equal("1", cut.Find("[data-testid='nav-checks-errors']").TextContent.Trim());
        Assert.Equal("2", cut.Find("[data-testid='nav-checks-warnings']").TextContent.Trim());
    }

    [Fact]
    public void Dashboard_SensorsCard_OmitsUnreadGpuAndUnreportedFanSpeed()
    {
        var store = new ResultStore();
        var sensorMod = new FakeModule(LibreHardwareMonitorModule.ModuleName, _ => Task.FromResult(FakeModule.Ok(LibreHardwareMonitorModule.ModuleName)));
        RegisterDashboardServices(store, sensorMod);
        var snap = new SensorSnapshot([
            new("Snapdragon X Elite", HardwareKind.Cpu, "CPU Package", SensorKind.Temperature, 65, 55, 70, "°C"),
            new("NVMe Drive", HardwareKind.Storage, "Composite Temperature", SensorKind.Temperature, 42, 38, 45, "°C"),
        ], IsElevated: true);
        var report = LibreHardwareMonitorModule.BuildReport(snap);
        var msg = LibreHardwareMonitorModule.Summarize(report);
        store.Set(new DiagnosticResult<SensorReport>(LibreHardwareMonitorModule.ModuleName, DiagnosticStatus.Ok, msg, DateTimeOffset.Now, report));

        var cut = Render<Dashboard>();

        var thermal = cut.Find("[data-testid='dashboard-thermal']");
        var items = thermal.QuerySelectorAll("li").Select(li => li.TextContent.Trim()).ToList();
        Assert.Equal(["CPU 65°C", "Storage 42°C"], items);
        Assert.DoesNotContain("GPU", thermal.TextContent, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("fan speed not reported", thermal.TextContent, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void StatusChip_And_NotRunResult_UseNotRunConsistently()
    {
        Assert.Equal("Not run", StatusChip.Label(DiagnosticStatus.NotRun));
        Assert.Equal("Not run", DiagnosticResult.NotRun("Test").Message);

        var cut = Render<StatusChip>(p => p.Add(c => c.Status, DiagnosticStatus.NotRun));
        Assert.Equal("Not run", cut.Find(".chip").TextContent.Trim());
    }

    [Fact]
    public void AppCss_CardHeadDotRule_DoesNotOffsetDotsInsideStatusPills()
    {
        var root = RepoRoot();
        var css = File.ReadAllText(Path.Combine(root, "src", "RemotePCDiagnostics.UI", "wwwroot", "app.css"));

        // Descendant `.card-head .dot` would leak margin-top: 6px into `.card-head .chip .dot` and knock pill dots off-center.
        Assert.DoesNotContain(".card-head .dot", css);
        Assert.Contains(".card-head > .dot { margin-top: 6px; }", css);
        Assert.Contains(".chip { font-size: 12px; line-height: 1; padding: 5px 9px; }", css);
        Assert.Contains(".chip .dot { margin: 0; }", css);
    }

    [Fact]
    public void AppCss_DashCardTitle_OverridesCardHeadStrongMinWidthSoPillsStayInsideCard()
    {
        var root = RepoRoot();
        var css = File.ReadAllText(Path.Combine(root, "src", "RemotePCDiagnostics.UI", "wwwroot", "app.css"));

        // .card-head strong (specificity 0,1,1) sets min-width: min(9em, 100%).
        // .dash-card-head .dash-card-title (specificity 0,2,0) must override min-width: 0 so right-side status pills never overflow the card boundary.
        Assert.Contains(".dash-card-head .dash-card-title { flex: 1 1 0; min-width: 0;", css);
    }

    [Fact]
    public void ThemeSwitcher_UpdatesActiveButtonAndTriggersThumbSync()
    {
        Services.AddSingleton(new AppServices());
        JSInterop.Mode = JSRuntimeMode.Loose;

        var cut = Render<ThemeSwitcher>();
        Assert.Contains("on", cut.Find("[data-testid='theme-system']").GetAttribute("class") ?? "");

        cut.Find("[data-testid='theme-light']").Click();
        Assert.Contains("on", cut.Find("[data-testid='theme-light']").GetAttribute("class") ?? "");
        Assert.DoesNotContain("on", cut.Find("[data-testid='theme-system']").GetAttribute("class") ?? "");
        Assert.Contains(JSInterop.Invocations, i => i.Identifier == "rpdTheme.set");
        Assert.Contains(JSInterop.Invocations, i => i.Identifier == "rpdSyncSegmentedControls");

        cut.Find("[data-testid='theme-dark']").Click();
        Assert.Contains("on", cut.Find("[data-testid='theme-dark']").GetAttribute("class") ?? "");
        Assert.DoesNotContain("on", cut.Find("[data-testid='theme-light']").GetAttribute("class") ?? "");
    }

    [Fact]
    public void DialogsJs_ObservesSegmentedButtonClassChangesWithoutGlobalAttributeObserver()
    {
        var root = RepoRoot();
        var js = File.ReadAllText(Path.Combine(root, "src", "RemotePCDiagnostics.UI", "wwwroot", "dialogs.js"));

        Assert.Contains("m.target.tagName === 'BUTTON'", js);
        Assert.Contains("attributeFilter: ['class', 'aria-checked', 'aria-pressed']", js);
        Assert.Contains("window.rpdSyncSegmentedControls = syncSegmentedControls;", js);
        // Global document.body observer must stay free of attributes: true so Blazor renders never loop.
        Assert.Contains(".observe(document.body, { childList: true, subtree: true, characterData: true });", js);
    }

    [Fact]
    public void NavRail_InvokesOnNavigate_And_MobileNavHidesControlBar()
    {
        var store = new ResultStore();
        RegisterDashboardServices(store);
        var navigated = 0;

        var cut = Render<NavRail>(p => p.Add(c => c.OnNavigate, () => { navigated++; }));
        cut.Find("#main-navigation").Click();
        Assert.Equal(1, navigated);

        var root = RepoRoot();
        var css = File.ReadAllText(Path.Combine(root, "src", "RemotePCDiagnostics.UI", "wwwroot", "app.css"));
        Assert.Contains("body:has(.app.nav-open) .rbwv-control-bar", css);
    }

    [Fact]
    public void HostIndexAndDialogs_SetRpcdFaviconAndComputerNameTabTitle()
    {
        var root = RepoRoot();
        var indexHtml = File.ReadAllText(Path.Combine(root, "src", "RemotePCDiagnostics.Host", "wwwroot", "index.html"));
        var svg = File.ReadAllText(Path.Combine(root, "src", "RemotePCDiagnostics.Host", "Assets", "diagnostics-icon.svg")).Trim();
        var expectedSvgHref = "data:image/svg+xml," + Uri.EscapeDataString(svg);

        Assert.Contains($"<link rel=\"icon\" type=\"image/svg+xml\" href=\"{expectedSvgHref}\" />", indexHtml);
        Assert.Contains("<link rel=\"alternate icon\" type=\"image/png\" sizes=\"32x32\" href=\"data:image/png;base64,", indexHtml);
        Assert.Contains("new URLSearchParams(window.location.search).get('pc')", indexHtml);

        var mainLayout = File.ReadAllText(Path.Combine(root, "src", "RemotePCDiagnostics.UI", "Shared", "MainLayout.razor"));
        Assert.Contains("data-rpcd-machine=\"@Session.MachineName\"", mainLayout);

        var dialogsJs = File.ReadAllText(Path.Combine(root, "src", "RemotePCDiagnostics.UI", "wwwroot", "dialogs.js"));
        Assert.Contains("function updateDocumentTitle()", dialogsJs);
        Assert.Contains("document.querySelector('.app[data-rpcd-machine]')", dialogsJs);
        Assert.Contains("document.title = machine;", dialogsJs);
    }

    [Fact]
    public void Dashboard_NeedsAttention_StartsCollapsed_AndExpandsAndCollapses()
    {
        var store = new ResultStore();
        var crashes = new FakeModule(ModuleSlugs.Crashes, _ => Task.FromResult(FakeModule.Ok(ModuleSlugs.Crashes)));
        var eventLog = new FakeModule(ModuleSlugs.EventLog, _ => Task.FromResult(FakeModule.Ok(ModuleSlugs.EventLog)));
        RegisterDashboardServices(store, crashes, eventLog);
        store.Set(new DiagnosticResult(ModuleSlugs.Crashes, DiagnosticStatus.Warning, "1 unexpected restart", DateTimeOffset.Now));
        store.Set(new DiagnosticResult(ModuleSlugs.EventLog, DiagnosticStatus.Warning, "128 Windows errors", DateTimeOffset.Now));

        var cut = Render<Dashboard>();

        var details = cut.Find("details[data-testid='dashboard-triage']");
        var toggle = cut.Find("[data-testid='dashboard-triage-toggle']");
        Assert.False(details.HasAttribute("open"));
        Assert.Equal("false", toggle.GetAttribute("aria-expanded"));
        Assert.Contains("Needs attention · 2", toggle.TextContent);

        toggle.Click();
        details = cut.Find("details[data-testid='dashboard-triage']");
        toggle = cut.Find("[data-testid='dashboard-triage-toggle']");
        Assert.True(details.HasAttribute("open"));
        Assert.Equal("true", toggle.GetAttribute("aria-expanded"));
        Assert.NotNull(cut.Find("[data-testid='dashboard-triage-crashes']"));
        Assert.NotNull(cut.Find("[data-testid='dashboard-triage-eventlog']"));

        toggle.Click();
        details = cut.Find("details[data-testid='dashboard-triage']");
        toggle = cut.Find("[data-testid='dashboard-triage-toggle']");
        Assert.False(details.HasAttribute("open"));
        Assert.Equal("false", toggle.GetAttribute("aria-expanded"));
    }

    [Fact]
    public void AppCss_DashCardDetails_HidesRedundantToolbarAndStatusLine()
    {
        var root = RepoRoot();
        var css = File.ReadAllText(Path.Combine(root, "src", "RemotePCDiagnostics.UI", "wwwroot", "app.css"));

        Assert.Contains(".dash-card-details .toolbar > h1, .dash-card-details .toolbar > .page-icon { display: none; }", css);
        Assert.Contains(".dash-card-details > .toolbar:not(:has(button, select, input, label)), .dash-card-details > .status-line { display: none; }", css);
    }

    [Fact]
    public void AreaPage_Cards_ExpandAndCollapseInline_WithoutClickForDetails()
    {
        var store = new ResultStore();
        var biosMod = new FakeModule(ModuleSlugs.BiosFirmware, _ => Task.FromResult(FakeModule.Ok(ModuleSlugs.BiosFirmware)));
        RegisterDashboardServices(store, biosMod);
        var report = new AreaReport(
        [
            new AreaCard("update", "BIOS update status", AreaLevel.Warning, "BIOS update check failed", "Catalog error",
                ["Detail", "Value"], [new AreaRow(AreaLevel.Warning, ["Status", "Catalog error"])]),
            new AreaCard("current", "Current BIOS / UEFI", AreaLevel.Ok, "F.34", "Insyde",
                ["Detail", "Value"], [new AreaRow(AreaLevel.Ok, ["Version", "F.34"])]),
        ], "BIOS F.34 (update check failed)", DiagnosticStatus.Warning);
        store.Set(new DiagnosticResult<AreaReport>(ModuleSlugs.BiosFirmware, DiagnosticStatus.Warning, report.Summary, DateTimeOffset.Now, report));

        var cut = Render<AreaPage>(p => p.Add(c => c.Slug, ModuleSlugs.BiosFirmware));

        Assert.DoesNotContain("Click for details", cut.Markup, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(cut.FindAll("[data-testid='area-drawer-update']"));
        Assert.Empty(cut.FindAll("[data-testid='area-drawer-current']"));

        cut.Find("[data-testid='osquery-card-update'] .card-summary-toggle").Click();
        var updateCard = cut.Find("[data-testid='osquery-card-update']");
        Assert.Contains("card-expanded", updateCard.GetAttribute("class") ?? "");
        Assert.Equal("true", updateCard.QuerySelector(".card-summary-toggle")?.GetAttribute("aria-expanded"));
        Assert.NotNull(updateCard.QuerySelector("[data-testid='area-drawer-update']"));
        Assert.Contains("Catalog error", updateCard.TextContent);

        cut.Find("[data-testid='osquery-card-current'] .card-summary-toggle").Click();
        Assert.NotNull(cut.Find("[data-testid='osquery-card-update'] [data-testid='area-drawer-update']"));
        Assert.NotNull(cut.Find("[data-testid='osquery-card-current'] [data-testid='area-drawer-current']"));

        cut.Find("[data-testid='osquery-card-update'] .card-summary-toggle").Click();
        Assert.Empty(cut.FindAll("[data-testid='area-drawer-update']"));
        Assert.Equal("false", cut.Find("[data-testid='osquery-card-update'] .card-summary-toggle").GetAttribute("aria-expanded"));
    }

    private static string RepoRoot()
    {
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
            if (File.Exists(Path.Combine(d.FullName, "RemotePCDiagnostics.sln"))) return d.FullName;
        throw new InvalidOperationException("Repository root (RemotePCDiagnostics.sln) not found.");
    }
}
