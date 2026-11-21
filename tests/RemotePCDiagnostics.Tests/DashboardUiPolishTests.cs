using Bunit;
using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core;
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
        var diagnostics = new DiagnosticsService(store, modules);
        Services.AddSingleton(store);
        Services.AddSingleton(diagnostics);
        Services.AddSingleton(new ChecksScreenState(diagnostics, store));
        Services.AddSingleton<ISessionContext>(new SessionContext(SessionMode.Local));
    }

    [Fact]
    public void Dashboard_DriveHealthNotRun_ShowsNotRunPillWithoutRedundantNotCheckedYet()
    {
        var store = new ResultStore();
        var driveMod = new FakeModule(ModuleSlugs.DriveHealth, _ => Task.FromResult(FakeModule.Ok(ModuleSlugs.DriveHealth)));
        RegisterDashboardServices(store, driveMod);

        var cut = Render<Dashboard>();

        var card = cut.Find("[data-testid='dashboard-card-drivehealth']");
        Assert.Equal("Not run", card.QuerySelector(".chip")?.TextContent.Trim());
        Assert.DoesNotContain("Not checked yet", card.TextContent, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Not run yet", card.TextContent, StringComparison.OrdinalIgnoreCase);

        var subtitle = cut.Find("[data-testid='dashboard-last-checked']").TextContent;
        Assert.Equal("Live readings only, checks not run", subtitle);
        Assert.DoesNotContain("not run yet", subtitle, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Dashboard_SensorsCard_OmitsUnreadGpuAndUnreportedFanSpeed()
    {
        var store = new ResultStore();
        var snap = new SensorSnapshot([
            new("Snapdragon X Elite", HardwareKind.Cpu, "CPU Package", SensorKind.Temperature, 65, 55, 70, "°C"),
            new("NVMe Drive", HardwareKind.Storage, "Composite Temperature", SensorKind.Temperature, 42, 38, 45, "°C"),
        ], IsElevated: true);
        var report = LibreHardwareMonitorModule.BuildReport(snap);
        var msg = LibreHardwareMonitorModule.Summarize(report);
        store.Set(new DiagnosticResult<SensorReport>(LibreHardwareMonitorModule.ModuleName, DiagnosticStatus.Ok, msg, DateTimeOffset.Now, report));
        RegisterDashboardServices(store);

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

    private static string RepoRoot()
    {
        for (var d = new DirectoryInfo(AppContext.BaseDirectory); d is not null; d = d.Parent)
            if (File.Exists(Path.Combine(d.FullName, "RemotePCDiagnostics.sln"))) return d.FullName;
        throw new InvalidOperationException("Repository root (RemotePCDiagnostics.sln) not found.");
    }
}
