using Bunit;
using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Agent.Core;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Benchmarks;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.UI;
using RemotePCDiagnostics.UI.Shared;

namespace RemotePCDiagnostics.Tests;

public class AppUpdateDialogTests : BunitContext
{
    private const string Installed = "1.2.0-ci.1931.1+59c17afac50e45a7af86f84db3e5cd7b00dc8059";

    [Fact]
    public void Versions_drop_the_commit_hash()
    {
        Assert.Equal("1.2.0-ci.1931.1", AppVersionComparer.ForDisplay(Installed));
        Assert.Equal("1.2.0-ci.1947.1", AppVersionComparer.ForDisplay("1.2.0-ci.1947.1"));
        Assert.Equal("1.2.0", AppVersionComparer.ForDisplay("v1.2.0"));
        Assert.Equal("unknown", AppVersionComparer.ForDisplay("unknown"));
        Assert.Null(AppVersionComparer.ForDisplay(null));
    }

    [Fact]
    public void Dialog_shows_short_versions_and_only_the_link_and_button_while_installing()
    {
        var install = new TaskCompletionSource<AppUpdateResult>();
        var updater = new FakeUpdater(new AppUpdateInfo(true, Installed, "1.2.0-ci.1947.1", AppInstallKind.Standalone,
            ReleaseUrl: "https://github.com/budcribar/RemotePCDiagnostics/releases/tag/prerelease", CanInstallSilently: true), install.Task);
        var cut = RenderLayout(updater);

        Assert.Equal("Update 1.2.0-ci.1947.1", cut.Find("[data-testid='app-update-pill']").TextContent.Trim());
        cut.Find("[data-testid='app-update-pill']").Click();

        Assert.Equal("1.2.0-ci.1931.1", cut.Find("[data-testid='app-update-installed']").TextContent);
        Assert.Equal("1.2.0-ci.1947.1", cut.Find("[data-testid='app-update-available']").TextContent);
        Assert.DoesNotContain("59c17afa", cut.Find("[data-testid='app-update-dialog']").TextContent);
        Assert.Contains("The elevated agent will download", cut.Find("[data-testid='app-update-explainer']").TextContent);

        cut.Find("[data-testid='app-update-install']").Click();

        var dialog = cut.Find("[data-testid='app-update-dialog']");
        Assert.Empty(cut.FindAll("[data-testid='app-update-explainer']"));
        Assert.DoesNotContain("elevated agent", dialog.TextContent);
        Assert.Contains("View release notes on GitHub", dialog.TextContent);
        Assert.Equal("Installing...", cut.Find("[data-testid='app-update-install']").TextContent.Trim());
        Assert.True(cut.Find("[data-testid='app-update-install']").HasAttribute("disabled"));
        Assert.DoesNotContain("Later", dialog.TextContent);

        install.SetResult(new AppUpdateResult(false, Error: "The download failed."));
        cut.WaitForAssertion(() =>
        {
            Assert.Equal("The download failed.", cut.Find("[data-testid='app-update-error']").TextContent);
            Assert.Equal("Install update", cut.Find("[data-testid='app-update-install']").TextContent.Trim());
            Assert.NotEmpty(cut.FindAll("[data-testid='app-update-explainer']"));
        });
    }

    private IRenderedComponent<MainLayout> RenderLayout(IAppUpdateService updater)
    {
        JSInterop.Mode = JSRuntimeMode.Loose;
        ComponentFactories.AddStub<ThemeSwitcher>();
        ComponentFactories.AddStub<NavRail>();
        ComponentFactories.AddStub<AppFaultData>();
        ComponentFactories.AddStub<AppActivityData>();
        ComponentFactories.AddStub<UpdateRpcdAgent>();
        var monitor = new AgentModeMonitor(_ => AgentModeSnapshot.LocalOnly, startLoop: false);
        var session = new SessionContext(SessionMode.Local);
        var app = new AppServices(AppUpdate: updater);
        var bench = new BenchmarkService(new BenchmarkRunner(new NoProbes()),
            new FileBenchmarkStore(Path.Combine(Path.GetTempPath(), "rpd-upd-" + Guid.NewGuid().ToString("N") + ".json")));
        Services.AddSingleton<ISessionContext>(session);
        Services.AddSingleton(app);
        Services.AddSingleton(monitor);
        Services.AddSingleton(new RemoteUsers());
        Services.AddSingleton(new BenchmarkUploader(bench, app, session));
        return Render<MainLayout>();
    }

    private sealed class FakeUpdater(AppUpdateInfo latest, Task<AppUpdateResult> install) : IAppUpdateService
    {
        public AppUpdateInfo? Latest => latest;
        public AppUpdateCheck? LastCheck => null;
        public event Action? Changed { add { } remove { } }
        public Task<AppUpdateInfo> CheckForUpdateAsync(bool force = false, CancellationToken ct = default) => Task.FromResult(latest);
        public Task<AppUpdateResult> InstallUpdateAsync(Action<AppUpdateProgress>? progress = null, CancellationToken ct = default) => install;
    }

    private sealed class NoProbes : IBenchmarkProbes
    {
        public BenchmarkConditions ReadConditions() => throw new NotSupportedException();
        public Task<IdleSample?> SampleIdleAsync(TimeSpan duration, CancellationToken ct) => throw new NotSupportedException();
        public Task<double?> StartProgramAsync(BuiltInProgram program, CancellationToken ct) => throw new NotSupportedException();
        public Task<double?> DiskRandomReadIopsAsync(TimeSpan duration, CancellationToken ct) => throw new NotSupportedException();
        public Task<IReadOnlyList<WinEvent>> ReadBootEventsAsync(CancellationToken ct) => throw new NotSupportedException();
    }
}
