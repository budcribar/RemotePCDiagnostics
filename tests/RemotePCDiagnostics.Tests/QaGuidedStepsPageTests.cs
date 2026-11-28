using Bunit;
using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Workflow;
using RemotePCDiagnostics.UI;
using RemotePCDiagnostics.UI.Pages;

namespace RemotePCDiagnostics.Tests;

/// <summary>QA page: a guided step done on the Interactive tests page shows an Open link and Skip while the run waits on it.</summary>
public class QaGuidedStepsPageTests : BunitContext
{
    private sealed class OnDemand(string name) : IDiagnosticModule
    {
        public string Name => name;
        public Guid Id => TestIds.For(name);
        public bool IncludeInRunAll => false;
        public event EventHandler<DiagnosticResult>? Updated { add { } remove { } }
        public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct = default) => Task.FromResult(ModuleAvailability.Available);
        public Task<DiagnosticResult> RefreshAsync(IProgress<string>? progress, CancellationToken ct = default) => Task.FromResult(FakeModule.Ok(name));
    }

    [Fact]
    public async Task Waiting_on_the_USB_port_check_links_to_it_and_Skip_moves_on()
    {
        JSInterop.Mode = JSRuntimeMode.Loose;
        var store = new ResultStore();
        var diag = new DiagnosticsService(store, [new OnDemand(ModuleSlugs.UsbPortCheck)]);
        var runner = new BenchQaRunner(diag, store);
        Services.AddSingleton(store);
        Services.AddSingleton(diag);
        Services.AddSingleton<ISessionContext>(new SessionContext(SessionMode.Local));
        Services.AddSingleton(new AppServices(BenchQa: runner));

        var run = runner.StartBenchQaAsync(["usb-port"]);
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (runner.WaitingFor != "usb-port")
        {
            if (DateTime.UtcNow > deadline) throw new TimeoutException();
            await Task.Delay(10);
        }

        var cut = Render<BrandingCertificatePage>();
        cut.WaitForAssertion(() => Assert.Equal("usb-port", cut.Find("[data-testid='qa-guided']").GetAttribute("data-step")));
        Assert.Equal("interactive?test=usbports", cut.Find("[data-testid='qa-guided-open']").GetAttribute("href"));
        Assert.Contains("USB port check", cut.Find("[data-testid='qa-guided-title']").TextContent);
        Assert.Contains("Waiting on the USB port check", cut.Find("[data-testid='qa-live-verdict']").TextContent);
        if (Environment.GetEnvironmentVariable("RPCD_DUMP_QA_MARKUP") is { Length: > 0 } dump) File.WriteAllText(dump, cut.Markup);

        await cut.Find("[data-testid='qa-guided-skip']").ClickAsync(new());
        await run.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.False(runner.IsRunning);
        cut.WaitForAssertion(() => Assert.Empty(cut.FindAll("[data-testid='qa-guided']")));
    }
}
