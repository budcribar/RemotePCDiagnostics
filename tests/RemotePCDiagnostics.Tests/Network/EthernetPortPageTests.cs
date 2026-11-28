using System.Net;
using Bunit;
using Microsoft.AspNetCore.Components;
using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.UI;
using RemotePCDiagnostics.UI.Pages;

namespace RemotePCDiagnostics.Tests.Network;

/// <summary>The Ethernet port pane on the Interactive tests page.</summary>
public class EthernetPortPageTests : BunitContext
{
    private sealed class PlugIo : IEthernetPortIo
    {
        private long _in, _out;
        public EthernetLink? Read(string adapter) =>
            new(true, 100_000_000, IPAddress.Parse("169.254.3.4"), IPAddress.Parse("255.255.0.0"), true, false, false, 10 + _in, 10 + _out);
        public int SendBroadcasts(IPAddress from, IPAddress mask, int count) { _in += count; _out += count; return count; }
        public bool IsOnlyRoute(string adapter) => true;
    }

    [Fact]
    public void Lists_the_wired_ports_and_runs_the_loopback_test()
    {
        JSInterop.Mode = JSRuntimeMode.Loose;
        var store = new ResultStore();
        var module = new EthernetPortModule(new WmiNicHardwareSource(NicHardwareTests.Wmi(adapters: [NicHardwareTests.Nic(speed: 100_000_000),
            NicHardwareTests.Nic(name: "Wi-Fi", medium: 9)])), new PlugIo(), new NicHardwareTests.StubProbe(), delay: (_, _) => Task.CompletedTask);
        var diagnostics = new DiagnosticsService(store, [module]);
        Services.AddSingleton(store);
        Services.AddSingleton(diagnostics);
        Services.AddSingleton(new ChecksScreenState(diagnostics, store));
        Services.AddSingleton<ISessionContext>(new SessionContext(SessionMode.Local));
        Services.AddSingleton(new AppServices(Remediation: new RemediationService(new SystemCommandRunner())));
        Services.GetRequiredService<NavigationManager>().NavigateTo("interactive?test=ethernet");
        var page = Render<InteractiveTestsPage>();

        page.WaitForAssertion(() => Assert.Single(page.FindAll("[data-testid='ethernet-port-select'] option")));
        Assert.Contains("Ethernet · Intel(R) Ethernet Connection", page.Find("[data-testid='ethernet-port-select'] option").TextContent);
        Assert.NotNull(page.Find("[data-testid='ethernet-session-warning']"));
        page.Find("[data-testid='ethernet-mode-select']").Change("loopback");
        page.Find("[data-testid='ethernet-start-btn']").Click();

        page.WaitForAssertion(() => Assert.Equal(DiagnosticStatus.Ok, store.Get(ModuleSlugs.EthernetPort).Status));
        page.WaitForAssertion(() => Assert.Contains("100 sent, 100 counted out, 100 counted back in", page.Find("[data-testid='ethernet-frames']").TextContent));
        Assert.StartsWith("Loopback passed on Ethernet at 100 Mbps", page.Find("[data-testid='ethernet-status']").TextContent.Trim());
        File.WriteAllText(Path.Combine(Path.GetTempPath(), "ethernet-loopback.html"), page.Markup);
    }
}
