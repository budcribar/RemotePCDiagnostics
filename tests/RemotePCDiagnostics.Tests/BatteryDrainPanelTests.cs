using System.Text.Json;
using Bunit;
using Microsoft.AspNetCore.Components;
using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core.Battery;
using RemotePCDiagnostics.UI.Shared;
using static RemotePCDiagnostics.Tests.BatteryDrainTests;

namespace RemotePCDiagnostics.Tests;

/// <summary>The battery drain test's pane on the Interactive tests page, its panel, and the batterydrain-data copy Admin's run_battery_drain_test reads.</summary>
public sealed class BatteryDrainPanelTests : BunitContext
{
    private static JsonElement Data(IRenderedComponent<BatteryDrainPanel> cut) =>
        JsonDocument.Parse(cut.Find("[data-testid=batterydrain-data]").GetAttribute("data-report")!).RootElement;

    [Fact]
    public void Before_a_run_it_shows_the_choices_and_the_battery_now()
    {
        var (module, _, _, _) = Make(new FakeBattery());
        var cut = Render<BatteryDrainPanel>(p => p.Add(x => x.Module, module));

        var options = cut.Find("[data-testid=batterydrain-options]");
        Assert.Equal("max", options.GetAttribute("data-mode"));
        Assert.Equal("false", options.GetAttribute("data-confirmed"));
        Assert.Equal("idle", options.GetAttribute("data-state"));
        Assert.Contains("On battery at 100 %", cut.Find("[data-testid=batterydrain-battery]").TextContent);

        var data = Data(cut);
        Assert.Equal(1, data.GetProperty("schema").GetInt32());
        Assert.True(data.GetProperty("batteryRead").GetBoolean());
        Assert.Equal("max", data.GetProperty("mode").GetString());
        Assert.False(data.GetProperty("shutdownConfirmed").GetBoolean());
        Assert.True(data.GetProperty("battery").GetProperty("onBattery").GetBoolean());
        Assert.Equal(JsonValueKind.Null, data.GetProperty("measured").ValueKind);
        Assert.Equal(15, data.GetProperty("confirmByPercent").GetInt32());
    }

    [Fact]
    public void Choosing_balanced_and_confirming_set_the_module_and_the_data_copy()
    {
        var (module, _, _, _) = Make(new FakeBattery());
        var cut = Render<BatteryDrainPanel>(p => p.Add(x => x.Module, module));

        cut.Find("[data-testid=batterydrain-mode-balanced]").Change(true);
        cut.Find("[data-testid=batterydrain-confirm]").Change(true);

        Assert.Equal(BatteryDrainMode.Balanced, module.Mode);
        Assert.True(module.ShutdownConfirmed);
        Assert.Equal("balanced", Data(cut).GetProperty("mode").GetString());
        Assert.True(Data(cut).GetProperty("shutdownConfirmed").GetBoolean());
    }

    [Fact]
    public void While_running_the_mode_is_fixed_but_the_shutdown_can_still_be_confirmed()
    {
        var (module, _, _, _) = Make(new FakeBattery());
        var cut = Render<BatteryDrainPanel>(p => p.Add(x => x.Module, module).Add(x => x.Running, true));

        Assert.True(cut.Find("fieldset.drain-mode").HasAttribute("disabled"));
        Assert.False(cut.Find("[data-testid=batterydrain-confirm]").HasAttribute("disabled"));
    }

    [Fact]
    public void A_run_the_PC_never_finished_is_announced()
    {
        var logs = new MemoryLogStore { Log = new BatteryDrainRunLog { BootUtc = Boot.AddDays(-1), Samples = [new(Boot, 0, false, 37, 1, 2, 3, 4)] } };
        var (module, _, _, _) = Make(new FakeBattery(), logs: logs);
        var cut = Render<BatteryDrainPanel>(p => p.Add(x => x.Module, module));

        Assert.Contains("The PC turned off during the last drain", cut.Find("[data-testid=batterydrain-leftover]").TextContent);
        Assert.Equal("PcShutOff", Data(cut).GetProperty("leftover").GetProperty("end").GetString());
        Assert.Equal(37, Data(cut).GetProperty("leftover").GetProperty("percent").GetInt32());
    }

    [Fact]
    public async Task After_a_run_the_data_copy_has_every_reading_and_the_measure()
    {
        var (module, _, _, _) = Make(new FakeBattery());
        module.ShutdownConfirmed = true;
        await module.RefreshAsync(null);
        var cut = Render<BatteryDrainPanel>(p => p.Add(x => x.Module, module));

        var data = Data(cut);
        Assert.Equal(module.LastSamples!.Count, data.GetProperty("samples").GetArrayLength());
        var measured = data.GetProperty("measured");
        Assert.InRange(measured.GetProperty("deliveredPercent").GetDouble(), 95, 105);
        Assert.Equal(100, measured.GetProperty("startPercent").GetInt32());
    }

    [Fact]
    public void The_Interactive_tests_pane_shows_the_panel_runs_the_drain_and_a_remote_technician_hands_control_to_the_PC_to_start_it()
    {
        JSInterop.Mode = JSRuntimeMode.Loose;
        var store = new RemotePCDiagnostics.Core.ResultStore();
        var (module, agent, _, _) = Make(new FakeBattery());
        var diagnostics = new RemotePCDiagnostics.Core.DiagnosticsService(store, [module]);
        Services.AddSingleton(store);
        Services.AddSingleton(diagnostics);
        Services.AddSingleton(new RemotePCDiagnostics.Core.ChecksScreenState(diagnostics, store));
        Services.AddSingleton<RemotePCDiagnostics.Core.Session.ISessionContext>(new RemotePCDiagnostics.Core.Session.SessionContext(RemotePCDiagnostics.Core.Session.SessionMode.Local));
        Services.AddSingleton(new RemotePCDiagnostics.UI.AppServices(Remediation: new RemotePCDiagnostics.Core.Areas.RemediationService(new RemotePCDiagnostics.Core.Areas.SystemCommandRunner())));
        Services.GetRequiredService<NavigationManager>().NavigateTo("interactive?test=batterydrain");
        var page = Render<RemotePCDiagnostics.UI.Pages.InteractiveTestsPage>();

        page.WaitForAssertion(() => Assert.NotNull(page.Find("[data-testid=batterydrain-options]")));
        Assert.True(page.Find("[data-testid=interactive-check-batterydrain]").HasAttribute("disabled"));
        var data = JsonDocument.Parse(page.Find("[data-testid=interactive-data]").GetAttribute("data-report")!).RootElement;
        var t = data.GetProperty("tests").EnumerateArray().Single(x => x.GetProperty("id").GetString() == "batterydrain");
        Assert.True(t.GetProperty("open").GetBoolean());
        Assert.Equal("waiting-for-person", t.GetProperty("state").GetString());

        page.Find("[data-testid=batterydrain-confirm]").Change(true);
        page.Find("[data-testid=batterydrain-start-btn]").Click();
        page.WaitForAssertion(() => Assert.Equal(RemotePCDiagnostics.Core.DiagnosticStatus.Ok, store.Get(RemotePCDiagnostics.Core.ModuleSlugs.BatteryDrain).Status));
        Assert.Equal("shutdown", agent.Verbs[^1]);
        page.WaitForAssertion(() => Assert.Contains("Run again", page.Find("[data-testid=batterydrain-start-btn]").TextContent));

        page.InvokeAsync(() => page.Instance.OnControlStateChanged(new RemotePCDiagnostics.UI.Pages.InteractiveTestsPage.RemoteControlInfo
        {
            IsRemoteDisplay = true, HasRemoteSession = true, TechnicianHasControl = true,
        }));
        // The technician in control can press Start: control moves to the PC for the test and comes back to them when it ends.
        page.WaitForAssertion(() => Assert.False(page.Find("[data-testid=batterydrain-start-btn]").HasAttribute("disabled")));
        Assert.Contains("person at the PC", page.Find("[data-testid=batterydrain-start-btn]").GetAttribute("title"));
        JSInterop.Setup<string?>("rpdSession.handControlToLocal").SetResult("tech-1");
        page.Find("[data-testid=batterydrain-confirm]").Change(true);
        page.Find("[data-testid=batterydrain-start-btn]").Click();
        page.WaitForAssertion(() => Assert.Contains(JSInterop.Invocations, i => i.Identifier == "rpdSession.handControlToLocal"));
        page.WaitForAssertion(() => Assert.Contains(JSInterop.Invocations, i => i.Identifier == "rpdSession.giveControlTo" && Equals(i.Arguments[0], "tech-1")));
    }
}
