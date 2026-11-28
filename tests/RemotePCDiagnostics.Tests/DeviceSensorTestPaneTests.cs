using Bunit;
using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.DeviceSensors;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.UI;
using RemotePCDiagnostics.UI.Pages;
using RemotePCDiagnostics.UI.Shared;

namespace RemotePCDiagnostics.Tests;

/// <summary>The Sensor test pane on the Interactive tests page.</summary>
public sealed class DeviceSensorTestPaneTests : BunitContext
{
    private sealed class Fixed(DeviceSensorSnapshot s) : IDeviceSensorSource
    {
        public Task<DeviceSensorSnapshot> ReadAsync(CancellationToken ct = default) => Task.FromResult(s);
    }

    private static DeviceSensorSnapshot Snap(double x, double y, double z, double lux) => new([
        new("a", DeviceSensorTypes.Accelerometer3D, "Accelerometer", DeviceSensorStatus.Ready, Reading: new(x, y, z)),
        new("l", DeviceSensorTypes.AmbientLight, "Ambient light sensor", DeviceSensorStatus.Ready, Reading: new(Lux: lux)),
        new("h", DeviceSensorTypes.HingeAngle, null, DeviceSensorStatus.Ready, Reading: new(AngleDegrees: 115)),
    ]);

    [Fact]
    public async Task Shows_the_ball_axes_and_steps_while_tilting_and_start_is_disabled_for_a_remote_viewer()
    {
        var test = new DeviceSensorTestService(new Fixed(Snap(0, 0, -1, 300)), autoPoll: false);
        var cut = Render<DeviceSensorTestPane>(p => p.Add(x => x.Service, test));
        Assert.False(cut.Find("[data-testid=devicesensors-start]").HasAttribute("disabled"));
        await cut.InvokeAsync(() => test.StartAsync());
        await cut.InvokeAsync(() => test.Observe(Snap(0.45, -0.2, -0.9, 300)));
        cut.WaitForAssertion(() => Assert.Equal("tilt", cut.Find("[data-testid=devicesensors-current]").GetAttribute("data-step")));
        Assert.Equal("true", cut.Find("[data-testid=devicesensors-axis-x]").GetAttribute("data-moved"));
        Assert.Equal("false", cut.Find("[data-testid=devicesensors-axis-y]").GetAttribute("data-moved"));
        Assert.Contains("left: 68.9%", cut.Find("[data-testid=devicesensors-ball]").GetAttribute("style"));
        Assert.Equal("active", cut.Find("[data-testid=devicesensors-step-tilt]").GetAttribute("data-state"));
        Assert.Equal("notsupported", cut.Find("[data-testid=devicesensors-step-presence]").GetAttribute("data-state"));
        Assert.Contains("Hinge 115°", cut.Find("[data-testid=devicesensors-other]").TextContent);

        cut.Find("[data-testid=devicesensors-skip]").Click();
        Assert.Equal("light", cut.Find("[data-testid=devicesensors-current]").GetAttribute("data-step"));
        await cut.InvokeAsync(() => test.Observe(Snap(0, 0, -1, 90)));

        var remote = Render<DeviceSensorTestPane>(p => p.Add(x => x.Service, new DeviceSensorTestService(autoPoll: false)).Add(x => x.IsRemoteDisplay, true));
        Assert.True(remote.Find("[data-testid=devicesensors-start]").HasAttribute("disabled"));
    }

    [Fact]
    public void Run_selected_on_a_sensorless_pc_finishes_with_skipped_without_hanging()
    {
        JSInterop.Mode = JSRuntimeMode.Loose;
        var store = new ResultStore();
        var diagnostics = new DiagnosticsService(store, []);
        using var sensorTest = new DeviceSensorTestService(new Fixed(new DeviceSensorSnapshot([])), autoPoll: false);
        Services.AddSingleton(store);
        Services.AddSingleton(diagnostics);
        Services.AddSingleton(new ChecksScreenState(diagnostics, store));
        Services.AddSingleton<ISessionContext>(new SessionContext(SessionMode.Local));
        Services.AddSingleton(new AppServices(SensorTest: sensorTest));

        var page = Render<InteractiveTestsPage>();
        page.Find("[data-testid=interactive-select-all]").Click();
        page.Find("[data-testid=interactive-check-devicesensors]").Click();
        page.Find("[data-testid=interactive-run-selected]").Click();

        page.WaitForAssertion(() =>
        {
            Assert.Equal(SensorTestVerdict.Skipped, sensorTest.Current.Verdict);
            Assert.Equal("Skipped", page.Find("[data-testid=interactive-status-devicesensors]").TextContent.Trim());
            Assert.NotNull(page.Find("[data-testid=interactive-run-selected]"));
        });
    }
}
