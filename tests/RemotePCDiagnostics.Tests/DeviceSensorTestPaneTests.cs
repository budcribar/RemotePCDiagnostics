using Bunit;
using RemotePCDiagnostics.Core.DeviceSensors;
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
        if (Environment.GetEnvironmentVariable("RPCD_PANE_MARKUP") is { Length: > 0 } dir) File.WriteAllText(Path.Combine(dir, "tilt.html"), cut.Markup);

        cut.Find("[data-testid=devicesensors-skip]").Click();
        Assert.Equal("light", cut.Find("[data-testid=devicesensors-current]").GetAttribute("data-step"));
        await cut.InvokeAsync(() => test.Observe(Snap(0, 0, -1, 90)));
        if (Environment.GetEnvironmentVariable("RPCD_PANE_MARKUP") is { Length: > 0 } dir2) File.WriteAllText(Path.Combine(dir2, "light.html"), cut.Markup);

        var remote = Render<DeviceSensorTestPane>(p => p.Add(x => x.Service, new DeviceSensorTestService(autoPoll: false)).Add(x => x.IsRemoteDisplay, true));
        Assert.True(remote.Find("[data-testid=devicesensors-start]").HasAttribute("disabled"));
    }
}
