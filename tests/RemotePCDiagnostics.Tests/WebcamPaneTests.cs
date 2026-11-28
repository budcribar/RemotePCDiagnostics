using System.Text.Json;
using Bunit;
using Microsoft.AspNetCore.Components;
using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.Core.Webcam;
using RemotePCDiagnostics.UI;
using RemotePCDiagnostics.UI.Pages;

namespace RemotePCDiagnostics.Tests;

/// <summary>#293 on the Interactive tests page: the camera's own result shows, with formats, controls, the holder and the question.</summary>
public class WebcamPaneTests : BunitContext
{
    private const int W = 32, H = 18;

    private static byte[] Scene(int seed)
    {
        var rnd = new Random(seed);
        var b = new byte[W * H];
        for (var i = 0; i < b.Length; i++) b[i] = (byte)Math.Clamp(100 + i % W * 80 / W + rnd.Next(-4, 5), 0, 255);
        return b;
    }

    private sealed class Io(Func<WebcamCaptureRequest, Task<WebcamCaptureResult>> capture) : IWebcamIo
    {
        public IReadOnlyList<WebcamDevice> ListDevices() =>
            [new("cam1", "HP Wide Vision FHD Camera", WebcamBus.BuiltIn), new(WebcamDevice.InfraredPrefix + "g1", "HP IR Camera", WebcamBus.BuiltIn, WebcamKind.Infrared)];
        public bool IsCameraBlockedByPrivacy() => false;
        public Task<WebcamCaptureResult> CaptureAsync(WebcamCaptureRequest r, CancellationToken ct) => capture(r);
    }

    private static Task<WebcamCaptureResult> Vga(WebcamCaptureRequest r)
    {
        for (var i = 0; i < 90; i++) r.OnFrame(new WebcamFrame(W, H, Scene(i), TimeSpan.FromSeconds(i / 30.0)));
        return Task.FromResult(new WebcamCaptureResult(640, 480, 30, "YUY2")
        {
            Formats = [new(640, 480, 30, "YUY2"), new(320, 240, 30, "YUY2")],
            Controls = [new("Focus", true, 0, 250, 5, 30, true, true), new("Exposure", true, -11, -2, 1, null, true, null, ReadFailed: true), new("Pan", false, 0, 0, 0, null, false, null)],
        });
    }

    private sealed class Registry : IRegistrySource
    {
        public Task<WmiQueryResult> ReadAsync(RegistryRead read, CancellationToken ct = default) =>
            Task.FromResult(new WmiQueryResult(read.Location, read.Describe(), read.Path.EndsWith("NonPackaged", StringComparison.Ordinal)
                ? [WmiRow.From(new Dictionary<string, object?> { [RegistryRead.KeyColumn] = @"C:#Zoom#Zoom.exe", ["LastUsedTimeStart"] = 9L, ["LastUsedTimeStop"] = 0L })]
                : []));
    }

    private (ResultStore Store, IRenderedComponent<InteractiveTestsPage> Page) Render(IWebcamIo io, bool agent = true)
    {
        JSInterop.Mode = JSRuntimeMode.Loose;
        var store = new ResultStore();
        var diagnostics = new DiagnosticsService(store, [new WebcamTestModule(io, registry: new Registry())]);
        diagnostics.RedetectAsync().GetAwaiter().GetResult();
        Services.AddSingleton(store);
        Services.AddSingleton(diagnostics);
        Services.AddSingleton(new ChecksScreenState(diagnostics, store));
        Services.AddSingleton<ISessionContext>(new SessionContext(SessionMode.Local));
        Services.AddSingleton(new AppServices(Remediation: new RemediationService(new SystemCommandRunner()),
            Elevation: agent ? null : new Bios.E2E.StubElevationContext(false, false)));
        Services.GetRequiredService<NavigationManager>().NavigateTo("interactive?test=webcam");
        return (store, Render<InteractiveTestsPage>());
    }

    /// <summary>
    /// Presses Start test and waits for its handler to finish. The page renders again when the run's task completes, after the result
    /// that shows the report, and that render gives every button a new event handler: a button found before it can't be clicked.
    /// </summary>
    private static Task StartAsync(IRenderedComponent<InteractiveTestsPage> page) =>
        page.Find("[data-testid='webcam-start-btn']").ClickAsync(new());

    private static JsonElement CamExport(IRenderedComponent<InteractiveTestsPage> page)
    {
        var json = page.Find("[data-testid='interactive-data']").GetAttribute("data-report")!;
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.GetProperty("tests").EnumerateArray().Single(t => t.GetProperty("id").GetString() == "webcam").Clone();
    }

    [Fact]
    public async Task A_camera_run_shows_its_own_result_with_formats_controls_and_the_question()
    {
        var (store, page) = Render(new Io(Vga));
        await StartAsync(page);
        page.WaitForAssertion(() => Assert.NotNull(page.Find("[data-testid='webcam-table']")));

        // The run was per camera (the module's own result only lists cameras): the pane still shows the camera's report.
        Assert.IsType<InstanceResults>(store.Get(ModuleSlugs.Webcam).Payload);
        Assert.Equal("true", page.Find("[data-testid='webcam-class']").GetAttribute("data-below"));
        Assert.Contains("640×480", page.Find("[data-testid='webcam-status']").TextContent);
        Assert.Equal(["ok", "unreadable", "unsupported"], page.FindAll("[data-testid='webcam-control']").Select(r => r.GetAttribute("data-state")));
        Assert.Empty(page.FindAll("[data-testid='webcam-holders']"));
        Assert.Equal("FewerFormats", CamExport(page).GetProperty("measured").GetProperty("verdict").GetString());

        page.Find("[data-testid='webcam-sees-no']").Click();
        page.WaitForAssertion(() => Assert.Equal("true", page.Find("[data-testid='webcam-sees-no']").GetAttribute("data-selected")));
        var own = store.InstancesOf(ModuleSlugs.Webcam).Single();
        Assert.Equal(DiagnosticStatus.Error, own.Status);
        Assert.Equal(WebcamVerdict.FewerFormats, Assert.IsType<WebcamReport>(own.Payload).Verdict);
        Assert.False(CamExport(page).GetProperty("personSawPicture").GetBoolean());

        // Pass camera keeps the person's verdict; a later answer is added to the report without changing it.
        page.Find("[data-testid='webcam-pass']").Click();
        page.Find("[data-testid='webcam-sees-yes']").Click();
        page.WaitForAssertion(() => Assert.True(CamExport(page).GetProperty("personSawPicture").GetBoolean()));
        Assert.Equal("passed", CamExport(page).GetProperty("personOutcome").GetString());
        Assert.Equal(DiagnosticStatus.Ok, store.Get(ModuleSlugs.Webcam).Status);
    }

    [Fact]
    public async Task Answering_no_on_an_instance_result_updates_the_module_summary_and_raises_Changed()
    {
        var (store, page) = Render(new Io(Vga));
        await StartAsync(page);
        page.WaitForAssertion(() => Assert.NotNull(page.Find("[data-testid='webcam-table']")));
        Assert.Equal(DiagnosticStatus.Warning, store.Get(ModuleSlugs.Webcam).Status);

        DiagnosticResult? changed = null;
        store.Changed += (_, r) => changed = r;

        page.Find("[data-testid='webcam-sees-no']").Click();
        page.WaitForAssertion(() => Assert.Equal("true", page.Find("[data-testid='webcam-sees-no']").GetAttribute("data-selected")));

        Assert.NotNull(changed);
        Assert.Equal(ModuleSlugs.Webcam, changed.ModuleName);
        Assert.Equal(DiagnosticStatus.Error, changed.Status);
        var module = store.Get(ModuleSlugs.Webcam);
        Assert.Equal(DiagnosticStatus.Error, module.Status);
        var instances = Assert.IsType<InstanceResults>(module.Payload);
        var own = Assert.Single(instances.Results);
        Assert.Equal(DiagnosticStatus.Error, own.Status);
        Assert.False(Assert.IsType<WebcamReport>(own.Payload).PersonSawPicture);
    }

    [Fact]
    public async Task A_busy_camera_names_the_app_and_offers_Close_or_says_it_needs_the_Agent()
    {
        var (_, page) = Render(new Io(_ => throw new WebcamBusyException("in use")));
        await StartAsync(page);
        page.WaitForAssertion(() => Assert.NotNull(page.Find("[data-testid='webcam-holders']")));
        Assert.Equal("Zoom", page.Find("[data-testid='webcam-close-holder']").GetAttribute("data-process"));
        Assert.Contains("Zoom.exe", page.Find("[data-testid='webcam-status']").TextContent);
        Assert.Empty(page.FindAll("[data-testid='webcam-question']")); // no picture, no question
        var holder = CamExport(page).GetProperty("measured").GetProperty("holders")[0];
        Assert.True(holder.GetProperty("canClose").GetBoolean());

        page.Find("[data-testid='webcam-close-holder']").Click();
        page.WaitForAssertion(() => Assert.Equal("EndProcessGroup", page.Find("[data-testid='remediation-confirm']").GetAttribute("data-action-kind")));
        Assert.Equal("Zoom", page.Find("[data-testid='remediation-confirm']").GetAttribute("data-action-target"));
    }

    [Fact]
    public async Task Without_the_Agent_the_holder_is_named_but_Close_is_marked_as_needing_it()
    {
        var (_, page) = Render(new Io(_ => throw new WebcamBusyException("in use")), agent: false);
        await StartAsync(page);
        page.WaitForAssertion(() => Assert.NotNull(page.Find("[data-testid='webcam-close-needs-agent']")));
        Assert.Empty(page.FindAll("[data-testid='webcam-close-holder']"));
    }

    [Fact]
    public void The_IR_camera_is_listed_as_its_own_camera()
    {
        var (_, page) = Render(new Io(Vga));
        var options = page.FindAll("[data-testid='webcam-device-select'] option").Select(o => o.TextContent.Trim()).ToList();
        Assert.Equal(["HP Wide Vision FHD Camera (built-in)", "HP IR Camera (IR, built-in)"], options);
    }

    [Fact]
    public async Task An_IR_camera_hides_the_Do_you_see_yourself_question()
    {
        var (store, page) = Render(new Io(Vga));
        page.Find("[data-testid='webcam-device-select']").Change(WebcamDevice.InfraredPrefix + "g1");
        await StartAsync(page);
        page.WaitForAssertion(() => Assert.NotNull(page.Find("[data-testid='webcam-table']")));

        var own = store.InstancesOf(ModuleSlugs.Webcam).Single();
        Assert.Equal(WebcamKind.Infrared, Assert.IsType<WebcamReport>(own.Payload).Kind);
        Assert.Empty(page.FindAll("[data-testid='webcam-question']"));
    }
}
