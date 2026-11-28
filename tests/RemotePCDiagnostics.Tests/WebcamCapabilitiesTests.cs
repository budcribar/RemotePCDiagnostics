using System.Text.Json;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.DataSources;
using RemotePCDiagnostics.Core.Webcam;
using RemotePCDiagnostics.Core.Workflow;

namespace RemotePCDiagnostics.Tests;

/// <summary>#293: formats against the camera's class, controls, the app holding the camera, the IR camera and the person's answer.</summary>
public class WebcamCapabilitiesTests
{
    private const int W = 32, H = 18;

    private static byte[] Scene(int seed, int baseLevel = 100, int noise = 4, int span = 80)
    {
        var rnd = new Random(seed);
        var b = new byte[W * H];
        for (var y = 0; y < H; y++)
            for (var x = 0; x < W; x++)
                b[y * W + x] = (byte)Math.Clamp(baseLevel + x * span / W + (noise > 0 ? rnd.Next(-noise, noise + 1) : 0), 0, 255);
        return b;
    }

    private static WebcamStats Live(int baseLevel = 100, int span = 80)
    {
        var a = new WebcamAnalyzer(30);
        for (var i = 0; i < 90; i++) a.Add(new WebcamFrame(W, H, Scene(i, baseLevel, span: span), TimeSpan.FromSeconds(i / 30.0)));
        return a.Result(TimeSpan.FromSeconds(3));
    }

    private static readonly WebcamFormat[] Vga = [new(640, 480, 30, "YUY2"), new(320, 240, 30, "YUY2"), new(640, 480, 15, "MJPG")];
    private static readonly WebcamFormat[] FullHd = [new(1920, 1080, 30, "MJPG"), new(1280, 720, 30, "NV12"), new(640, 480, 30, "NV12")];

    private static WebcamControl Ok(string name) => new(name, true, -10, 10, 1, 0, true, true);

    [Theory]
    [InlineData("HP 5MP Camera", 1920)]
    [InlineData("HP Wide Vision FHD Camera", 1920)]
    [InlineData("Integrated Webcam HD", 1280)]
    [InlineData("HD User Facing", 1280)]
    [InlineData("Logitech BRIO 4K Stream Edition", 3840)]
    [InlineData("Full HD webcam", 1920)]
    [InlineData("USB2.0 Camera", null)]
    [InlineData("Integrated Camera", null)]
    [InlineData("HP IR Camera", null)]
    public void The_class_comes_from_whole_words_in_the_name(string name, int? width) =>
        Assert.Equal(width, WebcamCapabilities.ClassOf(name).Width);

    [Fact]
    public void A_1080p_camera_that_only_offers_VGA_warns_about_the_driver()
    {
        var dev = new WebcamDevice("cam", "HP Wide Vision FHD Camera", WebcamBus.BuiltIn);
        var rep = WebcamTestModuleEvaluate(Live(), dev, new WebcamCaptureResult(640, 480, 30, "YUY2") { Formats = Vga });
        Assert.Equal(WebcamVerdict.FewerFormats, rep.Verdict);
        Assert.True(rep.Capability!.BelowClass);
        Assert.Equal((640, 480, 30.0, 3), (rep.Capability.MaxWidth, rep.Capability.MaxHeight, rep.Capability.MaxFps, rep.Capability.FormatCount));
        Assert.Equal(DiagnosticStatus.Warning, WebcamVerdicts.StatusOf(rep));
        var msg = WebcamVerdicts.MessageOf(rep);
        Assert.Contains("640×480", msg);
        Assert.Contains("1080p", msg);
        Assert.Contains("driver", msg);
    }

    [Fact]
    public void A_camera_that_offers_its_class_passes_and_formats_are_listed_largest_first_without_duplicates()
    {
        var dev = new WebcamDevice("cam", "HP 5MP Camera", WebcamBus.BuiltIn);
        var rep = WebcamTestModuleEvaluate(Live(), dev, new WebcamCaptureResult(1280, 720, 30, "NV12")
        {
            Formats = [.. FullHd, new(1920, 1080, 30.0001, "mjpg")],
            Controls = [.. WebcamControls.Names.Select(Ok)],
        });
        Assert.Equal(WebcamVerdict.Pass, rep.Verdict);
        Assert.False(rep.Capability!.BelowClass);
        Assert.Equal(3, rep.Formats.Count);
        Assert.Equal(new WebcamFormat(1920, 1080, 30, "MJPG"), rep.Formats[0]);
        Assert.Equal(DiagnosticStatus.Ok, WebcamVerdicts.StatusOf(rep));
    }

    [Fact]
    public void A_camera_with_no_class_in_its_name_is_never_below_class()
    {
        var rep = WebcamTestModuleEvaluate(Live(), new WebcamDevice("cam", "USB2.0 Camera", WebcamBus.Usb), new WebcamCaptureResult(640, 480, 30, "YUY2") { Formats = Vga });
        Assert.Equal(WebcamVerdict.Pass, rep.Verdict);
        Assert.Null(rep.Capability!.ClassName);
    }

    [Fact]
    public void Controls_the_driver_lists_but_cannot_read_are_a_warning_naming_them()
    {
        var controls = WebcamControls.Names.Select(n => n switch
        {
            "Focus" => new WebcamControl(n, true, 0, 0, 0, null, true, null, ReadFailed: true),
            "Pan" or "Tilt" => new WebcamControl(n, false, 0, 0, 0, null, false, null),
            _ => Ok(n),
        }).ToList();
        var rep = WebcamTestModuleEvaluate(Live(), new WebcamDevice("cam", "Integrated Camera", WebcamBus.BuiltIn),
            new WebcamCaptureResult(1280, 720, 30, "NV12") { Formats = FullHd, Controls = controls });
        Assert.Equal(WebcamVerdict.ControlsUnreadable, rep.Verdict);
        Assert.Contains("focus", WebcamVerdicts.MessageOf(rep));
        Assert.Equal(DiagnosticStatus.Warning, WebcamVerdicts.StatusOf(rep));
    }

    [Fact]
    public void A_picture_problem_wins_over_capability_warnings()
    {
        var dark = WebcamTestModuleEvaluate(Live(baseLevel: 5, span: 40), new WebcamDevice("cam", "FHD Camera", WebcamBus.BuiltIn),
            new WebcamCaptureResult(640, 480, 30, "YUY2") { Formats = Vga });
        Assert.Equal(WebcamVerdict.Dark, dark.Verdict);
        Assert.True(dark.Capability!.BelowClass); // still shown on the page and in the export
    }

    [Fact]
    public void The_IR_camera_is_its_own_entry_and_a_dim_grey_picture_passes()
    {
        var ir = new WebcamDevice(WebcamDevice.InfraredPrefix + "group1", "HP IR Camera", WebcamBus.BuiltIn, WebcamKind.Infrared);
        Assert.True(WebcamDevice.IsInfraredId(ir.Id));
        Assert.Equal("HP IR Camera (IR, built-in)", ir.Label);
        Assert.NotEqual(WebcamTestModule.InstanceOf(new WebcamDevice("group1", "HP IR Camera", WebcamBus.BuiltIn)).Key, WebcamTestModule.InstanceOf(ir).Key);

        var rep = WebcamTestModuleEvaluate(Live(baseLevel: 5, span: 40), ir, new WebcamCaptureResult(340, 340, 30, "L8") { Formats = [new(340, 340, 30, "L8")] });
        Assert.Equal(WebcamVerdict.Pass, rep.Verdict); // dark for a color camera, normal for IR
        Assert.Null(rep.Capability!.ClassName);
        Assert.StartsWith("Passed: the IR camera", WebcamVerdicts.MessageOf(rep));
    }

    [Theory]
    [InlineData(7.4, WebcamVerdict.Pass)]  // strobed Windows Hello camera (VH1): normal for IR
    [InlineData(15, WebcamVerdict.Pass)]
    [InlineData(2, WebcamVerdict.LowFps)]
    public void An_IR_camera_has_its_own_frame_rate_floor(double fps, WebcamVerdict expected)
    {
        var n = (int)Math.Round(fps * 5);
        var a = new WebcamAnalyzer(WebcamTestModule.IrExpectedFps);
        for (var i = 0; i < n; i++) a.Add(new WebcamFrame(W, H, Scene(i), TimeSpan.FromSeconds(i / fps)));
        var s = a.Result(TimeSpan.FromSeconds(5));
        Assert.Equal(expected, WebcamVerdicts.Decide(s, WebcamKind.Infrared));
        // The same rate on a color camera under 10 fps is still low.
        if (fps < WebcamVerdicts.MinFps) Assert.Equal(WebcamVerdict.LowFps, WebcamVerdicts.Decide(s));
        if (expected == WebcamVerdict.LowFps)
        {
            var ir = new WebcamDevice(WebcamDevice.InfraredPrefix + "g", "IR Camera", WebcamBus.BuiltIn, WebcamKind.Infrared);
            var rep = WebcamTestModule.Evaluate(s, ir, new WebcamCaptureResult(340, 340, 15, "L8"), TimeSpan.FromSeconds(5), false);
            Assert.StartsWith("The IR camera works, but its frame rate is very low", WebcamVerdicts.MessageOf(rep));
        }
    }

    [Fact]
    public void The_same_Hello_sensor_in_several_source_groups_is_one_IR_camera()
    {
        static WebcamIrCandidate C(string group, string name, string? sensor, int sources, bool panel, bool color = false) =>
            new(new WebcamDevice(WebcamDevice.InfraredPrefix + group, name, panel ? WebcamBus.BuiltIn : WebcamBus.Unknown, WebcamKind.Infrared), sensor, sources, panel, color);
        var list = WebcamIrSources.Distinct(
        [
            C("combined", "Front Camera", null, 3, false, color: true),       // color + IR sensor group, no device info
            C("hello", "Front IR Camera", @"\\?\USB#IR1", 1, true),
            C("profile", "Front IR Camera", @"\\?\USB#IR1", 2, false),     // same sensor again
            C("usb", "Logitech BRIO IR", @"\\?\USB#BRIO", 1, false),
        ]);
        Assert.Equal(["hello", "usb"], list.Select(d => d.Id[WebcamDevice.InfraredPrefix.Length..]));
        // A depth camera whose only IR stream is in a combined group is still listed.
        Assert.Single(WebcamIrSources.Distinct([C("realsense", "RealSense", null, 3, false, color: true)]));
        Assert.Equal(@"\\?\USB#X", WebcamIrSources.DevicePathOf(@"Source#0@\\?\USB#X"));
        Assert.Null(WebcamIrSources.DevicePathOf("Source#0"));
    }

    [Fact]
    public async Task An_IR_camera_Windows_keeps_for_Hello_is_not_supported_not_failed()
    {
        var ir = new WebcamDevice(WebcamDevice.InfraredPrefix + "g", "IR Camera", WebcamBus.BuiltIn, WebcamKind.Infrared);
        var m = new WebcamTestModule(new FakeIo([ir], (_, _) => throw new WebcamNotSupportedException("no IR stream")));
        var r = await m.RefreshAsync(WebcamTestModule.InstanceOf(ir), null);
        var rep = Assert.IsType<WebcamReport>(r.Payload);
        Assert.Equal(WebcamVerdict.NotSupported, rep.Verdict);
        Assert.Equal(WebcamKind.Infrared, rep.Kind);
        Assert.Equal(DiagnosticStatus.Warning, r.Status);
        Assert.StartsWith("Not supported", r.Message);
        Assert.Equal(CouldNotRun.OutcomeText, Core.Logging.ResultEventLogger.Outcome(r));
    }

    private static WmiRow Row(string key, long start, long stop) => WmiRow.From(new Dictionary<string, object?>
    {
        [RegistryRead.KeyColumn] = key,
        ["LastUsedTimeStart"] = start,
        ["LastUsedTimeStop"] = stop,
    });

    [Fact]
    public void Holders_are_the_apps_using_the_camera_now_without_this_app()
    {
        var packaged = new[]
        {
            Row("Microsoft.WindowsCamera_8wekyb3d8bbwe", 300, 0),
            Row("MicrosoftTeams_8wekyb3d8bbwe", 100, 200), // stopped
            Row("NonPackaged", 0, 0),
        };
        var desktop = new[]
        {
            Row(@"C:#Users#bud#AppData#Roaming#Zoom#bin#Zoom.exe", 500, 0),
            Row(@"C:#Program Files#RemotePCDiagnostics#RemotePCDiagnostics.exe", 600, 0), // this app
            Row(@"C:#Program Files#Old#Skype.exe", 50, 40), // a stop older than its start: still in use
            Row(@"C:#Tools#Obs.exe", 10, 20),
        };
        var holders = WebcamHolders.From(packaged, desktop, "RemotePCDiagnostics");
        Assert.Equal(["Zoom.exe", "Microsoft.WindowsCamera", "Skype.exe"], holders.Select(h => h.App));
        Assert.Equal("Zoom", holders[0].ProcessName);
        Assert.True(WebcamHolders.CanClose(holders[0]));
        Assert.True(holders[1].Packaged);
        Assert.Null(holders[1].ProcessName);
        Assert.False(WebcamHolders.CanClose(holders[1]));
        Assert.False(WebcamHolders.CanClose(new WebcamHolder("svchost.exe", "svchost", false)));
    }

    [Fact]
    public async Task A_busy_camera_names_the_app_holding_it_from_the_registry()
    {
        var reg = new FakeRegistry(r => r.Path.EndsWith("NonPackaged", StringComparison.Ordinal)
            ? [Row(@"C:#Program Files#Zoom#Zoom.exe", 500, 0)]
            : [Row("Microsoft.WindowsCamera_8wekyb3d8bbwe", 100, 200)]);
        var m = new WebcamTestModule(new FakeIo(null, (_, _) => throw new WebcamBusyException("in use")), registry: reg);
        var r = await m.RefreshAsync(null);
        var rep = Assert.IsType<WebcamReport>(r.Payload);
        Assert.Equal(WebcamVerdict.Busy, rep.Verdict);
        Assert.Equal("Zoom", Assert.Single(rep.Holders).ProcessName);
        Assert.Contains("Zoom.exe", r.Message);
        Assert.Equal(CouldNotRun.OutcomeText, Core.Logging.ResultEventLogger.Outcome(r));
        Assert.All(reg.Reads, x => Assert.Equal(RegistryRoot.CurrentUser, x.Root));
        Assert.Equal(2, reg.Reads.Count);
        // The fix the pane offers is the End task path, by process name.
        var fix = UI.Shared.WebcamReportDetails.CloseAction(rep.Holders[0]);
        Assert.Equal((RemediationKind.EndProcessGroup, "Zoom"), (fix.Kind, fix.Target));
    }

    [Fact]
    public async Task A_shared_mode_read_also_lists_the_holder_and_a_passing_run_reads_no_registry()
    {
        var reg = new FakeRegistry(r => r.Path.EndsWith("NonPackaged", StringComparison.Ordinal) ? [Row(@"C:#Zoom.exe", 5, 0)] : []);
        var shared = await new WebcamTestModule(new FakeIo(null, (r, _) => Feed(r, "Another app was using the camera")), registry: reg).RefreshAsync(null);
        Assert.Single(Assert.IsType<WebcamReport>(shared.Payload).Holders);

        var quiet = new FakeRegistry(_ => throw new InvalidOperationException("should not read"));
        var ok = await new WebcamTestModule(new FakeIo(null, (r, _) => Feed(r, null)), registry: quiet).RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Ok, ok.Status);
        Assert.Empty(quiet.Reads);
    }

    [Fact]
    public async Task The_persons_answer_is_saved_with_the_measured_verdict()
    {
        var r = await new WebcamTestModule(new FakeIo(null, (q, _) => Feed(q, null))).RefreshAsync(null);
        r = r with { RunId = Guid.NewGuid(), InstanceKey = "k", InstanceLabel = "Cam" };
        Assert.Equal(DiagnosticStatus.Ok, r.Status);

        var no = WebcamVerdicts.WithPersonAnswer(r, false);
        var rep = Assert.IsType<WebcamReport>(no.Payload);
        Assert.Equal(WebcamVerdict.Pass, rep.Verdict); // the measurement is kept
        Assert.False(rep.PersonSawPicture);
        Assert.Equal(DiagnosticStatus.Error, no.Status);
        Assert.StartsWith("The person at the PC said they don't see themselves", no.Message);
        Assert.Equal((r.RunId, "k", "Cam"), (no.RunId, no.InstanceKey, no.InstanceLabel));

        var yes = WebcamVerdicts.WithPersonAnswer(no, true);
        Assert.Equal(DiagnosticStatus.Ok, yes.Status);
        Assert.EndsWith("and the person at the PC sees themselves.", yes.Message);

        var notRun = DiagnosticResult.NotRun(WebcamTestModule.ModuleName);
        Assert.Same(notRun, WebcamVerdicts.WithPersonAnswer(notRun, true));
    }

    [Fact]
    public void The_interactive_export_carries_capabilities_controls_holders_and_the_answer()
    {
        var rep = WebcamTestModuleEvaluate(Live(), new WebcamDevice("cam", "FHD Camera", WebcamBus.BuiltIn),
            new WebcamCaptureResult(640, 480, 30, "YUY2")
            {
                Formats = Vga,
                Controls = [new("Focus", true, 0, 250, 5, 30, true, false), new("Pan", false, 0, 0, 0, null, false, null)],
            }) with { Holders = [new("Zoom.exe", "Zoom", false)], PersonSawPicture = true };
        var result = new DiagnosticResult<WebcamReport>("Webcam", WebcamVerdicts.StatusOf(rep), WebcamVerdicts.MessageOf(rep), DateTimeOffset.Now, rep);
        var page = new InteractiveExport.PageState("webcam", [], false, false, false, false);
        using var doc = JsonDocument.Parse(InteractiveExport.ToJson(page, new PhysicalBenchQaSnapshot(), new(result, false),
            new(DiagnosticResult.NotRun("SpeakerToMic"), false), new(DiagnosticResult.NotRun("MicToSpeaker"), false)));
        var cam = doc.RootElement.GetProperty("tests").EnumerateArray().Single(t => t.GetProperty("id").GetString() == "webcam");
        var measured = cam.GetProperty("measured");
        Assert.Equal("FewerFormats", measured.GetProperty("verdict").GetString());
        Assert.Equal("color", measured.GetProperty("kind").GetString());
        var cap = measured.GetProperty("capability");
        Assert.True(cap.GetProperty("belowClass").GetBoolean());
        Assert.Equal("1080p", cap.GetProperty("nameClass").GetString());
        Assert.Equal(640, cap.GetProperty("maxWidth").GetInt32());
        Assert.Equal(3, measured.GetProperty("formats").GetArrayLength());
        var focus = measured.GetProperty("controls")[0];
        Assert.Equal(250, focus.GetProperty("max").GetDouble());
        Assert.False(focus.GetProperty("auto").GetBoolean());
        Assert.False(measured.GetProperty("controls")[1].TryGetProperty("max", out _));
        var holder = measured.GetProperty("holders")[0];
        Assert.Equal("Zoom", holder.GetProperty("process").GetString());
        Assert.True(holder.GetProperty("canClose").GetBoolean());
        Assert.True(cam.GetProperty("personSawPicture").GetBoolean());
        Assert.Contains("Do you see yourself", cam.GetProperty("instructions").GetString());
    }

    private static WebcamReport WebcamTestModuleEvaluate(WebcamStats stats, WebcamDevice dev, WebcamCaptureResult cap) =>
        WebcamTestModule.Evaluate(stats, dev, cap, TimeSpan.FromSeconds(3), privacyDeny: false);

    private static Task<WebcamCaptureResult> Feed(WebcamCaptureRequest r, string? note)
    {
        for (var i = 0; i < 90; i++) r.OnFrame(new WebcamFrame(W, H, Scene(i), TimeSpan.FromSeconds(i / 30.0)));
        return Task.FromResult(new WebcamCaptureResult(1280, 720, 30, "NV12", note) { Formats = FullHd });
    }

    private sealed class FakeIo(IReadOnlyList<WebcamDevice>? devices, Func<WebcamCaptureRequest, CancellationToken, Task<WebcamCaptureResult>> capture) : IWebcamIo
    {
        public IReadOnlyList<WebcamDevice> ListDevices() => devices ?? [new("cam1", "Integrated Camera", WebcamBus.BuiltIn)];
        public bool IsCameraBlockedByPrivacy() => false;
        public Task<WebcamCaptureResult> CaptureAsync(WebcamCaptureRequest r, CancellationToken ct) => capture(r, ct);
    }

    private sealed class FakeRegistry(Func<RegistryRead, IReadOnlyList<WmiRow>> rows) : IRegistrySource
    {
        public List<RegistryRead> Reads { get; } = [];
        public Task<WmiQueryResult> ReadAsync(RegistryRead read, CancellationToken ct = default)
        {
            Reads.Add(read);
            return Task.FromResult(new WmiQueryResult(read.Location, read.Describe(), rows(read)));
        }
    }
}
