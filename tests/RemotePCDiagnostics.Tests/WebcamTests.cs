using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Webcam;

namespace RemotePCDiagnostics.Tests;

public class WebcamTests
{
    private const int W = 32, H = 18;

    /// <summary>Synthetic frame: gradient + per-frame noise (live scene) or fixed pixels.</summary>
    private static byte[] Scene(int seed, int baseLevel = 100, int noise = 4, int span = 80)
    {
        var rnd = new Random(seed);
        var b = new byte[W * H];
        for (var y = 0; y < H; y++)
            for (var x = 0; x < W; x++)
                b[y * W + x] = (byte)Math.Clamp(baseLevel + x * span / W + (noise > 0 ? rnd.Next(-noise, noise + 1) : 0), 0, 255);
        return b;
    }

    private static WebcamStats Run(int frames, double fps, Func<int, byte[]> frame, Func<int, double>? time = null)
    {
        var a = new WebcamAnalyzer(30);
        for (var i = 0; i < frames; i++) a.Add(new WebcamFrame(W, H, frame(i), TimeSpan.FromSeconds(time?.Invoke(i) ?? i / fps)));
        return a.Result(TimeSpan.FromSeconds(5));
    }

    [Fact]
    public void Live_scene_passes()
    {
        var s = Run(150, 30, i => Scene(i));
        Assert.Equal(150, s.Frames);
        Assert.InRange(s.Fps, 29.5, 30.5);
        Assert.Equal(0, s.FrozenFraction);
        Assert.Equal(0, s.BlackFraction);
        Assert.Equal(0, s.Stalls);
        Assert.InRange(s.MeanBrightness, 130, 150);
        Assert.True(s.MeanContrast > 10);
        Assert.True(s.Sharpness > 0);
        Assert.Equal(WebcamVerdict.Pass, WebcamVerdicts.Decide(s));
    }

    [Fact]
    public void Black_frames_are_flagged_with_shutter_hint()
    {
        var s = Run(150, 30, i => Scene(i, baseLevel: 2, noise: 2, span: 0));
        Assert.True(s.BlackFraction > 0.99);
        var v = WebcamVerdicts.Decide(s);
        Assert.Equal(WebcamVerdict.AllBlack, v);
        Assert.Equal(DiagnosticStatus.Warning, WebcamVerdicts.StatusOf(v));
        Assert.Contains("privacy shutter", WebcamVerdicts.MessageOf(v));
    }

    [Fact]
    public void Identical_frames_are_frozen()
    {
        var still = Scene(7);
        var s = Run(150, 30, _ => still);
        Assert.Equal(1, s.FrozenFraction);
        Assert.Equal(WebcamVerdict.Frozen, WebcamVerdicts.Decide(s));
        Assert.Equal(DiagnosticStatus.Error, WebcamVerdicts.StatusOf(WebcamVerdict.Frozen));
    }

    [Fact]
    public void Low_fps_and_stalls_and_drops_are_detected()
    {
        Assert.Equal(WebcamVerdict.LowFps, WebcamVerdicts.Decide(Run(25, 5, i => Scene(i))));
        // 30 fps with a 1.5 s hole in the middle.
        var s = Run(120, 30, i => Scene(i), i => i / 30.0 + (i >= 60 ? 1.5 : 0));
        Assert.Equal(1, s.Stalls);
        Assert.True(s.LongestGap > TimeSpan.FromSeconds(1.4));
        Assert.InRange(s.EstimatedDropped, 40, 50);
        Assert.Equal(WebcamVerdict.Stalled, WebcamVerdicts.Decide(s));
    }

    [Fact]
    public void Overexposed_and_dark_are_warnings()
    {
        var over = Run(60, 30, i => Scene(i, baseLevel: 252, noise: 1, span: 0));
        Assert.Equal(WebcamVerdict.Overexposed, WebcamVerdicts.Decide(over));
        var dark = Run(60, 30, i => Scene(i, baseLevel: 15, noise: 8, span: 20));
        Assert.Equal(WebcamVerdict.Dark, WebcamVerdicts.Decide(dark));
        Assert.Equal(DiagnosticStatus.Warning, WebcamVerdicts.StatusOf(WebcamVerdict.Dark));
    }

    [Fact]
    public void No_frames_fails()
    {
        var s = new WebcamAnalyzer(30).Result(TimeSpan.FromSeconds(5));
        Assert.Equal(WebcamVerdict.NoFrames, WebcamVerdicts.Decide(s));
        Assert.Equal(DiagnosticStatus.Error, WebcamVerdicts.StatusOf(WebcamVerdict.NoFrames));
    }

    [Fact]
    public void Exceptions_map_to_clear_verdicts()
    {
        Assert.Equal(WebcamVerdict.AccessDenied, WebcamVerdicts.FromException(new UnauthorizedAccessException(), false));
        Assert.Equal(WebcamVerdict.AccessDenied, WebcamVerdicts.FromException(new WebcamAccessDeniedException("x"), false));
        Assert.Equal(WebcamVerdict.AccessDenied, WebcamVerdicts.FromException(new Exception("x"), true));
        Assert.Equal(WebcamVerdict.Busy, WebcamVerdicts.FromException(new WebcamBusyException("x"), false));
        Assert.Equal(WebcamVerdict.Busy, WebcamVerdicts.FromException(new Exception("x") { HResult = unchecked((int)0xC00DABE5) }, false));
        Assert.Equal(WebcamVerdict.DeviceError, WebcamVerdicts.FromException(new WebcamDeviceException("x"), false));
        Assert.StartsWith("Camera access is blocked", WebcamVerdicts.MessageOf(WebcamVerdict.AccessDenied));
    }

    [Fact]
    public void Luma_downsample_is_bounded_and_correct()
    {
        int w = 1280, h = 720;
        var bgra = new byte[w * h * 4];
        for (var i = 0; i < bgra.Length; i += 4) { bgra[i] = 255; bgra[i + 1] = 255; bgra[i + 2] = 255; bgra[i + 3] = 255; }
        var dest = new byte[WebcamMath.ThumbWidth * WebcamMath.ThumbHeight(w, h)];
        var (tw, th) = WebcamMath.LumaFromBgra(bgra, w, h, w * 4, dest);
        Assert.Equal((160, 90), (tw, th));
        Assert.All(dest, v => Assert.InRange(v, 254, 255));
        Assert.Equal(WebcamDevice.GuessBus(@"\\?\USB#VID_046D&PID_085B", false), WebcamBus.Usb);
        Assert.Equal(WebcamBus.BuiltIn, WebcamDevice.GuessBus("x", true));
    }

    private sealed class FakeIo(Func<WebcamCaptureRequest, CancellationToken, Task<WebcamCaptureResult>> capture, bool privacy = false) : IWebcamIo
    {
        public WebcamCaptureRequest? Seen;
        public IReadOnlyList<WebcamDevice> ListDevices() => [new("cam1", "Integrated Camera", WebcamBus.BuiltIn), new("cam2", "USB Cam", WebcamBus.Usb)];
        public bool IsCameraBlockedByPrivacy() => privacy;
        public Task<WebcamCaptureResult> CaptureAsync(WebcamCaptureRequest r, CancellationToken ct) { Seen = r; return capture(r, ct); }
    }

    private static Task<WebcamCaptureResult> Feed(WebcamCaptureRequest r, Func<int, byte[]> frame, int n = 90)
    {
        for (var i = 0; i < n; i++) r.OnFrame(new WebcamFrame(W, H, frame(i), TimeSpan.FromSeconds(i / 30.0)));
        return Task.FromResult(new WebcamCaptureResult(1280, 720, 30, "NV12"));
    }

    [Fact]
    public async Task Module_passes_with_fake_camera_and_caps_request()
    {
        var io = new FakeIo((r, _) => Feed(r, i => Scene(i)));
        var m = new WebcamTestModule(io) { Duration = TimeSpan.FromMinutes(10), DeviceId = "cam2" };
        var res = await m.RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Ok, res.Status);
        Assert.Equal("cam2", io.Seen!.DeviceId);
        Assert.Equal(WebcamTestModule.MaxDuration, io.Seen.Duration);
        Assert.True(io.Seen.MaxWidth <= 1280 && io.Seen.MaxHeight <= 720 && io.Seen.MaxFps <= 30);
        var rep = Assert.IsType<WebcamReport>(res.Payload);
        Assert.Equal(1280, rep.Width);
    }

    [Fact]
    public async Task Module_maps_privacy_busy_and_no_device()
    {
        var denied = await new WebcamTestModule(new FakeIo((_, _) => throw new UnauthorizedAccessException())).RefreshAsync(null);
        Assert.Equal(WebcamVerdicts.PrivacyMessage, denied.Message);
        var busy = await new WebcamTestModule(new FakeIo((_, _) => throw new WebcamBusyException("in use"))).RefreshAsync(null);
        Assert.Equal(WebcamVerdicts.BusyMessage, busy.Message);
        // Privacy Deny + black frames (some drivers) => privacy message, not "covered lens".
        var black = await new WebcamTestModule(new FakeIo((r, _) => Feed(r, i => Scene(i, 0, 0, 0)), privacy: true)).RefreshAsync(null);
        Assert.Equal(WebcamVerdicts.PrivacyMessage, black.Message);
        var none = await new WebcamTestModule(new NullWebcamIo()).RefreshAsync(null);
        Assert.Equal(DiagnosticStatus.Warning, none.Status);
        Assert.StartsWith("Skipped", none.Message);
    }

    [Fact]
    public async Task Module_cancel_stops_capture()
    {
        var m = new WebcamTestModule(new FakeIo(async (_, ct) => { await Task.Delay(Timeout.Infinite, ct); return null!; }));
        var t = m.RefreshAsync(null);
        await Task.Delay(50);
        m.Cancel();
        var r = await t.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(r.Cancelled);
    }

    [Fact]
    public async Task Webcam_is_separate_step_after_audio_and_not_selected()
    {
        var store = new ResultStore();
        var svc = new DiagnosticsService(store, [new WebcamTestModule(new NullWebcamIo()), new RemotePCDiagnostics.Core.Audio.SpeakerToMicModule(new RemotePCDiagnostics.Core.Audio.NullAudioIo())]);
        Assert.Empty(await svc.RunAllAsync());
        var screen = new ChecksScreenState(svc, store);
        var names = screen.StressModules.Select(m => m.Name).ToList();
        Assert.True(names.IndexOf(WebcamTestModule.ModuleName) > names.IndexOf(RemotePCDiagnostics.Core.Audio.SpeakerToMicModule.ModuleName));
        Assert.False(screen.IsSelected(WebcamTestModule.ModuleName));
        Assert.True(ChecksScreenState.IsSeparateStep(svc.Modules[0]));
    }
}
