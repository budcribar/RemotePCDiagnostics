using System.Text.Json;
using Bunit;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Recording;
using RemotePCDiagnostics.Core.Stress;
using RemotePCDiagnostics.Core.VideoPlayback;
using RemotePCDiagnostics.UI.Shared;

namespace RemotePCDiagnostics.Tests;

/// <summary>The video playback test (#294): playback stress with simulated decoders (decode time, software decode, driver reset, crash),
/// streams added and removed while it runs, the media apps check, the report, record/replay, and the page's choices.</summary>
public sealed class VideoPlaybackTests : BunitContext
{
    internal const int SelfPid = 4242;
    internal static readonly VideoClipInfo TestClip = new("clip.mp4", "H.264", 1920, 1080, 30, TimeSpan.FromSeconds(8), HasAudio: true);

    /// <summary>How a simulated stream behaves: decode time per frame, on the graphics chip or not, and what goes wrong after how many frames.</summary>
    internal sealed record StreamPlan(TimeSpan DecodeTime, bool OnChip = true, int? LostAfter = null, int? CrashAfter = null, int? SlowAfter = null, TimeSpan? SlowDecode = null);

    /// <summary>Decoders whose decode time advances their stream's own fake clock, so lateness is exact.</summary>
    internal sealed class SimulatedVideo(Func<int, StreamPlan> plan, VideoClipInfo? clip = null, Exception? openError = null, int? openFailsFrom = null) : IVideoPlaybackSource
    {
        public readonly Dictionary<int, FakeStressClock> Clocks = [];
        public int Opened, Disposed;
        public List<GpuEngineLoad> Loads { get; set; } = [new(SelfPid, "VideoDecode", 40), new(SelfPid, "3D", 5), new(999, "VideoDecode", 70)];
        public List<MediaProcess> Before { get; set; } = [];
        public List<MediaProcess> After { get; set; } = [];
        public List<MediaSessionInfo> Sessions { get; set; } = [];
        private int _processReads;

        public VideoClipInfo? Clip => clip;
        public int SelfProcessId => SelfPid;
        public int LogicalProcessors => 8;

        public FakeStressClock ClockFor(int index) { lock (Clocks) return Clocks.TryGetValue(index, out var c) ? c : Clocks[index] = new FakeStressClock(); }

        public IVideoStreamDecoder OpenStream(int index)
        {
            if (openError is not null) throw openError;
            if (openFailsFrom is { } n && index >= n) throw new InvalidOperationException("out of decoder sessions");
            Interlocked.Increment(ref Opened);
            return new Decoder(plan(index), ClockFor(index), this);
        }

        public IGpuEngineMeter OpenEngineMeter() => new Meter(this);
        public IReadOnlyList<MediaProcess> ReadProcesses() => Interlocked.Increment(ref _processReads) == 1 ? Before : After;
        public IReadOnlyList<MediaSessionInfo> ReadMediaSessions() => Sessions;

        private sealed class Meter(SimulatedVideo v) : IGpuEngineMeter
        {
            public IReadOnlyList<GpuEngineLoad> Sample() => v.Loads;
            public void Dispose() { }
        }

        private sealed class Decoder(StreamPlan p, FakeStressClock clock, SimulatedVideo v) : IVideoStreamDecoder
        {
            private int _n, _frames;
            public VideoStreamInfo Info { get; } = new("Simulated decoder", p.OnChip, 30);

            public DecodedSample Next()
            {
                var n = _n++;
                // Every third sample is audio (about as often as AAC frames come with 30 fps video).
                if (n % 3 == 2) return new DecodedSample(DecodedSampleKind.Audio, TimeSpan.FromSeconds(_frames / 30.0), false);
                var f = _frames++;
                if (p.LostAfter is { } l && f >= l) throw new GpuDeviceLostException("device removed");
                if (p.CrashAfter is { } c && f >= c) throw new InvalidOperationException("decoder error 0xC00D36B2");
                clock.Advance(p.SlowAfter is { } s && f >= s ? p.SlowDecode ?? p.DecodeTime : p.DecodeTime);
                return new DecodedSample(DecodedSampleKind.Video, TimeSpan.FromSeconds(f / 30.0), p.OnChip);
            }

            public void Dispose() => Interlocked.Increment(ref v.Disposed);
        }
    }

    internal static VideoPlaybackModule Module(SimulatedVideo v, FakeStressClock? runClock = null, VideoPlaybackOptions? o = null) =>
        new(v, null, null, () => runClock ?? new FakeStressClock(), i => v.ClockFor(i), o ?? new VideoPlaybackOptions { StopTimeout = TimeSpan.FromSeconds(5) });

    private static async Task<(AreaReport Report, VideoPlaybackModule Module)> RunStress(SimulatedVideo v, int streams = 1, int minutes = 1, FakeStressClock? runClock = null)
    {
        var m = Module(v, runClock);
        m.Streams = streams;
        m.Duration = TimeSpan.FromMinutes(minutes);
        var r = await m.RefreshAsync(null, Xunit.TestContext.Current.CancellationToken);
        return ((AreaReport)r.Payload!, m);
    }

    [Fact]
    public async Task Fast_hardware_decode_passes_with_no_dropped_frames()
    {
        var v = new SimulatedVideo(_ => new StreamPlan(TimeSpan.FromMilliseconds(4)), TestClip);
        var (report, m) = await RunStress(v, streams: 2);

        Assert.Equal(DiagnosticStatus.Ok, report.Status);
        var s = m.LastStress!;
        Assert.Equal(VideoPlaybackOutcome.Passed, s.Outcome);
        Assert.Equal(2, s.MostStreams);
        Assert.All(s.Streams, x => Assert.True(x.Frames > 0));
        Assert.Equal(0, s.DroppedFrames);
        Assert.Equal(0, s.AudioGlitches);
        Assert.False(s.SoftwareDecode);
        Assert.Equal(40, s.DecodeEnginePeakPercent); // this app's decode engine, not the other process's 70%
        Assert.Equal(2, v.Disposed);
        var card = Assert.Single(report.Cards);
        Assert.Equal("playback", card.Id);
        Assert.StartsWith("Passed: 2 streams of 1080p H.264, 30 fps", card.Headline);
        Assert.Equal(2, card.Rows.Count);
        Assert.Contains(report.KeyMetrics!, k => k.Id == "DroppedPercent" && k.Value == 0);
    }

    [Fact]
    public async Task A_decoder_slower_than_the_frame_rate_drops_frames_and_fails()
    {
        // 30 fps = 33 ms per frame; 60 ms per frame falls further behind each frame.
        var v = new SimulatedVideo(_ => new StreamPlan(TimeSpan.FromMilliseconds(60)), TestClip);
        var (report, m) = await RunStress(v);

        Assert.Equal(DiagnosticStatus.Error, report.Status);
        Assert.Equal(VideoPlaybackOutcome.TooManyDropped, m.LastStress!.Outcome);
        Assert.True(m.LastStress.WorstStreamDroppedPercent > 5);
        Assert.True(m.LastStress.AudioGlitches > 0);
        Assert.StartsWith("Failed: stream 1 dropped", report.Cards[0].Headline);
        Assert.Equal(AreaLevel.Error, report.Cards[0].Rows[0].Level);
    }

    [Fact]
    public async Task Decoding_on_the_processor_is_a_warning()
    {
        var v = new SimulatedVideo(_ => new StreamPlan(TimeSpan.FromMilliseconds(4), OnChip: false), TestClip);
        var (report, m) = await RunStress(v);

        Assert.Equal(DiagnosticStatus.Warning, report.Status);
        Assert.Equal(VideoPlaybackOutcome.SoftwareDecode, m.LastStress!.Outcome);
        Assert.Equal("Processor", report.Cards[0].Rows[0].Values[5]);
        Assert.Contains("decoded by the processor", report.Cards[0].Note);
    }

    [Fact]
    public async Task A_driver_reset_fails_and_links_to_crashes()
    {
        var v = new SimulatedVideo(i => new StreamPlan(TimeSpan.FromMilliseconds(4), LostAfter: i == 2 ? 10 : null), TestClip);
        var (report, m) = await RunStress(v, streams: 3);

        Assert.Equal(DiagnosticStatus.Error, report.Status);
        Assert.Equal(VideoPlaybackOutcome.DriverReset, m.LastStress!.Outcome);
        Assert.Contains("Stream 2", m.LastStress.Reason);
        Assert.Equal(ModuleSlugs.Crashes, report.Cards[0].RunCheck?.CheckId);
        Assert.Equal(VideoStreamEnd.DriverReset, m.LastStress.Streams.Single(s => s.Index == 2).End);
        Assert.Equal(v.Opened, v.Disposed); // every decoder freed
    }

    [Fact]
    public async Task A_decoder_crash_fails_the_run()
    {
        var v = new SimulatedVideo(_ => new StreamPlan(TimeSpan.FromMilliseconds(4), CrashAfter: 15), TestClip);
        var (report, m) = await RunStress(v);

        Assert.Equal(VideoPlaybackOutcome.DecoderCrashed, m.LastStress!.Outcome);
        Assert.Equal(DiagnosticStatus.Error, report.Status);
        Assert.Equal("Decoder failed", report.Cards[0].Rows[0].Values[^1]);
        Assert.Contains("0xC00D36B2", report.Cards[0].Rows[0].Detail);
    }

    [Fact]
    public async Task No_decoder_for_the_clip_is_not_supported()
    {
        var v = new SimulatedVideo(_ => new StreamPlan(TimeSpan.Zero), TestClip, openError: new VideoPlaybackUnavailableException("Windows has no H.264 video decoder"));
        var (report, _) = await RunStress(v);

        Assert.True(report.NotOnThisPc);
        Assert.StartsWith("Not supported: Windows has no H.264", report.Summary);
    }

    [Fact]
    public async Task A_missing_clip_could_not_run()
    {
        var v = new SimulatedVideo(_ => new StreamPlan(TimeSpan.Zero), clip: null);
        var (report, _) = await RunStress(v);

        Assert.Equal(DiagnosticStatus.Error, report.Status);
        Assert.Contains("missing", report.CouldNotRunReason);
    }

    [Fact]
    public async Task More_streams_than_the_decoder_opens_keeps_the_ones_that_run()
    {
        var v = new SimulatedVideo(_ => new StreamPlan(TimeSpan.FromMilliseconds(4)), TestClip, openFailsFrom: 4);
        var (_, m) = await RunStress(v, streams: 6);

        Assert.Equal(3, m.LastStress!.MostStreams);
        Assert.Equal(3, v.Opened);
        Assert.Contains("Only 3 streams", m.LastStress.Reason);
    }

    [Fact]
    public async Task Streams_added_and_removed_while_it_runs()
    {
        // Ticks: 4 streams at first, + to 6 on tick 5, − to 2 on tick 10.
        VideoPlaybackModule? module = null;
        var runClock = new FakeStressClock(async (step, ct) =>
        {
            if (step == 5) module!.Streams = 6;
            if (step == 10) module!.Streams = 2;
            await Task.Delay(3, ct);
        });
        var v = new SimulatedVideo(_ => new StreamPlan(TimeSpan.FromMilliseconds(4)), TestClip);
        module = Module(v, runClock);
        module.Streams = 4;
        module.Duration = TimeSpan.FromMinutes(1);
        var r = await module.RefreshAsync(null, Xunit.TestContext.Current.CancellationToken);

        var s = module.LastStress!;
        Assert.Equal(VideoPlaybackOutcome.Passed, s.Outcome);
        Assert.Equal(6, s.MostStreams);
        Assert.Equal(6, s.Streams.Count);
        Assert.Equal(4, s.Streams.Count(x => x.End == VideoStreamEnd.Removed));
        Assert.Equal([1, 2], s.Streams.Where(x => x.End == VideoStreamEnd.Finished).Select(x => x.Index));
        Assert.Equal(6, v.Disposed);
        Assert.Contains("Removed with −", ((AreaReport)r.Payload!).Cards[0].Rows.Select(x => x.Values[^1]));
    }

    [Fact]
    public async Task Cancel_stops_every_stream()
    {
        VideoPlaybackModule? module = null;
        var runClock = new FakeStressClock(async (step, ct) => { if (step == 3) module!.Cancel(); await Task.Delay(2, ct); });
        var v = new SimulatedVideo(_ => new StreamPlan(TimeSpan.FromMilliseconds(4)), TestClip);
        module = Module(v, runClock);
        module.Streams = 3;
        var r = await module.RefreshAsync(null, Xunit.TestContext.Current.CancellationToken);

        Assert.True(r.Cancelled);
        Assert.Equal(v.Opened, v.Disposed);
        Assert.False(module.IsRunning);
    }

    [Fact]
    public void Stream_count_and_minutes_stay_in_range()
    {
        var m = Module(new SimulatedVideo(_ => new StreamPlan(TimeSpan.Zero), TestClip));
        m.Streams = 40; Assert.Equal(16, m.Streams);
        m.Streams = 0; Assert.Equal(1, m.Streams);
        m.Duration = TimeSpan.FromMinutes(30); Assert.Equal(TimeSpan.FromMinutes(10), m.Duration);
        Assert.False(m.IncludeInRunAll);
    }

    // ---- media apps ----

    private static MediaProcess P(int pid, string name, double cpuSeconds) => new(pid, name, TimeSpan.FromSeconds(cpuSeconds));

    [Fact]
    public void Media_apps_names_the_app_decoding_on_the_processor()
    {
        // Over 5 s: Chrome's GPU process uses the decode engine; VLC burns 3 s of CPU (60% of a core) with no decode engine use; Spotify is light.
        List<MediaProcess> before = [P(10, "chrome", 10), P(11, "chrome", 5), P(20, "vlc", 100), P(30, "Spotify", 1), P(40, "notepad", 1), P(SelfPid, "RemotePCDiagnostics.Host", 1)];
        List<MediaProcess> after = [P(10, "chrome", 10.5), P(11, "chrome", 5.4), P(20, "vlc", 103), P(30, "Spotify", 1.1), P(40, "notepad", 3), P(SelfPid, "RemotePCDiagnostics.Host", 9)];
        List<GpuEngineLoad> loads = [new(11, "VideoDecode", 12), new(20, "3D", 4), new(SelfPid, "VideoDecode", 50)];
        List<MediaSessionInfo> sessions = [new("Chrome", true), new("vlc.exe", true), new("Spotify.exe", true)];

        var r = MediaAppsCheck.Evaluate(before, after, 5, loads, sessions, SelfPid, enginesAvailable: true);

        Assert.Equal(["vlc", "chrome", "Spotify"], r.Apps.Select(a => a.Name));
        var vlc = r.Apps[0];
        Assert.Equal(MediaAppVerdict.ProcessorDecode, vlc.Verdict);
        Assert.Equal(60, vlc.CpuPercentOfCore);
        Assert.Contains("Hardware-accelerated decoding", vlc.Advice);
        var chrome = r.Apps[1];
        Assert.Equal(MediaAppVerdict.GraphicsChip, chrome.Verdict);
        Assert.Equal(2, chrome.Processes);
        Assert.Equal(18, chrome.CpuPercentOfCore);
        Assert.Equal(MediaAppVerdict.LightLoad, r.Apps[2].Verdict);

        var report = VideoPlaybackModule.MediaAppsReport(r);
        Assert.Equal(DiagnosticStatus.Warning, report.Status);
        Assert.StartsWith("VLC media player is decoding video on the processor", report.Summary);
        Assert.Contains("Tools > Preferences", report.Cards[0].Note);
        Assert.Equal(AreaLevel.Warning, report.Cards[0].Rows[0].Level);
    }

    [Fact]
    public void Media_apps_with_nothing_playing_is_skipped()
    {
        List<MediaProcess> procs = [P(10, "chrome", 1)];
        var r = MediaAppsCheck.Evaluate(procs, procs, 5, [], [], SelfPid, enginesAvailable: true);
        Assert.Equal(MediaAppVerdict.NotPlaying, Assert.Single(r.Apps).Verdict);

        var report = VideoPlaybackModule.MediaAppsReport(r);
        Assert.True(report.NotOnThisPc);
        Assert.StartsWith("Skipped: nothing was playing", report.Summary);
    }

    [Fact]
    public void Without_engine_counters_high_cpu_is_not_called_processor_decode()
    {
        List<MediaProcess> before = [P(20, "vlc", 0)], after = [P(20, "vlc", 3)];
        var r = MediaAppsCheck.Evaluate(before, after, 5, [], [new("vlc", true)], SelfPid, enginesAvailable: false);
        Assert.Equal(MediaAppVerdict.LightLoad, r.Apps[0].Verdict);
        Assert.Contains("doesn't report the video decode engine", VideoPlaybackModule.MediaAppsReport(r).Summary);
    }

    [Fact]
    public async Task Media_apps_mode_runs_through_the_module()
    {
        var v = new SimulatedVideo(_ => new StreamPlan(TimeSpan.Zero), TestClip)
        {
            Before = [P(10, "msedge", 0)],
            After = [P(10, "msedge", 0.2)],
            Loads = [new(10, "VideoDecode", 8)],
            Sessions = [new("MSEdge", true)],
        };
        var m = Module(v);
        m.Mode = VideoPlaybackMode.MediaApps;
        var r = await m.RefreshAsync(null, Xunit.TestContext.Current.CancellationToken);

        Assert.Equal(DiagnosticStatus.Ok, r.Status);
        Assert.Equal("Video decoded on the graphics chip: Microsoft Edge", r.Message);
        Assert.Equal(MediaAppVerdict.GraphicsChip, Assert.Single(m.LastMediaApps!.Apps).Verdict);
    }

    [Theory]
    [InlineData("Chrome", "chrome", true)]
    [InlineData("Spotify.exe", "Spotify", true)]
    [InlineData("MSEdge", "msedge", true)]
    [InlineData("Microsoft.ZuneMusic_8wekyb3d8bbwe!Microsoft.ZuneMusic", "Microsoft.Media.Player", true)]
    [InlineData("308046B0AF4A39CB", "firefox", true)]
    [InlineData("Chrome", "msedge", false)]
    [InlineData("", "vlc", false)]
    public void Media_sessions_match_their_app(string appId, string exe, bool matches) =>
        Assert.Equal(matches, MediaAppCatalog.SessionMatches(appId, exe, MediaAppCatalog.Find(exe)));

    [Theory]
    [InlineData("pid_1234_luid_0x00000000_0x0000D1B5_phys_0_eng_3_engtype_VideoDecode", 1234, "VideoDecode", true)]
    [InlineData("pid_88_luid_0x00000000_0x00011234_phys_0_eng_5_engtype_Video Codec", 88, "Video Codec", true)]
    [InlineData("pid_88_luid_0x00000000_0x00011234_phys_0_eng_0_engtype_3D", 88, "3D", false)]
    public void Gpu_engine_instances_parse(string instance, int pid, string engine, bool decode)
    {
        var x = GpuEngineLoad.ParseInstance(instance);
        Assert.Equal((pid, engine), x);
        Assert.Equal(decode, new GpuEngineLoad(pid, engine, 1).IsVideoDecode);
        Assert.Null(GpuEngineLoad.ParseInstance("_Total"));
    }

    // ---- record and replay ----

    [Fact]
    public async Task A_recorded_driver_reset_replays_as_a_driver_reset()
    {
        var calls = new CallRecorder();
        var live = new SimulatedVideo(_ => new StreamPlan(TimeSpan.FromMilliseconds(2), LostAfter: 12), TestClip);
        var recorded = new VideoPlaybackModule(new RecordingVideoPlaybackSource(live, calls), null, null, () => new FakeStressClock(), i => live.ClockFor(i));
        recorded.Streams = 1;
        await recorded.RefreshAsync(null, Xunit.TestContext.Current.CancellationToken);
        Assert.Equal(VideoPlaybackOutcome.DriverReset, recorded.LastStress!.Outcome);

        var json = JsonSerializer.Serialize(calls.Snapshot(), MachineRecording.Json);
        var replay = new RecordingReplay(JsonSerializer.Deserialize<List<RecordedCall>>(json, MachineRecording.Json)!);
        // Real clocks: the replayed decoder waits as long as each frame took, and the run checks the streams every 100 ms.
        var again = new VideoPlaybackModule(replay.VideoPlayback, options: new VideoPlaybackOptions { Tick = TimeSpan.FromMilliseconds(100) });
        again.Streams = 1;
        var r = await again.RefreshAsync(null, Xunit.TestContext.Current.CancellationToken);

        Assert.Equal(VideoPlaybackOutcome.DriverReset, again.LastStress!.Outcome);
        Assert.Equal(12, again.LastStress.Frames);
        Assert.Equal(TestClip.Label, again.LastStress.Clip!.Label);
        Assert.Equal(40, again.LastStress.DecodeEnginePeakPercent); // the recorded app's own decode load, by its recorded process id
        Assert.Equal(DiagnosticStatus.Error, r.Status);
    }

    [Fact]
    public async Task A_recorded_media_apps_check_replays()
    {
        var calls = new CallRecorder();
        var live = new SimulatedVideo(_ => new StreamPlan(TimeSpan.Zero), TestClip)
        {
            Before = [P(20, "vlc", 0)], After = [P(20, "vlc", 2.5)], Loads = [new(20, "3D", 3)], Sessions = [new("vlc", true)],
        };
        var m = new VideoPlaybackModule(new RecordingVideoPlaybackSource(live, calls), clockFactory: () => new FakeStressClock()) { Mode = VideoPlaybackMode.MediaApps };
        await m.RefreshAsync(null, Xunit.TestContext.Current.CancellationToken);

        var replay = new RecordingReplay(calls.Snapshot());
        var again = new VideoPlaybackModule(replay.VideoPlayback, clockFactory: () => new FakeStressClock()) { Mode = VideoPlaybackMode.MediaApps };
        var r = await again.RefreshAsync(null, Xunit.TestContext.Current.CancellationToken);

        Assert.Equal(DiagnosticStatus.Warning, r.Status);
        Assert.Equal(MediaAppVerdict.ProcessorDecode, again.LastMediaApps!.Apps.Single().Verdict);
        Assert.Empty(replay.Misses);
    }

    // ---- the page ----

    private static JsonElement Data(IRenderedComponent<VideoPlaybackChoices> cut) =>
        JsonDocument.Parse(cut.Find("[data-testid=videoplayback-data]").GetAttribute("data-report")!).RootElement;

    [Fact]
    public void Choices_show_the_mode_streams_and_minutes_and_the_data_copy()
    {
        var m = Module(new SimulatedVideo(_ => new StreamPlan(TimeSpan.Zero), TestClip));
        var cut = Render<VideoPlaybackChoices>(p => p.Add(x => x.Module, m));

        Assert.Equal("stress", cut.Find("[data-testid=videoplayback-options]").GetAttribute("data-mode"));
        Assert.Equal("4", cut.Find("[data-testid=videoplayback-streams]").TextContent);
        cut.Find("[data-testid=videoplayback-add-stream]").Click();
        cut.Find("[data-testid=videoplayback-add-stream]").Click();
        Assert.Equal(6, m.Streams);
        cut.Find("[data-testid=videoplayback-minutes]").Change("5");
        Assert.Equal(TimeSpan.FromMinutes(5), m.Duration);

        var data = Data(cut);
        Assert.Equal(6, data.GetProperty("streams").GetInt32());
        Assert.Equal(5, data.GetProperty("minutes").GetDouble());
        Assert.Equal("1080p H.264, 30 fps", data.GetProperty("clip").GetString());
        Assert.Equal(JsonValueKind.Null, data.GetProperty("stress").ValueKind);

        cut.Find("[data-testid=videoplayback-mode-media-apps]").Change(true);
        Assert.Equal(VideoPlaybackMode.MediaApps, m.Mode);
        Assert.Empty(cut.FindAll("[data-testid=videoplayback-add-stream]"));
        Assert.Equal("media-apps", Data(cut).GetProperty("mode").GetString());
    }

    [Fact]
    public void Minus_stops_at_one_stream_and_plus_at_sixteen()
    {
        var m = Module(new SimulatedVideo(_ => new StreamPlan(TimeSpan.Zero), TestClip));
        m.Streams = 1;
        var cut = Render<VideoPlaybackChoices>(p => p.Add(x => x.Module, m));
        Assert.True(cut.Find("[data-testid=videoplayback-remove-stream]").HasAttribute("disabled"));
        m.Streams = 16;
        cut.Render();
        Assert.True(cut.Find("[data-testid=videoplayback-add-stream]").HasAttribute("disabled"));
    }

    [Fact]
    public async Task The_last_result_is_in_the_data_copy()
    {
        var v = new SimulatedVideo(_ => new StreamPlan(TimeSpan.FromMilliseconds(60)), TestClip);
        var m = Module(v);
        m.Streams = 1;
        await m.RefreshAsync(null, Xunit.TestContext.Current.CancellationToken);
        var cut = Render<VideoPlaybackChoices>(p => p.Add(x => x.Module, m));

        var stress = Data(cut).GetProperty("stress");
        Assert.Equal("TooManyDropped", stress.GetProperty("outcome").GetString());
        Assert.Equal("Error", stress.GetProperty("level").GetString());
        var s = stress.GetProperty("streams")[0];
        Assert.True(s.GetProperty("droppedPercent").GetDouble() > 5);
        Assert.Equal("Finished", s.GetProperty("end").GetString());
    }
}
