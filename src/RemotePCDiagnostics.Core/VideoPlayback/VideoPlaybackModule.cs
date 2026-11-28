using System.Globalization;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Core.VideoPlayback;

/// <summary>
/// Video playback test, two modes. Playback stress plays 1 to 16 copies of the bundled 1080p clip at once for 1 to 10 minutes (+ and − change
/// the count while it runs) and measures late and dropped frames per stream, whether each frame was decoded on the graphics chip, the video
/// decode engine's load, the GPU temperature and audio glitches. Media apps watches what is playing now for a few seconds and names any app
/// that decodes its video on the processor. Runs in the app (no administrator rights), never in Run all, and Cancel stops it.
/// </summary>
public sealed class VideoPlaybackModule(
    IVideoPlaybackSource source,
    ISensorProvider? sensors = null,
    ILogger? log = null,
    Func<IStressClock>? clockFactory = null,
    Func<int, IStressClock>? streamClock = null,
    VideoPlaybackOptions? options = null) : AreaModuleBase(log), ICancellableScan
{
    public const string ModuleName = ModuleSlugs.VideoPlayback;
    private readonly object _gate = new();
    private CancellationTokenSource? _scan;
    private int _streams = VideoPlaybackOptions.DefaultStreams;

    public override string Name => ModuleName;
    public override Guid Id => ModuleIds.VideoPlayback;
    public override string DisplayName => "Video playback test";
    public bool IncludeInRunAll => false;
    protected override string FailedMessage => "The video playback test couldn't run.";

    public VideoPlaybackMode Mode { get; set; } = VideoPlaybackMode.Stress;

    /// <summary>How many copies play at once. Changing it while a stress run goes adds or removes streams within a second.</summary>
    public int Streams
    {
        get => Volatile.Read(ref _streams);
        set => Volatile.Write(ref _streams, VideoPlaybackOptions.ClampStreams(value));
    }

    private TimeSpan _duration = VideoPlaybackOptions.DefaultDuration;
    public TimeSpan Duration { get => _duration; set => _duration = VideoPlaybackOptions.ClampDuration(value); }

    public VideoClipInfo? Clip
    {
        get { try { return source.Clip; } catch (Exception) { return null; } }
    }

    public bool IsRunning { get { lock (_gate) return _scan is not null; } }
    public VideoPlaybackMode? RunningMode { get; private set; }
    public VideoPlaybackProgress? LastProgress { get; private set; }
    public VideoPlaybackResult? LastStress { get; private set; }
    public MediaAppsResult? LastMediaApps { get; private set; }

    public void Cancel()
    {
        lock (_gate) _scan?.Cancel();
    }

    protected override async Task<AreaReport> CollectAsync(IProgress<string>? progress, CancellationToken ct)
    {
        var mode = Mode;
        var o = (options ?? new VideoPlaybackOptions()) with { Streams = Streams, Duration = Duration };
        using var scan = CancellationTokenSource.CreateLinkedTokenSource(ct);
        lock (_gate) _scan = scan;
        RunningMode = mode;
        var started = DateTimeOffset.Now;
        try
        {
            if (mode == VideoPlaybackMode.MediaApps)
            {
                LastMediaApps = null;
                progress.ReportStep(0, 100, $"Watching the apps that play media for {o.MediaAppsWindow.TotalSeconds:0} seconds…");
                RaiseUpdated(new DiagnosticResult<double>(Name, DiagnosticStatus.Running, "Watching the apps that play media…", started, 0));
                var apps = await new MediaAppsCheck(source, clockFactory?.Invoke(), Logger).RunAsync(o.MediaAppsWindow, scan.Token).ConfigureAwait(false);
                LastMediaApps = apps;
                return MediaAppsReport(apps);
            }

            LastStress = null;
            progress.ReportStep(0, 100, "Starting the video streams…");
            var p = new InlineProgress(x =>
            {
                LastProgress = x;
                var text = $"Video playback: {Plural(x.Running, "stream")}, {Clock(x.Elapsed)} of {Clock(x.Duration)}, "
                    + $"{Percent(x.Streams.Sum(s => s.DroppedFrames), x.Streams.Sum(s => s.Frames))} dropped"
                    + (x.DecodeEnginePercent is { } d ? $", video decode engine {d:0}%" : "");
                progress.ReportStep((int)Math.Round(x.Fraction * 100), 100, text);
                RaiseUpdated(new DiagnosticResult<double>(Name, DiagnosticStatus.Running, text, started, x.Fraction * 100));
            });
            var result = await new VideoPlaybackTest(source, sensors, clockFactory?.Invoke(), streamClock, Logger)
                .RunAsync(o, () => Streams, p, scan.Token).ConfigureAwait(false);
            LastStress = result;
            if (ct.IsCancellationRequested) throw new OperationCanceledException(ct);
            return StressReport(result, o);
        }
        catch (OperationCanceledException) when (scan.IsCancellationRequested && !ct.IsCancellationRequested)
        {
            return AreaReport.ScanCancelled() with { Summary = "Video playback test cancelled" };
        }
        finally
        {
            lock (_gate) { if (ReferenceEquals(_scan, scan)) _scan = null; }
            LastProgress = null;
            RunningMode = null;
        }
    }

    // ---- playback stress report ----

    public static AreaLevel Level(VideoPlaybackOutcome o) => o switch
    {
        VideoPlaybackOutcome.Passed => AreaLevel.Ok,
        VideoPlaybackOutcome.TooManyDropped or VideoPlaybackOutcome.DecoderCrashed or VideoPlaybackOutcome.DriverReset => AreaLevel.Error,
        VideoPlaybackOutcome.NotSupported => AreaLevel.Neutral,
        _ => AreaLevel.Warning,
    };

    public static AreaReport StressReport(VideoPlaybackResult r, VideoPlaybackOptions? options = null)
    {
        var o = options ?? new VideoPlaybackOptions();
        if (r.Outcome == VideoPlaybackOutcome.Cancelled)
            return AreaReport.ScanCancelled() with { Summary = "Video playback test cancelled: every stream was stopped" };
        if (r.Outcome == VideoPlaybackOutcome.NotSupported)
            return new AreaReport([], "Not supported: " + r.Reason, DiagnosticStatus.Warning) { NotOnThisPc = true };
        var headline = StressHeadline(r, o);
        if (r.Outcome == VideoPlaybackOutcome.CouldNotRun)
            return new AreaReport([], headline, DiagnosticStatus.Error) { CouldNotRunReason = r.Reason ?? "The video couldn't be played." };

        string[] columns = ["Stream", "Played", "Frames", "Late", "Dropped", "Decoded on", "Audio glitches", "Worst delay", "Result"];
        var rows = r.Streams.Select(s => new AreaRow(StreamLevel(s, o),
        [
            s.Index.ToString(CultureInfo.InvariantCulture),
            Clock(s.Ran) + (s.StartedAt > TimeSpan.FromSeconds(1) ? $" (from {Clock(s.StartedAt)})" : ""),
            s.Frames.ToString("N0", CultureInfo.InvariantCulture),
            $"{s.LateFrames:N0} ({s.LatePercent:0.#}%)",
            $"{s.DroppedFrames:N0} ({s.DroppedPercent:0.#}%)",
            s.Frames == 0 ? "—" : !s.SoftwareDecode ? "Graphics chip" : s.GraphicsChipFrames == 0 ? "Processor" : $"Mixed ({s.GraphicsChipFrames * 100 / s.Frames}% graphics chip)",
            r.Clip?.HasAudio == false ? "—" : s.AudioGlitches.ToString("N0", CultureInfo.InvariantCulture),
            $"{s.WorstLag.TotalMilliseconds:0} ms",
            StreamText(s),
        ], SortKeys: [s.Index.ToString("D2", CultureInfo.InvariantCulture), null, null, null, s.DroppedPercent.ToString("000.000", CultureInfo.InvariantCulture), null, null, null, null],
        Key: "stream-" + s.Index.ToString(CultureInfo.InvariantCulture), Detail: s.Error)).ToList();

        var level = Level(r.Outcome);
        var note = r.Outcome switch
        {
            VideoPlaybackOutcome.TooManyDropped => $"At least one stream dropped more than {o.DropFailPercent:0}% of its frames: the PC couldn't keep up with {Plural(r.MostStreams, "video")} at once. "
                + (r.SoftwareDecode ? "The video was decoded on the processor, which is much slower: update the graphics driver. " : "")
                + "Try fewer streams; if even one or two stutter, update the graphics driver, check the temperature, and close other apps.",
            VideoPlaybackOutcome.DecoderCrashed => "The video decoder failed during playback (" + (r.Reason ?? "no reason given") + "). Update the graphics driver and run it again; "
                + "if it keeps happening, videos may freeze or crash in other apps too.",
            VideoPlaybackOutcome.DriverReset => "Windows reset the graphics driver during playback (" + (r.Reason ?? "device removed") + "). The screen may have flickered. Update the graphics driver "
                + "and run it again; if it keeps happening the graphics hardware may be faulty. Crashes & unexpected restarts shows the resets Windows logged.",
            VideoPlaybackOutcome.SoftwareDecode => "The video was decoded by the processor, not the graphics chip. That uses more battery and makes video stutter sooner. "
                + "Update (or reinstall) the graphics driver; Windows' basic display driver can't decode video on the graphics chip.",
            VideoPlaybackOutcome.Overheated => "The test stopped early to protect the PC. Check that the fans spin and the vents aren't blocked, then run it again.",
            _ => r.Reason,
        };
        var card = new AreaCard("playback", "Video playback", level, headline, StressMeta(r), columns, rows,
            EmptyText: "No stream played.", Note: note, PreserveRowOrder: true);
        if (r.Outcome is VideoPlaybackOutcome.DriverReset or VideoPlaybackOutcome.DecoderCrashed)
            card = card with { RunCheck = new AreaCheckLink(ModuleSlugs.Crashes, "Check graphics driver crashes") };
        var status = AreaReport.Worst([level]);
        return new AreaReport([card], headline, status)
        {
            KeyMetrics =
            [
                new KeyMetric("DroppedPercent", "Video frames dropped", Math.Round(r.WorstStreamDroppedPercent, 2), "%", MetricTrend.LowerIsBetter),
                new KeyMetric("Streams", "Video streams played at once", r.MostStreams, "", MetricTrend.Neutral),
                .. r.DecodeEnginePeakPercent is { } peak ? [new KeyMetric("DecodeEnginePeak", "Video decode engine peak load", peak, "%", MetricTrend.Neutral)] : Array.Empty<KeyMetric>(),
            ],
        };
    }

    public static string StressHeadline(VideoPlaybackResult r, VideoPlaybackOptions? options = null)
    {
        var o = options ?? new VideoPlaybackOptions();
        var what = $"{Plural(r.MostStreams, "stream")} of {r.Clip?.Label ?? "video"} for {Clock(r.Ran)}";
        var worst = r.Streams.Count == 0 ? null : r.Streams.MaxBy(s => s.DroppedPercent);
        return r.Outcome switch
        {
            VideoPlaybackOutcome.Passed => $"Passed: {what}, {r.DroppedPercent:0.#}% of frames dropped, decoded on the graphics chip",
            VideoPlaybackOutcome.SoftwareDecode => $"Decoded on the processor, not the graphics chip: {what}, {r.DroppedPercent:0.#}% of frames dropped",
            VideoPlaybackOutcome.TooManyDropped => $"Failed: stream {worst?.Index} dropped {worst?.DroppedPercent:0.#}% of its frames (over {o.DropFailPercent:0}%) with {what}",
            VideoPlaybackOutcome.DecoderCrashed => $"Failed: the video decoder failed during playback ({what})",
            VideoPlaybackOutcome.DriverReset => "Failed: the graphics driver stopped responding during playback (device removed)",
            VideoPlaybackOutcome.Overheated => $"Stopped early: the PC got too hot ({what})",
            VideoPlaybackOutcome.NotSupported => "Not supported: " + r.Reason,
            VideoPlaybackOutcome.Cancelled => "Cancelled",
            _ => "Couldn't run: " + r.Reason,
        };
    }

    private static string StressMeta(VideoPlaybackResult r)
    {
        var parts = new List<string>();
        if (r.Clip is { } c) parts.Add(c.Label + (c.HasAudio ? " with audio" : ""));
        if (r.Streams.Select(s => s.DecoderName).FirstOrDefault(n => !string.IsNullOrWhiteSpace(n)) is { } dec) parts.Add("decoder: " + dec);
        parts.Add(r.DecodeEngineAveragePercent is { } avg
            ? $"video decode engine {avg:0}% on average, {r.DecodeEnginePeakPercent:0}% at peak"
            : "video decode engine load not reported");
        parts.Add($"{r.Frames:N0} frames, {r.LateFrames:N0} late, {r.DroppedFrames:N0} dropped");
        if (r.Clip?.HasAudio == true) parts.Add(r.AudioGlitches == 0 ? "no audio glitches" : Plural((int)Math.Min(r.AudioGlitches, int.MaxValue), "audio glitch", "audio glitches"));
        parts.Add(r.MaxTemperatureC is { } t ? $"GPU up to {t:0}°C" + (r.StartTemperatureC is { } s ? $" (started at {s:0}°C)" : "") : "GPU temperature not reported");
        return string.Join(" · ", parts);
    }

    public static AreaLevel StreamLevel(VideoStreamResult s, VideoPlaybackOptions o) => s.End switch
    {
        VideoStreamEnd.Crashed or VideoStreamEnd.DriverReset or VideoStreamEnd.Hung => AreaLevel.Error,
        _ when s.DroppedPercent > o.DropFailPercent => AreaLevel.Error,
        _ when s.SoftwareDecode || s.DroppedFrames > 0 || s.AudioGlitches > 0 => AreaLevel.Warning,
        _ => AreaLevel.Ok,
    };

    public static string StreamText(VideoStreamResult s) => s.End switch
    {
        VideoStreamEnd.Crashed => "Decoder failed",
        VideoStreamEnd.DriverReset => "Driver reset",
        VideoStreamEnd.Hung => "Stopped responding",
        VideoStreamEnd.Removed => "Removed with −",
        _ => "Played to the end",
    };

    // ---- media apps report ----

    public static AreaReport MediaAppsReport(MediaAppsResult r)
    {
        var playing = r.Playing.ToList();
        string[] columns = ["App", "Playing", "Video decode on the graphics chip", "CPU (one core)", "Result"];
        var rows = r.Apps.Select(a => new AreaRow(AppLevel(a.Verdict),
        [
            a.DisplayName + (a.Processes > 1 ? $" ({a.Processes} processes)" : ""),
            a.Playing ? "Yes" : a.Verdict == MediaAppVerdict.NotPlaying ? "No" : "—",
            !r.EnginesAvailable ? "not reported" : a.DecodePercent >= MediaAppsCheck.DecodeActivePercent ? $"{a.DecodePercent:0.#}%" : "none",
            $"{a.CpuPercentOfCore:0}%",
            AppText(a.Verdict),
        ], SortKeys: [null, null, a.DecodePercent.ToString("000.0", CultureInfo.InvariantCulture), a.CpuPercentOfCore.ToString("0000.0", CultureInfo.InvariantCulture), null],
        Key: a.Name, Detail: a.Advice)).ToList();

        var slow = playing.Where(a => a.Verdict == MediaAppVerdict.ProcessorDecode).ToList();
        string headline;
        AreaLevel level;
        if (playing.Count == 0)
        {
            var why = "nothing was playing. Start a video in the app you want checked (a browser, VLC, Spotify), then run this again";
            var empty = new AreaCard("media-apps", "Media apps", AreaLevel.Neutral, "Skipped: " + why, MediaMeta(r), columns, rows,
                EmptyText: "No media app is open.", PreserveRowOrder: true);
            return new AreaReport([empty], "Skipped: " + why, DiagnosticStatus.Ok) { NotOnThisPc = true };
        }
        if (slow.Count > 0)
        {
            level = AreaLevel.Warning;
            headline = slow.Count == 1
                ? $"{slow[0].DisplayName} is decoding video on the processor ({slow[0].CpuPercentOfCore:0}% of a core, no video decode engine use)"
                : $"{string.Join(", ", slow.Select(a => a.DisplayName))} are decoding video on the processor";
        }
        else
        {
            level = AreaLevel.Ok;
            var gpu = playing.Where(a => a.Verdict == MediaAppVerdict.GraphicsChip).Select(a => a.DisplayName).ToList();
            headline = gpu.Count > 0
                ? $"Video decoded on the graphics chip: {string.Join(", ", gpu)}"
                : $"Playing with light processor load: {string.Join(", ", playing.Select(a => a.DisplayName))}";
            if (!r.EnginesAvailable) headline += " (this PC doesn't report the video decode engine)";
        }
        var note = slow.Count == 0 ? null
            : "Decoding on the processor uses more battery, makes the fan run and drops frames sooner. " + string.Join(" ", slow.Select(a => $"{a.DisplayName}: {a.Advice}"));
        var card = new AreaCard("media-apps", "Media apps", level, headline, MediaMeta(r), columns, rows, EmptyText: "No media app is open.", Note: note, PreserveRowOrder: true);
        return new AreaReport([card], headline, AreaReport.Worst([level]))
        {
            KeyMetrics = [new KeyMetric("ProcessorDecodeApps", "Apps decoding video on the processor", slow.Count, "", MetricTrend.LowerIsBetter)],
        };
    }

    private static string MediaMeta(MediaAppsResult r)
    {
        var parts = new List<string> { $"Watched for {r.Window.TotalSeconds:0} s" };
        if (!r.SessionsAvailable) parts.Add("Windows listed no media sessions, so only apps using the video decode engine count as playing");
        if (!r.EnginesAvailable) parts.Add("video decode engine load not reported on this PC");
        if (r.OtherDecodePercent >= MediaAppsCheck.DecodeActivePercent) parts.Add($"Windows itself decoding {r.OtherDecodePercent:0.#}%");
        return string.Join(" · ", parts);
    }

    public static AreaLevel AppLevel(MediaAppVerdict v) => v switch
    {
        MediaAppVerdict.ProcessorDecode => AreaLevel.Warning,
        MediaAppVerdict.GraphicsChip or MediaAppVerdict.LightLoad => AreaLevel.Ok,
        _ => AreaLevel.Neutral,
    };

    public static string AppText(MediaAppVerdict v) => v switch
    {
        MediaAppVerdict.GraphicsChip => "Decoded on the graphics chip",
        MediaAppVerdict.ProcessorDecode => "Decoding on the processor",
        MediaAppVerdict.LightLoad => "Light load",
        _ => "Not playing",
    };

    public static string ModeArg(VideoPlaybackMode m) => m == VideoPlaybackMode.MediaApps ? "media-apps" : "stress";

    public static string Clock(TimeSpan t) => t.TotalMinutes >= 1 ? $"{(int)t.TotalMinutes} min {t.Seconds} s" : $"{t.Seconds} s";

    private static string Percent(long part, long whole) => whole == 0 ? "0%" : (part * 100.0 / whole).ToString("0.#", CultureInfo.InvariantCulture) + "%";

    private sealed class InlineProgress(Action<VideoPlaybackProgress> a) : IProgress<VideoPlaybackProgress> { public void Report(VideoPlaybackProgress value) => a(value); }
}
