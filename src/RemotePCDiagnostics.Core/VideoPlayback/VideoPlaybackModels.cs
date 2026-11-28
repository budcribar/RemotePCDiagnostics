using System.Collections.Immutable;
using System.Text.Json.Serialization;

namespace RemotePCDiagnostics.Core.VideoPlayback;

/// <summary>Playback stress (copies of the test clip at once) or the media apps check (what is playing now, and whether its video is decoded
/// on the graphics chip).</summary>
[JsonConverter(typeof(JsonStringEnumConverter<VideoPlaybackMode>))]
public enum VideoPlaybackMode { Stress, MediaApps }

/// <summary>The bundled clip: <see cref="Path"/> on disk, its codec and size, and how long one loop is.</summary>
public sealed record VideoClipInfo(string Path, string Codec, int Width, int Height, double FramesPerSecond, TimeSpan Length, bool HasAudio)
{
    /// <summary>"1080p H.264, 30 fps".</summary>
    [JsonIgnore] public string Label => $"{Height}p {Codec}, {FramesPerSecond:0.#} fps";
}

/// <summary>What one decoder is: the decoder Windows picked (its friendly name), and whether it says it runs on the graphics chip.</summary>
public sealed record VideoStreamInfo(string? DecoderName, bool HardwareDecoder, double FramesPerSecond);

[JsonConverter(typeof(JsonStringEnumConverter<DecodedSampleKind>))]
public enum DecodedSampleKind { Video, Audio }

/// <summary>One decoded sample. <see cref="Timestamp"/> is its place in the endless loop (the clip's time plus every earlier loop), so it is when
/// the sample must be shown or heard counted from the stream's start. <see cref="OnGraphicsChip"/> = the frame came back in graphics memory
/// (decoded by the chip's video engine); false = decoded by the processor.</summary>
public readonly record struct DecodedSample(DecodedSampleKind Kind, TimeSpan Timestamp, bool OnGraphicsChip);

/// <summary>Load of one graphics engine in one process, in percent of that engine (Task Manager's GPU engine columns).</summary>
/// <param name="EngineType">The engine's type as Windows names it ("VideoDecode", "Video Codec", "3D", "Copy", "VideoProcessing").</param>
public sealed record GpuEngineLoad(int ProcessId, string EngineType, double Percent)
{
    /// <summary>Video decode engines: "VideoDecode" (Intel, NVIDIA, Qualcomm) and "Video Codec" (AMD, which decodes and encodes on one engine).</summary>
    [JsonIgnore] public bool IsVideoDecode =>
        EngineType.Contains("Decode", StringComparison.OrdinalIgnoreCase) || EngineType.Contains("Codec", StringComparison.OrdinalIgnoreCase);

    /// <summary>The process id and engine type from a GPU Engine instance name, such as "pid_1234_luid_0x0_0xD1B5_phys_0_eng_3_engtype_VideoDecode".</summary>
    public static (int Pid, string Engine)? ParseInstance(string name)
    {
        const string pidTag = "pid_", engTag = "engtype_";
        var p = name.IndexOf(pidTag, StringComparison.OrdinalIgnoreCase);
        var e = name.IndexOf(engTag, StringComparison.OrdinalIgnoreCase);
        if (p < 0 || e < 0) return null;
        var start = p + pidTag.Length;
        var end = name.IndexOf('_', start);
        if (end < 0 || !int.TryParse(name.AsSpan(start, end - start), out var pid)) return null;
        return (pid, name[(e + engTag.Length)..]);
    }
}

/// <summary>A process with its CPU time so far (user + kernel). <see cref="Name"/> is the exe name without ".exe".</summary>
public sealed record MediaProcess(int ProcessId, string Name, TimeSpan CpuTime);

/// <summary>A media session from Windows' media controls: the app (its app id, such as "Chrome", "MSEdge", "Spotify.exe") and whether it plays now.</summary>
public sealed record MediaSessionInfo(string AppId, bool Playing);

public sealed record VideoPlaybackOptions
{
    public const int MinStreams = 1, MaxStreams = 16, DefaultStreams = 4;
    public static readonly ImmutableArray<int> MinuteChoices = [1, 2, 5, 10];
    public static readonly TimeSpan DefaultDuration = TimeSpan.FromMinutes(2);
    public static TimeSpan MinDuration => TimeSpan.FromMinutes(MinuteChoices[0]);
    public static TimeSpan MaxDuration => TimeSpan.FromMinutes(MinuteChoices[^1]);

    public int Streams { get; init; } = DefaultStreams;
    public TimeSpan Duration { get; init; } = DefaultDuration;

    /// <summary>Failed when a stream drops more than this share of its frames.</summary>
    public double DropFailPercent { get; init; } = 5;
    /// <summary>Like a player's queue, a stream may decode this far ahead of the frame being shown.</summary>
    public TimeSpan Lookahead { get; init; } = TimeSpan.FromMilliseconds(150);
    /// <summary>How often the run reads the engines and the temperature, and adds or removes streams to match the count asked for.</summary>
    public TimeSpan Tick { get; init; } = TimeSpan.FromSeconds(1);
    /// <summary>How long a stream may take to stop before it counts as hung.</summary>
    public TimeSpan StopTimeout { get; init; } = TimeSpan.FromSeconds(10);
    /// <summary>The media apps check watches this long.</summary>
    public TimeSpan MediaAppsWindow { get; init; } = TimeSpan.FromSeconds(5);

    public static int ClampStreams(int n) => Math.Clamp(n, MinStreams, MaxStreams);
    public static TimeSpan ClampDuration(TimeSpan d) => d <= TimeSpan.Zero ? DefaultDuration : d < MinDuration ? MinDuration : d > MaxDuration ? MaxDuration : d;
}

[JsonConverter(typeof(JsonStringEnumConverter<VideoPlaybackOutcome>))]
public enum VideoPlaybackOutcome { Passed, TooManyDropped, DecoderCrashed, DriverReset, SoftwareDecode, Overheated, Cancelled, NotSupported, CouldNotRun }

/// <summary>How a stream ended: still running at the end, removed with −, its decoder failed, the driver was reset, or it never stopped.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<VideoStreamEnd>))]
public enum VideoStreamEnd { Finished, Removed, Crashed, DriverReset, Hung }

/// <summary>One stream's numbers. Late = shown after its time (a stutter); dropped = more than a frame late, so a player would skip it.</summary>
public sealed record VideoStreamResult(
    int Index, TimeSpan StartedAt, TimeSpan Ran, long Frames, long LateFrames, long DroppedFrames, long GraphicsChipFrames,
    long AudioBuffers, long AudioGlitches, TimeSpan WorstLag, string? DecoderName, VideoStreamEnd End, string? Error = null)
{
    [JsonIgnore] public double DroppedPercent => Frames == 0 ? 0 : DroppedFrames * 100.0 / Frames;
    [JsonIgnore] public double LatePercent => Frames == 0 ? 0 : LateFrames * 100.0 / Frames;
    /// <summary>Some frames came back from the processor, not the graphics chip.</summary>
    [JsonIgnore] public bool SoftwareDecode => Frames > 0 && GraphicsChipFrames < Frames;
}

/// <summary>A playback stress run.</summary>
public sealed record VideoPlaybackResult(
    VideoPlaybackOutcome Outcome, TimeSpan Ran, VideoClipInfo? Clip, IReadOnlyList<VideoStreamResult> Streams, int MostStreams,
    double? DecodeEngineAveragePercent, double? DecodeEnginePeakPercent, double? StartTemperatureC, double? MaxTemperatureC, string? Reason = null)
{
    [JsonIgnore] public long Frames => Streams.Sum(s => s.Frames);
    [JsonIgnore] public long DroppedFrames => Streams.Sum(s => s.DroppedFrames);
    [JsonIgnore] public long LateFrames => Streams.Sum(s => s.LateFrames);
    [JsonIgnore] public long AudioGlitches => Streams.Sum(s => s.AudioGlitches);
    [JsonIgnore] public double DroppedPercent => Frames == 0 ? 0 : DroppedFrames * 100.0 / Frames;
    [JsonIgnore] public double WorstStreamDroppedPercent => Streams.Count == 0 ? 0 : Streams.Max(s => s.DroppedPercent);
    [JsonIgnore] public bool SoftwareDecode => Streams.Any(s => s.SoftwareDecode);
}

/// <summary>Live numbers while a stress run goes: the clock, the streams running now, and each stream's counts so far.</summary>
public sealed record VideoPlaybackProgress(
    TimeSpan Elapsed, TimeSpan Duration, int TargetStreams, IReadOnlyList<VideoStreamResult> Streams, double? DecodeEnginePercent, double? GpuTemperatureC)
{
    [JsonIgnore] public double Fraction => Duration <= TimeSpan.Zero ? 0 : Math.Clamp(Elapsed / Duration, 0, 1);
    [JsonIgnore] public int Running => Streams.Count(s => s.End == VideoStreamEnd.Finished);
}

/// <summary>One app in the media apps check. CPU is in percent of one processor core, added up over the app's processes (a browser has many).</summary>
public sealed record MediaAppUsage(
    string Name, string DisplayName, int Processes, bool Playing, bool VideoApp, double CpuPercentOfCore, double DecodePercent, MediaAppVerdict Verdict, string? Advice)
{
    [JsonIgnore] public bool DecodesOnGraphicsChip => DecodePercent >= MediaAppsCheck.DecodeActivePercent;
}

[JsonConverter(typeof(JsonStringEnumConverter<MediaAppVerdict>))]
public enum MediaAppVerdict { GraphicsChip, LightLoad, ProcessorDecode, NotPlaying }

/// <summary>The media apps check: every app that plays media or uses the video decode engine, over <see cref="Window"/>.</summary>
public sealed record MediaAppsResult(TimeSpan Window, IReadOnlyList<MediaAppUsage> Apps, bool SessionsAvailable, bool EnginesAvailable, double OtherDecodePercent)
{
    [JsonIgnore] public IEnumerable<MediaAppUsage> Playing => Apps.Where(a => a.Verdict != MediaAppVerdict.NotPlaying);
}
