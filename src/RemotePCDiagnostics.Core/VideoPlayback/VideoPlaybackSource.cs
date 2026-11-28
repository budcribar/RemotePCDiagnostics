namespace RemotePCDiagnostics.Core.VideoPlayback;

/// <summary>
/// What the video playback test reads and drives: the bundled test clip and its decoders, the graphics chip's engine load per process,
/// the processes' CPU time and the media sessions Windows knows about. The app's source is Media Foundation and PDH (Host); record and
/// replay wrap it (<see cref="Recording.RecordingVideoPlaybackSource"/>), and tests use a simulated decoder.
/// </summary>
public interface IVideoPlaybackSource
{
    /// <summary>The bundled test clip, or null when it is missing from this install.</summary>
    VideoClipInfo? Clip { get; }

    /// <summary>Opens one more decoder on the clip (stream <paramref name="index"/>, from 1). Throws <see cref="VideoPlaybackUnavailableException"/>
    /// when this PC can't decode it at all, or <see cref="Stress.GpuDeviceLostException"/> when the graphics driver was reset.</summary>
    IVideoStreamDecoder OpenStream(int index);

    /// <summary>Starts measuring the graphics chip's engines. Each <see cref="IGpuEngineMeter.Sample"/> answers the load since the previous one.</summary>
    IGpuEngineMeter OpenEngineMeter();

    /// <summary>The signed-in user's processes with their CPU time so far (processes Windows won't open are left out).</summary>
    IReadOnlyList<MediaProcess> ReadProcesses();

    /// <summary>The media sessions Windows shows in its volume flyout (the app and whether it is playing). Empty when Windows can't list them.</summary>
    IReadOnlyList<MediaSessionInfo> ReadMediaSessions();

    /// <summary>This app's own process id (its decode load is the stress test's), and the number of logical processors.</summary>
    int SelfProcessId { get; }
    int LogicalProcessors { get; }
}

/// <summary>One decoder playing the clip in a loop. <see cref="Next"/> blocks until the next decoded audio or video sample is ready.</summary>
public interface IVideoStreamDecoder : IDisposable
{
    VideoStreamInfo Info { get; }

    /// <summary>The next decoded sample. Throws <see cref="Stress.GpuDeviceLostException"/> when Windows reset the graphics driver (TDR) or the
    /// device was removed, and any other exception when the decoder itself failed.</summary>
    DecodedSample Next();
}

/// <summary>Load per graphics engine and process since the previous call (the first call starts the measurement and may be empty).</summary>
public interface IGpuEngineMeter : IDisposable
{
    IReadOnlyList<GpuEngineLoad> Sample();
}

public sealed class VideoPlaybackUnavailableException(string message, bool notSupported = true) : Exception(message)
{
    /// <summary>True when this PC can't play the clip at all (no decoder, Remote Desktop only, no media features): Not supported, not a fault.</summary>
    public bool NotSupported { get; } = notSupported;
}

/// <summary>No clip, no decoders, no counters (a build or test with no Media Foundation).</summary>
public sealed class NoVideoPlaybackSource : IVideoPlaybackSource
{
    public VideoClipInfo? Clip => null;
    public IVideoStreamDecoder OpenStream(int index) => throw new VideoPlaybackUnavailableException("Video decoding isn't available on this build.");
    public IGpuEngineMeter OpenEngineMeter() => new NoMeter();
    public IReadOnlyList<MediaProcess> ReadProcesses() => [];
    public IReadOnlyList<MediaSessionInfo> ReadMediaSessions() => [];
    public int SelfProcessId => Environment.ProcessId;
    public int LogicalProcessors => Environment.ProcessorCount;

    private sealed class NoMeter : IGpuEngineMeter
    {
        public IReadOnlyList<GpuEngineLoad> Sample() => [];
        public void Dispose() { }
    }
}
