using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using RemotePCDiagnostics.Core.Stress;
using RemotePCDiagnostics.Core.VideoPlayback;
using SharpGen.Runtime;
using Vortice.Direct3D;
using Vortice.Direct3D11;
using Vortice.MediaFoundation;

namespace RemotePCDiagnostics.Host.Video;

/// <summary>
/// The video playback test on Windows. Each stream is a Media Foundation source reader on the bundled clip, sharing one Direct3D 11 device
/// (through a DXGI device manager) the way a player does, so Windows picks the graphics chip's decoder when it has one. A frame that comes back
/// as a DXGI surface was decoded on the graphics chip; one in system memory was decoded by the processor. Engine loads come from the "GPU
/// Engine" performance counters (PDH), CPU times from the process list, and playing apps from Windows' media controls. Nothing needs admin.
/// </summary>
public sealed class MediaFoundationVideoSource(ILogger? log = null, string? clipPath = null) : IVideoPlaybackSource, IDisposable
{
    /// <summary>Where the bundled clip lands next to the exe (RemotePCDiagnostics.Host.csproj links it there).</summary>
    public const string RelativeClipPath = @"media\playback-test-1080p30.mp4";

    // Media Foundation GUIDs (mfapi.h / mfreadwrite.h / mftransform.h), spelled out so they don't depend on wrapper names.
    private static readonly Guid MajorType = new("48eba18e-f8c9-4687-bf11-0a74c9f96a8f");
    private static readonly Guid Subtype = new("f7e34c9a-42e8-4714-b74b-cb29d72c35e5");
    private static readonly Guid MediaTypeVideo = new("73646976-0000-0010-8000-00aa00389b71");
    private static readonly Guid MediaTypeAudio = new("73647561-0000-0010-8000-00aa00389b71");
    private static readonly Guid FormatNv12 = new("3231564e-0000-0010-8000-00aa00389b71");
    private static readonly Guid FormatFloat = new("00000003-0000-0010-8000-00aa00389b71");
    private static readonly Guid ReaderD3DManager = new("ec822da2-e1e9-4b29-a0d8-563c719f5269");
    private static readonly Guid EnableHardwareTransforms = new("a634a91c-822b-41b9-a494-4de4643612b0");
    private static readonly Guid MftFriendlyName = new("314ffbae-5b41-4c95-9c19-4e7d586face3");
    private static readonly Guid MftHardwareUrl = new("2fb866ac-b078-4942-ab6c-003d05cda674");
    private const int DxgiDeviceRemoved = unchecked((int)0x887A0005), DxgiDeviceHung = unchecked((int)0x887A0006), DxgiDeviceReset = unchecked((int)0x887A0007);
    private const int MfTopoCodecNotFound = unchecked((int)0xC00D5212), MfUnsupportedSubtype = unchecked((int)0xC00D36B4);

    private readonly object _gate = new();
    private string ClipFile => clipPath ?? Path.Combine(AppContext.BaseDirectory, RelativeClipPath);
    private bool _started;
    private ID3D11Device? _device;
    private IMFDXGIDeviceManager? _manager;

    public VideoClipInfo? Clip => File.Exists(ClipFile)
        ? new VideoClipInfo(ClipFile, "H.264", 1920, 1080, 30, TimeSpan.FromSeconds(8), HasAudio: true)
        : null;

    public int SelfProcessId => Environment.ProcessId;
    public int LogicalProcessors => Environment.ProcessorCount;

    public IVideoStreamDecoder OpenStream(int index)
    {
        if (!OperatingSystem.IsWindows()) throw new VideoPlaybackUnavailableException("Video decoding needs Windows.");
        var clip = Clip ?? throw new VideoPlaybackUnavailableException("The test video is missing from this install.", notSupported: false);
        var manager = Manager();
        try { return new Decoder(index, clip, manager, Device(), log); }
        catch (SharpGenException ex) when (ex.HResult is MfTopoCodecNotFound or MfUnsupportedSubtype)
        {
            throw new VideoPlaybackUnavailableException($"Windows has no {clip.Codec} video decoder (a Windows N edition without the Media Feature Pack, or a missing codec).");
        }
        catch (SharpGenException ex) when (IsDeviceLost(ex.HResult)) { throw new GpuDeviceLostException(DeviceLostText(ex.HResult)); }
    }

    /// <summary>Starts Media Foundation and opens one Direct3D 11 device with video support for every stream.</summary>
    private IMFDXGIDeviceManager Manager()
    {
        lock (_gate)
        {
            if (_manager is not null) return _manager;
            if (!_started) { MediaFactory.MFStartup(useLightVersion: false).CheckError(); _started = true; }
            var hr = D3D11.D3D11CreateDevice(null, DriverType.Hardware, DeviceCreationFlags.VideoSupport | DeviceCreationFlags.BgraSupport,
                [FeatureLevel.Level_11_1, FeatureLevel.Level_11_0, FeatureLevel.Level_10_1, FeatureLevel.Level_10_0], out ID3D11Device? device);
            if (hr.Failure || device is null)
                throw new VideoPlaybackUnavailableException("No graphics chip with video support is available to this app (Remote Desktop, or only the basic display driver).");
            using (var mt = device.QueryInterfaceOrNull<ID3D11Multithread>()) mt?.SetMultithreadProtected(true);
            var manager = MediaFactory.MFCreateDXGIDeviceManager();
            manager.ResetDevice(device).CheckError();
            _device = device;
            _manager = manager;
            log.Info($"Video playback: D3D11 device level={device.FeatureLevel}");
            return manager;
        }
    }

    private ID3D11Device? Device() { lock (_gate) return _device; }

    internal static bool IsDeviceLost(int hr) => hr is DxgiDeviceRemoved or DxgiDeviceHung or DxgiDeviceReset;
    internal static string DeviceLostText(int hr) => hr switch
    {
        DxgiDeviceHung => "the graphics chip hung (DXGI_ERROR_DEVICE_HUNG)",
        DxgiDeviceReset => "the graphics driver was reset (DXGI_ERROR_DEVICE_RESET)",
        _ => "the graphics device was removed (DXGI_ERROR_DEVICE_REMOVED)",
    };

    public IGpuEngineMeter OpenEngineMeter() => OperatingSystem.IsWindows() ? new PdhEngineMeter() : throw new PlatformNotSupportedException();

    public IReadOnlyList<MediaProcess> ReadProcesses()
    {
        var list = new List<MediaProcess>();
        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                try { list.Add(new MediaProcess(p.Id, p.ProcessName, p.TotalProcessorTime)); }
                catch (Exception) { /* elevated, protected or another user's process: not ours to measure */ }
            }
        }
        return list;
    }

    public IReadOnlyList<MediaSessionInfo> ReadMediaSessions()
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 17763)) return [];
        var task = Windows.Media.Control.GlobalSystemMediaTransportControlsSessionManager.RequestAsync().AsTask();
        if (!task.Wait(TimeSpan.FromSeconds(3))) return [];
        return task.Result.GetSessions().Select(s => new MediaSessionInfo(s.SourceAppUserModelId ?? "",
            s.GetPlaybackInfo()?.PlaybackStatus == Windows.Media.Control.GlobalSystemMediaTransportControlsSessionPlaybackStatus.Playing)).ToList();
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _manager?.Dispose(); _manager = null;
            _device?.Dispose(); _device = null;
            if (_started) { try { MediaFactory.MFShutdown(); } catch (Exception) { } _started = false; }
        }
    }

    /// <summary>One source reader playing the clip in a loop: video as NV12 (the decoder's own output, no conversion), audio as float.</summary>
    private sealed class Decoder : IVideoStreamDecoder
    {
        private readonly IMFSourceReader _reader;
        private readonly ID3D11Device? _device;
        private readonly TimeSpan _length;
        private readonly bool _audio;
        private TimeSpan _offset, _lastTimestamp;
        public VideoStreamInfo Info { get; }

        public Decoder(int index, VideoClipInfo clip, IMFDXGIDeviceManager manager, ID3D11Device? device, ILogger? log)
        {
            _device = device;
            _length = clip.Length;
            using var attrs = MediaFactory.MFCreateAttributes(3);
            attrs.Set(ReaderD3DManager, manager);
            attrs.Set(EnableHardwareTransforms, 1u);
            _reader = MediaFactory.MFCreateSourceReaderFromURL(clip.Path, attrs);
            _reader.SetStreamSelection(SourceReaderIndex.AllStreams, false);
            _reader.SetStreamSelection(SourceReaderIndex.FirstVideoStream, true);
            using (var video = MediaFactory.MFCreateMediaType())
            {
                video.Set(MajorType, MediaTypeVideo);
                video.Set(Subtype, FormatNv12);
                _reader.SetCurrentMediaType(SourceReaderIndex.FirstVideoStream, video);
            }
            if (clip.HasAudio)
            {
                try
                {
                    using var audio = MediaFactory.MFCreateMediaType();
                    audio.Set(MajorType, MediaTypeAudio);
                    audio.Set(Subtype, FormatFloat);
                    _reader.SetStreamSelection(SourceReaderIndex.FirstAudioStream, true);
                    _reader.SetCurrentMediaType(SourceReaderIndex.FirstAudioStream, audio);
                    _audio = true;
                }
                catch (SharpGenException ex)
                {
                    log.Info($"Video playback: stream {index}: no audio decoder ({ex.Message}); video only");
                    _reader.SetStreamSelection(SourceReaderIndex.FirstAudioStream, false);
                }
            }
            var (name, hardware) = DecoderOf(_reader, log);
            Info = new VideoStreamInfo(name, hardware, clip.FramesPerSecond);
            log.Info($"Video playback: stream {index} opened decoder='{name}' hardwareMft={hardware} audio={_audio}");
        }

        /// <summary>The video decoder the reader loaded: its friendly name and whether it is a hardware MFT (the DXVA-accelerated Microsoft
        /// decoder isn't one, so the frames themselves say where decoding ran).</summary>
        private static (string? Name, bool Hardware) DecoderOf(IMFSourceReader reader, ILogger? log)
        {
            try
            {
                using var ex = reader.QueryInterfaceOrNull<IMFSourceReaderEx>();
                if (ex is null) return (null, false);
                ex.GetTransformForStream((int)SourceReaderIndex.FirstVideoStream, 0, out _, out var mft).CheckError();
                using (mft)
                using (var a = mft!.Attributes)
                {
                    string? name = null;
                    try { name = a.GetString(MftFriendlyName); } catch (SharpGenException) { }
                    var hw = false;
                    try { hw = !string.IsNullOrEmpty(a.GetString(MftHardwareUrl)); } catch (SharpGenException) { }
                    return (name, hw);
                }
            }
            catch (Exception e) { log.Info($"Video playback: decoder name unavailable: {e.Message}"); return (null, false); }
        }

        public DecodedSample Next()
        {
            for (var guard = 0; guard < 64; guard++)
            {
                IMFSample? sample;
                int stream;
                SourceReaderFlag flags;
                long time;
                try { sample = _reader.ReadSample(SourceReaderIndex.AnyStream, SourceReaderControlFlag.None, out stream, out flags, out time); }
                catch (SharpGenException ex) when (IsDeviceLost(ex.HResult) || DeviceRemoved() is not null)
                {
                    throw new GpuDeviceLostException(DeviceRemoved() ?? DeviceLostText(ex.HResult), ex);
                }
                using (sample)
                {
                    if ((flags & SourceReaderFlag.Error) != 0) throw new InvalidOperationException("The video decoder reported an error.");
                    if ((flags & SourceReaderFlag.EndOfStream) != 0)
                    {
                        // Loop: start over, one frame after the last timestamp so the next pass follows on.
                        _offset += _lastTimestamp + TimeSpan.FromSeconds(1 / Math.Max(1, Info.FramesPerSecond));
                        _lastTimestamp = TimeSpan.Zero;
                        _reader.SetCurrentPosition(0);
                        continue;
                    }
                    if (sample is null) continue; // a stream tick or a media type change
                    var ts = TimeSpan.FromTicks(time);
                    if (ts > _lastTimestamp) _lastTimestamp = ts;
                    var isVideo = stream == VideoStreamIndex();
                    var onChip = false;
                    if (isVideo)
                    {
                        using var buffer = sample.GetBufferByIndex(0);
                        using var dxgi = buffer.QueryInterfaceOrNull<IMFDXGIBuffer>();
                        onChip = dxgi is not null;
                    }
                    return new DecodedSample(isVideo ? DecodedSampleKind.Video : DecodedSampleKind.Audio, _offset + ts, onChip);
                }
            }
            throw new InvalidOperationException("The video decoder returned no samples.");
        }

        private int _videoStream = -1;
        private int VideoStreamIndex()
        {
            if (_videoStream >= 0) return _videoStream;
            // The reader numbers streams as the file does; find the selected video one once.
            for (var i = 0; i < 8; i++)
            {
                try
                {
                    using var t = _reader.GetCurrentMediaType(i);
                    if (t.GetGUID(MajorType) == MediaTypeVideo) return _videoStream = i;
                }
                catch (SharpGenException) { break; }
            }
            return _videoStream = 0;
        }

        private string? DeviceRemoved()
        {
            if (_device is null) return null;
            var reason = _device.DeviceRemovedReason;
            return reason.Success ? null : DeviceLostText(reason.Code);
        }

        public void Dispose() => _reader.Dispose();
    }

    /// <summary>"\GPU Engine(*)\Utilization Percentage": one instance per process and engine ("pid_1234_luid_…_engtype_VideoDecode").</summary>
    private sealed class PdhEngineMeter : IGpuEngineMeter
    {
        private readonly IntPtr _query, _counter;

        public PdhEngineMeter()
        {
            if (PdhOpenQuery(null, IntPtr.Zero, out _query) != 0) throw new InvalidOperationException("PdhOpenQuery failed");
            if (PdhAddEnglishCounter(_query, @"\GPU Engine(*)\Utilization Percentage", IntPtr.Zero, out _counter) != 0)
            {
                PdhCloseQuery(_query);
                throw new InvalidOperationException("This PC has no GPU Engine counters.");
            }
        }

        public IReadOnlyList<GpuEngineLoad> Sample()
        {
            if (PdhCollectQueryData(_query) != 0) return [];
            uint size = 0;
            var status = PdhGetFormattedCounterArray(_counter, PdhFmtDouble | PdhFmtNoCap100, ref size, out var count, IntPtr.Zero);
            if (status != PdhMoreData || size == 0) return [];
            var buffer = Marshal.AllocHGlobal((int)size);
            try
            {
                if (PdhGetFormattedCounterArray(_counter, PdhFmtDouble | PdhFmtNoCap100, ref size, out count, buffer) != 0) return [];
                var list = new List<GpuEngineLoad>((int)count);
                var itemSize = Marshal.SizeOf<PdhFmtCounterValueItem>();
                for (var i = 0; i < count; i++)
                {
                    var item = Marshal.PtrToStructure<PdhFmtCounterValueItem>(buffer + i * itemSize);
                    if (item.Status is not (0 or 1)) continue;
                    var name = Marshal.PtrToStringUni(item.Name) ?? "";
                    if (GpuEngineLoad.ParseInstance(name) is { } x) list.Add(new GpuEngineLoad(x.Pid, x.Engine, item.Value));
                }
                return list;
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        public void Dispose() => PdhCloseQuery(_query);

        private const uint PdhFmtDouble = 0x00000200, PdhFmtNoCap100 = 0x00008000, PdhMoreData = 0x800007D2;

        [StructLayout(LayoutKind.Sequential)]
        private struct PdhFmtCounterValueItem { public IntPtr Name; public uint Status; public uint Pad; public double Value; }

        [DllImport("pdh.dll", CharSet = CharSet.Unicode)] private static extern uint PdhOpenQuery(string? source, IntPtr user, out IntPtr query);
        [DllImport("pdh.dll", CharSet = CharSet.Unicode, EntryPoint = "PdhAddEnglishCounterW")] private static extern uint PdhAddEnglishCounter(IntPtr query, string path, IntPtr user, out IntPtr counter);
        [DllImport("pdh.dll")] private static extern uint PdhCollectQueryData(IntPtr query);
        [DllImport("pdh.dll", CharSet = CharSet.Unicode, EntryPoint = "PdhGetFormattedCounterArrayW")]
        private static extern uint PdhGetFormattedCounterArray(IntPtr counter, uint format, ref uint bufferSize, out uint itemCount, IntPtr items);
        [DllImport("pdh.dll")] private static extern uint PdhCloseQuery(IntPtr query);
    }
}
