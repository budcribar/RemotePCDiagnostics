using System.Diagnostics;
using System.Runtime.InteropServices.WindowsRuntime;
using Microsoft.Win32;
using RemotePCDiagnostics.Core.Webcam;
using Windows.Devices.Enumeration;
using Windows.Graphics.Imaging;
using Windows.Media.Capture;
using Windows.Media.Capture.Frames;
using Windows.Media.MediaProperties;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// Camera access via WinRT Windows.Media.Capture (MediaCapture + MediaFrameReader), part of the Windows SDK projection the Host already
/// targets (net10.0-windows10.0.19041.0), so no extra package. Frames are reduced to a small luma thumbnail and analysed in memory only;
/// nothing is saved or sent. The camera is always closed (MediaCapture disposed) when the capture ends, fails or is cancelled.
/// </summary>
public sealed class MediaCaptureWebcamIo(ILogger? log = null, bool showPreview = false) : IWebcamIo
{
    private const string ConsentKey = @"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam";

    private void Log(string m) => log.Info("Webcam: " + m);

    public IReadOnlyList<WebcamDevice> ListDevices()
    {
        var list = new List<WebcamDevice>();
        // IR cameras (Windows Hello) live in frame source groups, not always in the video capture class: each one is its own entry.
        var irDeviceIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var g in MediaFrameSourceGroup.FindAllAsync().AsTask().GetAwaiter().GetResult())
            {
                var ir = g.SourceInfos.FirstOrDefault(i => i.SourceKind == MediaFrameSourceKind.Infrared);
                if (ir is null || ir.DeviceInformation?.IsEnabled == false) continue;
                if (ir.DeviceInformation?.Id is { } devId
                    && !g.SourceInfos.Any(i => i.SourceKind == MediaFrameSourceKind.Color
                        && string.Equals(i.DeviceInformation?.Id, devId, StringComparison.OrdinalIgnoreCase)))
                    irDeviceIds.Add(devId);
                var panel = ir.DeviceInformation?.EnclosureLocation is { } e && e.Panel != Panel.Unknown;
                list.Add(new WebcamDevice(WebcamDevice.InfraredPrefix + g.Id, g.DisplayName, WebcamDevice.GuessBus(ir.DeviceInformation?.Id ?? g.Id, panel),
                    WebcamKind.Infrared));
            }
        }
        catch (Exception ex) { Log($"IR source groups: {ex.Message}"); }
        try
        {
            var all = DeviceInformation.FindAllAsync(DeviceClass.VideoCapture).AsTask().GetAwaiter().GetResult();
            foreach (var d in all)
            {
                if (!d.IsEnabled || irDeviceIds.Contains(d.Id)) continue; // an IR-only camera is tested as the IR entry above
                var panel = d.EnclosureLocation is { } e && e.Panel != Panel.Unknown;
                list.Add(new WebcamDevice(d.Id, d.Name, WebcamDevice.GuessBus(d.Id, panel)));
            }
        }
        catch (Exception ex) { Log($"device list: {ex.Message}"); }
        // Built-in color camera first so it is the default; IR cameras last.
        return list.OrderBy(d => d.Kind == WebcamKind.Infrared ? 2 : d.Bus == WebcamBus.BuiltIn ? 0 : 1).ToList();
    }

    public bool IsCameraBlockedByPrivacy()
    {
        static bool Deny(RegistryKey root, string path)
        {
            try { using var k = root.OpenSubKey(path); return string.Equals(k?.GetValue("Value") as string, "Deny", StringComparison.OrdinalIgnoreCase); }
            catch { return false; }
        }
        // Device-wide switch (HKLM), the user's switch, and "Let desktop apps access your camera" (NonPackaged).
        return Deny(Registry.LocalMachine, ConsentKey) || Deny(Registry.CurrentUser, ConsentKey) || Deny(Registry.CurrentUser, ConsentKey + @"\NonPackaged");
    }

    public async Task<WebcamCaptureResult> CaptureAsync(WebcamCaptureRequest request, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        string? note = null;
        MediaCapture? capture = null;
        MediaFrameReader? reader = null;
        WebcamPreview? preview = null;
        var infrared = WebcamDevice.IsInfraredId(request.DeviceId);
        try
        {
            MediaFrameSource? source;
            (capture, source) = await OpenAsync(request.DeviceId, MediaCaptureSharingMode.ExclusiveControl, ct).ConfigureAwait(false);
            if (source is null && infrared) throw new WebcamNotSupportedException("The IR camera has no IR stream this app can read.");
            // What the camera offers, read before a format is picked: every format of the stream, and its controls (color cameras).
            List<WebcamFormat> formats = source is null ? [] : ReadFormats(source);
            List<WebcamControl> controls = infrared ? [] : ReadControls(capture);
            var format = source is null ? null : PickFormat(source, request);
            if (source is not null && format is not null)
            {
                try { await source.SetFormatAsync(format).AsTask(ct).ConfigureAwait(false); }
                catch (Exception ex) when (ex is not OperationCanceledException) { Log($"set format: {ex.Message}"); }
            }
            reader = await CreateReaderAsync(capture, source, infrared, ct).ConfigureAwait(false);
            var status = reader is null ? MediaFrameReaderStartStatus.UnknownFailure : await reader.StartAsync().AsTask(ct).ConfigureAwait(false);
            if (status is MediaFrameReaderStartStatus.ExclusiveControlNotAvailable or MediaFrameReaderStartStatus.DeviceNotAvailable)
            {
                // Another app holds the camera: try read-only sharing (no format change) before calling it busy.
                Log($"start {status}, retrying shared read-only");
                DisposeCapture(ref reader, ref capture);
                (capture, source) = await OpenAsync(request.DeviceId, MediaCaptureSharingMode.SharedReadOnly, ct).ConfigureAwait(false);
                reader = await CreateReaderAsync(capture, source, infrared, ct).ConfigureAwait(false);
                status = reader is null ? MediaFrameReaderStartStatus.UnknownFailure : await reader.StartAsync().AsTask(ct).ConfigureAwait(false);
                if (status != MediaFrameReaderStartStatus.Success) throw new WebcamBusyException($"Frame reader start: {status}");
                controls = [];
                note = "Another app was using the camera, so it was read in shared mode at that app's resolution.";
            }
            else if (status != MediaFrameReaderStartStatus.Success && infrared) throw new WebcamNotSupportedException($"IR frame reader start: {status}");
            else if (status != MediaFrameReaderStartStatus.Success) throw new WebcamDeviceException($"Frame reader start: {status}");

            var cur = source!.CurrentFormat;
            var w = (int)(cur?.VideoFormat?.Width ?? 0);
            var h = (int)(cur?.VideoFormat?.Height ?? 0);
            var fps = cur?.FrameRate is { Denominator: > 0 } fr ? (double)fr.Numerator / fr.Denominator : 0;
            Log($"streaming {w}x{h} {cur?.Subtype} {fps:0.#} fps");

            Exception? failure = null;
            capture.Failed += (_, e) => { failure ??= new WebcamDeviceException($"Camera failed: {e.Message} (0x{e.Code:X8})") { HResult = unchecked((int)e.Code) }; };
            if (showPreview && System.Windows.Application.Current is { } app)
                preview = await app.Dispatcher.InvokeAsync(() => new WebcamPreview());
            var sw = Stopwatch.StartNew();
            var gate = new object();
            var stopped = false;
            byte[]? bgra = null;
            byte[]? luma = null;
            reader!.AcquisitionMode = MediaFrameReaderAcquisitionMode.Realtime;
            reader.FrameArrived += (r, _) =>
            {
                lock (gate)
                {
                    if (stopped) return;
                    try
                    {
                        using var frame = r.TryAcquireLatestFrame();
                        var bmp = frame?.VideoMediaFrame?.SoftwareBitmap;
                        if (bmp is null) return;
                        SoftwareBitmap? conv = null;
                        try
                        {
                            if (bmp.BitmapPixelFormat != BitmapPixelFormat.Bgra8) conv = SoftwareBitmap.Convert(bmp, BitmapPixelFormat.Bgra8);
                            var b = conv ?? bmp;
                            int bw = b.PixelWidth, bh = b.PixelHeight;
                            if (bw <= 0 || bh <= 0 || bw > 4096 || bh > 4096) return;
                            var need = bw * bh * 4;
                            if (bgra is null || bgra.Length != need) bgra = new byte[need]; // one reused buffer (bounded memory)
                            b.CopyToBuffer(bgra.AsBuffer());
                            var th = WebcamMath.ThumbHeight(bw, bh);
                            var tw = Math.Min(WebcamMath.ThumbWidth, bw);
                            if (luma is null || luma.Length != tw * th) luma = new byte[tw * th];
                            WebcamMath.LumaFromBgra(bgra, bw, bh, bw * 4, luma);
                            preview?.ShowFrame(bgra, bw, bh, sw.Elapsed);
                            request.OnFrame(new WebcamFrame(tw, th, luma, sw.Elapsed));
                        }
                        finally { conv?.Dispose(); bmp.Dispose(); }
                    }
                    catch (Exception ex) { failure ??= ex; }
                }
            };
            try { await Task.Delay(request.Duration, ct).ConfigureAwait(false); }
            finally
            {
                lock (gate) stopped = true;
                try { await reader.StopAsync().AsTask(CancellationToken.None).ConfigureAwait(false); } catch { }
            }
            if (failure is not null) throw failure;
            return new WebcamCaptureResult(w, h, fps, cur?.Subtype, note) { Formats = formats, Controls = controls };
        }
        catch (UnauthorizedAccessException ex) { throw new WebcamAccessDeniedException(ex.Message, ex); }
        catch (Exception ex) when (ex is not OperationCanceledException and not WebcamBusyException and not WebcamDeviceException and not WebcamAccessDeniedException
            and not WebcamNotSupportedException)
        {
            if (ex.HResult == unchecked((int)0x80070005)) throw new WebcamAccessDeniedException(ex.Message, ex);
            if (WebcamVerdicts.IsBusyHResult(ex.HResult)) throw new WebcamBusyException(ex.Message, ex);
            throw new WebcamDeviceException(ex.Message, ex);
        }
        finally
        {
            DisposeCapture(ref reader, ref capture);
            preview?.Close();
        }
    }

    private static async Task<(MediaCapture, MediaFrameSource?)> OpenAsync(string deviceId, MediaCaptureSharingMode mode, CancellationToken ct)
    {
        var settings = new MediaCaptureInitializationSettings
        {
            StreamingCaptureMode = StreamingCaptureMode.Video,
            SharingMode = mode,
            MemoryPreference = MediaCaptureMemoryPreference.Cpu,
        };
        var kind = MediaFrameSourceKind.Color;
        if (WebcamDevice.IsInfraredId(deviceId))
        {
            var groupId = deviceId[WebcamDevice.InfraredPrefix.Length..];
            var groups = await MediaFrameSourceGroup.FindAllAsync().AsTask(ct).ConfigureAwait(false);
            settings.SourceGroup = groups.FirstOrDefault(g => g.Id == groupId) ?? throw new WebcamDeviceException("The IR camera is no longer connected.");
            kind = MediaFrameSourceKind.Infrared;
        }
        else settings.VideoDeviceId = deviceId;
        var capture = new MediaCapture();
        try
        {
            await capture.InitializeAsync(settings).AsTask(ct).ConfigureAwait(false);
            var source = capture.FrameSources.Values.FirstOrDefault(s => s.Info.SourceKind == kind && s.Info.MediaStreamType == Windows.Media.Capture.MediaStreamType.VideoRecord)
                ?? capture.FrameSources.Values.FirstOrDefault(s => s.Info.SourceKind == kind);
            return (capture, source);
        }
        catch { capture.Dispose(); throw; }
    }

    /// <summary>Color frames are asked for as BGRA. IR frames come as the camera sends them (L8/L16) and are converted per frame.</summary>
    private static async Task<MediaFrameReader?> CreateReaderAsync(MediaCapture capture, MediaFrameSource? source, bool infrared, CancellationToken ct) =>
        source is null ? null
        : infrared ? await capture.CreateFrameReaderAsync(source).AsTask(ct).ConfigureAwait(false)
        : await capture.CreateFrameReaderAsync(source, MediaEncodingSubtypes.Bgra8).AsTask(ct).ConfigureAwait(false);

    private List<WebcamFormat> ReadFormats(MediaFrameSource source)
    {
        try
        {
            return source.SupportedFormats.Where(f => f.VideoFormat is not null)
                .Select(f => new WebcamFormat((int)f.VideoFormat.Width, (int)f.VideoFormat.Height,
                    f.FrameRate is { Denominator: > 0 } r ? (double)r.Numerator / r.Denominator : 0, f.Subtype))
                .ToList();
        }
        catch (Exception ex) { Log($"formats: {ex.Message}"); return []; }
    }

    /// <summary>Each control's range and current value. A control the driver lists but can't read is kept with ReadFailed set.</summary>
    private List<WebcamControl> ReadControls(MediaCapture capture)
    {
        var list = new List<WebcamControl>();
        Windows.Media.Devices.VideoDeviceController vdc;
        try { vdc = capture.VideoDeviceController; }
        catch (Exception ex) { Log($"controls: {ex.Message}"); return list; }
        foreach (var name in WebcamControls.Names)
        {
            var supported = false;
            try
            {
                var c = name switch
                {
                    "Pan" => vdc.Pan,
                    "Tilt" => vdc.Tilt,
                    "Zoom" => vdc.Zoom,
                    "Focus" => vdc.Focus,
                    "Exposure" => vdc.Exposure,
                    "Brightness" => vdc.Brightness,
                    "Contrast" => vdc.Contrast,
                    _ => vdc.WhiteBalance,
                };
                var caps = c.Capabilities;
                if (!caps.Supported) { list.Add(new WebcamControl(name, false, 0, 0, 0, null, false, null)); continue; }
                supported = true;
                var hasValue = c.TryGetValue(out var value);
                bool? auto = null;
                if (caps.AutoModeSupported && c.TryGetAuto(out var a)) auto = a;
                list.Add(new WebcamControl(name, true, caps.Min, caps.Max, caps.Step, hasValue ? value : null, caps.AutoModeSupported, auto, ReadFailed: !hasValue));
            }
            catch (Exception ex)
            {
                Log($"control {name}: {ex.Message}");
                list.Add(supported
                    ? new WebcamControl(name, true, 0, 0, 0, null, false, null, ReadFailed: true)
                    : new WebcamControl(name, false, 0, 0, 0, null, false, null));
            }
        }
        return list;
    }

    /// <summary>Largest format at or below the resolution and frame-rate caps; null = keep the current one.</summary>
    private static MediaFrameFormat? PickFormat(MediaFrameSource source, WebcamCaptureRequest req) =>
        source.SupportedFormats
            .Where(f => f.VideoFormat is { } v && v.Width <= req.MaxWidth && v.Height <= req.MaxHeight
                && f.FrameRate is { Denominator: > 0 } r && (double)r.Numerator / r.Denominator <= req.MaxFps + 0.5)
            .OrderByDescending(f => (long)f.VideoFormat.Width * f.VideoFormat.Height)
            .ThenByDescending(f => (double)f.FrameRate.Numerator / f.FrameRate.Denominator)
            .FirstOrDefault();

    private void DisposeCapture(ref MediaFrameReader? reader, ref MediaCapture? capture)
    {
        try { reader?.Dispose(); } catch (Exception ex) { Log($"reader dispose: {ex.Message}"); }
        try { capture?.Dispose(); } catch (Exception ex) { Log($"capture dispose: {ex.Message}"); }
        reader = null; capture = null;
    }
}
