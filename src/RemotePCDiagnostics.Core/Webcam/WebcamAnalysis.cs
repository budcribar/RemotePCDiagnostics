namespace RemotePCDiagnostics.Core.Webcam;

/// <summary>Pure frame maths for the webcam test (no hardware, unit-testable).</summary>
public static class WebcamMath
{
    /// <summary>Width of the luma thumbnail that is analysed (keeps CPU and memory small).</summary>
    public const int ThumbWidth = 160;

    /// <summary>Downsamples a BGRA8 image to an 8-bit luma thumbnail (nearest pixel, BT.601 weights). Returns the thumbnail size.</summary>
    public static (int Width, int Height) LumaFromBgra(ReadOnlySpan<byte> bgra, int width, int height, int stride, byte[] dest, int thumbWidth = ThumbWidth)
    {
        if (width <= 0 || height <= 0) return (0, 0);
        var tw = Math.Min(thumbWidth, width);
        var th = Math.Max(1, (int)((long)height * tw / width));
        if (dest.Length < tw * th) throw new ArgumentException("Destination too small.", nameof(dest));
        for (var y = 0; y < th; y++)
        {
            var sy = (int)((long)y * height / th);
            for (var x = 0; x < tw; x++)
            {
                var o = sy * stride + (int)((long)x * width / tw) * 4;
                if (o + 2 >= bgra.Length) { dest[y * tw + x] = 0; continue; }
                dest[y * tw + x] = (byte)((29 * bgra[o] + 150 * bgra[o + 1] + 77 * bgra[o + 2]) >> 8);
            }
        }
        return (tw, th);
    }

    public static int ThumbHeight(int width, int height, int thumbWidth = ThumbWidth) =>
        width <= 0 ? 0 : Math.Max(1, (int)((long)height * Math.Min(thumbWidth, width) / width));
}

public sealed record WebcamStats(int Frames, TimeSpan Duration, double Fps, double MeanBrightness, double MeanContrast,
    double BlackFraction, double FrozenFraction, double OverexposedFraction, double Sharpness, int Stalls, TimeSpan LongestGap, int EstimatedDropped)
{
    public static WebcamStats Empty { get; } = new(0, TimeSpan.Zero, 0, 0, 0, 0, 0, 0, 0, 0, TimeSpan.Zero, 0);
}

/// <summary>
/// Streaming analysis: fed one luma thumbnail at a time, keeps only running sums and the previous frame (bounded memory).
/// Not thread-safe; the host serialises frames.
/// </summary>
public sealed class WebcamAnalyzer(double expectedFps)
{
    /// <summary>Mean luma below this with low contrast = a black frame (covered lens, shutter closed).</summary>
    public const double BlackMean = 16;
    public const double BlackMaxStdDev = 6;
    /// <summary>Mean absolute difference to the previous frame below this (0..255) = identical / frozen frame. Real sensors always have some noise.</summary>
    public const double FrozenDiff = 0.25;
    /// <summary>Pixels at or above this luma count as blown out.</summary>
    public const byte OverexposedLuma = 250;
    /// <summary>A frame is overexposed when at least this fraction of its pixels is blown out.</summary>
    public const double OverexposedPixelFraction = 0.5;
    /// <summary>A gap between frames longer than this is a stall.</summary>
    public static readonly TimeSpan StallGap = TimeSpan.FromSeconds(1);

    private readonly double _expectedFps = expectedFps > 0 ? expectedFps : 30;
    private byte[]? _prev;
    private int _frames, _black, _frozen, _over, _compared, _stalls, _dropped;
    private double _sumMean, _sumStd, _sumSharp;
    private TimeSpan? _first, _last;
    private TimeSpan _longestGap;

    public int Frames => _frames;

    public void Add(in WebcamFrame f)
    {
        var n = f.Width * f.Height;
        if (n <= 0 || f.Luma.Length < n) return;
        var px = f.Luma.AsSpan(0, n);
        double sum = 0, sumSq = 0; var over = 0;
        foreach (var v in px) { sum += v; sumSq += v * v; if (v >= OverexposedLuma) over++; }
        var mean = sum / n;
        var std = Math.Sqrt(Math.Max(0, sumSq / n - mean * mean));
        _sumMean += mean; _sumStd += std; _sumSharp += Sharpness(px, f.Width, f.Height);
        if (mean < BlackMean && std < BlackMaxStdDev) _black++;
        if ((double)over / n >= OverexposedPixelFraction) _over++;

        if (_prev is not null && _prev.Length == n)
        {
            long diff = 0;
            for (var i = 0; i < n; i++) diff += Math.Abs(px[i] - _prev[i]);
            _compared++;
            if ((double)diff / n < FrozenDiff) _frozen++;
        }
        if (_prev is null || _prev.Length != n) _prev = new byte[n];
        px.CopyTo(_prev);

        if (_last is { } last)
        {
            var gap = f.Timestamp - last;
            if (gap > _longestGap) _longestGap = gap;
            if (gap > StallGap) _stalls++;
            var expected = 1.0 / _expectedFps;
            var missing = (int)Math.Round(gap.TotalSeconds / expected) - 1;
            if (missing > 0) _dropped += missing;
        }
        _first ??= f.Timestamp;
        _last = f.Timestamp;
        _frames++;
    }

    /// <summary>Mean absolute Laplacian (4-neighbour): higher = sharper. 0 for flat images.</summary>
    public static double Sharpness(ReadOnlySpan<byte> px, int w, int h)
    {
        if (w < 3 || h < 3) return 0;
        long s = 0;
        for (var y = 1; y < h - 1; y++)
            for (var x = 1; x < w - 1; x++)
            {
                var i = y * w + x;
                s += Math.Abs(4 * px[i] - px[i - 1] - px[i + 1] - px[i - w] - px[i + w]);
            }
        return (double)s / ((w - 2) * (h - 2));
    }

    /// <param name="window">Capture window (used for FPS when fewer than two frames arrived, and for a stall at the end).</param>
    public WebcamStats Result(TimeSpan window)
    {
        if (_frames == 0) return WebcamStats.Empty with { Duration = window };
        var span = (_last!.Value - _first!.Value);
        var fps = _frames > 1 && span > TimeSpan.Zero ? (_frames - 1) / span.TotalSeconds : _frames / Math.Max(window.TotalSeconds, 1e-3);
        return new WebcamStats(_frames, window, Math.Round(fps, 1), Math.Round(_sumMean / _frames, 1), Math.Round(_sumStd / _frames, 1),
            (double)_black / _frames, _compared == 0 ? 0 : (double)_frozen / _compared, (double)_over / _frames, Math.Round(_sumSharp / _frames, 1),
            _stalls, _longestGap, _dropped);
    }
}

public enum WebcamVerdict
{
    Pass,
    LowFps,
    Stalled,
    Dark,
    Overexposed,
    /// <summary>Frames arrive but are black: covered lens or privacy shutter likely.</summary>
    AllBlack,
    Frozen,
    NoFrames,
    AccessDenied,
    Busy,
    DeviceError,
    NoDevice,
}

public static class WebcamVerdicts
{
    public const string PrivacyMessage = "Camera access is blocked by Windows privacy settings (Settings > Privacy & security > Camera, including \"Let desktop apps access your camera\").";
    public const string BusyMessage = "The camera is in use by another app (for example Teams, Zoom or the Camera app). Close that app and run the test again.";

    /// <summary>Most frames black = covered.</summary>
    public const double BlackFractionLimit = 0.9;
    /// <summary>Most frame pairs identical = frozen.</summary>
    public const double FrozenFractionLimit = 0.9;
    /// <summary>Frozen needs at least this many frames to judge.</summary>
    public const int MinFramesForFrozen = 3;
    /// <summary>Effective frame rate below this = warning.</summary>
    public const double MinFps = 10;
    /// <summary>Average brightness below this (but not black) = too dark warning.</summary>
    public const double DarkMean = 40;
    public const double OverexposedFractionLimit = 0.5;

    /// <summary>The decision table for a capture that ran. Order matters: the first match wins.</summary>
    public static WebcamVerdict Decide(WebcamStats s)
    {
        if (s.Frames == 0) return WebcamVerdict.NoFrames;
        if (s.BlackFraction >= BlackFractionLimit) return WebcamVerdict.AllBlack;
        if (s.Frames >= MinFramesForFrozen && s.FrozenFraction >= FrozenFractionLimit) return WebcamVerdict.Frozen;
        if (s.Fps < MinFps) return WebcamVerdict.LowFps;
        if (s.Stalls > 0) return WebcamVerdict.Stalled;
        if (s.OverexposedFraction >= OverexposedFractionLimit) return WebcamVerdict.Overexposed;
        if (s.MeanBrightness < DarkMean) return WebcamVerdict.Dark;
        return WebcamVerdict.Pass;
    }

    /// <summary>Maps a capture exception (or a privacy Deny seen beforehand) to a verdict.</summary>
    public static WebcamVerdict FromException(Exception ex, bool privacyDeny)
    {
        if (ex is WebcamAccessDeniedException or UnauthorizedAccessException || ex.HResult == unchecked((int)0x80070005)) return WebcamVerdict.AccessDenied;
        if (ex is WebcamBusyException || IsBusyHResult(ex.HResult)) return WebcamVerdict.Busy;
        return privacyDeny ? WebcamVerdict.AccessDenied : WebcamVerdict.DeviceError;
    }

    /// <summary>Media Foundation / Win32 codes for "camera in use by another app".</summary>
    public static bool IsBusyHResult(int hr) => unchecked((uint)hr) is
        0xC00DABE4 /* MF_E_VIDEO_RECORDING_DEVICE_PREEMPTED */ or 0xC00DABE5 /* MF_E_VIDEO_RECORDING_DEVICE_LOCKED */ or
        0x80070020 /* ERROR_SHARING_VIOLATION */ or 0x800700AA /* ERROR_BUSY */ or 0xC00D3704 /* MF_E_HW_MFT_FAILED_START_STREAMING */;

    public static DiagnosticStatus StatusOf(WebcamVerdict v) => v switch
    {
        WebcamVerdict.Pass => DiagnosticStatus.Ok,
        WebcamVerdict.LowFps or WebcamVerdict.Stalled or WebcamVerdict.Dark or WebcamVerdict.Overexposed or WebcamVerdict.AllBlack or WebcamVerdict.NoDevice => DiagnosticStatus.Warning,
        _ => DiagnosticStatus.Error,
    };

    public static string MessageOf(WebcamVerdict v, WebcamStats? s = null) => v switch
    {
        WebcamVerdict.Pass => $"Passed: the camera delivered a live picture{(s is null ? "" : $" ({s.Fps:0.#} frames per second)")}.",
        WebcamVerdict.LowFps => $"The camera works, but the frame rate is low{(s is null ? "" : $" ({s.Fps:0.#} fps)")}. A busy PC, poor light or a slow USB port can cause this.",
        WebcamVerdict.Stalled => "The camera works, but the picture paused for over a second during the test (frame stall). Check the USB cable/port or the camera driver.",
        WebcamVerdict.Dark => "The camera works, but the picture is very dark. Check the lighting or whether something partly covers the lens.",
        WebcamVerdict.Overexposed => "The camera works, but the picture is mostly blown out (too bright). Check for a bright light pointing at the camera.",
        WebcamVerdict.AllBlack => "The camera sent only black frames. The lens may be covered or the privacy shutter closed (a slider or a key on many laptops). Open it and run again.",
        WebcamVerdict.Frozen => "The camera sent the same frame over and over (frozen picture). Try unplugging/replugging it or updating the camera driver.",
        WebcamVerdict.NoFrames => "The camera opened but sent no frames. Check the camera driver, or try another USB port.",
        WebcamVerdict.AccessDenied => PrivacyMessage,
        WebcamVerdict.Busy => BusyMessage,
        WebcamVerdict.DeviceError => "Couldn't open the camera. It may have been unplugged, or its driver has a problem.",
        WebcamVerdict.NoDevice => "Skipped: no camera was found on this PC.",
        _ => v.ToString(),
    };
}
