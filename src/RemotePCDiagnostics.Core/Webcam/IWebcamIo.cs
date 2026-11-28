namespace RemotePCDiagnostics.Core.Webcam;

public enum WebcamBus { Unknown, BuiltIn, Usb }

/// <summary>Color = the ordinary camera; Infrared = an IR sensor (usually the Windows Hello face sign-in camera), tested on its own.</summary>
public enum WebcamKind { Color, Infrared }

/// <param name="Id">Color: the device interface id. Infrared: <see cref="InfraredPrefix"/> + the frame source group id.</param>
public sealed record WebcamDevice(string Id, string Name, WebcamBus Bus, WebcamKind Kind = WebcamKind.Color)
{
    public const string InfraredPrefix = "ir:";

    public string Label => Name + (Kind, Bus) switch
    {
        (WebcamKind.Infrared, WebcamBus.BuiltIn) => " (IR, built-in)",
        (WebcamKind.Infrared, WebcamBus.Usb) => " (IR, USB)",
        (WebcamKind.Infrared, _) => " (IR)",
        (_, WebcamBus.BuiltIn) => " (built-in)",
        (_, WebcamBus.Usb) => " (USB)",
        _ => "",
    };

    public static bool IsInfraredId(string? id) => id?.StartsWith(InfraredPrefix, StringComparison.Ordinal) == true;

    /// <summary>Best-effort: a device interface id containing "USB#" is USB; a camera with a known panel (front/back) is built in.</summary>
    public static WebcamBus GuessBus(string? id, bool hasPanel)
    {
        if (hasPanel) return WebcamBus.BuiltIn;
        if ((id ?? "").Contains("USB#", StringComparison.OrdinalIgnoreCase)) return WebcamBus.Usb;
        return WebcamBus.Unknown;
    }
}

/// <summary>One IR source found in a frame source group, before duplicates are removed.</summary>
/// <param name="SensorKey">What identifies the physical sensor: its device interface id, or the device path in the source id; null if neither.</param>
/// <param name="SourceCount">How many sources the group has (an IR-only group has 1 or 2).</param>
/// <param name="HasColor">The group also has a color stream: a combined sensor group or a camera profile, not the IR camera's own group.</param>
public sealed record WebcamIrCandidate(WebcamDevice Device, string? SensorKey, int SourceCount, bool HasPanel, bool HasColor = false);

public static class WebcamIrSources
{
    /// <summary>
    /// One entry per IR sensor. Windows lists the same Windows Hello sensor in several frame source groups (its own group, a combined
    /// color + IR sensor group, a Studio Effects profile), so two groups with the same sensor or the same name are one camera. The kept entry
    /// is the one Windows says more about (a known panel), then the smallest group. A group that also streams color is only kept when no
    /// IR-only group exists (a depth camera like RealSense), since otherwise it is the same sensor under another name.
    /// </summary>
    public static IReadOnlyList<WebcamDevice> Distinct(IEnumerable<WebcamIrCandidate> candidates)
    {
        var all = candidates.ToList();
        if (all.Any(c => !c.HasColor)) all = all.Where(c => !c.HasColor).ToList();
        var kept = new List<WebcamIrCandidate>();
        foreach (var c in all.OrderByDescending(c => c.HasPanel).ThenBy(c => c.SourceCount))
        {
            var same = kept.Any(k => (c.SensorKey is not null && string.Equals(k.SensorKey, c.SensorKey, StringComparison.OrdinalIgnoreCase))
                || string.Equals(k.Device.Name.Trim(), c.Device.Name.Trim(), StringComparison.OrdinalIgnoreCase));
            if (!same) kept.Add(c);
        }
        return kept.Select(k => k.Device).ToList();
    }

    /// <summary>The device path in a frame source id ("Source#0@\\?\USB#VID…"), or null.</summary>
    public static string? DevicePathOf(string? sourceId) =>
        sourceId is { } id && id.IndexOf('@') is >= 0 and var at && at < id.Length - 1 ? id[(at + 1)..] : null;
}

/// <summary>Windows blocked the camera (privacy settings, E_ACCESSDENIED).</summary>
public sealed class WebcamAccessDeniedException(string message, Exception? inner = null) : Exception(message, inner);
/// <summary>The camera is in use by another app (exclusive control not available).</summary>
public sealed class WebcamBusyException(string message, Exception? inner = null) : Exception(message, inner);
/// <summary>The camera can't be read by a desktop app this way (an IR camera Windows keeps for Windows Hello only).</summary>
public sealed class WebcamNotSupportedException(string message, Exception? inner = null) : Exception(message, inner);
/// <summary>The camera could not be opened or failed while streaming (driver error, unplugged).</summary>
public sealed class WebcamDeviceException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>
/// One analysed frame: an 8-bit luma thumbnail (row-major, <paramref name="Width"/> x <paramref name="Height"/>), not the full image.
/// The buffer may be reused by the caller after the callback returns; it is never stored or sent anywhere.
/// </summary>
public readonly record struct WebcamFrame(int Width, int Height, byte[] Luma, TimeSpan Timestamp);

/// <param name="MaxWidth">Format cap (the host picks the largest format at or below it).</param>
public sealed record WebcamCaptureRequest(string DeviceId, TimeSpan Duration, int MaxWidth, int MaxHeight, int MaxFps, Action<WebcamFrame> OnFrame);

/// <summary>What the camera was opened with. <paramref name="Note"/> = extra info (e.g. shared mode).</summary>
public sealed record WebcamCaptureResult(int Width, int Height, double RequestedFps, string? Format, string? Note = null)
{
    /// <summary>Every format the camera's stream offers (read while it was open), before the test picked one. Empty when it couldn't be read.</summary>
    public IReadOnlyList<WebcamFormat> Formats { get; init; } = [];
    /// <summary>The camera controls (<see cref="WebcamControls.Names"/>), read while it was open. Empty for an IR camera or a shared-mode read.</summary>
    public IReadOnlyList<WebcamControl> Controls { get; init; } = [];
}

/// <summary>One format the camera offers. <paramref name="Subtype"/> is the pixel format (NV12, YUY2, MJPG, L8…).</summary>
public sealed record WebcamFormat(int Width, int Height, double Fps, string? Subtype);

/// <summary>
/// One camera control (pan, tilt, zoom, focus, exposure, brightness…) as the driver reports it. <paramref name="Supported"/> false = the
/// camera doesn't have it. <paramref name="ReadFailed"/> = the driver says it has the control but returned no current value.
/// </summary>
public sealed record WebcamControl(string Name, bool Supported, double Min, double Max, double Step, double? Value, bool AutoSupported, bool? Auto,
    bool ReadFailed = false);

/// <summary>Camera access (Host: Windows.Media.Capture). Implementations never show OS dialogs, never save frames, and honour cancellation.</summary>
public interface IWebcamIo
{
    IReadOnlyList<WebcamDevice> ListDevices();
    /// <summary>True when the Windows camera privacy switch (ConsentStore\webcam) says Deny.</summary>
    bool IsCameraBlockedByPrivacy();
    /// <summary>Opens the camera (an IR one when <see cref="WebcamDevice.IsInfraredId"/>), reads its formats and controls, calls <see cref="WebcamCaptureRequest.OnFrame"/> for each frame (serialised) for the duration, then always closes it.</summary>
    Task<WebcamCaptureResult> CaptureAsync(WebcamCaptureRequest request, CancellationToken ct);
}

/// <summary>No camera (CI, non-Windows): the test reports "no camera".</summary>
public sealed class NullWebcamIo : IWebcamIo
{
    public IReadOnlyList<WebcamDevice> ListDevices() => [];
    public bool IsCameraBlockedByPrivacy() => false;
    public Task<WebcamCaptureResult> CaptureAsync(WebcamCaptureRequest request, CancellationToken ct) => throw new WebcamDeviceException("No camera.");
}
