namespace RemotePCDiagnostics.Core.Webcam;

public enum WebcamBus { Unknown, BuiltIn, Usb }

public sealed record WebcamDevice(string Id, string Name, WebcamBus Bus)
{
    public string Label => Name + Bus switch { WebcamBus.BuiltIn => " (built-in)", WebcamBus.Usb => " (USB)", _ => "" };

    /// <summary>Best-effort: a device interface id containing "USB#" is USB; a camera with a known panel (front/back) is built in.</summary>
    public static WebcamBus GuessBus(string? id, bool hasPanel)
    {
        if (hasPanel) return WebcamBus.BuiltIn;
        if ((id ?? "").Contains("USB#", StringComparison.OrdinalIgnoreCase)) return WebcamBus.Usb;
        return WebcamBus.Unknown;
    }
}

/// <summary>Windows blocked the camera (privacy settings, E_ACCESSDENIED).</summary>
public sealed class WebcamAccessDeniedException(string message, Exception? inner = null) : Exception(message, inner);
/// <summary>The camera is in use by another app (exclusive control not available).</summary>
public sealed class WebcamBusyException(string message, Exception? inner = null) : Exception(message, inner);
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
public sealed record WebcamCaptureResult(int Width, int Height, double RequestedFps, string? Format, string? Note = null);

/// <summary>Camera access (Host: Windows.Media.Capture). Implementations never show OS dialogs, never save frames, and honour cancellation.</summary>
public interface IWebcamIo
{
    IReadOnlyList<WebcamDevice> ListDevices();
    /// <summary>True when the Windows camera privacy switch (ConsentStore\webcam) says Deny.</summary>
    bool IsCameraBlockedByPrivacy();
    /// <summary>Opens the camera, calls <see cref="WebcamCaptureRequest.OnFrame"/> for each frame (serialised) for the duration, then always closes it.</summary>
    Task<WebcamCaptureResult> CaptureAsync(WebcamCaptureRequest request, CancellationToken ct);
}

/// <summary>No camera (CI, non-Windows): the test reports "no camera".</summary>
public sealed class NullWebcamIo : IWebcamIo
{
    public IReadOnlyList<WebcamDevice> ListDevices() => [];
    public bool IsCameraBlockedByPrivacy() => false;
    public Task<WebcamCaptureResult> CaptureAsync(WebcamCaptureRequest request, CancellationToken ct) => throw new WebcamDeviceException("No camera.");
}
