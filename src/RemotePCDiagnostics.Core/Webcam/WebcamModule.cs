using System.Diagnostics;

namespace RemotePCDiagnostics.Core.Webcam;

/// <summary>Webcam test: on-demand, own page, not in Run All and not part of the stress run (like the audio tests).</summary>
public interface IWebcamTestModule : IPerDeviceModule
{
    /// <summary>Null = first camera. Used by the module-wide <see cref="IDiagnosticModule.RefreshAsync"/>; a per-device run names its camera.</summary>
    string? DeviceId { get; set; }
    TimeSpan Duration { get; set; }
    IReadOnlyList<WebcamDevice> Devices();
    void Cancel();
}

/// <summary>
/// A camera held by another app means the test never captured a frame: recorded as "Couldn't run", not as a failed camera.
/// </summary>
public sealed record WebcamReport(WebcamVerdict Verdict, string Device, WebcamBus Bus, int Width, int Height, double RequestedFps, string? Format,
    TimeSpan Duration, WebcamStats Stats, string? Notice) : IRunEnd
{
    [System.Text.Json.Serialization.JsonIgnore]
    public RunEnd RunEnd => Verdict is WebcamVerdict.Busy or WebcamVerdict.NotSupported ? RunEnd.CouldNotRun : RunEnd.Finished;

    public WebcamKind Kind { get; init; }
    /// <summary>Every format the camera offers, largest first (<see cref="WebcamCapabilities.Distinct"/>).</summary>
    public IReadOnlyList<WebcamFormat> Formats { get; init; } = [];
    /// <summary>The best format against the camera's class; null when the formats couldn't be read.</summary>
    public WebcamCapabilityCheck? Capability { get; init; }
    public IReadOnlyList<WebcamControl> Controls { get; init; } = [];
    /// <summary>The apps Windows lists as using a camera now: read when the camera was busy or only shared.</summary>
    public IReadOnlyList<WebcamHolder> Holders { get; init; } = [];
    /// <summary>The person's answer to "Do you see yourself?" (null = not asked yet), kept beside the measured <see cref="Verdict"/>.</summary>
    public bool? PersonSawPicture { get; init; }
}
