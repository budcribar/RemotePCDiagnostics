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

public sealed record WebcamReport(WebcamVerdict Verdict, string Device, WebcamBus Bus, int Width, int Height, double RequestedFps, string? Format,
    TimeSpan Duration, WebcamStats Stats, string? Notice);
