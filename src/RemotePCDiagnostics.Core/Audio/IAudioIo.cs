namespace RemotePCDiagnostics.Core.Audio;

public enum AudioFlow { Output, Input }
public enum AudioBus { Unknown, Internal, Usb, Bluetooth }

public sealed record AudioDevice(string Id, string Name, AudioFlow Flow, AudioBus Bus, bool IsDefault)
{
    public string Label => Name + (Bus switch { AudioBus.Usb => " (USB)", AudioBus.Bluetooth => " (Bluetooth)", _ => "" }) + (IsDefault ? " — Windows default" : "");

    /// <summary>Best-effort bus from the PnP enumerator name ("USB", "BTHENUM"/"BTHHFENUM") or, failing that, the device name.</summary>
    public static AudioBus GuessBus(string? enumerator, string? name)
    {
        var e = enumerator ?? "";
        if (e.StartsWith("BTH", StringComparison.OrdinalIgnoreCase)) return AudioBus.Bluetooth;
        if (e.Equals("USB", StringComparison.OrdinalIgnoreCase)) return AudioBus.Usb;
        if (e.Equals("HDAUDIO", StringComparison.OrdinalIgnoreCase) || e.Equals("INTELAUDIO", StringComparison.OrdinalIgnoreCase)) return AudioBus.Internal;
        var n = name ?? "";
        if (n.Contains("Bluetooth", StringComparison.OrdinalIgnoreCase) || n.Contains("Hands-Free", StringComparison.OrdinalIgnoreCase)) return AudioBus.Bluetooth;
        if (n.Contains("USB", StringComparison.OrdinalIgnoreCase)) return AudioBus.Usb;
        return AudioBus.Unknown;
    }
}

/// <summary>Windows blocked the microphone (privacy settings, E_ACCESSDENIED).</summary>
public sealed class AudioAccessDeniedException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>A device could not be opened (in use exclusively, unplugged, driver error).</summary>
public sealed class AudioDeviceException(string message, Exception? inner = null) : Exception(message, inner);

/// <param name="Tone">Mono samples at <paramref name="SampleRate"/> (already faded and level-capped).</param>
/// <param name="HalfDuplex">True = play the tone first, then record (no simultaneous play/record).</param>
public sealed record PlayCaptureRequest(string? OutputId, string? InputId, float[] Tone, int SampleRate, bool HalfDuplex, bool RequestRawMic,
    TimeSpan LeadIn, TimeSpan Tail);

/// <summary>Mono recordings. <paramref name="Loopback"/> null = output capture not available.</summary>
public sealed record PlayCaptureResult(float[] Mic, int MicSampleRate, float[]? Loopback, int LoopbackSampleRate, bool RawMicApplied, string? Note = null);

/// <param name="ProcessBlock">Called with each mono mic block (and its sample rate); returns the gain to play it at (0 = stop).</param>
public sealed record MonitorRequest(string? OutputId, string? InputId, TimeSpan Duration, bool HalfDuplex, bool RequestRawMic,
    Func<float[], int, float> ProcessBlock);

public sealed record MonitorResult(int SampleRate, bool RawMicApplied, bool StoppedEarly, string? Note = null);

/// <summary>Audio hardware access (Host: NAudio/WASAPI). Implementations never show OS dialogs and honour cancellation.</summary>
public interface IAudioIo
{
    IReadOnlyList<AudioDevice> ListDevices();
    /// <summary>True when the Windows microphone privacy switch (ConsentStore) says Deny.</summary>
    bool IsMicrophoneBlockedByPrivacy();
    /// <summary>Plays <see cref="PlayCaptureRequest.Tone"/> while recording the mic and the output (WASAPI loopback).</summary>
    Task<PlayCaptureResult> PlayAndCaptureAsync(PlayCaptureRequest request, CancellationToken ct);
    /// <summary>Plays the mic back through the output (live, or record-then-play when half-duplex).</summary>
    Task<MonitorResult> MonitorAsync(MonitorRequest request, CancellationToken ct);
}

/// <summary>No audio hardware (CI, non-Windows): every test reports "no device".</summary>
public sealed class NullAudioIo : IAudioIo
{
    public IReadOnlyList<AudioDevice> ListDevices() => [];
    public bool IsMicrophoneBlockedByPrivacy() => false;
    public Task<PlayCaptureResult> PlayAndCaptureAsync(PlayCaptureRequest request, CancellationToken ct) => throw new AudioDeviceException("No audio devices.");
    public Task<MonitorResult> MonitorAsync(MonitorRequest request, CancellationToken ct) => throw new AudioDeviceException("No audio devices.");
}
