using System.Text.Json;
using System.Text.Json.Serialization;
using RemotePCDiagnostics.Core.DataSources;

namespace RemotePCDiagnostics.Core.Audio;

/// <summary>Core Audio's endpoint states (<c>DEVICE_STATE_*</c>).</summary>
[JsonConverter(typeof(JsonStringEnumConverter<AudioEndpointState>))]
public enum AudioEndpointState { Active, Disabled, NotPresent, Unplugged }

/// <summary>
/// What a shared-mode <c>IAudioClient</c> open (no Start, so nothing plays or records) said about an endpoint: the cheap way to tell "the
/// audio service isn't answering" or "another app holds the device in exclusive mode" apart from a healthy device.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<AudioProbeOutcome>))]
public enum AudioProbeOutcome { NotRun, Ok, DeviceInUse, ServiceNotRunning, DeviceInvalidated, EndpointCreateFailed, TimedOut, Failed }

/// <summary>One audio endpoint (a speaker, headphones, a microphone) as Core Audio reports it.</summary>
/// <param name="Id">The endpoint id (<c>{0.0.0.00000000}.{guid}</c> for outputs, <c>{0.0.1.00000000}.{guid}</c> for inputs).</param>
/// <param name="FormFactor">Speakers, Headphones, Headset, LineLevel, DigitalAudioDisplayDevice, Microphone, Spdif, Handset, Unknown.</param>
/// <param name="InstanceId">The owning PnP device's instance path (joins to WMI <c>Win32_PnPEntity.DeviceID</c>); empty when unknown.</param>
/// <param name="DefaultFor">The roles this endpoint is the Windows default for: Console, Multimedia, Communications.</param>
/// <param name="Volume">Master volume, 0 to 1. Null when it couldn't be read (and always for an endpoint that isn't active).</param>
/// <param name="DeviceFormat">The shared-mode format Windows mixes at ("48000 Hz, 24-bit, 2 channels"); null when unknown.</param>
/// <param name="OemFormat">The driver's default format, in the same words; null when the driver doesn't set one.</param>
/// <param name="EnhancementsDisabled">The endpoint's "Audio enhancements" switch is off; null when unknown.</param>
/// <param name="ProbeHResult">The HRESULT behind a failed probe, for the log.</param>
public sealed record AudioEndpointInfo(
    string Id, string Name, AudioFlow Flow, AudioEndpointState State, AudioBus Bus, string FormFactor, string InstanceId,
    IReadOnlyList<string> DefaultFor, bool? Muted = null, double? Volume = null, string? DeviceFormat = null, string? OemFormat = null,
    bool? EnhancementsDisabled = null, AudioProbeOutcome Probe = AudioProbeOutcome.NotRun, int? ProbeHResult = null)
{
    public const string Console = "Console", Multimedia = "Multimedia", Communications = "Communications";

    public bool IsActive => State == AudioEndpointState.Active;
    public bool IsDefault => DefaultFor.Contains(Multimedia) || DefaultFor.Contains(Console);
    public bool IsDefaultForCalls => DefaultFor.Contains(Communications);

    /// <summary>A Bluetooth headset's call ("Hands-Free") endpoint: mono, call quality.</summary>
    public bool IsBluetoothHandsFree => Bus == AudioBus.Bluetooth && (Name.Contains("Hands-Free", StringComparison.OrdinalIgnoreCase)
        || Name.Contains("Hands Free", StringComparison.OrdinalIgnoreCase) || Name.Contains("Headset", StringComparison.OrdinalIgnoreCase) && FormFactor == "Headset");

    /// <summary>Sound to a monitor or TV over HDMI or DisplayPort.</summary>
    public bool IsDisplayAudio => FormFactor == "DigitalAudioDisplayDevice";

    public string FriendlyState => State switch
    {
        AudioEndpointState.Active => "Ready",
        AudioEndpointState.Disabled => "Disabled",
        AudioEndpointState.Unplugged => Bus == AudioBus.Internal ? "Nothing plugged in" : "Not connected",
        _ => "Not connected",
    };

    /// <summary>What to do about a device that is turned off or not connected.</summary>
    public string Reconnect => State == AudioEndpointState.Disabled
        ? "Turn the device back on."
        : Bus switch
        {
            AudioBus.Bluetooth => "Turn on or pair the headset.",
            AudioBus.Usb => "Plug the USB device in.",
            AudioBus.Internal => "Plug the device in, or check the jack.",
            _ => "Connect or turn on the device.",
        };
}

/// <summary>An app with an audio session on a default device (the Volume mixer).</summary>
/// <param name="EndpointId">The endpoint the app plays on (or records from); empty in recordings made before it was kept.</param>
/// <param name="WindowTitle">The app's main window title, when it has one (for the device busy dialog).</param>
public sealed record AudioSessionInfo(string ProcessName, int ProcessId, bool Muted, double Volume, bool Active, string EndpointId = "", string? WindowTitle = null);

/// <summary>Everything the Sound check reads from Core Audio, in one go.</summary>
/// <param name="Error">Why Core Audio couldn't be read; null when it could.</param>
/// <param name="CanChangeSettings">Windows' <c>IPolicyConfig</c> answered, so the default device, the endpoint switch, the format and the
/// enhancements switch can be changed; null when unknown (the Sound check then offers those fixes, and they fail closed).</param>
public sealed record AudioState(IReadOnlyList<AudioEndpointInfo> Endpoints, IReadOnlyList<AudioSessionInfo> Sessions, string? Error = null, bool? CanChangeSettings = null)
{
    public bool Available => Error is null;

    public static AudioState Unavailable(string reason) => new([], [], reason);

    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        // Names, not numbers, for AudioFlow and AudioBus too: recordings stay readable and the scrubber can spot Bluetooth endpoints.
        Converters = { new JsonStringEnumConverter() },
    };

    public string ToJson() => JsonSerializer.Serialize(this, Json);

    public static AudioState FromJson(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return Unavailable("No audio answer.");
        try { return JsonSerializer.Deserialize<AudioState>(json, Json) ?? Unavailable("No audio answer."); }
        catch (JsonException ex) { return Unavailable("The audio answer couldn't be read: " + ex.Message); }
    }
}

/// <summary>Reads audio endpoints, defaults, mute, volume, formats and the app sessions (Host: Core Audio through NAudio).</summary>
public interface IAudioStateSource
{
    Task<AudioState> ReadAsync(CancellationToken ct = default);
}

/// <summary>No Core Audio (CI, non-Windows).</summary>
public sealed class NullAudioStateSource : IAudioStateSource
{
    public Task<AudioState> ReadAsync(CancellationToken ct = default) => Task.FromResult(AudioState.Unavailable("Audio devices can't be read here."));
}

/// <summary>
/// For a module in user mode (the module host, restricted token, where Core Audio activation isn't guaranteed): asks the app
/// (<c>audio.state</c>), which reads Core Audio in the signed-in user's session.
/// </summary>
public sealed class HostAudioStateSource(Plugins.IHostQueries host, ILogger? log = null) : IAudioStateSource
{
    public async Task<AudioState> ReadAsync(CancellationToken ct = default)
    {
        try { return await host.ReadAudioStateAsync(ct).ConfigureAwait(false); }
        catch (Plugins.HostQueryException ex)
        {
            log.Warn($"audio.state refused ({ex.Error}): {ex.Message}");
            return AudioState.Unavailable(ex.Message);
        }
    }
}

/// <summary>
/// The Windows camera and microphone privacy switches (CapabilityAccessManager ConsentStore): the device-wide one (HKLM), the user's
/// "Let apps access" (HKCU) and "Let desktop apps access" (HKCU <c>NonPackaged</c>). <c>Value = "Deny"</c> means off.
/// </summary>
public static class CapturePrivacy
{
    public const string Microphone = "microphone", Webcam = "webcam";
    public const string Allow = "Allow", Deny = "Deny";
    public static string Key(string capability) => @"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\" + capability;
    public static string KeyFor(string capability, bool nonPackaged) => Key(capability) + (nonPackaged ? @"\NonPackaged" : "");

    /// <summary>The only switches the fix changes.</summary>
    public static bool IsCapability(string? c) => c is Microphone or Webcam;
    /// <summary>"Allow", "Deny" or absent (null or empty: delete the value).</summary>
    public static bool IsValue(string? v) => v is null or "" or Allow or Deny;
    public static string Thing(string capability) => capability == Webcam ? "Camera" : "Microphone";

    /// <summary>The switch's name as Windows Settings shows it.</summary>
    public static string SwitchName(RegistryRoot root, bool nonPackaged, string thing) =>
        root == RegistryRoot.LocalMachine ? $"{thing} access for this device"
        : nonPackaged ? $"Let desktop apps access your {thing.ToLowerInvariant()}" : $"Let apps access your {thing.ToLowerInvariant()}";

    /// <summary>Journal target (<c>ChangeKind.CapturePrivacy</c>): "HKLM|microphone", "HKCU|microphone", "HKCU|microphone|NonPackaged".</summary>
    public static string JournalTarget(RegistryRoot root, string capability, bool nonPackaged) =>
        (root == RegistryRoot.LocalMachine ? "HKLM|" : "HKCU|") + capability + (nonPackaged ? "|NonPackaged" : "");

    public static bool TryParseJournalTarget(string? target, out RegistryRoot root, out string capability, out bool nonPackaged)
    {
        root = RegistryRoot.CurrentUser; capability = ""; nonPackaged = false;
        var parts = (target ?? "").Split('|');
        if (parts.Length is < 2 or > 3 || !IsCapability(parts[1])) return false;
        if (parts[0] == "HKLM" && parts.Length == 2) root = RegistryRoot.LocalMachine;
        else if (parts[0] != "HKCU" || parts.Length == 3 && parts[2] != "NonPackaged") return false;
        capability = parts[1];
        nonPackaged = parts.Length == 3;
        return true;
    }

    /// <summary>Which switches are off, in the order Settings shows them.</summary>
    public sealed record Switches(bool DeviceOff, bool AppsOff, bool DesktopAppsOff, bool Read)
    {
        public bool Blocked => DeviceOff || AppsOff || DesktopAppsOff;
    }

    public static async Task<Switches> ReadAsync(IRegistrySource registry, string capability, CancellationToken ct = default)
    {
        var key = Key(capability);
        var device = await registry.ReadAsync(new RegistryRead(RegistryRoot.LocalMachine, key, ["Value"]), ct).ConfigureAwait(false);
        var user = await registry.ReadAsync(new RegistryRead(RegistryRoot.CurrentUser, key, ["Value"]), ct).ConfigureAwait(false);
        var desktop = await registry.ReadAsync(new RegistryRead(RegistryRoot.CurrentUser, key + @"\NonPackaged", ["Value"]), ct).ConfigureAwait(false);
        static bool Deny(WmiQueryResult r) => r.Rows?.FirstOrDefault() is { } row && string.Equals(row.Str("Value"), "Deny", StringComparison.OrdinalIgnoreCase);
        return new(Deny(device), Deny(user), Deny(desktop), device.Success || user.Success || desktop.Success);
    }

    /// <summary>The switches' names as Windows Settings shows them, for the ones that are off.</summary>
    public static IReadOnlyList<string> OffNames(Switches s, string thing)
    {
        var list = new List<string>();
        if (s.DeviceOff) list.Add($"{thing} access for this device");
        if (s.AppsOff) list.Add($"Let apps access your {thing.ToLowerInvariant()}");
        if (s.DesktopAppsOff) list.Add($"Let desktop apps access your {thing.ToLowerInvariant()}");
        return list;
    }
}

/// <summary>Plain words for a <c>WAVEFORMATEX</c> (or <c>WAVEFORMATEXTENSIBLE</c>) blob, as the Sound control panel's Advanced tab shows it.</summary>
public static class AudioFormatText
{
    private const ushort Extensible = 0xFFFE;

    /// <summary>"48000 Hz, 24-bit, 2 channels"; null when the blob is missing or too short.</summary>
    public static string? FromWaveFormatEx(byte[]? blob)
    {
        if (blob is null || blob.Length < 16) return null;
        var tag = BitConverter.ToUInt16(blob, 0);
        var channels = BitConverter.ToUInt16(blob, 2);
        var rate = BitConverter.ToUInt32(blob, 4);
        int bits = BitConverter.ToUInt16(blob, 14);
        // WAVEFORMATEXTENSIBLE: cbSize (offset 16) >= 22, then wValidBitsPerSample (offset 18), which the panel shows (24 in a 32-bit container).
        if (tag == Extensible && blob.Length >= 20 && BitConverter.ToUInt16(blob, 16) >= 22 && BitConverter.ToUInt16(blob, 18) is > 0 and var valid) bits = valid;
        if (rate == 0 || channels == 0) return null;
        return $"{rate} Hz, {bits}-bit, {channels} channel{(channels == 1 ? "" : "s")}";
    }
}
