using System.Diagnostics;
using System.Runtime.InteropServices;
using NAudio.CoreAudioApi;
using RemotePCDiagnostics.Core.Audio;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// <see cref="IAudioStateSource"/> over Core Audio (NAudio): every endpoint in every state, the Windows defaults for each role, mute,
/// volume, the shared-mode and driver default formats, the enhancements switch, a shared-mode open of each default endpoint (no Start, so
/// nothing plays or records) and the apps playing on the default output. Only reads; runs in the signed-in user's session, no admin.
/// </summary>
public sealed class WasapiAudioStateSource(ILogger? log = null, TimeSpan? probeTimeout = null) : IAudioStateSource
{
    private static readonly PropertyKey EnumeratorName = new(new Guid("a45c254e-df1c-4efd-8020-67d146a850e0"), 24);
    private static readonly PropertyKey InstanceIdKey = new(new Guid("78c34fc8-104a-4aca-9ea4-524d52996e57"), 256);
    private static readonly PropertyKey FormFactorKey = new(new Guid("1da5d803-d492-4edd-8c23-e0c0ffee7f0e"), 0);
    private static readonly PropertyKey DisableSysFxKey = new(new Guid("1da5d803-d492-4edd-8c23-e0c0ffee7f0e"), 5);
    private static readonly PropertyKey DeviceFormatKey = new(new Guid("f19f064d-082c-4e27-bc73-6882a1bb8e4c"), 0);
    private static readonly PropertyKey OemFormatKey = new(new Guid("e4870e26-3cc5-4cd2-ba46-ca0a9a70ed04"), 3);

    private const int AUDCLNT_E_DEVICE_INVALIDATED = unchecked((int)0x88890004);
    private const int AUDCLNT_E_DEVICE_IN_USE = unchecked((int)0x8889000A);
    private const int AUDCLNT_E_SERVICE_NOT_RUNNING = unchecked((int)0x88890010);
    private const int AUDCLNT_E_ENDPOINT_CREATE_FAILED = unchecked((int)0x88890013);

    private readonly TimeSpan _probeTimeout = probeTimeout ?? TimeSpan.FromSeconds(5);

    private void Warn(string m) => log.Warn("Audio state: " + m);

    public Task<AudioState> ReadAsync(CancellationToken ct = default) => Task.Run(async () =>
    {
        try
        {
            using var en = new MMDeviceEnumerator();
            var defaults = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (var flow in new[] { DataFlow.Render, DataFlow.Capture })
                foreach (var (role, name) in new[] { (Role.Console, AudioEndpointInfo.Console), (Role.Multimedia, AudioEndpointInfo.Multimedia), (Role.Communications, AudioEndpointInfo.Communications) })
                {
                    try
                    {
                        if (!en.TryGetDefaultAudioEndpoint(flow, role, out var d)) continue;
                        using (d)
                        {
                            if (!defaults.TryGetValue(d.ID, out var roles)) defaults[d.ID] = roles = [];
                            roles.Add(name);
                        }
                    }
                    catch (Exception ex) { Warn($"default {flow}/{role}: {ex.Message}"); }
                }

            var endpoints = new List<AudioEndpointInfo>();
            using (var all = en.EnumerateAudioEndPoints(DataFlow.All, DeviceState.All))
            {
                foreach (var dev in all)
                {
                    using (dev)
                    {
                        ct.ThrowIfCancellationRequested();
                        var info = await ReadEndpointAsync(dev, defaults, ct).ConfigureAwait(false);
                        if (info is not null) endpoints.Add(info);
                    }
                }
            }
            var sessions = ReadSessions(en);
            return new AudioState(endpoints, sessions);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            Warn("read failed: " + ex);
            return AudioState.Unavailable("Windows didn't list the audio devices: " + ex.Message);
        }
    }, ct);

    private async Task<AudioEndpointInfo?> ReadEndpointAsync(MMDevice dev, Dictionary<string, List<string>> defaults, CancellationToken ct)
    {
        string id;
        try { id = dev.ID; } catch (Exception ex) { Warn("endpoint id: " + ex.Message); return null; }
        var state = Safe(() => dev.State, (DeviceState)0) switch
        {
            DeviceState.Active => AudioEndpointState.Active,
            DeviceState.Disabled => AudioEndpointState.Disabled,
            DeviceState.Unplugged => AudioEndpointState.Unplugged,
            _ => AudioEndpointState.NotPresent,
        };
        var flow = Safe(() => dev.DataFlow, DataFlow.Render) == DataFlow.Capture ? AudioFlow.Input : AudioFlow.Output;
        var name = Safe(() => dev.FriendlyName, "") is { Length: > 0 } n ? n : "Unknown audio device";
        var enumerator = Prop<string>(dev, EnumeratorName);
        var formFactor = FormFactorName(Prop<uint?>(dev, FormFactorKey));
        var instanceId = Prop<string>(dev, InstanceIdKey) ?? "";
        IReadOnlyList<string> roles = defaults.TryGetValue(id, out var r) ? r : [];
        var info = new AudioEndpointInfo(id, name, flow, state, AudioDevice.GuessBus(enumerator, name), formFactor, instanceId, roles);
        if (state != AudioEndpointState.Active) return info;

        bool? muted = null; double? volume = null;
        try
        {
            var vol = dev.AudioEndpointVolume;
            muted = vol.Mute;
            volume = Math.Round(vol.MasterVolumeLevelScalar, 3);
        }
        catch (Exception ex) { Warn($"volume of '{name}': {ex.Message}"); }
        var sysFx = Prop<uint?>(dev, DisableSysFxKey);
        info = info with
        {
            Muted = muted, Volume = volume,
            DeviceFormat = AudioFormatText.FromWaveFormatEx(Prop<byte[]>(dev, DeviceFormatKey)),
            OemFormat = AudioFormatText.FromWaveFormatEx(Prop<byte[]>(dev, OemFormatKey)),
            EnhancementsDisabled = sysFx is null ? null : sysFx == 1,
        };
        if (roles.Count == 0) return info;
        var (outcome, hr) = await ProbeAsync(dev, ct).ConfigureAwait(false);
        return info with { Probe = outcome, ProbeHResult = hr };
    }

    /// <summary>Opens the endpoint in shared mode (no Start), on a worker thread with a timeout: a hung audio service never hangs the check.</summary>
    private async Task<(AudioProbeOutcome, int?)> ProbeAsync(MMDevice dev, CancellationToken ct)
    {
        var probe = Task.Run(() =>
        {
            try
            {
                using var client = dev.CreateAudioClient();
                var format = client.MixFormat;
                client.Initialize(AudioClientShareMode.Shared, AudioClientStreamFlags.None, 1_000_000, 0, format, Guid.Empty);
                return (AudioProbeOutcome.Ok, (int?)null);
            }
            catch (Exception ex)
            {
                var hr = (ex as COMException)?.HResult ?? ex.InnerException?.HResult ?? ex.HResult;
                var outcome = hr switch
                {
                    AUDCLNT_E_DEVICE_IN_USE => AudioProbeOutcome.DeviceInUse,
                    AUDCLNT_E_SERVICE_NOT_RUNNING => AudioProbeOutcome.ServiceNotRunning,
                    AUDCLNT_E_DEVICE_INVALIDATED => AudioProbeOutcome.DeviceInvalidated,
                    AUDCLNT_E_ENDPOINT_CREATE_FAILED => AudioProbeOutcome.EndpointCreateFailed,
                    _ => AudioProbeOutcome.Failed,
                };
                Warn($"probe of '{Safe(() => dev.FriendlyName, "?")}' failed: 0x{hr:X8} {ex.Message}");
                return (outcome, (int?)hr);
            }
        });
        var finished = await Task.WhenAny(probe, Task.Delay(_probeTimeout, ct)).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        if (finished == probe) return await probe.ConfigureAwait(false);
        // Abandoned, never awaited: a hung audio service can hold the call for minutes.
        _ = probe.ContinueWith(t => _ = t.Exception, TaskScheduler.Default);
        Warn($"probe of '{Safe(() => dev.FriendlyName, "?")}' timed out after {_probeTimeout.TotalSeconds:0} s");
        return (AudioProbeOutcome.TimedOut, null);
    }

    private List<AudioSessionInfo> ReadSessions(MMDeviceEnumerator en)
    {
        var list = new List<AudioSessionInfo>();
        try
        {
            if (!en.TryGetDefaultAudioEndpoint(DataFlow.Render, Role.Multimedia, out var dev)) return list;
            using (dev)
            {
                var manager = dev.AudioSessionManager;
                manager.RefreshSessions();
                var sessions = manager.Sessions;
                for (var i = 0; i < sessions.Count; i++)
                {
                    try
                    {
                        using var s = sessions[i];
                        if (s.IsSystemSoundsSession) continue;
                        var pid = (int)s.GetProcessID;
                        if (pid == 0) continue;
                        string process;
                        try { using var p = Process.GetProcessById(pid); process = p.ProcessName; }
                        catch { continue; } // it exited
                        list.Add(new AudioSessionInfo(process, pid, s.SimpleAudioVolume.Mute, Math.Round(s.SimpleAudioVolume.Volume, 3),
                            s.State == NAudio.CoreAudioApi.Interfaces.AudioSessionState.AudioSessionStateActive));
                    }
                    catch (Exception ex) { Warn("session: " + ex.Message); }
                }
            }
        }
        catch (Exception ex) { Warn("sessions: " + ex.Message); }
        return list;
    }

    private static string FormFactorName(uint? value) => value switch
    {
        0 => "RemoteNetworkDevice", 1 => "Speakers", 2 => "LineLevel", 3 => "Headphones", 4 => "Microphone", 5 => "Headset", 6 => "Handset",
        7 => "UnknownDigitalPassthrough", 8 => "Spdif", 9 => "DigitalAudioDisplayDevice", _ => "Unknown",
    };

    private T? Prop<T>(MMDevice dev, PropertyKey key)
    {
        try { return dev.Properties.TryGetValue<T>(key, out var v) ? v : default; }
        catch { return default; }
    }

    private static T Safe<T>(Func<T> read, T fallback)
    {
        try { return read(); } catch { return fallback; }
    }
}
