using System.Diagnostics;
using System.Runtime.InteropServices;
using NAudio.CoreAudioApi;
using RemotePCDiagnostics.Core.Audio;
using RemotePCDiagnostics.Core.DataSources;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// Windows' undocumented <c>IPolicyConfig</c> (CPolicyConfigClient), the interface the Sound control panel, EarTrumpet and SoundSwitch use
/// to set the default device, turn an endpoint on or off, set its format and write its FX properties without administrator rights. It
/// has been stable since Windows Vista; only the Windows 10/11 IID is used, and when QueryInterface fails the fixes that need it fail
/// closed (<see cref="IsAvailable"/>).
/// </summary>
internal static class PolicyConfig
{
    [ComImport, Guid("870af99c-171d-4f9e-af0d-e63df40c2bc9")]
    private class CPolicyConfigClient;

    [StructLayout(LayoutKind.Sequential)]
    public struct PropertyKeyStruct(Guid fmtid, uint pid)
    {
        public Guid FormatId = fmtid;
        public uint PropertyId = pid;
    }

    /// <summary>A PROPVARIANT holding a VT_UI4 (16 bytes on 32-bit Windows, 24 on 64-bit; the padding covers both).</summary>
    [StructLayout(LayoutKind.Explicit, Size = 24)]
    public struct PropVariantUInt
    {
        [FieldOffset(0)] public ushort VarType;
        [FieldOffset(8)] public uint Value;
        public const ushort VT_UI4 = 19;
    }

    [ComImport, Guid("f8679f50-850a-41cf-9c72-430f290290c8"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IPolicyConfig
    {
        [PreserveSig] int GetMixFormat([MarshalAs(UnmanagedType.LPWStr)] string deviceId, out IntPtr format);
        [PreserveSig] int GetDeviceFormat([MarshalAs(UnmanagedType.LPWStr)] string deviceId, int defaultFormat, out IntPtr format);
        [PreserveSig] int ResetDeviceFormat([MarshalAs(UnmanagedType.LPWStr)] string deviceId);
        [PreserveSig] int SetDeviceFormat([MarshalAs(UnmanagedType.LPWStr)] string deviceId, IntPtr endpointFormat, IntPtr mixFormat);
        [PreserveSig] int GetProcessingPeriod([MarshalAs(UnmanagedType.LPWStr)] string deviceId, int defaultPeriod, out long defaultPeriodOut, out long minimumPeriod);
        [PreserveSig] int SetProcessingPeriod([MarshalAs(UnmanagedType.LPWStr)] string deviceId, ref long period);
        [PreserveSig] int GetShareMode([MarshalAs(UnmanagedType.LPWStr)] string deviceId, out int shareMode);
        [PreserveSig] int SetShareMode([MarshalAs(UnmanagedType.LPWStr)] string deviceId, ref int shareMode);
        [PreserveSig] int GetPropertyValue([MarshalAs(UnmanagedType.LPWStr)] string deviceId, int fxStore, ref PropertyKeyStruct key, out PropVariantUInt value);
        [PreserveSig] int SetPropertyValue([MarshalAs(UnmanagedType.LPWStr)] string deviceId, int fxStore, ref PropertyKeyStruct key, ref PropVariantUInt value);
        [PreserveSig] int SetDefaultEndpoint([MarshalAs(UnmanagedType.LPWStr)] string deviceId, Role role);
        [PreserveSig] int SetEndpointVisibility([MarshalAs(UnmanagedType.LPWStr)] string deviceId, int visible);
    }

    /// <summary>A new client, or null when Windows doesn't have the interface (a build that changed it).</summary>
    public static IPolicyConfig? Create()
    {
        try { return new CPolicyConfigClient() as IPolicyConfig; }
        catch (COMException) { return null; }
        catch (InvalidCastException) { return null; }
    }

    private static readonly Lazy<bool> Available = new(() =>
    {
        var p = Create();
        if (p is null) return false;
        Marshal.ReleaseComObject(p);
        return true;
    });

    public static bool IsAvailable() => OperatingSystem.IsWindows() && Available.Value;

    public static void Check(int hr, string what)
    {
        if (hr < 0) throw new COMException($"{what} failed (0x{hr:X8}).", hr);
    }
}

/// <summary>
/// <see cref="IAudioEndpointControl"/> over Core Audio (NAudio) and <see cref="PolicyConfig"/>. Runs in the signed-in user's session
/// (the app, never elevated): mute and volume through IAudioEndpointVolume, app sessions through IAudioSessionManager2, the rest through
/// IPolicyConfig.
/// </summary>
public sealed class WasapiAudioEndpointControl(ILogger? log = null) : IAudioEndpointControl
{
    private static readonly PropertyKey DeviceFormatKey = new(new Guid("f19f064d-082c-4e27-bc73-6882a1bb8e4c"), 0);
    private static readonly PropertyKey OemFormatKey = new(new Guid("e4870e26-3cc5-4cd2-ba46-ca0a9a70ed04"), 3);
    private static readonly PolicyConfig.PropertyKeyStruct DisableSysFx = new(new Guid("1da5d803-d492-4edd-8c23-e0c0ffee7f0e"), 5);

    public bool CanChangeSettings => PolicyConfig.IsAvailable();

    private static T? With<T>(string id, Func<MMDevice, T?> read)
    {
        try
        {
            using var en = new MMDeviceEnumerator();
            using var dev = en.GetDevice(id);
            return read(dev);
        }
        catch (Exception ex) when (ex is COMException or ArgumentException or InvalidCastException) { return default; }
    }

    private static void Change(string id, Action<MMDevice> write)
    {
        using var en = new MMDeviceEnumerator();
        using var dev = en.GetDevice(id);
        write(dev);
    }

    private static void Policy(Func<PolicyConfig.IPolicyConfig, int> call, string what)
    {
        var p = PolicyConfig.Create() ?? throw new COMException("Windows' audio policy interface isn't available on this PC.");
        try { PolicyConfig.Check(call(p), what); }
        finally { Marshal.ReleaseComObject(p); }
    }

    public string? Name(string id) => With(id, d => d.FriendlyName);

    public AudioEndpointState? State(string id) => With<AudioEndpointState?>(id, d => d.State switch
    {
        DeviceState.Active => AudioEndpointState.Active,
        DeviceState.Disabled => AudioEndpointState.Disabled,
        DeviceState.Unplugged => AudioEndpointState.Unplugged,
        _ => AudioEndpointState.NotPresent,
    });

    public bool? GetMute(string id) => With<bool?>(id, d => d.AudioEndpointVolume.Mute);
    public void SetMute(string id, bool mute) => Change(id, d => d.AudioEndpointVolume.Mute = mute);
    public double? GetVolume(string id) => With<double?>(id, d => Math.Round(d.AudioEndpointVolume.MasterVolumeLevelScalar, 3));
    public void SetVolume(string id, double level) => Change(id, d => d.AudioEndpointVolume.MasterVolumeLevelScalar = (float)Math.Clamp(level, 0, 1));

    private static Role RoleOf(string role) => role switch
    {
        AudioEndpointInfo.Console => Role.Console,
        AudioEndpointInfo.Communications => Role.Communications,
        AudioEndpointInfo.Multimedia => Role.Multimedia,
        _ => throw new ArgumentException("Unknown role.", nameof(role)),
    };

    public string? GetDefault(AudioFlow flow, string role)
    {
        try
        {
            using var en = new MMDeviceEnumerator();
            if (!en.TryGetDefaultAudioEndpoint(flow == AudioFlow.Input ? DataFlow.Capture : DataFlow.Render, RoleOf(role), out var d)) return null;
            using (d) return d.ID;
        }
        catch (COMException) { return null; }
    }

    public void SetDefault(string id, string role)
    {
        var r = RoleOf(role);
        Policy(p => p.SetDefaultEndpoint(id, r), "SetDefaultEndpoint");
    }

    public void SetEnabled(string id, bool enabled) => Policy(p => p.SetEndpointVisibility(id, enabled ? 1 : 0), "SetEndpointVisibility");

    public byte[]? GetFormat(string id) => With(id, d => d.Properties.TryGetValue<byte[]>(DeviceFormatKey, out var v) ? v : null);
    public byte[]? GetOemFormat(string id) => With(id, d => d.Properties.TryGetValue<byte[]>(OemFormatKey, out var v) ? v : null);

    public void SetFormat(string id, byte[] waveFormat)
    {
        // Reset goes through ResetDeviceFormat (the driver's default, as the Advanced tab's Restore Defaults); anything else is
        // set as both the endpoint format and the mix format, which is what the Advanced tab does for PCM formats.
        if (GetOemFormat(id) is { } oem && oem.AsSpan().SequenceEqual(waveFormat))
        {
            Policy(p => p.ResetDeviceFormat(id), "ResetDeviceFormat");
            if (GetFormat(id) is { } now && now.AsSpan().SequenceEqual(waveFormat)) return;
        }
        var buffer = Marshal.AllocCoTaskMem(waveFormat.Length);
        try
        {
            Marshal.Copy(waveFormat, 0, buffer, waveFormat.Length);
            Policy(p => p.SetDeviceFormat(id, buffer, buffer), "SetDeviceFormat");
        }
        finally { Marshal.FreeCoTaskMem(buffer); }
    }

    public bool? GetEnhancementsDisabled(string id)
    {
        var p = PolicyConfig.Create();
        if (p is null) return null;
        try
        {
            var key = DisableSysFx;
            return p.GetPropertyValue(id, 0, ref key, out var v) >= 0 && v.VarType == PolicyConfig.PropVariantUInt.VT_UI4 ? v.Value == 1 : false;
        }
        catch (COMException) { return null; }
        finally { Marshal.ReleaseComObject(p); }
    }

    public void SetEnhancementsDisabled(string id, bool disabled)
    {
        var key = DisableSysFx;
        var value = new PolicyConfig.PropVariantUInt { VarType = PolicyConfig.PropVariantUInt.VT_UI4, Value = disabled ? 1u : 0u };
        Policy(p => p.SetPropertyValue(id, 0, ref key, ref value), "SetPropertyValue(Disable_SysFx)");
    }

    public IReadOnlyList<AudioSessionInfo> Sessions(string id) =>
        With(id, d => WasapiAudioStateSource.SessionsOf(d, id, msg => log.Warn("Audio fix: " + msg))) ?? [];

    public int SetSessionMute(string id, string process, bool mute) => With(id, d =>
    {
        var changed = 0;
        var manager = d.AudioSessionManager;
        manager.RefreshSessions();
        var sessions = manager.Sessions;
        for (var i = 0; i < sessions.Count; i++)
        {
            using var s = sessions[i];
            if (s.IsSystemSoundsSession) continue;
            var pid = (int)s.GetProcessID;
            if (pid == 0) continue;
            try
            {
                using var p = Process.GetProcessById(pid);
                if (!string.Equals(p.ProcessName, process, StringComparison.OrdinalIgnoreCase)) continue;
            }
            catch (ArgumentException) { continue; } // it exited
            s.SimpleAudioVolume.Mute = mute;
            changed++;
        }
        return changed;
    });
}
