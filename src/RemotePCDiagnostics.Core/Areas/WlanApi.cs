using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// The Native Wifi (WLAN) API, as the app uses it without administrator rights: list the Wi-Fi adapters, their radio switches and
/// connection, scan, list networks and access points, and connect or disconnect. Structures are read at their documented offsets
/// (wlanapi.h, 64- and 32-bit alike since they hold no pointers), which <c>WlanApiLayoutTests</c> pins.
/// </summary>
internal static class WlanApi
{
    private const string Dll = "wlanapi.dll";
    public const uint Ok = 0;
    public const uint AccessDenied = 5;
    public const uint ServiceNotActive = 1062;

    // WLAN_INTF_OPCODE
    public const int OpRadioState = 4;
    public const int OpInterfaceState = 6;
    public const int OpCurrentConnection = 7;
    public const int OpRssi = 0x10000102;

    // WLAN_INTERFACE_INFO: GUID, WCHAR[256], WLAN_INTERFACE_STATE
    public const int InterfaceInfoSize = 532;
    // WLAN_AVAILABLE_NETWORK
    public const int AvailableNetworkSize = 628;
    public const int AnSsid = 512, AnBssCount = 552, AnSignal = 604, AnSecurityEnabled = 608, AnAuth = 612, AnCipher = 616, AnFlags = 620;
    // WLAN_BSS_ENTRY
    public const int BssEntrySize = 360;
    public const int BssRssi = 56, BssFrequencyKhz = 92;
    // WLAN_CONNECTION_ATTRIBUTES: state, mode, profile name, then WLAN_ASSOCIATION_ATTRIBUTES (SSID first)
    public const int CaProfile = 8, CaSsid = 520, CaSignal = 576;
    // WLAN_INTERFACE_CAPABILITY: interfaceType, bDot11DSupported, two list sizes, dwNumberOfSupportedPhys, DOT11_PHY_TYPE[64]
    public const int CapPhyCount = 16, CapPhys = 20;

    [DllImport(Dll)] public static extern uint WlanOpenHandle(uint clientVersion, IntPtr reserved, out uint negotiatedVersion, out IntPtr handle);
    [DllImport(Dll)] public static extern uint WlanCloseHandle(IntPtr handle, IntPtr reserved);
    [DllImport(Dll)] public static extern void WlanFreeMemory(IntPtr memory);
    [DllImport(Dll)] public static extern uint WlanEnumInterfaces(IntPtr handle, IntPtr reserved, out IntPtr list);
    [DllImport(Dll)] public static extern uint WlanQueryInterface(IntPtr handle, ref Guid iface, int opCode, IntPtr reserved, out int dataSize, out IntPtr data, out int valueType);
    [DllImport(Dll)] public static extern uint WlanGetInterfaceCapability(IntPtr handle, ref Guid iface, IntPtr reserved, out IntPtr capability);
    [DllImport(Dll)] public static extern uint WlanScan(IntPtr handle, ref Guid iface, IntPtr ssid, IntPtr ie, IntPtr reserved);
    [DllImport(Dll)] public static extern uint WlanGetAvailableNetworkList(IntPtr handle, ref Guid iface, uint flags, IntPtr reserved, out IntPtr list);
    [DllImport(Dll)] public static extern uint WlanGetNetworkBssList(IntPtr handle, ref Guid iface, IntPtr ssid, int bssType, [MarshalAs(UnmanagedType.Bool)] bool securityEnabled, IntPtr reserved, out IntPtr list);
    [DllImport(Dll)] public static extern uint WlanConnect(IntPtr handle, ref Guid iface, ref ConnectionParameters parameters, IntPtr reserved);
    [DllImport(Dll)] public static extern uint WlanDisconnect(IntPtr handle, ref Guid iface, IntPtr reserved);

    /// <summary>WLAN_CONNECTION_PARAMETERS.</summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct ConnectionParameters
    {
        public int Mode;            // 0 = profile, 1 = temporary profile (XML)
        [MarshalAs(UnmanagedType.LPWStr)] public string Profile;
        public IntPtr Ssid;
        public IntPtr DesiredBssids;
        public int BssType;         // 1 = infrastructure
        public uint Flags;
    }

    /// <summary>An open client handle, closed on dispose.</summary>
    public sealed class Session : IDisposable
    {
        private IntPtr _handle;
        public IntPtr Handle => _handle;
        public uint Error { get; }
        public Session() { Error = WlanOpenHandle(2, IntPtr.Zero, out _, out _handle); }
        public bool IsOpen => Error == Ok && _handle != IntPtr.Zero;
        public void Dispose()
        {
            var h = Interlocked.Exchange(ref _handle, IntPtr.Zero);
            if (h != IntPtr.Zero) WlanCloseHandle(h, IntPtr.Zero);
        }
    }

    public static string InterfaceStateName(int state) => state switch
    {
        0 => "Not ready", 1 => "Connected", 2 => "Ad hoc network formed", 3 => "Disconnecting", 4 => "Disconnected",
        5 => "Associating", 6 => "Discovering", 7 => "Authenticating", _ => "Unknown",
    };

    /// <summary>A DOT11_SSID (ULONG length, UCHAR[32]) as text; SSIDs are bytes, normally UTF-8.</summary>
    public static string ReadSsid(IntPtr at)
    {
        var length = Math.Clamp(Marshal.ReadInt32(at), 0, 32);
        var bytes = new byte[length];
        Marshal.Copy(at + 4, bytes, 0, length);
        return Encoding.UTF8.GetString(bytes);
    }

    public static string ReadWideString(IntPtr at, int maxChars) => Marshal.PtrToStringUni(at, maxChars).Split('\0')[0];

    public static IReadOnlyList<(Guid Id, string Description, int State)> Interfaces(Session s, out uint error)
    {
        var result = new List<(Guid, string, int)>();
        error = WlanEnumInterfaces(s.Handle, IntPtr.Zero, out var list);
        if (error != Ok || list == IntPtr.Zero) return result;
        try
        {
            var count = Marshal.ReadInt32(list);
            for (var i = 0; i < count; i++)
            {
                var item = list + 8 + i * InterfaceInfoSize;
                var id = Marshal.PtrToStructure<Guid>(item);
                result.Add((id, ReadWideString(item + 16, 256), Marshal.ReadInt32(item + 16 + 512)));
            }
        }
        finally { WlanFreeMemory(list); }
        return result;
    }

    /// <summary>Queries one opcode and hands the data to <paramref name="read"/>; default when the query fails.</summary>
    public static T? Query<T>(Session s, Guid id, int opCode, Func<IntPtr, int, T> read, out uint error)
    {
        error = WlanQueryInterface(s.Handle, ref id, opCode, IntPtr.Zero, out var size, out var data, out _);
        if (error != Ok || data == IntPtr.Zero) return default;
        try { return read(data, size); }
        finally { WlanFreeMemory(data); }
    }

    /// <summary>WLAN_RADIO_STATE: whether any PHY has the software and hardware switch on (DOT11_RADIO_STATE 1 = on, 2 = off).</summary>
    public static (bool? Software, bool? Hardware) RadioState(IntPtr data, int size)
    {
        if (size < 4) return (null, null);
        var phys = Math.Min(Marshal.ReadInt32(data), (size - 4) / 12);
        bool? sw = null, hw = null;
        for (var i = 0; i < phys; i++)
        {
            var phy = data + 4 + i * 12;
            sw = Merge(sw, Marshal.ReadInt32(phy + 4));
            hw = Merge(hw, Marshal.ReadInt32(phy + 8));
        }
        return (sw, hw);
        static bool? Merge(bool? sofar, int state) => state switch { 1 => true, 2 => sofar ?? false, _ => sofar };
    }

    public static bool? Supports5Ghz(Session s, Guid id)
    {
        if (WlanGetInterfaceCapability(s.Handle, ref id, IntPtr.Zero, out var cap) != Ok || cap == IntPtr.Zero) return null;
        try
        {
            var count = Math.Clamp(Marshal.ReadInt32(cap + CapPhyCount), 0, 64);
            if (count == 0) return null;
            var phys = Enumerable.Range(0, count).Select(i => Marshal.ReadInt32(cap + CapPhys + i * 4)).ToList();
            // DOT11_PHY_TYPE: 4 = OFDM (802.11a), 8 = VHT (802.11ac): both are 5 GHz only. HT, HE and EHT can be 2.4 GHz only.
            return phys.Contains(4) || phys.Contains(8);
        }
        finally { WlanFreeMemory(cap); }
    }

    public static uint Connect(Guid id, int mode, string profile)
    {
        using var s = new Session();
        if (!s.IsOpen) return s.Error;
        var p = new ConnectionParameters { Mode = mode, Profile = profile, BssType = 1 };
        return WlanConnect(s.Handle, ref id, ref p, IntPtr.Zero);
    }
}

/// <summary>The Wi-Fi radio check's reading from the WLAN API (and airplane mode from the registry). Needs no administrator rights.</summary>
public sealed class WlanRadioSource(ILogger? log = null, Func<TimeSpan, CancellationToken, Task>? delay = null) : IWifiRadioSource
{
    /// <summary>How long a scan takes: Windows gives drivers 4 seconds to finish one.</summary>
    public static readonly TimeSpan ScanTime = TimeSpan.FromSeconds(4);
    private const string AirplaneKey = @"SYSTEM\CurrentControlSet\Control\RadioManagement\SystemRadioState";

    public async Task<WifiRadioReading> ReadAsync(bool scan, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) return WifiRadioReading.Unavailable("Wi-Fi is read on Windows only.");
        try
        {
            if (scan && StartScans() > 0)
                await (delay ?? Task.Delay)(ScanTime, ct).ConfigureAwait(false);
            return Read();
        }
        catch (DllNotFoundException) { return new([], ServiceRunning: true); }   // Server Core without the wireless feature: no Wi-Fi
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.Warn($"Wi-Fi radio read failed: {ex.Message}");
            return WifiRadioReading.Unavailable(ex.Message);
        }
    }

    /// <summary>Asks every adapter whose radio is on to scan; returns how many accepted.</summary>
    private int StartScans()
    {
        using var s = new WlanApi.Session();
        if (!s.IsOpen) return 0;
        var started = 0;
        foreach (var (id, _, _) in WlanApi.Interfaces(s, out _))
        {
            var g = id;
            var r = WlanApi.WlanScan(s.Handle, ref g, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            if (r == WlanApi.Ok) started++;
            else log.Info($"Wi-Fi scan on {id} not started: error {r}");
        }
        return started;
    }

    private WifiRadioReading Read()
    {
        var airplane = ReadAirplaneMode();
        using var s = new WlanApi.Session();
        if (s.Error == WlanApi.ServiceNotActive) return new([], ServiceRunning: false, AirplaneMode: airplane);
        if (!s.IsOpen) return new([], AirplaneMode: airplane, Error: $"WLAN API error {s.Error}");
        var interfaces = WlanApi.Interfaces(s, out var enumError);
        if (enumError == WlanApi.ServiceNotActive) return new([], ServiceRunning: false, AirplaneMode: airplane);
        if (enumError != WlanApi.Ok) return new([], AirplaneMode: airplane, Error: $"WLAN API error {enumError}");
        return new(interfaces.Select(i => ReadInterface(s, i.Id, i.Description, i.State)).ToList(), AirplaneMode: airplane);
    }

    private WifiRadioInterface ReadInterface(WlanApi.Session s, Guid id, string description, int state)
    {
        var (sw, hw) = WlanApi.Query(s, id, WlanApi.OpRadioState, WlanApi.RadioState, out _);
        var connected = state == 1;
        var conn = connected ? WlanApi.Query(s, id, WlanApi.OpCurrentConnection,
            (d, _) => (Profile: WlanApi.ReadWideString(d + WlanApi.CaProfile, 256), Ssid: WlanApi.ReadSsid(d + WlanApi.CaSsid)), out _) : default;
        var rssi = connected ? WlanApi.Query<int?>(s, id, WlanApi.OpRssi, (d, _) => Marshal.ReadInt32(d), out _) : null;
        var (networks, refused) = ReadNetworks(s, id);
        var connectedNet = networks.FirstOrDefault(n => n.Connected);
        log.Info($"Wi-Fi {description}: state={state} sw={sw} hw={hw} networks={networks.Count} refused={refused}");
        return new(id.ToString("B"), description, WlanApi.InterfaceStateName(state), sw, hw,
            conn.Ssid is { Length: > 0 } ? conn.Ssid : null, conn.Profile is { Length: > 0 } ? conn.Profile : null, rssi ?? connectedNet?.Rssi,
            networks, WlanApi.Supports5Ghz(s, id), refused, connectedNet?.FrequencyMhz);
    }

    /// <summary>The available networks (names, security, saved profiles) joined with the access points (RSSI, frequency) by SSID.</summary>
    private static (List<WifiNetworkSeen> Networks, bool Refused) ReadNetworks(WlanApi.Session s, Guid id)
    {
        var g = id;
        var error = WlanApi.WlanGetAvailableNetworkList(s.Handle, ref g, 0, IntPtr.Zero, out var list);
        if (error == WlanApi.AccessDenied) return ([], true);
        if (error != WlanApi.Ok || list == IntPtr.Zero) return ([], false);
        var entries = new List<(string Ssid, string Security, int Signal, bool Connected, bool HasProfile, string Profile, int Bss)>();
        try
        {
            var count = Marshal.ReadInt32(list);
            for (var i = 0; i < count; i++)
            {
                var item = list + 8 + i * WlanApi.AvailableNetworkSize;
                var flags = Marshal.ReadInt32(item + WlanApi.AnFlags);
                entries.Add((WlanApi.ReadSsid(item + WlanApi.AnSsid),
                    WifiRadio.SecurityName(Marshal.ReadInt32(item + WlanApi.AnAuth), Marshal.ReadInt32(item + WlanApi.AnCipher), Marshal.ReadInt32(item + WlanApi.AnSecurityEnabled) != 0),
                    Marshal.ReadInt32(item + WlanApi.AnSignal), (flags & 1) != 0, (flags & 2) != 0, WlanApi.ReadWideString(item, 256),
                    Marshal.ReadInt32(item + WlanApi.AnBssCount)));
            }
        }
        finally { WlanApi.WlanFreeMemory(list); }

        var bss = new List<(string Ssid, int Rssi, int Mhz)>();
        if (WlanApi.WlanGetNetworkBssList(s.Handle, ref g, IntPtr.Zero, 3, false, IntPtr.Zero, out var bssList) == WlanApi.Ok && bssList != IntPtr.Zero)
        {
            try
            {
                var count = Marshal.ReadInt32(bssList + 4);
                for (var i = 0; i < count; i++)
                {
                    var e = bssList + 8 + i * WlanApi.BssEntrySize;
                    bss.Add((WlanApi.ReadSsid(e), Marshal.ReadInt32(e + WlanApi.BssRssi), Marshal.ReadInt32(e + WlanApi.BssFrequencyKhz) / 1000));
                }
            }
            finally { WlanApi.WlanFreeMemory(bssList); }
        }
        return (Join(entries, bss), false);
    }

    /// <summary>One network per SSID: connected and saved flags from any entry, the strongest access point's RSSI and frequency.</summary>
    public static List<WifiNetworkSeen> Join(IReadOnlyList<(string Ssid, string Security, int Signal, bool Connected, bool HasProfile, string Profile, int Bss)> entries,
        IReadOnlyList<(string Ssid, int Rssi, int Mhz)> accessPoints) =>
        entries.GroupBy(e => e.Ssid, StringComparer.Ordinal).Select(g =>
        {
            var aps = accessPoints.Where(a => a.Ssid == g.Key).OrderByDescending(a => a.Rssi).ToList();
            var best = aps.Count > 0 ? aps[0] : default;
            var profile = g.Select(e => e.Profile).FirstOrDefault(p => p.Length > 0);
            return new WifiNetworkSeen(g.Key, g.First().Security, aps.Count > 0 ? best.Rssi : null, g.Max(e => e.Signal),
                aps.Count > 0 ? best.Mhz : null, g.Any(e => e.HasProfile), g.Any(e => e.Connected), profile,
                Math.Max(aps.Count, g.Max(e => e.Bss)), aps.Select(a => WifiRadio.BandOf(a.Mhz)).Where(b => b.Length > 0).Distinct().Order().ToList());
        }).ToList();

    private static bool? ReadAirplaneMode()
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(AirplaneKey);
            return key?.GetValue(null) is int v ? v == 1 : null;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException) { return null; }
    }
}

/// <summary>What the connect test needs from the Wi-Fi adapter: its connection now, connect, disconnect, and the router's address on it.</summary>
public interface IWifiConnector
{
    WifiLinkState? Read(string interfaceId);
    /// <summary>Connect with a saved profile; returns the WLAN API error (0 = asked).</summary>
    uint ConnectProfile(string interfaceId, string profileName);
    /// <summary>Connect with a profile that is never saved (<c>wlan_connection_mode_temporary_profile</c>); returns the WLAN API error.</summary>
    uint ConnectTemporary(string interfaceId, string profileXml);
    uint Disconnect(string interfaceId);
    /// <summary>The adapter's IPv4 default gateway once it has an address, else null.</summary>
    string? Gateway(string interfaceId);
}

/// <param name="State">As <see cref="WifiRadioInterface.State"/>.</param>
public sealed record WifiLinkState(string State, string? Ssid, string? Profile, int? Rssi)
{
    public bool IsConnected => State == "Connected";
}

public sealed class WlanConnector : IWifiConnector
{
    public WifiLinkState? Read(string interfaceId)
    {
        if (!OperatingSystem.IsWindows() || !Guid.TryParse(interfaceId, out var id)) return null;
        using var s = new WlanApi.Session();
        if (!s.IsOpen) return null;
        var state = WlanApi.Query<int?>(s, id, WlanApi.OpInterfaceState, (d, _) => Marshal.ReadInt32(d), out _);
        if (state is null) return null;
        if (state != 1) return new(WlanApi.InterfaceStateName(state.Value), null, null, null);
        var (profile, ssid) = WlanApi.Query(s, id, WlanApi.OpCurrentConnection,
            (d, _) => (WlanApi.ReadWideString(d + WlanApi.CaProfile, 256), WlanApi.ReadSsid(d + WlanApi.CaSsid)), out _);
        var rssi = WlanApi.Query<int?>(s, id, WlanApi.OpRssi, (d, _) => Marshal.ReadInt32(d), out _);
        return new("Connected", ssid is { Length: > 0 } ? ssid : null, profile is { Length: > 0 } ? profile : null, rssi);
    }

    public uint ConnectProfile(string interfaceId, string profileName) =>
        Guid.TryParse(interfaceId, out var id) ? WlanApi.Connect(id, 0, profileName) : 87;

    public uint ConnectTemporary(string interfaceId, string profileXml) =>
        Guid.TryParse(interfaceId, out var id) ? WlanApi.Connect(id, 1, profileXml) : 87;

    public uint Disconnect(string interfaceId)
    {
        if (!Guid.TryParse(interfaceId, out var id)) return 87;
        using var s = new WlanApi.Session();
        return s.IsOpen ? WlanApi.WlanDisconnect(s.Handle, ref id, IntPtr.Zero) : s.Error;
    }

    public string? Gateway(string interfaceId)
    {
        if (!Guid.TryParse(interfaceId, out var id)) return null;
        try
        {
            var nic = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => Guid.TryParse(n.Id, out var g) && g == id);
            if (nic is not { OperationalStatus: OperationalStatus.Up }) return null;
            var props = nic.GetIPProperties();
            if (!props.UnicastAddresses.Any(u => u.Address.AddressFamily == AddressFamily.InterNetwork && !u.Address.ToString().StartsWith("169.254.", StringComparison.Ordinal)))
                return null;
            return props.GatewayAddresses.Select(a => a.Address).FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(System.Net.IPAddress.Any))?.ToString();
        }
        catch (NetworkInformationException) { return null; }
    }
}
