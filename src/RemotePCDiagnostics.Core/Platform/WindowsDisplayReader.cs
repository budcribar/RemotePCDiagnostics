using System.Buffers.Binary;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32;
using RemotePCDiagnostics.Core.Display;

namespace RemotePCDiagnostics.Core.Platform;

/// <summary>
/// Reads the display configuration the way Settings &gt; Display sees it: every video output of every graphics adapter
/// (<c>QueryDisplayConfig</c> with all paths), the monitor on each (<c>DisplayConfigGetDeviceInfo</c>), its EDID from the monitor's device
/// key, the modes the driver offers (<c>EnumDisplaySettings</c>), scaling (<c>GetDpiForMonitor</c>) and HDR (advanced colour info). Nothing
/// here needs administrator rights or changes anything. The structures are read from byte buffers at the offsets wingdi.h gives them.
/// </summary>
[SupportedOSPlatform("windows")]
public static unsafe class WindowsDisplayReader
{
    private const uint QdcAllPaths = 0x1;
    private const int ErrorSuccess = 0, ErrorInsufficientBuffer = 122;
    private const int PathSize = 72, ModeSize = 64;
    private const uint PathActive = 0x1;
    private const uint InvalidModeIndex = 0xFFFFFFFF;
    private const int ModeInfoSource = 1, ModeInfoTarget = 2;

    // DISPLAYCONFIG_DEVICE_INFO_TYPE
    private const int GetSourceName = 1, GetTargetName = 2, GetTargetPreferredMode = 3, GetAdapterName = 4, GetAdvancedColorInfo = 9;

    private sealed record Path(ulong Adapter, uint SourceId, uint SourceMode, ulong TargetAdapter, uint TargetId, uint TargetMode, int Technology,
        int Rotation, uint RefreshNum, uint RefreshDen, bool Available, bool Active);

    public static DisplaySnapshot Read(CancellationToken ct = default)
    {
        var (paths, modes) = Query();
        // Per-monitor DPI awareness for this thread, so GetDpiForMonitor gives each monitor's own scaling, not the system's.
        var old = SetThreadDpiAwarenessContext(new IntPtr(-4));
        try
        {
            var adapterNames = new Dictionary<ulong, string>();
            var outputs = new List<DisplayOutput>();
            // All paths list every source × target pair; keep each target once, the active path when there is one.
            foreach (var g in paths.GroupBy(p => (p.TargetAdapter, p.TargetId)))
            {
                ct.ThrowIfCancellationRequested();
                var p = g.FirstOrDefault(x => x.Active) ?? g.First();
                if (!adapterNames.TryGetValue(p.TargetAdapter, out var adapterName))
                    adapterNames[p.TargetAdapter] = adapterName = AdapterName(p.TargetAdapter);
                outputs.Add(Output(p, adapterName, modes));
            }
            return new DisplaySnapshot([.. outputs.OrderBy(o => o.AdapterId, StringComparer.Ordinal).ThenBy(o => o.TargetId)]);
        }
        finally
        {
            if (old != IntPtr.Zero) SetThreadDpiAwarenessContext(old);
        }
    }

    private static (List<Path>, byte[]) Query()
    {
        for (var attempt = 0; attempt < 5; attempt++)
        {
            var rc = GetDisplayConfigBufferSizes(QdcAllPaths, out var numPaths, out var numModes);
            if (rc != ErrorSuccess) throw new Win32Exception(rc, "GetDisplayConfigBufferSizes failed");
            var pathBuf = new byte[Math.Max(1, numPaths) * PathSize];
            var modeBuf = new byte[Math.Max(1, numModes) * ModeSize];
            fixed (byte* pp = pathBuf)
            fixed (byte* mp = modeBuf)
                rc = QueryDisplayConfig(QdcAllPaths, ref numPaths, pp, ref numModes, mp, IntPtr.Zero);
            if (rc == ErrorInsufficientBuffer) continue; // a monitor came or went between the two calls
            if (rc != ErrorSuccess) throw new Win32Exception(rc, "QueryDisplayConfig failed");
            var paths = new List<Path>((int)numPaths);
            for (var i = 0; i < numPaths; i++)
            {
                var s = pathBuf.AsSpan(i * PathSize, PathSize);
                paths.Add(new Path(
                    Luid(s[0..]), U32(s, 8), U32(s, 12),
                    Luid(s[20..]), U32(s, 28), U32(s, 32), (int)U32(s, 36), (int)U32(s, 40),
                    U32(s, 48), U32(s, 52), U32(s, 60) != 0, (U32(s, 68) & PathActive) != 0));
            }
            return (paths, modeBuf.AsSpan(0, (int)numModes * ModeSize).ToArray());
        }
        throw new InvalidOperationException("The display configuration kept changing while it was read.");
    }

    private static DisplayOutput Output(Path p, string adapterName, byte[] modes)
    {
        var target = TargetName(p.TargetAdapter, p.TargetId);
        var o = new DisplayOutput(p.TargetAdapter.ToString("X16", CultureInfo.InvariantCulture), p.TargetId,
            target?.Technology ?? p.Technology, p.Available, p.Active, adapterName, target?.ConnectorInstance ?? 0);
        if (!p.Available) return o;

        string? instance = target?.DevicePath is { } path ? InstanceId(path) : null;
        o = o with
        {
            MonitorName = target?.FriendlyName is { Length: > 0 } fn ? fn : null,
            MonitorInstanceId = instance,
            EdidManufacturer = target is { EdidIdsValid: true } t ? Edid.PnpId(BinaryPrimitives.ReverseEndianness(t.ManufactureId)) : null,
            EdidProductCode = target is { EdidIdsValid: true } t2 ? t2.ProductCode : null,
            Edid = instance is null ? null : Edid.Parse(ReadEdid(instance)),
            Rotation = p.Rotation switch { 2 => 90, 3 => 180, 4 => 270, _ => 0 },
        };
        if (PreferredMode(p.TargetAdapter, p.TargetId) is { } pref)
            o = o with { PreferredWidth = pref.W, PreferredHeight = pref.H, PreferredRefreshHz = pref.Hz };
        if (AdvancedColor(p.TargetAdapter, p.TargetId) is { } color)
            o = o with { HdrSupported = color.Supported, HdrEnabled = color.Enabled, BitsPerColor = color.Bits > 0 ? color.Bits : null };
        if (!p.Active) return o;

        if (p.SourceMode != InvalidModeIndex && (p.SourceMode + 1) * ModeSize <= modes.Length)
        {
            var m = modes.AsSpan((int)p.SourceMode * ModeSize, ModeSize);
            if ((int)U32(m, 0) == ModeInfoSource)
            {
                int x = (int)U32(m, 28), y = (int)U32(m, 32);
                o = o with { Width = (int)U32(m, 16), Height = (int)U32(m, 20), X = x, Y = y, Primary = x == 0 && y == 0, ScalePercent = Scale(x, y) };
            }
        }
        double? hz = p.RefreshDen > 0 ? Math.Round(p.RefreshNum / (double)p.RefreshDen, 2) : null;
        if (p.TargetMode != InvalidModeIndex && (p.TargetMode + 1) * ModeSize <= modes.Length)
        {
            var m = modes.AsSpan((int)p.TargetMode * ModeSize, ModeSize);
            if ((int)U32(m, 0) == ModeInfoTarget && U32(m, 36) > 0) hz = Math.Round(U32(m, 32) / (double)U32(m, 36), 2);
        }
        o = o with { RefreshHz = hz };
        if (SourceName(p.Adapter, p.SourceId) is { } gdi)
        {
            o = o with { GdiName = gdi };
            var (maxW, maxH, maxHz) = Modes(gdi, o.Width, o.Height);
            o = o with { MaxWidth = maxW, MaxHeight = maxH, MaxRefreshHz = maxHz };
        }
        return o;
    }

    private sealed record Target(int Technology, bool EdidIdsValid, ushort ManufactureId, ushort ProductCode, int ConnectorInstance,
        string FriendlyName, string DevicePath);

    private static Target? TargetName(ulong adapter, uint id)
    {
        var b = Packet(GetTargetName, 420, adapter, id);
        if (!Get(b)) return null;
        return new Target((int)U32(b, 24), (U32(b, 20) & 0x4) != 0, BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(28)),
            BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(30)), (int)U32(b, 32), Str(b, 36, 64), Str(b, 164, 128));
    }

    private static string? SourceName(ulong adapter, uint id)
    {
        var b = Packet(GetSourceName, 84, adapter, id);
        return Get(b) && Str(b, 20, 32) is { Length: > 0 } s ? s : null;
    }

    private static (int W, int H, double? Hz)? PreferredMode(ulong adapter, uint id)
    {
        var b = Packet(GetTargetPreferredMode, 80, adapter, id);
        if (!Get(b)) return null;
        int w = (int)U32(b, 20), h = (int)U32(b, 24);
        var den = U32(b, 52);
        return w > 0 && h > 0 ? (w, h, den > 0 ? Math.Round(U32(b, 48) / (double)den, 2) : null) : null;
    }

    private static (bool Supported, bool Enabled, int Bits)? AdvancedColor(ulong adapter, uint id)
    {
        var b = Packet(GetAdvancedColorInfo, 32, adapter, id);
        if (!Get(b)) return null;
        var v = U32(b, 20);
        return ((v & 0x1) != 0, (v & 0x2) != 0, (int)U32(b, 28));
    }

    private static string AdapterName(ulong adapter)
    {
        var b = Packet(GetAdapterName, 276, adapter, 0);
        if (!Get(b)) return "Graphics adapter";
        var path = Str(b, 20, 128);
        if (InstanceId(path) is { } instance)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\" + instance);
                var name = key?.GetValue("FriendlyName") as string ?? key?.GetValue("DeviceDesc") as string;
                // DeviceDesc is often "@oem12.inf,%nvidia_dev%;NVIDIA GeForce RTX 3060": the name is after the last ';'.
                if (name is { Length: > 0 }) return name[(name.LastIndexOf(';') + 1)..].Trim();
            }
            catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException) { }
        }
        return "Graphics adapter";
    }

    /// <summary>"\\?\DISPLAY#DELA0B1#5&amp;2c03a83e&amp;0&amp;UID4353#{e6f07b5f-...}" as the device instance "DISPLAY\DELA0B1\5&amp;2c03a83e&amp;0&amp;UID4353".</summary>
    public static string? InstanceId(string? devicePath)
    {
        if (string.IsNullOrEmpty(devicePath)) return null;
        var s = devicePath.StartsWith(@"\\?\", StringComparison.Ordinal) ? devicePath[4..] : devicePath;
        var guid = s.LastIndexOf("#{", StringComparison.Ordinal);
        if (guid > 0) s = s[..guid];
        s = s.Replace('#', '\\');
        return s.Count(c => c == '\\') >= 2 ? s : null;
    }

    private static byte[]? ReadEdid(string instance)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\" + instance + @"\Device Parameters");
            return key?.GetValue("EDID") as byte[];
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException) { return null; }
    }

    private static int? Scale(int x, int y)
    {
        var mon = MonitorFromPoint(new Point(x, y), 0);
        if (mon == IntPtr.Zero) return null;
        return GetDpiForMonitor(mon, 0, out var dpiX, out _) == 0 && dpiX > 0 ? (int)Math.Round(dpiX * 100 / 96.0) : null;
    }

    /// <summary>The largest mode the driver offers, and the fastest refresh at the current size (either orientation).</summary>
    private static (int?, int?, double?) Modes(string gdi, int? width, int? height)
    {
        var dm = new byte[220];
        BinaryPrimitives.WriteUInt16LittleEndian(dm.AsSpan(68), 220);
        int maxW = 0, maxH = 0, maxHz = 0;
        fixed (byte* p = dm)
        {
            for (var i = 0; i < 2000 && EnumDisplaySettingsW(gdi, i, p); i++)
            {
                int w = (int)U32(dm, 172), h = (int)U32(dm, 176), hz = (int)U32(dm, 184);
                if ((long)w * h > (long)maxW * maxH) (maxW, maxH) = (w, h);
                if ((w == width && h == height || w == height && h == width) && hz > maxHz) maxHz = hz;
            }
        }
        return (maxW > 0 ? maxW : null, maxH > 0 ? maxH : null, maxHz > 1 ? maxHz : null);
    }

    private static byte[] Packet(int type, int size, ulong adapter, uint id)
    {
        var b = new byte[size];
        BinaryPrimitives.WriteInt32LittleEndian(b, type);
        BinaryPrimitives.WriteInt32LittleEndian(b.AsSpan(4), size);
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(8), (uint)adapter);
        BinaryPrimitives.WriteInt32LittleEndian(b.AsSpan(12), (int)(adapter >> 32));
        BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(16), id);
        return b;
    }

    private static bool Get(byte[] packet)
    {
        fixed (byte* p = packet) return DisplayConfigGetDeviceInfo(p) == ErrorSuccess;
    }

    private static ulong Luid(ReadOnlySpan<byte> s) => BinaryPrimitives.ReadUInt32LittleEndian(s) | (ulong)BinaryPrimitives.ReadUInt32LittleEndian(s[4..]) << 32;
    private static uint U32(ReadOnlySpan<byte> s, int at) => BinaryPrimitives.ReadUInt32LittleEndian(s[at..]);
    private static uint U32(byte[] s, int at) => BinaryPrimitives.ReadUInt32LittleEndian(s.AsSpan(at));

    private static string Str(byte[] b, int at, int chars)
    {
        var span = MemoryMarshal.Cast<byte, char>(b.AsSpan(at, chars * 2));
        var end = span.IndexOf('\0');
        return new string(end >= 0 ? span[..end] : span).Trim();
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly record struct Point(int X, int Y);

    [DllImport("user32.dll")]
    private static extern int GetDisplayConfigBufferSizes(uint flags, out uint numPathArrayElements, out uint numModeInfoArrayElements);

    [DllImport("user32.dll")]
    private static extern int QueryDisplayConfig(uint flags, ref uint numPathArrayElements, byte* pathArray, ref uint numModeInfoArrayElements,
        byte* modeInfoArray, IntPtr currentTopologyId);

    [DllImport("user32.dll")]
    private static extern int DisplayConfigGetDeviceInfo(byte* requestPacket);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumDisplaySettingsW(string deviceName, int modeNum, byte* devMode);

    [DllImport("user32.dll")]
    private static extern IntPtr MonitorFromPoint(Point pt, uint flags);

    [DllImport("user32.dll")]
    private static extern IntPtr SetThreadDpiAwarenessContext(IntPtr dpiContext);

    [DllImport("shcore.dll")]
    private static extern int GetDpiForMonitor(IntPtr monitor, int dpiType, out uint dpiX, out uint dpiY);
}
