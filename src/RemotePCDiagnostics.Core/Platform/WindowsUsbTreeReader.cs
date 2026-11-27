using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;
using RemotePCDiagnostics.Core.Usb;

namespace RemotePCDiagnostics.Core.Platform;

/// <summary>
/// Reads the USB part of the Windows device tree with configuration manager (<c>cfgmgr32.dll</c>) and asks each hub about its ports with the
/// hub driver's read-only IOCTLs, the way USBView does. Nothing here needs administrator rights or changes anything.
/// </summary>
[SupportedOSPlatform("windows")]
public static class WindowsUsbTreeReader
{
    private const uint CrSuccess = 0;
    private const uint CrBufferSmall = 0x1A;
    private const uint CmGetIdListFilterPresent = 0x100;
    private const uint CmGetDeviceInterfaceListPresent = 0;
    private const uint DnHasProblem = 0x400;

    // usbiodef.h: GUID_DEVINTERFACE_USB_HUB.
    private static readonly Guid HubInterface = new("F18A0E88-C30C-11D0-8815-00A0C906BED8");

    // devpkey.h
    private static readonly DevPropKey DeviceDesc = new(new Guid("A45C254E-DF1C-4EFD-8020-67D146A850E0"), 2);
    private static readonly DevPropKey FriendlyName = new(new Guid("A45C254E-DF1C-4EFD-8020-67D146A850E0"), 14);
    private static readonly DevPropKey Address = new(new Guid("A45C254E-DF1C-4EFD-8020-67D146A850E0"), 30);
    private static readonly DevPropKey ClassName = new(new Guid("A45C254E-DF1C-4EFD-8020-67D146A850E0"), 9);
    private static readonly DevPropKey Parent = new(new Guid("4340A6C5-93FA-4706-972C-7B648008A5A7"), 8);
    private static readonly DevPropKey ContainerId = new(new Guid("8C7ED206-3F8A-4827-B3AB-AE9E1FAEFC6C"), 2);

    private const uint DevPropTypeUint32 = 0x7, DevPropTypeGuid = 0xD, DevPropTypeString = 0x12;

    // usbioctl.h: CTL_CODE(FILE_DEVICE_USB, function, METHOD_BUFFERED, FILE_ANY_ACCESS) = 0x220000 | function << 2.
    private const uint IoctlConnectionInfoEx = 0x220448;      // USB_GET_NODE_CONNECTION_INFORMATION_EX (274)
    private const uint IoctlHubInfoEx = 0x220454;             // USB_GET_HUB_INFORMATION_EX (277)
    private const uint IoctlPortConnectorProps = 0x220458;    // USB_GET_PORT_CONNECTOR_PROPERTIES (278)
    private const uint IoctlConnectionInfoExV2 = 0x22045C;    // USB_GET_NODE_CONNECTION_INFORMATION_EX_V2 (279)

    /// <summary>The most ports read on one hub (a hub reports up to 255).</summary>
    private const int MaxPorts = 64;

    public static UsbSnapshot Read(CancellationToken ct = default)
    {
        var ids = PresentDeviceIds();
        var all = new Dictionary<string, Raw>(StringComparer.OrdinalIgnoreCase);
        foreach (var id in ids)
        {
            ct.ThrowIfCancellationRequested();
            if (CM_Locate_DevNodeW(out var inst, id, 0) != CrSuccess) continue;
            all[id] = new Raw(id, inst, StringProp(inst, Parent), StringProp(inst, ClassName));
        }

        // Host controllers are the USB-class devices not enumerated by USB itself; everything under them is the USB tree.
        var children = all.Values.Where(r => r.ParentId is not null).ToLookup(r => r.ParentId!, StringComparer.OrdinalIgnoreCase);
        var nodes = new List<UsbNode>();
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var controller in all.Values.Where(IsController).OrderBy(r => r.Id, StringComparer.OrdinalIgnoreCase))
        {
            ct.ThrowIfCancellationRequested();
            Walk(controller, depth: 0, underUsbDevice: false);
        }
        return new UsbSnapshot(nodes);

        void Walk(Raw r, int depth, bool underUsbDevice)
        {
            if (depth > 16 || !visited.Add(r.Id)) return;
            var usb = r.Id.StartsWith(@"USB\", StringComparison.OrdinalIgnoreCase);
            var isRootHub = depth > 0 && usb && r.Id.Contains("ROOT_HUB", StringComparison.OrdinalIgnoreCase);
            var hubPath = depth > 0 && usb ? HubPath(r.Id) : null;
            var kind = depth == 0 ? UsbNodeKind.Controller
                : isRootHub ? UsbNodeKind.RootHub
                : hubPath is not null ? UsbNodeKind.Hub
                : usb && !underUsbDevice ? UsbNodeKind.Device
                : UsbNodeKind.Function;
            int? hubType = null;
            IReadOnlyList<UsbPortInfo>? ports = null;
            if (hubPath is not null) (hubType, ports) = ReadHub(hubPath, ct);
            var problemCode = CM_Get_DevNode_Status(out var status, out var problem, r.Inst, 0) == CrSuccess && (status & DnHasProblem) != 0
                ? (int)problem : 0;
            var (vid, pid) = VidPid(r.Id);
            nodes.Add(new UsbNode(r.Id, depth == 0 ? null : r.ParentId, kind, Name(r.Inst, kind), r.Class, vid, pid,
                problemCode,
                kind is UsbNodeKind.Hub or UsbNodeKind.Device ? UintProp(r.Inst, Address) is { } a ? (int)a : null : null,
                GuidProp(r.Inst, ContainerId), ports, hubType));
            // Bluetooth devices paired with a USB radio aren't USB devices, and they're named after their owners ("Bud's AirPods"): left out.
            foreach (var c in children[r.Id].Where(c => !c.Id.StartsWith("BTH", StringComparison.OrdinalIgnoreCase)).OrderBy(c => c.Id, StringComparer.OrdinalIgnoreCase))
                Walk(c, depth + 1, underUsbDevice || kind == UsbNodeKind.Device);
        }
    }

    private sealed record Raw(string Id, uint Inst, string? ParentId, string? Class);

    private static bool IsController(Raw r) =>
        string.Equals(r.Class, "USB", StringComparison.OrdinalIgnoreCase) && !r.Id.StartsWith(@"USB\", StringComparison.OrdinalIgnoreCase);

    private static string Name(uint inst, UsbNodeKind kind) =>
        StringProp(inst, FriendlyName) ?? StringProp(inst, DeviceDesc) ?? kind switch
        {
            UsbNodeKind.Controller => "USB host controller",
            UsbNodeKind.RootHub => "USB root hub",
            UsbNodeKind.Hub => "USB hub",
            _ => "USB device",
        };

    /// <summary>VID_xxxx and PID_xxxx from an instance path (<c>USB\VID_046D&amp;PID_C52B\…</c>).</summary>
    public static (string? Vid, string? Pid) VidPid(string id)
    {
        static string? After(string s, string tag)
        {
            var i = s.IndexOf(tag, StringComparison.OrdinalIgnoreCase);
            return i >= 0 && i + tag.Length + 4 <= s.Length ? s.Substring(i + tag.Length, 4).ToUpperInvariant() : null;
        }
        return (After(id, "VID_"), After(id, "PID_"));
    }

    private static List<string> PresentDeviceIds()
    {
        for (var attempt = 0; attempt < 3; attempt++)
        {
            if (CM_Get_Device_ID_List_SizeW(out var len, null, CmGetIdListFilterPresent) != CrSuccess) break;
            var buffer = new char[len + 1];
            var cr = CM_Get_Device_ID_ListW(null, buffer, (uint)buffer.Length, CmGetIdListFilterPresent);
            if (cr == CrBufferSmall) continue;
            if (cr != CrSuccess) break;
            return Split(buffer);
        }
        throw new Win32Exception("Configuration manager didn't list the devices.");
    }

    private static List<string> Split(char[] multiSz)
    {
        var list = new List<string>();
        var start = 0;
        for (var i = 0; i < multiSz.Length; i++)
        {
            if (multiSz[i] != '\0') continue;
            if (i == start) break;
            list.Add(new string(multiSz, start, i - start));
            start = i + 1;
        }
        return list;
    }

    /// <summary>The hub's device interface path, or null when the device isn't a hub.</summary>
    private static string? HubPath(string deviceId)
    {
        var guid = HubInterface;
        if (CM_Get_Device_Interface_List_SizeW(out var len, ref guid, deviceId, CmGetDeviceInterfaceListPresent) != CrSuccess || len <= 1) return null;
        var buffer = new char[len];
        if (CM_Get_Device_Interface_ListW(ref guid, deviceId, buffer, len, CmGetDeviceInterfaceListPresent) != CrSuccess) return null;
        return Split(buffer).FirstOrDefault();
    }

    private static (int? HubType, IReadOnlyList<UsbPortInfo>? Ports) ReadHub(string path, CancellationToken ct)
    {
        using var hub = CreateFileW(path, GenericWrite, FileShareRead | FileShareWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
        if (hub.IsInvalid) return (null, null);
        var info = new byte[512];
        if (!Ioctl(hub, IoctlHubInfoEx, info, out var got) || got < 6) return (null, null);
        var hubType = BinaryPrimitives.ReadInt32LittleEndian(info);
        var count = Math.Min((int)BinaryPrimitives.ReadUInt16LittleEndian(info.AsSpan(4)), MaxPorts);
        var ports = new List<UsbPortInfo>(count);
        for (var port = 1; port <= count; port++)
        {
            ct.ThrowIfCancellationRequested();
            if (ReadPort(hub, port) is { } p) ports.Add(p);
        }
        return (hubType, ports);
    }

    private static UsbPortInfo? ReadPort(SafeFileHandle hub, int port)
    {
        // USB_NODE_CONNECTION_INFORMATION_EX (packed): ConnectionIndex @0, DeviceDescriptor @4 (18 bytes), CurrentConfigurationValue @22,
        // Speed @23, DeviceIsHub @24, DeviceAddress @25, NumberOfOpenPipes @27, ConnectionStatus @31.
        var buf = new byte[2048];
        BinaryPrimitives.WriteUInt32LittleEndian(buf, (uint)port);
        if (!Ioctl(hub, IoctlConnectionInfoEx, buf, out var got) || got < 35) return null;
        var status = UsbPortStatus.Name(BinaryPrimitives.ReadInt32LittleEndian(buf.AsSpan(31)));
        var connected = status != UsbPortStatus.NoDevice;
        var speed = buf[23] switch { 0 => UsbSpeed.Low, 1 => UsbSpeed.Full, 2 => UsbSpeed.High, 3 => UsbSpeed.Super, _ => UsbSpeed.Unknown };
        var rawBcd = connected ? BinaryPrimitives.ReadUInt16LittleEndian(buf.AsSpan(4 + 2)) : (ushort)0;
        var rawVid = connected ? BinaryPrimitives.ReadUInt16LittleEndian(buf.AsSpan(4 + 8)) : (ushort)0;
        var rawPid = connected ? BinaryPrimitives.ReadUInt16LittleEndian(buf.AsSpan(4 + 10)) : (ushort)0;
        int? bcd = rawBcd != 0 ? rawBcd : null;
        string? vid = rawVid != 0 ? rawVid.ToString("X4") : null;
        string? pid = rawVid != 0 ? rawPid.ToString("X4") : null;
        var isHub = buf[24] != 0;

        // USB_NODE_CONNECTION_INFORMATION_EX_V2: ConnectionIndex, Length, SupportedUsbProtocols (in: 1.1 | 2.0 | 3.0), Flags.
        bool? ssCap = null, atSs = null, sspCap = null, atSsp = null;
        var v2 = new byte[16];
        BinaryPrimitives.WriteUInt32LittleEndian(v2, (uint)port);
        BinaryPrimitives.WriteUInt32LittleEndian(v2.AsSpan(4), 16);
        BinaryPrimitives.WriteUInt32LittleEndian(v2.AsSpan(8), 0x7);
        if (connected && Ioctl(hub, IoctlConnectionInfoExV2, v2, out var gotV2) && gotV2 >= 16)
        {
            var flags = BinaryPrimitives.ReadUInt32LittleEndian(v2.AsSpan(12));
            atSs = (flags & 0x1) != 0;
            ssCap = (flags & 0x2) != 0;
            atSsp = (flags & 0x4) != 0;
            sspCap = (flags & 0x8) != 0;
            if (atSsp == true) speed = UsbSpeed.SuperPlus;
            else if (atSs == true && speed < UsbSpeed.Super) speed = UsbSpeed.Super;
        }

        // USB_PORT_CONNECTOR_PROPERTIES: ConnectionIndex, ActualLength, UsbPortProperties, CompanionIndex, CompanionPortNumber, name.
        bool? userConnectable = null, typeC = null;
        int? companion = null;
        var props = new byte[512];
        BinaryPrimitives.WriteUInt32LittleEndian(props, (uint)port);
        if (Ioctl(hub, IoctlPortConnectorProps, props, out var gotProps) && gotProps >= 16)
        {
            var p = BinaryPrimitives.ReadUInt32LittleEndian(props.AsSpan(8));
            userConnectable = (p & 0x1) != 0;
            typeC = (p & 0x8) != 0;
            var c = BinaryPrimitives.ReadUInt16LittleEndian(props.AsSpan(14));
            companion = c > 0 ? c : null;
        }

        return new UsbPortInfo(port, status, connected ? speed : UsbSpeed.Unknown, isHub, ssCap, atSs, sspCap, atSsp, userConnectable, typeC, bcd, vid, pid, companion);
    }

    private static bool Ioctl(SafeFileHandle h, uint code, byte[] buffer, out int returned)
    {
        var ok = DeviceIoControl(h, code, buffer, (uint)buffer.Length, buffer, (uint)buffer.Length, out var r, IntPtr.Zero);
        returned = (int)r;
        return ok;
    }

    private static byte[]? Prop(uint inst, DevPropKey key, out uint type)
    {
        uint size = 0;
        type = 0;
        var cr = CM_Get_DevNode_PropertyW(inst, in key, out type, null, ref size, 0);
        if (cr != CrBufferSmall || size == 0) return null;
        var buffer = new byte[size];
        return CM_Get_DevNode_PropertyW(inst, in key, out type, buffer, ref size, 0) == CrSuccess ? buffer : null;
    }

    private static string? StringProp(uint inst, DevPropKey key)
    {
        var b = Prop(inst, key, out var type);
        if (b is null || type != DevPropTypeString) return null;
        var s = System.Text.Encoding.Unicode.GetString(b).TrimEnd('\0').Trim();
        return s.Length > 0 ? s : null;
    }

    private static uint? UintProp(uint inst, DevPropKey key)
    {
        var b = Prop(inst, key, out var type);
        return b is { Length: >= 4 } && type == DevPropTypeUint32 ? BinaryPrimitives.ReadUInt32LittleEndian(b) : null;
    }

    private static string? GuidProp(uint inst, DevPropKey key)
    {
        var b = Prop(inst, key, out var type);
        return b is { Length: 16 } && type == DevPropTypeGuid ? new Guid(b).ToString("B") : null;
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct DevPropKey(Guid fmtid, uint pid)
    {
        public readonly Guid FmtId = fmtid;
        public readonly uint Pid = pid;
    }

    private const uint GenericWrite = 0x40000000, FileShareRead = 0x1, FileShareWrite = 0x2, OpenExisting = 3;

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    private static extern uint CM_Get_Device_ID_List_SizeW(out uint pulLen, string? pszFilter, uint ulFlags);

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    private static extern uint CM_Get_Device_ID_ListW(string? pszFilter, [Out] char[] buffer, uint bufferLen, uint ulFlags);

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    private static extern uint CM_Locate_DevNodeW(out uint pdnDevInst, string pDeviceID, uint ulFlags);

    [DllImport("cfgmgr32.dll")]
    private static extern uint CM_Get_DevNode_Status(out uint pulStatus, out uint pulProblemNumber, uint dnDevInst, uint ulFlags);

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    private static extern uint CM_Get_DevNode_PropertyW(uint dnDevInst, in DevPropKey propertyKey, out uint propertyType,
        [Out] byte[]? propertyBuffer, ref uint propertyBufferSize, uint ulFlags);

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    private static extern uint CM_Get_Device_Interface_List_SizeW(out uint pulLen, ref Guid interfaceClassGuid, string? pDeviceID, uint ulFlags);

    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
    private static extern uint CM_Get_Device_Interface_ListW(ref Guid interfaceClassGuid, string? pDeviceID, [Out] char[] buffer, uint bufferLen, uint ulFlags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes,
        uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(SafeFileHandle hDevice, uint dwIoControlCode, byte[] lpInBuffer, uint nInBufferSize,
        byte[] lpOutBuffer, uint nOutBufferSize, out uint lpBytesReturned, IntPtr lpOverlapped);
}
