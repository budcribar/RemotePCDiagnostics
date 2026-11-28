using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using RemotePCDiagnostics.Core.Input;

namespace RemotePCDiagnostics.Core.Platform;

/// <summary>
/// <see cref="IPhysicalInputMonitor"/> on Windows Raw Input. While a lease is held, a message-only window on its own thread receives
/// WM_INPUT for keyboards, mice, precision touchpads, touchscreens and pens (RIDEV_INPUTSINK, so the app's WebView2 window can have focus).
/// Input with no device handle (SendInput) or from a root-enumerated or software device (Remote Desktop's mouse and keyboard, virtual HID
/// drivers) is reported as injected. Runs in the app un-elevated: raw input needs no admin rights. Key reports keep no key identity.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed unsafe class WindowsRawInputMonitor : IPhysicalInputMonitor, IDisposable
{
    private readonly object _gate = new();
    private readonly Dictionary<nint, DeviceInfo?> _devices = [];
    private readonly Dictionary<nint, bool> _buttonDown = [];
    private static readonly TimeSpan PtpMouseWindow = TimeSpan.FromMilliseconds(250);
    private DateTimeOffset _lastPtpAt;
    private DeviceInfo? _lastPtpDevice;
    private int _leases;
    private Thread? _thread;
    private nint _hwnd;
    private volatile string? _failure;
    private WndProc? _wndProc;

    public event Action<PhysicalInputEvent>? Input;

    public string? UnavailableReason => _failure;

    public IReadOnlyList<PointerDevice> PointerDevices()
    {
        uint count = 0;
        var size = (uint)sizeof(RawInputDeviceList);
        if (GetRawInputDeviceList(null, ref count, size) != 0 || count == 0) return [];
        var list = new RawInputDeviceList[count];
        fixed (RawInputDeviceList* p = list)
        {
            var got = GetRawInputDeviceList(p, ref count, size);
            if (got == uint.MaxValue) return [];
            count = got;
        }
        var infos = new List<DeviceInfo>();
        for (var i = 0; i < count; i++)
        {
            if (list[i].Type == RimTypeKeyboard) continue;
            if (Describe(list[i].Device) is { Pointer: true, Virtual: false } info) infos.Add(info);
        }
        return infos.GroupBy(d => d.EntryId).Select(g =>
        {
            var first = g.First();
            return new PointerDevice(g.Key, first.Name, first.Kind, g.Any(d => d.Precision));
        }).OrderBy(d => d.Kind).ThenBy(d => d.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public IDisposable Listen()
    {
        lock (_gate)
        {
            if (_leases++ == 0) StartLocked();
        }
        return new Lease(this);
    }

    public void Dispose()
    {
        lock (_gate) _leases = 0;
        Stop();
    }

    private void Release()
    {
        bool stop;
        lock (_gate) stop = _leases > 0 && --_leases == 0;
        if (stop) Stop();
    }

    private void StartLocked()
    {
        _failure = null;
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() => Run(ready)) { IsBackground = true, Name = "RPCD raw input" };
        _thread = thread;
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        ready.Task.Wait(TimeSpan.FromSeconds(5));
    }

    // Outside the lock: the input thread takes it while it resolves devices.
    private void Stop()
    {
        Thread? thread;
        nint hwnd;
        lock (_gate)
        {
            if (_leases > 0 || _thread is null) return;
            thread = _thread;
            hwnd = _hwnd;
            _thread = null;
            _hwnd = 0;
            _buttonDown.Clear();
            _lastPtpAt = default;
            _lastPtpDevice = null;
        }
        if (hwnd != 0) PostMessageW(hwnd, WmClose, 0, 0);
        thread.Join(TimeSpan.FromSeconds(2));
    }

    private void Run(TaskCompletionSource ready)
    {
        try
        {
            _wndProc = WindowProc;
            nint hwnd;
            var instance = GetModuleHandleW(null);
            var className = "RpcdRawInput" + Environment.CurrentManagedThreadId;
            fixed (char* cls = className)
            {
                var wc = new WndClassEx
                {
                    Size = (uint)sizeof(WndClassEx),
                    WndProc = Marshal.GetFunctionPointerForDelegate(_wndProc),
                    Instance = instance,
                    ClassName = cls,
                };
                if (RegisterClassExW(&wc) == 0) { Fail("Couldn't create the input window."); return; }
                hwnd = CreateWindowExW(0, cls, null, 0, 0, 0, 0, 0, HwndMessage, 0, instance, 0);
            }
            if (hwnd == 0) { Fail("Couldn't create the input window."); return; }
            if (!Register(hwnd, RidevInputSink)) { Fail("Windows refused to report raw input."); DestroyWindow(hwnd); return; }
            // Not under the lock: Listen holds it while it waits for this thread to be ready.
            Interlocked.Exchange(ref _hwnd, hwnd);
            ready.TrySetResult();
            Msg msg;
            while (GetMessageW(&msg, 0, 0, 0) > 0)
            {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            UnregisterClassW(className, instance);
        }
        catch (Exception ex)
        {
            Fail("Input monitor failed: " + ex.Message);
        }
        finally
        {
            ready.TrySetResult();
        }
    }

    private void Fail(string reason) => _failure = reason;

    private static bool Register(nint hwnd, uint flags)
    {
        var devices = stackalloc RawInputDevice[5];
        devices[0] = new RawInputDevice(0x01, 0x02, flags, hwnd); // mouse
        devices[1] = new RawInputDevice(0x01, 0x06, flags, hwnd); // keyboard
        devices[2] = new RawInputDevice(0x0D, 0x05, flags, hwnd); // precision touchpad
        devices[3] = new RawInputDevice(0x0D, 0x04, flags, hwnd); // touchscreen
        devices[4] = new RawInputDevice(0x0D, 0x02, flags, hwnd); // pen
        return RegisterRawInputDevices(devices, 5, (uint)sizeof(RawInputDevice));
    }

    private nint WindowProc(nint hwnd, uint msg, nint wParam, nint lParam)
    {
        switch (msg)
        {
            case WmInput:
                try { OnRawInput(lParam); } catch { }
                break;
            case WmClose:
                // Registration is per process: leave it when a new listener has already registered its own window.
                var current = Volatile.Read(ref _hwnd);
                if (current == 0 || current == hwnd) Register(0, RidevRemove);
                DestroyWindow(hwnd);
                return 0;
            case WmDestroy:
                PostQuitMessage(0);
                return 0;
        }
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    private void OnRawInput(nint handle)
    {
        uint size = 0;
        var headerSize = (uint)sizeof(RawInputHeader);
        GetRawInputData(handle, RidInput, null, ref size, headerSize);
        if (size < headerSize || size > 64 * 1024) return;
        var buffer = stackalloc byte[(int)size];
        if (GetRawInputData(handle, RidInput, buffer, ref size, headerSize) != size) return;
        var payloadSize = size - headerSize;
        var header = (RawInputHeader*)buffer;
        var data = buffer + headerSize;
        var now = DateTimeOffset.UtcNow;
        var device = header->Device == 0 ? null : Resolve(header->Device);
        var injected = device is null || device.Virtual;

        switch (header->Type)
        {
            case RimTypeKeyboard:
            {
                if (payloadSize < 4) break;
                var flags = *(ushort*)(data + 2);
                if ((flags & RiKeyBreak) == 0) Raise(new PhysicalInputEvent(now, PhysicalInputKind.Key, Injected: injected));
                break;
            }
            case RimTypeMouse:
            {
                if (payloadSize < 20) break;
                // Windows' Precision Touchpad synthesizer delivers RIM_TYPEMOUSE with hDevice == 0 right after a verified PTP HID report.
                if (header->Device == 0)
                {
                    DeviceInfo? ptp;
                    lock (_gate) ptp = _lastPtpDevice is not null && now - _lastPtpAt <= PtpMouseWindow ? _lastPtpDevice : null;
                    if (ptp is not null)
                    {
                        device = ptp;
                        injected = false;
                    }
                }
                var buttons = *(ushort*)(data + 4);
                var buttonData = *(short*)(data + 6);
                var dx = *(int*)(data + 12);
                var dy = *(int*)(data + 16);
                var id = injected ? null : device!.EntryId;
                var kind = injected ? (PointerDeviceKind?)null : device!.Kind;
                var isPrecisionTouchpad = !injected && device is { Kind: PointerDeviceKind.Touchpad, Precision: true };
                if (dx != 0 || dy != 0) Raise(new PhysicalInputEvent(now, PhysicalInputKind.Move, id, kind, injected));
                // For a Precision Touchpad, real physical presses come from OnDigitizerReport (HID button page 0x09);
                // RIM_TYPEMOUSE button flags are synthesized for taps too and would falsely mark a tap as a press.
                if (!isPrecisionTouchpad)
                {
                    if ((buttons & 0x0001) != 0) Raise(new PhysicalInputEvent(now, PhysicalInputKind.ButtonDown, id, kind, injected, PointerButton.Left));
                    if ((buttons & 0x0004) != 0) Raise(new PhysicalInputEvent(now, PhysicalInputKind.ButtonDown, id, kind, injected, PointerButton.Right));
                    if ((buttons & 0x0010) != 0) Raise(new PhysicalInputEvent(now, PhysicalInputKind.ButtonDown, id, kind, injected, PointerButton.Middle));
                }
                if ((buttons & 0x0400) != 0) Raise(new PhysicalInputEvent(now, PhysicalInputKind.Wheel, id, kind, injected, Value: Ticks(buttonData)));
                if ((buttons & 0x0800) != 0) Raise(new PhysicalInputEvent(now, PhysicalInputKind.HWheel, id, kind, injected, Value: Ticks(buttonData)));
                break;
            }
            case RimTypeHid when device is { Preparsed: not null } d:
            {
                if (payloadSize < 8) break;
                var reportSize = *(uint*)data;
                var reports = *(uint*)(data + 4);
                if (reportSize == 0 || reports == 0 || (ulong)reports * reportSize > payloadSize - 8) break;
                if (!injected && d.Kind == PointerDeviceKind.Touchpad && d.Precision)
                {
                    lock (_gate) { _lastPtpAt = now; _lastPtpDevice = d; }
                }
                var report = data + 8;
                for (var i = 0; i < reports; i++, report += reportSize)
                    OnDigitizerReport(header->Device, d, injected, report, reportSize, now);
                break;
            }
        }
    }

    private void OnDigitizerReport(nint handle, DeviceInfo d, bool injected, byte* report, uint length, DateTimeOffset now)
    {
        fixed (byte* preparsed = d.Preparsed)
        {
            var contacts = 0;
            if (HidP_GetUsageValue(HidPInput, 0x0D, 0, 0x54, out var count, preparsed, report, length) == HidpStatusSuccess)
                contacts = (int)count;
            // Tip switches that are on: one per finger (or the pen tip) touching; InRange (0x32) covers pen hover.
            var usages = stackalloc ushort[16];
            uint usageCount = 16;
            var inRange = false;
            if (HidP_GetUsages(HidPInput, 0x0D, 0, usages, ref usageCount, preparsed, report, length) == HidpStatusSuccess)
            {
                var tips = 0;
                for (var i = 0; i < usageCount; i++)
                {
                    if (usages[i] == 0x42) tips++;
                    else if (usages[i] == 0x32) inRange = true;
                }
                contacts = Math.Max(contacts, tips);
            }
            if (contacts > 0) Raise(new PhysicalInputEvent(now, PhysicalInputKind.Contacts, injected ? null : d.EntryId, d.Kind, injected, Value: contacts));
            else if (d.Kind == PointerDeviceKind.Pen && inRange) Raise(new PhysicalInputEvent(now, PhysicalInputKind.Move, injected ? null : d.EntryId, d.Kind, injected));

            if (d.Kind != PointerDeviceKind.Touchpad) return;
            usageCount = 16;
            var pressed = HidP_GetUsages(HidPInput, 0x09, 0, usages, ref usageCount, preparsed, report, length) == HidpStatusSuccess && usageCount > 0;
            bool was;
            lock (_gate)
            {
                _buttonDown.TryGetValue(handle, out was);
                _buttonDown[handle] = pressed;
            }
            if (pressed && !was)
                Raise(new PhysicalInputEvent(now, PhysicalInputKind.ButtonDown, injected ? null : d.EntryId, d.Kind, injected, PointerButton.Left));
        }
    }

    private static int Ticks(short data) => data == 0 ? 0 : data / 120 != 0 ? data / 120 : Math.Sign(data);

    private void Raise(PhysicalInputEvent e)
    {
        try { Input?.Invoke(e); } catch { }
    }

    private DeviceInfo? Resolve(nint handle)
    {
        lock (_gate)
        {
            if (_devices.TryGetValue(handle, out var known)) return known;
        }
        var info = Describe(handle);
        // Cached even when null: a device that can't be described would otherwise be looked up again on every report.
        lock (_gate) _devices[handle] = info;
        return info;
    }

    /// <summary>What a raw input device is and which list entry its input belongs to.</summary>
    private sealed record DeviceInfo(string EntryId, string Name, PointerDeviceKind Kind, bool Pointer, bool Precision, bool Virtual, byte[]? Preparsed);

    private static DeviceInfo? Describe(nint handle)
    {
        var name = DeviceName(handle);
        if (name is null) return null;
        RidDeviceInfo info = default;
        var size = (uint)sizeof(RidDeviceInfo);
        info.Size = size;
        if (GetRawInputDeviceInfoW(handle, RidiDeviceInfo, &info, ref size) == uint.MaxValue) return null;

        var instance = DeviceProperties.InterfaceInstanceId(name);
        var parent = instance is null ? null : DeviceProperties.ParentInstanceId(instance);
        var root = parent ?? instance ?? name;
        var isVirtual = IsVirtual(instance) || IsVirtual(parent);
        var friendly = (parent is null ? null : DeviceProperties.BusReportedName(parent))
            ?? (parent is null ? null : DeviceProperties.Name(parent))
            ?? (instance is null ? null : DeviceProperties.Name(instance))
            ?? "Pointing device";

        switch (info.Type)
        {
            case RimTypeMouse:
            {
                // A mouse collection that shares its device with a digitizer (a precision touchpad) belongs to that device's entry.
                var kind = friendly.Contains("touchpad", StringComparison.OrdinalIgnoreCase) || friendly.Contains("trackpad", StringComparison.OrdinalIgnoreCase)
                    ? PointerDeviceKind.Touchpad : PointerDeviceKind.Mouse;
                var sibling = parent is null ? null : DigitizerSibling(parent);
                return new DeviceInfo(root, friendly, sibling ?? kind, true, sibling == PointerDeviceKind.Touchpad, isVirtual, null);
            }
            case RimTypeHid when info.Hid.UsagePage == 0x0D:
            {
                var kind = info.Hid.Usage switch
                {
                    0x05 => PointerDeviceKind.Touchpad,
                    0x04 => PointerDeviceKind.Touchscreen,
                    0x02 => PointerDeviceKind.Pen,
                    _ => (PointerDeviceKind?)null,
                };
                if (kind is null) return null;
                // A screen with both touch and a pen lists them separately.
                var id = kind == PointerDeviceKind.Pen && parent is not null && DigitizerSibling(parent) == PointerDeviceKind.Touchscreen ? root + "#pen" : root;
                return new DeviceInfo(id, friendly, kind.Value, true, kind == PointerDeviceKind.Touchpad, isVirtual, Preparsed(handle));
            }
            case RimTypeKeyboard:
                return new DeviceInfo(root, friendly, PointerDeviceKind.Mouse, false, false, isVirtual, null);
            default:
                return null;
        }
    }

    // Remote Desktop's mouse and keyboard are root-enumerated (ROOT\RDP_MOU, ROOT\RDP_KBD) or on the terminal input bus. Software
    // devices (SWD\) are not treated as virtual: some laptops' built-in keyboards and touchpads sit behind one.
    private static bool IsVirtual(string? instanceId) =>
        instanceId is not null && (instanceId.StartsWith(@"ROOT\", StringComparison.OrdinalIgnoreCase)
            || instanceId.StartsWith(@"TERMINPUT_BUS\", StringComparison.OrdinalIgnoreCase)
            || instanceId.Contains("RDP_", StringComparison.OrdinalIgnoreCase));

    /// <summary>The digitizer kind among a device's raw input collections (touchpad first), or null when it has none.</summary>
    private static PointerDeviceKind? DigitizerSibling(string parent)
    {
        uint count = 0;
        var size = (uint)sizeof(RawInputDeviceList);
        if (GetRawInputDeviceList(null, ref count, size) != 0 || count == 0) return null;
        var list = new RawInputDeviceList[count];
        fixed (RawInputDeviceList* p = list)
        {
            if (GetRawInputDeviceList(p, ref count, size) == uint.MaxValue) return null;
        }
        PointerDeviceKind? found = null;
        foreach (var d in list)
        {
            if (d.Type != RimTypeHid) continue;
            RidDeviceInfo info = default;
            var infoSize = (uint)sizeof(RidDeviceInfo);
            info.Size = infoSize;
            if (GetRawInputDeviceInfoW(d.Device, RidiDeviceInfo, &info, ref infoSize) == uint.MaxValue || info.Hid.UsagePage != 0x0D) continue;
            if (DeviceName(d.Device) is not { } n || DeviceProperties.InterfaceInstanceId(n) is not { } inst
                || !string.Equals(DeviceProperties.ParentInstanceId(inst), parent, StringComparison.OrdinalIgnoreCase)) continue;
            if (info.Hid.Usage == 0x05) return PointerDeviceKind.Touchpad;
            if (info.Hid.Usage == 0x04) found = PointerDeviceKind.Touchscreen;
            else if (info.Hid.Usage == 0x02) found ??= PointerDeviceKind.Pen;
        }
        return found;
    }

    private static string? DeviceName(nint handle)
    {
        uint chars = 0;
        GetRawInputDeviceInfoW(handle, RidiDeviceName, null, ref chars);
        if (chars == 0 || chars > 2048) return null;
        var buffer = stackalloc char[(int)chars];
        var got = GetRawInputDeviceInfoW(handle, RidiDeviceName, buffer, ref chars);
        if (got == uint.MaxValue || got == 0) return null;
        return new string(buffer).TrimEnd('\0');
    }

    private static byte[]? Preparsed(nint handle)
    {
        uint size = 0;
        GetRawInputDeviceInfoW(handle, RidiPreparsedData, null, ref size);
        if (size == 0 || size > 1024 * 1024) return null;
        var data = new byte[size];
        fixed (byte* p = data)
        {
            return GetRawInputDeviceInfoW(handle, RidiPreparsedData, p, ref size) == uint.MaxValue ? null : data;
        }
    }

    private sealed class Lease(WindowsRawInputMonitor owner) : IDisposable
    {
        private int _disposed;
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0) owner.Release();
        }
    }

    /// <summary>Device properties through cfgmgr32: the device behind an interface, its parent, and its names.</summary>
    private static class DeviceProperties
    {
        private static readonly DevPropKey InstanceIdKey = new(new Guid("78c34fc8-104a-4aca-9ea4-524d52996e57"), 256);
        private static readonly DevPropKey NameKey = new(new Guid("b725f130-47ef-101a-a5f1-02608c9ebac0"), 10);
        private static readonly DevPropKey BusReportedDescKey = new(new Guid("540b947e-8b40-45bc-a8a2-6a0b894cbda2"), 4);

        public static string? InterfaceInstanceId(string interfacePath)
        {
            var key = InstanceIdKey;
            uint size = 0;
            CM_Get_Device_Interface_PropertyW(interfacePath, &key, out _, null, ref size, 0);
            if (size == 0 || size > 4096) return null;
            var buffer = stackalloc byte[(int)size];
            return CM_Get_Device_Interface_PropertyW(interfacePath, &key, out _, buffer, ref size, 0) == 0 ? Text(buffer, size) : null;
        }

        public static string? ParentInstanceId(string instanceId)
        {
            if (CM_Locate_DevNodeW(out var node, instanceId, 0) != 0 || CM_Get_Parent(out var parent, node, 0) != 0) return null;
            var buffer = stackalloc char[512];
            return CM_Get_Device_IDW(parent, buffer, 512, 0) == 0 ? new string(buffer).TrimEnd('\0') : null;
        }

        public static string? Name(string instanceId) => NodeText(instanceId, NameKey);

        public static string? BusReportedName(string instanceId) => NodeText(instanceId, BusReportedDescKey);

        private static string? NodeText(string instanceId, DevPropKey key)
        {
            if (CM_Locate_DevNodeW(out var node, instanceId, 0) != 0) return null;
            uint size = 0;
            CM_Get_DevNode_PropertyW(node, &key, out _, null, ref size, 0);
            if (size == 0 || size > 4096) return null;
            var buffer = stackalloc byte[(int)size];
            if (CM_Get_DevNode_PropertyW(node, &key, out _, buffer, ref size, 0) != 0) return null;
            var text = Text(buffer, size);
            return string.IsNullOrWhiteSpace(text) ? null : text.Trim();
        }

        private static string Text(byte* buffer, uint size) => new string((char*)buffer, 0, (int)(size / 2)).TrimEnd('\0');
    }

    // ---- Win32 ----

    private const uint WmInput = 0x00FF, WmClose = 0x0010, WmDestroy = 0x0002;
    private const uint RidInput = 0x10000003;
    private const uint RidiDeviceName = 0x20000007, RidiDeviceInfo = 0x2000000b, RidiPreparsedData = 0x20000005;
    private const uint RimTypeMouse = 0, RimTypeKeyboard = 1, RimTypeHid = 2;
    private const uint RidevInputSink = 0x00000100, RidevRemove = 0x00000001;
    private const ushort RiKeyBreak = 0x01;
    private const int HidPInput = 0;
    private const int HidpStatusSuccess = 0x00110000;
    private static readonly nint HwndMessage = -3;

    private delegate nint WndProc(nint hwnd, uint msg, nint wParam, nint lParam);

    [StructLayout(LayoutKind.Sequential)]
    private struct RawInputDevice(ushort usagePage, ushort usage, uint flags, nint target)
    {
        public ushort UsagePage = usagePage;
        public ushort Usage = usage;
        public uint Flags = flags;
        public nint Target = target;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct RawInputDeviceList
    {
        public nint Device;
        public uint Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct RawInputHeader
    {
        public uint Type;
        public uint Size;
        public nint Device;
        public nint WParam;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct RidDeviceInfoHid
    {
        public uint VendorId;
        public uint ProductId;
        public uint VersionNumber;
        public ushort UsagePage;
        public ushort Usage;
    }

    [StructLayout(LayoutKind.Explicit)]
    private struct RidDeviceInfo
    {
        [FieldOffset(0)] public uint Size;
        [FieldOffset(4)] public uint Type;
        [FieldOffset(8)] public RidDeviceInfoHid Hid;
        // The union's largest member (RID_DEVICE_INFO_KEYBOARD) is 24 bytes.
        [FieldOffset(28)] private uint _pad;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WndClassEx
    {
        public uint Size;
        public uint Style;
        public nint WndProc;
        public int ClsExtra;
        public int WndExtra;
        public nint Instance;
        public nint Icon;
        public nint Cursor;
        public nint Background;
        public char* MenuName;
        public char* ClassName;
        public nint IconSm;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Msg
    {
        public nint Hwnd;
        public uint Message;
        public nint WParam;
        public nint LParam;
        public uint Time;
        public int X;
        public int Y;
        public uint Private;
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct DevPropKey(Guid fmtid, uint pid)
    {
        public readonly Guid Fmtid = fmtid;
        public readonly uint Pid = pid;
    }

    [DllImport("user32.dll", SetLastError = true)] private static extern bool RegisterRawInputDevices(RawInputDevice* devices, uint count, uint size);
    [DllImport("user32.dll", SetLastError = true)] private static extern uint GetRawInputData(nint rawInput, uint command, void* data, ref uint size, uint headerSize);
    [DllImport("user32.dll", SetLastError = true)] private static extern uint GetRawInputDeviceList(RawInputDeviceList* list, ref uint count, uint size);
    [DllImport("user32.dll", SetLastError = true)] private static extern uint GetRawInputDeviceInfoW(nint device, uint command, void* data, ref uint size);
    [DllImport("user32.dll", SetLastError = true)] private static extern ushort RegisterClassExW(WndClassEx* wc);
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool UnregisterClassW(string className, nint instance);
    [DllImport("user32.dll", SetLastError = true)] private static extern nint CreateWindowExW(uint exStyle, char* className, char* windowName, uint style, int x, int y, int w, int h, nint parent, nint menu, nint instance, nint param);
    [DllImport("user32.dll")] private static extern bool DestroyWindow(nint hwnd);
    [DllImport("user32.dll")] private static extern nint DefWindowProcW(nint hwnd, uint msg, nint wParam, nint lParam);
    [DllImport("user32.dll")] private static extern int GetMessageW(Msg* msg, nint hwnd, uint min, uint max);
    [DllImport("user32.dll")] private static extern bool TranslateMessage(Msg* msg);
    [DllImport("user32.dll")] private static extern nint DispatchMessageW(Msg* msg);
    [DllImport("user32.dll")] private static extern bool PostMessageW(nint hwnd, uint msg, nint wParam, nint lParam);
    [DllImport("user32.dll")] private static extern void PostQuitMessage(int code);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern nint GetModuleHandleW(string? name);
    [DllImport("hid.dll")] private static extern int HidP_GetUsageValue(int reportType, ushort usagePage, ushort linkCollection, ushort usage, out uint value, byte* preparsed, byte* report, uint length);
    [DllImport("hid.dll")] private static extern int HidP_GetUsages(int reportType, ushort usagePage, ushort linkCollection, ushort* usages, ref uint length, byte* preparsed, byte* report, uint reportLength);
    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)] private static extern uint CM_Get_Device_Interface_PropertyW(string path, DevPropKey* key, out uint type, byte* buffer, ref uint size, uint flags);
    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)] private static extern uint CM_Locate_DevNodeW(out uint node, string id, uint flags);
    [DllImport("cfgmgr32.dll")] private static extern uint CM_Get_Parent(out uint parent, uint node, uint flags);
    [DllImport("cfgmgr32.dll")] private static extern uint CM_Get_Device_IDW(uint node, char* buffer, uint length, uint flags);
    [DllImport("cfgmgr32.dll")] private static extern uint CM_Get_DevNode_PropertyW(uint node, DevPropKey* key, out uint type, byte* buffer, ref uint size, uint flags);
}
