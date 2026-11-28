using System.Runtime.InteropServices;
using RemotePCDiagnostics.Core.Display;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// <see cref="IScreenControl"/> for the display test: the monitors from <c>EnumDisplayMonitors</c> / <c>GetMonitorInfo</c> (the
/// window is placed on them by <see cref="MainWindow"/>), and the screen off and on check through the app's own window
/// (<c>WM_SYSCOMMAND</c> / <c>SC_MONITORPOWER</c>, which <c>DefWindowProc</c> handles for any top-level window). Runs as the signed-in
/// user; nothing here needs administrator rights.
/// </summary>
public sealed class WindowsScreenControl(ILogger? log = null) : IScreenControl
{
    public IReadOnlyList<ScreenInfo> ListScreens()
    {
        var screens = new List<ScreenInfo>();
        try
        {
            EnumDisplayMonitors(IntPtr.Zero, IntPtr.Zero, (hMonitor, _, _, _) =>
            {
                var info = new MONITORINFOEXW { cbSize = Marshal.SizeOf<MONITORINFOEXW>() };
                if (!GetMonitorInfoW(hMonitor, ref info)) return true;
                var device = info.szDevice ?? "";
                var r = info.rcMonitor;
                screens.Add(new ScreenInfo(device, NameOf(device, screens.Count + 1), (info.dwFlags & MONITORINFOF_PRIMARY) != 0,
                    r.Left, r.Top, r.Right - r.Left, r.Bottom - r.Top));
                return true;
            }, IntPtr.Zero);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or ExternalException)
        {
            log.Warn($"Screens unreadable: {ex.GetType().Name}: {ex.Message}");
            return [];
        }
        return [.. screens.OrderByDescending(s => s.Primary).ThenBy(s => s.X).ThenBy(s => s.Y)];
    }

    public ScreenInfo? Find(string? id) =>
        string.IsNullOrEmpty(id) ? null : ListScreens().FirstOrDefault(s => string.Equals(s.Id, id, StringComparison.OrdinalIgnoreCase));

    public async Task<string?> BlankScreensAsync(TimeSpan off, CancellationToken ct = default)
    {
        var hwnd = await MainWindowHandleAsync().ConfigureAwait(false);
        if (hwnd == IntPtr.Zero) return "The app's window isn't open.";
        log.Info($"Display test: turning the screens off for {off.TotalSeconds:0.#} s.");
        if (!PostMessageW(hwnd, WM_SYSCOMMAND, SC_MONITORPOWER, MonitorOff))
            return "Windows refused to turn the screens off (error " + Marshal.GetLastPInvokeError() + ").";
        try
        {
            await Task.Delay(off, ct).ConfigureAwait(false);
        }
        finally
        {
            // Back on even when cancelled. Win10+ ignores SC_MONITORPOWER "on" on some PCs, so also say the display is needed and move
            // the mouse by one pixel and back (input turns the display on).
            SetThreadExecutionState(ES_DISPLAY_REQUIRED);
            PostMessageW(hwnd, WM_SYSCOMMAND, SC_MONITORPOWER, MonitorOn);
            SendMouseMove(1, 0);
            await Task.Delay(50).ConfigureAwait(false);
            SendMouseMove(-1, 0);
            log.Info("Display test: screens asked to turn back on.");
        }
        return null;
    }

    private static void SendMouseMove(int dx, int dy)
    {
        var inputs = new INPUT[]
        {
            new()
            {
                type = INPUT_MOUSE,
                u = new InputUnion
                {
                    mi = new MOUSEINPUT { dx = dx, dy = dy, dwFlags = MOUSEEVENTF_MOVE },
                },
            },
        };
        _ = SendInput(1, inputs, Marshal.SizeOf<INPUT>());
    }

    private static Task<IntPtr> MainWindowHandleAsync()
    {
        var app = System.Windows.Application.Current;
        if (app is null) return Task.FromResult(IntPtr.Zero);
        return app.Dispatcher.InvokeAsync(() => app.MainWindow is { } w ? new System.Windows.Interop.WindowInteropHelper(w).Handle : IntPtr.Zero).Task;
    }

    /// <summary>"Screen 2: DELL U2720Q" from the monitor's device string; just "Screen 2" when Windows gives no model.</summary>
    private static string NameOf(string device, int fallbackNumber)
    {
        var number = ScreenNumber(device) ?? fallbackNumber;
        var dd = new DISPLAY_DEVICEW { cb = Marshal.SizeOf<DISPLAY_DEVICEW>() };
        var model = EnumDisplayDevicesW(device, 0, ref dd, 0) ? dd.DeviceString?.Trim() : null;
        return string.IsNullOrEmpty(model) ? $"Screen {number}" : $"Screen {number}: {model}";
    }

    /// <summary>The number at the end of <c>\\.\DISPLAY2</c>, or null.</summary>
    private static int? ScreenNumber(string device)
    {
        var end = device.Length;
        var start = end;
        while (start > 0 && char.IsAsciiDigit(device[start - 1])) start--;
        return start < end && int.TryParse(device.AsSpan(start, end - start), out var n) ? n : null;
    }

    private const int MONITORINFOF_PRIMARY = 1;
    private const uint WM_SYSCOMMAND = 0x0112;
    private static readonly IntPtr SC_MONITORPOWER = 0xF170;
    private static readonly IntPtr MonitorOff = 2;
    private static readonly IntPtr MonitorOn = -1;
    private const uint ES_DISPLAY_REQUIRED = 0x00000002;
    private const uint INPUT_MOUSE = 0;
    private const uint MOUSEEVENTF_MOVE = 0x0001;

    private delegate bool MonitorEnumProc(IntPtr hMonitor, IntPtr hdc, IntPtr lprcMonitor, IntPtr dwData);

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT { public int Left, Top, Right, Bottom; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct MONITORINFOEXW
    {
        public int cbSize;
        public RECT rcMonitor;
        public RECT rcWork;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string szDevice;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct DISPLAY_DEVICEW
    {
        public int cb;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string DeviceName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceString;
        public uint StateFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceID;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceKey;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct INPUT
    {
        public uint type;
        public InputUnion u;
    }

    [StructLayout(LayoutKind.Explicit)]
    private struct InputUnion
    {
        [FieldOffset(0)] public MOUSEINPUT mi;
        [FieldOffset(0)] public KEYBDINPUT ki;
        [FieldOffset(0)] public HARDWAREINPUT hi;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MOUSEINPUT
    {
        public int dx;
        public int dy;
        public uint mouseData;
        public uint dwFlags;
        public uint time;
        public UIntPtr dwExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct KEYBDINPUT
    {
        public ushort wVk;
        public ushort wScan;
        public uint dwFlags;
        public uint time;
        public UIntPtr dwExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct HARDWAREINPUT
    {
        public uint uMsg;
        public ushort wParamL;
        public ushort wParamH;
    }

    [DllImport("user32.dll")]
    private static extern bool EnumDisplayMonitors(IntPtr hdc, IntPtr lprcClip, MonitorEnumProc lpfnEnum, IntPtr dwData);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern bool GetMonitorInfoW(IntPtr hMonitor, ref MONITORINFOEXW lpmi);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern bool EnumDisplayDevicesW(string lpDevice, uint iDevNum, ref DISPLAY_DEVICEW lpDisplayDevice, uint dwFlags);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool PostMessageW(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("kernel32.dll")]
    private static extern uint SetThreadExecutionState(uint esFlags);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);
}
