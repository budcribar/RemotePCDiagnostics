using System.Runtime.InteropServices;
using System.Windows.Interop;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// The notification-area icon shown while the app runs with no window (<see cref="NoWindowStart"/>), so the person at the PC can
/// see that the shop is checking it and open the app. Clicking it shows the window. Plain Shell_NotifyIcon, because WPF has no
/// tray icon of its own and pulling in Windows Forms for one icon would bring a second UI stack into the app.
/// </summary>
internal sealed class NoWindowTrayIcon : IDisposable
{
    private const int CallbackMessage = 0x8000 + 1; // WM_APP + 1
    private const int WM_LBUTTONUP = 0x0202, WM_LBUTTONDBLCLK = 0x0203, WM_RBUTTONUP = 0x0205;
    private const int NIM_ADD = 0, NIM_DELETE = 2;
    private const int NIF_MESSAGE = 0x1, NIF_ICON = 0x2, NIF_TIP = 0x4;

    private readonly HwndSource _window;
    private readonly IntPtr _icon;
    private readonly bool _ownsIcon;
    private readonly Action _open;
    private readonly int _taskbarCreated;
    private bool _added;
    private bool _disposed;

    /// <param name="open">Runs when the person clicks the icon (on the UI thread, after the click is handled).</param>
    public NoWindowTrayIcon(Action open)
    {
        _open = open;
        // An invisible top-level window (style 0): not message-only, so it still hears TaskbarCreated when Explorer restarts.
        _window = new HwndSource(new HwndSourceParameters("RemotePCDiagnosticsNoWindowTray") { Width = 0, Height = 0, WindowStyle = 0 });
        _window.AddHook(WndProc);
        _taskbarCreated = RegisterWindowMessage("TaskbarCreated");

        var small = new IntPtr[1];
        var path = Environment.ProcessPath;
        if (path is not null && ExtractIconEx(path, 0, null, small, 1) > 0 && small[0] != IntPtr.Zero)
        {
            _icon = small[0];
            _ownsIcon = true;
        }
        else
            _icon = LoadIcon(IntPtr.Zero, (IntPtr)32512); // IDI_APPLICATION, shared: never destroyed

        Add();
    }

    private void Add()
    {
        var data = Data(NIF_MESSAGE | NIF_ICON | NIF_TIP);
        _added = Shell_NotifyIcon(NIM_ADD, ref data);
        App.Log(_added ? "No-window start: tray icon shown." : $"No-window start: the tray icon could not be shown (error {Marshal.GetLastWin32Error()}).");
    }

    private NOTIFYICONDATAW Data(int flags) => new()
    {
        cbSize = Marshal.SizeOf<NOTIFYICONDATAW>(),
        hWnd = _window.Handle,
        uID = 1,
        uFlags = flags,
        uCallbackMessage = CallbackMessage,
        hIcon = _icon,
        szTip = NoWindowStart.TrayTip,
        szInfo = string.Empty,
        szInfoTitle = string.Empty,
    };

    private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg == CallbackMessage)
        {
            var mouse = (int)(lParam.ToInt64() & 0xFFFF);
            if (mouse is WM_LBUTTONUP or WM_LBUTTONDBLCLK or WM_RBUTTONUP)
                _window.Dispatcher.BeginInvoke(_open); // after this message: opening the window removes this icon
            handled = true;
        }
        else if (_taskbarCreated != 0 && msg == _taskbarCreated && !_disposed)
            Add(); // Explorer restarted and lost the icon
        return IntPtr.Zero;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_added)
        {
            var data = Data(0);
            Shell_NotifyIcon(NIM_DELETE, ref data);
        }
        _window.RemoveHook(WndProc);
        _window.Dispose();
        if (_ownsIcon) DestroyIcon(_icon);
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NOTIFYICONDATAW
    {
        public int cbSize;
        public IntPtr hWnd;
        public int uID;
        public int uFlags;
        public int uCallbackMessage;
        public IntPtr hIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string szTip;
        public int dwState;
        public int dwStateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string szInfo;
        public int uTimeoutOrVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string szInfoTitle;
        public int dwInfoFlags;
        public Guid guidItem;
        public IntPtr hBalloonIcon;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, EntryPoint = "Shell_NotifyIconW", SetLastError = true)]
    private static extern bool Shell_NotifyIcon(int message, ref NOTIFYICONDATAW data);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, EntryPoint = "ExtractIconExW")]
    private static extern uint ExtractIconEx(string file, int index, IntPtr[]? large, IntPtr[]? small, uint count);

    [DllImport("user32.dll")]
    private static extern bool DestroyIcon(IntPtr icon);

    [DllImport("user32.dll", EntryPoint = "LoadIconW")]
    private static extern IntPtr LoadIcon(IntPtr instance, IntPtr name);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, EntryPoint = "RegisterWindowMessageW")]
    private static extern int RegisterWindowMessage(string name);
}
