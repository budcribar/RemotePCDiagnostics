using System.Runtime.InteropServices;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// Asks Windows not to put the PC to sleep on its idle timer (a "system required" power request, listed by
/// <c>powercfg /requests</c> with the reason given here). Held while an unattended session is up: nobody is at the PC, so it
/// counts as idle and would otherwise go to sleep behind the lock screen, taking the relay connection and any long run with it.
/// The display may still turn off, and closing the lid or pressing the power button still sleeps the PC.
/// </summary>
internal sealed class SystemAwake : IDisposable
{
    private const int PowerRequestSystemRequired = 1;
    private const uint SimpleReasonStringFlag = 0x1;
    private static readonly IntPtr InvalidHandle = new(-1);

    private readonly object _gate = new();
    private IntPtr _request = IntPtr.Zero;
    private bool _held;

    public bool Held { get { lock (_gate) return _held; } }

    /// <summary>Holds or releases the request. Returns true when the state changed.</summary>
    public bool Set(bool hold, string reason)
    {
        lock (_gate)
        {
            if (hold == _held) return false;
            if (hold)
            {
                if (_request == IntPtr.Zero)
                {
                    var context = new REASON_CONTEXT { Version = 0, Flags = SimpleReasonStringFlag, SimpleReasonString = reason };
                    var handle = PowerCreateRequest(ref context);
                    if (handle == IntPtr.Zero || handle == InvalidHandle) return false;
                    _request = handle;
                }
                if (!PowerSetRequest(_request, PowerRequestSystemRequired)) return false;
                _held = true;
                return true;
            }
            if (_request != IntPtr.Zero) PowerClearRequest(_request, PowerRequestSystemRequired);
            _held = false;
            return true;
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_request == IntPtr.Zero) return;
            if (_held) PowerClearRequest(_request, PowerRequestSystemRequired);
            CloseHandle(_request);
            _request = IntPtr.Zero;
            _held = false;
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct REASON_CONTEXT
    {
        public uint Version;
        public uint Flags;
        [MarshalAs(UnmanagedType.LPWStr)] public string SimpleReasonString;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr PowerCreateRequest(ref REASON_CONTEXT context);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PowerSetRequest(IntPtr powerRequest, int requestType);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PowerClearRequest(IntPtr powerRequest, int requestType);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}
