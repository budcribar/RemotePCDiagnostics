using System.Runtime.InteropServices;

namespace RemotePCDiagnostics.Core.Stress;

/// <summary>
/// Keeps a stress thread out of Windows efficiency mode (EcoQoS). Windows 11 may give low QoS to the threads of an app whose window is
/// minimized, hidden or absent, which on a hybrid CPU moves them to the efficiency cores and on any CPU lowers their clock. A stress
/// test that ran that way would load the PC less than it reports and make throttling look different from what it is. Opting out sets
/// the thread to high QoS; it changes nothing about its priority, so BelowNormal stress threads still give way to the UI.
/// </summary>
public static class StressThreadQos
{
    private const int ThreadPowerThrottling = 3; // THREAD_INFORMATION_CLASS
    private const uint ThreadPowerThrottlingCurrentVersion = 1;
    private const uint ThreadPowerThrottlingExecutionSpeed = 0x1;

    [StructLayout(LayoutKind.Sequential)]
    private struct ThreadPowerThrottlingState
    {
        public uint Version;
        public uint ControlMask;
        public uint StateMask;
    }

    [DllImport("kernel32.dll", ExactSpelling = true)]
    private static extern IntPtr GetCurrentThread();

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetThreadInformation(IntPtr thread, int informationClass, ref ThreadPowerThrottlingState information, uint size);

    /// <summary>Turns efficiency mode off for the calling thread. False when not on Windows or when Windows refused (older than Windows 10 1709).</summary>
    public static bool DisableForCurrentThread()
    {
        if (!OperatingSystem.IsWindows()) return false;
        try
        {
            // ControlMask says we decide execution speed ourselves; StateMask 0 says "not throttled" (high QoS).
            var state = new ThreadPowerThrottlingState { Version = ThreadPowerThrottlingCurrentVersion, ControlMask = ThreadPowerThrottlingExecutionSpeed, StateMask = 0 };
            return SetThreadInformation(GetCurrentThread(), ThreadPowerThrottling, ref state, (uint)Marshal.SizeOf<ThreadPowerThrottlingState>());
        }
        catch (Exception ex) when (ex is EntryPointNotFoundException or DllNotFoundException) { return false; }
    }
}
