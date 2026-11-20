using System.Runtime.InteropServices;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// Lets a second launch (desktop icon, Start menu) bring the copy that is already running to the front. The second copy can't do
/// that itself: Windows only lets the running copy take the foreground when the process that has it allows it, so the second copy,
/// which the person just started and which therefore holds foreground rights, grants them and then signals a named event the running
/// copy waits on. The running copy restores, maximizes and activates its own window. The event is per desktop session (Local\), so a
/// copy running for another Windows user isn't touched. Nothing here needs administrator rights.
/// </summary>
internal static class InstanceActivation
{
    private const string EventName = @"Local\RemotePCDiagnostics.Host.Activate";
    private const int AsfwAny = -1;

    private static EventWaitHandle? _event;
    private static RegisteredWaitHandle? _wait;

    /// <summary>Running copy: calls <paramref name="activate"/> (on a thread-pool thread) each time a second launch signals.</summary>
    public static void Listen(Action activate)
    {
        try
        {
            _event = new EventWaitHandle(false, EventResetMode.AutoReset, EventName);
            _wait = ThreadPool.RegisterWaitForSingleObject(_event, (_, _) =>
            {
                try { activate(); } catch { }
            }, null, Timeout.Infinite, executeOnlyOnce: false);
        }
        catch (Exception ex) { App.Log($"Instance activation: couldn't listen for a second launch: {ex.Message}"); }
    }

    /// <summary>Second launch: lets the running copy take the foreground and asks it to show its window. False when it isn't listening (an older build).</summary>
    public static bool SignalRunningCopy()
    {
        try
        {
            AllowSetForegroundWindow(AsfwAny);
            if (!EventWaitHandle.TryOpenExisting(EventName, out var running)) return false;
            using (running) running.Set();
            return true;
        }
        catch (Exception ex)
        {
            App.Log($"Instance activation: couldn't signal the running copy: {ex.Message}");
            return false;
        }
    }

    public static void Stop()
    {
        try { _wait?.Unregister(null); _event?.Dispose(); } catch { }
        _wait = null;
        _event = null;
    }

    [DllImport("user32.dll")]
    private static extern bool AllowSetForegroundWindow(int dwProcessId);
}
