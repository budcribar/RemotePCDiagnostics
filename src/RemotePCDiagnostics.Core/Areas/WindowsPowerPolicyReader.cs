using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using RemotePCDiagnostics.Core.Benchmarks;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// Un-elevated Windows power policy and AC/battery probes shared by <see cref="WmiBatteryPowerSource"/> and
/// <c>WindowsBenchmarkProbes</c>. Returns null on non-Windows or whenever a Windows API reports an error.
/// </summary>
public static class WindowsPowerPolicyReader
{
    public static readonly Guid SubProcessorGuid = new("54533251-82be-4824-96c1-47b60b740d00");
    public static readonly Guid ProcThrottleMaxGuid = new("bc5038f7-23e0-4960-96da-33abaf5935ec");

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_POWER_STATUS
    {
        public byte ACLineStatus, BatteryFlag, BatteryLifePercent, SystemStatusFlag;
        public int BatteryLifeTime, BatteryFullLifeTime;
    }

    [DllImport("kernel32.dll")]
    private static extern bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS s);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr hMem);

    [DllImport("powrprof.dll")]
    private static extern uint PowerGetEffectiveOverlayScheme(out Guid effectiveOverlayGuid);

    [DllImport("powrprof.dll")]
    private static extern uint PowerGetActiveScheme(IntPtr userRootPowerKey, out IntPtr activePolicyGuid);

    [DllImport("powrprof.dll")]
    private static extern uint PowerReadACValueIndex(
        IntPtr rootPowerKey,
        ref Guid schemeGuid,
        ref Guid subGroupOfPowerSettingsGuid,
        ref Guid powerSettingGuid,
        out uint acValueIndex);

    /// <summary>True when running on battery, false on AC, null when unknown or non-Windows.</summary>
    public static (bool? OnBattery, bool EnergySaver) ReadPowerLineStatus(ILogger? log = null)
    {
        if (!OperatingSystem.IsWindows()) return (null, false);
        try
        {
            if (GetSystemPowerStatus(out var s))
            {
                bool? onBattery = s.ACLineStatus switch { 0 => true, 1 => false, _ => null };
                return (onBattery, s.SystemStatusFlag == 1);
            }
        }
        catch (Exception ex) { log.Info("[power] GetSystemPowerStatus failed: " + ex.Message); }
        return (null, false);
    }

    /// <summary>Active Windows 10/11 power mode ("Best power efficiency", "Balanced", "Best performance", or "Energy Saver").</summary>
    public static string? ReadPowerMode(bool energySaver, ILogger? log = null)
    {
        if (!OperatingSystem.IsWindows()) return null;
        if (energySaver) return "Energy Saver";
        try
        {
            return PowerGetEffectiveOverlayScheme(out var overlay) == 0
                ? PowerModeNames.FromOverlayGuid(overlay, energySaver: false)
                : null;
        }
        catch (EntryPointNotFoundException) { return null; }
        catch (Exception ex) { log.Info("[power] PowerGetEffectiveOverlayScheme failed: " + ex.Message); return null; }
    }

    /// <summary>
    /// Reads the configured AC Maximum processor state (<c>PROCTHROTTLEMAX</c>) on the active power scheme (0..100).
    /// Returns null on any non-zero Win32 error code (stripped Modern Standby scheme, access denied, etc.).
    /// </summary>
    public static int? ReadAcMaxProcessorStatePercent(ILogger? log = null)
    {
        if (!OperatingSystem.IsWindows()) return null;
        IntPtr schemePtr = IntPtr.Zero;
        try
        {
            var activeErr = PowerGetActiveScheme(IntPtr.Zero, out schemePtr);
            if (activeErr != 0 || schemePtr == IntPtr.Zero)
            {
                log.Info($"[power] PowerGetActiveScheme returned error {activeErr}");
                return null;
            }
            var scheme = Marshal.PtrToStructure<Guid>(schemePtr);
            var sub = SubProcessorGuid;
            var setting = ProcThrottleMaxGuid;
            var readErr = PowerReadACValueIndex(IntPtr.Zero, ref scheme, ref sub, ref setting, out var value);
            if (readErr != 0)
            {
                log.Info($"[power] PowerReadACValueIndex(PROCTHROTTLEMAX) returned error {readErr}");
                return null;
            }
            return value <= 100 ? (int)value : null;
        }
        catch (EntryPointNotFoundException) { return null; }
        catch (Exception ex)
        {
            log.Info("[power] ReadAcMaxProcessorStatePercent failed: " + ex.Message);
            return null;
        }
        finally
        {
            if (schemePtr != IntPtr.Zero) LocalFree(schemePtr);
        }
    }

    public static PowerPolicySnapshot? ReadSnapshot(ILogger? log = null)
    {
        if (!OperatingSystem.IsWindows()) return null;
        var (_, energySaver) = ReadPowerLineStatus(log);
        var mode = ReadPowerMode(energySaver, log);
        var acMax = ReadAcMaxProcessorStatePercent(log);
        return mode is null && acMax is null ? null : new PowerPolicySnapshot(mode, acMax);
    }
}
