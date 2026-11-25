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

    public const uint ErrorAccessDenied = 5;
    private const int AccessAcPowerSettingIndex = 0;

    [DllImport("powrprof.dll")]
    private static extern uint PowerReadACValueIndex(
        IntPtr rootPowerKey,
        ref Guid schemeGuid,
        ref Guid subGroupOfPowerSettingsGuid,
        ref Guid powerSettingGuid,
        out uint acValueIndex);

    [DllImport("powrprof.dll")]
    private static extern uint PowerWriteACValueIndex(
        IntPtr rootPowerKey,
        ref Guid schemeGuid,
        ref Guid subGroupOfPowerSettingsGuid,
        ref Guid powerSettingGuid,
        uint acValueIndex);

    [DllImport("powrprof.dll")]
    private static extern uint PowerSetActiveScheme(IntPtr userRootPowerKey, ref Guid schemeGuid);

    [DllImport("powrprof.dll")]
    private static extern uint PowerSettingAccessCheck(int accessFlags, ref Guid powerGuid);

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

    /// <summary>Returns the active Windows power scheme GUID, or null on non-Windows/error.</summary>
    public static Guid? ReadActiveSchemeGuid(ILogger? log = null)
    {
        if (!OperatingSystem.IsWindows()) return null;
        IntPtr schemePtr = IntPtr.Zero;
        try
        {
            var err = PowerGetActiveScheme(IntPtr.Zero, out schemePtr);
            if (err != 0 || schemePtr == IntPtr.Zero)
            {
                log.Info($"[power] PowerGetActiveScheme returned error {err}");
                return null;
            }
            return Marshal.PtrToStructure<Guid>(schemePtr);
        }
        catch (EntryPointNotFoundException) { return null; }
        catch (Exception ex) { log.Info("[power] ReadActiveSchemeGuid failed: " + ex.Message); return null; }
        finally
        {
            if (schemePtr != IntPtr.Zero) LocalFree(schemePtr);
        }
    }

    /// <summary>
    /// Checks <c>PowerSettingAccessCheck(ACCESS_AC_POWER_SETTING_INDEX, PROCTHROTTLEMAX)</c>.
    /// Returns false when Group Policy overrides or locks the setting, true when editable, null when unknown/non-Windows.
    /// </summary>
    public static bool? IsAcMaxProcessorStateEditable(ILogger? log = null)
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            var setting = ProcThrottleMaxGuid;
            var err = PowerSettingAccessCheck(AccessAcPowerSettingIndex, ref setting);
            if (err == 0) return true;
            log.Info($"[power] PowerSettingAccessCheck(PROCTHROTTLEMAX) returned {err}");
            return false;
        }
        catch (EntryPointNotFoundException) { return null; }
        catch (Exception ex) { log.Info("[power] PowerSettingAccessCheck failed: " + ex.Message); return null; }
    }

    /// <summary>
    /// Reads the configured AC Maximum processor state (<c>PROCTHROTTLEMAX</c>) on the active power scheme (0..100).
    /// Returns null on any non-zero Win32 error code (stripped Modern Standby scheme, access denied, etc.).
    /// </summary>
    public static int? ReadAcMaxProcessorStatePercent(ILogger? log = null) =>
        ReadActiveSchemeGuid(log) is { } scheme ? ReadAcMaxProcessorStatePercent(scheme, log) : null;

    public static int? ReadAcMaxProcessorStatePercent(Guid schemeGuid, ILogger? log = null)
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            var scheme = schemeGuid;
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
    }

    public static uint WriteAcMaxProcessorStatePercent(Guid schemeGuid, int value, ILogger? log = null)
    {
        if (!OperatingSystem.IsWindows()) return 50; // ERROR_NOT_SUPPORTED
        try
        {
            var scheme = schemeGuid;
            var sub = SubProcessorGuid;
            var setting = ProcThrottleMaxGuid;
            return PowerWriteACValueIndex(IntPtr.Zero, ref scheme, ref sub, ref setting, (uint)Math.Clamp(value, 0, 100));
        }
        catch (Exception ex)
        {
            log.Info("[power] WriteAcMaxProcessorStatePercent failed: " + ex.Message);
            return 1;
        }
    }

    public static uint SetActiveScheme(Guid schemeGuid, ILogger? log = null)
    {
        if (!OperatingSystem.IsWindows()) return 50;
        try
        {
            var scheme = schemeGuid;
            return PowerSetActiveScheme(IntPtr.Zero, ref scheme);
        }
        catch (Exception ex)
        {
            log.Info("[power] PowerSetActiveScheme failed: " + ex.Message);
            return 1;
        }
    }

    public static PowerPolicySnapshot? ReadSnapshot(ILogger? log = null)
    {
        if (!OperatingSystem.IsWindows()) return null;
        var (_, energySaver) = ReadPowerLineStatus(log);
        var mode = ReadPowerMode(energySaver, log);
        var acMax = ReadAcMaxProcessorStatePercent(log);
        var editable = acMax.HasValue ? IsAcMaxProcessorStateEditable(log) : null;
        return mode is null && acMax is null ? null : new PowerPolicySnapshot(mode, acMax, editable);
    }
}
