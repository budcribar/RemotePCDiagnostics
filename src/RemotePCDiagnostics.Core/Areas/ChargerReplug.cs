using System.Runtime.InteropServices;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>Whether the PC is on wall power and the battery charging, as Windows reports it now.</summary>
/// <param name="OnAc">True on wall power, false on battery, null when Windows doesn't know.</param>
/// <param name="Charging">True while the battery charges, null when unknown.</param>
/// <param name="Percent">The battery's charge, null when unknown.</param>
/// <param name="HasBattery">False on a PC without a battery (a desktop).</param>
public sealed record PowerLineState(bool? OnAc, bool? Charging, int? Percent, bool HasBattery = true);

/// <summary>Reads <see cref="PowerLineState"/>. Instant and without administrator rights, so the replug test can poll it.</summary>
public interface IPowerLineSource
{
    PowerLineState? Read();
}

/// <summary><c>GetSystemPowerStatus</c>: the same AC line and charging flags the taskbar's battery icon shows.</summary>
public sealed class WindowsPowerLineSource : IPowerLineSource
{
    public PowerLineState? Read()
    {
        if (!OperatingSystem.IsWindows() || !GetSystemPowerStatus(out var s)) return null;
        return FromStatus(s.ACLineStatus, s.BatteryFlag, s.BatteryLifePercent);
    }

    /// <summary>ACLineStatus 0 = battery, 1 = AC, 255 = unknown. BatteryFlag 8 = charging, 128 = no battery, 255 = unknown. Percent 255 = unknown.</summary>
    public static PowerLineState FromStatus(byte acLine, byte batteryFlag, byte percent) => new(
        acLine switch { 0 => false, 1 => true, _ => null },
        batteryFlag == 255 ? null : (batteryFlag & 8) != 0,
        percent <= 100 ? percent : null,
        HasBattery: batteryFlag == 255 || (batteryFlag & 128) == 0);

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_POWER_STATUS { public byte ACLineStatus, BatteryFlag, BatteryLifePercent, SystemStatusFlag; public int BatteryLifeTime, BatteryFullLifeTime; }

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS s);
}

/// <summary>How far the replug test got.</summary>
public enum ReplugOutcome
{
    /// <summary>Unplug and plug-in both seen, and the battery started charging (or was full).</summary>
    Passed,
    /// <summary>Both changes seen, but the battery didn't start charging and isn't full: a charge limit, or a charger that can't charge.</summary>
    NotCharging,
    /// <summary>The charger was never plugged in at the start.</summary>
    NeverPluggedIn,
    /// <summary>Windows didn't see the charger unplugged in time.</summary>
    UnplugNotSeen,
    /// <summary>Windows didn't see the charger plugged back in in time.</summary>
    PlugNotSeen,
    /// <summary>Windows doesn't report the power source on this PC.</summary>
    NotReported,
    /// <summary>A desktop without a battery.</summary>
    NotApplicable,
}

/// <param name="UnplugSeenAfter">How long after "Unplug" Windows saw the PC go on battery.</param>
/// <param name="PlugSeenAfter">How long after "Plug back in" Windows saw wall power again.</param>
/// <param name="Percent">The battery's charge at the end.</param>
public sealed record ChargerReplugReport(ReplugOutcome Outcome, TimeSpan? UnplugSeenAfter, TimeSpan? PlugSeenAfter, bool? StartedCharging, int? Percent) : IRunEnd
{
    public RunEnd RunEnd => Outcome is ReplugOutcome.NotApplicable or ReplugOutcome.NotReported ? RunEnd.CouldNotRun : RunEnd.Finished;
}

/// <summary>
/// The interactive charger test's rules (the module is RemotePCDiagnostics.Modules.ChargerReplug): the person unplugs the charger, then
/// plugs it back in. Windows must see each change within <see cref="StepWindow"/> of asking, and the battery must start charging within
/// <see cref="ChargingWindow"/> (a full battery passes without charging). Nothing on the PC is changed, so there is nothing to restore on
/// cancel. While it runs, the result's message is the instruction to the person, which the Interactive tests page shows.
/// </summary>
public static class ChargerReplug
{
    public static readonly TimeSpan StepWindow = TimeSpan.FromSeconds(10);
    /// <summary>Time to plug the charger in first, when the test starts on battery.</summary>
    public static readonly TimeSpan PlugInFirstWindow = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan ChargingWindow = TimeSpan.FromSeconds(15);
    public static readonly TimeSpan Poll = TimeSpan.FromMilliseconds(250);
    /// <summary>At or above this charge a battery that doesn't start charging is full, not faulty.</summary>
    public const int FullPercent = 95;

    public const string PlugInPrompt = "Plug in the charger.";
    public const string UnplugPrompt = "Unplug the charger now.";
    public const string PlugBackPrompt = "Plug the charger back in now.";
    public const string ChargingPrompt = "Checking that the battery starts charging…";

    public static (DiagnosticStatus Status, string Message) Outcome(ChargerReplugReport r) => r.Outcome switch
    {
        ReplugOutcome.Passed => (DiagnosticStatus.Ok, r.StartedCharging == true
            ? "Passed: Windows saw the charger unplugged and plugged back in, and the battery started charging."
            : "Passed: Windows saw the charger unplugged and plugged back in. The battery is full, so it didn't need to charge."),
        ReplugOutcome.NotCharging => (DiagnosticStatus.Warning,
            "Windows saw the charger unplugged and plugged back in, but the battery didn't start charging. A charge limit (such as HP Battery Health Manager or Lenovo Conservation mode) can do this; otherwise the charger or the charging circuit may be faulty."),
        ReplugOutcome.NeverPluggedIn => (DiagnosticStatus.Error,
            $"The charger wasn't plugged in within {PlugInFirstWindow.TotalSeconds:0} seconds. If it was plugged in, the charger, its cable or the PC's charging port may be faulty."),
        ReplugOutcome.UnplugNotSeen => (DiagnosticStatus.Error,
            $"Windows didn't see the charger unplugged within {StepWindow.TotalSeconds:0} seconds. If it was unplugged, the PC isn't detecting the power source. Run the test again to retry."),
        ReplugOutcome.PlugNotSeen => (DiagnosticStatus.Error,
            $"Windows didn't see the charger plugged back in within {StepWindow.TotalSeconds:0} seconds. If it was plugged in, the charger, its cable or the PC's charging port may be faulty."),
        ReplugOutcome.NotReported => (DiagnosticStatus.Warning, "Not supported: Windows doesn't report the power source on this PC."),
        _ => (DiagnosticStatus.Warning, "Not applicable: this PC has no battery, so it runs on wall power only."),
    };

    public static DiagnosticResult ToResult(ChargerReplugReport r)
    {
        var (status, msg) = Outcome(r);
        return new DiagnosticResult<ChargerReplugReport>(ModuleSlugs.ChargerReplug, status, msg, DateTimeOffset.Now, r);
    }
}
