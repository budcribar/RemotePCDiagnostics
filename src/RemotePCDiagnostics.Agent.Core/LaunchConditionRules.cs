namespace RemotePCDiagnostics.Agent.Core;

/// <summary>Where the PC gets its power, as the agent read it.</summary>
public enum PowerReading { Unknown, Ac, Battery }

/// <summary>
/// The conditions a hidden launch for scheduled checks carries: plugged in, nobody using the PC for a while, and inside the allowed
/// hours in the PC's local time. The agent checks them right before it starts the app; any that fails means nothing starts.
/// </summary>
public static class LaunchConditionRules
{
    /// <summary>True when the local minute of the day is inside the window. start == end is any time; the window may cross midnight.</summary>
    public static bool InWindow(int startMinute, int endMinute, int localMinute)
    {
        if (startMinute == endMinute)
            return true;
        return startMinute < endMinute
            ? localMinute >= startMinute && localMinute < endMinute
            : localMinute >= startMinute || localMinute < endMinute;
    }

    /// <summary>"10:00 PM to 6:00 AM".</summary>
    public static string WindowText(int startMinute, int endMinute) => $"{Clock(startMinute)} to {Clock(endMinute)}";

    private static string Clock(int minute) =>
        new DateTime(2000, 1, 1).AddMinutes(Math.Clamp(minute, 0, 1439)).ToString("h:mm tt", System.Globalization.CultureInfo.InvariantCulture);

    /// <summary>
    /// Why the launch must not start, in plain words, or null when every condition holds. <paramref name="idleSeconds"/> is null when it
    /// couldn't be read (or wasn't read: see <see cref="NeedsIdle"/>): an idle rule then fails, as nothing proves the PC is free. A locked session counts as idle.
    /// </summary>
    public static string? Check(bool requireAcPower, int minIdleMinutes, int windowStartMinute, int windowEndMinute,
        DateTimeOffset localNow, PowerReading power, bool sessionLocked, int? idleSeconds)
    {
        var minute = localNow.Hour * 60 + localNow.Minute;
        if (!InWindow(windowStartMinute, windowEndMinute, minute))
            return $"It's outside the allowed hours ({WindowText(windowStartMinute, windowEndMinute)}) on this computer.";
        if (requireAcPower && power != PowerReading.Ac)
            return power == PowerReading.Battery ? "This computer is on battery." : "Couldn't tell whether this computer is plugged in.";
        if (minIdleMinutes > 0 && !sessionLocked)
        {
            var idle = idleSeconds;
            if (idle is null)
                return "Couldn't tell whether someone is using this computer.";
            if (idle.Value < minIdleMinutes * 60)
                return $"Someone used this computer {Ago(idle.Value)} (it needs {minIdleMinutes} minutes without use).";
        }
        return null;
    }

    /// <summary>Whether <see cref="Check"/> needs the idle time: only with an idle rule on an unlocked session.</summary>
    public static bool NeedsIdle(int minIdleMinutes, bool sessionLocked) => minIdleMinutes > 0 && !sessionLocked;

    private static string Ago(int seconds) => seconds < 90 ? "just now" : $"{seconds / 60} minutes ago";
}
