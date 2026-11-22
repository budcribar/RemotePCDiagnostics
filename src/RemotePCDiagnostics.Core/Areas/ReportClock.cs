namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// The time and time zone a check builds its report in: "now" for the "last 7 days" counts, and the zone event times are shown in. A check that
/// is given a clock (a replay test pins it to when the PC was recorded, in UTC) builds its report inside <see cref="Use"/>; otherwise it is the
/// PC's own clock and zone.
/// </summary>
public static class ReportClock
{
    private static readonly AsyncLocal<TimeProvider?> Scoped = new();

    public static TimeProvider Current => Scoped.Value ?? TimeProvider.System;

    /// <summary>Now, in <see cref="Current"/>'s zone.</summary>
    public static DateTimeOffset Now => Current.GetLocalNow();

    /// <summary><paramref name="t"/> in <see cref="Current"/>'s zone.</summary>
    public static DateTimeOffset Local(DateTimeOffset t) => TimeZoneInfo.ConvertTime(t, Current.LocalTimeZone);

    /// <summary>Builds the report with <paramref name="clock"/> until disposed (nothing changes when it is null).</summary>
    public static IDisposable Use(TimeProvider? clock)
    {
        var previous = Scoped.Value;
        if (clock is not null) Scoped.Value = clock;
        return new Restore(previous);
    }

    private sealed class Restore(TimeProvider? previous) : IDisposable
    {
        public void Dispose() => Scoped.Value = previous;
    }
}

/// <summary>A clock stopped at one instant, in one zone (UTC unless given): a replay test's "now" is when the PC was recorded.</summary>
public sealed class FixedClock(DateTimeOffset now, TimeZoneInfo? zone = null) : TimeProvider
{
    public override DateTimeOffset GetUtcNow() => now.ToUniversalTime();
    public override TimeZoneInfo LocalTimeZone => zone ?? TimeZoneInfo.Utc;
}
