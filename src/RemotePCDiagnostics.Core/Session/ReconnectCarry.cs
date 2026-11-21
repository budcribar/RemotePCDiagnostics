using System.Globalization;

namespace RemotePCDiagnostics.Core.Session;

/// <summary>
/// The app reconnects to the relay by starting a new copy of itself under the same session id. This is what one copy hands the
/// next through the environment (not the command line, which Setup and the Agent check against a fixed list): when the
/// reconnect began and how many copies have tried, so a copy that can't reach the relay either keeps going with a longer wait
/// or gives up once <see cref="Window"/> has passed, instead of every copy starting over or the first failure ending it.
/// </summary>
public sealed record ReconnectCarry(DateTimeOffset Since, int Attempt)
{
    public const string SinceEnvVar = "RPD_RECONNECT_SINCE";
    public const string AttemptEnvVar = "RPD_RECONNECT_ATTEMPT";

    /// <summary>How long the app keeps trying after the connection dropped: long enough for Wi-Fi to come back after a wake or a
    /// relay redeploy to finish, short enough that a PC whose relay is gone for good stops trying.</summary>
    public static readonly TimeSpan Window = TimeSpan.FromMinutes(15);

    /// <summary>The longest wait between two tries.</summary>
    public static readonly TimeSpan MaxDelay = TimeSpan.FromSeconds(60);

    /// <summary>A reconnect that starts now.</summary>
    public static ReconnectCarry Start(DateTimeOffset now) => new(now, 0);

    /// <summary>The reconnect this copy was started to continue, or null when it wasn't (or the values are unusable).</summary>
    public static ReconnectCarry? FromEnvironment(Func<string, string?> getEnv, DateTimeOffset now)
    {
        var since = getEnv(SinceEnvVar);
        if (string.IsNullOrWhiteSpace(since) ||
            !DateTimeOffset.TryParse(since, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var started))
            return null;
        if (started > now + TimeSpan.FromMinutes(1))
            return null; // a clock change or a value that wasn't ours
        _ = int.TryParse(getEnv(AttemptEnvVar), NumberStyles.Integer, CultureInfo.InvariantCulture, out var attempt);
        return new ReconnectCarry(started, Math.Max(0, attempt));
    }

    public bool Expired(DateTimeOffset now) => now - Since > Window;

    /// <summary>The wait before try number <see cref="Attempt"/> + 1: 2 s, doubling, at most <see cref="MaxDelay"/>.</summary>
    public TimeSpan NextDelay()
    {
        var seconds = 2.0 * Math.Pow(2, Math.Min(Attempt, 10));
        return TimeSpan.FromSeconds(Math.Min(seconds, MaxDelay.TotalSeconds));
    }

    public ReconnectCarry Next() => this with { Attempt = Attempt + 1 };

    /// <summary>Sets the values for the copy about to start (<see cref="System.Diagnostics.ProcessStartInfo.Environment"/>).</summary>
    public void WriteTo(IDictionary<string, string?> environment)
    {
        environment[SinceEnvVar] = Since.ToString("O", CultureInfo.InvariantCulture);
        environment[AttemptEnvVar] = Attempt.ToString(CultureInfo.InvariantCulture);
    }

    /// <summary>Clears them, for a copy that starts a fresh session (Local Mode, a manual retry).</summary>
    public static void ClearIn(IDictionary<string, string?> environment)
    {
        environment.Remove(SinceEnvVar);
        environment.Remove(AttemptEnvVar);
    }
}
