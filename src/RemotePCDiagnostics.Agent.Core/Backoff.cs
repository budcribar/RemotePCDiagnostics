namespace RemotePCDiagnostics.Agent.Core;

/// <summary>Reconnect delays: 2 s, doubling up to 60 s. <see cref="Reset"/> after a connection that stayed up.</summary>
public sealed class Backoff
{
    public static readonly TimeSpan Initial = TimeSpan.FromSeconds(2);
    public static readonly TimeSpan Max = TimeSpan.FromSeconds(60);
    /// <summary>A connection that lasted at least this long counts as healthy, so the next failure starts again at 2 s.</summary>
    public static readonly TimeSpan HealthyConnection = TimeSpan.FromSeconds(30);

    private TimeSpan _next = Initial;

    /// <summary>The delay to wait now; the following call returns twice as much (at most <see cref="Max"/>).</summary>
    public TimeSpan Next()
    {
        var d = _next;
        var doubled = TimeSpan.FromTicks(_next.Ticks * 2);
        _next = doubled > Max ? Max : doubled;
        return d;
    }

    public void Reset() => _next = Initial;

    /// <summary>Call after a connection ends: resets when it lasted long enough to be considered healthy.</summary>
    public void ConnectionEnded(TimeSpan lasted)
    {
        if (lasted >= HealthyConnection) Reset();
    }
}
