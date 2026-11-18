namespace RemotePCDiagnostics.Core;

/// <summary>One fault the app noticed in itself: a page that threw while drawing or handling a click.</summary>
public sealed record AppFault(int Seq, string Page, string Type, string Message, DateTimeOffset At);

/// <summary>
/// The app's own record of its faults, published on every page as a hidden copy (app-fault-data). An automation notes
/// <see cref="Seq"/> before a step and reads it again afterwards: a higher number means the app faulted during the step, so the
/// step's failure is the app's and not a missing element. The app does not retry; whoever asked for the step decides that.
/// </summary>
public sealed class AppFaults(Func<DateTimeOffset>? now = null)
{
    /// <summary>The app's one record. Tests make their own.</summary>
    public static AppFaults Shared { get; } = new();

    private readonly Func<DateTimeOffset> _now = now ?? (() => DateTimeOffset.Now);
    private readonly object _gate = new();
    private AppFault? _last;
    private int _seq;

    /// <summary>The number of faults recorded so far; it only grows.</summary>
    public int Seq { get { lock (_gate) return _seq; } }
    /// <summary>The latest fault, or null when there has been none.</summary>
    public AppFault? Last { get { lock (_gate) return _last; } }
    /// <summary>Raised after a fault is recorded.</summary>
    public event Action? Changed;

    public AppFault Record(string page, Exception exception)
    {
        var inner = exception is AggregateException { InnerExceptions.Count: 1 } one ? one.InnerExceptions[0] : exception;
        var message = (inner.Message ?? "").Split('\n')[0].Trim();
        if (message.Length > 300) message = message[..299] + "…";
        AppFault fault;
        lock (_gate) _last = fault = new(++_seq, page, inner.GetType().Name, message, _now());
        try { Changed?.Invoke(); } catch { /* a listener must not turn one fault into two */ }
        return fault;
    }
}
