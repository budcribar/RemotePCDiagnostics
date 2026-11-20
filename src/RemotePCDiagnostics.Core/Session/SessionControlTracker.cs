namespace RemotePCDiagnostics.Core.Session;

/// <summary>
/// Who should keep control of a shared session, and when the PC's own window must give it back.
/// </summary>
/// <remarks>
/// The relay gives control back to the owner window when the controlling mirror's stream ends
/// (<c>BrowserIPCService.OnConnectionClosed</c>). A quiet mirror stream is cut off about once a minute
/// (a proxy idle timeout, or the mirror reloading after the connection-lost notice), so control bounces:
/// the mirror is in control, the stream dies, the owner window has it, and the next join is handed it again
/// a couple of seconds later. Focus, a reconnect and a timer are not a reason to keep that. Only an explicit
/// Take or Give on the session bar is. <see cref="StreamKeepalive"/> is how often a remote session redraws
/// so that stream is not left idle long enough to be cut off.
/// </remarks>
public sealed class SessionControlTracker
{
    public const int GestureWindowMs = 10_000;
    public const int HandbackIntervalMs = 3_000;

    /// <summary>Shorter than a one-minute idle cut-off, so a quiet session still writes to every mirror's stream.</summary>
    public static readonly TimeSpan StreamKeepalive = TimeSpan.FromSeconds(20);

    /// <summary>Who has control right now: "owner", "remote", or "none".</summary>
    public string ActualHolder { get; private set; } = "none";

    /// <summary>Who last took control on purpose and should keep it: "owner" or "remote".</summary>
    public string KeptWith { get; private set; } = "owner";

    /// <summary>Why <see cref="KeptWith"/> last changed.</summary>
    public string Reason { get; private set; } = "session-start";

    /// <summary>When <see cref="Reason"/> last changed.</summary>
    public DateTimeOffset? MovedAt { get; private set; }

    private DateTimeOffset _lastHandback = DateTimeOffset.MinValue;

    public event Action? Changed;

    /// <param name="ReportedByOwnerPage">The notice came from the PC's own window, the only page that can give control back.</param>
    /// <param name="OwnerHasControl">The roster says the owner window's connection is the controller.</param>
    /// <param name="RemotePresent">A mirror other than the owner is in the roster.</param>
    /// <param name="Gesture">"take" or "give" when this page's session bar was clicked, otherwise null.</param>
    /// <param name="GestureAgeMs">How long ago that click was. Negative when there was none.</param>
    public readonly record struct Observation(
        bool ReportedByOwnerPage,
        bool OwnerHasControl,
        bool RemotePresent,
        string? Gesture,
        int? GestureAgeMs);

    /// <summary>
    /// The notice the owner window's script sends. Names match <c>rpdSession.getControlInfo</c>.
    /// <see cref="LocalHasControl"/> is the roster: true when the owner window holds control, on every mirror.
    /// </summary>
    public sealed class Notice
    {
        public bool IsRemoteDisplay { get; set; }
        public bool RemoteJoined { get; set; }
        public bool LocalHasControl { get; set; }
        public string? Gesture { get; set; }
        public int GestureAgeMs { get; set; } = -1;

        public Observation ToObservation() => new(
            ReportedByOwnerPage: !IsRemoteDisplay,
            OwnerHasControl: LocalHasControl,
            RemotePresent: RemoteJoined,
            Gesture: Gesture,
            GestureAgeMs: GestureAgeMs < 0 ? null : GestureAgeMs);
    }

    /// <summary>True when the owner window should give control back to the remote mirror.</summary>
    public bool Observe(Observation observation, DateTimeOffset now)
    {
        var gestureFresh = observation.Gesture is "take" or "give"
            && observation.GestureAgeMs is int age && age >= 0 && age <= GestureWindowMs;
        var explicitTake = gestureFresh && observation.Gesture == "take" && observation.ReportedByOwnerPage;
        var explicitGive = gestureFresh && observation.Gesture == "give" && observation.ReportedByOwnerPage;

        var actual = observation.RemotePresent
            ? observation.OwnerHasControl ? "owner" : "remote"
            : observation.OwnerHasControl ? "owner" : "none";

        string kept;
        string reason;
        var handBack = false;

        if (explicitTake)
        {
            kept = "owner";
            reason = "explicit-take";
        }
        else if (explicitGive)
        {
            kept = "remote";
            reason = "explicit-give";
        }
        else if (!observation.OwnerHasControl && observation.RemotePresent)
        {
            // The mirror has it, however it got it (unattended handoff, or the connector asked).
            kept = "remote";
            reason = "remote-holds";
        }
        else if (observation.OwnerHasControl && observation.RemotePresent && KeptWith == "remote")
        {
            // The owner window gained it without a Take click: a dropped mirror stream, focus, or a timer.
            kept = "remote";
            reason = "restored";
            handBack = observation.ReportedByOwnerPage;
        }
        else if (!observation.RemotePresent && KeptWith == "remote")
        {
            kept = "remote";
            reason = "remote-away";
        }
        else
        {
            kept = actual == "remote" ? "remote" : "owner";
            reason = kept == "owner" ? "owner-holds" : "remote-holds";
        }

        if (actual != ActualHolder || kept != KeptWith || reason != Reason)
        {
            ActualHolder = actual;
            KeptWith = kept;
            Reason = reason;
            MovedAt = now;
            Changed?.Invoke();
        }
        return handBack;
    }

    /// <summary>True the first time in <see cref="HandbackIntervalMs"/>, so a restore is not requested on every roster tick.</summary>
    public bool TryMarkHandback(DateTimeOffset now)
    {
        if (now - _lastHandback < TimeSpan.FromMilliseconds(HandbackIntervalMs))
            return false;
        _lastHandback = now;
        return true;
    }
}
