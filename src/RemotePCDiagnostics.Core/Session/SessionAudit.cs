using RemotePCDiagnostics.Core.Logging;

namespace RemotePCDiagnostics.Core.Session;

/// <summary>One page in the shared session, as RemoteBlazorWebView's ParticipantsChanged reports it.</summary>
/// <param name="Id">The page's connection id.</param>
/// <param name="IsOwner">This PC's own window.</param>
/// <param name="HasControl">Its input reaches the app.</param>
/// <param name="Name">The signed-in name when the relay requires sign-in; otherwise empty.</param>
public sealed record SessionParticipant(string Id, bool IsOwner, bool HasControl, string Name);

/// <summary>Windows Event Log IDs of the session audit (see README "Session audit").</summary>
public static class SessionAuditIds
{
    public const int Started = 2000;
    public const int RemoteUserJoined = 2001;
    public const int ViewerJoined = 2002;
    public const int ControlToRemoteUser = 2003;
    public const int ControlBackToOwner = 2004;
    public const int Left = 2005;
    public const int Ended = 2006;
}

/// <summary>
/// The audit trail of a remote session: when it started (supervised or unattended), who joined (with their signed-in name),
/// every time control moved, who left, and when it ended. Fed the whole roster on every change and writes only what changed.
/// The first page that is not this PC's window is the remote user; any later ones are read-only viewers.
/// Service and fix actions are already logged with who did them (event 1100), so they are not repeated here.
/// </summary>
public sealed class SessionAudit(Action<LogEntry> write, Func<DateTimeOffset>? clock = null)
{
    /// <summary>How long after the remote user's page left while in control <see cref="RemoteUserHadControl"/> still says yes: a
    /// browser refresh drops their page and joins a new one, and the restart it asks for comes after that.</summary>
    public static readonly TimeSpan ControlLeftGrace = TimeSpan.FromMinutes(2);

    private readonly object _lock = new();
    private readonly Func<DateTimeOffset> _clock = clock ?? (() => DateTimeOffset.UtcNow);
    private DateTimeOffset? _remoteLeftInControlUtc;
    private Dictionary<string, SessionParticipant> _present = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _roles = new(StringComparer.Ordinal);
    private string? _controller;
    private bool _started;

    public void Started(bool unattended)
    {
        lock (_lock)
        {
            if (_started) return;
            _started = true;
            Write(SessionAuditIds.Started, unattended
                ? "Remote session started.\nMode: Unattended (the remote user gets control when they join)"
                : "Remote session started.\nMode: Supervised (the person at this PC gives control)");
        }
    }

    public void Update(IReadOnlyList<SessionParticipant> roster)
    {
        lock (_lock)
        {
            var now = new Dictionary<string, SessionParticipant>(StringComparer.Ordinal);
            foreach (var p in roster) now[p.Id] = p;

            // Joined, in roster (join) order. Each page keeps the role it joined with.
            bool remoteUserPresent = _present.Values.Any(p => !p.IsOwner && _roles.GetValueOrDefault(p.Id) == RemoteUser);
            foreach (var p in roster)
            {
                if (p.IsOwner || _present.ContainsKey(p.Id)) continue;
                var role = remoteUserPresent ? Viewer : RemoteUser;
                if (role == RemoteUser) remoteUserPresent = true;
                _roles[p.Id] = role;
                Write(role == RemoteUser ? SessionAuditIds.RemoteUserJoined : SessionAuditIds.ViewerJoined,
                    $"{Capital(role)} joined.\nName: {NameOf(p)}");
            }

            // The remote user's page left while it had control (closed, refreshed, or its connection dropped): remembered for a
            // short while, so a restart asked for right after still gives control back.
            var previous = _controller is { } pc && _present.TryGetValue(pc, out var prev) ? prev : null;
            if (previous is { IsOwner: false } && !now.ContainsKey(previous.Id)) _remoteLeftInControlUtc = _clock();

            // Control moved.
            var controller = roster.FirstOrDefault(p => p.HasControl);
            if (controller is not null && controller.Id != _controller)
            {
                if (controller.IsOwner)
                {
                    // Taken back (or handed back) while the remote user is still here: that is the owner's choice, so it sticks.
                    if (previous is { IsOwner: false } && now.ContainsKey(previous.Id)) _remoteLeftInControlUtc = null;
                    if (_controller is not null) // the owner starting in control is not news
                        Write(SessionAuditIds.ControlBackToOwner, "Control is back with the person at this PC.");
                }
                else
                {
                    _remoteLeftInControlUtc = null;
                    Write(SessionAuditIds.ControlToRemoteUser,
                        $"Control moved to the {RoleOf(controller.Id)}.\nName: {NameOf(controller)}");
                }
            }
            if (controller is not null) _controller = controller.Id;

            // Left.
            foreach (var gone in _present.Values.Where(p => !p.IsOwner && !now.ContainsKey(p.Id)))
            {
                Write(SessionAuditIds.Left, $"{Capital(RoleOf(gone.Id))} left.\nName: {NameOf(gone)}");
                _roles.Remove(gone.Id);
                if (_controller == gone.Id) _controller = null;
            }

            _present = now;
        }
    }

    /// <summary>
    /// True when the remote user has control now, or their page left while it had control less than <see cref="ControlLeftGrace"/>
    /// ago (and the person at this PC has not taken it back since). A restart asked for from the session then hands control back
    /// to the remote user when they rejoin, instead of leaving it with the person at this PC.
    /// </summary>
    public bool RemoteUserHadControl
    {
        get
        {
            lock (_lock) return HadControl(RemoteUserHasControlLocked(), _remoteLeftInControlUtc, _clock());
        }
    }

    /// <summary>The remote user has control right now.</summary>
    public bool RemoteUserHasControl
    {
        get { lock (_lock) return RemoteUserHasControlLocked(); }
    }

    /// <summary>When the remote user's page last left while it had control (null once the person at this PC took it back).</summary>
    public DateTimeOffset? RemoteLeftInControlUtc
    {
        get { lock (_lock) return _remoteLeftInControlUtc; }
    }

    /// <summary><see cref="RemoteUserHadControl"/> from saved state (the Agent reads it from the active session file).</summary>
    public static bool HadControl(bool hasControlNow, DateTimeOffset? leftInControlUtc, DateTimeOffset nowUtc) =>
        hasControlNow || (leftInControlUtc is { } left && nowUtc - left <= ControlLeftGrace && nowUtc >= left);

    private bool RemoteUserHasControlLocked() =>
        _controller is { } c && _present.TryGetValue(c, out var p) && !p.IsOwner;

    public void Ended(string reason)
    {
        lock (_lock)
        {
            if (!_started) return;
            _started = false;
            Write(SessionAuditIds.Ended, string.IsNullOrWhiteSpace(reason) ? "Remote session ended." : $"Remote session ended.\nReason: {reason}");
            _present = new(StringComparer.Ordinal);
            _roles.Clear();
            _controller = null;
            _remoteLeftInControlUtc = null;
        }
    }

    private const string RemoteUser = "remote user", Viewer = "viewer";

    private string RoleOf(string id) => _roles.GetValueOrDefault(id) ?? RemoteUser;

    private static string NameOf(SessionParticipant p) => string.IsNullOrWhiteSpace(p.Name) ? "(not signed in)" : p.Name;

    private static string Capital(string s) => char.ToUpperInvariant(s[0]) + s[1..];

    private void Write(int id, string message)
    {
        try { write(new LogEntry(id, LogLevel.Information, message.Replace("\n", Environment.NewLine))); } catch { }
    }
}
