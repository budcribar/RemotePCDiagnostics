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
public sealed class SessionAudit(Action<LogEntry> write)
{
    private readonly object _lock = new();
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

            // Control moved.
            var controller = roster.FirstOrDefault(p => p.HasControl);
            if (controller is not null && controller.Id != _controller)
            {
                if (controller.IsOwner)
                {
                    if (_controller is not null) // the owner starting in control is not news
                        Write(SessionAuditIds.ControlBackToOwner, "Control is back with the person at this PC.");
                }
                else
                {
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
