namespace RemotePCDiagnostics.Core.Session;

public enum SessionMode { Local, Remote }

public interface ISessionContext
{
    SessionMode Mode { get; }
    string MachineName { get; }
    /// <summary>Relay server (RemoteWebViewService) when <see cref="Mode"/> is Remote; otherwise null.</summary>
    Uri? ServerUri => null;
    /// <summary>Active remote session ID (<c>/app/&lt;id&gt;</c>) when <see cref="Mode"/> is Remote; otherwise <see cref="Guid.Empty"/>.</summary>
    Guid SessionId => Guid.Empty;
    /// <summary>True when the local window mirrors the remote user's session (<c>-m</c> / <c>--mirror</c>).</summary>
    bool Mirror => false;
    /// <summary>True for the demo direction (<c>--reverse-mirror</c>): the local window is in control, the shared link is read-only.</summary>
    bool ReverseMirror => false;
    /// <summary>True for an unattended session (<c>--unattended</c>): the remote user gets control on joining; the user can take it back.</summary>
    bool Unattended => false;
    /// <summary>True when the session was started with a voice call between the user and the remote user (<c>--voice</c>).</summary>
    bool Voice => false;
}

public sealed class SessionContext : ISessionContext
{
    public SessionContext(SessionMode mode, Uri? serverUri = null, Guid sessionId = default, bool mirror = false, bool reverseMirror = false, bool unattended = false, bool voice = false)
    {
        Mode = mode;
        ServerUri = serverUri;
        SessionId = sessionId != Guid.Empty
            ? sessionId
            : (mode == SessionMode.Remote ? Guid.NewGuid() : Guid.Empty);
        Mirror = mirror;
        ReverseMirror = reverseMirror;
        Unattended = unattended;
        Voice = voice;
    }

    public SessionMode Mode { get; }
    public Uri? ServerUri { get; }
    public Guid SessionId { get; set; }
    public bool Mirror { get; }
    public bool ReverseMirror { get; }
    public bool Unattended { get; }
    public bool Voice { get; }
    public string MachineName { get; } = Environment.MachineName;
}
