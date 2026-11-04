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
    /// <summary>True when the local window mirrors the remote technician's session (<c>-m</c> / <c>--mirror</c>).</summary>
    bool Mirror => false;
    /// <summary>True for the demo direction (<c>--reverse-mirror</c>): the local window is in control, the shared link is read-only.</summary>
    bool ReverseMirror => false;
}

public sealed class SessionContext : ISessionContext
{
    public SessionContext(SessionMode mode, Uri? serverUri = null, Guid sessionId = default, bool mirror = false, bool reverseMirror = false)
    {
        Mode = mode;
        ServerUri = serverUri;
        SessionId = sessionId != Guid.Empty
            ? sessionId
            : (mode == SessionMode.Remote ? Guid.NewGuid() : Guid.Empty);
        Mirror = mirror;
        ReverseMirror = reverseMirror;
    }

    public SessionMode Mode { get; }
    public Uri? ServerUri { get; }
    public Guid SessionId { get; set; }
    public bool Mirror { get; }
    public bool ReverseMirror { get; }
    public string MachineName { get; } = Environment.MachineName;
}
