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
}

public sealed class SessionContext : ISessionContext
{
    public SessionContext(SessionMode mode, Uri? serverUri = null, Guid sessionId = default)
    {
        Mode = mode;
        ServerUri = serverUri;
        SessionId = sessionId != Guid.Empty
            ? sessionId
            : (mode == SessionMode.Remote ? Guid.NewGuid() : Guid.Empty);
    }

    public SessionMode Mode { get; }
    public Uri? ServerUri { get; }
    public Guid SessionId { get; set; }
    public string MachineName { get; } = Environment.MachineName;
}
