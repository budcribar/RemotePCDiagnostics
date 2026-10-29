namespace RemotePCDiagnostics.Core.Session;

public enum SessionMode { Local, Remote }

public interface ISessionContext
{
    SessionMode Mode { get; }
    string MachineName { get; }
    /// <summary>Relay server (RemoteWebViewService) when <see cref="Mode"/> is Remote; otherwise null.</summary>
    Uri? ServerUri => null;
}

public sealed class SessionContext(SessionMode mode, Uri? serverUri = null) : ISessionContext
{
    public SessionMode Mode { get; } = mode;
    public Uri? ServerUri { get; } = serverUri;
    public string MachineName { get; } = Environment.MachineName;
}
