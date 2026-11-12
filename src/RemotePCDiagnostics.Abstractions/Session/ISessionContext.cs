namespace RemotePCDiagnostics.Core.Session;

public enum SessionMode { Local, Remote }

public interface ISessionContext
{
    SessionMode Mode { get; }
    string MachineName { get; }
    /// <summary>Relay server (RemoteWebViewService) when <see cref="Mode"/> is Remote; otherwise null.</summary>
    Uri? ServerUri => null;
    /// <summary>Active remote session ID (the <c>&lt;id&gt;</c> in the session's links) when <see cref="Mode"/> is Remote; otherwise <see cref="Guid.Empty"/>.</summary>
    Guid SessionId => Guid.Empty;
    /// <summary>True for an unattended session (<c>--unattended</c>): the remote user gets control on joining; the user can take it back.</summary>
    bool Unattended => false;
    /// <summary>True when the session was started with a voice call between the user and the remote user (<c>--voice</c>).</summary>
    bool Voice => false;
    /// <summary>Optional normalized relay shop tenant slug (<c>-g=&lt;group&gt;</c> / <c>REMOTEPC_GROUP</c>) when connected to a shop relay.</summary>
    string? Group => null;
}

public sealed class SessionContext : ISessionContext
{
    public SessionContext(SessionMode mode, Uri? serverUri = null, Guid sessionId = default, bool unattended = false, bool voice = false, string? group = null)
    {
        Mode = mode;
        ServerUri = serverUri;
        SessionId = sessionId != Guid.Empty
            ? sessionId
            : (mode == SessionMode.Remote ? Guid.NewGuid() : Guid.Empty);
        Unattended = unattended;
        Voice = voice;
        Group = NormalizeGroup(group);
    }

    public SessionMode Mode { get; }
    public Uri? ServerUri { get; }
    public Guid SessionId { get; set; }
    public bool Unattended { get; }
    public bool Voice { get; }
    public string? Group { get; }
    public string MachineName { get; } = Environment.MachineName;

    private static string? NormalizeGroup(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var trimmed = value.Trim().Trim('"').Trim();
        return trimmed.Length == 0 ? null : trimmed.ToLowerInvariant();
    }
}
