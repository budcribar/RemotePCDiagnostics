namespace RemotePCDiagnostics.Core.Session;

public enum SessionMode { Local, Remote }

public interface ISessionContext
{
    SessionMode Mode { get; }
    string MachineName { get; }
}

public sealed class SessionContext(SessionMode mode) : ISessionContext
{
    public SessionMode Mode { get; } = mode;
    public string MachineName { get; } = Environment.MachineName;
}
