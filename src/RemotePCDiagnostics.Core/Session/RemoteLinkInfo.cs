namespace RemotePCDiagnostics.Core.Session;

/// <summary>States shown by the Host's native "Remote session" overlay.</summary>
public enum RemoteSessionState { Connecting, Ready, Unreachable, TechnicianConnected, Disconnected }

/// <summary>Link building and status text for the Remote-mode overlay (no WPF dependency, unit-tested).</summary>
public static class RemoteLinkInfo
{
    /// <summary>How long to wait for ReadyToConnect before showing the "couldn't reach the server" warning.</summary>
    public static readonly TimeSpan ReadyTimeout = TimeSpan.FromSeconds(15);

    /// <summary>Technician URL <c>&lt;server&gt;/app/&lt;id&gt;</c>, safe with or without a trailing slash / path on the server URI.</summary>
    public static Uri BuildTechnicianUrl(Uri serverUri, Guid id)
    {
        ArgumentNullException.ThrowIfNull(serverUri);
        if (!serverUri.IsAbsoluteUri) throw new ArgumentException("Server URI must be absolute.", nameof(serverUri));
        var b = new UriBuilder(serverUri) { Query = string.Empty, Fragment = string.Empty };
        if (!b.Path.EndsWith('/')) b.Path += "/";
        return new Uri(b.Uri, $"app/{id}");
    }

    /// <summary>"host:port" for display (port always shown, e.g. remoteblazor.pagetomovie.com:34544 or example.com:443).</summary>
    public static string HostAndPort(Uri serverUri) => $"{serverUri.Host}:{serverUri.Port}";

    public static string StatusText(RemoteSessionState state, Uri serverUri) => state switch
    {
        RemoteSessionState.Connecting => "Connecting to server…",
        RemoteSessionState.Ready => "Ready. Share this link with the technician:",
        RemoteSessionState.Unreachable => $"Couldn't reach the server yet: {HostAndPort(serverUri)}. Check your internet connection; still trying…",
        RemoteSessionState.TechnicianConnected => "Technician connected",
        RemoteSessionState.Disconnected => "Technician disconnected",
        _ => string.Empty,
    };

    /// <summary>True when the state is a warning (styled differently in the overlay).</summary>
    public static bool IsWarning(RemoteSessionState state) => state == RemoteSessionState.Unreachable;
}
