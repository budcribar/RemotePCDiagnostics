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

    /// <summary>
    /// What the local window shows in remote mode, under the native panel (which has the link and Copy link): a short note for
    /// the person at the PC, styled like the panel. Never the link again.
    /// </summary>
    public const string LocalPlaceholderHtml =
        "<!DOCTYPE html><html><head><meta charset='utf-8'><style>" +
        "html,body{margin:0;height:100%;background:#1f2329;color:#d0d5dd;font:15px 'Segoe UI',system-ui,sans-serif}" +
        "main{max-width:560px;margin:72px auto;padding:0 24px;line-height:1.5}h1{font-size:18px;font-weight:600;color:#f2f4f7;margin:0 0 8px}" +
        "</style></head><body><main><h1>Your technician is working on this PC</h1>" +
        "<p>The diagnostics run in the technician's browser. Keep this window open (you can minimize it). " +
        "Closing it ends the session.</p></main></body></html>";

    /// <summary>"host:port" for display (port always shown, e.g. remoteblazorwebview.com:34544 or example.com:443).</summary>
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
