namespace RemotePCDiagnostics.Core.Session;

/// <summary>States shown by the Host's native "Remote session" overlay.</summary>
public enum RemoteSessionState { Connecting, Ready, Unreachable, TechnicianConnected, Disconnected }

/// <summary>Link building and status text for the Remote-mode overlay (no WPF dependency, unit-tested).</summary>
public static class RemoteLinkInfo
{
    /// <summary>
    /// True when RemoteBlazorWebView reports that the relay sent its "shutdown" command ("Server shut down connection"): the relay
    /// dropped this client (the technician's tab closed) and the link stops working until a copy registers the session id again.
    /// </summary>
    public static bool IsServerShutdown(Exception? error) =>
        error?.Message is { } m && m.Contains("shut down", StringComparison.OrdinalIgnoreCase);

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

    /// <summary>Mirror URL <c>&lt;server&gt;/mirror/&lt;id&gt;</c> so the local user can watch what the technician is doing in real time.</summary>
    public static Uri BuildMirrorUrl(Uri serverUri, Guid id)
    {
        ArgumentNullException.ThrowIfNull(serverUri);
        if (!serverUri.IsAbsoluteUri) throw new ArgumentException("Server URI must be absolute.", nameof(serverUri));
        var b = new UriBuilder(serverUri) { Query = string.Empty, Fragment = string.Empty };
        if (!b.Path.EndsWith('/')) b.Path += "/";
        return new Uri(b.Uri, $"mirror/{id}");
    }

    /// <summary>
    /// Turns the client card markup (which links to the controlling <c>/app/&lt;id&gt;</c> page) into one that links to the read-only
    /// <c>/mirror/&lt;id&gt;</c> page, for the admin Clients list in reverse-mirror demos: the local window already controls /app, so the
    /// admin link should watch, not hit "Locked". Only the href changes.
    /// </summary>
    public static string ToMirrorMarkup(string? appMarkup) => appMarkup?.Replace("/app/", "/mirror/") ?? string.Empty;

    /// <summary>The link to share: the technician link normally, the read-only mirror link with <c>--reverse-mirror</c> (the local window is in control).</summary>
    public static Uri BuildShareUrl(Uri serverUri, Guid id, bool reverseMirror) => reverseMirror ? BuildMirrorUrl(serverUri, id) : BuildTechnicianUrl(serverUri, id);

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

    public static string StatusText(RemoteSessionState state, Uri serverUri, bool mirror = false, bool reverseMirror = false) => state switch
    {
        RemoteSessionState.Connecting => "Connecting to server…",
        RemoteSessionState.Ready when reverseMirror => "Demo: you're in control here. Share this view-only link:",
        RemoteSessionState.Ready => "Ready. Share this link with the technician:",
        RemoteSessionState.Unreachable => $"Couldn't reach the server yet: {HostAndPort(serverUri)}. Check your internet connection; still trying…",
        RemoteSessionState.TechnicianConnected when reverseMirror => "Demo running: you're in control; anyone with the link can watch but not click",
        RemoteSessionState.TechnicianConnected => mirror ? "Technician connected — watching live below" : "Technician connected",
        RemoteSessionState.Disconnected when reverseMirror => "Disconnected from the server",
        RemoteSessionState.Disconnected => "Technician disconnected",
        _ => string.Empty,
    };

    /// <summary>True when the state is a warning (styled differently in the overlay).</summary>
    public static bool IsWarning(RemoteSessionState state) => state == RemoteSessionState.Unreachable;
}
