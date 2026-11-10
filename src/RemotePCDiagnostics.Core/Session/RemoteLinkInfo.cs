namespace RemotePCDiagnostics.Core.Session;

/// <summary>States shown by the Host's native "Remote session" overlay.</summary>
public enum RemoteSessionState { Connecting, Ready, Unreachable, RemoteUserConnected, Disconnected }

/// <summary>Link building and status text for the Remote-mode overlay (no WPF dependency, unit-tested).</summary>
public static class RemoteLinkInfo
{
    /// <summary>
    /// True when RemoteBlazorWebView reports that the relay sent its "shutdown" command ("Server shut down connection"): the relay
    /// dropped this client (the remote user's tab closed) and the link stops working until a copy registers the session id again.
    /// </summary>
    public static bool IsServerShutdown(Exception? error) =>
        error?.Message is { } m && m.Contains("shut down", StringComparison.OrdinalIgnoreCase);

    /// <summary>How long to wait for ReadyToConnect before showing the "couldn't reach the server" warning.</summary>
    public static readonly TimeSpan ReadyTimeout = TimeSpan.FromSeconds(15);

    /// <summary>The app's own page, <c>&lt;server&gt;/app/&lt;id&gt;</c> (the one this window shows, as the owner), safe with or without a trailing slash / path on the server URI.</summary>
    public static Uri BuildRemoteUserUrl(Uri serverUri, Guid id)
    {
        ArgumentNullException.ThrowIfNull(serverUri);
        if (!serverUri.IsAbsoluteUri) throw new ArgumentException("Server URI must be absolute.", nameof(serverUri));
        var b = new UriBuilder(serverUri) { Query = string.Empty, Fragment = string.Empty };
        if (!b.Path.EndsWith('/')) b.Path += "/";
        return new Uri(b.Uri, $"app/{id}");
    }

    /// <summary>The link to share, <c>&lt;server&gt;/mirror/&lt;id&gt;</c>: the read-only page the remote user joins at and is handed control from.</summary>
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
    /// <c>/mirror/&lt;id&gt;</c> page, for the admin Clients list: the local window already holds /app, so the admin link should
    /// join the session, not hit "Locked". Only the href changes.
    /// </summary>
    public static string ToMirrorMarkup(string? appMarkup) => appMarkup?.Replace("/app/", "/mirror/") ?? string.Empty;

    /// <summary>
    /// Marks a page URL as the machine owner's (<c>?role=owner</c>) so the relay records this connection as the owner and
    /// lets it reclaim control. Only the local window's own surface gets this — never the link shared with the remote user.
    /// </summary>
    public static Uri WithOwnerRole(Uri pageUri)
    {
        ArgumentNullException.ThrowIfNull(pageUri);
        var b = new UriBuilder(pageUri);
        b.Query = string.IsNullOrEmpty(b.Query) ? "role=owner" : b.Query.TrimStart('?') + "&role=owner";
        return b.Uri;
    }

    /// <summary>
    /// Unattended sessions: marks the owner's page so it gives control to the remote user as soon as they join
    /// (<c>control=remote</c>, read by RemoteBlazorWebView's page script). The owner can still take control back.
    /// </summary>
    public static Uri WithRemoteUserFirst(Uri pageUri)
    {
        ArgumentNullException.ThrowIfNull(pageUri);
        var b = new UriBuilder(pageUri);
        b.Query = string.IsNullOrEmpty(b.Query) ? "control=remote" : b.Query.TrimStart('?') + "&control=remote";
        return b.Uri;
    }

    /// <summary>What the local window shows while the relay can't be reached (once the app's page is up, its header carries the status).</summary>
    public static string UnreachableHtml(Uri serverUri) =>
        "<!DOCTYPE html><html><head><meta charset='utf-8'><style>" +
        "html,body{margin:0;height:100%;background:#1f2329;color:#d0d5dd;font:15px 'Segoe UI',system-ui,sans-serif}" +
        "main{max-width:560px;margin:72px auto;padding:0 24px;line-height:1.5}h1{font-size:18px;font-weight:600;color:#ffc857;margin:0 0 8px}" +
        "</style></head><body><main><h1>Remote session not connected</h1><p>" +
        System.Net.WebUtility.HtmlEncode(StatusText(RemoteSessionState.Unreachable, serverUri)) + "</p></main></body></html>";

    /// <summary>"host:port" for display (port always shown, e.g. remoteblazorwebview.com:34544 or example.com:443).</summary>
    public static string HostAndPort(Uri serverUri) => $"{serverUri.Host}:{serverUri.Port}";

    public static string StatusText(RemoteSessionState state, Uri serverUri) => state switch
    {
        RemoteSessionState.Connecting => "Connecting to server…",
        RemoteSessionState.Ready => "Ready. Share this link:",
        RemoteSessionState.Unreachable => $"Couldn't reach the server yet: {HostAndPort(serverUri)}. Check your internet connection; still trying…",
        RemoteSessionState.RemoteUserConnected => "Remote user connected",
        RemoteSessionState.Disconnected => "Remote user disconnected",
        _ => string.Empty,
    };

    /// <summary>True when the state is a warning (styled differently in the overlay).</summary>
    public static bool IsWarning(RemoteSessionState state) => state == RemoteSessionState.Unreachable;
}
