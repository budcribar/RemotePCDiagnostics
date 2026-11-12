using System.Diagnostics;
using System.Net;

namespace RemotePCDiagnostics.Core.Session;

public enum RemoteRelayIssueKind
{
    None,
    GroupInactive,
    SessionLimitReached,
    CreateFailedOrDenied,
    RelayUnreachable,
}

/// <summary>
/// Live relay connection health observed by the host window so <c>MainLayout</c> can display clear, human-friendly guidance when a
/// shop group is inactive, at its concurrent session cap, or unreachable.
/// </summary>
public sealed class RemoteSessionHealth
{
    private readonly object _gate = new();
    private RemoteSessionState _state;
    private RemoteRelayIssueKind _issue = RemoteRelayIssueKind.None;
    private string? _detail;

    public event Action? Changed;

    public RemoteSessionState State { get { lock (_gate) return _state; } }
    public RemoteRelayIssueKind Issue { get { lock (_gate) return _issue; } }
    public string? Detail { get { lock (_gate) return _detail; } }

    public void ReportReady()
    {
        lock (_gate)
        {
            _state = RemoteSessionState.Ready;
            _issue = RemoteRelayIssueKind.None;
            _detail = null;
        }
        Notify();
    }

    public void ReportConnected()
    {
        lock (_gate)
        {
            _state = RemoteSessionState.RemoteUserConnected;
            _issue = RemoteRelayIssueKind.None;
            _detail = null;
        }
        Notify();
    }

    public void ReportFailure(RemoteSessionState state, string? exceptionMessage)
    {
        var classified = ClassifyError(exceptionMessage, state);
        lock (_gate)
        {
            _state = state;
            _issue = classified;
            _detail = string.IsNullOrWhiteSpace(exceptionMessage) ? null : exceptionMessage.Trim();
        }
        Notify();
    }

    public static RemoteRelayIssueKind ClassifyError(string? message, RemoteSessionState state = RemoteSessionState.Unreachable)
    {
        if (!string.IsNullOrWhiteSpace(message))
        {
            if (message.Contains("group_inactive", StringComparison.OrdinalIgnoreCase))
                return RemoteRelayIssueKind.GroupInactive;
            if (message.Contains("session_limit_reached", StringComparison.OrdinalIgnoreCase))
                return RemoteRelayIssueKind.SessionLimitReached;
            if (message.Contains("Create failed", StringComparison.OrdinalIgnoreCase)
                || message.Contains("createFailed", StringComparison.OrdinalIgnoreCase))
                return RemoteRelayIssueKind.CreateFailedOrDenied;
        }
        return state == RemoteSessionState.Unreachable
            ? RemoteRelayIssueKind.RelayUnreachable
            : RemoteRelayIssueKind.None;
    }

    /// <summary>
    /// Fallback HTML displayed in the host WebView when <c>CreateWebView</c> fails before the remote Blazor app page can load
    /// and a shop <paramref name="groupSlug"/> was specified.
    /// </summary>
    public static string BuildShopRelayDeniedHtml(Uri serverUri, string groupSlug, RemoteRelayIssueKind issue)
    {
        var server = WebUtility.HtmlEncode(serverUri.GetLeftPart(UriPartial.Authority));
        var group = WebUtility.HtmlEncode(groupSlug);
        var (headline, explanation) = issue switch
        {
            RemoteRelayIssueKind.GroupInactive => (
                $"Shop code \"{group}\" is not active",
                "This repair shop code was not found on the relay or its subscription/trial is currently inactive. Ask the shop to verify their shop code or billing status."),
            RemoteRelayIssueKind.SessionLimitReached => (
                $"Shop \"{group}\" is at its active session limit",
                "All concurrent remote support slots for this shop plan are currently in use. Ask a bench member to close an idle session or try again shortly."),
            RemoteRelayIssueKind.CreateFailedOrDenied => (
                $"Could not start remote session for shop \"{group}\"",
                "The relay declined the remote session request. Confirm that the shop code is active and has an open concurrent session slot, or restart in Local mode."),
            _ => (
                $"Can't reach relay {server}",
                $"Remote PC Diagnostics could not connect to {server} for shop \"{group}\". Check the internet connection and relay address, or run without -u= for Local mode."),
        };

        return $$"""
            <!DOCTYPE html>
            <html lang="en"><head><meta charset="utf-8"><title>Remote PC Diagnostics</title>
            <style>
              body { font: 15px/1.55 "Segoe UI", system-ui, sans-serif; margin: 0; padding: 48px 24px; background: #0f1419; color: #e6edf3; }
              main { max-width: 560px; margin: 0 auto; background: #161c23; border: 1px solid #3b2e14; border-radius: 10px; padding: 24px 28px; }
              h1 { font-size: 18px; margin: 0 0 10px; color: #fbbf24; }
              p { margin: 0 0 12px; color: #9fb0c0; }
              code { background: #0f1419; padding: 2px 6px; border-radius: 4px; color: #e6edf3; }
            </style></head>
            <body><main>
              <h1>{{headline}}</h1>
              <p>{{explanation}}</p>
              <p>Relay: <code>{{server}}</code> &middot; Shop code: <code>{{group}}</code></p>
            </main></body></html>
            """;
    }

    private void Notify()
    {
        try { Changed?.Invoke(); } catch { }
    }
}

public sealed record SessionRelaunchOutcome(
    bool RelaunchedDesktopProcess,
    string CommandLinePreview,
    string Message);

public interface ISessionRelauncher
{
    bool CanRelaunchDesktopProcess { get; }
    SessionRelaunchOutcome RequestRemoteSession(Uri relayServerUri, string groupSlug);
}

/// <summary>
/// Relaunches <c>RemotePCDiagnostics.Host.exe</c> into <see cref="SessionMode.Remote"/> with <c>-u=&lt;relay&gt; -g=&lt;group&gt; --restarted</c>
/// when bound to a live desktop <c>MainWindow</c>, or returns a preview confirmation when running in headless/test hosts.
/// </summary>
public sealed class DesktopSessionRelauncher(ISessionContext session, ILogger? log = null) : ISessionRelauncher
{
    private Action? _closeCurrentWindow;

    public bool CanRelaunchDesktopProcess => _closeCurrentWindow is not null;

    public void BindWindowClose(Action closeWindow) => _closeCurrentWindow = closeWindow;

    public SessionRelaunchOutcome RequestRemoteSession(Uri relayServerUri, string groupSlug)
    {
        ArgumentNullException.ThrowIfNull(relayServerUri);
        var normalizedGroup = SessionLaunchOptions.NormalizeGroup(groupSlug)
            ?? throw new ArgumentException("Shop group code is required.", nameof(groupSlug));
        var cleanUrl = relayServerUri.AbsoluteUri.TrimEnd('/');
        var args = new List<string>
        {
            $"-u={cleanUrl}",
            $"-g={normalizedGroup}",
        };
        if (session.Unattended) args.Add(SessionLaunchOptions.UnattendedArg);
        if (session.Voice) args.Add(SessionLaunchOptions.VoiceArg);
        args.Add(SessionLaunchOptions.RestartedArg);

        var preview = $"RemotePCDiagnostics.Host.exe -u=\"{cleanUrl}\" -g=\"{normalizedGroup}\"";

        if (_closeCurrentWindow is { } closeWindow && Environment.ProcessPath is { Length: > 0 } exePath && File.Exists(exePath))
        {
            var psi = new ProcessStartInfo(exePath)
            {
                UseShellExecute = false,
                WorkingDirectory = Path.GetDirectoryName(exePath) ?? Environment.CurrentDirectory,
            };
            foreach (var a in args) psi.ArgumentList.Add(a);

            Process.Start(psi);
            log.Info($"[shop-relaunch] Started remote session copy: {exePath} {string.Join(' ', args)}");
            closeWindow();
            return new SessionRelaunchOutcome(
                RelaunchedDesktopProcess: true,
                CommandLinePreview: preview,
                Message: $"Relaunching into remote shop session '{normalizedGroup}'…");
        }

        log.Info($"[shop-relaunch] Preview mode remote session configured: {preview}");
        return new SessionRelaunchOutcome(
            RelaunchedDesktopProcess: false,
            CommandLinePreview: preview,
            Message: $"Preview mode: saved relay {cleanUrl} and shop code '{normalizedGroup}'. Desktop Host launches with {preview}.");
    }
}
