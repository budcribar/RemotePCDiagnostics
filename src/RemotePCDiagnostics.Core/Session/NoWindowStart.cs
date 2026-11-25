namespace RemotePCDiagnostics.Core.Session;

/// <summary>
/// Starting the app with no visible window (<c>--no-window</c>, or <c>REMOTEPC_NO_WINDOW=1</c>), so a remote user or an AI agent can
/// run checks through the session at a quiet time without a window opening on the person's screen. The session works as usual: the
/// remote UI is served by the relay and does not need the local window to be visible.
/// Only a remote session can start hidden. A local start has nobody else to see it, so it ignores the request and shows the window.
/// Copies this one starts again under the same session (a reconnect, a restart from a browser) inherit the setting through the
/// environment, and showing the window (a second launch at the PC, or clicking the icon in the notification area) turns it off
/// for them.
/// </summary>
public static class NoWindowStart
{
    public const string Arg = "--no-window";
    public const string Variable = "REMOTEPC_NO_WINDOW";

    /// <summary>
    /// The tooltip on the notification-area icon shown while the app runs with no window, so the person at the PC knows why it is
    /// there. Clicking the icon opens the app. Windows cuts a tooltip off at 127 characters.
    /// </summary>
    public const string TrayTip = "Remote PC Diagnostics: your shop is checking this PC. Click to open it.";

    /// <summary>True when this start asked for no window: the argument, or the environment variable set to 1, true or on.</summary>
    public static bool Requested(IEnumerable<string> args, Func<string, string?> env)
    {
        if (args.Any(a => string.Equals(a, Arg, StringComparison.OrdinalIgnoreCase))) return true;
        var v = env(Variable)?.Trim();
        return v is "1" || string.Equals(v, "true", StringComparison.OrdinalIgnoreCase) || string.Equals(v, "on", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>True when the window should stay hidden: asked for, and the session is remote.</summary>
    public static bool Applies(IEnumerable<string> args, Func<string, string?> env, SessionMode mode) =>
        mode == SessionMode.Remote && Requested(args, env);
}
