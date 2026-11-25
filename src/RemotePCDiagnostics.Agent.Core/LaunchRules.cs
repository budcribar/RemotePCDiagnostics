using System.Text;

namespace RemotePCDiagnostics.Agent.Core;

public enum Readiness { Wait, Ready, ReadyUnconfirmed, Exited }

/// <summary>Rules for starting the app from a LaunchCommand.</summary>
public static class LaunchRules
{
    /// <summary>
    /// How long to wait before asking the relay again whether the app has registered. The app normally registers a second or two
    /// after it starts, so the first few seconds are asked often: a fixed 2 seconds added, on average, a second to every launch.
    /// A launch that is taking long is asked less often, so one that never registers costs about 70 requests in
    /// <see cref="StatusPollLimit"/>, not hundreds.
    /// </summary>
    public static TimeSpan PollInterval(TimeSpan elapsed) =>
        elapsed < TimeSpan.FromSeconds(5) ? TimeSpan.FromMilliseconds(250)
        : elapsed < TimeSpan.FromSeconds(20) ? TimeSpan.FromSeconds(1)
        : TimeSpan.FromSeconds(2);
    public static readonly TimeSpan StatusPollLimit = TimeSpan.FromSeconds(90);
    /// <summary>Running this long without exiting counts as started when the relay's /status can't confirm it.</summary>
    public static readonly TimeSpan AssumeReadyAfter = TimeSpan.FromSeconds(20);

    /// <summary>Checks the relay-supplied fields that end up on the app's command line. Returns null when they're fine.</summary>
    public static string? Validate(string? sessionId, string? serverUrl, out Guid session, out string server, string? configuredServer = null)
    {
        server = "";
        if (!Guid.TryParse(sessionId, out session) || session == Guid.Empty) return "The relay sent an invalid session id.";
        if (!AgentCommandLine.TryNormalizeServer(serverUrl, out server)) return "The relay sent an invalid server address.";
        if (!string.IsNullOrWhiteSpace(configuredServer)
            && AgentCommandLine.TryNormalizeServer(configuredServer, out var expectedServer))
        {
            var actualUri = new Uri(server, UriKind.Absolute);
            var expectedUri = new Uri(expectedServer, UriKind.Absolute);
            if (!string.Equals(actualUri.Scheme, expectedUri.Scheme, StringComparison.OrdinalIgnoreCase)
                || !string.Equals(actualUri.Host, expectedUri.Host, StringComparison.OrdinalIgnoreCase)
                || actualUri.Port != expectedUri.Port)
            {
                return "The relay sent a server address that does not match this agent's configured server.";
            }
        }
        return null;
    }

    /// <summary><c>&lt;server&gt;/status/&lt;session&gt;</c>, which answers <c>{"connected":true}</c> once the app has registered.</summary>
    public static string StatusUrl(string server, Guid session) => server.TrimEnd('/') + "/status/" + session.ToString("D");

    /// <summary>Reads the relay's /status answer. null when it isn't the expected JSON (e.g. the relay requires sign-in).</summary>
    public static bool? ParseStatus(string? body)
    {
        if (string.IsNullOrWhiteSpace(body)) return null;
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(body);
            if (doc.RootElement.ValueKind == System.Text.Json.JsonValueKind.Object
                && doc.RootElement.TryGetProperty("connected", out var c)
                && c.ValueKind is System.Text.Json.JsonValueKind.True or System.Text.Json.JsonValueKind.False)
                return c.GetBoolean();
        }
        catch (System.Text.Json.JsonException) { }
        return null;
    }

    /// <summary>
    /// After the app started: READY as soon as the relay says the app registered; when the relay can't tell us (no usable answer), READY once the
    /// app has run <see cref="AssumeReadyAfter"/> without exiting; when the relay keeps answering "not yet", wait up to <see cref="StatusPollLimit"/> and then
    /// report it running but unconfirmed.
    /// </summary>
    public static Readiness Decide(TimeSpan elapsed, bool processExited, bool? relaySaysConnected, bool relayEverAnswered)
    {
        if (processExited) return Readiness.Exited;
        if (relaySaysConnected == true) return Readiness.Ready;
        if (!relayEverAnswered && elapsed >= AssumeReadyAfter) return Readiness.Ready;
        if (elapsed >= StatusPollLimit) return Readiness.ReadyUnconfirmed;
        return Readiness.Wait;
    }

    /// <summary>Plain words for an app that exited before it was ready (exit codes from RemotePCDiagnostics.Host App.xaml.cs).</summary>
    public static string EarlyExitText(uint exitCode) => exitCode switch
    {
        2 => "Remote PC Diagnostics is already open on this computer",
        5 => "Remote PC Diagnostics needs administrator rights, and the signed-in user isn't an administrator",
        _ => $"Remote PC Diagnostics closed right after starting (exit code {exitCode})",
    };

    /// <summary>
    /// The app's command line: <c>"&lt;entry path&gt;" -u=&lt;server&gt; -i=&lt;session&gt; [-g=&lt;group&gt;] --unattended [--no-window]</c>. A session the
    /// agent starts is shared like any other (the app shows at the PC, the requester joins at the session's link), and unattended, so
    /// the requester gets control on joining without anyone at the PC handing it over. This is not the agent's own "unattended"
    /// setting, which is about skipping the consent prompt. <paramref name="hidden"/> (LaunchCommand.hidden, set by the relay only
    /// for a session nobody was asked about) adds <see cref="NoWindowArg"/>: the app runs with no window and shows a tray icon.
    /// </summary>
    public static string AppCommandLine(string entryPath, string server, Guid session, string? group = null, bool hidden = false)
    {
        var parts = new List<string> { entryPath, "-u=" + server, "-i=" + session.ToString("D") };
        if (!string.IsNullOrWhiteSpace(group)) parts.Add("-g=" + group.Trim().ToLowerInvariant());
        parts.Add("--unattended");
        if (hidden) parts.Add(NoWindowArg);
        return WindowsCommandLine.Join(parts);
    }

    /// <summary>The app's no-window switch (RemotePCDiagnostics.Core.Session.NoWindowStart.Arg; this project doesn't reference Core).</summary>
    public const string NoWindowArg = "--no-window";

    /// <summary>The consent prompt's command line, run in the user's session.</summary>
    public static string ConsentCommandLine(string agentExe, string requester, int timeoutSeconds) =>
        WindowsCommandLine.Join([agentExe, "consent", "--requester=" + AgentCommandLine.CleanRequester(requester),
            "--timeout=" + timeoutSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture)]);

    /// <summary>The agent started in the signed-in user's session to read how long since the keyboard or mouse was last used.</summary>
    public static string IdleProbeCommandLine(string agentExe) => WindowsCommandLine.Join([agentExe, "idle"]);

    /// <summary>"Windows 11 Pro 24H2 (26100)". The registry's ProductName still says "Windows 10" on Windows 11 (build 22000 and later).</summary>
    public static string OsVersionText(string? productName, string? displayVersion, string? build)
    {
        var name = string.IsNullOrWhiteSpace(productName) ? "Windows" : productName.Trim();
        if (int.TryParse(build, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var b) && b >= 22000
            && name.StartsWith("Windows 10", StringComparison.OrdinalIgnoreCase))
            name = "Windows 11" + name["Windows 10".Length..];
        var sb = new StringBuilder(name);
        if (!string.IsNullOrWhiteSpace(displayVersion)) sb.Append(' ').Append(displayVersion.Trim());
        if (!string.IsNullOrWhiteSpace(build)) sb.Append(" (").Append(build.Trim()).Append(')');
        return sb.ToString();
    }
}

/// <summary>Builds a command line that CommandLineToArgvW / the C runtime split back into the same arguments.</summary>
public static class WindowsCommandLine
{
    public static string Join(IEnumerable<string> args) => string.Join(' ', args.Select(Quote));

    public static string Quote(string arg)
    {
        if (arg.Length > 0 && !arg.Any(ch => ch is ' ' or '\t' or '\n' or '\v' or '"')) return arg;
        var sb = new StringBuilder("\"");
        var backslashes = 0;
        foreach (var ch in arg)
        {
            if (ch == '\\') { backslashes++; continue; }
            if (ch == '"') { sb.Append('\\', backslashes * 2 + 1).Append('"'); backslashes = 0; continue; }
            sb.Append('\\', backslashes).Append(ch);
            backslashes = 0;
        }
        sb.Append('\\', backslashes * 2).Append('"');
        return sb.ToString();
    }
}
