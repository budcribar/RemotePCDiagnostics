namespace RemotePCDiagnostics.Agent.Core;

/// <summary>
/// The app reconnects to the relay, and restarts when a browser asks, by starting a new copy of itself under the same session
/// id and then closing. For an Agent-launched session that new copy is still the same session, so the Agent follows it
/// (its admin pipe, the end request, the "ended" report) instead of treating the first copy's exit as the end.
/// These read the command lines the app writes (SessionLaunchOptions.RestartArguments): <c>-i=&lt;id&gt;</c> and <c>--restarted</c>.
/// </summary>
public static class RestartedCopy
{
    public const string RestartedArg = "--restarted";
    private const string IdPrefix = "-i=";

    /// <summary>How long the Agent looks for the new copy after the old one exits. It is started before the old one closes.</summary>
    public static readonly TimeSpan SuccessorWait = TimeSpan.FromSeconds(5);

    /// <summary>The session id on a command line (<c>-i=&lt;id&gt;</c>), or null.</summary>
    public static string? SessionIdFrom(string? commandLine)
    {
        foreach (var token in Tokens(commandLine))
        {
            if (token.StartsWith(IdPrefix, StringComparison.OrdinalIgnoreCase) && token.Length > IdPrefix.Length)
                return token[IdPrefix.Length..];
        }
        return null;
    }

    /// <summary>True when <paramref name="commandLine"/> is a restarted copy (<c>--restarted</c>) of session <paramref name="sessionId"/>.</summary>
    public static bool IsRestartOf(string? commandLine, string? sessionId)
    {
        if (string.IsNullOrWhiteSpace(sessionId)) return false;
        var restarted = false;
        var sameSession = false;
        foreach (var token in Tokens(commandLine))
        {
            if (string.Equals(token, RestartedArg, StringComparison.OrdinalIgnoreCase))
                restarted = true;
            else if (token.StartsWith(IdPrefix, StringComparison.OrdinalIgnoreCase) &&
                     string.Equals(token[IdPrefix.Length..], sessionId, StringComparison.OrdinalIgnoreCase))
                sameSession = true;
        }
        return restarted && sameSession;
    }

    /// <summary>Whitespace-separated tokens with surrounding quotes removed (the app's own arguments hold no spaces).</summary>
    private static IEnumerable<string> Tokens(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) yield break;
        foreach (var raw in commandLine.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
            yield return raw.Trim('"');
    }
}
