namespace RemotePCDiagnostics.Agent.Core;

public enum AgentCommand { Help, Install, Uninstall, Status, Run, Consent }

/// <summary>What the person who installed the agent allows (the relay and remote users can only be stricter).</summary>
public enum ConsentCeiling { Ask, Unattended }

public enum AgentLifetime { Persistent, Session }

/// <summary>A parsed agent command line. <see cref="Error"/> is set (and <see cref="Command"/> is Help) when it isn't valid.</summary>
public sealed record AgentArgs(
    AgentCommand Command,
    string? Server = null,
    string? Key = null,
    ConsentCeiling? Consent = null,
    AgentLifetime? Lifetime = null,
    string Requester = "",
    int TimeoutSeconds = AgentCommandLine.DefaultConsentTimeoutSeconds,
    bool Pause = false,
    string? Error = null);

/// <summary>
/// The agent command line (docs/roadmap.md, "Agent program"):
/// <c>install [--server=URL] [--key=KEY] [--consent=ask|unattended] [--lifetime=persistent|session]</c>, <c>uninstall</c>, <c>status</c>,
/// <c>run</c> and the internal <c>consent --remote user=NAME --timeout=SECONDS</c>. Options are <c>--name=value</c>; names and commands are
/// case-insensitive. <c>--pause</c> (internal) keeps the window of an elevated relaunch open until a key is pressed.
/// </summary>
public static class AgentCommandLine
{
    public const string DefaultServer = "https://server.remoteblazorwebview.com:34544";
    public const int DefaultConsentTimeoutSeconds = 120;
    public const int MinConsentTimeoutSeconds = 10, MaxConsentTimeoutSeconds = 600;
    public const int MaxRequesterLength = 80;

    public const string Usage =
        "Remote PC Diagnostics agent\n" +
        "\n" +
        "  RemotePCDiagnostics.Agent.exe install [--server=" + DefaultServer + "] [--key=<enrollment key>]\n" +
        "                                        [--consent=ask|unattended] [--lifetime=persistent|session]\n" +
        "  RemotePCDiagnostics.Agent.exe uninstall\n" +
        "  RemotePCDiagnostics.Agent.exe status\n" +
        "  RemotePCDiagnostics.Agent.exe run        (what the service runs; also usable in a console for testing)\n" +
        "\n" +
        "install and uninstall need administrator rights (they ask for them).\n";

    public static AgentArgs Parse(IReadOnlyList<string> args)
    {
        if (args.Count == 0) return new AgentArgs(AgentCommand.Help);
        var verb = args[0].Trim().ToLowerInvariant();
        AgentCommand command;
        switch (verb)
        {
            case "install": command = AgentCommand.Install; break;
            case "uninstall": command = AgentCommand.Uninstall; break;
            case "status": command = AgentCommand.Status; break;
            case "run": command = AgentCommand.Run; break;
            case "consent": command = AgentCommand.Consent; break;
            case "help" or "-h" or "--help" or "/?" or "-?": return new AgentArgs(AgentCommand.Help);
            default: return Fail($"Unknown command '{args[0]}'.");
        }

        var result = new AgentArgs(command);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 1; i < args.Count; i++)
        {
            var a = args[i];
            if (!a.StartsWith("--", StringComparison.Ordinal) || a.Length < 3) return Fail($"Unexpected argument '{a}'.");
            var eq = a.IndexOf('=');
            var name = (eq < 0 ? a[2..] : a[2..eq]).ToLowerInvariant();
            var value = eq < 0 ? null : a[(eq + 1)..];
            if (!seen.Add(name)) return Fail($"--{name} is given more than once.");
            if (!Allowed(command, name)) return Fail($"--{name} isn't an option of '{verb}'.");

            if (name == "pause")
            {
                if (value is not null) return Fail("--pause takes no value.");
                result = result with { Pause = true };
                continue;
            }
            if (value is null) return Fail($"--{name} needs a value (--{name}=...).");

            switch (name)
            {
                case "server":
                    if (!TryNormalizeServer(value, out var server)) return Fail($"--server must be an https:// address, not '{value}'.");
                    result = result with { Server = server };
                    break;
                case "key":
                    value = value.Trim();
                    if (value.Length == 0 || value.Length > 256 || value.Any(char.IsControl)) return Fail("--key must be 1 to 256 printable characters.");
                    result = result with { Key = value };
                    break;
                case "consent":
                    ConsentCeiling? c = value.Trim().ToLowerInvariant() switch { "ask" => ConsentCeiling.Ask, "unattended" => ConsentCeiling.Unattended, _ => null };
                    if (c is null) return Fail("--consent must be ask or unattended.");
                    result = result with { Consent = c };
                    break;
                case "lifetime":
                    AgentLifetime? l = value.Trim().ToLowerInvariant() switch { "persistent" => AgentLifetime.Persistent, "session" => AgentLifetime.Session, _ => null };
                    if (l is null) return Fail("--lifetime must be persistent or session.");
                    result = result with { Lifetime = l };
                    break;
                case "requester":
                    result = result with { Requester = CleanRequester(value) };
                    break;
                case "timeout":
                    if (!int.TryParse(value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var t)
                        || t < MinConsentTimeoutSeconds || t > MaxConsentTimeoutSeconds)
                        return Fail($"--timeout must be {MinConsentTimeoutSeconds} to {MaxConsentTimeoutSeconds} seconds.");
                    result = result with { TimeoutSeconds = t };
                    break;
            }
        }
        return result;

        static AgentArgs Fail(string error) => new(AgentCommand.Help, Error: error);
    }

    private static bool Allowed(AgentCommand command, string option) => command switch
    {
        AgentCommand.Install => option is "server" or "key" or "consent" or "lifetime" or "pause",
        AgentCommand.Uninstall => option is "pause",
        AgentCommand.Consent => option is "requester" or "timeout",
        _ => false,
    };

    /// <summary>Accepts an absolute https URL without user info, query or fragment; returns it without a trailing slash.
    /// Plain http is accepted only for a loopback address (a relay on the same PC, for testing).</summary>
    public static bool TryNormalizeServer(string? value, out string server)
    {
        server = "";
        if (string.IsNullOrWhiteSpace(value)) return false;
        if (!Uri.TryCreate(value.Trim(), UriKind.Absolute, out var uri)) return false;
        var schemeOk = uri.Scheme == Uri.UriSchemeHttps || (uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback);
        if (!schemeOk || uri.UserInfo.Length > 0 || uri.Query.Length > 0 || uri.Fragment.Length > 0 || uri.Host.Length == 0) return false;
        server = uri.GetLeftPart(UriPartial.Path).TrimEnd('/');
        return true;
    }

    /// <summary>The remote user's display name as shown in the consent prompt: printable, no quotes, at most <see cref="MaxRequesterLength"/> characters.</summary>
    public static string CleanRequester(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return "";
        var chars = name.Where(ch => !char.IsControl(ch) && ch != '"').ToArray();
        var s = string.Join(' ', new string(chars).Split(' ', StringSplitOptions.RemoveEmptyEntries));
        return s.Length > MaxRequesterLength ? s[..MaxRequesterLength].TrimEnd() : s;
    }
}
