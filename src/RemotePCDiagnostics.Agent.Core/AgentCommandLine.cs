namespace RemotePCDiagnostics.Agent.Core;

public enum AgentCommand { Help, Install, Uninstall, Status, Run, Consent, Launch, Helper }

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
    string? Error = null,
    bool SelfCheck = false,
    bool FromMsi = false,
    string? Group = null,
    IReadOnlyList<string>? ForwardedArgs = null,
    int ParentPid = 0,
    string? PipeName = null,
    string? ClientSid = null);

/// <summary>
/// The agent command line (docs/roadmap.md, "Agent program"):
/// <c>install [--server=URL] [--key=KEY] [--group=SHOP] [--consent=ask|unattended] [--lifetime=persistent|session] [--from-msi=PATH]</c>, <c>uninstall</c>, <c>status</c>,
/// <c>run [--self-check]</c> and the internal <c>consent --requester=NAME --timeout=SECONDS</c>. Options are <c>--name=value</c>; names and commands are
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
        "  RemotePCDiagnostics.Agent.exe [options]  (launches Remote PC Diagnostics with elevated background worker)\n" +
        "  RemotePCDiagnostics.Agent.exe --launch [options]\n" +
        "  RemotePCDiagnostics.Agent.exe install [--server=" + DefaultServer + "] [--key=<enrollment key>]\n" +
        "                                        [--group=<shop>] [--consent=ask|unattended] [--lifetime=persistent|session]\n" +
        "  RemotePCDiagnostics.Agent.exe uninstall\n" +
        "  RemotePCDiagnostics.Agent.exe status\n" +
        "  RemotePCDiagnostics.Agent.exe run        (what the service runs; also usable in a console for testing)\n" +
        "\n" +
        "install and uninstall need administrator rights (they ask for them).\n";

    public static AgentArgs Parse(IReadOnlyList<string> args)
    {
        if (args.Count == 0) return new AgentArgs(AgentCommand.Launch, ForwardedArgs: []);

        if (args.Any(a => a.StartsWith("--mode=helper", StringComparison.OrdinalIgnoreCase) || string.Equals(a, "--mode", StringComparison.OrdinalIgnoreCase)))
        {
            if (TryParseHelperArguments(args, out var parentPid, out var pipeName, out var clientSid))
                return new AgentArgs(AgentCommand.Helper, ParentPid: parentPid, PipeName: pipeName, ClientSid: clientSid);
            return Fail("Invalid helper arguments.");
        }

        var verb = args[0].Trim().ToLowerInvariant();
        if (verb == "--self-check")
        {
            return args.Count == 1
                ? new AgentArgs(AgentCommand.Run, SelfCheck: true)
                : Fail($"Unexpected argument '{args[1]}'.");
        }

        if (verb == "--launch")
        {
            var forwarded = args.Skip(1).ToList();
            return new AgentArgs(AgentCommand.Launch, ForwardedArgs: forwarded);
        }

        AgentCommand command;
        switch (verb)
        {
            case "install": command = AgentCommand.Install; break;
            case "uninstall": command = AgentCommand.Uninstall; break;
            case "status": command = AgentCommand.Status; break;
            case "run": command = AgentCommand.Run; break;
            case "consent": command = AgentCommand.Consent; break;
            case "help" or "-h" or "--help" or "/?" or "-?": return new AgentArgs(AgentCommand.Help);
            default:
                if (verb.StartsWith('-'))
                {
                    // Parameter meant for Host (e.g. -u=..., --voice, etc.)
                    return new AgentArgs(AgentCommand.Launch, ForwardedArgs: args.ToArray());
                }
                return Fail($"Unknown command '{args[0]}'.");
        }

        var result = new AgentArgs(command);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        string? fromMsiRaw = null;
        string? serverRaw = null;
        string? keyRaw = null;
        string? consentRaw = null;
        string? lifetimeRaw = null;
        string? groupRaw = null;

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
            if (name == "self-check")
            {
                if (value is not null) return Fail("--self-check takes no value.");
                result = result with { SelfCheck = true };
                continue;
            }
            if (value is null) return Fail($"--{name} needs a value (--{name}=...).");

            switch (name)
            {
                case "from-msi":
                    fromMsiRaw = value;
                    break;
                case "server":
                    serverRaw = value;
                    break;
                case "key":
                    keyRaw = value;
                    break;
                case "consent":
                    consentRaw = value;
                    break;
                case "lifetime":
                    lifetimeRaw = value;
                    break;
                case "group":
                    groupRaw = value;
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

        var fromMsi = fromMsiRaw is not null;
        if (fromMsi)
        {
            if (!AgentMsiParameters.TryParseFileName(fromMsiRaw, out var msiMeta, out var msiError))
                return Fail(msiError ?? "Invalid --from-msi value.");

            result = result with { FromMsi = true };
            if (msiMeta is not null)
            {
                result = result with
                {
                    Server = msiMeta.Server,
                    Key = msiMeta.Key,
                    Consent = msiMeta.Consent,
                    Lifetime = msiMeta.Lifetime,
                };
            }
        }

        if (serverRaw is not null && (!fromMsi || !string.IsNullOrWhiteSpace(serverRaw)))
        {
            if (!TryNormalizeServer(serverRaw, out var server)) return Fail($"--server must be an https:// address, not '{serverRaw}'.");
            result = result with { Server = server };
        }

        if (keyRaw is not null && (!fromMsi || !string.IsNullOrWhiteSpace(keyRaw)))
        {
            var trimmedKey = keyRaw.Trim();
            if (trimmedKey.Length == 0 || trimmedKey.Length > 256 || trimmedKey.Any(char.IsControl))
                return Fail("--key must be 1 to 256 printable characters.");
            result = result with { Key = trimmedKey };
        }

        if (consentRaw is not null && (!fromMsi || !string.IsNullOrWhiteSpace(consentRaw)))
        {
            ConsentCeiling? c = consentRaw.Trim().ToLowerInvariant() switch { "ask" => ConsentCeiling.Ask, "unattended" => ConsentCeiling.Unattended, _ => null };
            if (c is null) return Fail("--consent must be ask or unattended.");
            result = result with { Consent = c };
        }

        if (lifetimeRaw is not null && (!fromMsi || !string.IsNullOrWhiteSpace(lifetimeRaw)))
        {
            AgentLifetime? l = lifetimeRaw.Trim().ToLowerInvariant() switch { "persistent" => AgentLifetime.Persistent, "session" => AgentLifetime.Session, _ => null };
            if (l is null) return Fail("--lifetime must be persistent or session.");
            result = result with { Lifetime = l };
        }

        if (groupRaw is not null && (!fromMsi || !string.IsNullOrWhiteSpace(groupRaw)))
        {
            var group = AgentLayout.NormalizeShopGroup(groupRaw);
            if (group is null) return Fail("--group must be a shop code of 1 to 64 characters, without quotes or slashes.");
            result = result with { Group = group };
        }

        return result;

        static AgentArgs Fail(string error) => new(AgentCommand.Help, Error: error);
    }

    private static bool Allowed(AgentCommand command, string option) => command switch
    {
        AgentCommand.Install => option is "server" or "key" or "group" or "consent" or "lifetime" or "from-msi" or "pause",
        AgentCommand.Uninstall => option is "pause",
        AgentCommand.Run => option is "self-check",
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

    public static bool TryParseHelperArguments(
        IReadOnlyList<string> args,
        out int parentPid,
        out string pipeName,
        out string? clientSid)
    {
        parentPid = 0;
        pipeName = "";
        clientSid = null;
        string? mode = null;

        for (var i = 0; i < args.Count; i++)
        {
            var arg = args[i];
            if (TryReadOption(args, ref i, "--mode", out var m))
                mode = m;
            else if (TryReadOption(args, ref i, "--parent-pid", out var pidText) && int.TryParse(pidText, out var parsedPid))
                parentPid = parsedPid;
            else if (TryReadOption(args, ref i, "--pipe", out var p))
                pipeName = p;
            else if (TryReadOption(args, ref i, "--client-sid", out var sid))
                clientSid = sid;
        }

        return string.Equals(mode, "helper", StringComparison.OrdinalIgnoreCase)
            && parentPid > 0
            && !string.IsNullOrWhiteSpace(pipeName)
            && !pipeName.Contains('\\')
            && !pipeName.Contains('/');
    }

    private static bool TryReadOption(IReadOnlyList<string> args, ref int index, string prefix, out string value)
    {
        var current = args[index];
        var eqPrefix = prefix + "=";
        if (current.StartsWith(eqPrefix, StringComparison.OrdinalIgnoreCase))
        {
            value = current[eqPrefix.Length..].Trim();
            return true;
        }
        if (string.Equals(current, prefix, StringComparison.OrdinalIgnoreCase) && index + 1 < args.Count)
        {
            index++;
            value = args[index].Trim();
            return true;
        }
        value = "";
        return false;
    }
}
