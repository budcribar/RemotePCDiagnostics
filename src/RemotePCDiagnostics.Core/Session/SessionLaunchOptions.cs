namespace RemotePCDiagnostics.Core.Session;

/// <summary>
/// How the Host should run, resolved from command-line args and environment.
/// Precedence: <c>-u=&lt;url&gt;</c> arg (forces Remote) &gt; REMOTEPC_MODE / REMOTEPC_SERVER_URL env vars &gt; Local.
/// </summary>
public sealed record SessionLaunchOptions(SessionMode Mode, Uri? ServerUri, Guid Id, bool PostReboot = false)
{
    public const string ModeVariable = "REMOTEPC_MODE";
    public const string ServerUrlVariable = "REMOTEPC_SERVER_URL";
    public const string IdVariable = "REMOTEPC_ID";
    public const string PostRebootArg = "--post-reboot";
    /// <summary>Default relay (PeakSWC.RemoteWebViewService on Railway) used when Remote mode has no explicit URL.</summary>
    public const string DefaultServerUrl = "https://remoteblazor.pagetomovie.com:34544";

    public static SessionLaunchOptions Resolve(IEnumerable<string> args, Func<string, string?> env)
    {
        var argList = args as IReadOnlyList<string> ?? args.ToList();
        string? Arg(string prefix) => argList.FirstOrDefault(a => a.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))?[prefix.Length..];

        var urlArg = Arg("-u=");
        var idText = Arg("-i=") ?? env(IdVariable);
        var id = Guid.TryParse(idText, out var g) ? g : Guid.Empty; // Guid.Empty = server assigns a new id each run
        var postReboot = argList.Any(a => string.Equals(a, PostRebootArg, StringComparison.OrdinalIgnoreCase));

        var modeText = env(ModeVariable);
        var remote = urlArg is not null || string.Equals(modeText?.Trim(), "Remote", StringComparison.OrdinalIgnoreCase);
        if (!remote) return new(SessionMode.Local, null, id, postReboot);

        var url = urlArg ?? env(ServerUrlVariable);
        if (string.IsNullOrWhiteSpace(url)) url = DefaultServerUrl;
        if (!Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
            throw new ArgumentException($"Invalid remote server URL '{url}'. Set {ServerUrlVariable} (or -u=) to e.g. {DefaultServerUrl}.");
        return new(SessionMode.Remote, uri, id, postReboot);
    }

    /// <summary>
    /// Builds the Windows <c>RunOnce</c> command line so that after a reboot, <c>RemotePCDiagnostics.Host</c> restarts
    /// into the exact same session mode, relay server, and remote session ID (<c>-i=&lt;guid&gt;</c>).
    /// </summary>
    public static string BuildResumeCommandLine(string executablePath, SessionMode mode, Uri? serverUri, Guid sessionId)
    {
        var quotedExe = $"\"{executablePath.Trim('"')}\"";
        if (mode == SessionMode.Remote && serverUri is not null)
        {
            var urlPart = $"-u={serverUri.AbsoluteUri.TrimEnd('/')}";
            var idPart = sessionId != Guid.Empty ? $" -i={sessionId:D}" : "";
            return $"{quotedExe} {urlPart}{idPart} {PostRebootArg}";
        }
        return $"{quotedExe} {PostRebootArg}";
    }
}
