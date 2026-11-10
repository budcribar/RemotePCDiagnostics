using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Session;

/// <summary>
/// How the Host should run, resolved from command-line args, environment, and any pending post-reboot state.
/// Precedence: <c>-u=&lt;url&gt;</c> arg (forces Remote) &gt; REMOTEPC_MODE / REMOTEPC_SERVER_URL env vars &gt; pending reboot state &gt; Local.
/// Pass <c>-m</c> or <c>--mirror</c> (or <c>REMOTEPC_MIRROR=1</c>) in Remote mode so the local window mirrors what the technician is doing.
/// Pass <c>--reverse-mirror</c> (or <c>REMOTEPC_REVERSE_MIRROR=1</c>) for the opposite, for demos: the local window is in control and the shared
/// link is the read-only <c>/mirror/&lt;id&gt;</c> page, so someone in a browser can watch but not click.
/// Pass <c>--unattended</c> (or <c>REMOTEPC_UNATTENDED=1</c>) so the technician gets control as soon as they join, without anyone at
/// the PC handing it over (the user can still take it back). Without it the session is supervised: the user starts in control and gives it.
/// </summary>
public sealed record SessionLaunchOptions(SessionMode Mode, Uri? ServerUri, Guid Id, bool PostReboot = false, bool Mirror = false, bool ReverseMirror = false, bool Unattended = false)
{
    public const string ModeVariable = "REMOTEPC_MODE";
    public const string ServerUrlVariable = "REMOTEPC_SERVER_URL";
    public const string IdVariable = "REMOTEPC_ID";
    public const string MirrorVariable = "REMOTEPC_MIRROR";
    public const string MirrorArg = "--mirror";
    public const string ShortMirrorArg = "-m";
    public const string ReverseMirrorVariable = "REMOTEPC_REVERSE_MIRROR";
    public const string ReverseMirrorArg = "--reverse-mirror";
    public const string UnattendedVariable = "REMOTEPC_UNATTENDED";
    public const string UnattendedArg = "--unattended";
    public const string PostRebootArg = "--post-reboot";
    /// <summary>Default relay (PeakSWC.RemoteWebViewService on Railway) used when Remote mode has no explicit URL.</summary>
    public const string DefaultServerUrl = "https://remoteblazorwebview.com:34544";

    public static SessionLaunchOptions Resolve(IEnumerable<string> args, Func<string, string?> env, PendingRebootState? pendingReboot = null)
    {
        var argList = args as IReadOnlyList<string> ?? args.ToList();
        string? Arg(string prefix) => argList.FirstOrDefault(a => a.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))?[prefix.Length..];

        static bool? ParseBool(string? v) => v?.Trim() switch
        {
            "true" or "TRUE" or "True" or "1" or "yes" or "YES" or "Yes" => true,
            "false" or "FALSE" or "False" or "0" or "no" or "NO" or "No" => false,
            _ => null,
        };

        bool? mirrorArg = null, reverseArg = null;
        foreach (var a in argList)
        {
            if (string.Equals(a, ReverseMirrorArg, StringComparison.OrdinalIgnoreCase)) { reverseArg = true; continue; }
            if (a.StartsWith(ReverseMirrorArg + "=", StringComparison.OrdinalIgnoreCase)) { reverseArg = ParseBool(a[(ReverseMirrorArg.Length + 1)..]) ?? true; continue; }
            if (string.Equals(a, MirrorArg, StringComparison.OrdinalIgnoreCase) || string.Equals(a, ShortMirrorArg, StringComparison.OrdinalIgnoreCase))
                mirrorArg = true;
            else if (a.StartsWith("-m=", StringComparison.OrdinalIgnoreCase))
                mirrorArg = ParseBool(a[3..]) ?? true;
            else if (a.StartsWith("--mirror=", StringComparison.OrdinalIgnoreCase))
                mirrorArg = ParseBool(a[9..]) ?? true;
        }
        var reverse = reverseArg ?? (ParseBool(env(ReverseMirrorVariable)) == true);
        bool? unattendedArg = null;
        foreach (var a in argList)
        {
            if (string.Equals(a, UnattendedArg, StringComparison.OrdinalIgnoreCase)) unattendedArg = true;
            else if (a.StartsWith(UnattendedArg + "=", StringComparison.OrdinalIgnoreCase)) unattendedArg = ParseBool(a[(UnattendedArg.Length + 1)..]) ?? true;
        }
        // Unattended is a shared session (the app window here, the technician on the link) where the technician gets control on joining.
        var unattended = !reverse && (unattendedArg ?? (ParseBool(env(UnattendedVariable)) == true));
        // The two directions exclude each other; reverse wins (it's the one asked for explicitly for a demo).
        var mirror = !reverse && (unattended || (mirrorArg ?? (ParseBool(env(MirrorVariable)) == true)));

        var urlArg = Arg("-u=");
        var idText = Arg("-i=") ?? env(IdVariable);
        var id = Guid.TryParse(idText, out var g) ? g : Guid.Empty; // Guid.Empty = server assigns a new id each run unless restored from pendingReboot
        var postReboot = argList.Any(a => string.Equals(a, PostRebootArg, StringComparison.OrdinalIgnoreCase));

        var modeText = env(ModeVariable);
        var remote = urlArg is not null || string.Equals(modeText?.Trim(), "Remote", StringComparison.OrdinalIgnoreCase);

        if (!remote)
        {
            var localOpts = new SessionLaunchOptions(SessionMode.Local, null, id, postReboot, mirror, reverse, unattended);
            return ApplyPendingReboot(localOpts, pendingReboot);
        }

        var url = urlArg ?? env(ServerUrlVariable);
        if (string.IsNullOrWhiteSpace(url)) url = DefaultServerUrl;
        if (!Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
            throw new ArgumentException($"Invalid remote server URL '{url}'. Set {ServerUrlVariable} (or -u=) to e.g. {DefaultServerUrl}.");

        var remoteOpts = new SessionLaunchOptions(SessionMode.Remote, uri, id, postReboot, mirror, reverse, unattended);
        return ApplyPendingReboot(remoteOpts, pendingReboot);
    }

    /// <summary>
    /// Ensures that when <c>RemotePCDiagnostics</c> restarts after a scheduled reboot, it reuses the exact same
    /// <see cref="Id"/> (and remote <see cref="ServerUri"/> and <see cref="Mirror"/> setting) that it had before the reboot.
    /// </summary>
    public static SessionLaunchOptions ApplyPendingReboot(SessionLaunchOptions launch, PendingRebootState? pending)
    {
        if (pending is null) return launch;

        var effectiveId = launch.Id != Guid.Empty ? launch.Id : pending.SessionId;
        var effectiveReverse = launch.ReverseMirror || pending.ReverseMirror;
        var effectiveMirror = !effectiveReverse && (launch.Mirror || pending.Mirror);
        if (pending.Mode == SessionMode.Remote)
        {
            var effectiveUri = launch.ServerUri;
            if (effectiveUri is null && !string.IsNullOrWhiteSpace(pending.ServerUri) && Uri.TryCreate(pending.ServerUri, UriKind.Absolute, out var parsedUri)
                && (parsedUri.Scheme == Uri.UriSchemeHttps || parsedUri.Scheme == Uri.UriSchemeHttp))
                effectiveUri = parsedUri;
            if (effectiveUri is null)
                effectiveUri = new Uri(DefaultServerUrl);

            return new(SessionMode.Remote, effectiveUri, effectiveId, PostReboot: true, Mirror: effectiveMirror, ReverseMirror: effectiveReverse,
                Unattended: launch.Unattended && !effectiveReverse);
        }

        return launch with { Id = effectiveId, PostReboot = true, Mirror = effectiveMirror, ReverseMirror = effectiveReverse };
    }

    /// <summary>Marks a copy started by <see cref="RestartArguments"/>: it waits for the old copy to exit instead of leaving at once.</summary>
    public const string RestartedArg = "--restarted";

    /// <summary>How long a restarted copy waits for the old one to close before giving up.</summary>
    public static readonly TimeSpan RestartWait = TimeSpan.FromSeconds(60);

    public static bool IsRestarted(IEnumerable<string> args) =>
        args.Any(a => string.Equals(a, RestartedArg, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Arguments for the copy started when the technician's browser refreshes the remote session (RemoteBlazorWebView's
    /// Refreshed event; the library's own Restart() starts the same <c>-u=</c>/<c>-i=</c> pair). The same session id keeps the
    /// technician's link working; <see cref="RestartedArg"/> lets the new copy wait for this one to release the one-copy lock.
    /// </summary>
    public static IReadOnlyList<string> RestartArguments(Uri serverUri, Guid sessionId, bool mirror = false, bool reverseMirror = false, bool unattended = false)
    {
        if (sessionId == Guid.Empty) throw new ArgumentException("A restart needs the session id the server assigned.", nameof(sessionId));
        var list = new List<string> { $"-u={serverUri.AbsoluteUri.TrimEnd('/')}", $"-i={sessionId:D}" };
        if (reverseMirror) list.Add(ReverseMirrorArg);
        else if (mirror) list.Add(MirrorArg);
        if (unattended && !reverseMirror) list.Add(UnattendedArg);
        list.Add(RestartedArg);
        return list;
    }

    /// <summary>
    /// Builds the Windows <c>RunOnce</c> command line so that after a reboot, <c>RemotePCDiagnostics.Host</c> restarts
    /// into the exact same session mode, relay server, remote session ID (<c>-i=&lt;guid&gt;</c>), and mirror setting.
    /// </summary>
    public static string BuildResumeCommandLine(string executablePath, SessionMode mode, Uri? serverUri, Guid sessionId, bool mirror = false, bool reverseMirror = false)
    {
        var quotedExe = $"\"{executablePath.Trim('"')}\"";
        if (mode == SessionMode.Remote && serverUri is not null)
        {
            var urlPart = $"-u={serverUri.AbsoluteUri.TrimEnd('/')}";
            var idPart = sessionId != Guid.Empty ? $" -i={sessionId:D}" : "";
            var mirrorPart = reverseMirror ? $" {ReverseMirrorArg}" : mirror ? $" {MirrorArg}" : "";
            return $"{quotedExe} {urlPart}{idPart}{mirrorPart} {PostRebootArg}";
        }
        return $"{quotedExe} {PostRebootArg}";
    }
}
