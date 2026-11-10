using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Session;

/// <summary>
/// How the Host should run, resolved from command-line args, environment, and any pending post-reboot state.
/// Precedence: <c>-u=&lt;url&gt;</c> arg (forces Remote) &gt; REMOTEPC_MODE / REMOTEPC_SERVER_URL env vars &gt; pending reboot state &gt; Local.
/// A remote session is shared: the app shows in the window at the PC with the person there in control, and the remote user joins
/// at the session's link and is handed control.
/// Pass <c>--unattended</c> (or <c>REMOTEPC_UNATTENDED=1</c>) so the remote user gets control as soon as they join, without anyone at
/// the PC handing it over (the user can still take it back).
/// Pass <c>--voice</c> (or <c>REMOTEPC_VOICE=1</c>) for a voice call between the user and the remote user (needs an https relay).
/// </summary>
public sealed record SessionLaunchOptions(SessionMode Mode, Uri? ServerUri, Guid Id, bool PostReboot = false, bool Unattended = false, bool Voice = false)
{
    public const string ModeVariable = "REMOTEPC_MODE";
    public const string ServerUrlVariable = "REMOTEPC_SERVER_URL";
    public const string IdVariable = "REMOTEPC_ID";
    public const string UnattendedVariable = "REMOTEPC_UNATTENDED";
    public const string UnattendedArg = "--unattended";
    public const string VoiceVariable = "REMOTEPC_VOICE";
    public const string VoiceArg = "--voice";
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

        bool? unattendedArg = null;
        foreach (var a in argList)
        {
            if (string.Equals(a, UnattendedArg, StringComparison.OrdinalIgnoreCase)) unattendedArg = true;
            else if (a.StartsWith(UnattendedArg + "=", StringComparison.OrdinalIgnoreCase)) unattendedArg = ParseBool(a[(UnattendedArg.Length + 1)..]) ?? true;
        }
        bool? voiceArg = null;
        foreach (var a in argList)
        {
            if (string.Equals(a, VoiceArg, StringComparison.OrdinalIgnoreCase)) voiceArg = true;
            else if (a.StartsWith(VoiceArg + "=", StringComparison.OrdinalIgnoreCase)) voiceArg = ParseBool(a[(VoiceArg.Length + 1)..]) ?? true;
        }
        var voice = voiceArg ?? (ParseBool(env(VoiceVariable)) == true);
        // Unattended: the remote user gets control on joining.
        var unattended = unattendedArg ?? (ParseBool(env(UnattendedVariable)) == true);

        var urlArg = Arg("-u=");
        var idText = Arg("-i=") ?? env(IdVariable);
        var id = Guid.TryParse(idText, out var g) ? g : Guid.Empty; // Guid.Empty = server assigns a new id each run unless restored from pendingReboot
        var postReboot = argList.Any(a => string.Equals(a, PostRebootArg, StringComparison.OrdinalIgnoreCase));

        var modeText = env(ModeVariable);
        var remote = urlArg is not null || string.Equals(modeText?.Trim(), "Remote", StringComparison.OrdinalIgnoreCase);

        if (!remote)
        {
            var localOpts = new SessionLaunchOptions(SessionMode.Local, null, id, postReboot, unattended, voice);
            return ApplyPendingReboot(localOpts, pendingReboot);
        }

        var url = urlArg ?? env(ServerUrlVariable);
        if (string.IsNullOrWhiteSpace(url)) url = DefaultServerUrl;
        if (!Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
            throw new ArgumentException($"Invalid remote server URL '{url}'. Set {ServerUrlVariable} (or -u=) to e.g. {DefaultServerUrl}.");

        var remoteOpts = new SessionLaunchOptions(SessionMode.Remote, uri, id, postReboot, unattended, voice);
        return ApplyPendingReboot(remoteOpts, pendingReboot);
    }

    /// <summary>
    /// Ensures that when <c>RemotePCDiagnostics</c> restarts after a scheduled reboot, it reuses the exact same
    /// <see cref="Id"/> (and remote <see cref="ServerUri"/>, unattended and voice settings) that it had before the reboot.
    /// </summary>
    public static SessionLaunchOptions ApplyPendingReboot(SessionLaunchOptions launch, PendingRebootState? pending)
    {
        if (pending is null) return launch;

        var effectiveId = launch.Id != Guid.Empty ? launch.Id : pending.SessionId;
        var effectiveUnattended = launch.Unattended || pending.Unattended;
        if (pending.Mode == SessionMode.Remote)
        {
            var effectiveUri = launch.ServerUri;
            if (effectiveUri is null && !string.IsNullOrWhiteSpace(pending.ServerUri) && Uri.TryCreate(pending.ServerUri, UriKind.Absolute, out var parsedUri)
                && (parsedUri.Scheme == Uri.UriSchemeHttps || parsedUri.Scheme == Uri.UriSchemeHttp))
                effectiveUri = parsedUri;
            if (effectiveUri is null)
                effectiveUri = new Uri(DefaultServerUrl);

            return new(SessionMode.Remote, effectiveUri, effectiveId, PostReboot: true,
                Unattended: effectiveUnattended, Voice: launch.Voice || pending.Voice);
        }

        return launch with { Id = effectiveId, PostReboot = true, Unattended = effectiveUnattended, Voice = launch.Voice || pending.Voice };
    }

    /// <summary>Marks a copy started by <see cref="RestartArguments"/>: it waits for the old copy to exit instead of leaving at once.</summary>
    public const string RestartedArg = "--restarted";

    /// <summary>How long a restarted copy waits for the old one to close before giving up.</summary>
    public static readonly TimeSpan RestartWait = TimeSpan.FromSeconds(60);

    public static bool IsRestarted(IEnumerable<string> args) =>
        args.Any(a => string.Equals(a, RestartedArg, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Arguments for the copy started when a restart is requested from a browser (RemoteBlazorWebView's Refreshed event:
    /// the session's page was loaded again, or Restart was pressed in the session bar). The same session id keeps the
    /// remote user's link working; <see cref="RestartedArg"/> lets the new copy wait for this one to release the one-copy lock.
    /// </summary>
    public static IReadOnlyList<string> RestartArguments(Uri serverUri, Guid sessionId, bool unattended = false, bool voice = false)
    {
        if (sessionId == Guid.Empty) throw new ArgumentException("A restart needs the session id the server assigned.", nameof(sessionId));
        var list = new List<string> { $"-u={serverUri.AbsoluteUri.TrimEnd('/')}", $"-i={sessionId:D}" };
        if (unattended) list.Add(UnattendedArg);
        if (voice) list.Add(VoiceArg);
        list.Add(RestartedArg);
        return list;
    }

    /// <summary>
    /// Builds the Windows <c>RunOnce</c> command line so that after a reboot, <c>RemotePCDiagnostics.Host</c> restarts
    /// into the exact same session mode, relay server, remote session ID (<c>-i=&lt;guid&gt;</c>), and unattended and voice settings.
    /// </summary>
    public static string BuildResumeCommandLine(string executablePath, SessionMode mode, Uri? serverUri, Guid sessionId, bool unattended = false, bool voice = false)
    {
        var quotedExe = $"\"{executablePath.Trim('"')}\"";
        if (mode == SessionMode.Remote && serverUri is not null)
        {
            var urlPart = $"-u={serverUri.AbsoluteUri.TrimEnd('/')}";
            var idPart = sessionId != Guid.Empty ? $" -i={sessionId:D}" : "";
            var unattendedPart = unattended ? $" {UnattendedArg}" : "";
            var voicePart = voice ? $" {VoiceArg}" : "";
            return $"{quotedExe} {urlPart}{idPart}{unattendedPart}{voicePart} {PostRebootArg}";
        }
        return $"{quotedExe} {PostRebootArg}";
    }
}
