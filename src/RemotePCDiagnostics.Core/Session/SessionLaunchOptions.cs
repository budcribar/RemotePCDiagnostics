using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Session;

/// <summary>
/// How the Host should run, resolved from command-line args, environment, and any pending post-reboot state.
/// Precedence: <c>-u=&lt;url&gt;</c> arg (forces Remote) &gt; REMOTEPC_MODE / REMOTEPC_SERVER_URL env vars &gt; pending reboot state &gt; Local.
/// The pending reboot state (the session saved by "Schedule clean restart") counts only when the PC has restarted since it was saved
/// and it is recent (<see cref="CanResume"/>): a restart that was called off must not bring a later start up in the old remote session.
/// A remote session is shared: the app shows in the window at the PC with the person there in control, and the remote user joins
/// at the session's link and is handed control.
/// Pass <c>--unattended</c> (or <c>REMOTEPC_UNATTENDED=1</c>) so the remote user gets control as soon as they join, without anyone at
/// the PC handing it over (the user can still take it back).
/// Pass <c>--voice</c> (or <c>REMOTEPC_VOICE=1</c>) for a voice call between the user and the remote user (needs an https relay).
/// </summary>
public sealed record SessionLaunchOptions(
    SessionMode Mode,
    Uri? ServerUri,
    Guid Id,
    bool PostReboot = false,
    bool Unattended = false,
    bool Voice = false,
    string? Group = null,
    bool Admin = false)
{
    public const string ModeVariable = "REMOTEPC_MODE";
    public const string ServerUrlVariable = "REMOTEPC_SERVER_URL";
    public const string IdVariable = "REMOTEPC_ID";
    public const string GroupVariable = "REMOTEPC_GROUP";
    public const string UnattendedVariable = "REMOTEPC_UNATTENDED";
    public const string UnattendedArg = "--unattended";
    public const string VoiceVariable = "REMOTEPC_VOICE";
    public const string VoiceArg = "--voice";
    public const string AdminVariable = "REMOTEPC_ADMIN";
    public const string AdminArg = "--admin";
    public const string PostRebootArg = "--post-reboot";
    /// <summary>Marks the start made by the service workflow's own resume task (which also passes <see cref="PostRebootArg"/>).</summary>
    public const string WorkflowArg = "--workflow";
    /// <summary>A saved session older than this is not resumed, restart or not.</summary>
    public static readonly TimeSpan PendingRebootMaxAge = TimeSpan.FromHours(48);

    /// <summary>Normalizes a relay shop group slug to lowercase trimmed text, or <c>null</c> when empty.</summary>
    public static string? NormalizeGroup(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var trimmed = value.Trim().Trim('"').Trim();
        return trimmed.Length == 0 ? null : trimmed.ToLowerInvariant();
    }

    /// <summary>True when Windows started after <paramref name="pending"/> was saved: the boot time is later than the save, or the
    /// PC has been up for less time than it had been then (which also holds if the clock was changed in between).</summary>
    public static bool RestartedSince(PendingRebootState pending, DateTimeOffset nowUtc, TimeSpan uptime) =>
        nowUtc - uptime > pending.InitiatedAtUtc || (pending.PreUptimeSeconds > 0 && uptime.TotalSeconds < pending.PreUptimeSeconds);

    /// <summary>True when the saved session should be picked up again: the PC restarted since it was saved, and it is recent.</summary>
    public static bool CanResume(PendingRebootState pending, DateTimeOffset nowUtc, TimeSpan uptime) =>
        RestartedSince(pending, nowUtc, uptime) && nowUtc - pending.InitiatedAtUtc <= PendingRebootMaxAge;
    /// <summary>Default relay (PeakSWC.RemoteWebViewService on Railway) used when Remote mode has no explicit URL.</summary>
    public const string DefaultServerUrl = "https://remoteblazorwebview.com:34544";

    public static SessionLaunchOptions Parse(IEnumerable<string> args, Func<string, string?>? env = null) =>
        Resolve(args, env ?? (_ => null));

    /// <param name="nowUtc">The time now (tests); default the clock.</param>
    /// <param name="uptime">How long Windows has been up (tests); default the system's.</param>
    public static SessionLaunchOptions Resolve(IEnumerable<string> args, Func<string, string?> env, PendingRebootState? pendingReboot = null,
        DateTimeOffset? nowUtc = null, TimeSpan? uptime = null)
    {
        var argList = args as IReadOnlyList<string> ?? args.ToList();
        if (pendingReboot is not null && !CanResume(pendingReboot, nowUtc ?? DateTimeOffset.UtcNow, uptime ?? TimeSpan.FromMilliseconds(Environment.TickCount64)))
        {
            // The restart the session was saved for did not happen (or happened long ago): nothing is restored from it. If this
            // start is the resume entry that restart left behind (it runs at the next sign-in, restart or not), its server and
            // session id are the saved ones too, so they are dropped and the app starts as it would by hand. The service
            // workflow's resume task is not part of this: it decides for itself whether its restart happened.
            var staleResume = argList.Any(a => string.Equals(a, PostRebootArg, StringComparison.OrdinalIgnoreCase))
                && !argList.Any(a => string.Equals(a, WorkflowArg, StringComparison.OrdinalIgnoreCase));
            if (staleResume)
            {
                var filtered = new List<string>(argList.Count);
                for (var i = 0; i < argList.Count; i++)
                {
                    var a = argList[i];
                    if (string.Equals(a, "-g", StringComparison.OrdinalIgnoreCase) || string.Equals(a, "--group", StringComparison.OrdinalIgnoreCase))
                    {
                        if (i + 1 < argList.Count && !argList[i + 1].StartsWith('-')) i++;
                        continue;
                    }
                    if (a.StartsWith("-u=", StringComparison.OrdinalIgnoreCase)
                        || a.StartsWith("-i=", StringComparison.OrdinalIgnoreCase)
                        || a.StartsWith("-g=", StringComparison.OrdinalIgnoreCase)
                        || a.StartsWith("--group=", StringComparison.OrdinalIgnoreCase)
                        || string.Equals(a, PostRebootArg, StringComparison.OrdinalIgnoreCase)
                        || string.Equals(a, UnattendedArg, StringComparison.OrdinalIgnoreCase)
                        || string.Equals(a, VoiceArg, StringComparison.OrdinalIgnoreCase))
                        continue;
                    filtered.Add(a);
                }
                argList = filtered;
            }
            pendingReboot = null;
        }
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

        string? groupArg = null;
        for (var i = 0; i < argList.Count; i++)
        {
            var a = argList[i];
            if (a.StartsWith("-g=", StringComparison.OrdinalIgnoreCase))
                groupArg = a[3..];
            else if (a.StartsWith("--group=", StringComparison.OrdinalIgnoreCase))
                groupArg = a[8..];
            else if ((string.Equals(a, "-g", StringComparison.OrdinalIgnoreCase) || string.Equals(a, "--group", StringComparison.OrdinalIgnoreCase))
                     && i + 1 < argList.Count && !argList[i + 1].StartsWith('-'))
                groupArg = argList[++i];
        }
        var group = NormalizeGroup(groupArg) ?? NormalizeGroup(env(GroupVariable));

        var urlArg = Arg("-u=");
        var idText = Arg("-i=") ?? env(IdVariable);
        var id = Guid.TryParse(idText, out var g) ? g : Guid.Empty; // Guid.Empty = server assigns a new id each run unless restored from pendingReboot
        var postReboot = argList.Any(a => string.Equals(a, PostRebootArg, StringComparison.OrdinalIgnoreCase));

        var modeText = env(ModeVariable);
        var remote = urlArg is not null || string.Equals(modeText?.Trim(), "Remote", StringComparison.OrdinalIgnoreCase);

        bool? adminArg = null;
        foreach (var a in argList)
        {
            if (string.Equals(a, AdminArg, StringComparison.OrdinalIgnoreCase)) adminArg = true;
            else if (a.StartsWith(AdminArg + "=", StringComparison.OrdinalIgnoreCase)) adminArg = ParseBool(a[(AdminArg.Length + 1)..]) ?? true;
            else if (string.Equals(a, "--no-admin", StringComparison.OrdinalIgnoreCase)) adminArg = false;
        }
        var admin = adminArg ?? (ParseBool(env(AdminVariable)) ?? remote);

        if (!remote)
        {
            var localOpts = new SessionLaunchOptions(SessionMode.Local, null, id, postReboot, unattended, voice, group, admin);
            return ApplyPendingReboot(localOpts, pendingReboot);
        }

        var url = urlArg ?? env(ServerUrlVariable);
        if (string.IsNullOrWhiteSpace(url)) url = DefaultServerUrl;
        if (!Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
            throw new ArgumentException($"Invalid remote server URL '{url}'. Set {ServerUrlVariable} (or -u=) to e.g. {DefaultServerUrl}.");

        var remoteOpts = new SessionLaunchOptions(SessionMode.Remote, uri, id, postReboot, unattended, voice, group, admin);
        return ApplyPendingReboot(remoteOpts, pendingReboot);
    }

    /// <summary>
    /// Ensures that when <c>RemotePCDiagnostics</c> restarts after a scheduled reboot, it reuses the exact same
    /// <see cref="Id"/> (and remote <see cref="ServerUri"/>, shop <see cref="Group"/>, unattended and voice settings) that it had before the reboot.
    /// Applies <paramref name="pending"/> as given: whether the reboot happened is the caller's check (<see cref="CanResume"/>;
    /// <see cref="Resolve"/> makes it).
    /// </summary>
    public static SessionLaunchOptions ApplyPendingReboot(SessionLaunchOptions launch, PendingRebootState? pending)
    {
        if (pending is null) return launch;

        var effectiveId = launch.Id != Guid.Empty ? launch.Id : pending.SessionId;
        var effectiveUnattended = launch.Unattended || pending.Unattended;
        var effectiveGroup = NormalizeGroup(launch.Group) ?? NormalizeGroup(pending.Group);
        if (pending.Mode == SessionMode.Remote)
        {
            var effectiveUri = launch.ServerUri;
            if (effectiveUri is null && !string.IsNullOrWhiteSpace(pending.ServerUri) && Uri.TryCreate(pending.ServerUri, UriKind.Absolute, out var parsedUri)
                && (parsedUri.Scheme == Uri.UriSchemeHttps || parsedUri.Scheme == Uri.UriSchemeHttp))
                effectiveUri = parsedUri;
            if (effectiveUri is null)
                effectiveUri = new Uri(DefaultServerUrl);

            return new(SessionMode.Remote, effectiveUri, effectiveId, PostReboot: true,
                Unattended: effectiveUnattended, Voice: launch.Voice || pending.Voice, Group: effectiveGroup, Admin: launch.Admin);
        }

        return launch with
        {
            Id = effectiveId,
            PostReboot = true,
            Unattended = effectiveUnattended,
            Voice = launch.Voice || pending.Voice,
            Group = effectiveGroup,
        };
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
    public static IReadOnlyList<string> RestartArguments(Uri serverUri, Guid sessionId, bool unattended = false, bool voice = false, string? group = null, bool? admin = null)
    {
        if (sessionId == Guid.Empty) throw new ArgumentException("A restart needs the session id the server assigned.", nameof(sessionId));
        var list = new List<string> { $"-u={serverUri.AbsoluteUri.TrimEnd('/')}", $"-i={sessionId:D}" };
        if (NormalizeGroup(group) is { } normalizedGroup) list.Add($"-g={normalizedGroup}");
        if (unattended) list.Add(UnattendedArg);
        if (voice) list.Add(VoiceArg);
        if (admin.HasValue) list.Add(admin.Value ? AdminArg : "--no-admin");
        list.Add(RestartedArg);
        return list;
    }

    /// <summary>
    /// Builds the Windows <c>RunOnce</c> command line so that after a reboot, <c>RemotePCDiagnostics.Host</c> restarts
    /// into the exact same session mode, relay server, remote session ID (<c>-i=&lt;guid&gt;</c>), shop group (<c>-g=&lt;group&gt;</c>), and unattended and voice settings.
    /// </summary>
    public static string BuildResumeCommandLine(string executablePath, SessionMode mode, Uri? serverUri, Guid sessionId, bool unattended = false, bool voice = false, string? group = null, bool? admin = null)
    {
        var quotedExe = $"\"{executablePath.Trim('"')}\"";
        if (mode == SessionMode.Remote && serverUri is not null)
        {
            var urlPart = $"-u={serverUri.AbsoluteUri.TrimEnd('/')}";
            var idPart = sessionId != Guid.Empty ? $" -i={sessionId:D}" : "";
            var groupPart = NormalizeGroup(group) is { } normalizedGroup ? $" -g={normalizedGroup}" : "";
            var unattendedPart = unattended ? $" {UnattendedArg}" : "";
            var voicePart = voice ? $" {VoiceArg}" : "";
            var adminPart = admin.HasValue ? (admin.Value ? $" {AdminArg}" : " --no-admin") : "";
            return $"{quotedExe} {urlPart}{idPart}{groupPart}{unattendedPart}{voicePart}{adminPart} {PostRebootArg}";
        }
        var localAdminPart = admin == true ? $" {AdminArg}" : "";
        return $"{quotedExe}{localAdminPart} {PostRebootArg}";
    }
}
