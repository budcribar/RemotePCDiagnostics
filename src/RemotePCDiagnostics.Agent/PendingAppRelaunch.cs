using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using RemotePCDiagnostics.Agent.Core;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Agent;

/// <summary>
/// Brings an unattended session's app back after an in-app update that the agent service ran. The service is SYSTEM on
/// Session 0, so Setup cannot start the app on the user's desktop itself. Instead the service saves the app's restart command
/// line here, and starts the app in the user's session when Setup is done. If Setup's Agent MSI step replaced the service
/// meanwhile, the new service finds the file when it starts and does it instead. Whoever claims the file first starts the app.
/// </summary>
internal static class PendingAppRelaunch
{
    /// <summary>A request older than this is from an update that never finished; it is dropped.</summary>
    public static readonly TimeSpan MaxAge = TimeSpan.FromMinutes(15);

    private const string FileName = "pending-app-relaunch.json";

    private sealed record Request(DateTimeOffset SavedUtc, IReadOnlyList<string> Arguments);

    /// <summary>Lives in the update staging folder, which <c>AgentSelfUpdater</c> locks down to Administrators and SYSTEM.</summary>
    public static string FilePath(string stagingDir) => Path.Combine(stagingDir, FileName);

    public static void Save(string stagingDir, IReadOnlyList<string> arguments)
    {
        var path = FilePath(stagingDir);
        // Delete first: a file someone else created keeps its own ACL and owner when it is only overwritten.
        if (File.Exists(path)) File.Delete(path);
        File.WriteAllText(path, JsonSerializer.Serialize(new Request(DateTimeOffset.UtcNow, arguments)));
    }

    /// <summary>
    /// Starts the app with the saved command line when there is a fresh, trusted request. <paramref name="configuredServer"/>
    /// is the agent's own relay: the app is only started against that relay, never one named only in the file.
    /// </summary>
    public static void TryResume(string stagingDir, string? configuredServer, Func<string, string, string?> startHost, Action<string>? log)
    {
        var path = FilePath(stagingDir);
        if (!File.Exists(path))
            return;

        // Claim the file so the old and the new service cannot both start the app.
        var claimed = $"{path}.{Environment.ProcessId}.claimed";
        try { File.Move(path, claimed); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return; }

        try
        {
            if (!IsOwnedByAdministratorsOrSystem(claimed))
            {
                log?.Invoke("[update-relaunch] Ignoring a relaunch request not written by the agent.");
                return;
            }

            var request = JsonSerializer.Deserialize<Request>(File.ReadAllText(claimed));
            if (request is null || DateTimeOffset.UtcNow - request.SavedUtc > MaxAge || request.SavedUtc > DateTimeOffset.UtcNow.AddMinutes(1))
            {
                log?.Invoke("[update-relaunch] Ignoring a stale relaunch request.");
                return;
            }

            var args = request.Arguments;
            if (!SessionLaunchOptions.IsRestartCommandLine(args))
            {
                log?.Invoke("[update-relaunch] Ignoring a relaunch request that is not a session restart.");
                return;
            }

            var server = ValueOf(args, "-u=");
            var session = ValueOf(args, "-i=");
            if (server is null || session is null)
            {
                log?.Invoke("[update-relaunch] The relaunch request has no relay or session id; not starting the app.");
                return;
            }

            var invalid = LaunchRules.Validate(session, server, out _, out _, configuredServer);
            if (invalid is not null)
            {
                log?.Invoke($"[update-relaunch] Not starting the app: {invalid}");
                return;
            }

            var hostExe = AgentPaths.TryFindLocalInstalledHostExe();
            if (hostExe is null)
            {
                log?.Invoke("[update-relaunch] RemotePCDiagnostics.Host.exe was not found after the update.");
                return;
            }

            var error = startHost(hostExe, WindowsCommandLine.Join([hostExe, .. args]));
            log?.Invoke(error is null
                ? $"[update-relaunch] Started {hostExe} for session {session} after the update."
                : $"[update-relaunch] Could not start the app after the update: {error}");
        }
        catch (Exception ex)
        {
            log?.Invoke($"[update-relaunch] Relaunch failed: {ex.Message}");
        }
        finally
        {
            try { File.Delete(claimed); } catch { }
        }
    }

    private static string? ValueOf(IReadOnlyList<string> args, string prefix) =>
        args.FirstOrDefault(a => a.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) is { } hit ? hit[prefix.Length..] : null;

    private static bool IsOwnedByAdministratorsOrSystem(string path)
    {
        if (!OperatingSystem.IsWindows())
            return true;
        var owner = new FileInfo(path).GetAccessControl().GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        return owner is not null
            && (owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) || owner.IsWellKnown(WellKnownSidType.LocalSystemSid));
    }
}
