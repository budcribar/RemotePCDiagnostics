using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using RemotePCDiagnostics.Agent.Core;

namespace RemotePCDiagnostics.Agent;

/// <summary>
/// Creates <see cref="UpdateBusyLock.MutexName"/> for the agent service and keeps it for the life of the service, so the app of any
/// signed-in user can take it. SYSTEM and Administrators get full control; authenticated users may only wait on and release it.
/// </summary>
internal static class AgentUpdateLock
{
    /// <summary>The service's handle, or null when it could not be created (the app then creates it with default permissions).</summary>
    public static Mutex? Create(Action<string>? log)
    {
        if (!OperatingSystem.IsWindows())
            return null;
        try
        {
            var mutex = MutexAcl.Create(false, UpdateBusyLock.MutexName, out var createdNew, Access());
            if (!createdNew)
                log?.Invoke("[rpcd-update] The update lock already existed before the service started; its permissions were kept.");
            return mutex;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or WaitHandleCannotBeOpenedException)
        {
            log?.Invoke($"[rpcd-update] Could not create the update lock: {ex.Message}");
            return null;
        }
    }

    [SupportedOSPlatform("windows")]
    private static MutexSecurity Access()
    {
        var security = new MutexSecurity();
        void Allow(WellKnownSidType sid, MutexRights rights) =>
            security.AddAccessRule(new MutexAccessRule(new SecurityIdentifier(sid, null), rights, AccessControlType.Allow));
        Allow(WellKnownSidType.LocalSystemSid, MutexRights.FullControl);
        Allow(WellKnownSidType.BuiltinAdministratorsSid, MutexRights.FullControl);
        Allow(WellKnownSidType.AuthenticatedUserSid, MutexRights.Synchronize | MutexRights.Modify);
        return security;
    }
}
