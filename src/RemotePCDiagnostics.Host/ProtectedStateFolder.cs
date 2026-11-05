using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using RemotePCDiagnostics.Core;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// Secures %ProgramData%\RemotePCDiagnostics (everyone may read, only Administrators and SYSTEM may change) and its state folder
/// (Administrators and SYSTEM only), owned by Administrators. Windows lets any user create folders under %ProgramData%, so a folder
/// that already exists isn't trusted as is: one that is owned by someone else or grants more is taken back (owner and permissions
/// reset). A state folder that wasn't ours is set aside as state.untrusted-&lt;time&gt; and replaced, since anything in it could be forged.
/// </summary>
public static class ProtectedStateFolder
{
    private static readonly SecurityIdentifier Admins = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier LocalSystem = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier Users = new(WellKnownSidType.BuiltinUsersSid, null);
    private const FileSystemRights ReadOnly = FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize;

    /// <summary>Returns false (after logging why) when either folder couldn't be secured.</summary>
    public static bool Ensure(Action<string>? log) => Ensure(ProtectedState.AppDataFolder(), ProtectedState.Folder(), log);

    public static bool Ensure(string appFolder, string stateFolder, Action<string>? log)
    {
        try
        {
            if (!SecureInPlace(appFolder, readers: true, log)) return false;
            var state = new DirectoryInfo(stateFolder);
            state.Create(Wanted(readers: false)); // does nothing when it already exists
            if (IsSecure(state, readers: false)) return true;

            var aside = $"{stateFolder}.untrusted-{DateTime.Now:yyyyMMdd-HHmmss}";
            log?.Invoke($"Protected state: {stateFolder} wasn't created by this app or was opened up; moved it to {aside}");
            Directory.Move(stateFolder, aside);
            state = new DirectoryInfo(stateFolder);
            state.Create(Wanted(readers: false));
            if (IsSecure(state, readers: false)) return true;
            log?.Invoke($"Protected state: {stateFolder} is still not secure after replacing it");
            return false;
        }
        catch (Exception ex)
        {
            log?.Invoke($"Protected state: couldn't secure {stateFolder}: {ex.Message}");
            return false;
        }
    }

    private static bool SecureInPlace(string path, bool readers, Action<string>? log)
    {
        var dir = new DirectoryInfo(path);
        dir.Create(Wanted(readers));
        if (IsSecure(dir, readers)) return true;
        log?.Invoke($"Protected state: resetting the owner and permissions of {path}");
        using (Privileges.Enable("SeTakeOwnershipPrivilege", "SeRestorePrivilege"))
        {
            var owner = new DirectorySecurity();
            owner.SetOwner(Admins);
            dir.SetAccessControl(owner); // owner only: needs SeTakeOwnership when someone else owns it
            dir.SetAccessControl(Wanted(readers));
        }
        if (IsSecure(dir, readers)) return true;
        log?.Invoke($"Protected state: {path} is still not secure after resetting it");
        return false;
    }

    private static DirectorySecurity Wanted(bool readers)
    {
        const InheritanceFlags all = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        var s = new DirectorySecurity();
        s.SetOwner(Admins);
        s.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        s.AddAccessRule(new FileSystemAccessRule(Admins, FileSystemRights.FullControl, all, PropagationFlags.None, AccessControlType.Allow));
        s.AddAccessRule(new FileSystemAccessRule(LocalSystem, FileSystemRights.FullControl, all, PropagationFlags.None, AccessControlType.Allow));
        if (readers) s.AddAccessRule(new FileSystemAccessRule(Users, FileSystemRights.ReadAndExecute, all, PropagationFlags.None, AccessControlType.Allow));
        return s;
    }

    /// <summary>Owned by Administrators or SYSTEM, no inherited permissions, no deny rules, and only Administrators and SYSTEM may change
    /// anything (with <paramref name="readers"/>, others may read; without it, others get nothing).</summary>
    internal static bool IsSecure(DirectoryInfo dir, bool readers)
    {
        var acl = dir.GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        if (acl.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner || !(owner.Equals(Admins) || owner.Equals(LocalSystem))) return false;
        if (!acl.AreAccessRulesProtected) return false;
        foreach (FileSystemAccessRule rule in acl.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow) return false;
            var who = (SecurityIdentifier)rule.IdentityReference;
            if (who.Equals(Admins) || who.Equals(LocalSystem)) continue;
            if (!readers || (rule.FileSystemRights & ~ReadOnly) != 0) return false;
        }
        return true;
    }

    /// <summary>Turns token privileges on for a block and puts them back as they were.</summary>
    private sealed class Privileges : IDisposable
    {
        private readonly SafeAccessTokenHandle _token;
        private readonly byte[] _previous;

        private Privileges(SafeAccessTokenHandle token, byte[] previous) { _token = token; _previous = previous; }

        public static Privileges Enable(params string[] names)
        {
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out var token)) throw new System.ComponentModel.Win32Exception();
            var size = 4 + names.Length * 12;
            var wanted = new byte[size];
            BitConverter.GetBytes(names.Length).CopyTo(wanted, 0);
            for (var i = 0; i < names.Length; i++)
            {
                if (!LookupPrivilegeValue(null, names[i], out var luid)) { token.Dispose(); throw new System.ComponentModel.Win32Exception(); }
                BitConverter.GetBytes(luid).CopyTo(wanted, 4 + i * 12);
                BitConverter.GetBytes(SE_PRIVILEGE_ENABLED).CopyTo(wanted, 4 + i * 12 + 8);
            }
            var previous = new byte[size];
            if (!AdjustTokenPrivileges(token, false, wanted, size, previous, out _) || Marshal.GetLastWin32Error() != 0)
            {
                var error = Marshal.GetLastWin32Error();
                token.Dispose();
                throw new System.ComponentModel.Win32Exception(error);
            }
            return new Privileges(token, previous);
        }

        public void Dispose()
        {
            AdjustTokenPrivileges(_token, false, _previous, 0, null, out _);
            _token.Dispose();
        }
    }

    private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020, TOKEN_QUERY = 0x0008, SE_PRIVILEGE_ENABLED = 0x2;

    [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValue(string? system, string name, out long luid);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(SafeAccessTokenHandle token, bool disableAll, byte[] newState, int length, byte[]? previous, out int returnLength);
}
