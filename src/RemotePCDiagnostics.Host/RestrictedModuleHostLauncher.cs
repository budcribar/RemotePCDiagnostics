using System.IO;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using RemotePCDiagnostics.Core.Plugins;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// Starts RemotePCDiagnostics.ModuleHost.exe for an unsigned module with a restricted copy of the app's own token: the Administrators group
/// deny-only, every privilege but SeChangeNotify removed, Medium integrity. Windows lets a process start a child with a restricted version
/// of its own token, so no extra rights are needed. An unsigned module's host also has INTERACTIVE and Event Log Readers deny-only
/// (<see cref="UnsignedDenyOnly"/>), so it can't read the Application or System log itself. The host talks to the app over anonymous pipes for its stdin and stdout, which only
/// the app holds, and exits when the app closes them.
/// </summary>
public sealed class RestrictedModuleHostLauncher(Microsoft.Extensions.Logging.ILogger? log = null, string? directory = null) : IModuleHostLauncher
{
    public IModuleHostConnection Start(UserModeModule module)
    {
        // A module that ships with the app and needs administrator runs out of process for isolation only: the app's own (elevated) token.
        if (module is { Bundled: true, Elevated: true })
        {
            if (log is not null) Microsoft.Extensions.Logging.LoggerExtensions.LogInformation(log, "Module host [{Slug}]: starting with the app's own token (needs administrator)", module.Manifest.Slug);
            return new ProcessModuleHostLauncher(directory, log).Start(module);
        }
        var dir = directory ?? AppContext.BaseDirectory;
        var exe = Path.Combine(dir, ProcessModuleHostLauncher.HostName + ".exe");
        if (!File.Exists(exe)) throw new FileNotFoundException("Module host not found", exe);
        var commandLine = new StringBuilder($"\"{exe}\" \"{module.Path}\"");

        // An unsigned module also loses INTERACTIVE and Event Log Readers (it can't read the event logs itself). A module that ships with
        // the app keeps them: its code is ours, and it gets its event log reads from the app anyway.
        using var token = RestrictedToken(unsigned: !module.Bundled);
        // Every pipe end starts out non-inheritable; only the child's three ends are handed to it (CreateRestricted).
        var sa = new SECURITY_ATTRIBUTES { nLength = Marshal.SizeOf<SECURITY_ATTRIBUTES>(), bInheritHandle = false };
        SafeFileHandle? inRead = null, inWrite = null, outRead = null, outWrite = null, errRead = null, errWrite = null;
        Process process;
        try
        {
            Check(CreatePipe(out inRead, out inWrite, ref sa, 0));
            Check(CreatePipe(out outRead, out outWrite, ref sa, 0));
            Check(CreatePipe(out errRead, out errWrite, ref sa, 0));

            var si = new STARTUPINFO
            {
                cb = Marshal.SizeOf<STARTUPINFO>(), dwFlags = STARTF_USESTDHANDLES,
                hStdInput = inRead.DangerousGetHandle(), hStdOutput = outWrite.DangerousGetHandle(), hStdError = errWrite.DangerousGetHandle(),
            };
            PROCESS_INFORMATION pi;
            try
            {
                pi = CreateRestricted(token, commandLine, CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, dir, si, inRead, outWrite, errWrite);
            }
            finally
            {
                inRead.Dispose(); outWrite.Dispose(); errWrite.Dispose(); // the child's ends
            }
            try
            {
                process = Process.GetProcessById(pi.dwProcessId);
            }
            finally
            {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
            }
            if (log is not null) Microsoft.Extensions.Logging.LoggerExtensions.LogInformation(log, "Module host [{Slug}]: started pid={Pid} (restricted token, Medium integrity{Unsigned})",
                module.Manifest.Slug, pi.dwProcessId, module.Bundled ? "" : ", no INTERACTIVE or Event Log Readers");
        }
        catch
        {
            inRead?.Dispose(); inWrite?.Dispose();
            outRead?.Dispose(); outWrite?.Dispose();
            errRead?.Dispose(); errWrite?.Dispose();
            throw;
        }

        var stderr = new StreamReader(new FileStream(errRead, FileAccess.Read), Encoding.UTF8);
        _ = Task.Run(async () =>
        {
            try { while (await stderr.ReadLineAsync().ConfigureAwait(false) is { } line) { if (log is not null) Microsoft.Extensions.Logging.LoggerExtensions.LogInformation(log, "Module host [{Slug}]: {Line}", module.Manifest.Slug, line); } }
            catch { }
        });
        return new Connection(process,
            new StreamWriter(new FileStream(inWrite, FileAccess.Write), new UTF8Encoding(false)) { AutoFlush = true },
            new StreamReader(new FileStream(outRead, FileAccess.Read), Encoding.UTF8), stderr);
    }

    /// <summary>
    /// Starts a GUI process (a module's UI host) with the same restricted token, Medium integrity and no pipes. Its window is shown
    /// normally; the caller owns the returned process.
    /// </summary>
    public static Process StartRestrictedGui(string exe, string arguments, string workingDirectory)
    {
        if (!File.Exists(exe)) throw new FileNotFoundException("UI host not found", exe);
        using var token = RestrictedToken();
        var si = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFO>() };
        Check(CreateProcessAsUser(token, null, new StringBuilder($"\"{exe}\" {arguments}"), IntPtr.Zero, IntPtr.Zero, false, CREATE_UNICODE_ENVIRONMENT,
            IntPtr.Zero, workingDirectory, ref si, out var pi));
        try
        {
            return Process.GetProcessById(pi.dwProcessId);
        }
        finally
        {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
    }

    /// <summary>
    /// <see cref="StartRestrictedGui"/> with a pipe on the process's stdin (only stdin is inherited), for the app to send it lines (a module's
    /// UI host gets the module's latest result this way). Closing the returned writer ends the input.
    /// </summary>
    public static (Process Process, StreamWriter Input) StartRestrictedGuiWithInput(string exe, string arguments, string workingDirectory)
    {
        if (!File.Exists(exe)) throw new FileNotFoundException("UI host not found", exe);
        using var token = RestrictedToken();
        var sa = new SECURITY_ATTRIBUTES { nLength = Marshal.SizeOf<SECURITY_ATTRIBUTES>(), bInheritHandle = false };
        Check(CreatePipe(out var inRead, out var inWrite, ref sa, 0));
        try
        {
            // Only stdin is handed over; the process has no stdout or stderr (it logs to its own file).
            var si = new STARTUPINFO { dwFlags = STARTF_USESTDHANDLES, hStdInput = inRead.DangerousGetHandle() };
            PROCESS_INFORMATION pi;
            try
            {
                pi = CreateRestricted(token, new StringBuilder($"\"{exe}\" {arguments}"), CREATE_UNICODE_ENVIRONMENT, workingDirectory, si, inRead);
            }
            finally { inRead.Dispose(); } // the child's end
            try
            {
                return (Process.GetProcessById(pi.dwProcessId), new StreamWriter(new FileStream(inWrite, FileAccess.Write), new UTF8Encoding(false)) { AutoFlush = true });
            }
            finally
            {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
            }
        }
        catch
        {
            inRead.Dispose(); inWrite.Dispose();
            throw;
        }
    }

    /// <summary>
    /// CreateProcessAsUser with the restricted token that hands the child exactly <paramref name="inherit"/> (PROC_THREAD_ATTRIBUTE_HANDLE_LIST)
    /// and no other handle of the app's. The handles are inheritable only for the call. Without the list, a host started at the same moment
    /// as another (Check all) could pick up the other's pipe ends, and then closing that host's stdin wouldn't end it.
    /// </summary>
    private static PROCESS_INFORMATION CreateRestricted(SafeAccessTokenHandle token, StringBuilder commandLine, uint flags, string directory,
        STARTUPINFO startup, params SafeFileHandle[] inherit)
    {
        var handles = inherit.Select(h => h.DangerousGetHandle()).Distinct().ToArray();
        var size = IntPtr.Zero;
        InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size); // asks for the size; fails by design
        var list = Marshal.AllocHGlobal(size);
        var pin = GCHandle.Alloc(handles, GCHandleType.Pinned);
        try
        {
            Check(InitializeProcThreadAttributeList(list, 1, 0, ref size));
            try
            {
                Check(UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, pin.AddrOfPinnedObject(),
                    (IntPtr)(IntPtr.Size * handles.Length), IntPtr.Zero, IntPtr.Zero));
                var si = new STARTUPINFOEX { StartupInfo = startup, lpAttributeList = list };
                si.StartupInfo.cb = Marshal.SizeOf<STARTUPINFOEX>();
                foreach (var h in inherit) Check(SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT));
                try
                {
                    Check(CreateProcessAsUser(token, null, commandLine, IntPtr.Zero, IntPtr.Zero, true, flags | EXTENDED_STARTUPINFO_PRESENT,
                        IntPtr.Zero, directory, ref si, out var pi));
                    return pi;
                }
                finally { foreach (var h in inherit) SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0); }
            }
            finally { DeleteProcThreadAttributeList(list); }
        }
        finally { pin.Free(); Marshal.FreeHGlobal(list); }
    }

    /// <summary>The groups an unsigned module's host also gets deny-only: INTERACTIVE and Event Log Readers. The Application and System logs
    /// grant reading to those groups (and to Administrators, already deny-only), so the module can't read the logs itself; it gets what it
    /// needs from the app, redacted (host queries). Groups the app's token doesn't have are ignored.</summary>
    public static readonly IReadOnlyList<string> UnsignedDenyOnly = ["S-1-5-4", "S-1-5-32-573"];

    /// <summary>
    /// The token a module host gets: a restricted copy of the app's own, Administrators deny-only, every privilege but SeChangeNotify
    /// removed, Medium integrity, owned by the user. For an unsigned module (<paramref name="unsigned"/>) also <see cref="UnsignedDenyOnly"/>.
    /// The caller owns the handle.
    /// </summary>
    public static SafeAccessTokenHandle CreateToken(bool unsigned) => RestrictedToken(unsigned);

    private static SafeAccessTokenHandle RestrictedToken(bool unsigned = false)
    {
        Check(OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT, out var own));
        using (own)
        {
            var adminSid = new byte[SECURITY_MAX_SID_SIZE];
            var size = adminSid.Length;
            Check(CreateWellKnownSid(WinBuiltinAdministratorsSid, IntPtr.Zero, adminSid, ref size));
            var sids = new List<byte[]> { adminSid };
            if (unsigned)
                foreach (var sddl in UnsignedDenyOnly)
                {
                    var sid = new System.Security.Principal.SecurityIdentifier(sddl);
                    var bytes = new byte[sid.BinaryLength];
                    sid.GetBinaryForm(bytes, 0);
                    sids.Add(bytes);
                }
            var pins = sids.Select(b => GCHandle.Alloc(b, GCHandleType.Pinned)).ToList();
            try
            {
                var disable = pins.Select(p => new SID_AND_ATTRIBUTES { Sid = p.AddrOfPinnedObject(), Attributes = 0 }).ToArray();
                Check(CreateRestrictedToken(own, DISABLE_MAX_PRIVILEGE | LUA_TOKEN, (uint)disable.Length, disable, 0, IntPtr.Zero, 0, IntPtr.Zero, out var restricted));
                try
                {
                    SetMediumIntegrity(restricted);
                    SetUserOwnerAndDefaultDacl(restricted);
                    return restricted;
                }
                catch
                {
                    restricted.Dispose();
                    throw;
                }
            }
            finally { foreach (var p in pins) p.Free(); }
        }
    }

    private static void SetMediumIntegrity(SafeAccessTokenHandle token)
    {
        Check(ConvertStringSidToSid("S-1-16-8192", out var mediumSid));
        try
        {
            var label = new TOKEN_MANDATORY_LABEL { Label = new SID_AND_ATTRIBUTES { Sid = mediumSid, Attributes = SE_GROUP_INTEGRITY } };
            var size = Marshal.SizeOf<TOKEN_MANDATORY_LABEL>() + GetLengthSid(mediumSid);
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(label, buffer, false);
                Check(SetTokenInformation(token, TokenIntegrityLevel, buffer, size));
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        finally { LocalFree(mediumSid); }
    }

    /// <summary>
    /// An elevated token's owner and default DACL are the Administrators group (plus SYSTEM). With Administrators deny-only, the child
    /// could not open its own process and thread objects, and fails to start with 0xC0000142 (DLL initialization failed). So objects it
    /// creates are owned by the user and grant the user and SYSTEM full access.
    /// </summary>
    private static void SetUserOwnerAndDefaultDacl(SafeAccessTokenHandle token)
    {
        var user = System.Security.Principal.WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException("no user SID");
        var system = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.LocalSystemSid, null);
        var userSid = new byte[user.BinaryLength];
        user.GetBinaryForm(userSid, 0);
        var acl = new System.Security.AccessControl.RawAcl(System.Security.AccessControl.RawAcl.AclRevision, 2);
        acl.InsertAce(0, new System.Security.AccessControl.CommonAce(System.Security.AccessControl.AceFlags.None,
            System.Security.AccessControl.AceQualifier.AccessAllowed, GENERIC_ALL, user, false, null));
        acl.InsertAce(1, new System.Security.AccessControl.CommonAce(System.Security.AccessControl.AceFlags.None,
            System.Security.AccessControl.AceQualifier.AccessAllowed, GENERIC_ALL, system, false, null));
        var aclBytes = new byte[acl.BinaryLength];
        acl.GetBinaryForm(aclBytes, 0);

        var sidPin = GCHandle.Alloc(userSid, GCHandleType.Pinned);
        var aclPin = GCHandle.Alloc(aclBytes, GCHandleType.Pinned);
        try
        {
            var owner = sidPin.AddrOfPinnedObject();          // TOKEN_OWNER { PSID Owner }
            Check(SetTokenInformation(token, TokenOwner, ref owner, IntPtr.Size));
            var dacl = aclPin.AddrOfPinnedObject();           // TOKEN_DEFAULT_DACL { PACL DefaultDacl }
            Check(SetTokenInformation(token, TokenDefaultDacl, ref dacl, IntPtr.Size));
        }
        finally { sidPin.Free(); aclPin.Free(); }
    }

    private static void Check(bool ok) { if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error()); }

    private sealed class Connection(Process process, StreamWriter input, StreamReader output, StreamReader error) : IModuleHostConnection
    {
        public async Task WriteLineAsync(string line, CancellationToken ct) => await input.WriteLineAsync(line.AsMemory(), ct).ConfigureAwait(false);
        public Task<string?> ReadLineAsync(CancellationToken ct) => output.ReadLineAsync(ct).AsTask();
        public bool HasExited { get { try { return process.HasExited; } catch { return true; } } }
        public void Kill() { try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch { } }
        public void Dispose()
        {
            try { input.Dispose(); } catch { } // closing stdin ends the host
            try { if (!process.WaitForExit(2000)) Kill(); } catch { }
            try { output.Dispose(); error.Dispose(); process.Dispose(); } catch { }
        }
    }

    private const uint TOKEN_DUPLICATE = 0x0002, TOKEN_QUERY = 0x0008, TOKEN_ASSIGN_PRIMARY = 0x0001, TOKEN_ADJUST_DEFAULT = 0x0080;
    private const uint DISABLE_MAX_PRIVILEGE = 0x1, LUA_TOKEN = 0x4;
    private const int WinBuiltinAdministratorsSid = 26, SECURITY_MAX_SID_SIZE = 68, TokenIntegrityLevel = 25, TokenOwner = 4, TokenDefaultDacl = 6;
    private const int GENERIC_ALL = 0x10000000;
    private const uint SE_GROUP_INTEGRITY = 0x20, HANDLE_FLAG_INHERIT = 1, STARTF_USESTDHANDLES = 0x100;
    private const uint CREATE_NO_WINDOW = 0x08000000, CREATE_UNICODE_ENVIRONMENT = 0x00000400, EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    private static readonly IntPtr PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002;

    [StructLayout(LayoutKind.Sequential)] private struct SID_AND_ATTRIBUTES { public IntPtr Sid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)] private struct TOKEN_MANDATORY_LABEL { public SID_AND_ATTRIBUTES Label; }
    [StructLayout(LayoutKind.Sequential)] private struct SECURITY_ATTRIBUTES { public int nLength; public IntPtr lpSecurityDescriptor; public bool bInheritHandle; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb; public string? lpReserved, lpDesktop, lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute;
        public uint dwFlags; public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct STARTUPINFOEX { public STARTUPINFO StartupInfo; public IntPtr lpAttributeList; }
    [StructLayout(LayoutKind.Sequential)] private struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CreateWellKnownSid(int type, IntPtr domainSid, byte[] sid, ref int size);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CreateRestrictedToken(SafeAccessTokenHandle existing, uint flags, uint disableSidCount, SID_AND_ATTRIBUTES[] sidsToDisable,
        uint deletePrivilegeCount, IntPtr privilegesToDelete, uint restrictedSidCount, IntPtr sidsToRestrict, out SafeAccessTokenHandle newToken);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool ConvertStringSidToSid(string sid, out IntPtr psid);
    [DllImport("advapi32.dll")] private static extern int GetLengthSid(IntPtr sid);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SetTokenInformation(SafeAccessTokenHandle token, int infoClass, IntPtr info, int length);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SetTokenInformation(SafeAccessTokenHandle token, int infoClass, ref IntPtr info, int length);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessAsUser(SafeAccessTokenHandle token, string? application, StringBuilder commandLine, IntPtr processAttributes,
        IntPtr threadAttributes, bool inheritHandles, uint flags, IntPtr environment, string? currentDirectory, ref STARTUPINFO startup, out PROCESS_INFORMATION info);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessAsUser(SafeAccessTokenHandle token, string? application, StringBuilder commandLine, IntPtr processAttributes,
        IntPtr threadAttributes, bool inheritHandles, uint flags, IntPtr environment, string? currentDirectory, ref STARTUPINFOEX startup, out PROCESS_INFORMATION info);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previous, IntPtr returnSize);
    [DllImport("kernel32.dll")] private static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CreatePipe(out SafeFileHandle read, out SafeFileHandle write, ref SECURITY_ATTRIBUTES sa, int size);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetHandleInformation(SafeFileHandle handle, uint mask, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr mem);
}
