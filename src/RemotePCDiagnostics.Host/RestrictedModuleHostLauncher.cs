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
/// of its own token, so no extra rights are needed. The host talks to the app over anonymous pipes for its stdin and stdout, which only
/// the app holds, and exits when the app closes them.
/// </summary>
public sealed class RestrictedModuleHostLauncher(Action<string>? log = null, string? directory = null) : IModuleHostLauncher
{
    public IModuleHostConnection Start(UserModeModule module)
    {
        var dir = directory ?? AppContext.BaseDirectory;
        var exe = Path.Combine(dir, ProcessModuleHostLauncher.HostName + ".exe");
        if (!File.Exists(exe)) throw new FileNotFoundException("Module host not found", exe);
        var commandLine = new StringBuilder($"\"{exe}\" \"{module.Path}\"");

        using var token = RestrictedToken();
        var sa = new SECURITY_ATTRIBUTES { nLength = Marshal.SizeOf<SECURITY_ATTRIBUTES>(), bInheritHandle = true };
        Check(CreatePipe(out var inRead, out var inWrite, ref sa, 0));
        Check(CreatePipe(out var outRead, out var outWrite, ref sa, 0));
        Check(CreatePipe(out var errRead, out var errWrite, ref sa, 0));
        // The app's ends must not be inherited.
        Check(SetHandleInformation(inWrite, HANDLE_FLAG_INHERIT, 0));
        Check(SetHandleInformation(outRead, HANDLE_FLAG_INHERIT, 0));
        Check(SetHandleInformation(errRead, HANDLE_FLAG_INHERIT, 0));

        var si = new STARTUPINFO
        {
            cb = Marshal.SizeOf<STARTUPINFO>(), dwFlags = STARTF_USESTDHANDLES,
            hStdInput = inRead.DangerousGetHandle(), hStdOutput = outWrite.DangerousGetHandle(), hStdError = errWrite.DangerousGetHandle(),
        };
        PROCESS_INFORMATION pi;
        try
        {
            Check(CreateProcessAsUser(token, null, commandLine, IntPtr.Zero, IntPtr.Zero, true, CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                IntPtr.Zero, dir, ref si, out pi));
        }
        finally
        {
            inRead.Dispose(); outWrite.Dispose(); errWrite.Dispose(); // the child's ends
        }
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        var process = Process.GetProcessById(pi.dwProcessId);
        log?.Invoke($"Module host [{module.Manifest.Slug}]: started pid={pi.dwProcessId} (restricted token, Medium integrity)");

        var stderr = new StreamReader(new FileStream(errRead, FileAccess.Read), Encoding.UTF8);
        _ = Task.Run(async () =>
        {
            try { while (await stderr.ReadLineAsync().ConfigureAwait(false) is { } line) log?.Invoke($"Module host [{module.Manifest.Slug}]: {line}"); }
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
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return Process.GetProcessById(pi.dwProcessId);
    }

    private static SafeAccessTokenHandle RestrictedToken()
    {
        Check(OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT, out var own));
        using (own)
        {
            var adminSid = new byte[SECURITY_MAX_SID_SIZE];
            var size = adminSid.Length;
            Check(CreateWellKnownSid(WinBuiltinAdministratorsSid, IntPtr.Zero, adminSid, ref size));
            var sidHandle = GCHandle.Alloc(adminSid, GCHandleType.Pinned);
            try
            {
                var disable = new[] { new SID_AND_ATTRIBUTES { Sid = sidHandle.AddrOfPinnedObject(), Attributes = 0 } };
                Check(CreateRestrictedToken(own, DISABLE_MAX_PRIVILEGE | LUA_TOKEN, 1, disable, 0, IntPtr.Zero, 0, IntPtr.Zero, out var restricted));
                SetMediumIntegrity(restricted);
                return restricted;
            }
            finally { sidHandle.Free(); }
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
    private const int WinBuiltinAdministratorsSid = 26, SECURITY_MAX_SID_SIZE = 68, TokenIntegrityLevel = 25;
    private const uint SE_GROUP_INTEGRITY = 0x20, HANDLE_FLAG_INHERIT = 1, STARTF_USESTDHANDLES = 0x100;
    private const uint CREATE_NO_WINDOW = 0x08000000, CREATE_UNICODE_ENVIRONMENT = 0x00000400;

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
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessAsUser(SafeAccessTokenHandle token, string? application, StringBuilder commandLine, IntPtr processAttributes,
        IntPtr threadAttributes, bool inheritHandles, uint flags, IntPtr environment, string? currentDirectory, ref STARTUPINFO startup, out PROCESS_INFORMATION info);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CreatePipe(out SafeFileHandle read, out SafeFileHandle write, ref SECURITY_ATTRIBUTES sa, int size);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetHandleInformation(SafeFileHandle handle, uint mask, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr mem);
}
