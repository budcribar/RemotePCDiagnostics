using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using RemotePCDiagnostics.Core.Memory;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// Undo for removed Store apps (<see cref="StoreReinstall"/>): runs the fixed winget command as the signed-in user and checks with
/// Get-AppxPackage that the package is back. msstore installs are per-user, so winget never runs elevated or as SYSTEM: the elevated Host
/// starts it with the desktop shell's (Explorer's) token, the standard way to start a non-elevated process from an elevated one.
/// </summary>
public sealed partial class WindowsMemorySystem
{
    public async Task<WingetResult> RunWingetAsync(WingetCommand command, CancellationToken ct)
    {
        if (!StoreReinstall.IsAllowedCommand(command)) { Log("Refused winget: " + command.Display); return WingetResult.NotStarted("that command isn't one this app may run"); }
        using var user = SignedInUser.Open(Log);
        if (user is null) return WingetResult.NotStarted("no signed-in desktop was found to reinstall it for");
        var exe = StoreReinstall.WingetPath(user.LocalAppData());
        if (exe is null) return WingetResult.NotStarted("the signed-in account's folders couldn't be found");
        if (!File.Exists(exe)) return WingetResult.NotStarted("winget (App Installer) isn't installed for the signed-in account");

        var r = user.IsCurrentProcessUser && !IsElevatedOrSystem()
            ? await RunDirectAsync(exe, command.Arguments, ct).ConfigureAwait(false)
            : await user.RunAsync(exe, command.Arguments, StoreReinstall.Timeout, Log, ct).ConfigureAwait(false);
        Log($"winget {command.Display} as {user.Sid}: started={r.Started} exit={r.ExitCode?.ToString() ?? "none"} {r.Problem}");
        return r;
    }

    public async Task<bool?> IsStorePackageInstalledAsync(RemovableAppx app, CancellationToken ct)
    {
        if (!StoreReinstall.CanReinstall(app)) return null;
        using var user = SignedInUser.Open(Log);
        if (user is null) return null;
        // Elevated (always, for the Host): Get-AppxPackage -User <signed-in user's SID>. Not elevated and the same account: its own packages.
        var sid = user.IsCurrentProcessUser && !IsElevatedOrSystem() ? null : user.Sid;
        if (sid is not null && !StoreReinstall.IsValidSid(sid)) { Log($"Package check: unexpected SID {sid}"); return null; }
        var r = await RunPowerShellAsync(StoreReinstall.VerifyScript(app, sid), ct, TimeSpan.FromMinutes(1)).ConfigureAwait(false);
        var found = r.ExitCode == 0 ? StoreReinstall.ParseInstalled(r.Output) : null;
        Log($"Package check {app.FamilyName} for {user.Sid}: exit={r.ExitCode} installed={found?.ToString() ?? "?"} err={r.Error.Trim()}");
        return found;
    }

    private static bool IsElevatedOrSystem()
    {
        using var me = WindowsIdentity.GetCurrent();
        return me.IsSystem || new WindowsPrincipal(me).IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>Not elevated and already the signed-in user: an ordinary ProcessStartInfo with ArgumentList (no shell).</summary>
    private async Task<WingetResult> RunDirectAsync(string exe, IReadOnlyList<string> args, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(exe) { UseShellExecute = false, CreateNoWindow = true };
        foreach (var a in args) psi.ArgumentList.Add(a);
        try
        {
            using var p = Process.Start(psi);
            if (p is null) return WingetResult.NotStarted("winget didn't start");
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(StoreReinstall.Timeout);
            try { await p.WaitForExitAsync(timeout.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                try { p.Kill(entireProcessTree: true); } catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception) { }
                return WingetResult.TimedOut();
            }
            return WingetResult.Exited(p.ExitCode);
        }
        catch (System.ComponentModel.Win32Exception ex) { Log("winget: " + ex.Message); return WingetResult.NotStarted("winget couldn't be started"); }
    }

    /// <summary>The account signed in at the desktop: a primary token duplicated from the shell (Explorer) process, and its SID.</summary>
    private sealed class SignedInUser : IDisposable
    {
        private readonly SafeAccessTokenHandle _token;
        public string Sid { get; }
        public bool IsCurrentProcessUser { get; }

        private SignedInUser(SafeAccessTokenHandle token, string sid, bool current) { _token = token; Sid = sid; IsCurrentProcessUser = current; }
        public void Dispose() => _token.Dispose();

        public static SignedInUser? Open(Action<string> log)
        {
            try
            {
                var shell = Native.GetShellWindow();
                if (shell == IntPtr.Zero) { log("No desktop shell window (nobody signed in at this desktop?)"); return null; }
                Native.GetWindowThreadProcessId(shell, out var pid);
                if (pid == 0) { log("Shell process not found"); return null; }
                using var process = Native.OpenProcess(Native.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                if (process.IsInvalid) { log($"OpenProcess(shell) failed: {Marshal.GetLastWin32Error()}"); return null; }
                if (!Native.OpenProcessToken(process, Native.TOKEN_DUPLICATE | Native.TOKEN_QUERY, out var shellToken)) { log($"OpenProcessToken(shell) failed: {Marshal.GetLastWin32Error()}"); return null; }
                using (shellToken)
                {
                    if (!Native.DuplicateTokenEx(shellToken, Native.TOKEN_PRIMARY_ACCESS, IntPtr.Zero, Native.SecurityImpersonation, Native.TokenPrimary, out var primary))
                    { log($"DuplicateTokenEx failed: {Marshal.GetLastWin32Error()}"); return null; }
                    string? sid;
                    using (var id = new WindowsIdentity(primary.DangerousGetHandle())) sid = id.User?.Value;
                    using var me = WindowsIdentity.GetCurrent();
                    if (sid is null || sid == "S-1-5-18") { primary.Dispose(); log("Shell runs as SYSTEM or an unknown account"); return null; }
                    return new(primary, sid, string.Equals(me.User?.Value, sid, StringComparison.OrdinalIgnoreCase));
                }
            }
            catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or UnauthorizedAccessException or ArgumentException or System.Security.SecurityException)
            {
                log("Signed-in user: " + ex.Message);
                return null;
            }
        }

        /// <summary>The signed-in account's %LOCALAPPDATA% (its profile folder from ProfileList when it isn't the Host's own account).</summary>
        public string? LocalAppData()
        {
            if (IsCurrentProcessUser) return Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            try
            {
                using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                using var k = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" + Sid);
                return k?.GetValue("ProfileImagePath") is string profile && profile.Length > 0 ? Path.Combine(profile, "AppData", "Local") : null;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException) { return null; }
        }

        /// <summary>Starts <paramref name="exe"/> with this user's token (CreateProcessWithTokenW, the user's own environment), no window, and waits.</summary>
        public async Task<WingetResult> RunAsync(string exe, IReadOnlyList<string> args, TimeSpan limit, Action<string> log, CancellationToken ct)
        {
            var si = new Native.STARTUPINFO { cb = Marshal.SizeOf<Native.STARTUPINFO>() };
            var commandLine = new StringBuilder(StoreReinstall.CommandLine(exe, args));
            if (!Native.CreateProcessWithTokenW(_token, Native.LOGON_WITH_PROFILE, exe, commandLine, Native.CREATE_NO_WINDOW | Native.CREATE_UNICODE_ENVIRONMENT,
                    IntPtr.Zero, null, ref si, out var pi))
            {
                log($"CreateProcessWithTokenW failed: {Marshal.GetLastWin32Error()}");
                return WingetResult.NotStarted("Windows didn't allow starting winget for the signed-in account");
            }
            Native.CloseHandle(pi.hThread);
            using var process = new SafeProcessHandle(pi.hProcess, ownsHandle: true);
            using var wait = new ProcessWait(process);
            var done = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var registration = ThreadPool.RegisterWaitForSingleObject(wait, (_, timedOut) => done.TrySetResult(!timedOut), null, limit, executeOnlyOnce: true);
            try
            {
                using (ct.Register(() => done.TrySetCanceled(ct)))
                    if (!await done.Task.ConfigureAwait(false))
                    {
                        Native.TerminateProcess(process, 1);
                        return WingetResult.TimedOut();
                    }
            }
            finally { registration.Unregister(null); }
            return Native.GetExitCodeProcess(process, out var code) ? WingetResult.Exited(unchecked((int)code)) : new(true, null, "its result couldn't be read");
        }
    }

    private sealed class ProcessWait : WaitHandle
    {
        public ProcessWait(SafeProcessHandle process) => SafeWaitHandle = new SafeWaitHandle(process.DangerousGetHandle(), ownsHandle: false);
    }

    private static class Native
    {
        public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        public const uint TOKEN_ASSIGN_PRIMARY = 0x0001, TOKEN_DUPLICATE = 0x0002, TOKEN_QUERY = 0x0008, TOKEN_ADJUST_DEFAULT = 0x0080, TOKEN_ADJUST_SESSIONID = 0x0100;
        public const uint TOKEN_PRIMARY_ACCESS = TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID;
        public const int SecurityImpersonation = 2, TokenPrimary = 1;
        public const uint LOGON_WITH_PROFILE = 0x1, CREATE_NO_WINDOW = 0x08000000, CREATE_UNICODE_ENVIRONMENT = 0x00000400;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public int cb;
            public string? lpReserved, lpDesktop, lpTitle;
            public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
            public short wShowWindow, cbReserved2;
            public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }

        [DllImport("user32.dll")] public static extern IntPtr GetShellWindow();
        [DllImport("user32.dll", SetLastError = true)] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);
        [DllImport("kernel32.dll", SetLastError = true)] public static extern SafeProcessHandle OpenProcess(uint access, bool inherit, uint processId);
        [DllImport("advapi32.dll", SetLastError = true)] public static extern bool OpenProcessToken(SafeProcessHandle process, uint access, out SafeAccessTokenHandle token);
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool DuplicateTokenEx(SafeAccessTokenHandle existing, uint access, IntPtr attributes, int impersonationLevel, int tokenType, out SafeAccessTokenHandle token);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithTokenW(SafeAccessTokenHandle token, uint logonFlags, string? applicationName, StringBuilder commandLine, uint creationFlags,
            IntPtr environment, string? currentDirectory, ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInformation);
        [DllImport("kernel32.dll", SetLastError = true)] public static extern bool GetExitCodeProcess(SafeProcessHandle process, out uint exitCode);
        [DllImport("kernel32.dll", SetLastError = true)] public static extern bool TerminateProcess(SafeProcessHandle process, uint exitCode);
        [DllImport("kernel32.dll", SetLastError = true)] public static extern bool CloseHandle(IntPtr handle);
    }
}
