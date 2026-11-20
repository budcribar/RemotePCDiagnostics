using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using RemotePCDiagnostics.Core.Optimizations;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// Undo for removed Store apps (<see cref="StoreReinstall"/>): runs the fixed winget command as the signed-in user and checks with
/// Get-AppxPackage that the package is back. msstore installs are per-user and need no administrator rights, so this stays in the app,
/// which runs un-elevated as the account signed in at the desktop. winget never runs elevated or as SYSTEM, and nothing here goes
/// through the Agent. When the app isn't running as that account, it refuses rather than install for the wrong one.
/// </summary>
public sealed partial class WindowsMemorySystem
{
    public async Task<WingetResult> RunWingetAsync(WingetCommand command, CancellationToken ct)
    {
        if (!StoreReinstall.IsAllowedCommand(command)) { Log("Refused winget: " + command.Display); return WingetResult.NotStarted("that command isn't one this app may run"); }
        if (DesktopUserProblem() is { } problem) return WingetResult.NotStarted(problem);
        var exe = StoreReinstall.WingetPath(LocalAppData);
        if (exe is null) return WingetResult.NotStarted("the signed-in account's folders couldn't be found");
        if (!File.Exists(exe)) return WingetResult.NotStarted("winget (App Installer) isn't installed for the signed-in account");

        var r = await RunDirectAsync(exe, command.Arguments, ct).ConfigureAwait(false);
        Log($"winget {command.Display}: started={r.Started} exit={r.ExitCode?.ToString() ?? "none"} {r.Problem}");
        return r;
    }

    public async Task<bool?> IsStorePackageInstalledAsync(RemovableAppx app, CancellationToken ct)
    {
        if (!StoreReinstall.CanReinstall(app)) return null;
        if (DesktopUserProblem() is not null) return null;
        // The app's own account: Get-AppxPackage without -User (which would need administrator rights).
        var r = await RunPowerShellAsync(StoreReinstall.VerifyScript(app, null), ct, TimeSpan.FromMinutes(1)).ConfigureAwait(false);
        var found = r.ExitCode == 0 ? StoreReinstall.ParseInstalled(r.Output) : null;
        Log($"Package check {app.FamilyName}: exit={r.ExitCode} installed={found?.ToString() ?? "?"} err={r.Error.Trim()}");
        return found;
    }

    /// <summary>Why the Store reinstall can't run for the desktop's account from this process, or null when it can.</summary>
    private string? DesktopUserProblem()
    {
        using var user = SignedInUser.Open(Logger);
        if (user is null) return "no signed-in desktop was found to reinstall it for";
        if (user.IsCurrentProcessUser) return null;
        Log($"Store reinstall: the app runs as a different account than the desktop's ({user.Sid})");
        return "the app isn't running as the account signed in at the desktop";
    }

    /// <summary>An ordinary ProcessStartInfo with ArgumentList (no shell), as the app's own account.</summary>
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
    internal sealed class SignedInUser : IDisposable
    {
        private readonly SafeAccessTokenHandle _token;
        public string Sid { get; }
        public bool IsCurrentProcessUser { get; }

        private SignedInUser(SafeAccessTokenHandle token, string sid, bool current) { _token = token; Sid = sid; IsCurrentProcessUser = current; }
        public void Dispose() => _token.Dispose();

        public static SignedInUser? Open(ILogger? log)
        {
            try
            {
                var shell = Native.GetShellWindow();
                if (shell == IntPtr.Zero) { log.Info("No desktop shell window (nobody signed in at this desktop?)"); return null; }
                Native.GetWindowThreadProcessId(shell, out var pid);
                if (pid == 0) { log.Info("Shell process not found"); return null; }
                using var process = Native.OpenProcess(Native.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                if (process.IsInvalid) { log.Warn($"OpenProcess(shell) failed: {Marshal.GetLastWin32Error()}"); return null; }
                if (!Native.OpenProcessToken(process, Native.TOKEN_DUPLICATE | Native.TOKEN_QUERY, out var shellToken)) { log.Warn($"OpenProcessToken(shell) failed: {Marshal.GetLastWin32Error()}"); return null; }
                using (shellToken)
                {
                    if (!Native.DuplicateTokenEx(shellToken, Native.TOKEN_PRIMARY_ACCESS, IntPtr.Zero, Native.SecurityImpersonation, Native.TokenPrimary, out var primary))
                    { log.Warn($"DuplicateTokenEx failed: {Marshal.GetLastWin32Error()}"); return null; }
                    string? sid;
                    using (var id = new WindowsIdentity(primary.DangerousGetHandle())) sid = id.User?.Value;
                    using var me = WindowsIdentity.GetCurrent();
                    if (sid is null || sid == "S-1-5-18") { primary.Dispose(); log.Info("Shell runs as SYSTEM or an unknown account"); return null; }
                    return new(primary, sid, string.Equals(me.User?.Value, sid, StringComparison.OrdinalIgnoreCase));
                }
            }
            catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or UnauthorizedAccessException or ArgumentException or System.Security.SecurityException)
            {
                log.Info("Signed-in user: " + ex.Message);
                return null;
            }
        }
    }

    private static class Native
    {
        public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        public const uint TOKEN_ASSIGN_PRIMARY = 0x0001, TOKEN_DUPLICATE = 0x0002, TOKEN_QUERY = 0x0008, TOKEN_ADJUST_DEFAULT = 0x0080, TOKEN_ADJUST_SESSIONID = 0x0100;
        public const uint TOKEN_PRIMARY_ACCESS = TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID;
        public const int SecurityImpersonation = 2, TokenPrimary = 1;

        [DllImport("user32.dll")] public static extern IntPtr GetShellWindow();
        [DllImport("user32.dll", SetLastError = true)] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);
        [DllImport("kernel32.dll", SetLastError = true)] public static extern SafeProcessHandle OpenProcess(uint access, bool inherit, uint processId);
        [DllImport("advapi32.dll", SetLastError = true)] public static extern bool OpenProcessToken(SafeProcessHandle process, uint access, out SafeAccessTokenHandle token);
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool DuplicateTokenEx(SafeAccessTokenHandle existing, uint access, IntPtr attributes, int impersonationLevel, int tokenType, out SafeAccessTokenHandle token);
    }
}
