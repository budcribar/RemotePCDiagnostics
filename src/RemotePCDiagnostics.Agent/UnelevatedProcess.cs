using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using RemotePCDiagnostics.Agent.Core;
using RemotePCDiagnostics.Logging;

namespace RemotePCDiagnostics.Agent;

/// <summary>
/// Starts the app from the elevated launcher without administrator rights: with the token of the signed-in user's own shell
/// (explorer.exe in this session), the same un-elevated token the app gets when the user starts it. The app never runs as administrator;
/// what needs it goes through the launcher's admin pipe.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class UnelevatedProcess
{
    /// <summary>How long to wait for the shell after sign-in (a task that runs at logon can start before explorer.exe).</summary>
    public static TimeSpan ShellWait { get; set; } = TimeSpan.FromSeconds(90);

    public static async Task<Process> StartAsync(string exe, IReadOnlyList<string> args, string workingDirectory, ILogger? log, CancellationToken ct = default)
    {
        var shell = await WaitForShellAsync(ct).ConfigureAwait(false)
            ?? throw new InvalidOperationException($"The Windows shell (explorer.exe) didn't start in this session within {ShellWait.TotalSeconds:0} s, so the app can't be started without administrator rights.");
        using (shell)
        {
            var commandLine = WindowsCommandLine.Join([exe, .. args]);
            Check(OpenProcessToken(shell.Handle, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, out var shellToken), "OpenProcessToken");
            try
            {
                Check(DuplicateTokenEx(shellToken, TOKEN_ALL_ACCESS, IntPtr.Zero, SecurityImpersonation, TokenPrimary, out var primary), "DuplicateTokenEx");
                try
                {
                    var si = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFO>(), lpDesktop = @"winsta0\default" };
                    Check(CreateProcessWithTokenW(primary, LOGON_WITH_PROFILE, null, commandLine, CREATE_UNICODE_ENVIRONMENT, IntPtr.Zero,
                        workingDirectory, ref si, out var pi), "CreateProcessWithTokenW");
                    CloseHandle(pi.hThread);
                    CloseHandle(pi.hProcess);
                    log.Info($"[agent-launcher] Host started un-elevated with the shell's token (pid={pi.dwProcessId}, shell pid={shell.Id}).");
                    return Process.GetProcessById(pi.dwProcessId);
                }
                finally { CloseHandle(primary); }
            }
            finally { CloseHandle(shellToken); }
        }
    }

    private static async Task<Process?> WaitForShellAsync(CancellationToken ct)
    {
        var session = Process.GetCurrentProcess().SessionId;
        var until = DateTime.UtcNow + ShellWait;
        while (true)
        {
            var shell = Process.GetProcessesByName("explorer").FirstOrDefault(p => p.SessionId == session);
            if (shell is not null) return shell;
            if (DateTime.UtcNow >= until) return null;
            await Task.Delay(TimeSpan.FromSeconds(1), ct).ConfigureAwait(false);
        }
    }

    private static void Check(bool ok, string what)
    {
        if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error(), what + " failed");
    }

    private const uint TOKEN_ASSIGN_PRIMARY = 0x0001, TOKEN_DUPLICATE = 0x0002, TOKEN_QUERY = 0x0008, TOKEN_ALL_ACCESS = 0xF01FF;
    private const int SecurityImpersonation = 2, TokenPrimary = 1;
    private const uint LOGON_WITH_PROFILE = 0x1, CREATE_UNICODE_ENVIRONMENT = 0x400;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string? lpReserved, lpDesktop, lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DuplicateTokenEx(IntPtr existing, uint access, IntPtr attributes, int impersonationLevel, int tokenType, out IntPtr newToken);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessWithTokenW(IntPtr token, uint logonFlags, string? applicationName, string commandLine, uint creationFlags,
        IntPtr environment, string? currentDirectory, ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
