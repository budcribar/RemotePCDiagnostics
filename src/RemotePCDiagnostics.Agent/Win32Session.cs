using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using RemotePCDiagnostics.Agent.Core;

namespace RemotePCDiagnostics.Agent;

/// <summary>
/// Win32 session discovery, SCM parent detection, desktop consent dialog (<c>MessageBoxTimeoutW</c>),
/// and <c>CreateProcessAsUserW</c> interactive user-session launcher for Session 0 Windows Services.
/// </summary>
internal static class Win32Session
{
    private const uint NoSessionId = 0xFFFFFFFF;
    private const uint MB_YESNO = 0x00000004;
    private const uint MB_ICONQUESTION = 0x00000020;
    private const uint MB_DEFBUTTON2 = 0x00000100;
    private const uint MB_SETFOREGROUND = 0x00010000;
    private const uint MB_TOPMOST = 0x00040000;

    /// <summary>
    /// True only when started directly by the Windows Service Control Manager (<c>services.exe</c> in Session 0),
    /// avoiding false positives when run non-interactively under CI runners or PowerShell jobs.
    /// </summary>
    public static bool IsStartedByServiceControlManager()
    {
        if (!OperatingSystem.IsWindows() || Environment.UserInteractive)
            return false;

        try
        {
            var parentPid = GetParentProcessId((uint)Environment.ProcessId);
            if (parentPid == 0)
                return false;

            using var parent = Process.GetProcessById((int)parentPid);
            return string.Equals(parent.ProcessName, "services", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    public static string GetOsVersionText()
    {
        if (!OperatingSystem.IsWindows())
            return RuntimeInformation.OSDescription;

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            if (key is not null)
            {
                var productName = key.GetValue("ProductName") as string;
                var displayVersion = (key.GetValue("DisplayVersion") as string) ?? (key.GetValue("ReleaseId") as string);
                var build = (key.GetValue("CurrentBuildNumber") as string) ?? (key.GetValue("CurrentBuild") as string);
                return LaunchRules.OsVersionText(productName, displayVersion, build);
            }
        }
        catch
        {
            // Fall through to Environment.OSVersion.
        }

        return LaunchRules.OsVersionText("Windows", null, Environment.OSVersion.Version.Build.ToString());
    }

    /// <summary>
    /// Returns <c>DOMAIN\user</c> (or <c>user</c>) for the active interactive console/RDP session, or <c>""</c> when nobody is signed in.
    /// </summary>
    public static string GetActiveSignedInUser()
    {
        if (!OperatingSystem.IsWindows())
            return Environment.UserName;

        var sessionId = FindActiveUserSessionId();
        if (sessionId == NoSessionId)
            return "";

        var user = QuerySessionString(sessionId, WTS_INFO_CLASS.WTSUserName);
        if (string.IsNullOrWhiteSpace(user))
            return "";

        var domain = QuerySessionString(sessionId, WTS_INFO_CLASS.WTSDomainName);
        return string.IsNullOrWhiteSpace(domain) ? user : $"{domain}\\{user}";
    }

    /// <summary>
    /// Runs the interactive desktop consent prompt inside the active user's session and returns a <see cref="ConsentPolicy"/> exit code.
    /// </summary>
    public static int ShowConsentMessageBox(string requester, int timeoutSeconds)
    {
        if (!OperatingSystem.IsWindows())
            return ConsentPolicy.ExitFailed;

        var text = ConsentPolicy.PromptText(requester);
        var flags = MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2 | MB_SETFOREGROUND | MB_TOPMOST;
        var timeoutMs = (uint)Math.Clamp(timeoutSeconds, AgentCommandLine.MinConsentTimeoutSeconds, AgentCommandLine.MaxConsentTimeoutSeconds) * 1000u;

        try
        {
            var result = MessageBoxTimeoutW(IntPtr.Zero, text, ConsentPolicy.Caption, flags, 0, timeoutMs);
            return ConsentPolicy.ExitCodeForMessageBoxResult(result);
        }
        catch (EntryPointNotFoundException)
        {
            using var timer = new Timer(_ => Environment.Exit(ConsentPolicy.ExitTimedOut), null, (int)timeoutMs, Timeout.Infinite);
            var fallback = MessageBoxW(IntPtr.Zero, text, ConsentPolicy.Caption, flags);
            return ConsentPolicy.ExitCodeForMessageBoxResult(fallback);
        }
        catch
        {
            return ConsentPolicy.ExitFailed;
        }
    }

    /// <summary>
    /// Starts a command line in the active signed-in user's desktop session when running as <c>LocalSystem</c> in Session 0,
    /// or directly via <see cref="Process.Start(ProcessStartInfo)"/> when running interactively in a user console.
    /// </summary>
    public static (Process? Process, string? Error) StartInActiveUserSession(
        string executablePath,
        string fullCommandLine,
        string workingDirectory,
        bool preferElevatedToken,
        bool createNoWindow)
    {
        if (!OperatingSystem.IsWindows())
            return StartDirectProcess(executablePath, fullCommandLine, workingDirectory, createNoWindow);

        var currentSessionId = 0u;
        var hasCurrentSession = ProcessIdToSessionId((uint)Environment.ProcessId, out currentSessionId);
        var runningInSessionZero = hasCurrentSession && currentSessionId == 0;

        if (!runningInSessionZero)
        {
            // Agent was started interactively by a developer/tester in an existing user session.
            return StartDirectProcess(executablePath, fullCommandLine, workingDirectory, createNoWindow);
        }

        var targetSessionId = FindActiveUserSessionId();
        if (targetSessionId == NoSessionId || string.IsNullOrWhiteSpace(QuerySessionString(targetSessionId, WTS_INFO_CLASS.WTSUserName)))
            return (null, "Nobody is signed in at this computer.");

        if (!WTSQueryUserToken(targetSessionId, out var userToken) || userToken == IntPtr.Zero)
        {
            var err = Marshal.GetLastWin32Error();
            return (null, $"Could not query the signed-in user's session token (Win32 error {err}).");
        }

        IntPtr tokenToDuplicate = userToken;
        IntPtr linkedToken = IntPtr.Zero;
        IntPtr primaryToken = IntPtr.Zero;
        IntPtr envBlock = IntPtr.Zero;

        try
        {
            if (preferElevatedToken && TryGetLinkedElevatedToken(userToken, out linkedToken) && linkedToken != IntPtr.Zero)
            {
                tokenToDuplicate = linkedToken;
            }

            if (!DuplicateTokenEx(
                    tokenToDuplicate,
                    TOKEN_ALL_ACCESS,
                    IntPtr.Zero,
                    SECURITY_IMPERSONATION_LEVEL.SecurityIdentification,
                    TOKEN_TYPE.TokenPrimary,
                    out primaryToken) || primaryToken == IntPtr.Zero)
            {
                // Fall back to duplicating the base user token if linked token duplication failed.
                if (tokenToDuplicate != userToken)
                {
                    if (!DuplicateTokenEx(
                            userToken,
                            TOKEN_ALL_ACCESS,
                            IntPtr.Zero,
                            SECURITY_IMPERSONATION_LEVEL.SecurityIdentification,
                            TOKEN_TYPE.TokenPrimary,
                            out primaryToken) || primaryToken == IntPtr.Zero)
                    {
                        return (null, $"Could not prepare primary user token (Win32 error {Marshal.GetLastWin32Error()}).");
                    }
                }
                else
                {
                    return (null, $"Could not duplicate user token (Win32 error {Marshal.GetLastWin32Error()}).");
                }
            }

            // Ensure primary token targets the interactive session.
            uint sid = targetSessionId;
            SetTokenInformation(primaryToken, TOKEN_INFORMATION_CLASS.TokenSessionId, ref sid, sizeof(uint));

            uint creationFlags = CREATE_UNICODE_ENVIRONMENT | (createNoWindow ? CREATE_NO_WINDOW : 0u);
            if (!CreateEnvironmentBlock(out envBlock, primaryToken, false))
                envBlock = IntPtr.Zero;

            var si = new STARTUPINFOW
            {
                cb = (uint)Marshal.SizeOf<STARTUPINFOW>(),
                lpDesktop = @"winsta0\default",
            };

            var cmdBuilder = new StringBuilder(fullCommandLine + "\0");
            if (!CreateProcessAsUserW(
                    primaryToken,
                    null,
                    cmdBuilder,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    creationFlags,
                    envBlock,
                    string.IsNullOrWhiteSpace(workingDirectory) ? null : workingDirectory,
                    ref si,
                    out var pi))
            {
                var win32Err = Marshal.GetLastWin32Error();
                return (null, $"Could not start process in user session (Win32 error {win32Err}: {new Win32Exception(win32Err).Message}).");
            }

            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);

            try
            {
                var proc = Process.GetProcessById((int)pi.dwProcessId);
                return (proc, null);
            }
            catch
            {
                return (null, "Remote PC Diagnostics exited immediately after starting.");
            }
        }
        finally
        {
            if (envBlock != IntPtr.Zero) DestroyEnvironmentBlock(envBlock);
            if (primaryToken != IntPtr.Zero) CloseHandle(primaryToken);
            if (linkedToken != IntPtr.Zero) CloseHandle(linkedToken);
            CloseHandle(userToken);
        }
    }

    private static (Process? Process, string? Error) StartDirectProcess(
        string executablePath,
        string fullCommandLine,
        string workingDirectory,
        bool createNoWindow)
    {
        try
        {
            var argsOnly = ExtractArgumentsAfterExecutable(executablePath, fullCommandLine);
            var psi = new ProcessStartInfo
            {
                FileName = executablePath,
                Arguments = argsOnly,
                WorkingDirectory = string.IsNullOrWhiteSpace(workingDirectory)
                    ? (Path.GetDirectoryName(executablePath) ?? AppContext.BaseDirectory)
                    : workingDirectory,
                UseShellExecute = false,
                CreateNoWindow = createNoWindow,
            };
            var proc = Process.Start(psi);
            return proc is null ? (null, $"Failed to start '{executablePath}'.") : (proc, null);
        }
        catch (Exception ex)
        {
            return (null, ex.Message);
        }
    }

    internal static string ExtractArgumentsAfterExecutable(string executablePath, string fullCommandLine)
    {
        var quotedExe = WindowsCommandLine.Quote(executablePath);
        if (fullCommandLine.StartsWith(quotedExe, StringComparison.OrdinalIgnoreCase))
            return fullCommandLine[quotedExe.Length..].TrimStart();

        if (fullCommandLine.StartsWith('"'))
        {
            var closing = fullCommandLine.IndexOf('"', 1);
            if (closing > 0)
                return fullCommandLine[(closing + 1)..].TrimStart();
        }
        else
        {
            var space = fullCommandLine.IndexOf(' ');
            if (space > 0)
                return fullCommandLine[(space + 1)..].TrimStart();
        }
        return "";
    }

    private static uint FindActiveUserSessionId()
    {
        var consoleId = WTSGetActiveConsoleSessionId();
        if (consoleId != NoSessionId && !string.IsNullOrWhiteSpace(QuerySessionString(consoleId, WTS_INFO_CLASS.WTSUserName)))
            return consoleId;

        if (WTSEnumerateSessionsW(IntPtr.Zero, 0, 1, out var pSessions, out var count) && pSessions != IntPtr.Zero)
        {
            try
            {
                var itemSize = Marshal.SizeOf<WTS_SESSION_INFOW>();
                for (var i = 0; i < count; i++)
                {
                    var ptr = IntPtr.Add(pSessions, i * itemSize);
                    var info = Marshal.PtrToStructure<WTS_SESSION_INFOW>(ptr);
                    if (info.State == WTS_CONNECTSTATE_CLASS.WTSActive && info.SessionId != 0)
                    {
                        if (!string.IsNullOrWhiteSpace(QuerySessionString(info.SessionId, WTS_INFO_CLASS.WTSUserName)))
                            return info.SessionId;
                    }
                }
            }
            finally
            {
                WTSFreeMemory(pSessions);
            }
        }

        return consoleId;
    }

    private static string QuerySessionString(uint sessionId, WTS_INFO_CLASS infoClass)
    {
        if (!WTSQuerySessionInformationW(IntPtr.Zero, sessionId, infoClass, out var buffer, out var bytesReturned) || buffer == IntPtr.Zero)
            return "";

        try
        {
            if (bytesReturned <= 2)
                return "";
            return Marshal.PtrToStringUni(buffer)?.Trim() ?? "";
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
    }

    private static bool TryGetLinkedElevatedToken(IntPtr userToken, out IntPtr linkedToken)
    {
        linkedToken = IntPtr.Zero;
        int elevType = 0;
        if (!GetTokenInformationInt(userToken, TOKEN_INFORMATION_CLASS.TokenElevationType, out elevType))
            return false;

        // TokenElevationTypeLimited == 3 means split-token admin whose elevated companion is in TokenLinkedToken.
        if (elevType != 3)
            return false;

        var size = IntPtr.Size;
        var buf = Marshal.AllocHGlobal(size);
        try
        {
            if (!GetTokenInformation(userToken, TOKEN_INFORMATION_CLASS.TokenLinkedToken, buf, (uint)size, out _))
                return false;
            linkedToken = Marshal.ReadIntPtr(buf);
            return linkedToken != IntPtr.Zero;
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }

    private static bool GetTokenInformationInt(IntPtr token, TOKEN_INFORMATION_CLASS cls, out int value)
    {
        value = 0;
        var buf = Marshal.AllocHGlobal(sizeof(int));
        try
        {
            if (!GetTokenInformation(token, cls, buf, sizeof(int), out _))
                return false;
            value = Marshal.ReadInt32(buf);
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }

    private static uint GetParentProcessId(uint pid)
    {
        const uint TH32CS_SNAPPROCESS = 0x00000002;
        var snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == IntPtr.Zero || snap == new IntPtr(-1))
            return 0;

        try
        {
            var entry = new PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32W>() };
            if (!Process32FirstW(snap, ref entry))
                return 0;

            do
            {
                if (entry.th32ProcessID == pid)
                    return entry.th32ParentProcessID;
            }
            while (Process32NextW(snap, ref entry));

            return 0;
        }
        finally
        {
            CloseHandle(snap);
        }
    }

    private const uint TOKEN_ALL_ACCESS = 0x000F01FF;
    private const uint CREATE_NO_WINDOW = 0x08000000;
    private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;

    private enum WTS_INFO_CLASS
    {
        WTSUserName = 5,
        WTSDomainName = 7,
    }

    private enum WTS_CONNECTSTATE_CLASS
    {
        WTSActive = 0,
        WTSConnected = 1,
        WTSConnectQuery = 2,
        WTSShadow = 3,
        WTSDisconnected = 4,
        WTSIdle = 5,
        WTSListen = 6,
        WTSReset = 7,
        WTSDown = 8,
        WTSInit = 9,
    }

    private enum SECURITY_IMPERSONATION_LEVEL
    {
        SecurityAnonymous = 0,
        SecurityIdentification = 1,
        SecurityImpersonation = 2,
        SecurityDelegation = 3,
    }

    private enum TOKEN_TYPE
    {
        TokenPrimary = 1,
        TokenImpersonation = 2,
    }

    private enum TOKEN_INFORMATION_CLASS
    {
        TokenSessionId = 12,
        TokenElevationType = 18,
        TokenLinkedToken = 19,
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WTS_SESSION_INFOW
    {
        public uint SessionId;
        public string pWinStationName;
        public WTS_CONNECTSTATE_CLASS State;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFOW
    {
        public uint cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public ushort wShowWindow;
        public ushort cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32W
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    [DllImport("kernel32.dll")]
    private static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ProcessIdToSessionId(uint dwProcessId, out uint pSessionId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool Process32FirstW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool Process32NextW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool WTSQuerySessionInformationW(
        IntPtr hServer,
        uint sessionId,
        WTS_INFO_CLASS wtsInfoClass,
        out IntPtr ppBuffer,
        out uint pBytesReturned);

    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool WTSEnumerateSessionsW(
        IntPtr hServer,
        uint reserved,
        uint version,
        out IntPtr ppSessionInfo,
        out uint pCount);

    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr pMemory);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQueryUserToken(uint sessionId, out IntPtr phToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DuplicateTokenEx(
        IntPtr hExistingToken,
        uint dwDesiredAccess,
        IntPtr lpTokenAttributes,
        SECURITY_IMPERSONATION_LEVEL impersonationLevel,
        TOKEN_TYPE tokenType,
        out IntPtr phNewToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(
        IntPtr tokenHandle,
        TOKEN_INFORMATION_CLASS tokenInformationClass,
        IntPtr tokenInformation,
        uint tokenInformationLength,
        out uint returnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SetTokenInformation(
        IntPtr tokenHandle,
        TOKEN_INFORMATION_CLASS tokenInformationClass,
        ref uint tokenInformation,
        uint tokenInformationLength);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessAsUserW(
        IntPtr hToken,
        string? lpApplicationName,
        StringBuilder lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string? lpCurrentDirectory,
        ref STARTUPINFOW lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int MessageBoxTimeoutW(
        IntPtr hWnd,
        string lpText,
        string lpCaption,
        uint uType,
        ushort wLanguageId,
        uint dwMilliseconds);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int MessageBoxW(
        IntPtr hWnd,
        string lpText,
        string lpCaption,
        uint uType);
}
