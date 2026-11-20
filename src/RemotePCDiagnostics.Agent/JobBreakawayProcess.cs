using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace RemotePCDiagnostics.Agent;

/// <summary>
/// Starts a process outside the job object this process is in. The elevated helper puts itself in a kill-on-close job that
/// the Host holds (<c>AgentAdminHost.TryBindKillOnParentCloseJob</c>), and a child started the usual way joins that job. Setup
/// closes the Host, the job closes with it, and Windows ends every process left in the job, Setup included, before it has
/// copied the new files. So Setup is started with <c>CREATE_BREAKAWAY_FROM_JOB</c>, which the helper's job allows.
/// </summary>
internal static class JobBreakawayProcess
{
    /// <summary>
    /// Starts <paramref name="fileName"/> outside the current job. Returns false when Windows refuses the breakaway (a job
    /// further up does not allow it), so the caller can start it the usual way instead. <paramref name="process"/> is null
    /// when the new process has already exited.
    /// </summary>
    public static bool TryStart(string fileName, string arguments, string workingDirectory, out Process? process)
    {
        process = null;
        if (!OperatingSystem.IsWindows())
            return false;

        var si = new STARTUPINFOW { cb = Marshal.SizeOf<STARTUPINFOW>() };
        // CreateProcessW may write to the command line buffer, so it gets its own copy.
        var commandLine = new StringBuilder(BuildCommandLine(fileName, arguments));
        if (!CreateProcessW(
                fileName,
                commandLine,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                CREATE_BREAKAWAY_FROM_JOB | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                IntPtr.Zero,
                workingDirectory,
                ref si,
                out var pi))
        {
            var error = Marshal.GetLastWin32Error();
            if (error == ERROR_ACCESS_DENIED)
                return false;
            throw new Win32Exception(error);
        }

        try
        {
            process = Process.GetProcessById((int)pi.dwProcessId);
        }
        catch (ArgumentException)
        {
            // It already exited: the launch itself worked, there is just nothing left to wait on.
        }
        finally
        {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
        return true;
    }

    /// <summary>The program path in quotes, then its arguments, as Windows expects in a command line.</summary>
    public static string BuildCommandLine(string fileName, string arguments) =>
        string.IsNullOrWhiteSpace(arguments) ? $"\"{fileName}\"" : $"\"{fileName}\" {arguments}";

    /// <summary>True when this process is in a job (so a plain child would be in it too).</summary>
    public static bool IsInJob()
    {
        if (!OperatingSystem.IsWindows())
            return false;
        return IsProcessInJob(GetCurrentProcess(), IntPtr.Zero, out var inJob) && inJob;
    }

    private const uint CREATE_BREAKAWAY_FROM_JOB = 0x01000000;
    private const uint CREATE_NO_WINDOW = 0x08000000;
    private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const int ERROR_ACCESS_DENIED = 5;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFOW
    {
        public int cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
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

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessW(
        string lpApplicationName,
        StringBuilder lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFOW lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool result);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);
}
