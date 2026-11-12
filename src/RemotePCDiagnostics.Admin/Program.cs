using System.Diagnostics;
using System.Runtime.InteropServices;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Admin;

public static class Program
{
    public const int ExitOk = 0;
    public const int ExitBadArguments = 2;
    public const int ExitFatal = 1;

    private const string AllowTestParentEnvVar = "RPD_ADMIN_ALLOW_TEST_PARENT";

    public static async Task<int> Main(string[] args)
    {
        if (args.Any(a => string.Equals(a, "--self-check", StringComparison.OrdinalIgnoreCase)))
            return ExitOk;

        if (!TryParseArguments(args, out var parentPid, out var pipeName, out var clientSid))
            return ExitBadArguments;

        Process parent;
        try
        {
            parent = Process.GetProcessById(parentPid);
            if (parent.HasExited)
            {
                parent.Dispose();
                return ExitOk;
            }
        }
        catch
        {
            return ExitOk; // Parent already exited before helper finished starting.
        }

        using (parent)
        {
            // Kernel-level lifetime tie-in: duplicate a KILL_ON_JOB_CLOSE job handle into the parent Host process and close our own handle.
            TryBindKillOnParentCloseJob(parentPid);

            using var cts = new CancellationTokenSource();
            _ = WatchParentExitAsync(parent, cts);

            var allowTestParent = string.Equals(
                Environment.GetEnvironmentVariable(AllowTestParentEnvVar)?.Trim(),
                "1",
                StringComparison.OrdinalIgnoreCase);

            var expectedClientExe = allowTestParent
                ? AdminPipeServer.TryQueryProcessImagePath((uint)parentPid)
                : Path.Combine(AppContext.BaseDirectory, "RemotePCDiagnostics.Host.exe");

            var logPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "RemotePCDiagnostics",
                "logs",
                "RemotePCDiagnostics.Admin.log");
            var fileLog = new RollingFileLog(logPath);
            var loggerFactory = AppLoggerFactory.From(line =>
                fileLog.Write($"{DateTimeOffset.Now:O} [pid={Environment.ProcessId}] {line}"));
            var log = loggerFactory.CreateLogger(typeof(AdminPipeServer).FullName!);

            try
            {
                using var server = new AdminPipeServer(
                    new AdminPipeServerOptions
                    {
                        PipeName = pipeName,
                        ExpectedClientPid = parentPid,
                        ExpectedClientExePath = expectedClientExe,
                        AllowedClientSid = clientSid,
                        ConnectTimeout = TimeSpan.FromSeconds(30),
                    },
                    new SystemProcessLauncher(),
                    log);

                await server.RunSingleSessionAsync(cts.Token).ConfigureAwait(false);
                return ExitOk;
            }
            catch (OperationCanceledException)
            {
                return ExitOk;
            }
            catch (Exception ex)
            {
                log.Error($"[admin-helper] Fatal error: {ex}");
                return ExitFatal;
            }
        }
    }

    public static bool TryParseArguments(
        IReadOnlyList<string> args,
        out int parentPid,
        out string pipeName,
        out string? clientSid)
    {
        parentPid = 0;
        pipeName = "";
        clientSid = null;
        string? mode = null;

        for (var i = 0; i < args.Count; i++)
        {
            var arg = args[i];
            if (TryReadOption(args, ref i, "--mode", out var m))
                mode = m;
            else if (TryReadOption(args, ref i, "--parent-pid", out var pidText) && int.TryParse(pidText, out var parsedPid))
                parentPid = parsedPid;
            else if (TryReadOption(args, ref i, "--pipe", out var p))
                pipeName = p;
            else if (TryReadOption(args, ref i, "--client-sid", out var sid))
                clientSid = sid;
        }

        return string.Equals(mode, "helper", StringComparison.OrdinalIgnoreCase)
            && parentPid > 0
            && !string.IsNullOrWhiteSpace(pipeName)
            && !pipeName.Contains('\\')
            && !pipeName.Contains('/');
    }

    private static bool TryReadOption(IReadOnlyList<string> args, ref int index, string prefix, out string value)
    {
        var current = args[index];
        var eqPrefix = prefix + "=";
        if (current.StartsWith(eqPrefix, StringComparison.OrdinalIgnoreCase))
        {
            value = current[eqPrefix.Length..].Trim();
            return true;
        }
        if (string.Equals(current, prefix, StringComparison.OrdinalIgnoreCase) && index + 1 < args.Count)
        {
            index++;
            value = args[index].Trim();
            return true;
        }
        value = "";
        return false;
    }

    private static async Task WatchParentExitAsync(Process parent, CancellationTokenSource cts)
    {
        try
        {
            await parent.WaitForExitAsync(cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return;
        }
        catch
        {
            // Fall through to cancel session if parent handle becomes invalid.
        }

        try { cts.Cancel(); } catch { }

        // Ensure helper never lingers even if an external system repair tool is mid-execution when Host terminates.
        await Task.Delay(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
        Environment.Exit(ExitOk);
    }

    /// <summary>
    /// Creates an unnamed Windows Job Object with <c>JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE</c>, duplicates its handle into the parent
    /// <c>RemotePCDiagnostics.Host.exe</c> process, assigns this helper process to the job, and closes our local job handle so the OS
    /// kernel guarantees immediate termination if the parent Host process crashes or is killed.
    /// </summary>
    private static void TryBindKillOnParentCloseJob(int parentPid)
    {
        if (!OperatingSystem.IsWindows())
            return;

        var hParent = OpenProcess(PROCESS_DUP_HANDLE, false, (uint)parentPid);
        if (hParent == IntPtr.Zero)
            return;

        try
        {
            var hJob = CreateJobObjectW(IntPtr.Zero, null);
            if (hJob == IntPtr.Zero)
                return;

            try
            {
                var info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION
                {
                    BasicLimitInformation = new JOBOBJECT_BASIC_LIMIT_INFORMATION
                    {
                        LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                    },
                };

                if (!SetInformationJobObject(
                        hJob,
                        JobObjectExtendedLimitInformation,
                        ref info,
                        (uint)Marshal.SizeOf<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()))
                {
                    return;
                }

                if (!DuplicateHandle(
                        GetCurrentProcess(),
                        hJob,
                        hParent,
                        out _,
                        0,
                        false,
                        DUPLICATE_SAME_ACCESS))
                {
                    return;
                }

                AssignProcessToJobObject(hJob, GetCurrentProcess());
            }
            finally
            {
                CloseHandle(hJob);
            }
        }
        catch
        {
            // Parent WatchParentExitAsync + pipe EOF still enforce helper lifetime if job objects are restricted.
        }
        finally
        {
            CloseHandle(hParent);
        }
    }

    private const uint PROCESS_DUP_HANDLE = 0x0040;
    private const uint DUPLICATE_SAME_ACCESS = 0x00000002;
    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    private const int JobObjectExtendedLimitInformation = 9;

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateJobObjectW(IntPtr lpJobAttributes, string? lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(
        IntPtr hJob,
        int JobObjectInfoClass,
        ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION lpJobObjectInfo,
        uint cbJobObjectInfoLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DuplicateHandle(
        IntPtr hSourceProcessHandle,
        IntPtr hSourceHandle,
        IntPtr hTargetProcessHandle,
        out IntPtr lpTargetHandle,
        uint dwDesiredAccess,
        bool bInheritHandle,
        uint dwOptions);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);
}
