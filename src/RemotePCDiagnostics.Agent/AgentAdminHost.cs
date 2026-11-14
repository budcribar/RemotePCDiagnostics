using System.Diagnostics;
using System.Runtime.InteropServices;
using RemotePCDiagnostics.Agent.Core;
using Microsoft.Extensions.Logging;
using RemotePCDiagnostics.Core.Logging;
using RemotePCDiagnostics.Logging;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Agent;

internal static class AgentAdminHost
{
    public const int ExitOk = 0;
    public const int ExitError = 1;
    public const int ExitFatal = 1;

    private const string AllowTestParentEnvVar = "RPD_ADMIN_ALLOW_TEST_PARENT";

    public static async Task<int> RunLauncherModeAsync(AgentArgs args)
    {
        // 1. Elevate if on Windows and not elevated
        if (OperatingSystem.IsWindows() && !Environment.IsPrivilegedProcess && !ElevationService.IsSimulateStandardUser())
        {
            var exe = Environment.ProcessPath ?? Path.Combine(AppContext.BaseDirectory, "RemotePCDiagnostics.Agent.exe");
            if (File.Exists(exe))
            {
                var forwarded = (args.ForwardedArgs ?? []).ToList();
                if (!forwarded.Any(a => string.Equals(a, "--launch", StringComparison.OrdinalIgnoreCase)))
                    forwarded.Insert(0, "--launch");

                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = exe,
                        Arguments = WindowsCommandLine.Join(forwarded),
                        UseShellExecute = true,
                        Verb = "runas",
                        WorkingDirectory = AppContext.BaseDirectory,
                    };
                    using var proc = Process.Start(psi);
                    if (proc is not null)
                    {
                        await proc.WaitForExitAsync().ConfigureAwait(false);
                        return proc.ExitCode;
                    }
                }
                catch (System.ComponentModel.Win32Exception)
                {
                    // User declined UAC prompt
                    return ExitOk;
                }
            }
        }

        // 2. Locate RemotePCDiagnostics.Host
        var hostExe = Path.Combine(AppContext.BaseDirectory, "RemotePCDiagnostics.Host.exe");
        var hostDll = Path.Combine(AppContext.BaseDirectory, "RemotePCDiagnostics.Host.dll");
        var useDotnet = !File.Exists(hostExe) && File.Exists(hostDll);
        if (!File.Exists(hostExe) && !useDotnet)
        {
            Console.Error.WriteLine($"Could not find RemotePCDiagnostics.Host at '{hostExe}'.");
            return ExitError;
        }

        // 3. Create unique pipe name
        var pipeName = $"rpd-admin-{Guid.NewGuid():N}";
        var log = CreateFileLogger("RemotePCDiagnostics.Agent.Launcher.log");

        // 4. Start elevated background worker hosting AdminPipeServer
        using var workerCts = new CancellationTokenSource();
        IDisposable? sensorProvider = null;
        Func<CancellationToken, Task<SensorSnapshot?>>? sensorReader = null;
        if (OperatingSystem.IsWindows())
        {
            sensorProvider = CreateWindowsSensorProvider(log, out sensorReader);
        }

        using (sensorProvider)
        {
            var serverOptions = new AdminPipeServerOptions
            {
                PipeName = pipeName,
                ExpectedClientExePath = useDotnet ? null : hostExe,
                ConnectTimeout = TimeSpan.FromSeconds(60),
            };

            var server = new AdminPipeServer(
                serverOptions,
                new SystemProcessLauncher(),
                sensorReader: sensorReader,
                log: log);

        var serverTask = Task.Run(async () =>
        {
            try
            {
                await server.RunSingleSessionAsync(workerCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                log.Warn($"[agent-launcher] Admin pipe server ended: {ex.Message}");
            }
            finally
            {
                server.Dispose();
            }
        });

        // 5. Launch RemotePCDiagnostics.Host
        var hostArgs = new List<string>();
        if (args.ForwardedArgs is not null)
        {
            foreach (var a in args.ForwardedArgs)
            {
                if (!string.Equals(a, "--launch", StringComparison.OrdinalIgnoreCase))
                    hostArgs.Add(a);
            }
        }
        hostArgs.Add($"{ElevationService.AdminPipeArgPrefix}{pipeName}");

        ProcessStartInfo startInfo;
        if (useDotnet)
        {
            startInfo = new ProcessStartInfo("dotnet")
            {
                WorkingDirectory = AppContext.BaseDirectory,
                UseShellExecute = false,
            };
            startInfo.ArgumentList.Add(hostDll);
            foreach (var a in hostArgs) startInfo.ArgumentList.Add(a);
        }
        else
        {
            startInfo = new ProcessStartInfo(hostExe)
            {
                WorkingDirectory = AppContext.BaseDirectory,
                UseShellExecute = false,
            };
            foreach (var a in hostArgs) startInfo.ArgumentList.Add(a);
        }
        startInfo.EnvironmentVariables[ElevationService.AdminPipeEnvVar] = pipeName;

        Process? hostProcess;
        try
        {
            hostProcess = Process.Start(startInfo);
        }
        catch (Exception ex)
        {
            log.Error($"[agent-launcher] Failed to start Host process: {ex.Message}");
            workerCts.Cancel();
            return ExitError;
        }

        if (hostProcess is null)
        {
            workerCts.Cancel();
            return ExitError;
        }

        using (hostProcess)
        {
            serverOptions.ExpectedClientPid = hostProcess.Id;
            log.Info($"[agent-launcher] Host started (pid={hostProcess.Id}); monitoring lifetime...");

            // 6. Monitor PID and exit when Host exits
            await hostProcess.WaitForExitAsync().ConfigureAwait(false);
            var exitCode = hostProcess.ExitCode;
            log.Info($"[agent-launcher] Host exited with code {exitCode}. Stopping background worker...");

            workerCts.Cancel();
            try { await serverTask.ConfigureAwait(false); } catch { }

            return exitCode;
        }
    }
    }

    public static async Task<int> RunHelperModeAsync(AgentArgs args)
    {
        var parentPid = args.ParentPid;
        var pipeName = args.PipeName ?? "";
        var clientSid = args.ClientSid;

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
            return ExitOk;
        }

        using (parent)
        {
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

            var log = CreateFileLogger("RemotePCDiagnostics.Agent.Admin.log");
            IDisposable? sensorProvider = null;
            Func<CancellationToken, Task<SensorSnapshot?>>? sensorReader = null;
            if (OperatingSystem.IsWindows())
            {
                sensorProvider = CreateWindowsSensorProvider(log, out sensorReader);
            }

            using (sensorProvider)
            {
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
                        sensorReader: sensorReader,
                        log: log);

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
    }

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private static IDisposable? CreateWindowsSensorProvider(ILogger log, out Func<CancellationToken, Task<SensorSnapshot?>>? reader)
    {
        var ecFan = LenovoEcFanSource.Create(log);
        var provider = new LhmSensorProvider(ecFan, logger: log);
        reader = ct => Task.FromResult<SensorSnapshot?>(provider.Read());
        return provider;
    }

    private static ILogger CreateFileLogger(string fileName)
    {
        var logPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "RemotePCDiagnostics",
            "logs",
            fileName);
        var fileLog = new RollingFileLog(logPath);
        var loggerFactory = AppLoggerFactory.From(line =>
            fileLog.Write($"{DateTimeOffset.Now:O} [pid={Environment.ProcessId}] {line}"));
        return loggerFactory.CreateLogger(typeof(AgentAdminHost).FullName!);
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
