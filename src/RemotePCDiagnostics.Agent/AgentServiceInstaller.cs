using System.Diagnostics;
using System.ServiceProcess;
using RemotePCDiagnostics.Agent.Core;

namespace RemotePCDiagnostics.Agent;

/// <summary>
/// Windows Service host (<see cref="ServiceBase"/>) and CLI handlers for <c>status</c>, <c>install</c>, and <c>uninstall</c>.
/// </summary>
internal static class AgentServiceInstaller
{
    public const int ExitOk = 0;
    public const int ExitError = 1;
    public const int ExitAccessDenied = 5;

    public static int RunStatus()
    {
        var configPath = AgentPaths.ConfigPath();
        var config = AgentPaths.TryLoadConfig(out var configError);
        var serviceStatus = QueryServiceStatusText();
        var cachedApp = AgentPaths.GetInstalledOrCachedAppVersion();

        Console.WriteLine($"Service:     {AgentPaths.ServiceName} ({serviceStatus})");
        if (config is not null)
        {
            Console.WriteLine($"Config:      {configPath}");
            Console.WriteLine($"Server:      {config.Server}");
            Console.WriteLine($"Machine ID:  {config.MachineId}");
            Console.WriteLine($"Consent:     {config.Consent}");
            Console.WriteLine($"Lifetime:    {config.Lifetime}");
            Console.WriteLine($"Key:         {(string.IsNullOrEmpty(config.Key) ? "(none)" : "configured")}");
        }
        else if (configError is not null)
        {
            Console.WriteLine($"Config:      {configError}");
        }
        else
        {
            Console.WriteLine($"Config:      {configPath} (not installed)");
        }
        Console.WriteLine($"App Cache:   {(string.IsNullOrEmpty(cachedApp) ? "(none)" : cachedApp)}");
        return ExitOk;
    }

    public static int RunInstall(AgentArgs args, IReadOnlyList<string> rawArgs)
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("The Remote PC Diagnostics agent Windows Service can only be installed on Windows.");
            return ExitError;
        }

        if (!Environment.IsPrivilegedProcess)
        {
            return TryRelaunchElevatedOrFail(rawArgs, "install");
        }

        try
        {
            var existing = AgentPaths.TryLoadConfig(out _);
            var merged = AgentConfig.ForInstall(existing, args, Guid.NewGuid());
            if (args.FromMsi && string.IsNullOrWhiteSpace(merged.Key))
            {
                Console.Error.WriteLine(
                    "No enrollment key was provided. Download the pre-configured MSI installer from your Remote PC Diagnostics portal, " +
                    "or run msiexec /i <package.msi> ENROLLMENT_KEY=<your_key>.");
                return PauseIfRequested(args, ExitError);
            }
            AgentPaths.WriteSecuredConfig(merged);

            // Stop any running instance first so the installed binary can be updated cleanly.
            StopServiceIfRunning(TimeSpan.FromSeconds(15));

            var currentExe = Environment.ProcessPath
                ?? throw new InvalidOperationException("Cannot determine the current agent executable path.");
            var targetDir = AgentPaths.DefaultInstallDir();
            var targetExe = AgentPaths.DefaultInstalledAgentExe();
            Directory.CreateDirectory(targetDir);

            if (!PathsEqual(currentExe, targetExe))
            {
                CopyAgentDeployment(currentExe, targetDir, targetExe);
            }

            var binPathValue = $"\"{targetExe}\" run";
            if (!ServiceExists())
            {
                var (createCode, createOut) = RunSc($"create {AgentPaths.ServiceName} binPath= \"{EscapeForSc(binPathValue)}\" start= auto DisplayName= \"{AgentPaths.ServiceDisplayName}\"");
                if (createCode != 0)
                    throw new InvalidOperationException($"sc.exe create failed ({createCode}): {createOut}");
            }
            else
            {
                var (cfgCode, cfgOut) = RunSc($"config {AgentPaths.ServiceName} binPath= \"{EscapeForSc(binPathValue)}\" start= auto DisplayName= \"{AgentPaths.ServiceDisplayName}\"");
                if (cfgCode != 0)
                    throw new InvalidOperationException($"sc.exe config failed ({cfgCode}): {cfgOut}");
            }

            RunSc($"description {AgentPaths.ServiceName} \"{AgentPaths.ServiceDescription}\"");
            RunSc($"failure {AgentPaths.ServiceName} reset= 86400 actions= restart/5000/restart/15000/restart/60000");

            StartServiceAndWait(TimeSpan.FromSeconds(15));

            Console.WriteLine($"Installed and started '{AgentPaths.ServiceName}'.");
            Console.WriteLine($"  Executable: {targetExe}");
            Console.WriteLine($"  Config:     {AgentPaths.ConfigPath()}");
            Console.WriteLine($"  Server:     {merged.Server}");
            Console.WriteLine($"  Machine ID: {merged.MachineId}");
            Console.WriteLine($"  Consent:    {merged.Consent}");
            Console.WriteLine($"  Lifetime:   {merged.Lifetime}");
            return PauseIfRequested(args, ExitOk);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Agent installation failed: {ex.Message}");
            return PauseIfRequested(args, ExitError);
        }
    }

    public static int RunUninstall(AgentArgs args, IReadOnlyList<string> rawArgs)
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("The Remote PC Diagnostics agent Windows Service can only be uninstalled on Windows.");
            return ExitError;
        }

        if (!Environment.IsPrivilegedProcess)
        {
            return TryRelaunchElevatedOrFail(rawArgs, "uninstall");
        }

        try
        {
            if (ServiceExists())
            {
                StopServiceIfRunning(TimeSpan.FromSeconds(15));
                var (delCode, delOut) = RunSc($"delete {AgentPaths.ServiceName}");
                if (delCode != 0 && ServiceExists())
                    throw new InvalidOperationException($"sc.exe delete failed ({delCode}): {delOut}");
                Console.WriteLine($"Stopped and removed Windows Service '{AgentPaths.ServiceName}'.");
            }
            else
            {
                Console.WriteLine($"Windows Service '{AgentPaths.ServiceName}' is not installed.");
            }

            var cfgPath = AgentPaths.ConfigPath();
            if (File.Exists(cfgPath))
            {
                try
                {
                    File.Delete(cfgPath);
                    Console.WriteLine($"Removed '{cfgPath}'.");
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Note: could not delete '{cfgPath}': {ex.Message}");
                }
            }

            return PauseIfRequested(args, ExitOk);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Agent uninstall failed: {ex.Message}");
            return PauseIfRequested(args, ExitError);
        }
    }

    /// <summary>
    /// Removes <c>agent.json</c>, cached app downloads, and the Windows Service after a one-shot <c>--lifetime=session</c> run.
    /// Never touches the user/system change journal so any applied fixes remain undoable later.
    /// </summary>
    public static void CleanupPerSessionAgentBestEffort()
    {
        try
        {
            var cfg = AgentPaths.ConfigPath();
            if (File.Exists(cfg))
                File.Delete(cfg);
        }
        catch { }

        try
        {
            var appRoot = AgentPaths.AppCacheRootDir();
            if (Directory.Exists(appRoot))
                Directory.Delete(appRoot, recursive: true);
        }
        catch { }

        if (OperatingSystem.IsWindows())
        {
            try
            {
                RunSc($"delete {AgentPaths.ServiceName}");
            }
            catch { }
        }
    }

    public static string QueryServiceStatusText()
    {
        if (!OperatingSystem.IsWindows())
            return "Not supported on non-Windows OS";

        try
        {
            using var sc = new ServiceController(AgentPaths.ServiceName);
            return sc.Status.ToString();
        }
        catch (InvalidOperationException)
        {
            return "Not installed";
        }
        catch (Exception ex)
        {
            return $"Unavailable ({ex.Message})";
        }
    }

    private static bool ServiceExists()
    {
        if (!OperatingSystem.IsWindows())
            return false;

        try
        {
            using var sc = new ServiceController(AgentPaths.ServiceName);
            _ = sc.Status;
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static void StopServiceIfRunning(TimeSpan timeout)
    {
        if (!ServiceExists())
            return;

        try
        {
            using var sc = new ServiceController(AgentPaths.ServiceName);
            if (sc.Status is not (ServiceControllerStatus.Stopped or ServiceControllerStatus.StopPending))
            {
                sc.Stop();
            }
            sc.WaitForStatus(ServiceControllerStatus.Stopped, timeout);
        }
        catch
        {
            // Ignore timeout/already stopped.
        }
    }

    private static void StartServiceAndWait(TimeSpan timeout)
    {
        using var sc = new ServiceController(AgentPaths.ServiceName);
        if (sc.Status == ServiceControllerStatus.Stopped)
        {
            sc.Start();
        }
        sc.WaitForStatus(ServiceControllerStatus.Running, timeout);
    }

    private static void CopyAgentDeployment(string currentExe, string targetDir, string targetExe)
    {
        var sourceDir = Path.GetDirectoryName(currentExe) ?? AppContext.BaseDirectory;
        var runtimeConfig = Path.Combine(sourceDir, "RemotePCDiagnostics.Agent.runtimeconfig.json");
        if (File.Exists(runtimeConfig))
        {
            // Framework-dependent / multi-file build: copy companion files in the same folder.
            foreach (var file in Directory.GetFiles(sourceDir))
            {
                var dest = Path.Combine(targetDir, Path.GetFileName(file));
                File.Copy(file, dest, overwrite: true);
            }
        }
        else
        {
            // Single-file published executable.
            File.Copy(currentExe, targetExe, overwrite: true);
        }
    }

    private static int TryRelaunchElevatedOrFail(IReadOnlyList<string> rawArgs, string verbName)
    {
        if (Environment.UserInteractive && !Console.IsInputRedirected)
        {
            var exe = Environment.ProcessPath;
            if (!string.IsNullOrWhiteSpace(exe) && File.Exists(exe))
            {
                var forwarded = rawArgs.ToList();
                if (!forwarded.Any(a => string.Equals(a, "--pause", StringComparison.OrdinalIgnoreCase)))
                    forwarded.Add("--pause");

                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = exe,
                        Arguments = WindowsCommandLine.Join(forwarded),
                        UseShellExecute = true,
                        Verb = "runas",
                    };
                    using var proc = Process.Start(psi);
                    if (proc is not null)
                    {
                        proc.WaitForExit();
                        return proc.ExitCode;
                    }
                }
                catch
                {
                    // UAC prompt declined or unavailable in non-GUI console.
                }
            }
        }

        Console.Error.WriteLine($"Administrator rights are required to {verbName} the Remote PC Diagnostics agent. Run from an elevated prompt or RMM.");
        return ExitAccessDenied;
    }

    private static int PauseIfRequested(AgentArgs args, int exitCode)
    {
        if (args.Pause && Environment.UserInteractive && !Console.IsInputRedirected)
        {
            Console.WriteLine();
            Console.Write("Press any key to close...");
            try { Console.ReadKey(intercept: true); } catch { }
            Console.WriteLine();
        }
        return exitCode;
    }

    private static bool PathsEqual(string a, string b) =>
        string.Equals(Path.GetFullPath(a).TrimEnd('\\', '/'), Path.GetFullPath(b).TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase);

    private static string EscapeForSc(string value) => value.Replace("\"", "\\\"");

    private static (int ExitCode, string Output) RunSc(string arguments)
    {
        var scExe = Path.Combine(Environment.SystemDirectory, "sc.exe");
        if (!File.Exists(scExe))
            scExe = "sc.exe";

        var psi = new ProcessStartInfo
        {
            FileName = scExe,
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        using var proc = Process.Start(psi) ?? throw new InvalidOperationException("Failed to start sc.exe.");
        var stdout = proc.StandardOutput.ReadToEnd();
        var stderr = proc.StandardError.ReadToEnd();
        proc.WaitForExit(30_000);
        var combined = (stdout + "\n" + stderr).Trim();
        return (proc.ExitCode, combined);
    }
}

/// <summary>
/// <see cref="ServiceBase"/> adapter when <c>RemotePCDiagnostics.Agent.exe run</c> is started by the Windows Service Control Manager.
/// </summary>
internal sealed class AgentWindowsService : ServiceBase
{
    private readonly AgentConfig _config;
    private CancellationTokenSource? _cts;
    private Task? _workerTask;
    private WindowsAgentPlatform? _platform;

    public AgentWindowsService(AgentConfig config)
    {
        _config = config;
        ServiceName = AgentPaths.ServiceName;
        CanStop = true;
        CanShutdown = true;
        AutoLog = false;
    }

    protected override void OnStart(string[] args)
    {
        _cts = new CancellationTokenSource();
        _platform = new WindowsAgentPlatform();
        var logFile = Path.Combine(AgentPaths.ProgramDataDir(), "logs", "RemotePCDiagnostics.Agent.log");
        var worker = new AgentHubWorker(_config, _platform, new AgentSessionOptions
        {
            Log = line => AppendLogLineSafe(logFile, line),
        });

        _workerTask = Task.Run(async () =>
        {
            try
            {
                await worker.RunLoopAsync(_cts.Token).ConfigureAwait(false);
            }
            finally
            {
                // If per-session lifetime ended naturally, tell SCM the service has stopped cleanly.
                if (!_cts.IsCancellationRequested)
                {
                    try { Stop(); } catch { }
                }
            }
        });
    }

    protected override void OnStop() => StopWorker();

    protected override void OnShutdown() => StopWorker();

    private void StopWorker()
    {
        try { _cts?.Cancel(); } catch { }
        if (_workerTask is not null)
        {
            try { _workerTask.Wait(TimeSpan.FromSeconds(10)); } catch { }
        }
        _platform?.Dispose();
        _cts?.Dispose();
    }

    internal static void AppendLogLineSafe(string logFile, string line)
    {
        try
        {
            var dir = Path.GetDirectoryName(logFile);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);
            File.AppendAllText(logFile, line + Environment.NewLine);
        }
        catch
        {
            // Logging must never crash the service.
        }
    }
}
