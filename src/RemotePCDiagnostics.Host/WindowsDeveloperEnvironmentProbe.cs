using System.IO;
using System.Security.Principal;
using Microsoft.Win32;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Benchmarks;
using RemotePCDiagnostics.Core.Optimizations;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Host;

/// <summary>Windows implementation of <see cref="IDeveloperEnvironmentProbe"/> for the Developer setup check and developer benchmarks.</summary>
internal sealed class WindowsDeveloperEnvironmentProbe(
    SystemCommandRunner commands,
    IMachineTweaks machineTweaks,
    IElevatedCommandBridge? bridge,
    Func<BenchmarkConditions> readConditions,
    ILogger? log = null) : IDeveloperEnvironmentProbe
{
    private readonly DeveloperToolchainDetector _detector = new();

    public bool IsAgentConnected => bridge is { IsConnected: true };

    public Task<IReadOnlyList<DetectedToolchain>> DetectToolchainsAsync(CancellationToken ct = default) =>
        _detector.DetectAllAsync(ct);

    public string? FindHyperfine() => _detector.FindHyperfine();

    public double? ReadTempVolumeFreeGb()
    {
        try
        {
            var root = Path.GetPathRoot(Path.GetTempPath());
            if (string.IsNullOrWhiteSpace(root)) return null;
            return Math.Round(new DriveInfo(root).AvailableFreeSpace / (double)(1L << 30), 1);
        }
        catch (Exception ex)
        {
            log.Info("[dev-env] free space: " + ex.Message);
            return null;
        }
    }

    public async Task<DevDriveVolumeStatus> QueryDevDriveAsync(string? driveLetter = null, CancellationToken ct = default)
    {
        var (build, ubr) = ReadWindowsBuild();
        var capable = DeveloperToolchainDetector.IsWindows11DevDriveCapable(build, ubr);
        if (!capable)
            return DeveloperToolchainDetector.ParseFsutilDevDriveQuery(1, null, isWindows11Capable: false);

        try
        {
            var drive = !string.IsNullOrWhiteSpace(driveLetter)
                ? driveLetter.TrimEnd(':', '\\') + ":"
                : (Path.GetPathRoot(Path.GetTempPath()) ?? @"C:\").TrimEnd('\\');
            var fsutil = SystemCommandRunner.SystemTool("fsutil.exe");
            var r = await commands.RunAsync(fsutil, ["devdrv", "query", drive], ct).ConfigureAwait(false);
            if (r is not null)
            {
                var text = string.IsNullOrWhiteSpace(r.StdOut) ? r.StdErr : r.StdOut;
                var parsed = DeveloperToolchainDetector.ParseFsutilDevDriveQuery(r.ExitCode, text, isWindows11Capable: true);
                if (parsed.IsDevDrive || r.ExitCode == 0)
                    return parsed;
                // fsutil devdrv query requires administrator privileges; fall back to ReFS check when un-elevated.
                if (TryIsRefsDrive(drive))
                    return new(true, true, true, null, $"ReFS Dev Drive volume ({drive})");
                return parsed;
            }
            if (TryIsRefsDrive(drive))
                return new(true, true, true, null, $"ReFS Dev Drive volume ({drive})");
            return new(true, false, false, null, "Could not query Dev Drive status.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.Info("[dev-env] fsutil devdrv query: " + ex.Message);
            return new(true, false, false, null, "Could not query Dev Drive status.");
        }
    }

    private static bool TryIsRefsDrive(string drive)
    {
        try
        {
            var root = drive.TrimEnd('\\') + "\\";
            var info = new DriveInfo(root);
            return info.IsReady && info.DriveFormat.Contains("ReFS", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    public async Task<DefenderProbe.Status?> ReadDefenderAsync(CancellationToken ct = default)
    {
        try
        {
            var json = await machineTweaks.ReadDefenderAsync(ct).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(json))
                return DefenderProbe.Parse(json);

            // Fallback non-admin read (returns real-time state, with "N/A" for exclusions)
            var fallbackJson = await Task.Run(RemotePCDiagnostics.Core.Platform.WindowsDefenderWmi.ReadStatusJson, ct).ConfigureAwait(false);
            return DefenderProbe.Parse(fallbackJson);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.Info("[dev-env] defender read: " + ex.Message);
            return null;
        }
    }

    public BenchmarkConditions ReadConditions() => readConditions();

    public (string? CpuName, int CoreCount) ReadCpuInfo()
    {
        string? name = null;
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0");
            name = (key?.GetValue("ProcessorNameString") as string)?.Trim();
        }
        catch { }
        return (name, Environment.ProcessorCount);
    }

    public (int Build, int Ubr) ReadWindowsBuild()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            var buildStr = key?.GetValue("CurrentBuildNumber") as string;
            var ubrObj = key?.GetValue("UBR");
            var build = int.TryParse(buildStr, out var b) ? b : Environment.OSVersion.Version.Build;
            var ubr = ubrObj is int u ? u : 0;
            return (build, ubr);
        }
        catch
        {
            return (Environment.OSVersion.Version.Build, 0);
        }
    }

    public string? ReadCurrentUserSid()
    {
        try { return WindowsIdentity.GetCurrent().User?.Value; }
        catch { return null; }
    }
}

/// <summary>Reads and appends anonymous developer benchmark samples in <c>dev-benchmarks.json</c> through the Agent.</summary>
internal sealed class AgentDeveloperSampleStore(IElevatedCommandBridge bridge, ILogger? log = null) : IDeveloperSampleStore
{
    private readonly AgentStateFile _file = new(bridge, ProtectedState.DevBenchmarksFile, FileDeveloperSampleStore.DefaultPath(), log);

    public DeveloperSampleHistory Load() =>
        DeveloperSampleHistory.FromJson(_file.Read()) ?? new(DeveloperSampleHistory.CurrentSchemaVersion, []);

    public void Append(DeveloperBenchmarkSample sample)
    {
        var current = Load();
        var list = current.Samples.Concat([sample]).TakeLast(DeveloperSampleHistory.MaxStoredSamples).ToList();
        _file.Write(new DeveloperSampleHistory(DeveloperSampleHistory.CurrentSchemaVersion, list).ToJson());
    }
}
