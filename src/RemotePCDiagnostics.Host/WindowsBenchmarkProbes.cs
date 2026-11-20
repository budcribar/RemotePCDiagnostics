using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Benchmarks;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Stress;

namespace RemotePCDiagnostics.Host;

/// <summary>
/// Windows measurements for the before/after benchmarks. Only Windows' own programs are started (and closed again);
/// counters use English names (PDH), so they work on any Windows language.
/// </summary>
public sealed class WindowsBenchmarkProbes(SystemCommandRunner commands, ISensorProvider? sensors, ILogger? log = null) : IBenchmarkProbes
{
    private void Log(string m) => log.Info("[benchmark] " + m);

    // ---- conditions ----
    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_POWER_STATUS { public byte ACLineStatus, BatteryFlag, BatteryLifePercent, SystemStatusFlag; public int BatteryLifeTime, BatteryFullLifeTime; }
    [DllImport("kernel32.dll")] private static extern bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS s);

    public BenchmarkConditions ReadConditions()
    {
        bool? battery = null;
        try { if (GetSystemPowerStatus(out var s)) battery = s.ACLineStatus switch { 0 => true, 1 => false, _ => null }; } catch (Exception ex) { Log("power status: " + ex.Message); }
        double? cpu = null;
        try
        {
            cpu = sensors?.Read().Readings
                .Where(r => r.SensorType == SensorKind.Temperature && r.HardwareType == HardwareKind.Cpu && r.IsLive)
                .Select(r => r.Value).DefaultIfEmpty().Max();
        }
        catch (Exception ex) { Log("cpu temp: " + ex.Message); }
        return new(battery, cpu, ReadPowerPlan());
    }

    /// <summary>Active power plan name from "powercfg /getactivescheme" ("... (Balanced)").</summary>
    private string? ReadPowerPlan()
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "powercfg.exe"), "/getactivescheme")
                { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true })!;
            var text = p.StandardOutput.ReadToEnd();
            p.WaitForExit(5000);
            int a = text.LastIndexOf('('), b = text.LastIndexOf(')');
            return a >= 0 && b > a ? text[(a + 1)..b].Trim() : null;
        }
        catch (Exception ex) { Log("power plan: " + ex.Message); return null; }
    }

    // ---- idle CPU + paging (PDH, English counter names) ----
    [StructLayout(LayoutKind.Explicit)]
    private struct PDH_FMT_COUNTERVALUE { [FieldOffset(0)] public uint CStatus; [FieldOffset(8)] public double doubleValue; }
    private const uint PDH_FMT_DOUBLE = 0x00000200, PDH_FMT_NOCAP100 = 0x00008000;
    [DllImport("pdh.dll", CharSet = CharSet.Unicode)] private static extern uint PdhOpenQuery(string? source, IntPtr user, out IntPtr query);
    [DllImport("pdh.dll", CharSet = CharSet.Unicode, EntryPoint = "PdhAddEnglishCounterW")] private static extern uint PdhAddEnglishCounter(IntPtr query, string path, IntPtr user, out IntPtr counter);
    [DllImport("pdh.dll")] private static extern uint PdhCollectQueryData(IntPtr query);
    [DllImport("pdh.dll")] private static extern uint PdhGetFormattedCounterValue(IntPtr counter, uint format, out uint type, out PDH_FMT_COUNTERVALUE value);
    [DllImport("pdh.dll")] private static extern uint PdhCloseQuery(IntPtr query);

    public async Task<IdleSample?> SampleIdleAsync(TimeSpan duration, CancellationToken ct)
    {
        if (PdhOpenQuery(null, IntPtr.Zero, out var q) != 0) throw new InvalidOperationException("PdhOpenQuery failed");
        try
        {
            if (PdhAddEnglishCounter(q, @"\Processor(_Total)\% Processor Time", IntPtr.Zero, out var cpu) != 0) throw new InvalidOperationException("CPU counter unavailable");
            if (PdhAddEnglishCounter(q, @"\Memory\Pages/sec", IntPtr.Zero, out var pages) != 0) throw new InvalidOperationException("Paging counter unavailable");
            PdhCollectQueryData(q); // first sample primes rate counters
            var c = new List<double>(); var p = new List<double>();
            var end = DateTime.UtcNow + duration;
            while (DateTime.UtcNow < end)
            {
                await Task.Delay(1000, ct).ConfigureAwait(false);
                if (PdhCollectQueryData(q) != 0) continue;
                if (PdhGetFormattedCounterValue(cpu, PDH_FMT_DOUBLE, out _, out var cv) == 0 && cv.CStatus == 0) c.Add(cv.doubleValue);
                if (PdhGetFormattedCounterValue(pages, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, out _, out var pv) == 0 && pv.CStatus == 0) p.Add(pv.doubleValue);
            }
            Log($"idle: {c.Count} samples cpu={(c.Count > 0 ? c.Average() : double.NaN):0.0}% pages={(p.Count > 0 ? p.Average() : double.NaN):0}/s");
            return c.Count == 0 || p.Count == 0 ? null : new IdleSample(c.Average(), p.Average());
        }
        finally { PdhCloseQuery(q); }
    }

    // ---- program start ----
    public async Task<double?> StartProgramAsync(BuiltInProgram program, CancellationToken ct)
    {
        var path = Path.Combine(Environment.SystemDirectory, program.FileName);
        if (!File.Exists(path)) { Log($"{program.Name}: not found at {path}"); return null; }
        var psi = new ProcessStartInfo(path) { UseShellExecute = false, CreateNoWindow = !program.HasWindow };
        foreach (var a in program.Arguments) psi.ArgumentList.Add(a);
        var sw = Stopwatch.StartNew();
        using var p = Process.Start(psi);
        if (p is null) return null;
        try
        {
            if (program.HasWindow)
            {
                var ready = await Task.Run(() => p.WaitForInputIdle(15_000), ct).ConfigureAwait(false);
                var ms = sw.Elapsed.TotalMilliseconds;
                return ready ? ms : null;
            }
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(20));
            await p.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            return sw.Elapsed.TotalMilliseconds;
        }
        finally
        {
            // Close what we opened: politely first, then make sure.
            try
            {
                if (!p.HasExited)
                {
                    p.CloseMainWindow();
                    if (!p.WaitForExit(2000)) p.Kill(entireProcessTree: true);
                }
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception) { }
        }
    }

    // ---- disk ----
    public async Task<double?> DiskRandomReadIopsAsync(TimeSpan duration, CancellationToken ct)
    {
        var test = new DiskSpeedTest(new PhysicalDiskTestFileSystem(log), sensors ?? new NoSensors(), log: log);
        var r = await test.RunAsync(new DiskSpeedOptions
        {
            Duration = duration, RequestedSizeBytes = 256 * DiskSpeedOptions.MB, MaxRandomPhase = TimeSpan.FromSeconds(Math.Max(2, duration.TotalSeconds / 3)),
        }, null, ct).ConfigureAwait(false);
        Log($"disk: outcome={r.Outcome} randomRead={r.RandomReadIops:0} IOPS");
        return r.RandomReadIops;
    }

    private sealed class NoSensors : ISensorProvider
    {
        public RemotePCDiagnostics.Core.ModuleAvailability CheckAvailability() => RemotePCDiagnostics.Core.ModuleAvailability.Unavailable("no sensors");
        public SensorSnapshot Read() => new([], false);
    }

    // ---- boot ----
    // Only an administrator can read the Diagnostics-Performance log, so the Agent reads it (wevtutil qe, the one wevtutil use it allows).
    // Without the Agent nothing is run here: the app never has administrator rights, and the result says to turn on Admin Repair Mode.
    public async Task<IReadOnlyList<WinEvent>> ReadBootEventsAsync(CancellationToken ct)
    {
        if (!commands.HasAdminRights)
            throw new RemotePCDiagnostics.Core.Session.AdminRequiredException(BenchmarkRunner.BootLogUnreadable);
        return await new WindowsEventLog(commands).QueryAsync(BootRecord.Channel, BootRecord.Query, 20, ct).ConfigureAwait(false)
            ?? throw new RemotePCDiagnostics.Core.Session.AdminRequiredException(BenchmarkRunner.BootLogUnreadable);
    }

    // ---- idle resources: memory in use + background processes (sampled several times) ----
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32W
    {
        public uint dwSize, cntUsage, th32ProcessID; public IntPtr th32DefaultHeapID; public uint th32ModuleID, cntThreads, th32ParentProcessID;
        public int pcPriClassBase; public uint dwFlags; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
    }
    private const uint TH32CS_SNAPPROCESS = 0x2;
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool Process32FirstW(IntPtr snapshot, ref PROCESSENTRY32W entry);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool Process32NextW(IntPtr snapshot, ref PROCESSENTRY32W entry);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);

    /// <summary>Every process with its parent (Toolhelp snapshot: no access rights needed, unlike reading each process).</summary>
    private static List<ProcessRow> ReadProcessRows()
    {
        var snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == new IntPtr(-1)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            var rows = new List<ProcessRow>();
            var e = new PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32W>() };
            for (var ok = Process32FirstW(snap, ref e); ok; ok = Process32NextW(snap, ref e))
                rows.Add(new((int)e.th32ProcessID, (int)e.th32ParentProcessID, e.szExeFile ?? ""));
            return rows;
        }
        finally { CloseHandle(snap); }
    }

    public Task<IdleResourceSample?> ReadIdleResourcesAsync(CancellationToken ct)
    {
        double? memUsedMb = null;
        try { memUsedMb = Math.Round(new WindowsMemorySystem(null, log).ReadMemory().UsedBytes / (double)(1L << 20), 0); } catch (Exception ex) { Log("memUsed: " + ex.Message); }

        int? bgProcs = null;
        try
        {
            var rows = ReadProcessRows();
            bgProcs = BackgroundProcessCount.Count(rows, Environment.ProcessId);
            Log($"bgProcs: {bgProcs} of {rows.Count} running (this app, its child processes and the benchmark's own programs not counted)");
        }
        catch (Exception ex) { Log("bgProcs: " + ex.Message); }

        return Task.FromResult<IdleResourceSample?>(memUsedMb is null && bgProcs is null ? null : new(memUsedMb, bgProcs));
    }

    // ---- disk space & bloatware inventory snapshot ----
    public async Task<SystemResourceSnapshot?> ReadResourceSnapshotAsync(CancellationToken ct)
    {
        var memSys = new WindowsMemorySystem(null, log);
        double? diskFreeGb = null;
        try
        {
            var root = Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\";
            diskFreeGb = Math.Round(new DriveInfo(root).AvailableFreeSpace / (double)(1L << 30), 1);
        }
        catch (Exception ex) { Log("diskFree: " + ex.Message); }

        int? startupCount = null, autoSvcCount = null, taskCount = null, bloatCount = null;
        try
        {
            ct.ThrowIfCancellationRequested();
            startupCount = memSys.ReadEnabledStartupCount();
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { Log("startupCount: " + ex.Message); }

        try
        {
            var inventory = await InventoryProbe.ReadAsync(commands, ct).ConfigureAwait(false);
            autoSvcCount = inventory.AutoVendorServices;
            taskCount = inventory.ActiveScheduledTasks;
            bloatCount = inventory.InstalledBloatwareApps;
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { Log("inventory script: " + ex.Message); }

        return new(diskFreeGb, startupCount, autoSvcCount, taskCount, bloatCount);
    }

    // ---- Speedometer 3 (headless Chromium over local loopback CDP) ----
    public async Task<SpeedometerResult?> RunSpeedometerAsync(TimeSpan timeout, CancellationToken ct)
    {
        SpeedometerProcessRunner.CleanupOrphanedProfiles();
        var browser = SelectDefaultChromiumBrowser();
        if (browser is null)
            return new(null, Note: "No supported Chromium browser (Edge, Chrome, Brave, or Opera) was found.");

        var (rootDir, error) = await SpeedometerPackage.EnsureAssetsAsync(
            expectedSha256: SpeedometerPackage.ExpectedSha256,
            ct: ct).ConfigureAwait(false);
        if (rootDir is null)
            return new(null, browser.Engine, browser.DisplayName, browser.Version, Note: error ?? "Speedometer 3 assets are not available.");

        return await SpeedometerProcessRunner.RunAsync(browser, rootDir, timeout, log, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Detects installed Chromium-family browsers RPCD can drive via CDP and prefers the user's
    /// Windows default HTTPS browser when it is one of them (falling back to Edge → Chrome → Brave → Opera).
    /// </summary>
    private static SpeedometerBrowser? SelectDefaultChromiumBrowser()
    {
        var installed = DetectInstalledChromiumBrowsers();
        if (installed.Count == 0) return null;

        var preferredEngine = ReadDefaultHttpsEngine();
        if (preferredEngine is not null)
        {
            var match = installed.FirstOrDefault(b => b.Engine.Equals(preferredEngine, StringComparison.OrdinalIgnoreCase));
            if (match is not null) return match;
        }
        return installed[0];
    }

    private static string? ReadDefaultHttpsEngine()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice");
            var progId = key?.GetValue("ProgId") as string;
            if (string.IsNullOrWhiteSpace(progId)) return null;
            if (progId.Contains("MSEdge", StringComparison.OrdinalIgnoreCase)) return "edge";
            if (progId.Contains("Chrome", StringComparison.OrdinalIgnoreCase)) return "chrome";
            if (progId.Contains("Brave", StringComparison.OrdinalIgnoreCase)) return "brave";
            if (progId.Contains("Opera", StringComparison.OrdinalIgnoreCase)) return "opera";
        }
        catch { }
        return null;
    }

    private static List<SpeedometerBrowser> DetectInstalledChromiumBrowsers()
    {
        var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var candidates = new (string Engine, string Name, string[] Paths)[]
        {
            ("edge", "Microsoft Edge", [
                Path.Combine(pf86, @"Microsoft\Edge\Application\msedge.exe"),
                Path.Combine(pf, @"Microsoft\Edge\Application\msedge.exe"),
            ]),
            ("chrome", "Google Chrome", [
                Path.Combine(pf, @"Google\Chrome\Application\chrome.exe"),
                Path.Combine(pf86, @"Google\Chrome\Application\chrome.exe"),
                Path.Combine(local, @"Google\Chrome\Application\chrome.exe"),
            ]),
            ("brave", "Brave", [
                Path.Combine(pf, @"BraveSoftware\Brave-Browser\Application\brave.exe"),
                Path.Combine(pf86, @"BraveSoftware\Brave-Browser\Application\brave.exe"),
                Path.Combine(local, @"BraveSoftware\Brave-Browser\Application\brave.exe"),
            ]),
            ("opera", "Opera", [
                Path.Combine(local, @"Programs\Opera\opera.exe"),
                Path.Combine(pf, @"Opera\opera.exe"),
            ]),
        };

        var result = new List<SpeedometerBrowser>();
        foreach (var (engine, name, paths) in candidates)
        {
            var exe = paths.FirstOrDefault(p => !string.IsNullOrEmpty(p) && File.Exists(p));
            if (exe is null) continue;
            string? ver = null;
            try { ver = FileVersionInfo.GetVersionInfo(exe).ProductVersion?.Split(' ')[0]; } catch { }
            result.Add(new(engine, name, exe, ver));
        }
        return result;
    }
}
