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
public sealed class WindowsBenchmarkProbes(SystemCommandRunner commands, ISensorProvider? sensors, Action<string>? log = null) : IBenchmarkProbes
{
    private void Log(string m) { try { log?.Invoke("[benchmark] " + m); } catch { } }

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
    public async Task<IReadOnlyList<WinEvent>> ReadBootEventsAsync(CancellationToken ct) =>
        await new WindowsEventLog(commands).QueryAsync(BootRecord.Channel, BootRecord.Query, 20, ct).ConfigureAwait(false)
        ?? throw new InvalidOperationException("Diagnostics-Performance log unavailable (administrator rights needed)");

    // ---- resource & bloatware inventory snapshot ----
    public async Task<SystemResourceSnapshot?> ReadResourceSnapshotAsync(CancellationToken ct)
    {
        var memSys = new WindowsMemorySystem(null, log);
        double? memUsedMb = null;
        try { memUsedMb = Math.Round(memSys.ReadMemory().UsedBytes / (double)(1L << 20), 0); } catch (Exception ex) { Log("memUsed: " + ex.Message); }

        int? bgProcs = null;
        try
        {
            var ps = Process.GetProcesses();
            bgProcs = ps.Length;
            foreach (var p in ps) p.Dispose();
        }
        catch (Exception ex) { Log("bgProcs: " + ex.Message); }

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
            var snap = await memSys.CaptureAsync([], ct).ConfigureAwait(false);
            startupCount = snap.Startup?.Count(e => e.Enabled);
        }
        catch (Exception ex) { Log("startupCount: " + ex.Message); }

        try
        {
            const string script =
                "$ErrorActionPreference='SilentlyContinue';" +
                "$tasks=(Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\\Microsoft\\Windows\\*' -and $_.State -ne 'Disabled' }).Count;" +
                "$svcs=(Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' -and $_.PathName -notmatch 'C:\\\\Windows\\\\' }).Count;" +
                "$bloat=(Get-AppxPackage | Where-Object { $_.Name -match 'Clipchamp|PowerAutomateDesktop|MicrosoftJournal|SolitaireCollection|WindowsMaps|windowscommunicationsapps|MixedReality\\.Portal|Windows\\.DevHome|Microsoft\\.People|DropboxOEM|BingNews|BingWeather|NarratorExtension|NarratorScript' }).Count;" +
                "\"$svcs|$tasks|$bloat\"";
            var r = await commands.RunAsync(SystemCommandRunner.PowerShell, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], ct).ConfigureAwait(false);
            if (r is { ExitCode: 0 } && r.StdOut.Trim().Split('|') is { Length: 3 } parts)
            {
                if (int.TryParse(parts[0], out var s)) autoSvcCount = s;
                if (int.TryParse(parts[1], out var t)) taskCount = t;
                if (int.TryParse(parts[2], out var b)) bloatCount = b;
            }
        }
        catch (Exception ex) { Log("inventory script: " + ex.Message); }

        return new(memUsedMb, bgProcs, diskFreeGb, startupCount, autoSvcCount, taskCount, bloatCount);
    }
}
