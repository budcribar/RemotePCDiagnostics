using System.Diagnostics;
using System.Runtime.InteropServices;
using RemotePCDiagnostics.Core.OutlookBench;

namespace OutlookBenchmark;

/// <summary>
/// Starts classic Outlook and times it until it's ready (main window shown and its processor use settled), then closes it
/// politely. Normal and safe-mode (no add-ins) starts alternate so both see the same conditions; the difference is what
/// add-ins cost on this PC. Memory, paging and disk reads are recorded during each start.
/// </summary>
internal sealed class StartTest(string exe, string? profile)
{
    public static readonly TimeSpan ReadyTimeout = TimeSpan.FromSeconds(120), CloseTimeout = TimeSpan.FromSeconds(60);
    private const int IntervalMs = 500;

    public static bool OutlookRunning() { var p = Process.GetProcessesByName("OUTLOOK"); foreach (var x in p) x.Dispose(); return p.Length > 0; }

    public IReadOnlyList<StartRun> Run(int runsEach)
    {
        var runs = new List<StartRun>();
        var plan = new List<(StartMode, bool)> { (StartMode.Normal, true) };
        for (var i = 0; i < runsEach; i++) { plan.Add((StartMode.Safe, false)); plan.Add((StartMode.Normal, false)); }
        for (var i = 0; i < plan.Count; i++)
        {
            var (mode, first) = plan[i];
            Console.WriteLine($"  Start {i + 1} of {plan.Count}: {(first ? "first start" : mode == StartMode.Safe ? "safe mode (no add-ins)" : "normal")}…");
            var r = Once(i + 1, mode, first);
            runs.Add(r);
            Console.WriteLine(r.ReadyMs is { } ms ? $"    ready in {ms / 1000:0.0} s" : $"    {r.Note}");
            WaitForExit(TimeSpan.FromSeconds(30));
            Thread.Sleep(5000); // let the disk and memory settle between starts
        }
        return runs;
    }

    private StartRun Once(int index, StartMode mode, bool first)
    {
        var psi = new ProcessStartInfo(exe) { UseShellExecute = false };
        if (mode == StartMode.Safe) psi.ArgumentList.Add("/safe");
        if (profile is { Length: > 0 }) { psi.ArgumentList.Add("/profile"); psi.ArgumentList.Add(profile); } // skips the profile chooser
        using var pdh = new PagingCounter();
        var sw = Stopwatch.StartNew();
        using var p = Process.Start(psi);
        if (p is null) return new(index, mode, first, null, null, 0, 0, 0, 0, 0, false, "Outlook didn't start");
        double? windowMs = null;
        var samples = new List<(double, double)>();
        var lastCpu = TimeSpan.Zero;
        long peakWs = 0, peakPriv = 0, minAvail = long.MaxValue;
        string? note = null;
        double? ready = null;
        while (sw.Elapsed < ReadyTimeout)
        {
            Thread.Sleep(IntervalMs);
            try
            {
                p.Refresh();
                if (p.HasExited) { note = "Outlook closed by itself during start"; break; }
                peakWs = Math.Max(peakWs, p.PeakWorkingSet64);
                peakPriv = Math.Max(peakPriv, p.PrivateMemorySize64);
                var cpu = p.TotalProcessorTime;
                samples.Add((sw.Elapsed.TotalMilliseconds, (cpu - lastCpu).TotalMilliseconds));
                lastCpu = cpu;
                if (windowMs is null && p.MainWindowHandle != IntPtr.Zero)
                {
                    windowMs = sw.Elapsed.TotalMilliseconds;
                    // The main window's title ends in "Outlook"; anything else (profile chooser, safe-mode notice, sign-in) is a prompt.
                    if (!p.MainWindowTitle.Contains("Outlook", StringComparison.OrdinalIgnoreCase) || p.MainWindowTitle.Contains("Choose Profile", StringComparison.OrdinalIgnoreCase))
                    { note = $"Outlook showed a prompt (\"{p.MainWindowTitle}\"); not timed"; break; }
                }
            }
            catch (InvalidOperationException) { note = "Outlook closed during start"; break; }
            minAvail = Math.Min(minAvail, AvailableBytes());
            pdh.Sample();
            if (windowMs is { } w && OutlookBenchMath.ReadyAt(samples, w, IntervalMs) is { } r) { ready = r; break; }
        }
        if (ready is null && note is null) note = $"didn't settle within {ReadyTimeout.TotalSeconds:0} s";
        var read = ReadBytes(p);
        var clean = Close(p);
        return new(index, mode, first, windowMs, ready, peakWs, peakPriv, read, pdh.Average, minAvail == long.MaxValue ? 0 : minAvail, clean, clean ? note : (note is null ? "had to be ended" : note + "; had to be ended"));
    }

    /// <summary>Closes like clicking X (Outlook saves and closes its data file); ends it only if it doesn't close within a minute.</summary>
    private static bool Close(Process p)
    {
        try
        {
            if (p.HasExited) return true;
            p.CloseMainWindow();
            if (p.WaitForExit((int)CloseTimeout.TotalMilliseconds)) return true;
            p.Kill(entireProcessTree: true);
            p.WaitForExit(10_000);
        }
        catch (InvalidOperationException) { return true; }
        return false;
    }

    private static void WaitForExit(TimeSpan max)
    {
        var end = DateTime.UtcNow + max;
        while (OutlookRunning() && DateTime.UtcNow < end) Thread.Sleep(500);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS { public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes; }
    [DllImport("kernel32.dll")] private static extern bool GetProcessIoCounters(IntPtr h, out IO_COUNTERS c);
    private static long ReadBytes(Process p) { try { return GetProcessIoCounters(p.Handle, out var c) ? (long)c.ReadBytes : 0; } catch { return 0; } }

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORYSTATUSEX { public uint dwLength, dwMemoryLoad; public ulong ullTotalPhys, ullAvailPhys, ullTotalPageFile, ullAvailPageFile, ullTotalVirtual, ullAvailVirtual, ullAvailExtendedVirtual; }
    [DllImport("kernel32.dll")] private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX m);
    public static long AvailableBytes() { var m = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() }; return GlobalMemoryStatusEx(ref m) ? (long)m.ullAvailPhys : 0; }

    /// <summary>System-wide memory paging (pages/s) via PDH with the English counter name (works on any Windows language).</summary>
    private sealed class PagingCounter : IDisposable
    {
        [StructLayout(LayoutKind.Explicit)] private struct PDH_FMT_COUNTERVALUE { [FieldOffset(0)] public uint CStatus; [FieldOffset(8)] public double doubleValue; }
        [DllImport("pdh.dll", CharSet = CharSet.Unicode)] private static extern uint PdhOpenQuery(string? s, IntPtr u, out IntPtr q);
        [DllImport("pdh.dll", CharSet = CharSet.Unicode, EntryPoint = "PdhAddEnglishCounterW")] private static extern uint PdhAddEnglishCounter(IntPtr q, string path, IntPtr u, out IntPtr c);
        [DllImport("pdh.dll")] private static extern uint PdhCollectQueryData(IntPtr q);
        [DllImport("pdh.dll")] private static extern uint PdhGetFormattedCounterValue(IntPtr c, uint f, out uint t, out PDH_FMT_COUNTERVALUE v);
        [DllImport("pdh.dll")] private static extern uint PdhCloseQuery(IntPtr q);
        private readonly IntPtr _q, _c;
        private readonly List<double> _v = [];
        public PagingCounter()
        {
            if (PdhOpenQuery(null, IntPtr.Zero, out _q) == 0 && PdhAddEnglishCounter(_q, @"\Memory\Pages/sec", IntPtr.Zero, out _c) == 0) PdhCollectQueryData(_q);
        }
        public void Sample()
        {
            if (_c == IntPtr.Zero || PdhCollectQueryData(_q) != 0) return;
            if (PdhGetFormattedCounterValue(_c, 0x00000200 | 0x00008000, out _, out var v) == 0 && v.CStatus == 0) _v.Add(v.doubleValue);
        }
        public double Average => _v.Count == 0 ? 0 : _v.Average();
        public void Dispose() { if (_q != IntPtr.Zero) PdhCloseQuery(_q); }
    }
}
