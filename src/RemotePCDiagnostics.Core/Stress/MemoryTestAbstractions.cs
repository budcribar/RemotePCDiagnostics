using System.Diagnostics;
using System.Runtime.InteropServices;

namespace RemotePCDiagnostics.Core.Stress;

public interface IMemoryInfo
{
    /// <summary>Available and total physical memory in bytes.</summary>
    (long Available, long Total) Read();
}

/// <summary>A running memory test helper process.</summary>
public interface IMemTestHelperProcess : IDisposable
{
    /// <summary>Next stdout line, or null when the helper has exited / closed its output.</summary>
    Task<string?> ReadLineAsync(CancellationToken cancellationToken);
    void Kill();
    int? ExitCode { get; }
}

public interface IMemTestHelperLauncher
{
    IMemTestHelperProcess Start(long bytes, TimeSpan duration);
}

/// <summary>Launches Windows Memory Diagnostic (mdsched.exe), which offers to restart the PC to test memory.</summary>
public interface IWindowsMemoryDiagnosticLauncher
{
    bool Launch();
}

public sealed class SystemMemoryInfo : IMemoryInfo
{
    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORYSTATUSEX
    {
        public uint dwLength, dwMemoryLoad;
        public ulong ullTotalPhys, ullAvailPhys, ullTotalPageFile, ullAvailPageFile, ullTotalVirtual, ullAvailVirtual, ullAvailExtendedVirtual;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX m);

    public (long Available, long Total) Read()
    {
        if (OperatingSystem.IsWindows())
        {
            var m = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
            if (GlobalMemoryStatusEx(ref m)) return ((long)m.ullAvailPhys, (long)m.ullTotalPhys);
        }
        var total = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;
        try
        {
            var line = File.ReadLines("/proc/meminfo").FirstOrDefault(l => l.StartsWith("MemAvailable:"));
            if (line is not null) return (long.Parse(line.Split(' ', StringSplitOptions.RemoveEmptyEntries)[1]) * 1024, total);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        return (total / 2, total);
    }
}

/// <summary>Starts the bundled RemotePCDiagnostics.MemTest helper (next to the app) at below-normal priority.</summary>
public sealed class ProcessMemTestHelperLauncher(string? directory = null, Action<string>? log = null) : IMemTestHelperLauncher
{
    public const string HelperName = "RemotePCDiagnostics.MemTest";

    public static string Arguments(long bytes, TimeSpan duration) => $"--bytes {bytes} --seconds {(long)Math.Ceiling(duration.TotalSeconds)}";

    public IMemTestHelperProcess Start(long bytes, TimeSpan duration)
    {
        var dir = directory ?? AppContext.BaseDirectory;
        var exe = Path.Combine(dir, HelperName + (OperatingSystem.IsWindows() ? ".exe" : ""));
        var dll = Path.Combine(dir, HelperName + ".dll");
        var psi = File.Exists(exe) ? new ProcessStartInfo(exe, Arguments(bytes, duration))
            : File.Exists(dll) ? new ProcessStartInfo("dotnet", $"\"{dll}\" {Arguments(bytes, duration)}")
            : throw new FileNotFoundException("Memory test helper not found", exe);
        psi.UseShellExecute = false; psi.RedirectStandardOutput = true; psi.RedirectStandardError = true; psi.CreateNoWindow = true;
        var p = Process.Start(psi) ?? throw new InvalidOperationException("Memory test helper did not start");
        try { p.PriorityClass = ProcessPriorityClass.BelowNormal; } catch (Exception ex) { log?.Invoke($"Memory test: couldn't lower helper priority: {ex.Message}"); }
        p.ErrorDataReceived += (_, e) => { if (e.Data is { Length: > 0 }) log?.Invoke($"Memory test helper stderr: {e.Data}"); };
        p.BeginErrorReadLine();
        log?.Invoke($"Memory test: started helper pid={p.Id} {psi.FileName} {psi.Arguments}");
        return new Proc(p);
    }

    private sealed class Proc(Process p) : IMemTestHelperProcess
    {
        public Task<string?> ReadLineAsync(CancellationToken ct) => p.StandardOutput.ReadLineAsync(ct).AsTask();
        public void Kill() { try { if (!p.HasExited) p.Kill(entireProcessTree: true); } catch (Exception) { } }
        public int? ExitCode { get { try { return p.HasExited ? p.ExitCode : null; } catch (Exception) { return null; } } }
        public void Dispose() { try { Kill(); } finally { p.Dispose(); } }
    }
}

public sealed class MdschedLauncher(Action<string>? log = null) : IWindowsMemoryDiagnosticLauncher
{
    public bool Launch()
    {
        try
        {
            var exe = Path.Combine(Environment.SystemDirectory, "mdsched.exe");
            Process.Start(new ProcessStartInfo(exe) { UseShellExecute = true })?.Dispose();
            log?.Invoke("Memory test: launched Windows Memory Diagnostic");
            return true;
        }
        catch (Exception ex) { log?.Invoke($"Memory test: couldn't launch Windows Memory Diagnostic: {ex.Message}"); return false; }
    }
}
