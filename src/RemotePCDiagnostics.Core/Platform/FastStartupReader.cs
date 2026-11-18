using System.Runtime.InteropServices;
using Microsoft.Win32;
using RemotePCDiagnostics.Core.Areas;

namespace RemotePCDiagnostics.Core.Platform;

/// <summary>
/// Native in-process C# reader for Fast Startup (HiberbootEnabled registry) and total/free physical memory.
/// Replaces FastStartupState.ps1 to avoid ~400 ms of PowerShell subprocess overhead in standard user mode.
/// </summary>
public static class FastStartupReader
{
    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORYSTATUSEX
    {
        public uint dwLength;
        public uint dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX m);

    public static (bool? FastStartup, long? TotalBytes, long? FreeBytes) Read()
    {
        bool? fastStartup = null;
        long? totalBytes = null;
        long? freeBytes = null;

        if (OperatingSystem.IsWindows())
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager\Power");
                if (key?.GetValue("HiberbootEnabled") is int val)
                {
                    fastStartup = val == 1;
                }
                else if (key?.GetValue("HiberbootEnabled") is long lVal)
                {
                    fastStartup = lVal == 1L;
                }
            }
            catch
            {
                // Non-fatal if registry read fails or key doesn't exist
            }

            try
            {
                var m = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
                if (GlobalMemoryStatusEx(ref m))
                {
                    var total = (long)m.ullTotalPhys;
                    var free = (long)m.ullAvailPhys;
                    if (total > 0 && free >= 0)
                    {
                        totalBytes = total;
                        freeBytes = free;
                    }
                }
            }
            catch
            {
                // Fall back to GC memory info if Win32 API fails
            }
        }

        if (totalBytes is null || freeBytes is null)
        {
            try
            {
                var gc = GC.GetGCMemoryInfo();
                if (gc.TotalAvailableMemoryBytes > 0)
                {
                    totalBytes = gc.TotalAvailableMemoryBytes;
                    freeBytes = Math.Max(0, gc.TotalAvailableMemoryBytes - gc.MemoryLoadBytes);
                }
            }
            catch
            {
            }
        }

        return (fastStartup, totalBytes, freeBytes);
    }
}
