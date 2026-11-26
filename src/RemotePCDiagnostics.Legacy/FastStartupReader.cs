using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace RemotePCDiagnostics.Legacy;

/// <summary>
/// Native in-process C# reader for Fast Startup (HiberbootEnabled registry) and total/free physical memory.
/// Used instead of FastStartupState.ps1 (which takes ~400 ms to start PowerShell) by the Store edition without an Agent, as a standard user.
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

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetPhysicallyInstalledSystemMemory(out ulong totalMemoryInKilobytes);

    /// <summary>
    /// System memory commitments: commit charge and limit (RAM plus page file), installed RAM, and page file use.
    /// Every value is null when Windows doesn't report it.
    /// </summary>
    public static (long? CommitUsedBytes, long? CommitLimitBytes, long? InstalledBytes, long? PagefileUsedBytes, long? PagefileSizeBytes) ReadCommit()
    {
        if (!OperatingSystem.IsWindows()) return (null, null, null, null, null);
        long? used = null, limit = null, installed = null, pfUsed = null, pfSize = null;
        try
        {
            var m = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
            if (GlobalMemoryStatusEx(ref m) && m.ullTotalPageFile > 0)
            {
                limit = (long)m.ullTotalPageFile;
                used = Math.Max(0, (long)m.ullTotalPageFile - (long)m.ullAvailPageFile);
            }
        }
        catch { }
        try
        {
            if (GetPhysicallyInstalledSystemMemory(out var kb) && kb > 0) installed = (long)kb * 1024;
        }
        catch { }
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher("SELECT CurrentUsage, AllocatedBaseSize FROM Win32_PageFileUsage");
            using var collection = searcher.Get();
            long cur = 0, size = 0;
            foreach (var item in collection)
            {
                using (item)
                {
                    cur += Convert.ToInt64(item["CurrentUsage"] ?? 0L, System.Globalization.CultureInfo.InvariantCulture);
                    size += Convert.ToInt64(item["AllocatedBaseSize"] ?? 0L, System.Globalization.CultureInfo.InvariantCulture);
                }
            }
            pfUsed = cur * 1024 * 1024;
            pfSize = size * 1024 * 1024;
        }
        catch { }
        return (used, limit, installed, pfUsed, pfSize);
    }

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

        if (totalBytes is null)
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
