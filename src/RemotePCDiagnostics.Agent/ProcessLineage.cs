using System.Runtime.InteropServices;

namespace RemotePCDiagnostics.Agent;

/// <summary>Parent process ids, so an upgrade does not kill the process whose job still contains Setup.</summary>
internal static class ProcessLineage
{
    public static bool TryParentChain(int pid, out List<int> chain)
    {
        chain = [];
        if (!OperatingSystem.IsWindows() || pid <= 0)
            return false;

        var current = pid;
        var seen = new HashSet<int> { pid };
        for (var i = 0; i < 16; i++)
        {
            if (!TryParent(current, out var parent) || parent <= 0 || !seen.Add(parent))
                return chain.Count > 0;
            chain.Add(parent);
            current = parent;
        }
        return true;
    }

    private static bool TryParent(int pid, out int parent)
    {
        parent = 0;
        var handle = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (handle == IntPtr.Zero)
            return false;
        try
        {
            var info = new ProcessBasicInformation();
            var status = NtQueryInformationProcess(handle, ProcessBasicInformationClass, ref info, Marshal.SizeOf<ProcessBasicInformation>(), out _);
            if (status != 0)
                return false;
            parent = unchecked((int)info.InheritedFromUniqueProcessId.ToInt64());
            return parent > 0;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const int ProcessBasicInformationClass = 0;

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessBasicInformation
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        IntPtr process,
        int processInformationClass,
        ref ProcessBasicInformation processInformation,
        int processInformationLength,
        out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
