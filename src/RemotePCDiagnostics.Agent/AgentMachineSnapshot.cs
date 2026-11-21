using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;
using RemotePCDiagnostics.Agent.Core;

namespace RemotePCDiagnostics.Agent;

/// <summary>Other agent processes and service registrations, for the single-instance log and the upgrade.</summary>
internal static class AgentMachineSnapshot
{
    public static IReadOnlyList<AgentProcessSighting> OtherProcesses()
    {
        if (!OperatingSystem.IsWindows())
            return [];

        var current = Environment.ProcessId;
        Process[] found;
        try
        {
            found = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(AgentLayout.AgentExeName));
        }
        catch
        {
            return [];
        }

        var list = new List<AgentProcessSighting>();
        foreach (var process in found)
        {
            try
            {
                if (process.Id == current || process.Id <= 0) continue;
                var path = ImagePathOf(process);
                list.Add(new AgentProcessSighting(process.Id, path, FileVersionOf(path)));
            }
            catch
            {
                // The process exited between the list and the read.
            }
            finally
            {
                process.Dispose();
            }
        }
        return list;
    }

    public static IReadOnlyList<AgentServiceRegistration> ReadServices()
    {
        if (!OperatingSystem.IsWindows())
            return [];

        var list = new List<AgentServiceRegistration>();
        try
        {
            using var services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (services is null) return list;
            foreach (var name in services.GetSubKeyNames())
            {
                string? image = null;
                try
                {
                    using var key = services.OpenSubKey(name);
                    image = key?.GetValue("ImagePath") as string;
                }
                catch
                {
                    // A service key we cannot read is still stopped when its name is one we own.
                }
                if (!AgentInstancePolicy.ServiceLaunchesAgent(name, image)) continue;
                list.Add(new AgentServiceRegistration(name, image, ServiceState(name)));
            }
        }
        catch
        {
            // The upgrade still stops the known service names below.
            foreach (var name in AgentInstancePolicy.KnownServiceNames)
                list.Add(new AgentServiceRegistration(name, null, ServiceState(name)));
        }
        return list;
    }

    public static AgentInstanceClaim? ReadClaim()
    {
        try
        {
            var path = AgentLayout.InstanceClaimPath();
            if (!File.Exists(path)) return null;
            return AgentInstanceClaim.Parse(File.ReadAllText(path));
        }
        catch
        {
            return null;
        }
    }

    public static void WriteClaim(AgentInstanceClaim claim)
    {
        try
        {
            var path = AgentLayout.InstanceClaimPath();
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);
            var temp = path + ".tmp";
            File.WriteAllText(temp, AgentInstanceClaim.Format(claim));
            File.Move(temp, path, overwrite: true);
        }
        catch
        {
            // The mutex is the guard. The claim file only names the holder.
        }
    }

    public static void DeleteClaimIfOwned(int pid)
    {
        try
        {
            var path = AgentLayout.InstanceClaimPath();
            var claim = ReadClaim();
            if (claim is null || claim.Pid != pid) return;
            File.Delete(path);
        }
        catch
        {
            // The next holder overwrites it.
        }
    }

    public static bool PidAlive(int pid)
    {
        if (pid <= 0) return false;
        try
        {
            using var process = Process.GetProcessById(pid);
            return !process.HasExited;
        }
        catch
        {
            return false;
        }
    }

    public static string? FileVersionOf(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return null;
        try
        {
            var info = FileVersionInfo.GetVersionInfo(path);
            var version = string.IsNullOrWhiteSpace(info.ProductVersion) ? info.FileVersion : info.ProductVersion;
            if (string.IsNullOrWhiteSpace(version)) return null;
            var plus = version.IndexOf('+');
            return plus > 0 ? version[..plus] : version;
        }
        catch
        {
            return null;
        }
    }

    private static string? ServiceState(string name)
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            using var controller = new System.ServiceProcess.ServiceController(name);
            return controller.Status.ToString();
        }
        catch
        {
            return null;
        }
    }

    private static string? ImagePathOf(Process process)
    {
        try
        {
            return process.MainModule?.FileName;
        }
        catch
        {
            // A service in session 0 often cannot read another session through MainModule.
        }

        if (!OperatingSystem.IsWindows()) return null;
        var handle = OpenProcess(ProcessQueryLimitedInformation, false, process.Id);
        if (handle == IntPtr.Zero) return null;
        try
        {
            var buffer = new StringBuilder(1024);
            var size = buffer.Capacity;
            return QueryFullProcessImageName(handle, 0, buffer, ref size) ? buffer.ToString() : null;
        }
        catch
        {
            return null;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private const int ProcessQueryLimitedInformation = 0x1000;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int access, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr process, int flags, StringBuilder name, ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
