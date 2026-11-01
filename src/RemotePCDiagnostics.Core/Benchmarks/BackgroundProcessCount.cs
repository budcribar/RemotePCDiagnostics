namespace RemotePCDiagnostics.Core.Benchmarks;

/// <summary>One running process as Windows lists it (Toolhelp snapshot or Win32_Process).</summary>
/// <param name="Name">Executable name, with or without ".exe" (e.g. "svchost.exe").</param>
public sealed record ProcessRow(int Pid, int ParentPid, string Name);

/// <summary>
/// "Background processes" for the benchmark: everything running except this app (with everything it started, such as its
/// WebView2 browser processes and the PowerShell/osquery queries), the programs the benchmark itself starts, and Windows'
/// kernel pseudo-processes. Without this the app counts itself, and that changes from run to run.
/// </summary>
public static class BackgroundProcessCount
{
    /// <summary>Kernel pseudo-processes, not programs (PID 0 is the idle process, PID 4 is System).</summary>
    public static readonly IReadOnlySet<string> PseudoProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { "[System Process]", "System Idle Process", "Idle", "System", "Secure System", "Registry", "Memory Compression" };

    /// <summary>Programs the benchmark starts (timed Windows programs, power-plan query); excluded with their child processes even if orphaned.</summary>
    public static readonly IReadOnlySet<string> BenchmarkTools = new HashSet<string>(
        BuiltInPrograms.All.Select(p => Stem(p.FileName)).Append("powercfg"), StringComparer.OrdinalIgnoreCase);

    public static int Count(IEnumerable<ProcessRow> processes, int ownPid)
    {
        var rows = processes.ToList();
        var children = rows.Where(r => r.Pid != r.ParentPid).ToLookup(r => r.ParentPid);
        var excluded = new HashSet<int>();
        var pending = new Stack<int>(rows.Where(r => BenchmarkTools.Contains(Stem(r.Name))).Select(r => r.Pid).Append(ownPid));
        while (pending.TryPop(out var pid))
            if (excluded.Add(pid))
                foreach (var child in children[pid]) pending.Push(child.Pid);
        return rows.Count(r => !excluded.Contains(r.Pid) && r.Pid is not (0 or 4) && !PseudoProcesses.Contains(Stem(r.Name)));
    }

    /// <summary>"C:\Windows\System32\cmd.exe" / "cmd.exe" / "cmd" → "cmd".</summary>
    public static string Stem(string name)
    {
        var file = name[(name.LastIndexOfAny(['\\', '/']) + 1)..];
        return file.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? file[..^4] : file;
    }
}
