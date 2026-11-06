using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>One process row from osquery <c>processes</c>.</summary>
public sealed record ProcessResourceRow(string Name, int Pid, long ResidentBytes, long CpuTimeMs, long DiskBytes)
{
    public static ProcessResourceRow FromRow(IReadOnlyDictionary<string, string> r)
    {
        var user = Math.Max(0, r.Long("user_time") ?? 0);
        var sys = Math.Max(0, r.Long("system_time") ?? 0);
        var read = Math.Max(0, r.Long("disk_bytes_read") ?? 0);
        var write = Math.Max(0, r.Long("disk_bytes_written") ?? 0);
        return new(r.Str("name"), r.Int("pid") ?? 0, Math.Max(0, r.Long("resident_size") ?? 0), user + sys, read + write);
    }
}

/// <summary>Grouped resource usage for a process executable name (e.g. all <c>chrome.exe</c> instances combined).</summary>
public sealed record ProcessGroupUsage(string Name, int Instances, long MemoryBytes, long CpuTimeMs, long DiskBytes)
{
    public string DisplayName => Instances > 1 ? $"{Name} ({Instances})" : Name;
}

/// <summary>System uptime from osquery <c>uptime</c> plus Windows Fast Startup state.</summary>
public sealed record SystemUptimeInfo(long TotalSeconds, int Days, int Hours, int Minutes, bool? FastStartupEnabled)
{
    public static SystemUptimeInfo FromRow(IReadOnlyDictionary<string, string> r, bool? fastStartup = null) => new(
        r.Long("total_seconds") ?? 0, r.Int("days") ?? 0, r.Int("hours") ?? 0, r.Int("minutes") ?? 0, fastStartup);

    public string FriendlyDuration => Days > 0 ? $"{Days}d {Hours}h" : Hours > 0 ? $"{Hours}h {Minutes}m" : $"{Math.Max(1, Minutes)}m";
}

/// <summary>The process and uptime queries shared by the Resource hogs module and the restart-and-resume flow (which runs them itself).</summary>
public static class ResourceUsage
{
    public const string UptimeSql = "SELECT days, hours, minutes, total_seconds FROM uptime;";
    public const string ProcessesSql = "SELECT pid, name, resident_size, user_time, system_time, disk_bytes_read, disk_bytes_written FROM processes WHERE pid > 4;";

    public static List<ProcessGroupUsage> GroupProcesses(IEnumerable<ProcessResourceRow> rows) =>
        rows.Where(p => p.Name.Length > 0 && !p.Name.Equals("[System Process]", StringComparison.OrdinalIgnoreCase) && !p.Name.Equals("System", StringComparison.OrdinalIgnoreCase) && !p.Name.Equals("svchost", StringComparison.OrdinalIgnoreCase) && !p.Name.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase))
            .GroupBy(p => p.Name, StringComparer.OrdinalIgnoreCase)
            .Select(g => new ProcessGroupUsage(g.First().Name, g.Count(), g.Sum(x => x.ResidentBytes), g.Sum(x => x.CpuTimeMs), g.Sum(x => x.DiskBytes)))
            .ToList();
}
