namespace RemotePCDiagnostics.Core.Areas;

/// <summary>CPU and disk activity of one process, measured between two process snapshots.</summary>
public sealed record ProcessRate(double CpuPercent, long DiskBytesPerSecond);

/// <summary>
/// One top-level app with every helper process it started rolled into it (for example chrome.exe and its renderer, GPU and
/// crashpad children, or Teams and its msedgewebview2.exe children).
/// </summary>
public sealed record AppTreeUsage(
    string Name, int RootPid, int ProcessCount, long WorkingSetBytes, long PrivateBytes, long CpuTimeMs, long DiskBytes,
    double? CpuPercent, long? DiskBytesPerSecond, IReadOnlyList<(string Name, int Count)> Helpers)
{
    public string DisplayName => ProcessCount > 1 ? $"{Name} ({ProcessCount})" : Name;

    /// <summary>"Includes msedgewebview2.exe (12), crashpad_handler.exe", or null when the app has no helpers of another name.</summary>
    public string? HelpersText => Helpers.Count == 0 ? null
        : "Includes " + string.Join(", ", Helpers.Select(h => h.Count > 1 ? $"{h.Name} ({h.Count})" : h.Name)) + ".";
}

/// <summary>
/// Rolls processes up to their top-level app by walking parent PIDs, and works out CPU % and disk rate from two snapshots.
/// </summary>
public static class ProcessTree
{
    /// <summary>
    /// Windows shell and service hosts. The parent walk stops below them, so an app started from Explorer or by a service is its own
    /// top-level app instead of being folded into explorer.exe or services.exe.
    /// </summary>
    private static readonly HashSet<string> StopAt = new(StringComparer.OrdinalIgnoreCase)
    {
        "explorer", "services", "svchost", "wininit", "winlogon", "smss", "csrss", "userinit", "sihost", "System", "[System Process]",
    };

    /// <summary>Processes left out of the app list, matching <see cref="ResourceUsage.GroupProcesses"/>.</summary>
    private static readonly HashSet<string> Hidden = new(StringComparer.OrdinalIgnoreCase) { "System", "[System Process]", "svchost" };

    private static string BaseName(string name) => name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name[..^4] : name;

    public static bool IsStopProcess(string name) => StopAt.Contains(BaseName(name));

    /// <summary>
    /// The top-level process that <paramref name="p"/> belongs to. The walk goes up through parents that are still running, and stops
    /// at a shell or service host, at a missing parent, at a loop, or at a "parent" that started after its child, which means the
    /// parent PID was reused by an unrelated process after the real parent exited.
    /// </summary>
    public static ProcessResourceRow RootOf(ProcessResourceRow p, IReadOnlyDictionary<int, ProcessResourceRow> byPid)
    {
        var cur = p;
        var visited = new HashSet<int> { p.Pid };
        while (cur.ParentPid > 0 && byPid.TryGetValue(cur.ParentPid, out var parent))
        {
            if (IsStopProcess(parent.Name)) break;
            if (parent.StartTime > 0 && cur.StartTime > 0 && parent.StartTime > cur.StartTime) break;
            if (!visited.Add(parent.Pid)) break;
            cur = parent;
        }
        return cur;
    }

    /// <summary>Groups processes by top-level app. Trees whose top process has the same name (two chrome.exe windows) are combined.</summary>
    public static List<AppTreeUsage> RollUp(IEnumerable<ProcessResourceRow> rows, IReadOnlyDictionary<int, ProcessRate>? rates = null)
    {
        var list = rows.Where(p => p.Name.Length > 0).ToList();
        var byPid = new Dictionary<int, ProcessResourceRow>();
        foreach (var p in list) byPid.TryAdd(p.Pid, p);

        var groups = new Dictionary<string, (ProcessResourceRow Root, List<ProcessResourceRow> Members)>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in list)
        {
            if (Hidden.Contains(BaseName(p.Name))) continue;
            var root = RootOf(p, byPid);
            if (Hidden.Contains(BaseName(root.Name))) root = p;
            if (!groups.TryGetValue(root.Name, out var g))
                groups[root.Name] = g = (root, []);
            else if (root.Pid != g.Root.Pid && root.ResidentBytes > g.Root.ResidentBytes)
                g = groups[root.Name] = (root, g.Members);
            g.Members.Add(p);
        }

        var apps = new List<AppTreeUsage>(groups.Count);
        foreach (var (root, members) in groups.Values)
        {
            double? cpu = null;
            long? disk = null;
            if (rates is not null)
            {
                cpu = 0;
                disk = 0;
                foreach (var m in members)
                {
                    if (!rates.TryGetValue(m.Pid, out var r)) continue;
                    cpu += r.CpuPercent;
                    disk += r.DiskBytesPerSecond;
                }
            }
            var helpers = members.Where(m => !m.Name.Equals(root.Name, StringComparison.OrdinalIgnoreCase))
                .GroupBy(m => m.Name, StringComparer.OrdinalIgnoreCase)
                .Select(h => (h.First().Name, h.Count()))
                .OrderByDescending(h => h.Item2).ThenBy(h => h.Item1, StringComparer.OrdinalIgnoreCase)
                .ToList();
            apps.Add(new(root.Name, root.Pid, members.Count,
                members.Sum(m => m.ResidentBytes), members.Sum(m => Math.Max(0, m.PrivateBytes)),
                members.Sum(m => m.CpuTimeMs), members.Sum(m => m.DiskBytes), cpu, disk, helpers));
        }
        return apps;
    }

    /// <summary>
    /// Per-process CPU % (of the whole PC, so 100% means every logical core busy) and disk bytes per second between two snapshots.
    /// A PID is only compared with itself: a PID that ended and was reused between the snapshots (different start time) is skipped.
    /// </summary>
    public static Dictionary<int, ProcessRate> Rates(IEnumerable<ProcessResourceRow> before, IEnumerable<ProcessResourceRow> after, TimeSpan elapsed, int logicalCores)
    {
        var result = new Dictionary<int, ProcessRate>();
        if (elapsed <= TimeSpan.Zero) return result;
        var cores = Math.Max(1, logicalCores);
        var first = new Dictionary<int, ProcessResourceRow>();
        foreach (var p in before) first.TryAdd(p.Pid, p);
        foreach (var p in after)
        {
            if (!first.TryGetValue(p.Pid, out var b)) continue;
            if (b.StartTime > 0 && p.StartTime > 0 && b.StartTime != p.StartTime) continue;
            var cpuMs = Math.Max(0, p.CpuTimeMs - b.CpuTimeMs);
            var diskBytes = Math.Max(0, p.DiskBytes - b.DiskBytes);
            var cpu = Math.Min(100.0, 100.0 * cpuMs / (elapsed.TotalMilliseconds * cores));
            result[p.Pid] = new(cpu, (long)(diskBytes / elapsed.TotalSeconds));
        }
        return result;
    }
}
