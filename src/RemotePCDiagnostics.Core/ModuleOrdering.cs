namespace RemotePCDiagnostics.Core;

/// <summary>Why a module didn't run in a Run All (or stress run): its <see cref="ModuleDescriptor.DependsOn"/> wasn't met.</summary>
public enum GateKind
{
    /// <summary>A dependency ran in the same run and did not pass.</summary>
    Skipped,
    /// <summary>A dependency can't run here at all (missing, retired, disabled, not present on this hardware, part of a cycle).</summary>
    Blocked,
}

/// <summary>Payload of a result recorded instead of running the module. <see cref="Outcome"/> is what History and the Event Log show.</summary>
public sealed record DependencyGate(GateKind Kind, string Reason, Guid Dependency)
{
    public string Outcome => Kind.ToString();
}

/// <summary>Run order from <see cref="ModuleDescriptor.DependsOn"/> and <see cref="ModuleDescriptor.RunAfter"/>. Group and Order only break ties.</summary>
public static class ModuleOrdering
{
    /// <summary>Topological order of <paramref name="selected"/> on DependsOn and RunAfter edges between them; ties by group rank, Order, slug.
    /// Modules caught in a cycle (rejected at load, so normally none) come last in tie order.</summary>
    public static IReadOnlyList<ModuleDescriptor> Sort(IEnumerable<ModuleDescriptor> selected)
    {
        var nodes = selected.GroupBy(d => d.Id).Select(g => g.First()).ToList();
        var byId = nodes.ToDictionary(d => d.Id);
        var indegree = nodes.ToDictionary(d => d.Id, _ => 0);
        var next = nodes.ToDictionary(d => d.Id, _ => new List<Guid>());
        foreach (var d in nodes)
            foreach (var before in Before(d).Where(byId.ContainsKey).Distinct())
            {
                if (before == d.Id) continue;
                next[before].Add(d.Id);
                indegree[d.Id]++;
            }
        var ready = new SortedSet<ModuleDescriptor>(nodes.Where(d => indegree[d.Id] == 0), TieBreak.Instance);
        var result = new List<ModuleDescriptor>(nodes.Count);
        while (ready.Count > 0)
        {
            var d = ready.Min!;
            ready.Remove(d);
            result.Add(d);
            foreach (var n in next[d.Id])
                if (--indegree[n] == 0) ready.Add(byId[n]);
        }
        if (result.Count < nodes.Count) result.AddRange(nodes.Where(d => !result.Contains(d)).Order(TieBreak.Instance));
        return result;
    }

    /// <summary>Each set of modules that depend on each other in a loop (DependsOn and RunAfter between known modules). Every module in one
    /// is rejected at load.</summary>
    public static IReadOnlyList<IReadOnlyList<Guid>> FindCycles(IEnumerable<ModuleDescriptor> modules)
    {
        // Tarjan's strongly connected components.
        var byId = modules.GroupBy(d => d.Id).ToDictionary(g => g.Key, g => g.First());
        var index = new Dictionary<Guid, int>();
        var low = new Dictionary<Guid, int>();
        var onStack = new HashSet<Guid>();
        var stack = new Stack<Guid>();
        var cycles = new List<IReadOnlyList<Guid>>();
        var counter = 0;

        void Visit(Guid v)
        {
            index[v] = low[v] = counter++;
            stack.Push(v); onStack.Add(v);
            foreach (var w in Before(byId[v]).Where(byId.ContainsKey))
            {
                if (!index.ContainsKey(w)) { Visit(w); low[v] = Math.Min(low[v], low[w]); }
                else if (onStack.Contains(w)) low[v] = Math.Min(low[v], index[w]);
            }
            if (low[v] != index[v]) return;
            var scc = new List<Guid>();
            Guid x;
            do { x = stack.Pop(); onStack.Remove(x); scc.Add(x); } while (x != v);
            if (scc.Count > 1 || Before(byId[v]).Contains(v)) cycles.Add(scc);
        }

        foreach (var id in byId.Keys.OrderBy(i => byId[i].Slug, StringComparer.OrdinalIgnoreCase)) if (!index.ContainsKey(id)) Visit(id);
        return cycles;
    }

    /// <summary>A result that lets dependents run: OK or Warning, not cancelled, not unavailable, not itself skipped or blocked.</summary>
    public static bool Passed(DiagnosticResult? r) =>
        r is { Status: DiagnosticStatus.Ok or DiagnosticStatus.Warning, Cancelled: false, Payload: not (DependencyGate or ModuleAvailability) };

    /// <summary>The result recorded for a module that was skipped or blocked.</summary>
    public static DiagnosticResult GateResult(string moduleName, DependencyGate gate) =>
        new(moduleName, DiagnosticStatus.Warning, $"{gate.Kind}: {gate.Reason}", DateTimeOffset.Now, gate);

    private static IEnumerable<Guid> Before(ModuleDescriptor d) => d.DependsOn.Concat(d.RunAfter);

    private sealed class TieBreak : IComparer<ModuleDescriptor>
    {
        public static readonly TieBreak Instance = new();
        public int Compare(ModuleDescriptor? a, ModuleDescriptor? b)
        {
            if (ReferenceEquals(a, b)) return 0;
            if (a is null) return -1;
            if (b is null) return 1;
            var c = ModuleGroups.Rank(a.Group).CompareTo(ModuleGroups.Rank(b.Group));
            if (c == 0) c = a.Order.CompareTo(b.Order);
            if (c == 0) c = string.Compare(a.Slug, b.Slug, StringComparison.OrdinalIgnoreCase);
            return c != 0 ? c : a.Id.CompareTo(b.Id);
        }
    }
}
