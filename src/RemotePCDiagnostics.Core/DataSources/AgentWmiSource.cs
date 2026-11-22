using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.DataSources;

/// <summary>
/// WMI for the app: every query runs in the Agent (<see cref="IElevatedCommandBridge.QueryWmiAsync"/>), which has administrator rights,
/// so classes that refuse a standard user (Win32_PowerPlan, the storage reliability counters) answer too. The app itself never queries WMI.
/// When the Agent isn't connected every query fails, and checks fall back to what they can read without it.
/// </summary>
public sealed class AgentWmiSource(IElevatedCommandBridge agent) : IWmiSource
{
    public const string NotConnected = "The Agent isn't connected, so WMI can't be read.";

    public Task<WmiQueryResult> QueryAsync(string wmiNamespace, string wql, CancellationToken ct = default) =>
        agent.IsConnected
            ? agent.QueryWmiAsync(wmiNamespace, wql, ct)
            : Task.FromResult(WmiQueryResult.Failed(wmiNamespace, wql, NotConnected));
}

/// <summary>
/// WMI for a module in user mode (the module host): each query goes to the app (<c>wmi.query</c>), which passes it to the Agent, so the module
/// host never reads WMI itself either. A refused or failed query is a failed answer, as from <see cref="AgentWmiSource"/>.
/// </summary>
public sealed class HostWmiSource(Plugins.IHostQueries host, ILogger? log = null) : IWmiSource
{
    public async Task<WmiQueryResult> QueryAsync(string wmiNamespace, string wql, CancellationToken ct = default)
    {
        try { return await host.QueryWmiAsync(wmiNamespace, wql, ct).ConfigureAwait(false); }
        catch (Plugins.HostQueryException ex)
        {
            log.Warn($"wmi.query refused ({ex.Error}): {ex.Message}");
            return WmiQueryResult.Failed(wmiNamespace, wql, ex.Message);
        }
    }
}

/// <summary>What the Agent's <c>wmi_query</c> runs: one SELECT, in a namespace the checks read. WQL SELECT only reads.</summary>
public static class WmiQueryPolicy
{
    public const int MaxQueryLength = 2048;

    public static readonly IReadOnlySet<string> Namespaces = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        @"root\cimv2", @"root\wmi", @"root\cimv2\power", @"root\Microsoft\Windows\Storage", @"root\StandardCimv2",
    };

    /// <summary>Why the Agent won't run this query, or null when it will.</summary>
    public static string? Problem(string wmiNamespace, string wql)
    {
        if (!Namespaces.Contains(wmiNamespace)) return $"WMI namespace '{wmiNamespace}' isn't one the Agent reads.";
        var q = wql.Trim();
        if (q.Length == 0 || q.Length > MaxQueryLength) return "The WMI query is empty or too long.";
        // Both are read-only. ASSOCIATORS OF follows an object's links (a disk's reliability counters are only reachable that way).
        if (!q.StartsWith("SELECT ", StringComparison.OrdinalIgnoreCase) && !q.StartsWith("ASSOCIATORS OF {", StringComparison.OrdinalIgnoreCase))
            return "The Agent only runs WMI SELECT and ASSOCIATORS OF queries.";
        if (q.Any(char.IsControl)) return "The WMI query has control characters.";
        return null;
    }
}
