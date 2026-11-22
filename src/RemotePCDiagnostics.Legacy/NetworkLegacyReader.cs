using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Legacy;

/// <summary>
/// The Network check's old reader: adapters from osquery <c>interface_details</c>, and as osquery 5.24 on Windows leaves the packet and error
/// counters blank, the counters from the NetAdapterStatistics PowerShell script (matched by adapter name); the IP configuration from the
/// IpConfig PowerShell script. When the commands aren't scripted (the app), both are read in this process with .NET's network API instead.
/// </summary>
public sealed class OsqueryNetworkSource(OsqueryRunner runner, SystemCommandRunner? commands = null) : INetworkSource
{
    public const string Sql = "SELECT * FROM interface_details;";
    public static string StatsScript => Core.Scripts.PowerShellScripts.Get("NetAdapterStatistics");
    public static string IpConfigScript => WifiConfigModule.IpConfigScript;

    public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct) => LegacyAvailability.Of(runner, OsqueryAreaModuleBase.ToolMissingMessage);

    public async Task<IReadOnlyList<NetworkAdapter>?> ReadAdaptersAsync(CancellationToken ct)
    {
        var q = await runner.RunQueryAsync(Sql, ct).ConfigureAwait(false);
        if (!q.Success) return null;
        var adapters = q.Rows!.Select(NetworkAdapter.FromRow).ToList();
        if (adapters.Count == 0 || adapters.Any(a => a.HasCounters)) return adapters;
        if (commands is { IsScripted: true })
        {
            commands.Log.Line("Network: interface_details reported no traffic/error counters; using Get-NetAdapterStatistics");
            var pr = await commands.RunPowerShellAsync(StatsScript, ct).ConfigureAwait(false);
            if (pr is not { ExitCode: 0 }) return adapters;
            try { return MergeStatistics(adapters, OsqueryJson.ParseRows(pr.StdOut)); }
            catch (FormatException ex) { commands.Log.Warn($"Network: adapter statistics unreadable: {ex.Message}"); return adapters; }
        }
        var netStats = Core.Platform.NetworkInfoReader.ReadAdapterStatistics();
        return adapters.Select(a => a.HasCounters || !netStats.TryGetValue(a.Name, out var s) ? a : a with
        {
            PacketsIn = s.PacketsIn, PacketsOut = s.PacketsOut, ErrorsIn = s.ErrorsIn, ErrorsOut = s.ErrorsOut, DropsIn = s.DropsIn, DropsOut = s.DropsOut,
        }).ToList();
    }

    public async Task<IpConfigSnapshot?> ReadIpConfigAsync(CancellationToken ct)
    {
        if (commands is not { IsScripted: true }) return Core.Platform.NetworkInfoReader.ReadIpConfig();
        var ipRes = await commands.RunPowerShellAsync(IpConfigScript, ct).ConfigureAwait(false);
        return ipRes is { ExitCode: 0 } ? WifiConfigModule.ParseIpSnapshot(ipRes.StdOut) : null;
    }

    /// <summary>Fills blank counters from Get-NetAdapterStatistics rows (matched on adapter name = connection name).</summary>
    public static List<NetworkAdapter> MergeStatistics(IReadOnlyList<NetworkAdapter> adapters, IReadOnlyList<IReadOnlyDictionary<string, string>> stats)
    {
        var byName = stats.GroupBy(r => r.Str("Name"), StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
        return adapters.Select(a => a.HasCounters || !byName.TryGetValue(a.Name, out var r) ? a : a with
        {
            PacketsIn = r.Long("ipackets"), PacketsOut = r.Long("opackets"), ErrorsIn = r.Long("ierrors"), ErrorsOut = r.Long("oerrors"),
            DropsIn = r.Long("idrops"), DropsOut = r.Long("odrops"),
        }).ToList();
    }
}
