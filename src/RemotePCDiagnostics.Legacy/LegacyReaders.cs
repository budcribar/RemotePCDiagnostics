using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Legacy;

/// <summary>Registers the Store edition's readers: the Agent's when it is connected, these otherwise.</summary>
public static class LegacyReaders
{
    /// <summary>Replaces the Agent-only readers (battery, drives, hardware, services, drivers, programs, security essentials) with Agent-or-legacy ones.</summary>
    public static IServiceCollection AddLegacyFallbacks(this IServiceCollection services) => services
        .AddSingleton<IBatteryPowerSource>(sp => new AgentOrFallbackBatteryPowerSource(sp.GetRequiredService<IElevatedCommandBridge>(),
            new WmiBatteryPowerSource(sp.GetRequiredService<Core.DataSources.IWmiSource>()),
            new OsqueryBatteryPowerSource(sp.GetRequiredService<OsqueryRunner>(), sp.GetRequiredService<SystemCommandRunner>())))
        .AddSingleton<IDriveSource>(sp => new AgentOrFallbackDriveSource(sp.GetRequiredService<IElevatedCommandBridge>(),
            new WmiDriveSource(sp.GetRequiredService<Core.DataSources.IWmiSource>()),
            new PowerShellDriveSource(sp.GetRequiredService<SystemCommandRunner>(), sp.GetRequiredService<OsqueryRunner>())))
        .AddSingleton<IHardwareInventorySource>(sp => new AgentOrFallbackHardwareInventorySource(sp.GetRequiredService<IElevatedCommandBridge>(),
            new WmiHardwareInventorySource(sp.GetRequiredService<Core.DataSources.IWmiSource>()),
            new OsqueryHardwareInventorySource(sp.GetRequiredService<OsqueryRunner>())))
        .AddSingleton<IServiceSource>(sp => new AgentOrFallbackServiceSource(sp.GetRequiredService<IElevatedCommandBridge>(),
            new WmiServiceSource(sp.GetRequiredService<Core.DataSources.IWmiSource>()),
            new OsqueryServiceSource(sp.GetRequiredService<OsqueryRunner>())))
        .AddSingleton<IDeviceDriverSource>(sp => new AgentOrFallbackDeviceDriverSource(sp.GetRequiredService<IElevatedCommandBridge>(),
            new WmiDeviceDriverSource(sp.GetRequiredService<Core.DataSources.IWmiSource>()),
            new OsqueryDeviceDriverSource(sp.GetRequiredService<OsqueryRunner>(), sp.GetRequiredService<SystemCommandRunner>())))
        // Programs read the registry in the app either way; only the Windows version and updates need the Agent's WMI.
        .AddSingleton<IProgramsSource>(sp => new AgentOrFallbackProgramsSource(sp.GetRequiredService<IElevatedCommandBridge>(),
            new WmiProgramsSource(sp.GetRequiredService<Core.DataSources.IWmiSource>(), sp.GetRequiredService<Core.DataSources.IRegistrySource>()),
            new OsqueryProgramsSource(sp.GetRequiredService<OsqueryRunner>())))
        .AddSingleton<Core.Security.ISecurityEssentialsSource>(sp => new Core.Security.AgentOrFallbackSecurityEssentialsSource(sp.GetRequiredService<IElevatedCommandBridge>(),
            new Core.Security.WmiSecurityEssentialsSource(sp.GetRequiredService<Core.DataSources.IWmiSource>(), sp.GetRequiredService<Core.DataSources.IRegistrySource>(),
                sp.GetRequiredService<SystemCommandRunner>()),
            new PowerShellSecurityEssentialsSource(sp.GetRequiredService<SystemCommandRunner>())));
}

/// <summary>Batteries from osquery <c>battery</c>, the plan from <c>powercfg /getactivescheme</c>. Both work as a standard user.</summary>
public sealed class OsqueryBatteryPowerSource(OsqueryRunner osquery, SystemCommandRunner? commands = null) : IBatteryPowerSource
{
    public const string BatterySql = "SELECT * FROM battery;";
    public static string PowerCfg => SystemCommandRunner.SystemTool("powercfg.exe");

    /// <summary>
    /// On Windows, osquery's <c>battery</c> table divides the capacities Windows reports in mWh by an assumed 12 V, to show them in
    /// mAh like its macOS table (osquery/tables/system/windows/battery.cpp). Multiplying back gives mWh again, to within 12 mWh.
    /// </summary>
    public const int OsqueryAssumedVolts = 12;

    public async Task<IReadOnlyList<BatteryStatus>?> ReadBatteriesAsync(CancellationToken ct)
    {
        if (!osquery.Exists) return null;
        var q = await osquery.RunQueryAsync(BatterySql, ct).ConfigureAwait(false);
        return q.Success ? q.Rows!.Select(FromRow).ToList() : null;
    }

    public async Task<string?> ReadActivePlanAsync(CancellationToken ct)
    {
        if (commands is null) return null;
        var pr = await commands.RunAsync(PowerCfg, ["/getactivescheme"], ct).ConfigureAwait(false);
        return pr is { ExitCode: 0 } ? ParsePowerPlan(pr.StdOut) : null;
    }

    public static string? ParsePowerPlan(string? stdout)
    {
        if (string.IsNullOrWhiteSpace(stdout)) return null;
        var open = stdout.LastIndexOf('(');
        var close = stdout.LastIndexOf(')');
        if (open >= 0 && close > open + 1)
            return stdout[(open + 1)..close].Trim();
        return stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault();
    }

    /// <summary>One row of osquery <c>battery</c>, with the capacities in mWh.</summary>
    public static BatteryStatus FromRow(IReadOnlyDictionary<string, string> r) => new(
        r.Str("model"), r.Str("manufacturer"), Chemistry(r.Str("chemistry")), r.Str("state"),
        r.Int("percent_remaining") is >= 0 and <= 100 and var pct ? pct : null, ToMilliwattHours(r.Int("designed_capacity")),
        ToMilliwattHours(r.Int("max_capacity")), r.Int("cycle_count"));

    /// <summary>
    /// The chemistry is four letters at most. osquery copies the driver's 4-byte field as a C string, so without a terminating zero it runs on
    /// into whatever follows ("LION\u0018τ" on an HP OmniBook X): keep the leading printable letters, as the WMI path does.
    /// </summary>
    public static string Chemistry(string s)
    {
        var n = 0;
        while (n < s.Length && n < 4 && s[n] is >= ' ' and <= '~') n++;
        return s[..n].Trim();
    }

    /// <summary>Back to mWh; null when the driver didn't know the capacity (osquery passes BATTERY_UNKNOWN_CAPACITY through, divided by 12).</summary>
    private static int? ToMilliwattHours(int? osqueryMilliampHours) =>
        osqueryMilliampHours is { } v && BatteryReader.Capacity((long)v * OsqueryAssumedVolts) is { } mWh ? (int)mWh : null;
}

/// <summary>
/// Drives from the Get-PhysicalDisk / Get-StorageReliabilityCounter script (as a standard user the counters are empty); when that fails,
/// the drive list from osquery <c>disk_info</c>, with health not reported.
/// </summary>
public sealed class PowerShellDriveSource(SystemCommandRunner commands, OsqueryRunner osquery) : IDriveSource
{
    public const string ListOnlyNotice = "Windows didn't report drive health on this PC, so only the drive list is shown.";

    public static string Script { get; } = Load("DriveHealth");

    public async Task<DriveList?> ReadDrivesAsync(CancellationToken ct)
    {
        var pr = await commands.RunPowerShellAsync(Script, ct).ConfigureAwait(false);
        if (pr is { ExitCode: 0 })
        {
            try
            {
                if (OsqueryJson.ParseRows(pr.StdOut).Select(DriveHealth.FromRow).ToList() is { Count: > 0 } drives) return new(drives);
            }
            catch (FormatException ex) { commands.Log.Warn($"DriveHealth: storage health output unreadable: {ex.Message}"); }
        }
        commands.Log.Warn("DriveHealth: Windows storage health unavailable; falling back to osquery disk_info (no health data)");
        var q = await osquery.RunQueryAsync(HardwareInventory.DiskSql, ct).ConfigureAwait(false);
        if (q is not { Success: true }) return null;
        var list = q.Rows!.Select(DiskInfo.FromRow)
            .Select(d => new DriveHealth(d.HardwareModel, d.Serial, "", d.Type, "", "", d.SizeBytes, null, null, null, null, null)).ToList();
        return list.Count > 0 ? new(list, ListOnlyNotice) : null;
    }

    private static string Load(string name)
    {
        using var stream = typeof(PowerShellDriveSource).Assembly.GetManifestResourceStream($"Legacy/{name}.ps1")
            ?? throw new InvalidOperationException($"No embedded script named {name}.");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd().Trim().TrimStart('﻿');
    }
}
