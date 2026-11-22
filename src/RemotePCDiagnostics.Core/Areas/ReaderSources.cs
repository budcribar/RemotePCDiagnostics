using RemotePCDiagnostics.Core.DataSources;

namespace RemotePCDiagnostics.Core.Areas;

/// <summary>
/// Where BatteryPower reads from. The app registers <see cref="WmiBatteryPowerSource"/> (WMI, through the Agent); the Store edition, which
/// may have no Agent, also has the legacy osquery + powercfg source (RemotePCDiagnostics.Legacy) for when the Agent isn't connected.
/// </summary>
public interface IBatteryPowerSource
{
    /// <summary>The batteries; empty when the PC has none, null when they couldn't be read.</summary>
    Task<IReadOnlyList<BatteryStatus>?> ReadBatteriesAsync(CancellationToken ct);
    /// <summary>The active power plan's name, or null.</summary>
    Task<string?> ReadActivePlanAsync(CancellationToken ct);
}

/// <summary>Where DriveHealth reads the drives from (see <see cref="IBatteryPowerSource"/> for which one the app uses).</summary>
public interface IDriveSource
{
    /// <summary>The drives, or null when they couldn't be read.</summary>
    Task<DriveList?> ReadDrivesAsync(CancellationToken ct);
}

/// <param name="Notice">Shown above the report, for instance when only the drive list (no health) could be read.</param>
public sealed record DriveList(IReadOnlyList<DriveHealth> Drives, string? Notice = null);

public sealed class WmiBatteryPowerSource(IWmiSource wmi) : IBatteryPowerSource
{
    public const string PowerPlanNamespace = @"root\cimv2\power";
    public const string ActivePlanSql = "SELECT ElementName FROM Win32_PowerPlan WHERE IsActive = TRUE";

    public Task<IReadOnlyList<BatteryStatus>?> ReadBatteriesAsync(CancellationToken ct) => BatteryReader.ReadWmiAsync(wmi, ct);

    public async Task<string?> ReadActivePlanAsync(CancellationToken ct)
    {
        var q = await wmi.QueryAsync(PowerPlanNamespace, ActivePlanSql, ct).ConfigureAwait(false);
        return q.Rows?.Select(r => r.Str("ElementName").Trim()).FirstOrDefault(n => n.Length > 0);
    }
}

public sealed class WmiDriveSource(IWmiSource wmi) : IDriveSource
{
    public async Task<DriveList?> ReadDrivesAsync(CancellationToken ct) =>
        await DriveReader.ReadWmiAsync(wmi, ct).ConfigureAwait(false) is { Count: > 0 } drives ? new DriveList(drives) : null;
}

/// <summary>In the module host (user mode): the app reads the drives for it (<c>storage.drives</c>), with the app's own source.</summary>
public sealed class HostDriveSource(Plugins.IHostQueries host, string module, ILogger? log = null) : IDriveSource
{
    public Task<DriveList?> ReadDrivesAsync(CancellationToken ct) =>
        Plugins.HostQueryExtensions.AskAsync(host, module, log, h => h.ReadDrivesAsync(ct));
}

/// <summary>Picks a source per read: the Agent's when it is connected, otherwise the fallback (the Store edition's legacy readers).</summary>
public sealed class AgentOrFallbackBatteryPowerSource(Session.IElevatedCommandBridge agent, IBatteryPowerSource withAgent, IBatteryPowerSource fallback) : IBatteryPowerSource
{
    private IBatteryPowerSource Current => agent.IsConnected ? withAgent : fallback;
    public Task<IReadOnlyList<BatteryStatus>?> ReadBatteriesAsync(CancellationToken ct) => Current.ReadBatteriesAsync(ct);
    public Task<string?> ReadActivePlanAsync(CancellationToken ct) => Current.ReadActivePlanAsync(ct);
}

/// <inheritdoc cref="AgentOrFallbackBatteryPowerSource"/>
public sealed class AgentOrFallbackDriveSource(Session.IElevatedCommandBridge agent, IDriveSource withAgent, IDriveSource fallback) : IDriveSource
{
    public Task<DriveList?> ReadDrivesAsync(CancellationToken ct) => (agent.IsConnected ? withAgent : fallback).ReadDrivesAsync(ct);
}
