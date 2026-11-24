using RemotePCDiagnostics.Core.Osquery;
using Microsoft.Extensions.DependencyInjection;
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

/// <inheritdoc cref="AgentOrFallbackBatteryPowerSource"/>
public sealed class AgentOrFallbackHardwareInventorySource(Session.IElevatedCommandBridge agent, IHardwareInventorySource withAgent, IHardwareInventorySource fallback) : IHardwareInventorySource
{
    private IHardwareInventorySource Current => agent.IsConnected ? withAgent : fallback;
    public Task<HardwareInventory> ReadAsync(IProgress<string>? progress, CancellationToken ct) => Current.ReadAsync(progress, ct);
    public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct) => Current.CheckAvailabilityAsync(ct);
}

/// <inheritdoc cref="AgentOrFallbackBatteryPowerSource"/>
public sealed class AgentOrFallbackServiceSource(Session.IElevatedCommandBridge agent, IServiceSource withAgent, IServiceSource fallback) : IServiceSource
{
    private IServiceSource Current => agent.IsConnected ? withAgent : fallback;
    public Task<IReadOnlyList<ServiceInfo>?> ReadServicesAsync(CancellationToken ct) => Current.ReadServicesAsync(ct);
    public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct) => Current.CheckAvailabilityAsync(ct);
}

/// <inheritdoc cref="AgentOrFallbackBatteryPowerSource"/>
public sealed class AgentOrFallbackDeviceDriverSource(Session.IElevatedCommandBridge agent, IDeviceDriverSource withAgent, IDeviceDriverSource fallback) : IDeviceDriverSource
{
    private IDeviceDriverSource Current => agent.IsConnected ? withAgent : fallback;
    public Task<IReadOnlyList<ProblemDevice>?> ReadProblemDevicesAsync(CancellationToken ct) => Current.ReadProblemDevicesAsync(ct);
    public Task<IReadOnlyList<DriverEntry>?> ReadDriversAsync(CancellationToken ct) => Current.ReadDriversAsync(ct);
    public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct) => Current.CheckAvailabilityAsync(ct);
}

/// <inheritdoc cref="AgentOrFallbackBatteryPowerSource"/>
public sealed class AgentOrFallbackProgramsSource(Session.IElevatedCommandBridge agent, IProgramsSource withAgent, IProgramsSource fallback) : IProgramsSource
{
    private IProgramsSource Current => agent.IsConnected ? withAgent : fallback;
    public Task<WindowsVersionRead> ReadWindowsVersionAsync(CancellationToken ct) => Current.ReadWindowsVersionAsync(ct);
    public Task<IReadOnlyList<InstalledUpdate>?> ReadUpdatesAsync(CancellationToken ct) => Current.ReadUpdatesAsync(ct);
    public Task<IReadOnlyList<InstalledProgram>?> ReadProgramsAsync(CancellationToken ct) => Current.ReadProgramsAsync(ct);
    public Task<ModuleAvailability> CheckAvailabilityAsync(CancellationToken ct) => Current.CheckAvailabilityAsync(ct);
}

/// <summary>Registers the readers the checks use, over the <see cref="IWmiSource"/> and <see cref="IRegistrySource"/> already registered.</summary>
public static class ReaderRegistration
{
    /// <summary>Store apps come from <see cref="IPackageSource"/> when the app registers one (the Windows package API); otherwise none.</summary>
    public static IServiceCollection AddReaders(this IServiceCollection services) => services
        .TryAddPackages()
        .AddSingleton<IBatteryPowerSource>(sp => new WmiBatteryPowerSource(sp.GetRequiredService<IWmiSource>()))
        .AddSingleton<IDriveSource>(sp => new WmiDriveSource(sp.GetRequiredService<IWmiSource>()))
        .AddSingleton<IHardwareInventorySource>(sp => new WmiHardwareInventorySource(sp.GetRequiredService<IWmiSource>()))
        .AddSingleton<IServiceSource>(sp => new WmiServiceSource(sp.GetRequiredService<IWmiSource>()))
        .AddSingleton<IDeviceDriverSource>(sp => new WmiDeviceDriverSource(sp.GetRequiredService<IWmiSource>()))
        .AddSingleton<INetworkSource>(sp => new WmiNetworkSource(sp.GetRequiredService<IWmiSource>(), sp.GetRequiredService<IRegistrySource>()))
        .AddSingleton<IProgramsSource>(sp => new WmiProgramsSource(sp.GetRequiredService<IWmiSource>(), sp.GetRequiredService<IRegistrySource>(),
            sp.GetRequiredService<IPackageSource>()))
        .AddSingleton<Security.ISecurityEssentialsSource>(sp => new Security.WmiSecurityEssentialsSource(sp.GetRequiredService<IWmiSource>(),
            sp.GetRequiredService<IRegistrySource>(), sp.GetRequiredService<SystemCommandRunner>()))
        .AddSingleton<IResourceHogsSource>(sp => new WmiResourceHogsSource(
            sp.GetRequiredService<IWmiSource>(),
            sp.GetRequiredService<IRegistrySource>(),
            monotonicUptimeSeconds: OperatingSystem.IsWindows() ? () => Environment.TickCount64 / 1000 : null))
        .AddSingleton<ICrashDumpSource>(sp => new WmiCrashDumpSource(sp.GetRequiredService<IWmiSource>()));

    private static IServiceCollection TryAddPackages(this IServiceCollection services)
    {
        Microsoft.Extensions.DependencyInjection.Extensions.ServiceCollectionDescriptorExtensions.TryAddSingleton<IPackageSource, NoPackageSource>(services);
        return services;
    }
}
