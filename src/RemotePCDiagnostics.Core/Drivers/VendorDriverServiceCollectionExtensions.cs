using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Bios;
using RemotePCDiagnostics.Core.DataSources;

namespace RemotePCDiagnostics.Core.Drivers;

public static class VendorDriverServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="VendorDriverUpdates"/> with the HP, Lenovo and Dell catalogs (after <see cref="BiosServiceCollectionExtensions.AddBiosUpdates"/>,
    /// whose system probe it shares). The Drivers check adds their newer packages to its driver-updates card.
    /// </summary>
    public static IServiceCollection AddVendorDriverUpdates(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddSingleton<IDriverInventory>(sp => new WindowsDriverInventory(sp.GetService<IWmiSource>(), sp.GetService<IRegistrySource>()));
        services.TryAddSingleton(sp =>
        {
            var commands = sp.GetService<SystemCommandRunner>();
            return new VendorDriverUpdates(sp.GetRequiredService<IBiosSystemProbe>(),
                [new HpDriverCatalog(commands: commands), new LenovoDriverCatalog(), new DellDriverCatalog(commands: commands)],
                sp.GetRequiredService<IDriverInventory>(),
                sp.GetService<Microsoft.Extensions.Logging.ILoggerFactory>()?.CreateLogger(typeof(VendorDriverUpdates).FullName!));
        });
        return services;
    }
}
