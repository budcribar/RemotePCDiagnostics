using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Core.Bios;

/// <summary>DI registration helpers for the pluggable BIOS update subsystem and vendor providers.</summary>
public static class BiosServiceCollectionExtensions
{
    /// <summary>
    /// Registers the vendor-independent BIOS update orchestrator (<see cref="IBiosUpdateService"/>) and its default
    /// system/safety probes (<see cref="IBiosSystemProbe"/>, <see cref="IBiosInstallSafetyProbe"/>).
    /// Call <see cref="AddBiosUpdateProvider{TProvider}"/> to register one or more vendor implementations.
    /// </summary>
    public static IServiceCollection AddBiosUpdates(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<IBiosSystemProbe>(sp => new DefaultBiosSystemProbe(
            sp.GetService<DataSources.IWmiSource>(),
            sp.GetService<Microsoft.Extensions.Logging.ILoggerFactory>()?.CreateLogger(typeof(DefaultBiosSystemProbe).FullName!)));

        services.TryAddSingleton<IBiosInstallSafetyProbe>(sp => new DefaultBiosInstallSafetyProbe(
            sp.GetService<IElevationContext>(),
            sp.GetService<SystemCommandRunner>(),
            sp.GetService<Microsoft.Extensions.Logging.ILoggerFactory>()?.CreateLogger(typeof(DefaultBiosInstallSafetyProbe).FullName!)));

        services.TryAddSingleton<IBiosUpdateService>(sp => new BiosUpdateService(
            sp.GetRequiredService<IBiosSystemProbe>(),
            sp.GetRequiredService<IBiosInstallSafetyProbe>(),
            sp.GetServices<IBiosUpdateProvider>(),
            sp.GetService<Microsoft.Extensions.Logging.ILoggerFactory>()?.CreateLogger(typeof(BiosUpdateService).FullName!)));

        return services;
    }

    /// <summary>Registers a pluggable vendor <see cref="IBiosUpdateProvider"/> implementation.</summary>
    public static IServiceCollection AddBiosUpdateProvider<TProvider>(this IServiceCollection services)
        where TProvider : class, IBiosUpdateProvider
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddSingleton<IBiosUpdateProvider, TProvider>();
        return services;
    }

    /// <summary>Registers a pluggable vendor <see cref="IBiosUpdateProvider"/> using a factory delegate.</summary>
    public static IServiceCollection AddBiosUpdateProvider(
        this IServiceCollection services,
        Func<IServiceProvider, IBiosUpdateProvider> factory)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(factory);
        services.AddSingleton(factory);
        return services;
    }
}
