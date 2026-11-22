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

    /// <summary>
    /// Registers a pluggable vendor <see cref="IBiosUpdateProvider"/> implementation.
    /// When <typeparamref name="TProvider"/> is one of the 9 built-in vendor providers, it is wired
    /// through the same DI factory used by <see cref="AddBuiltInBiosUpdateProviders"/> so optional
    /// <see cref="HttpClient"/>, <see cref="HttpMessageHandler"/>, <see cref="SystemCommandRunner"/>,
    /// <see cref="IBiosSignatureVerifier"/>, <see cref="IBiosWindowsUpdateClient"/>,
    /// <see cref="IElevatedCommandBridge"/>, <see cref="IElevationContext"/>, and
    /// <see cref="Microsoft.Extensions.Logging.ILoggerFactory"/> dependencies are honored identically
    /// whether registered standalone, before, or after <see cref="AddBuiltInBiosUpdateProviders"/>.
    /// </summary>
    public static IServiceCollection AddBiosUpdateProvider<TProvider>(this IServiceCollection services)
        where TProvider : class, IBiosUpdateProvider
    {
        ArgumentNullException.ThrowIfNull(services);
        if (TryAddBuiltInProvider(services, typeof(TProvider)))
            return services;

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IBiosUpdateProvider, TProvider>());
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

    /// <summary>
    /// Registers all 9 built-in vendor <see cref="IBiosUpdateProvider"/> implementations as singletons:
    /// HP, Dell, Lenovo, ASUS, Acer, MSI, Microsoft Surface, Framework (Priority 100), and
    /// Windows Update UEFI capsule fallback (Priority 10).
    /// Idempotent and deduplicated via <see cref="ServiceCollectionDescriptorExtensions.TryAddEnumerable(IServiceCollection, ServiceDescriptor)"/>.
    /// All optional dependencies (<see cref="HttpClient"/>, <see cref="HttpMessageHandler"/>,
    /// <see cref="SystemCommandRunner"/>, <see cref="IBiosSignatureVerifier"/>,
    /// <see cref="IBiosWindowsUpdateClient"/>, <see cref="IElevatedCommandBridge"/>,
    /// <see cref="IElevationContext"/>, and <see cref="Microsoft.Extensions.Logging.ILoggerFactory"/>)
    /// are resolved if registered and safely defaulted otherwise.
    /// </summary>
    /// <remarks>
    /// Security requirement: if a custom <see cref="HttpClient"/> is registered in DI, its underlying handler
    /// must disable automatic redirects (<c>AllowAutoRedirect = false</c>) so per-hop
    /// <see cref="BiosPackageVerifier.IsSafeDownloadUrl"/> validation in <see cref="BiosProviderHttp"/> is preserved.
    /// When no <see cref="HttpClient"/> or <see cref="HttpMessageHandler"/> is registered, providers share
    /// <see cref="BiosProviderHttp.SharedClient"/> which enforces <c>AllowAutoRedirect = false</c>.
    /// </remarks>
    public static IServiceCollection AddBuiltInBiosUpdateProviders(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        foreach (var providerType in BuiltInProviderTypes)
            TryAddBuiltInProvider(services, providerType);

        return services;
    }

    private static readonly Type[] BuiltInProviderTypes =
    [
        typeof(HpBiosUpdateProvider),
        typeof(DellBiosUpdateProvider),
        typeof(LenovoBiosUpdateProvider),
        typeof(AsusBiosUpdateProvider),
        typeof(AcerBiosUpdateProvider),
        typeof(MsiBiosUpdateProvider),
        typeof(MicrosoftSurfaceBiosUpdateProvider),
        typeof(FrameworkBiosUpdateProvider),
        typeof(WindowsUpdateBiosProvider),
    ];

    private static bool TryAddBuiltInProvider(IServiceCollection services, Type providerType)
    {
        if (providerType == typeof(HpBiosUpdateProvider))
        {
            services.TryAddSingleton(sp => new BiosProviderHttpClientHolder(sp));
            services.TryAddEnumerable(ServiceDescriptor.Singleton<IBiosUpdateProvider, HpBiosUpdateProvider>(sp =>
                new HpBiosUpdateProvider(
                    httpClient: ResolveHttpClient(sp),
                    commands: sp.GetService<SystemCommandRunner>(),
                    signatureVerifier: sp.GetService<IBiosSignatureVerifier>(),
                    elevatedBridge: sp.GetService<IElevatedCommandBridge>(),
                    isProcessElevated: ResolveElevationCheck(sp),
                    log: CreateLogger<HpBiosUpdateProvider>(sp))));
            return true;
        }

        if (providerType == typeof(DellBiosUpdateProvider))
        {
            services.TryAddSingleton(sp => new BiosProviderHttpClientHolder(sp));
            services.TryAddEnumerable(ServiceDescriptor.Singleton<IBiosUpdateProvider, DellBiosUpdateProvider>(sp =>
                new DellBiosUpdateProvider(
                    httpClient: ResolveHttpClient(sp),
                    commands: sp.GetService<SystemCommandRunner>(),
                    signatureVerifier: sp.GetService<IBiosSignatureVerifier>(),
                    elevatedBridge: sp.GetService<IElevatedCommandBridge>(),
                    isProcessElevated: ResolveElevationCheck(sp),
                    log: CreateLogger<DellBiosUpdateProvider>(sp))));
            return true;
        }

        if (providerType == typeof(LenovoBiosUpdateProvider))
        {
            services.TryAddSingleton(sp => new BiosProviderHttpClientHolder(sp));
            services.TryAddEnumerable(ServiceDescriptor.Singleton<IBiosUpdateProvider, LenovoBiosUpdateProvider>(sp =>
                new LenovoBiosUpdateProvider(
                    httpClient: ResolveHttpClient(sp),
                    commands: sp.GetService<SystemCommandRunner>(),
                    signatureVerifier: sp.GetService<IBiosSignatureVerifier>(),
                    elevatedBridge: sp.GetService<IElevatedCommandBridge>(),
                    isProcessElevated: ResolveElevationCheck(sp),
                    log: CreateLogger<LenovoBiosUpdateProvider>(sp))));
            return true;
        }

        if (providerType == typeof(AsusBiosUpdateProvider))
        {
            services.TryAddSingleton(sp => new BiosProviderHttpClientHolder(sp));
            services.TryAddEnumerable(ServiceDescriptor.Singleton<IBiosUpdateProvider, AsusBiosUpdateProvider>(sp =>
                new AsusBiosUpdateProvider(
                    httpClient: ResolveHttpClient(sp),
                    log: CreateLogger<AsusBiosUpdateProvider>(sp))));
            return true;
        }

        if (providerType == typeof(AcerBiosUpdateProvider))
        {
            services.TryAddSingleton(sp => new BiosProviderHttpClientHolder(sp));
            services.TryAddEnumerable(ServiceDescriptor.Singleton<IBiosUpdateProvider, AcerBiosUpdateProvider>(sp =>
                new AcerBiosUpdateProvider(
                    httpClient: ResolveHttpClient(sp),
                    log: CreateLogger<AcerBiosUpdateProvider>(sp))));
            return true;
        }

        if (providerType == typeof(MsiBiosUpdateProvider))
        {
            services.TryAddSingleton(sp => new BiosProviderHttpClientHolder(sp));
            services.TryAddEnumerable(ServiceDescriptor.Singleton<IBiosUpdateProvider, MsiBiosUpdateProvider>(sp =>
                new MsiBiosUpdateProvider(
                    httpClient: ResolveHttpClient(sp),
                    log: CreateLogger<MsiBiosUpdateProvider>(sp))));
            return true;
        }

        if (providerType == typeof(MicrosoftSurfaceBiosUpdateProvider))
        {
            services.TryAddSingleton(sp => new BiosProviderHttpClientHolder(sp));
            services.TryAddEnumerable(ServiceDescriptor.Singleton<IBiosUpdateProvider, MicrosoftSurfaceBiosUpdateProvider>(sp =>
                new MicrosoftSurfaceBiosUpdateProvider(
                    httpClient: ResolveHttpClient(sp),
                    commands: sp.GetService<SystemCommandRunner>(),
                    signatureVerifier: sp.GetService<IBiosSignatureVerifier>(),
                    elevatedBridge: sp.GetService<IElevatedCommandBridge>(),
                    isProcessElevated: ResolveElevationCheck(sp),
                    log: CreateLogger<MicrosoftSurfaceBiosUpdateProvider>(sp))));
            return true;
        }

        if (providerType == typeof(FrameworkBiosUpdateProvider))
        {
            services.TryAddSingleton(sp => new BiosProviderHttpClientHolder(sp));
            services.TryAddEnumerable(ServiceDescriptor.Singleton<IBiosUpdateProvider, FrameworkBiosUpdateProvider>(sp =>
                new FrameworkBiosUpdateProvider(
                    httpClient: ResolveHttpClient(sp),
                    commands: sp.GetService<SystemCommandRunner>(),
                    signatureVerifier: sp.GetService<IBiosSignatureVerifier>(),
                    elevatedBridge: sp.GetService<IElevatedCommandBridge>(),
                    isProcessElevated: ResolveElevationCheck(sp),
                    log: CreateLogger<FrameworkBiosUpdateProvider>(sp))));
            return true;
        }

        if (providerType == typeof(WindowsUpdateBiosProvider))
        {
            // WindowsUpdateBiosProvider uses WUA COM / Agent bridge only and never needs HttpClient.
            services.TryAddEnumerable(ServiceDescriptor.Singleton<IBiosUpdateProvider, WindowsUpdateBiosProvider>(sp =>
                new WindowsUpdateBiosProvider(
                    wuaClient: sp.GetService<IBiosWindowsUpdateClient>(),
                    commands: sp.GetService<SystemCommandRunner>(),
                    elevatedBridge: sp.GetService<IElevatedCommandBridge>(),
                    isProcessElevated: ResolveElevationCheck(sp),
                    log: CreateLogger<WindowsUpdateBiosProvider>(sp))));
            return true;
        }

        return false;
    }

    private static HttpClient ResolveHttpClient(IServiceProvider sp) =>
        sp.GetRequiredService<BiosProviderHttpClientHolder>().Client;

    private static Func<bool>? ResolveElevationCheck(IServiceProvider sp)
    {
        var elevation = sp.GetService<IElevationContext>();
        // Return null when IElevationContext is unregistered so providers cleanly fall through to
        // SystemCommandRunner.IsProcessElevated rather than shadowing it with DetectProcessElevated().
        return elevation is not null ? () => elevation.IsProcessElevated : null;
    }

    private static ILogger? CreateLogger<T>(IServiceProvider sp) =>
        sp.GetService<Microsoft.Extensions.Logging.ILoggerFactory>()?.CreateLogger(typeof(T).FullName!);

    /// <summary>
    /// Container-scoped holder that provides a single shared <see cref="HttpClient"/> to all HTTP-based
    /// built-in BIOS providers. Any DI-registered <see cref="HttpClient"/> must disable automatic redirects
    /// (<c>AllowAutoRedirect = false</c>) so per-hop <see cref="BiosPackageVerifier.IsSafeDownloadUrl"/>
    /// redirect validation is preserved.
    /// </summary>
    private sealed class BiosProviderHttpClientHolder : IDisposable
    {
        private readonly HttpClient? _ownedClient;

        public BiosProviderHttpClientHolder(IServiceProvider sp)
        {
            // Prefer an explicitly registered HttpClient (must have AllowAutoRedirect = false);
            // owned by DI/caller, so never disposed by this holder.
            var existing = sp.GetService<HttpClient>();
            if (existing is not null)
            {
                Client = existing;
                return;
            }

            // Otherwise wrap an injected HttpMessageHandler in a single shared HttpClient with
            // disposeHandler: false, disposed once by this holder without disposing the handler.
            var handler = sp.GetService<HttpMessageHandler>();
            if (handler is not null)
            {
                _ownedClient = BiosProviderHttp.CreateClient(handler);
                Client = _ownedClient;
                return;
            }

            // Fall back to the process-wide shared client (AllowAutoRedirect = false); never disposed here.
            Client = BiosProviderHttp.SharedClient;
        }

        public HttpClient Client { get; }

        public void Dispose() => _ownedClient?.Dispose();
    }
}
