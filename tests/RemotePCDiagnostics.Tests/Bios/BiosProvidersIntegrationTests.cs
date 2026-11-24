using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Bios;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests.Bios;

/// <summary>
/// Integration tests for Milestone M5 (Feature F19): <see cref="BiosServiceCollectionExtensions.AddBuiltInBiosUpdateProviders"/>,
/// <c>HostServices.cs</c> composition-root wiring, deterministic 9-provider priority ordering,
/// full OEM/UEFI/Legacy routing matrix, boundary DI injection, and live cross-platform Agent elevation bridge round-trips.
/// </summary>
public sealed class BiosProvidersIntegrationTests
{
    private static readonly Guid SampleWuaUpdateId = Guid.Parse("11112222-3333-4444-5555-666677778888");
    private const string HpDefaultCatalogUrl = "https://hpia.hpcloud.hp.com/ref/880d/880d_64_11.0.cab";
    private const string HpDownloadUrl = "https://ftp.hp.com/pub/softpaq/sp151234.exe";
    private const string ValidSha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    private const string SampleHpCatalogXml = """
        <?xml version="1.0" encoding="utf-8"?>
        <ImagePal>
          <Solutions>
            <UpdateInfo>
              <Id>sp151234</Id>
              <Category>BIOS</Category>
              <Name>HP Notebook System BIOS Update (T76)</Name>
              <Version>01.15.00 Rev.A</Version>
              <DateReleased>2024-05-10</DateReleased>
              <Severity>Critical</Severity>
              <Size>31457280</Size>
              <SHA256>0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF</SHA256>
              <Url>ftp.hp.com/pub/softpaq/sp151234.exe</Url>
              <CvaUrl>https://ftp.hp.com/pub/softpaq/sp151234.cva</CvaUrl>
              <Description>Critical security and UEFI stability update for T76 family.</Description>
            </UpdateInfo>
          </Solutions>
        </ImagePal>
        """;

    private const string SampleAsusCatalogJson = """
        {
          "Result": {
            "Obj": [
              {
                "Name": "BIOS",
                "Files": [
                  {
                    "Id": "asus-3201",
                    "Version": "Version 3201",
                    "Title": "ROG STRIX Z690-E GAMING WIFI BIOS 3201",
                    "Description": "Improve system stability.",
                    "ReleaseDate": "2024/08/15",
                    "FileSize": "16.45 MBytes",
                    "Sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    "ReleaseNotesUrl": "https://www.asus.com/support/faq/1044348/",
                    "DownloadUrl": {
                      "Global": "https://dlcdnets.asus.com/pub/ASUS/mb/BIOS/ROG-STRIX-Z690-E-GAMING-WIFI-ASUS-3201.ZIP"
                    }
                  }
                ]
              }
            ]
          }
        }
        """;

    private static readonly ServiceProviderOptions StrictValidation = new()
    {
        ValidateOnBuild = true,
        ValidateScopes = true,
    };

    private static readonly HashSet<string> ForbiddenShellBinaries = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell", "powershell.exe", "pwsh", "pwsh.exe",
        "cmd", "cmd.exe", "sh", "bash", "zsh",
    };

    private static readonly string[] ForbiddenScriptExtensions = [".ps1", ".bat", ".cmd", ".sh"];

    private static readonly string[] ExpectedOrderedVendorIds =
    [
        "acer",
        "asus",
        "dell",
        "framework",
        "hp",
        "lenovo",
        "microsoft",
        "msi",
        "windows-update",
    ];

    // =========================================================================
    // Group 1 — Exact 9 Providers, Priority Order & Capabilities Matrix
    // =========================================================================

    [Fact]
    public void AddBuiltInBiosUpdateProviders_RegistersExactNineProvidersInDeterministicPriorityOrderWithContractCapabilities()
    {
        var services = new ServiceCollection();
        services.AddBiosUpdates();
        services.AddBuiltInBiosUpdateProviders();

        using var sp = services.BuildServiceProvider(StrictValidation);
        var service = sp.GetRequiredService<IBiosUpdateService>();

        Assert.Equal(9, service.Providers.Count);

        var expected = new (
            Type ConcreteType,
            string VendorId,
            string DisplayName,
            int Priority,
            bool CanCheckLatest,
            bool CanInstall,
            bool SupportsSilentInstall,
            bool RequiresReboot,
            bool RequiresElevation,
            bool RequiresInternet)[]
        {
            (typeof(AcerBiosUpdateProvider), "acer", "Acer", 100, true, false, false, false, false, true),
            (typeof(AsusBiosUpdateProvider), "asus", "ASUS", 100, true, false, false, false, false, true),
            (typeof(DellBiosUpdateProvider), "dell", "Dell", 100, true, true, true, true, true, true),
            (typeof(FrameworkBiosUpdateProvider), "framework", "Framework", 100, true, true, true, true, true, true),
            (typeof(HpBiosUpdateProvider), "hp", "HP", 100, true, true, true, true, true, true),
            (typeof(LenovoBiosUpdateProvider), "lenovo", "Lenovo", 100, true, true, true, true, true, true),
            (typeof(MicrosoftSurfaceBiosUpdateProvider), "microsoft", "Microsoft Surface", 100, true, true, true, true, true, true),
            (typeof(MsiBiosUpdateProvider), "msi", "MSI", 100, true, false, false, false, false, true),
            (typeof(WindowsUpdateBiosProvider), "windows-update", "Windows Update", 10, true, true, true, true, true, true),
        };

        for (var i = 0; i < expected.Length; i++)
        {
            var actual = service.Providers[i];
            var exp = expected[i];

            Assert.IsType(exp.ConcreteType, actual);
            Assert.Equal(exp.VendorId, actual.VendorId);
            Assert.Equal(exp.DisplayName, actual.DisplayName);
            Assert.Equal(exp.Priority, actual.Priority);
            Assert.Equal(exp.CanCheckLatest, actual.Capabilities.CanCheckLatest);
            Assert.Equal(exp.CanInstall, actual.Capabilities.CanInstall);
            Assert.Equal(exp.SupportsSilentInstall, actual.Capabilities.SupportsSilentInstall);
            Assert.Equal(exp.RequiresReboot, actual.Capabilities.RequiresReboot);
            Assert.Equal(exp.RequiresElevation, actual.Capabilities.RequiresElevation);
            Assert.Equal(exp.RequiresInternet, actual.Capabilities.RequiresInternet);
        }
    }

    // =========================================================================
    // Group 2 — Container Validation (ValidateOnBuild & ValidateScopes)
    // =========================================================================

    [Fact]
    public void AddBuiltInBiosUpdateProviders_MinimalDi_ZeroOptionalServices_ValidatesAndResolvesCleanly()
    {
        var services = new ServiceCollection();
        services.AddBiosUpdates();
        services.AddBuiltInBiosUpdateProviders();

        using var sp = services.BuildServiceProvider(StrictValidation);

        // Root resolution
        var service = sp.GetRequiredService<IBiosUpdateService>();
        var systemProbe = sp.GetRequiredService<IBiosSystemProbe>();
        var safetyProbe = sp.GetRequiredService<IBiosInstallSafetyProbe>();
        var providers = sp.GetServices<IBiosUpdateProvider>().ToList();

        Assert.NotNull(systemProbe);
        Assert.NotNull(safetyProbe);
        Assert.Equal(9, providers.Count);
        Assert.Equal(9, service.Providers.Count);
        Assert.Equal("hp", service.ResolveProvider(BiosIdentityFactory.Hp())?.VendorId);

        // Scoped resolution (also confirms singleton identity & ValidateScopes compatibility)
        using var scope = sp.CreateScope();
        var scopedService = scope.ServiceProvider.GetRequiredService<IBiosUpdateService>();
        Assert.Same(service, scopedService);
        Assert.Equal(9, scope.ServiceProvider.GetServices<IBiosUpdateProvider>().Count());

        // Emulate HostServicesTests.Every_app_service_resolves across all RemotePCDiagnostics.* descriptors
        var appTypes = services
            .Select(d => d.ServiceType)
            .Where(t => !t.IsGenericTypeDefinition && t.Namespace?.StartsWith("RemotePCDiagnostics", StringComparison.Ordinal) == true)
            .Distinct()
            .ToList();

        Assert.NotEmpty(appTypes);
        foreach (var type in appTypes)
            Assert.Contains(sp.GetServices(type), s => s is not null);
    }

    [Fact]
    public void AddBuiltInBiosUpdateProviders_FullBoundaryDoubles_HostAndE2eShape_ValidatesAndResolvesCleanly()
    {
        using var httpHandler = new FakeBiosHttpHandler();
        using var httpClient = httpHandler.CreateClient();
        var launcher = CreateGuardedLauncher();
        var elevation = new StubElevationContext(isProcessElevated: true, isAdminHelperConnected: false);
        var loggerFactory = new CapturingLoggerFactory();
        var bridge = new StubElevatedCommandBridge(isConnected: false);

        var services = new ServiceCollection();
        services.AddSingleton<IBiosSystemProbe>(new StubSystemProbe(BiosIdentityFactory.Hp()));
        services.AddSingleton<IBiosInstallSafetyProbe>(new StubSafetyProbe(BiosIdentityFactory.SafeSnapshot()));
        services.AddSingleton<HttpMessageHandler>(httpHandler);
        services.AddSingleton<HttpClient>(httpClient);
        services.AddSingleton<IElevationContext>(elevation);
        services.AddSingleton<IElevatedCommandBridge>(bridge);
        services.AddSingleton(new SystemCommandRunner(
            launcher: launcher,
            log: loggerFactory.CreateLogger(typeof(SystemCommandRunner).FullName!),
            elevatedBridge: bridge,
            isProcessElevated: () => elevation.IsProcessElevated));
        services.AddSingleton<IBiosSignatureVerifier>(new FakeSignatureVerifier(result: true));
        services.AddSingleton<IBiosWindowsUpdateClient>(new FakeWindowsUpdateClient());
        services.AddSingleton<Microsoft.Extensions.Logging.ILoggerFactory>(loggerFactory);

        services.AddBiosUpdates();
        services.AddBuiltInBiosUpdateProviders();

        using var sp = services.BuildServiceProvider(StrictValidation);
        var rootService = sp.GetRequiredService<IBiosUpdateService>();
        Assert.Equal(ExpectedOrderedVendorIds, rootService.Providers.Select(p => p.VendorId).ToArray());

        using var scope = sp.CreateScope();
        var scopedService = scope.ServiceProvider.GetRequiredService<IBiosUpdateService>();
        Assert.Same(rootService, scopedService);
    }

    [Fact]
    public void AddBuiltInBiosUpdateProviders_WorksRegardlessOfOrderRelativeToAddBiosUpdates()
    {
        var services = new ServiceCollection();
        services.AddBuiltInBiosUpdateProviders();
        services.AddBiosUpdates();

        using var sp = services.BuildServiceProvider(StrictValidation);
        var service = sp.GetRequiredService<IBiosUpdateService>();

        Assert.Equal(ExpectedOrderedVendorIds, service.Providers.Select(p => p.VendorId).ToArray());
    }

    [Fact]
    public async Task AddBuiltInBiosUpdateProviders_HttpClientAndHandlerRegisteredAfterProviders_StillReachProviders()
    {
        // Case A: HttpClient registered AFTER AddBuiltInBiosUpdateProviders()
        {
            using var handler = new FakeBiosHttpHandler();
            handler.MapText(HpDefaultCatalogUrl, SampleHpCatalogXml, "application/xml");
            using var client = handler.CreateClient();

            var services = new ServiceCollection();
            services.AddSingleton<IBiosSystemProbe>(new StubSystemProbe(BiosIdentityFactory.Hp()));
            services.AddBiosUpdates();
            services.AddBuiltInBiosUpdateProviders();
            services.AddSingleton<HttpClient>(client);

            using var sp = services.BuildServiceProvider(StrictValidation);
            var service = sp.GetRequiredService<IBiosUpdateService>();

            var result = await service.CheckForUpdateAsync();
            Assert.Equal("hp", result.ProviderId);
            Assert.Equal(BiosCheckStatus.UpdateAvailable, result.Latest.Status);
            Assert.Single(handler.Requests);
        }

        // Case B: HttpMessageHandler registered AFTER AddBuiltInBiosUpdateProviders() (without HttpClient)
        {
            using var inner = new FakeBiosHttpHandler();
            inner.MapText(HpDefaultCatalogUrl, SampleHpCatalogXml, "application/xml");
            using var tracking = new DisposeTrackingHttpHandler(inner);

            var services = new ServiceCollection();
            services.AddSingleton<IBiosSystemProbe>(new StubSystemProbe(BiosIdentityFactory.Hp()));
            services.AddBiosUpdates();
            services.AddBuiltInBiosUpdateProviders();
            services.AddSingleton<HttpMessageHandler>(tracking);

            using var sp = services.BuildServiceProvider(StrictValidation);
            var service = sp.GetRequiredService<IBiosUpdateService>();

            var result = await service.CheckForUpdateAsync();
            Assert.Equal("hp", result.ProviderId);
            Assert.Equal(BiosCheckStatus.UpdateAvailable, result.Latest.Status);
            Assert.Equal(1, tracking.RequestCount);
        }
    }

    [Fact]
    public async Task AddBuiltInBiosUpdateProviders_MinimalDi_DisposingContainerDoesNotDisposeSharedHttpClient()
    {
        var services = new ServiceCollection();
        services.AddBiosUpdates();
        services.AddBuiltInBiosUpdateProviders();

        using (var sp = services.BuildServiceProvider(StrictValidation))
        {
            var service = sp.GetRequiredService<IBiosUpdateService>();
            Assert.Equal(9, service.Providers.Count);
        }

        // Sending with an already-cancelled token never touches the network, but WOULD throw
        // ObjectDisposedException immediately if BiosProviderHttp.SharedClient had been disposed.
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        using var req = new HttpRequestMessage(HttpMethod.Get, "https://localhost.invalid/health");

        var ex = await Record.ExceptionAsync(() => BiosProviderHttp.SharedClient.SendAsync(req, cts.Token));
        Assert.NotNull(ex);
        Assert.IsNotType<ObjectDisposedException>(ex);
        Assert.IsAssignableFrom<OperationCanceledException>(ex);
    }

    // =========================================================================
    // Group 3 — Null Guard & Idempotency
    // =========================================================================

    [Fact]
    public void AddBuiltInBiosUpdateProviders_NullServices_ThrowsArgumentNullException()
    {
        IServiceCollection? nullServices = null;
        Assert.Throws<ArgumentNullException>("services", () => nullServices!.AddBuiltInBiosUpdateProviders());
    }

    [Theory]
    [InlineData(2)]
    [InlineData(3)]
    public void AddBuiltInBiosUpdateProviders_CalledMultipleTimes_IsIdempotentWithZeroDuplicates(int callCount)
    {
        var services = new ServiceCollection();
        services.AddBiosUpdates();
        for (var i = 0; i < callCount; i++)
            services.AddBuiltInBiosUpdateProviders();

        using var sp = services.BuildServiceProvider(StrictValidation);
        var service = sp.GetRequiredService<IBiosUpdateService>();

        Assert.Equal(9, service.Providers.Count);
        Assert.Equal(ExpectedOrderedVendorIds, service.Providers.Select(p => p.VendorId).ToArray());
    }

    [Fact]
    public void AddBuiltInBiosUpdateProviders_WithExplicitAddBiosUpdateProviderBeforeAndAfter_HasZeroDuplicates()
    {
        // Case A: AddBiosUpdateProvider<HpBiosUpdateProvider>() BEFORE AddBuiltInBiosUpdateProviders()
        {
            var services = new ServiceCollection();
            services.AddBiosUpdates();
            services.AddBiosUpdateProvider<HpBiosUpdateProvider>();
            services.AddBuiltInBiosUpdateProviders();

            using var sp = services.BuildServiceProvider(StrictValidation);
            var service = sp.GetRequiredService<IBiosUpdateService>();

            Assert.Equal(9, service.Providers.Count);
            Assert.Equal(1, service.Providers.Count(p => p.VendorId == "hp"));
            Assert.Equal(ExpectedOrderedVendorIds, service.Providers.Select(p => p.VendorId).ToArray());
        }

        // Case B: AddBuiltInBiosUpdateProviders() BEFORE AddBiosUpdateProvider<HpBiosUpdateProvider>()
        {
            var services = new ServiceCollection();
            services.AddBiosUpdates();
            services.AddBuiltInBiosUpdateProviders();
            services.AddBiosUpdateProvider<HpBiosUpdateProvider>();

            using var sp = services.BuildServiceProvider(StrictValidation);
            var service = sp.GetRequiredService<IBiosUpdateService>();

            Assert.Equal(9, service.Providers.Count);
            Assert.Equal(1, service.Providers.Count(p => p.VendorId == "hp"));
            Assert.Equal(ExpectedOrderedVendorIds, service.Providers.Select(p => p.VendorId).ToArray());
        }
    }

    [Fact]
    public async Task AddBiosUpdateProvider_StandaloneBuiltInHp_WiresHttpMessageHandlerElevationContextAndLoggerFactory()
    {
        using var staging = new TempStagingDir();
        var payload = TestPayload.FromString("HP-STANDALONE-SOFTPAQ-PAYLOAD");
        using var inner = new FakeBiosHttpHandler();
        inner.MapText(HpDefaultCatalogUrl, SampleHpCatalogXml, "application/xml");
        inner.MapBytes(HpDownloadUrl, payload.Bytes);
        using var trackingHandler = new DisposeTrackingHttpHandler(inner);

        var launcher = CreateGuardedLauncher();
        var elevation = new StubElevationContext(isProcessElevated: true, isAdminHelperConnected: false);
        var loggerFactory = new CapturingLoggerFactory();
        var identity = BiosIdentityFactory.Hp();

        var services = new ServiceCollection();
        services.AddSingleton<IBiosSystemProbe>(new StubSystemProbe(identity));
        services.AddSingleton<IBiosInstallSafetyProbe>(sp => new ElevationAwareStubSafetyProbe(sp.GetRequiredService<IElevationContext>()));
        // Intentionally register HttpMessageHandler WITHOUT HttpClient
        services.AddSingleton<HttpMessageHandler>(trackingHandler);
        // Set SystemCommandRunner.IsProcessElevated = false while IElevationContext.IsProcessElevated = true
        // to prove HpBiosUpdateProvider received IElevationContext rather than falling back to null.
        services.AddSingleton(RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: false));
        services.AddSingleton<IBiosSignatureVerifier>(new FakeSignatureVerifier(result: true));
        services.AddSingleton<IElevationContext>(elevation);
        services.AddSingleton<Microsoft.Extensions.Logging.ILoggerFactory>(loggerFactory);
        services.AddBiosUpdates();
        services.AddBiosUpdateProvider<HpBiosUpdateProvider>();

        using var sp = services.BuildServiceProvider(StrictValidation);
        var service = sp.GetRequiredService<IBiosUpdateService>();

        var provider = Assert.Single(service.Providers);
        Assert.IsType<HpBiosUpdateProvider>(provider);
        Assert.Contains(typeof(HpBiosUpdateProvider).FullName!, loggerFactory.RequestedCategories);

        var check = await service.CheckForUpdateAsync();
        Assert.Equal("hp", check.ProviderId);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, check.Latest.Status);
        Assert.Equal(1, trackingHandler.RequestCount);

        var installRequest = BiosIdentityFactory.CreateInstallRequest(
            system: identity,
            downloadUrl: HpDownloadUrl,
            sha256: payload.Sha256,
            suspendBitLocker: false,
            allowReboot: false,
            stagingDirectory: staging.Path);

        var install = await service.InstallUpdateAsync(installRequest);
        Assert.True(install.Succeeded, install.Message);
        Assert.Equal(BiosInstallStatus.StagedForReboot, install.Status);
        Assert.Equal(2, trackingHandler.RequestCount);
        Assert.Equal(2, launcher.Calls.Count);
        Assert.Equal("sp151234.exe", launcher.Calls[0].BaseName, ignoreCase: true);
    }

    [Fact]
    public async Task AddBiosUpdateProvider_StandaloneWindowsUpdate_WiresDependenciesWithoutConstructingHttpMessageHandler()
    {
        var handlerFactoryCalls = 0;
        var wua = new FakeWindowsUpdateClient
        {
            SearchHandler = _ => Task.FromResult<IReadOnlyList<BiosWuaFirmwareUpdate>>(
            [
                new BiosWuaFirmwareUpdate(
                    UpdateId: SampleWuaUpdateId.ToString("D"),
                    Title: "Contoso System Firmware - 2.2.0",
                    Version: "2.2.0",
                    ReleaseDate: new DateOnly(2024, 11, 1),
                    SizeBytes: 9_000_000,
                    Severity: BiosUpdateSeverity.Recommended,
                    RebootRequired: true,
                    DriverClass: "Firmware",
                    DriverModel: "System Firmware"),
            ]),
        };

        var launcher = CreateGuardedLauncher();
        var elevation = new StubElevationContext(isProcessElevated: true, isAdminHelperConnected: false);
        var loggerFactory = new CapturingLoggerFactory();
        var identity = BiosIdentityFactory.GenericUefi();

        var services = new ServiceCollection();
        services.AddSingleton<IBiosSystemProbe>(new StubSystemProbe(identity));
        services.AddSingleton<IBiosInstallSafetyProbe>(sp => new ElevationAwareStubSafetyProbe(sp.GetRequiredService<IElevationContext>()));
        services.AddSingleton<HttpMessageHandler>(_ =>
        {
            Interlocked.Increment(ref handlerFactoryCalls);
            return new FakeBiosHttpHandler();
        });
        services.AddSingleton<IBiosWindowsUpdateClient>(wua);
        // Set SystemCommandRunner.IsProcessElevated = false while IElevationContext.IsProcessElevated = true
        // to prove WindowsUpdateBiosProvider received IElevationContext.
        services.AddSingleton(RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: false));
        services.AddSingleton<IElevationContext>(elevation);
        services.AddSingleton<Microsoft.Extensions.Logging.ILoggerFactory>(loggerFactory);
        services.AddBiosUpdates();
        services.AddBiosUpdateProvider<WindowsUpdateBiosProvider>();

        using var sp = services.BuildServiceProvider(StrictValidation);
        var service = sp.GetRequiredService<IBiosUpdateService>();

        var provider = Assert.Single(service.Providers);
        Assert.IsType<WindowsUpdateBiosProvider>(provider);
        Assert.Equal(0, Volatile.Read(ref handlerFactoryCalls));
        Assert.Contains(typeof(WindowsUpdateBiosProvider).FullName!, loggerFactory.RequestedCategories);

        var check = await service.CheckForUpdateAsync();
        Assert.Equal("windows-update", check.ProviderId);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, check.Latest.Status);

        var installRequest = new BiosInstallRequest(
            System: identity,
            Current: identity.CurrentBios,
            Target: check.Latest,
            Approved: true,
            ApprovedBy: "operator@contoso.com",
            SuspendBitLocker: false,
            AllowReboot: false,
            VerifyHash: true);

        var install = await service.InstallUpdateAsync(installRequest);
        Assert.True(install.Succeeded, install.Message);
        Assert.Contains(SampleWuaUpdateId, wua.InstalledUpdateIds);
        Assert.Equal(0, Volatile.Read(ref handlerFactoryCalls));
    }

    public static IEnumerable<object[]> AllBuiltInProviderTypesData()
    {
        yield return ["hp", typeof(HpBiosUpdateProvider), true];
        yield return ["dell", typeof(DellBiosUpdateProvider), true];
        yield return ["lenovo", typeof(LenovoBiosUpdateProvider), true];
        yield return ["asus", typeof(AsusBiosUpdateProvider), true];
        yield return ["acer", typeof(AcerBiosUpdateProvider), true];
        yield return ["msi", typeof(MsiBiosUpdateProvider), true];
        yield return ["microsoft", typeof(MicrosoftSurfaceBiosUpdateProvider), true];
        yield return ["framework", typeof(FrameworkBiosUpdateProvider), true];
        yield return ["windows-update", typeof(WindowsUpdateBiosProvider), false];
    }

    [Theory]
    [MemberData(nameof(AllBuiltInProviderTypesData))]
    public async Task AddBiosUpdateProvider_BeforeAddBuiltInBiosUpdateProviders_PreservesFullDiWiringForAllNineProviders(
        string expectedVendorId,
        Type providerType,
        bool isHttpProvider)
    {
        using var inner = new FakeBiosHttpHandler();
        inner.MapPredicate(_ => true, (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound)));
        using var trackingHandler = new DisposeTrackingHttpHandler(inner);

        var wuaSearchCalls = 0;
        var wua = new FakeWindowsUpdateClient
        {
            SearchHandler = _ =>
            {
                Interlocked.Increment(ref wuaSearchCalls);
                return Task.FromResult<IReadOnlyList<BiosWuaFirmwareUpdate>>([]);
            },
        };
        var launcher = CreateGuardedLauncher();
        var elevation = new StubElevationContext(isProcessElevated: true, isAdminHelperConnected: false);
        var loggerFactory = new CapturingLoggerFactory();
        var identity = CreateIdentityForVendor(expectedVendorId);

        var services = new ServiceCollection();
        services.AddSingleton<IBiosSystemProbe>(new StubSystemProbe(identity));
        services.AddSingleton<HttpMessageHandler>(trackingHandler);
        services.AddSingleton<IBiosWindowsUpdateClient>(wua);
        services.AddSingleton(RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: false));
        services.AddSingleton<IElevationContext>(elevation);
        services.AddSingleton<Microsoft.Extensions.Logging.ILoggerFactory>(loggerFactory);
        services.AddBiosUpdates();
        // Register the concrete built-in provider BEFORE AddBuiltInBiosUpdateProviders()
        RegisterBuiltInProviderGeneric(services, providerType);
        services.AddBuiltInBiosUpdateProviders();

        using var sp = services.BuildServiceProvider(StrictValidation);
        var service = sp.GetRequiredService<IBiosUpdateService>();

        Assert.Equal(9, service.Providers.Count);
        Assert.Equal(ExpectedOrderedVendorIds, service.Providers.Select(p => p.VendorId).ToArray());

        // Every single built-in provider type (including the one registered before AddBuiltInBiosUpdateProviders)
        // must have received a logger from the DI ILoggerFactory.
        var allBuiltInTypes = new[]
        {
            typeof(HpBiosUpdateProvider),
            typeof(DellBiosUpdateProvider),
            typeof(LenovoBiosUpdateProvider),
            typeof(AsusBiosUpdateProvider),
            typeof(AcerBiosUpdateProvider),
            typeof(MsiBiosUpdateProvider),
            typeof(MicrosoftSurfaceBiosUpdateProvider),
            typeof(FrameworkBiosUpdateProvider),
            typeof(WindowsUpdateBiosProvider),
        };
        foreach (var builtInType in allBuiltInTypes)
        {
            Assert.Contains(builtInType.FullName!, loggerFactory.RequestedCategories);
        }

        // Trigger the specific provider via IBiosUpdateService.CheckForUpdateAsync and confirm it hits
        // the DI-injected boundary double rather than escaping to BiosProviderHttp.SharedClient.
        var check = await service.CheckForUpdateAsync();
        Assert.Equal(expectedVendorId, check.ProviderId);

        if (isHttpProvider)
        {
            Assert.True(
                trackingHandler.RequestCount >= 1,
                $"Expected {providerType.Name} to route through DI HttpMessageHandler, but RequestCount was {trackingHandler.RequestCount}.");
        }
        else
        {
            Assert.Equal(1, Volatile.Read(ref wuaSearchCalls));
            Assert.Equal(0, trackingHandler.RequestCount);
        }
    }

    // =========================================================================
    // Group 4 — Coexistence with Custom Third-Party IBiosUpdateProvider
    // =========================================================================

    [Fact]
    public void CustomProviders_CoexistWithBuiltIns_HonoringPriority200_50_And_1()
    {
        // Part 1: Priority 200 (overrides OEM), Priority 50 (between OEM and WUA), Priority 1 (below WUA)
        {
            var services = new ServiceCollection();
            services.AddBiosUpdates();
            services.AddBuiltInBiosUpdateProviders();
            services.AddBiosUpdateProvider(_ => new CustomBiosProvider(
                vendorId: "custom-override",
                displayName: "Custom Override",
                priority: 200,
                canHandle: id => id.Manufacturer.Contains("HP", StringComparison.OrdinalIgnoreCase)));
            services.AddBiosUpdateProvider(_ => new CustomBiosProvider(
                vendorId: "custom-mid",
                displayName: "Custom Mid",
                priority: 50,
                canHandle: id => id.CurrentBios.FirmwareMode == BiosFirmwareMode.Uefi));
            services.AddBiosUpdateProvider(_ => new CustomBiosProvider(
                vendorId: "custom-fallback",
                displayName: "Custom Fallback",
                priority: 1,
                canHandle: _ => true));

            using var sp = services.BuildServiceProvider(StrictValidation);
            var service = sp.GetRequiredService<IBiosUpdateService>();

            Assert.Equal(12, service.Providers.Count);
            Assert.Equal(
                [
                    "custom-override",
                    "acer", "asus", "dell", "framework", "hp", "lenovo", "microsoft", "msi",
                    "custom-mid",
                    "windows-update",
                    "custom-fallback",
                ],
                service.Providers.Select(p => p.VendorId).ToArray());

            // Priority 200 overrides built-in HP (100)
            Assert.Equal("custom-override", service.ResolveProvider(BiosIdentityFactory.Hp())?.VendorId);
            // Built-in Dell (100) beats custom-mid (50) and windows-update (10)
            Assert.Equal("dell", service.ResolveProvider(BiosIdentityFactory.Dell())?.VendorId);
            // custom-mid (50) beats windows-update (10) on generic UEFI
            Assert.Equal("custom-mid", service.ResolveProvider(BiosIdentityFactory.GenericUefi())?.VendorId);
            // custom-fallback (1) catches Legacy when no OEM or windows-update handles it
            Assert.Equal("custom-fallback", service.ResolveProvider(BiosIdentityFactory.Legacy())?.VendorId);
        }

        // Part 2: Priority 1 fallback alone alongside built-ins
        {
            var services = new ServiceCollection();
            services.AddBiosUpdates();
            services.AddBuiltInBiosUpdateProviders();
            services.AddBiosUpdateProvider(_ => new CustomBiosProvider(
                vendorId: "custom-fallback",
                displayName: "Custom Fallback",
                priority: 1,
                canHandle: _ => true));

            using var sp = services.BuildServiceProvider(StrictValidation);
            var service = sp.GetRequiredService<IBiosUpdateService>();

            Assert.Equal(10, service.Providers.Count);
            Assert.Equal("hp", service.ResolveProvider(BiosIdentityFactory.Hp())?.VendorId);
            Assert.Equal("windows-update", service.ResolveProvider(BiosIdentityFactory.GenericUefi())?.VendorId);
            Assert.Equal("custom-fallback", service.ResolveProvider(BiosIdentityFactory.Legacy())?.VendorId);
        }
    }

    // =========================================================================
    // Group 5 — Full OEM Routing Matrix via IBiosUpdateService.ResolveProvider
    // =========================================================================

    public static IEnumerable<object[]> OemRoutingCases()
    {
        // All 8 OEMs in UEFI and Legacy modes
        yield return [BiosIdentityFactory.Hp(), "hp"];
        yield return [WithMode(BiosIdentityFactory.Hp(), BiosFirmwareMode.Legacy), "hp"];
        yield return [BiosIdentityFactory.Dell(), "dell"];
        yield return [WithMode(BiosIdentityFactory.Dell(), BiosFirmwareMode.Legacy), "dell"];
        yield return [BiosIdentityFactory.Lenovo(), "lenovo"];
        yield return [WithMode(BiosIdentityFactory.Lenovo(), BiosFirmwareMode.Legacy), "lenovo"];
        yield return [BiosIdentityFactory.Asus(), "asus"];
        yield return [WithMode(BiosIdentityFactory.Asus(), BiosFirmwareMode.Legacy), "asus"];
        yield return [BiosIdentityFactory.Acer(), "acer"];
        yield return [WithMode(BiosIdentityFactory.Acer(), BiosFirmwareMode.Legacy), "acer"];
        yield return [BiosIdentityFactory.Msi(), "msi"];
        yield return [WithMode(BiosIdentityFactory.Msi(), BiosFirmwareMode.Legacy), "msi"];
        yield return [BiosIdentityFactory.MicrosoftSurface(), "microsoft"];
        yield return [WithMode(BiosIdentityFactory.MicrosoftSurface(), BiosFirmwareMode.Legacy), "microsoft"];
        yield return [BiosIdentityFactory.Framework(), "framework"];
        yield return [WithMode(BiosIdentityFactory.Framework(), BiosFirmwareMode.Legacy), "framework"];

        // Alternate vendor spellings
        yield return [BiosIdentityFactory.Hp(manufacturer: "Hewlett-Packard"), "hp"];
        yield return [BiosIdentityFactory.Hp(manufacturer: "HP Inc."), "hp"];
        yield return [BiosIdentityFactory.Dell(manufacturer: "Alienware"), "dell"];
        yield return [BiosIdentityFactory.Asus(manufacturer: "ASUS"), "asus"];
        yield return [BiosIdentityFactory.Acer(manufacturer: "Acer Incorporated"), "acer"];
        yield return [BiosIdentityFactory.Msi(manufacturer: "MSI"), "msi"];

        // BoardManufacturer-only matches (generic System Manufacturer)
        yield return [BiosIdentityFactory.GenericUefi("Generic OEM") with { BoardManufacturer = "Hewlett-Packard" }, "hp"];
        yield return [BiosIdentityFactory.GenericUefi("Generic OEM") with { BoardManufacturer = "Dell Inc." }, "dell"];
        yield return [BiosIdentityFactory.GenericUefi("Generic OEM") with { BoardManufacturer = "LENOVO" }, "lenovo"];
        yield return [BiosIdentityFactory.GenericUefi("Generic OEM") with { BoardManufacturer = "ASUSTeK COMPUTER INC." }, "asus"];
        yield return [BiosIdentityFactory.GenericUefi("Generic OEM") with { BoardManufacturer = "Acer" }, "acer"];
        yield return [BiosIdentityFactory.GenericUefi("Generic OEM") with { BoardManufacturer = "Micro-Star International Co., Ltd." }, "msi"];
        yield return [BiosIdentityFactory.GenericUefi("Generic OEM") with { BoardManufacturer = "Framework" }, "framework"];
        yield return [BiosIdentityFactory.GenericUefi("Generic OEM") with { BoardManufacturer = "Microsoft Corporation", BoardProduct = "Surface Pro 9" }, "microsoft"];
    }

    [Theory]
    [MemberData(nameof(OemRoutingCases))]
    public void ResolveProvider_AllEightOems_UefiAndLegacy_RouteToExactOemProvider(
        BiosSystemIdentity identity,
        string expectedVendorId)
    {
        var services = new ServiceCollection();
        services.AddBiosUpdates();
        services.AddBuiltInBiosUpdateProviders();

        using var sp = services.BuildServiceProvider(StrictValidation);
        var service = sp.GetRequiredService<IBiosUpdateService>();

        var resolved = service.ResolveProvider(identity);
        Assert.NotNull(resolved);
        Assert.Equal(expectedVendorId, resolved.VendorId);
        Assert.Equal(100, resolved.Priority);
    }

    [Fact]
    public async Task ResolveProvider_HyperVVm_And_GenericOem_FallbackToWindowsUpdateOnUefiAndNullOnLegacyOrUnknown()
    {
        var legacyProbe = new StubSystemProbe(BiosIdentityFactory.Legacy());
        var services = new ServiceCollection();
        services.AddSingleton<IBiosSystemProbe>(legacyProbe);
        services.AddBiosUpdates();
        services.AddBuiltInBiosUpdateProviders();

        using var sp = services.BuildServiceProvider(StrictValidation);
        var service = sp.GetRequiredService<IBiosUpdateService>();

        // Hyper-V VM on UEFI must NOT match Microsoft Surface; falls back to Windows Update (Priority 10)
        var hyperVUefi = service.ResolveProvider(BiosIdentityFactory.HyperVVm());
        Assert.NotNull(hyperVUefi);
        Assert.Equal("windows-update", hyperVUefi.VendorId);
        Assert.Equal(10, hyperVUefi.Priority);

        // Hyper-V VM on Legacy -> null
        Assert.Null(service.ResolveProvider(WithMode(BiosIdentityFactory.HyperVVm(), BiosFirmwareMode.Legacy)));

        // Generic OEM on UEFI -> windows-update (Priority 10)
        var genericUefi = service.ResolveProvider(BiosIdentityFactory.GenericUefi());
        Assert.NotNull(genericUefi);
        Assert.Equal("windows-update", genericUefi.VendorId);
        Assert.Equal(10, genericUefi.Priority);

        // Generic Legacy / Unknown / Empty -> null
        Assert.Null(service.ResolveProvider(BiosIdentityFactory.Legacy()));
        Assert.Null(service.ResolveProvider(WithMode(BiosIdentityFactory.GenericUefi(), BiosFirmwareMode.Unknown)));
        Assert.Null(service.ResolveProvider(BiosIdentityFactory.Unknown()));

        // CheckForUpdateAsync on Generic Legacy returns UnsupportedHardware with ProviderId == null
        var check = await service.CheckForUpdateAsync();
        Assert.Null(check.ProviderId);
        Assert.Equal(BiosCheckStatus.UnsupportedHardware, check.Latest.Status);
    }

    [Theory]
    [InlineData("Ship")]
    [InlineData("Racer")]
    [InlineData("CustomSI")]
    [InlineData("Odell")]
    [InlineData("Chip")]
    [InlineData("Comsi")]
    [InlineData("Tracer")]
    [InlineData("Pegasus")]
    [InlineData("PHP Hardware")]
    [InlineData("Spaceship")]
    public void ResolveProvider_FalsePositiveSubstrings_NeverMatchOem_FallbackToWindowsUpdateOnUefiAndNullOnLegacy(
        string manufacturer)
    {
        var services = new ServiceCollection();
        services.AddBiosUpdates();
        services.AddBuiltInBiosUpdateProviders();

        using var sp = services.BuildServiceProvider(StrictValidation);
        var service = sp.GetRequiredService<IBiosUpdateService>();

        var uefiResolved = service.ResolveProvider(BiosIdentityFactory.GenericUefi(manufacturer));
        Assert.NotNull(uefiResolved);
        Assert.Equal("windows-update", uefiResolved.VendorId);

        Assert.Null(service.ResolveProvider(BiosIdentityFactory.Legacy(manufacturer)));
    }

    // =========================================================================
    // Group 6 — End-to-End DI-Wired Boundary Injection Through IBiosUpdateService
    // =========================================================================

    [Fact]
    public async Task DiInjection_HttpClient_ReachesOemProviderThroughBiosUpdateService()
    {
        using var handler = new FakeBiosHttpHandler();
        handler.MapText(HpDefaultCatalogUrl, SampleHpCatalogXml, "application/xml");
        using var httpClient = handler.CreateClient();

        var services = new ServiceCollection();
        services.AddSingleton<IBiosSystemProbe>(new StubSystemProbe(BiosIdentityFactory.Hp()));
        services.AddSingleton<HttpClient>(httpClient);
        services.AddBiosUpdates();
        services.AddBuiltInBiosUpdateProviders();

        using var sp = services.BuildServiceProvider(StrictValidation);
        var service = sp.GetRequiredService<IBiosUpdateService>();

        var check = await service.CheckForUpdateAsync();

        Assert.Equal("hp", check.ProviderId);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, check.Latest.Status);
        Assert.Equal("01.15.00", check.Latest.LatestVersion);
        Assert.Equal(HpDownloadUrl, check.Latest.DownloadUrl);
        Assert.Contains(handler.Requests, r => string.Equals(r.RequestUri?.AbsoluteUri, HpDefaultCatalogUrl, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task DiInjection_HttpMessageHandlerWithoutHttpClient_ReachesMultipleOemProvidersAndDoesNotDoubleDispose()
    {
        // Subcase A: DI-owned factory registration -> single shared HttpClient across HP + ASUS; disposed once by DI
        {
            using var inner = new FakeBiosHttpHandler();
            inner.MapText(HpDefaultCatalogUrl, SampleHpCatalogXml, "application/xml");
            inner.MapPrefix("https://www.asus.com/support/api/product.asmx/GetPDBIOS", (_, _) =>
                Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(SampleAsusCatalogJson, Encoding.UTF8, "application/json"),
                }));

            var tracking = new DisposeTrackingHttpHandler(inner);
            var systemProbe = new StubSystemProbe(BiosIdentityFactory.Hp());

            var services = new ServiceCollection();
            services.AddSingleton<IBiosSystemProbe>(systemProbe);
            services.AddSingleton<HttpMessageHandler>(_ => tracking);
            services.AddBiosUpdates();
            services.AddBuiltInBiosUpdateProviders();

            using (var sp = services.BuildServiceProvider(StrictValidation))
            {
                var service = sp.GetRequiredService<IBiosUpdateService>();

                var hpCheck = await service.CheckForUpdateAsync();
                Assert.Equal("hp", hpCheck.ProviderId);
                Assert.Equal(BiosCheckStatus.UpdateAvailable, hpCheck.Latest.Status);

                systemProbe.Identity = BiosIdentityFactory.Asus();
                var asusCheck = await service.CheckForUpdateAsync();
                Assert.Equal("asus", asusCheck.ProviderId);
                Assert.Equal(BiosCheckStatus.UpdateAvailable, asusCheck.Latest.Status);
                Assert.Equal("3201", asusCheck.Latest.LatestVersion);

                Assert.Equal(2, tracking.RequestCount);
                Assert.Equal(0, tracking.DisposeCount);
            }

            // DI owns the factory-created HttpMessageHandler and must dispose it exactly once (zero double-dispose)
            Assert.Equal(1, tracking.DisposeCount);
        }

        // Subcase B: Caller-owned instance registration -> shared across HP + ASUS; NOT disposed by ServiceProvider
        {
            using var inner = new FakeBiosHttpHandler();
            inner.MapText(HpDefaultCatalogUrl, SampleHpCatalogXml, "application/xml");
            inner.MapPrefix("https://www.asus.com/support/api/product.asmx/GetPDBIOS", (_, _) =>
                Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(SampleAsusCatalogJson, Encoding.UTF8, "application/json"),
                }));

            var instanceHandler = new DisposeTrackingHttpHandler(inner);
            var systemProbe = new StubSystemProbe(BiosIdentityFactory.Hp());

            var services = new ServiceCollection();
            services.AddSingleton<IBiosSystemProbe>(systemProbe);
            services.AddSingleton<HttpMessageHandler>(instanceHandler);
            services.AddBiosUpdates();
            services.AddBuiltInBiosUpdateProviders();

            using (var sp = services.BuildServiceProvider(StrictValidation))
            {
                var service = sp.GetRequiredService<IBiosUpdateService>();

                var hpCheck = await service.CheckForUpdateAsync();
                Assert.Equal(BiosCheckStatus.UpdateAvailable, hpCheck.Latest.Status);

                systemProbe.Identity = BiosIdentityFactory.Asus();
                var asusCheck = await service.CheckForUpdateAsync();
                Assert.Equal(BiosCheckStatus.UpdateAvailable, asusCheck.Latest.Status);

                Assert.Equal(2, instanceHandler.RequestCount);
            }

            // Caller owns the instance registration -> BiosProviderHttpClientHolder used disposeHandler: false
            Assert.Equal(0, instanceHandler.DisposeCount);
            instanceHandler.Dispose();
            Assert.Equal(1, instanceHandler.DisposeCount);
        }
    }

    [Fact]
    public async Task DiInjection_HttpClientTakesPrecedenceOverHttpMessageHandler()
    {
        using var innerA = new FakeBiosHttpHandler();
        innerA.MapText(HpDefaultCatalogUrl, SampleHpCatalogXml, "application/xml");
        using var trackingA = new DisposeTrackingHttpHandler(innerA);
        using var clientA = BiosProviderHttp.CreateClient(trackingA, TimeSpan.FromSeconds(10));

        using var innerB = new FakeBiosHttpHandler();
        innerB.MapText(HpDefaultCatalogUrl, SampleHpCatalogXml, "application/xml");
        using var trackingB = new DisposeTrackingHttpHandler(innerB);
        var handlerBFactoryCalls = 0;

        var services = new ServiceCollection();
        services.AddSingleton<IBiosSystemProbe>(new StubSystemProbe(BiosIdentityFactory.Hp()));
        services.AddSingleton<HttpClient>(clientA);
        services.AddSingleton<HttpMessageHandler>(_ =>
        {
            Interlocked.Increment(ref handlerBFactoryCalls);
            return trackingB;
        });
        services.AddBiosUpdates();
        services.AddBuiltInBiosUpdateProviders();

        using var sp = services.BuildServiceProvider(StrictValidation);
        var service = sp.GetRequiredService<IBiosUpdateService>();

        var check = await service.CheckForUpdateAsync();
        Assert.Equal("hp", check.ProviderId);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, check.Latest.Status);
        Assert.Equal(1, trackingA.RequestCount);
        Assert.Equal(0, trackingB.RequestCount);
        Assert.Equal(0, Volatile.Read(ref handlerBFactoryCalls));
    }

    [Fact]
    public async Task DiInjection_WindowsUpdateClient_ReachesWindowsUpdateProviderForCheckAndElevatedInstall()
    {
        var wua = new FakeWindowsUpdateClient
        {
            SearchHandler = _ => Task.FromResult<IReadOnlyList<BiosWuaFirmwareUpdate>>(
            [
                new BiosWuaFirmwareUpdate(
                    UpdateId: SampleWuaUpdateId.ToString("D"),
                    Title: "Contoso System Firmware - 2.1.0",
                    Version: "2.1.0",
                    ReleaseDate: new DateOnly(2024, 9, 1),
                    SizeBytes: 12_500_000,
                    Severity: BiosUpdateSeverity.Recommended,
                    RebootRequired: true,
                    DriverClass: "Firmware",
                    DriverModel: "System Firmware"),
            ]),
        };

        var launcher = CreateGuardedLauncher();
        var elevation = new StubElevationContext(isProcessElevated: true, isAdminHelperConnected: false);
        var loggerFactory = new CapturingLoggerFactory();
        var identity = BiosIdentityFactory.GenericUefi();

        var services = new ServiceCollection();
        services.AddSingleton<IBiosSystemProbe>(new StubSystemProbe(identity));
        services.AddSingleton<IBiosInstallSafetyProbe>(new StubSafetyProbe(BiosIdentityFactory.SafeSnapshot()));
        services.AddSingleton<IBiosWindowsUpdateClient>(wua);
        services.AddSingleton(RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: true));
        services.AddSingleton<IElevationContext>(elevation);
        services.AddSingleton<Microsoft.Extensions.Logging.ILoggerFactory>(loggerFactory);
        services.AddBiosUpdates();
        services.AddBuiltInBiosUpdateProviders();

        using var sp = services.BuildServiceProvider(StrictValidation);
        var service = sp.GetRequiredService<IBiosUpdateService>();

        var check = await service.CheckForUpdateAsync();
        Assert.Equal("windows-update", check.ProviderId);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, check.Latest.Status);
        Assert.Equal(SampleWuaUpdateId.ToString("D"), check.Latest.PackageId);

        var progress = new SyncProgress<BiosInstallProgress>();
        var installRequest = new BiosInstallRequest(
            System: identity,
            Current: identity.CurrentBios,
            Target: check.Latest,
            Approved: true,
            ApprovedBy: "operator@contoso.com",
            SuspendBitLocker: true,
            AllowReboot: false,
            VerifyHash: true);

        var result = await service.InstallUpdateAsync(installRequest, progress);

        Assert.True(result.Succeeded, result.Message);
        Assert.Equal(BiosInstallStatus.StagedForReboot, result.Status);
        Assert.True(result.BitLockerSuspended);
        Assert.Contains(SampleWuaUpdateId, wua.InstalledUpdateIds);
        Assert.Single(launcher.Calls);
        Assert.Equal("manage-bde.exe", launcher.Calls[0].BaseName, ignoreCase: true);
        Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, result.Message, StringComparison.OrdinalIgnoreCase);
        loggerFactory.AssertDoesNotContainSecret();
    }

    [Fact]
    public async Task DiInjection_CommandRunner_SignatureVerifier_ElevationContext_And_LoggerFactory_ReachResolvedProviderInstall()
    {
        using var staging = new TempStagingDir();
        var payload = TestPayload.FromString("HP-SOFTPAQ-SIGNED-BINARY-CONTENT");
        using var httpHandler = new FakeBiosHttpHandler();
        httpHandler.MapBytes(HpDownloadUrl, payload.Bytes);
        using var httpClient = httpHandler.CreateClient();

        var launcher = CreateGuardedLauncher((call, _) =>
        {
            if (string.Equals(call.BaseName, "manage-bde.exe", StringComparison.OrdinalIgnoreCase))
                return Task.FromResult(new ProcessResult(0, "Protectors disabled.", ""));
            return Task.FromResult(new ProcessResult(0, $"SoftPaq staged for {BiosIdentityFactory.SentinelSerialNumber}", ""));
        });
        var sigVerifier = new FakeSignatureVerifier(result: true);
        var elevation = new StubElevationContext(isProcessElevated: true, isAdminHelperConnected: false);
        var loggerFactory = new CapturingLoggerFactory();
        var identity = BiosIdentityFactory.Hp();

        var services = new ServiceCollection();
        services.AddSingleton<IBiosSystemProbe>(new StubSystemProbe(identity));
        services.AddSingleton<IBiosInstallSafetyProbe>(new StubSafetyProbe(BiosIdentityFactory.SafeSnapshot()));
        services.AddSingleton<HttpClient>(httpClient);
        services.AddSingleton(RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: true));
        services.AddSingleton<IBiosSignatureVerifier>(sigVerifier);
        services.AddSingleton<IElevationContext>(elevation);
        services.AddSingleton<Microsoft.Extensions.Logging.ILoggerFactory>(loggerFactory);
        services.AddBiosUpdates();
        services.AddBuiltInBiosUpdateProviders();

        using var sp = services.BuildServiceProvider(StrictValidation);
        var service = sp.GetRequiredService<IBiosUpdateService>();

        // Sha256: null with VerifyHash: true forces Authenticode verification via DI-injected IBiosSignatureVerifier
        var request = BiosIdentityFactory.CreateInstallRequest(
            system: identity,
            downloadUrl: HpDownloadUrl,
            sha256: null,
            suspendBitLocker: true,
            allowReboot: false,
            verifyHash: true,
            stagingDirectory: staging.Path);

        var progress = new SyncProgress<BiosInstallProgress>();
        var result = await service.InstallUpdateAsync(request, progress);

        Assert.True(result.Succeeded, result.Message);
        Assert.Equal(BiosInstallStatus.StagedForReboot, result.Status);
        Assert.True(result.BitLockerSuspended);

        Assert.Equal(1, sigVerifier.CallCount);
        Assert.Equal(3, launcher.Calls.Count);
        Assert.Equal("manage-bde.exe", launcher.Calls[0].BaseName, ignoreCase: true);
        Assert.Contains("-protectors", launcher.Calls[0].Arguments);
        Assert.Contains("-disable", launcher.Calls[0].Arguments);
        Assert.Contains("-RebootCount", launcher.Calls[0].Arguments);
        Assert.Contains("1", launcher.Calls[0].Arguments);

        Assert.Equal("sp151234.exe", launcher.Calls[^1].BaseName, ignoreCase: true);
        Assert.Equal(["-s"], launcher.Calls[^1].Arguments);

        // Verify logger factory wiring and secret redaction
        Assert.Contains(typeof(BiosUpdateService).FullName!, loggerFactory.RequestedCategories);
        Assert.Contains(typeof(HpBiosUpdateProvider).FullName!, loggerFactory.RequestedCategories);
        Assert.NotEmpty(loggerFactory.Entries);
        Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, result.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, result.LogTail ?? "", StringComparison.OrdinalIgnoreCase);
        loggerFactory.AssertDoesNotContainSecret();

        // Verify ordered progress stages
        var stages = progress.Reports.Select(r => r.Stage).ToList();
        var expectedOrder = new[]
        {
            BiosInstallStage.CheckingPrerequisites,
            BiosInstallStage.Downloading,
            BiosInstallStage.Verifying,
            BiosInstallStage.SuspendingBitLocker,
            BiosInstallStage.Staging,
            BiosInstallStage.RebootRequired,
        };

        var lastIdx = -1;
        foreach (var stage in expectedOrder)
        {
            var idx = stages.IndexOf(stage);
            Assert.True(idx > lastIdx, $"Expected stage {stage} after index {lastIdx}; actual sequence: [{string.Join(", ", stages)}]");
            lastIdx = idx;
        }
    }

    [Fact]
    public async Task DiInjection_CommandRunnerWithoutElevationContext_DoesNotShadowCommandRunnerElevation()
    {
        // Case A: SystemCommandRunner reports IsProcessElevated == true, IElevationContext is NOT registered.
        // ResolveElevationCheck must return null so HpBiosUpdateProvider honors SystemCommandRunner.IsProcessElevated.
        {
            using var staging = new TempStagingDir();
            var payload = TestPayload.FromString("HP-SOFTPAQ-NO-ELEVATION-CTX");
            using var httpHandler = new FakeBiosHttpHandler();
            httpHandler.MapBytes(HpDownloadUrl, payload.Bytes);
            using var httpClient = httpHandler.CreateClient();
            var launcher = CreateGuardedLauncher();
            var identity = BiosIdentityFactory.Hp();

            var services = new ServiceCollection();
            services.AddSingleton<IBiosSystemProbe>(new StubSystemProbe(identity));
            services.AddSingleton<IBiosInstallSafetyProbe>(new StubSafetyProbe(BiosIdentityFactory.SafeSnapshot()));
            services.AddSingleton<HttpClient>(httpClient);
            services.AddSingleton(RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: true));
            services.AddSingleton<IBiosSignatureVerifier>(new FakeSignatureVerifier(result: true));
            // Intentionally do NOT register IElevationContext or IElevatedCommandBridge
            services.AddBiosUpdates();
            services.AddBuiltInBiosUpdateProviders();

            using var sp = services.BuildServiceProvider(StrictValidation);
            var service = sp.GetRequiredService<IBiosUpdateService>();

            var request = BiosIdentityFactory.CreateInstallRequest(
                system: identity,
                downloadUrl: HpDownloadUrl,
                sha256: payload.Sha256,
                suspendBitLocker: false,
                allowReboot: false,
                stagingDirectory: staging.Path);

            var result = await service.InstallUpdateAsync(request);
            Assert.True(result.Succeeded, result.Message);
            Assert.Equal(BiosInstallStatus.StagedForReboot, result.Status);
            Assert.Equal(2, launcher.Calls.Count);
            Assert.Equal("sp151234.exe", launcher.Calls[0].BaseName, ignoreCase: true);
        }

        // Case B: SystemCommandRunner reports IsProcessElevated == false, IElevationContext is NOT registered,
        // and no bridge is connected -> provider refuses local un-elevated execution cleanly (0 launcher calls).
        {
            using var staging = new TempStagingDir();
            var payload = TestPayload.FromString("HP-SOFTPAQ-UNELEVATED-CMD");
            using var httpHandler = new FakeBiosHttpHandler();
            httpHandler.MapBytes(HpDownloadUrl, payload.Bytes);
            using var httpClient = httpHandler.CreateClient();
            var launcher = CreateGuardedLauncher();
            var identity = BiosIdentityFactory.Hp();

            var services = new ServiceCollection();
            services.AddSingleton<IBiosSystemProbe>(new StubSystemProbe(identity));
            services.AddSingleton<IBiosInstallSafetyProbe>(new StubSafetyProbe(BiosIdentityFactory.SafeSnapshot()));
            services.AddSingleton<HttpClient>(httpClient);
            services.AddSingleton(RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: false));
            services.AddSingleton<IBiosSignatureVerifier>(new FakeSignatureVerifier(result: true));
            services.AddBiosUpdates();
            services.AddBuiltInBiosUpdateProviders();

            using var sp = services.BuildServiceProvider(StrictValidation);
            var service = sp.GetRequiredService<IBiosUpdateService>();

            var request = BiosIdentityFactory.CreateInstallRequest(
                system: identity,
                downloadUrl: HpDownloadUrl,
                sha256: payload.Sha256,
                suspendBitLocker: false,
                allowReboot: false,
                stagingDirectory: staging.Path);

            var result = await service.InstallUpdateAsync(request);
            Assert.False(result.Succeeded);
            Assert.Equal(BiosInstallStatus.Failed, result.Status);
            Assert.Empty(launcher.Calls);
        }
    }

    [Fact]
    public async Task DiInjection_DynamicElevationContextMutation_SwitchesBetweenLocalAndAgentBridgedExecution()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var userStaging1 = new TempStagingDir();
        using var userStaging2 = new TempStagingDir();
        using var adminRoot = new TempStagingDir();

        var payload = TestPayload.FromString("HP-SOFTPAQ-DYNAMIC-ELEVATION");
        using var httpHandler = new FakeBiosHttpHandler();
        httpHandler.MapBytes(HpDownloadUrl, payload.Bytes);
        using var httpClient = httpHandler.CreateClient();

        var hostLauncher = CreateGuardedLauncher();
        var agentLauncher = CreateGuardedLauncher();
        var agentSigVerifier = new FakeSignatureVerifier(result: true);
        var biosOps = new AgentBiosOperations(
            launcher: agentLauncher,
            signatureVerifier: agentSigVerifier,
            stagingRoot: adminRoot.Path);

        var (server, serverTask, client) = await StartPipeAsync(agentLauncher, biosOps, cts);
        try
        {
            var elevation = new StubElevationContext(isProcessElevated: true, isAdminHelperConnected: true);
            var identity = BiosIdentityFactory.Hp();

            var services = new ServiceCollection();
            services.AddSingleton<IBiosSystemProbe>(new StubSystemProbe(identity));
            services.AddSingleton<IBiosInstallSafetyProbe>(new StubSafetyProbe(BiosIdentityFactory.SafeSnapshot()));
            services.AddSingleton<HttpClient>(httpClient);
            services.AddSingleton<IBiosSignatureVerifier>(new FakeSignatureVerifier(result: true));
            services.AddSingleton<IElevationContext>(elevation);
            services.AddSingleton<IElevatedCommandBridge>(client);
            services.AddSingleton(new SystemCommandRunner(
                launcher: hostLauncher,
                elevatedBridge: client,
                isProcessElevated: () => elevation.IsProcessElevated));
            services.AddBiosUpdates();
            services.AddBuiltInBiosUpdateProviders();

            using var sp = services.BuildServiceProvider(StrictValidation);
            var service = sp.GetRequiredService<IBiosUpdateService>();

            // Call 1: IsProcessElevated == true -> runs locally on Host
            var req1 = BiosIdentityFactory.CreateInstallRequest(
                system: identity,
                downloadUrl: HpDownloadUrl,
                sha256: payload.Sha256,
                suspendBitLocker: true,
                allowReboot: false,
                stagingDirectory: userStaging1.Path);

            var res1 = await service.InstallUpdateAsync(req1, ct: cts.Token);
            Assert.True(res1.Succeeded, res1.Message);
            Assert.Equal(3, hostLauncher.Calls.Count);
            Assert.Empty(agentLauncher.Calls);

            // Mutate IElevationContext mid-container lifetime: IsProcessElevated -> false
            elevation.IsProcessElevated = false;

            // Call 2: IsProcessElevated == false -> routes over live Agent pipe
            var req2 = BiosIdentityFactory.CreateInstallRequest(
                system: identity,
                downloadUrl: HpDownloadUrl,
                sha256: payload.Sha256,
                suspendBitLocker: true,
                allowReboot: false,
                stagingDirectory: userStaging2.Path);

            var res2 = await service.InstallUpdateAsync(req2, ct: cts.Token);
            Assert.True(res2.Succeeded, res2.Message);
            Assert.Equal(BiosInstallStatus.StagedForReboot, res2.Status);
            Assert.True(res2.BitLockerSuspended);
            Assert.Equal(3, hostLauncher.Calls.Count); // Unchanged — zero new Host launches
            Assert.Equal(3, agentLauncher.Calls.Count); // manage-bde + admin-staged SoftPaq extract + run
            Assert.Equal(1, agentSigVerifier.CallCount);
        }
        finally
        {
            await client.DisposeAsync();
            await serverTask;
            server.Dispose();
        }
    }

    [Fact]
    public async Task DiInjection_LiveAdminPipe_UnElevatedHost_RoutesOemBiosInstallAndBitLockerThroughAgent()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var userStaging = new TempStagingDir();
        using var adminRoot = new TempStagingDir();

        var payload = TestPayload.FromString("HP-SOFTPAQ-AGENT-BRIDGED-BINARY");
        using var httpHandler = new FakeBiosHttpHandler();
        httpHandler.MapBytes(HpDownloadUrl, payload.Bytes);
        using var httpClient = httpHandler.CreateClient();

        var hostLauncher = CreateGuardedLauncher();
        var agentLauncher = CreateGuardedLauncher((call, _) =>
        {
            if (string.Equals(call.BaseName, "manage-bde.exe", StringComparison.OrdinalIgnoreCase))
                return Task.FromResult(new ProcessResult(0, "Protectors disabled.", ""));
            return Task.FromResult(new ProcessResult(0, $"Agent staged ok ({BiosIdentityFactory.SentinelSerialNumber})", ""));
        });
        var hostSigVerifier = new FakeSignatureVerifier(result: true);
        var agentSigVerifier = new FakeSignatureVerifier(result: true);
        var loggerFactory = new CapturingLoggerFactory();

        var biosOps = new AgentBiosOperations(
            launcher: agentLauncher,
            signatureVerifier: agentSigVerifier,
            stagingRoot: adminRoot.Path,
            log: loggerFactory.CreateLogger(typeof(AgentBiosOperations).FullName!));

        var (server, serverTask, client) = await StartPipeAsync(agentLauncher, biosOps, cts);
        try
        {
            var elevation = new StubElevationContext(isProcessElevated: false, isAdminHelperConnected: true);
            var identity = BiosIdentityFactory.Hp();

            var services = new ServiceCollection();
            services.AddSingleton<IBiosSystemProbe>(new StubSystemProbe(identity));
            // Use deterministic elevation-aware safety probe so install routing is 100% hermetic on Windows & Linux
            // (immune to host AC power / battery / pending-reboot state) while still flowing IElevationContext.HasAdminCapabilities.
            services.AddSingleton<IBiosInstallSafetyProbe>(sp => new ElevationAwareStubSafetyProbe(sp.GetRequiredService<IElevationContext>()));
            services.AddSingleton<HttpClient>(httpClient);
            services.AddSingleton<IBiosSignatureVerifier>(hostSigVerifier);
            services.AddSingleton<IElevationContext>(elevation);
            services.AddSingleton<IElevatedCommandBridge>(client);
            services.AddSingleton(new SystemCommandRunner(
                launcher: hostLauncher,
                log: loggerFactory.CreateLogger(typeof(SystemCommandRunner).FullName!),
                elevatedBridge: client,
                isProcessElevated: () => elevation.IsProcessElevated));
            services.AddSingleton<Microsoft.Extensions.Logging.ILoggerFactory>(loggerFactory);
            services.AddBiosUpdates();
            services.AddBuiltInBiosUpdateProviders();

            using var sp = services.BuildServiceProvider(StrictValidation);
            var service = sp.GetRequiredService<IBiosUpdateService>();

            var request = BiosIdentityFactory.CreateInstallRequest(
                system: identity,
                downloadUrl: HpDownloadUrl,
                sha256: payload.Sha256,
                suspendBitLocker: true,
                allowReboot: false,
                stagingDirectory: userStaging.Path);

            var safety = await service.EvaluateInstallSafetyAsync(request, cts.Token);
            Assert.True(safety.Passed, string.Join("; ", safety.BlockingReasons));

            var result = await service.InstallUpdateAsync(request, ct: cts.Token);

            Assert.True(result.Succeeded, result.Message);
            Assert.Equal(BiosInstallStatus.StagedForReboot, result.Status);
            Assert.True(result.BitLockerSuspended);

            // Un-elevated Host must perform ZERO local process launches
            Assert.Empty(hostLauncher.Calls);

            // Agent executed manage-bde.exe and then admin-staged SoftPaq strictly inside adminRoot
            Assert.Equal(3, agentLauncher.Calls.Count);
            Assert.Equal("manage-bde.exe", agentLauncher.Calls[0].BaseName, ignoreCase: true);

            var installerCall = agentLauncher.Calls[^1];
            var normalizedAdminRoot = Path.GetFullPath(adminRoot.Path);
            var normalizedUserStaging = Path.GetFullPath(userStaging.Path);
            var normalizedExePath = Path.GetFullPath(installerCall.FileName);
            Assert.StartsWith(normalizedAdminRoot, normalizedExePath, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(normalizedUserStaging, normalizedExePath, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(["-s"], installerCall.Arguments);

            // Agent verified Authenticode on admin-staged copy and cleaned up admin staging directory
            Assert.Equal(1, agentSigVerifier.CallCount);
            Assert.StartsWith(normalizedAdminRoot, Path.GetFullPath(agentSigVerifier.VerifiedPaths[0]), StringComparison.OrdinalIgnoreCase);
            Assert.Empty(Directory.GetFileSystemEntries(adminRoot.Path));

            Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, result.Message, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, result.LogTail ?? "", StringComparison.OrdinalIgnoreCase);
            loggerFactory.AssertDoesNotContainSecret();
        }
        finally
        {
            await client.DisposeAsync();
            await serverTask;
            server.Dispose();
        }
    }

    [Fact]
    public async Task DiInjection_LiveAdminPipe_UnElevatedHost_RoutesWuaInstallAndBitLockerThroughAgent()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));

        var hostLauncher = CreateGuardedLauncher();
        var agentLauncher = CreateGuardedLauncher();
        var fakeWuaApi = new FakeWuaApi
        {
            FoundUpdates = [new FakeWuaUpdate("Contoso System Firmware - 3.0.0", eulaAccepted: false, isDownloaded: false)],
            InstallOutcome = new UpdateInstallOutcome(AgentWindowsUpdate.SucceededCode, 0, RebootRequired: true),
        };
        var localWua = new FakeWindowsUpdateClient
        {
            SearchHandler = _ => Task.FromResult<IReadOnlyList<BiosWuaFirmwareUpdate>>(
            [
                new BiosWuaFirmwareUpdate(
                    UpdateId: SampleWuaUpdateId.ToString("D"),
                    Title: "Contoso System Firmware - 3.0.0",
                    Version: "3.0.0",
                    ReleaseDate: new DateOnly(2024, 10, 1),
                    SizeBytes: 8_000_000,
                    Severity: BiosUpdateSeverity.Recommended,
                    RebootRequired: true,
                    DriverClass: "Firmware",
                    DriverModel: "System Firmware"),
            ]),
        };
        var loggerFactory = new CapturingLoggerFactory();

        var biosOps = new AgentBiosOperations(
            launcher: agentLauncher,
            wuaApiFactory: () => fakeWuaApi,
            log: loggerFactory.CreateLogger(typeof(AgentBiosOperations).FullName!));

        var (server, serverTask, client) = await StartPipeAsync(agentLauncher, biosOps, cts);
        try
        {
            var elevation = new StubElevationContext(isProcessElevated: false, isAdminHelperConnected: true);
            var identity = BiosIdentityFactory.GenericUefi();

            var services = new ServiceCollection();
            services.AddSingleton<IBiosSystemProbe>(new StubSystemProbe(identity));
            // Deterministic elevation-aware safety probe keeps the live-pipe install test hermetic on Windows & Linux
            // while still verifying IElevationContext.HasAdminCapabilities flows into the safety gate.
            services.AddSingleton<IBiosInstallSafetyProbe>(sp => new ElevationAwareStubSafetyProbe(sp.GetRequiredService<IElevationContext>()));
            services.AddSingleton<IBiosWindowsUpdateClient>(localWua);
            services.AddSingleton<IElevationContext>(elevation);
            services.AddSingleton<IElevatedCommandBridge>(client);
            services.AddSingleton(new SystemCommandRunner(
                launcher: hostLauncher,
                log: loggerFactory.CreateLogger(typeof(SystemCommandRunner).FullName!),
                elevatedBridge: client,
                isProcessElevated: () => elevation.IsProcessElevated));
            services.AddSingleton<Microsoft.Extensions.Logging.ILoggerFactory>(loggerFactory);
            services.AddBiosUpdates();
            services.AddBuiltInBiosUpdateProviders();

            using var sp = services.BuildServiceProvider(StrictValidation);
            var service = sp.GetRequiredService<IBiosUpdateService>();

            var check = await service.CheckForUpdateAsync(cts.Token);
            Assert.Equal("windows-update", check.ProviderId);
            Assert.Equal(BiosCheckStatus.UpdateAvailable, check.Latest.Status);
            Assert.Equal(SampleWuaUpdateId.ToString("D"), check.Latest.PackageId);

            var installRequest = new BiosInstallRequest(
                System: identity,
                Current: identity.CurrentBios,
                Target: check.Latest,
                Approved: true,
                ApprovedBy: "operator@contoso.com",
                SuspendBitLocker: true,
                AllowReboot: false,
                VerifyHash: true);

            var result = await service.InstallUpdateAsync(installRequest, ct: cts.Token);

            Assert.True(result.Succeeded, result.Message);
            Assert.Equal(BiosInstallStatus.StagedForReboot, result.Status);
            Assert.True(result.BitLockerSuspended);

            // Un-elevated Host must NOT invoke local WUA install or local processes
            Assert.Empty(localWua.InstalledUpdateIds);
            Assert.Empty(hostLauncher.Calls);

            // Agent executed BitLocker suspend and WUA firmware install by UpdateID
            Assert.Single(agentLauncher.Calls);
            Assert.Equal("manage-bde.exe", agentLauncher.Calls[0].BaseName, ignoreCase: true);
            Assert.Contains(
                $"IsInstalled=0 and UpdateID='{SampleWuaUpdateId:D}'",
                fakeWuaApi.SearchCriteria);

            Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, result.Message, StringComparison.OrdinalIgnoreCase);
            loggerFactory.AssertDoesNotContainSecret();
        }
        finally
        {
            await client.DisposeAsync();
            await serverTask;
            server.Dispose();
        }
    }

    [Fact]
    public async Task DiInjection_DefaultBiosInstallSafetyProbe_ResolvesElevationContext_HasElevationTracksAdminCapabilities()
    {
        // Case A: Un-elevated Host with connected elevated Agent -> HasElevation == true
        {
            var elevation = new StubElevationContext(isProcessElevated: false, isAdminHelperConnected: true);
            var services = new ServiceCollection();
            // Intentionally omit IBiosInstallSafetyProbe so real DefaultBiosInstallSafetyProbe is resolved from DI.
            services.AddSingleton<IElevationContext>(elevation);
            services.AddBiosUpdates();
            services.AddBuiltInBiosUpdateProviders();

            using var sp = services.BuildServiceProvider(StrictValidation);
            var probe = sp.GetRequiredService<IBiosInstallSafetyProbe>();
            Assert.IsType<DefaultBiosInstallSafetyProbe>(probe);

            var snapshot = await probe.ProbeAsync();
            Assert.True(snapshot.HasElevation);
        }

        // Case B: Un-elevated Host without connected Agent -> HasElevation == false, then toggles true when connected
        {
            var elevation = new StubElevationContext(isProcessElevated: false, isAdminHelperConnected: false);
            var services = new ServiceCollection();
            services.AddSingleton<IElevationContext>(elevation);
            services.AddBiosUpdates();
            services.AddBuiltInBiosUpdateProviders();

            using var sp = services.BuildServiceProvider(StrictValidation);
            var probe = sp.GetRequiredService<IBiosInstallSafetyProbe>();
            Assert.IsType<DefaultBiosInstallSafetyProbe>(probe);

            var disconnectedSnapshot = await probe.ProbeAsync();
            Assert.False(disconnectedSnapshot.HasElevation);

            elevation.IsAdminHelperConnected = true;
            var connectedSnapshot = await probe.ProbeAsync();
            Assert.True(connectedSnapshot.HasElevation);
        }
    }

    [Fact]
    public async Task DiInjection_UnElevatedHostWithoutConnectedAgent_BlocksCleanlyAtSafetyGate()
    {
        using var httpHandler = new FakeBiosHttpHandler();
        using var httpClient = httpHandler.CreateClient();
        var launcher = CreateGuardedLauncher();
        var identity = BiosIdentityFactory.Hp();

        var services = new ServiceCollection();
        services.AddSingleton<IBiosSystemProbe>(new StubSystemProbe(identity));
        // Real DefaultBiosInstallSafetyProbe (omitted stub) + IsProcessElevated = false, IsAdminHelperConnected = false
        services.AddSingleton<IElevationContext>(new StubElevationContext(isProcessElevated: false, isAdminHelperConnected: false));
        services.AddSingleton<HttpClient>(httpClient);
        services.AddSingleton(RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: false));
        services.AddBiosUpdates();
        services.AddBuiltInBiosUpdateProviders();

        using var sp = services.BuildServiceProvider(StrictValidation);
        var service = sp.GetRequiredService<IBiosUpdateService>();

        var request = BiosIdentityFactory.CreateInstallRequest(
            system: identity,
            downloadUrl: HpDownloadUrl,
            sha256: ValidSha256,
            suspendBitLocker: true,
            allowReboot: false);

        var safety = await service.EvaluateInstallSafetyAsync(request);
        Assert.False(safety.Passed);
        Assert.Contains(safety.BlockingReasons, r => r.Contains("Administrator", StringComparison.OrdinalIgnoreCase));

        var result = await service.InstallUpdateAsync(request);

        Assert.False(result.Succeeded);
        Assert.Equal(BiosInstallStatus.BlockedByPrerequisites, result.Status);
        Assert.Contains("Administrator", result.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(httpHandler.Requests);
        Assert.Empty(launcher.Calls);
    }

    // =========================================================================
    // Group 7 — HostServices.cs Wiring & Static Pure-C# / Logging-Convention Audit
    // =========================================================================

    [Fact]
    public void HostServices_CallsAddBuiltInBiosUpdateProvidersDirectlyAfterAddBiosUpdates()
    {
        var repoRoot = FindRepoRoot();
        var hostServicesPath = Path.Combine(repoRoot, "src", "RemotePCDiagnostics.Host", "HostServices.cs");
        Assert.True(File.Exists(hostServicesPath), $"Expected file not found: {hostServicesPath}");

        var source = File.ReadAllText(hostServicesPath);
        var stripped = StripComments(source);
        var codeLines = stripped
            .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .Select(l => l.Trim())
            .Where(l => l.Length > 0)
            .ToList();

        var addBiosUpdatesIdx = codeLines.FindIndex(l => l == "services.AddBiosUpdates();");
        Assert.True(addBiosUpdatesIdx >= 0, "HostServices.cs must call services.AddBiosUpdates();");
        Assert.True(addBiosUpdatesIdx + 1 < codeLines.Count, "Expected a statement immediately after services.AddBiosUpdates();");
        Assert.Equal("services.AddBuiltInBiosUpdateProviders();", codeLines[addBiosUpdatesIdx + 1]);
    }

    [Fact]
    public void BiosDiWiringAndHostServices_ContainZeroLoggingNamespaceImportAndZeroShellReferences()
    {
        var repoRoot = FindRepoRoot();
        var filesToAudit = new[]
        {
            Path.Combine(repoRoot, "src", "RemotePCDiagnostics.Core", "Bios", "BiosServiceCollectionExtensions.cs"),
            Path.Combine(repoRoot, "src", "RemotePCDiagnostics.Host", "HostServices.cs"),
        };

        var forbiddenLoggingDirective = new Regex(
            @"(?m)^\s*(?:global\s+)?using\s+Microsoft\.Extensions\.Logging\s*;",
            RegexOptions.CultureInvariant);

        var forbiddenShellTokens = new[]
        {
            "powershell.exe",
            "RunPowerShellAsync",
            "PowerShellArgs",
            "BitLockerProbeScript",
            "pwsh.exe",
            "cmd.exe",
            "/bin/sh",
        };

        var forbiddenScriptExtensionRegex = new Regex(
            @"(?i)\.(?:ps1|bat|cmd|sh)(?![A-Za-z0-9_])",
            RegexOptions.CultureInvariant);

        foreach (var path in filesToAudit)
        {
            Assert.True(File.Exists(path), $"Expected file not found: {path}");
            var text = File.ReadAllText(path);

            Assert.DoesNotMatch(forbiddenLoggingDirective, text);
            Assert.DoesNotMatch(forbiddenScriptExtensionRegex, text);

            foreach (var token in forbiddenShellTokens)
            {
                Assert.DoesNotContain(token, text, StringComparison.OrdinalIgnoreCase);
            }
        }
    }

    // =========================================================================
    // Private Test Helpers (Zero Edits to BiosTestHarness.cs)
    // =========================================================================

    private static BiosSystemIdentity WithMode(BiosSystemIdentity identity, BiosFirmwareMode mode) =>
        identity with { CurrentBios = identity.CurrentBios with { FirmwareMode = mode } };

    private static RecordingProcessLauncher CreateGuardedLauncher(
        Func<RecordedProcessCall, CancellationToken, Task<ProcessResult>>? inner = null) =>
        new((call, ct) =>
        {
            if (ForbiddenShellBinaries.Contains(call.BaseName))
                throw new InvalidOperationException($"Pure-C# violation: forbidden shell binary '{call.FileName}' invoked.");

            foreach (var arg in call.Arguments)
            {
                foreach (var ext in ForbiddenScriptExtensions)
                {
                    if (arg.EndsWith(ext, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException($"Pure-C# violation: forbidden script argument '{arg}' passed.");
                }
            }

            return inner is not null ? inner(call, ct) : Task.FromResult(new ProcessResult(0, "", ""));
        });

    private static void RegisterBuiltInProviderGeneric(IServiceCollection services, Type providerType)
    {
        if (providerType == typeof(HpBiosUpdateProvider))
            services.AddBiosUpdateProvider<HpBiosUpdateProvider>();
        else if (providerType == typeof(DellBiosUpdateProvider))
            services.AddBiosUpdateProvider<DellBiosUpdateProvider>();
        else if (providerType == typeof(LenovoBiosUpdateProvider))
            services.AddBiosUpdateProvider<LenovoBiosUpdateProvider>();
        else if (providerType == typeof(AsusBiosUpdateProvider))
            services.AddBiosUpdateProvider<AsusBiosUpdateProvider>();
        else if (providerType == typeof(AcerBiosUpdateProvider))
            services.AddBiosUpdateProvider<AcerBiosUpdateProvider>();
        else if (providerType == typeof(MsiBiosUpdateProvider))
            services.AddBiosUpdateProvider<MsiBiosUpdateProvider>();
        else if (providerType == typeof(MicrosoftSurfaceBiosUpdateProvider))
            services.AddBiosUpdateProvider<MicrosoftSurfaceBiosUpdateProvider>();
        else if (providerType == typeof(FrameworkBiosUpdateProvider))
            services.AddBiosUpdateProvider<FrameworkBiosUpdateProvider>();
        else if (providerType == typeof(WindowsUpdateBiosProvider))
            services.AddBiosUpdateProvider<WindowsUpdateBiosProvider>();
        else
            throw new ArgumentOutOfRangeException(nameof(providerType), providerType, "Unexpected provider type.");
    }

    private static BiosSystemIdentity CreateIdentityForVendor(string vendorId) => vendorId switch
    {
        "hp" => BiosIdentityFactory.Hp(),
        "dell" => BiosIdentityFactory.Dell(),
        "lenovo" => BiosIdentityFactory.Lenovo(),
        "asus" => BiosIdentityFactory.Asus(),
        "acer" => BiosIdentityFactory.Acer(),
        "msi" => BiosIdentityFactory.Msi(),
        "microsoft" => BiosIdentityFactory.MicrosoftSurface(),
        "framework" => BiosIdentityFactory.Framework(),
        "windows-update" => BiosIdentityFactory.GenericUefi(),
        _ => throw new ArgumentOutOfRangeException(nameof(vendorId), vendorId, "Unexpected vendor ID."),
    };

    private static async Task<(AdminPipeServer Server, Task ServerTask, AdminPipeClient Client)> StartPipeAsync(
        IProcessLauncher agentLauncher,
        IAgentBiosOperations biosOps,
        CancellationTokenSource cts,
        ILogger? log = null)
    {
        var pipeName = $"rpd-bios-int-{Guid.NewGuid():N}";
        var server = new AdminPipeServer(
            new AdminPipeServerOptions
            {
                PipeName = pipeName,
                ExpectedClientPid = Environment.ProcessId,
            },
            launcher: agentLauncher,
            log: log,
            biosOperations: biosOps);

        var serverTask = server.RunSingleSessionAsync(cts.Token);
        try
        {
            var client = await AdminPipeClient.ConnectAsync(pipeName, TimeSpan.FromSeconds(10), cts.Token);
            return (server, serverTask, client);
        }
        catch
        {
            cts.Cancel();
            server.Dispose();
            try
            {
                await serverTask;
            }
            catch
            {
                // Expected when the server session is cancelled/disposed after a failed client connect.
            }
            throw;
        }
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "RemotePCDiagnostics.sln")))
                return dir.FullName;
            dir = dir.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate RemotePCDiagnostics.sln from AppContext.BaseDirectory.");
    }

    private static string StripComments(string source)
    {
        var withoutBlock = Regex.Replace(source, @"/\*.*?\*/", "", RegexOptions.Singleline);
        return Regex.Replace(withoutBlock, @"//[^\r\n]*", "");
    }

    private sealed class StubSystemProbe(BiosSystemIdentity identity) : IBiosSystemProbe
    {
        public BiosSystemIdentity Identity { get; set; } = identity;

        public Task<BiosSystemIdentity> ProbeAsync(CancellationToken ct = default) =>
            Task.FromResult(Identity);
    }

    private sealed class StubSafetyProbe(BiosSafetySnapshot snapshot) : IBiosInstallSafetyProbe
    {
        public int ProbeCount { get; private set; }

        public Task<BiosSafetySnapshot> ProbeAsync(CancellationToken ct = default)
        {
            ProbeCount++;
            return Task.FromResult(snapshot);
        }
    }

    private sealed class ElevationAwareStubSafetyProbe(IElevationContext elevation) : IBiosInstallSafetyProbe
    {
        public int ProbeCount { get; private set; }

        public Task<BiosSafetySnapshot> ProbeAsync(CancellationToken ct = default)
        {
            ProbeCount++;
            return Task.FromResult(BiosIdentityFactory.SafeSnapshot() with { HasElevation = elevation.HasAdminCapabilities });
        }
    }

    private sealed class StubElevationContext(bool isProcessElevated, bool isAdminHelperConnected) : IElevationContext
    {
        public bool IsProcessElevated { get; set; } = isProcessElevated;
        public bool IsAdminHelperConnected { get; set; } = isAdminHelperConnected;
        // These tests prove DI wiring of IElevationContext into providers, so "elevated" still counts here.
        // The real ElevationService only counts the Agent (the app never runs as admin).
        public bool HasAdminCapabilities => IsProcessElevated || IsAdminHelperConnected;

        public event Action? Changed
        {
            add { }
            remove { }
        }

        public Task<ElevationResult> EnableAdminModeAsync(CancellationToken ct = default) =>
            Task.FromResult(new ElevationResult(false, false, "Stub elevation context."));
    }

    private sealed class StubElevatedCommandBridge(bool isConnected) : IElevatedCommandBridge
    {
        public bool IsConnected => isConnected;

        public Task<ProcessResult?> RunElevatedAsync(
            string fileName,
            IReadOnlyList<string> arguments,
            TimeSpan timeout,
            CancellationToken ct,
            Action<string>? outputLine = null) =>
            Task.FromResult<ProcessResult?>(null);

        public Task<SensorSnapshot?> ReadSensorsAsync(CancellationToken ct = default) =>
            Task.FromResult<SensorSnapshot?>(null);

        public Task<IReadOnlyList<DriveHealth>?> ReadDrivesAsync(CancellationToken ct = default) =>
            Task.FromResult<IReadOnlyList<DriveHealth>?>(null);
    }

    private sealed class DisposeTrackingHttpHandler(HttpMessageHandler inner) : HttpMessageHandler
    {
        private readonly HttpMessageInvoker _invoker = new(inner, disposeHandler: false);
        private int _requestCount;
        private int _disposeCount;

        public int RequestCount => Volatile.Read(ref _requestCount);
        public int DisposeCount => Volatile.Read(ref _disposeCount);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            ObjectDisposedException.ThrowIf(DisposeCount > 0, this);
            Interlocked.Increment(ref _requestCount);
            return _invoker.SendAsync(request, cancellationToken);
        }

        protected override void Dispose(bool disposing)
        {
            Interlocked.Increment(ref _disposeCount);
            if (disposing)
                _invoker.Dispose();
            base.Dispose(disposing);
        }
    }

    private sealed class CapturingLoggerFactory : Microsoft.Extensions.Logging.ILoggerFactory
    {
        private readonly Lock _lock = new();
        private readonly List<string> _categories = [];
        private readonly List<(string Category, Microsoft.Extensions.Logging.LogLevel Level, string Message)> _entries = [];

        public IReadOnlyList<string> RequestedCategories
        {
            get
            {
                lock (_lock)
                    return [.. _categories];
            }
        }

        public IReadOnlyList<(string Category, Microsoft.Extensions.Logging.LogLevel Level, string Message)> Entries
        {
            get
            {
                lock (_lock)
                    return [.. _entries];
            }
        }

        public ILogger CreateLogger(string categoryName)
        {
            lock (_lock)
                _categories.Add(categoryName);
            return new CapturingLogger(categoryName, this);
        }

        public void AddProvider(Microsoft.Extensions.Logging.ILoggerProvider provider) { }

        public void Dispose() { }

        public void AssertDoesNotContainSecret(string secret = BiosIdentityFactory.SentinelSerialNumber)
        {
            var combined = string.Join("\n", Entries.Select(e => e.Message));
            Assert.DoesNotContain(secret, combined, StringComparison.OrdinalIgnoreCase);
        }

        private void Record(string category, Microsoft.Extensions.Logging.LogLevel level, string message)
        {
            lock (_lock)
                _entries.Add((category, level, message));
        }

        private sealed class CapturingLogger(string category, CapturingLoggerFactory owner) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => true;

            public void Log<TState>(
                Microsoft.Extensions.Logging.LogLevel logLevel,
                Microsoft.Extensions.Logging.EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                var msg = formatter(state, exception);
                if (exception is not null)
                    msg = $"{msg} | {exception}";
                owner.Record(category, logLevel, msg);
            }
        }
    }

    private sealed class CustomBiosProvider(
        string vendorId,
        string displayName,
        int priority,
        Func<BiosSystemIdentity, bool> canHandle) : IBiosUpdateProvider
    {
        public string VendorId => vendorId;
        public string DisplayName => displayName;
        public int Priority => priority;
        public BiosProviderCapabilities Capabilities => new(CanCheckLatest: true, CanInstall: false);

        public bool CanHandle(BiosSystemIdentity system) => system is not null && canHandle(system);

        public Task<BiosCurrentInfo> GetCurrentVersionAsync(BiosSystemIdentity system, CancellationToken ct = default) =>
            Task.FromResult(system.CurrentBios with { ProviderId = vendorId });

        public Task<BiosLatestInfo> GetLatestVersionAsync(BiosSystemIdentity system, BiosCurrentInfo current, CancellationToken ct = default) =>
            Task.FromResult(BiosLatestInfo.UpToDate(vendorId, current.Version));

        public Task<BiosInstallResult> InstallAsync(
            BiosInstallRequest request,
            IProgress<BiosInstallProgress>? progress = null,
            CancellationToken ct = default) =>
            Task.FromResult(BiosInstallResult.Unsupported($"Provider '{vendorId}' is check-only."));
    }

    private sealed class FakeWuaUpdate(string title, bool eulaAccepted, bool isDownloaded) : IFoundUpdate
    {
        public string Title { get; } = title;
        public bool EulaAccepted { get; private set; } = eulaAccepted;
        public bool IsDownloaded { get; set; } = isDownloaded;
        public void AcceptEula() => EulaAccepted = true;
    }

    private sealed class FakeWuaApi : IWindowsUpdateApi
    {
        public List<string> SearchCriteria { get; } = [];
        public IReadOnlyList<FakeWuaUpdate> FoundUpdates { get; set; } = [];
        public int DownloadResult { get; set; } = AgentWindowsUpdate.SucceededCode;
        public UpdateInstallOutcome InstallOutcome { get; set; } = new(AgentWindowsUpdate.SucceededCode, 0, true);

        public IReadOnlyList<IFoundUpdate> Search(string criteria)
        {
            SearchCriteria.Add(criteria);
            return FoundUpdates;
        }

        public int Download(IReadOnlyList<IFoundUpdate> updates)
        {
            foreach (var u in updates.OfType<FakeWuaUpdate>())
                u.IsDownloaded = DownloadResult is AgentWindowsUpdate.SucceededCode or AgentWindowsUpdate.SucceededWithErrorsCode;
            return DownloadResult;
        }

        public UpdateInstallOutcome Install(IReadOnlyList<IFoundUpdate> updates) => InstallOutcome;

        public void StartInteractiveScan() { }
    }
}
