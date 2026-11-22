using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.IO.Compression;
using System.IO.Pipes;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Bios;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests.Bios.E2E;

/// <summary>
/// Self-contained opaque-box E2E test harness for the built-in BIOS update providers and
/// Agent elevation bridge. Wires the real production DI container
/// (<see cref="BiosServiceCollectionExtensions.AddBiosUpdates"/> +
/// <see cref="BiosServiceCollectionExtensions.AddBuiltInBiosUpdateProviders"/>) and replaces
/// only external I/O boundaries (HTTP, child processes, SMBIOS probe, safety probe, WUA COM,
/// Authenticode P/Invoke, and optional live cross-platform Admin Pipe).
/// </summary>
internal sealed class BiosE2eTestHost : IAsyncDisposable
{
    public const string CanarySerial = "SN-SECRET-CANARY-994821";

    public StubSystemProbe SystemProbe { get; }
    public StubSafetyProbe SafetyProbe { get; }
    public HermeticElevationSafetyProbe? HermeticSafetyProbe { get; }
    public StubElevationContext ElevationContext { get; }
    public ScriptedHttpHandler HttpHandler { get; }
    public RecordingProcessLauncher HostProcessLauncher { get; }
    public StubSignatureVerifier SignatureVerifier { get; }
    public StubWindowsUpdateClient WindowsUpdateClient { get; }
    public CapturingLoggerFactory LoggerFactory { get; }
    public IsolatedStagingDir StagingDir { get; }
    public LiveAgentPipeFixture? LivePipe { get; }
    public IElevatedCommandBridge? RegisteredBridge { get; }
    public ServiceProvider ServiceProvider { get; }
    public IBiosUpdateService Service { get; }

    private BiosE2eTestHost(
        StubSystemProbe systemProbe,
        StubSafetyProbe safetyProbe,
        HermeticElevationSafetyProbe? hermeticSafetyProbe,
        StubElevationContext elevationContext,
        ScriptedHttpHandler httpHandler,
        RecordingProcessLauncher hostProcessLauncher,
        StubSignatureVerifier signatureVerifier,
        StubWindowsUpdateClient windowsUpdateClient,
        CapturingLoggerFactory loggerFactory,
        IsolatedStagingDir stagingDir,
        LiveAgentPipeFixture? livePipe,
        IElevatedCommandBridge? registeredBridge,
        ServiceProvider serviceProvider)
    {
        SystemProbe = systemProbe;
        SafetyProbe = safetyProbe;
        HermeticSafetyProbe = hermeticSafetyProbe;
        ElevationContext = elevationContext;
        HttpHandler = httpHandler;
        HostProcessLauncher = hostProcessLauncher;
        SignatureVerifier = signatureVerifier;
        WindowsUpdateClient = windowsUpdateClient;
        LoggerFactory = loggerFactory;
        StagingDir = stagingDir;
        LivePipe = livePipe;
        RegisteredBridge = registeredBridge;
        ServiceProvider = serviceProvider;
        Service = serviceProvider.GetRequiredService<IBiosUpdateService>();
    }

    public static async Task<BiosE2eTestHost> CreateAsync(
        BiosE2eHostOptions? options = null,
        CancellationToken ct = default)
    {
        options ??= new BiosE2eHostOptions();

        var systemProbe = new StubSystemProbe(options.InitialIdentity ?? E2eIdentities.HpEliteBook());
        var safetyProbe = new StubSafetyProbe(options.InitialSafetySnapshot ?? StubSafetyProbe.SafeLaptop());
        var elevationContext = new StubElevationContext(
            isProcessElevated: options.IsProcessElevated,
            isAdminHelperConnected: options.IsAdminHelperConnected ?? (options.UseLiveAgentPipe || options.UseLegacyAgentPipe || options.UseMinimalLegacyBridge));
        var httpHandler = new ScriptedHttpHandler();
        var hostLauncher = new RecordingProcessLauncher("Host");
        var signatureVerifier = new StubSignatureVerifier(options.SignatureVerificationResult);
        var wuaClient = new StubWindowsUpdateClient();
        var loggerFactory = new CapturingLoggerFactory();
        var stagingDir = new IsolatedStagingDir("host");

        LiveAgentPipeFixture? livePipe = null;
        IElevatedCommandBridge? bridge = null;

        try
        {
            if (options.UseLiveAgentPipe || options.UseLegacyAgentPipe)
            {
                livePipe = await LiveAgentPipeFixture.StartAsync(
                    legacyWithoutBiosOps: options.UseLegacyAgentPipe,
                    agentSignatureResult: options.AgentSignatureVerificationResult,
                    createAllowlistedDcuTool: options.CreateAllowlistedDcuTool,
                    includeWindowsSystemProgramFilesToolRoots: options.IncludeWindowsSystemProgramFilesToolRoots,
                    ct: ct).ConfigureAwait(false);
                bridge = livePipe.Client;
            }
            else if (options.CustomBridge is not null)
            {
                bridge = options.CustomBridge;
            }
            else if (options.UseMinimalLegacyBridge)
            {
                bridge = new MinimalLegacyBridgeStub(isConnected: true);
            }
            else if (options.UseDisconnectedBridge)
            {
                bridge = new DisconnectedBridgeStub();
            }

            HermeticElevationSafetyProbe? hermeticProbe = null;
            var services = new ServiceCollection();

            services.AddSingleton<IBiosSystemProbe>(systemProbe);

            if (options.UseHermeticRealSafetyProbe)
            {
                var realProbe = new DefaultBiosInstallSafetyProbe(
                    elevation: elevationContext,
                    bitLockerProbe: _ => Task.FromResult<int?>(0));
                hermeticProbe = new HermeticElevationSafetyProbe(
                    realProbe,
                    real => new BiosSafetySnapshot(
                        OnAcPower: options.HermeticOnAcPower,
                        HasBattery: options.HermeticHasBattery,
                        BatteryPercent: options.HermeticBatteryPercent,
                        BitLockerActive: options.HermeticBitLockerActive,
                        BitLockerSuspended: options.HermeticBitLockerSuspended,
                        HasElevation: real.HasElevation,
                        PendingReboot: options.HermeticPendingReboot));
                services.AddSingleton<IBiosInstallSafetyProbe>(hermeticProbe);
            }
            else if (!options.UseRawRealSafetyProbe)
            {
                services.AddSingleton<IBiosInstallSafetyProbe>(safetyProbe);
            }

            services.AddSingleton<HttpMessageHandler>(httpHandler);
            if (options.RegisterElevationContext)
                services.AddSingleton<IElevationContext>(elevationContext);
            if (bridge is not null)
                services.AddSingleton<IElevatedCommandBridge>(bridge);

            services.AddSingleton(new SystemCommandRunner(
                launcher: hostLauncher,
                log: loggerFactory.CreateLogger<SystemCommandRunner>(),
                elevatedBridge: bridge,
                isProcessElevated: () => elevationContext.IsProcessElevated));

            if (options.RegisterSignatureVerifier)
                services.AddSingleton<IBiosSignatureVerifier>(signatureVerifier);
            if (options.RegisterWindowsUpdateClient)
                services.AddSingleton<IBiosWindowsUpdateClient>(wuaClient);

            services.AddSingleton<Microsoft.Extensions.Logging.ILoggerFactory>(loggerFactory);

            services.AddBiosUpdates();
            services.AddBuiltInBiosUpdateProviders();

            options.ConfigureServices?.Invoke(services, hostLauncher, httpHandler, signatureVerifier, wuaClient, loggerFactory);

            var sp = services.BuildServiceProvider(new ServiceProviderOptions
            {
                ValidateOnBuild = true,
                ValidateScopes = true
            });

            return new BiosE2eTestHost(
                systemProbe,
                safetyProbe,
                hermeticProbe,
                elevationContext,
                httpHandler,
                hostLauncher,
                signatureVerifier,
                wuaClient,
                loggerFactory,
                stagingDir,
                livePipe,
                bridge,
                sp);
        }
        catch
        {
            if (livePipe is not null)
                await livePipe.DisposeAsync().ConfigureAwait(false);
            stagingDir.Dispose();
            httpHandler.Dispose();
            throw;
        }
    }

    public static BiosE2eTestHost CreateElevated(
        BiosSystemIdentity? identity = null,
        BiosSafetySnapshot? safety = null,
        bool registerSignatureVerifier = true,
        bool registerWindowsUpdateClient = true,
        Action<IServiceCollection, RecordingProcessLauncher, ScriptedHttpHandler, StubSignatureVerifier, StubWindowsUpdateClient, CapturingLoggerFactory>? configureServices = null)
    {
        return CreateAsync(new BiosE2eHostOptions
        {
            InitialIdentity = identity,
            InitialSafetySnapshot = safety,
            IsProcessElevated = true,
            IsAdminHelperConnected = false,
            RegisterSignatureVerifier = registerSignatureVerifier,
            RegisterWindowsUpdateClient = registerWindowsUpdateClient,
            ConfigureServices = configureServices
        }).GetAwaiter().GetResult();
    }

    public void AssertNoSerialNumberLeaked(string serial = CanarySerial, BiosInstallResult? result = null)
    {
        Assert.False(string.IsNullOrWhiteSpace(serial), "Canary serial number must be non-empty.");

        foreach (var entry in LoggerFactory.Entries)
        {
            Assert.DoesNotContain(serial, entry.Message, StringComparison.OrdinalIgnoreCase);
            if (entry.Exception is not null)
                Assert.DoesNotContain(serial, entry.Exception.Message, StringComparison.OrdinalIgnoreCase);
        }

        if (LivePipe is not null)
        {
            foreach (var entry in LivePipe.AgentLoggerFactory.Entries)
            {
                Assert.DoesNotContain(serial, entry.Message, StringComparison.OrdinalIgnoreCase);
                if (entry.Exception is not null)
                    Assert.DoesNotContain(serial, entry.Exception.Message, StringComparison.OrdinalIgnoreCase);
            }
        }

        foreach (var req in HttpHandler.Requests)
        {
            Assert.DoesNotContain(serial, req.RequestUri.ToString(), StringComparison.OrdinalIgnoreCase);
            foreach (var h in req.Headers)
                Assert.DoesNotContain(serial, h, StringComparison.OrdinalIgnoreCase);
        }

        foreach (var call in HostProcessLauncher.Calls)
        {
            Assert.DoesNotContain(serial, call.FileName, StringComparison.OrdinalIgnoreCase);
            foreach (var arg in call.Arguments)
                Assert.DoesNotContain(serial, arg, StringComparison.OrdinalIgnoreCase);
        }

        if (LivePipe is not null)
        {
            foreach (var call in LivePipe.AgentProcessLauncher.Calls)
            {
                Assert.DoesNotContain(serial, call.FileName, StringComparison.OrdinalIgnoreCase);
                foreach (var arg in call.Arguments)
                    Assert.DoesNotContain(serial, arg, StringComparison.OrdinalIgnoreCase);
            }
        }

        if (result is not null)
        {
            Assert.DoesNotContain(serial, result.Message ?? "", StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(serial, result.LogTail ?? "", StringComparison.OrdinalIgnoreCase);
        }
    }

    public void AssertZeroShellInvocations()
    {
        HostProcessLauncher.AssertNoForbiddenShellCalls();
        LivePipe?.AgentProcessLauncher.AssertNoForbiddenShellCalls();
    }

    public async ValueTask DisposeAsync()
    {
        // Dispose ServiceProvider first; if LivePipe is active, LivePipe.DisposeAsync closes client BEFORE awaiting serverTask.
        await ServiceProvider.DisposeAsync().ConfigureAwait(false);
        if (LivePipe is not null)
            await LivePipe.DisposeAsync().ConfigureAwait(false);
        HttpHandler.Dispose();
        StagingDir.Dispose();
    }
}

internal sealed class BiosE2eHostOptions
{
    public BiosSystemIdentity? InitialIdentity { get; init; }
    public BiosSafetySnapshot? InitialSafetySnapshot { get; init; }
    public bool IsProcessElevated { get; init; } = true;
    public bool? IsAdminHelperConnected { get; init; }
    public bool UseLiveAgentPipe { get; init; }
    public bool UseLegacyAgentPipe { get; init; }
    public bool UseDisconnectedBridge { get; init; }
    public bool UseMinimalLegacyBridge { get; init; }
    public IElevatedCommandBridge? CustomBridge { get; init; }
    public bool RegisterElevationContext { get; init; } = true;
    public bool RegisterSignatureVerifier { get; init; } = true;
    public bool RegisterWindowsUpdateClient { get; init; } = true;
    public bool SignatureVerificationResult { get; init; } = true;
    public bool AgentSignatureVerificationResult { get; init; } = true;
    public bool CreateAllowlistedDcuTool { get; init; }
    public bool IncludeWindowsSystemProgramFilesToolRoots { get; init; }
    public bool UseHermeticRealSafetyProbe { get; init; }
    public bool UseRawRealSafetyProbe { get; init; }
    public bool HermeticOnAcPower { get; init; } = true;
    public bool HermeticHasBattery { get; init; } = true;
    public int HermeticBatteryPercent { get; init; } = 100;
    public bool HermeticBitLockerActive { get; init; }
    public bool HermeticBitLockerSuspended { get; init; }
    public bool HermeticPendingReboot { get; init; }
    public Action<IServiceCollection, RecordingProcessLauncher, ScriptedHttpHandler, StubSignatureVerifier, StubWindowsUpdateClient, CapturingLoggerFactory>? ConfigureServices { get; init; }
}

internal static class E2eIdentities
{
    public static BiosSystemIdentity HpEliteBook(
        string boardProduct = "8B41",
        string biosVersion = "U74 Ver. 01.10.00",
        string osVersion = "Windows 11 23H2",
        BiosFirmwareMode firmwareMode = BiosFirmwareMode.Uefi,
        DateOnly? releaseDate = null,
        string serial = BiosE2eTestHost.CanarySerial,
        string manufacturer = "HP",
        string boardManufacturer = "HP",
        string systemSku = "") =>
        new(
            Manufacturer: manufacturer,
            Model: "HP EliteBook 840 G10",
            SystemSku: systemSku,
            BoardManufacturer: boardManufacturer,
            BoardProduct: boardProduct,
            BoardVersion: "KBC Version 01",
            SerialNumber: serial,
            OsVersion: osVersion,
            Architecture: "X64",
            CurrentBios: new BiosCurrentInfo(
                Vendor: "HP",
                Version: biosVersion,
                ReleaseDate: releaseDate ?? new DateOnly(2024, 6, 1),
                ReleaseDateRaw: (releaseDate ?? new DateOnly(2024, 6, 1)).ToString("yyyy-MM-dd"),
                FirmwareMode: firmwareMode));

    public static BiosSystemIdentity DellLatitude(
        string systemSku = "0A1B",
        string biosVersion = "1.12.0",
        string osVersion = "Windows 11 23H2",
        BiosFirmwareMode firmwareMode = BiosFirmwareMode.Uefi,
        DateOnly? releaseDate = null,
        string serial = BiosE2eTestHost.CanarySerial) =>
        new(
            Manufacturer: "Dell Inc.",
            Model: "Latitude 5430",
            SystemSku: systemSku,
            BoardManufacturer: "Dell Inc.",
            BoardProduct: "0X1Y2Z",
            BoardVersion: "A00",
            SerialNumber: serial,
            OsVersion: osVersion,
            Architecture: "X64",
            CurrentBios: new BiosCurrentInfo(
                Vendor: "Dell Inc.",
                Version: biosVersion,
                ReleaseDate: releaseDate ?? new DateOnly(2024, 5, 1),
                ReleaseDateRaw: (releaseDate ?? new DateOnly(2024, 5, 1)).ToString("yyyy-MM-dd"),
                FirmwareMode: firmwareMode));

    public static BiosSystemIdentity LenovoThinkPad(
        string model = "21HM001GUS",
        string systemSku = "LENOVO_MT_21HM_BU_think_FM_ThinkPad X1 Carbon Gen 11",
        string biosVersion = "N3XET48W (1.23 )",
        string osVersion = "Windows 11 23H2",
        BiosFirmwareMode firmwareMode = BiosFirmwareMode.Uefi,
        DateOnly? releaseDate = null,
        string serial = BiosE2eTestHost.CanarySerial) =>
        new(
            Manufacturer: "LENOVO",
            Model: model,
            SystemSku: systemSku,
            BoardManufacturer: "LENOVO",
            BoardProduct: "21HM001GUS",
            BoardVersion: "SDK0T76461 WIN",
            SerialNumber: serial,
            OsVersion: osVersion,
            Architecture: "X64",
            CurrentBios: new BiosCurrentInfo(
                Vendor: "LENOVO",
                Version: biosVersion,
                ReleaseDate: releaseDate ?? new DateOnly(2024, 4, 15),
                ReleaseDateRaw: (releaseDate ?? new DateOnly(2024, 4, 15)).ToString("yyyy-MM-dd"),
                FirmwareMode: firmwareMode));

    public static BiosSystemIdentity AsusRog(
        string model = "ROG STRIX Z790-E GAMING WIFI",
        string boardProduct = "ROG STRIX Z790-E GAMING WIFI",
        string biosVersion = "1801",
        BiosFirmwareMode firmwareMode = BiosFirmwareMode.Uefi,
        DateOnly? releaseDate = null,
        string serial = BiosE2eTestHost.CanarySerial,
        string manufacturer = "ASUSTeK COMPUTER INC.",
        string boardManufacturer = "ASUSTeK COMPUTER INC.") =>
        new(
            Manufacturer: manufacturer,
            Model: model,
            SystemSku: "SKU",
            BoardManufacturer: boardManufacturer,
            BoardProduct: boardProduct,
            BoardVersion: "Rev 1.xx",
            SerialNumber: serial,
            OsVersion: "Windows 11 23H2",
            Architecture: "X64",
            CurrentBios: new BiosCurrentInfo(
                Vendor: "American Megatrends Inc.",
                Version: biosVersion,
                ReleaseDate: releaseDate ?? new DateOnly(2024, 3, 10),
                ReleaseDateRaw: (releaseDate ?? new DateOnly(2024, 3, 10)).ToString("yyyy-MM-dd"),
                FirmwareMode: firmwareMode));

    public static BiosSystemIdentity AcerPredator(
        string model = "Predator PH315-55",
        string boardProduct = "Predator PH315-55",
        string biosVersion = "1.08",
        BiosFirmwareMode firmwareMode = BiosFirmwareMode.Uefi,
        DateOnly? releaseDate = null,
        string serial = BiosE2eTestHost.CanarySerial) =>
        new(
            Manufacturer: "Acer",
            Model: model,
            SystemSku: "Predator",
            BoardManufacturer: "Acer",
            BoardProduct: boardProduct,
            BoardVersion: "V1.08",
            SerialNumber: serial,
            OsVersion: "Windows 11 23H2",
            Architecture: "X64",
            CurrentBios: new BiosCurrentInfo(
                Vendor: "Insyde Corp.",
                Version: biosVersion,
                ReleaseDate: releaseDate ?? new DateOnly(2024, 2, 1),
                ReleaseDateRaw: (releaseDate ?? new DateOnly(2024, 2, 1)).ToString("yyyy-MM-dd"),
                FirmwareMode: firmwareMode));

    public static BiosSystemIdentity MsiMag(
        string model = "MAG B650 TOMAHAWK WIFI (MS-7D75)",
        string boardProduct = "MS-7D75",
        string biosVersion = "1.A0",
        BiosFirmwareMode firmwareMode = BiosFirmwareMode.Uefi,
        DateOnly? releaseDate = null,
        string serial = BiosE2eTestHost.CanarySerial) =>
        new(
            Manufacturer: "Micro-Star International Co., Ltd.",
            Model: model,
            SystemSku: "MS-7D75",
            BoardManufacturer: "Micro-Star International Co., Ltd.",
            BoardProduct: boardProduct,
            BoardVersion: "1.0",
            SerialNumber: serial,
            OsVersion: "Windows 11 23H2",
            Architecture: "X64",
            CurrentBios: new BiosCurrentInfo(
                Vendor: "American Megatrends International, LLC.",
                Version: biosVersion,
                ReleaseDate: releaseDate ?? new DateOnly(2024, 1, 20),
                ReleaseDateRaw: (releaseDate ?? new DateOnly(2024, 1, 20)).ToString("yyyy-MM-dd"),
                FirmwareMode: firmwareMode));

    public static BiosSystemIdentity SurfacePro9(
        string model = "Surface Pro 9",
        string boardProduct = "Surface Pro 9",
        string biosVersion = "15.100.143",
        string osVersion = "Windows 11 23H2",
        BiosFirmwareMode firmwareMode = BiosFirmwareMode.Uefi,
        DateOnly? releaseDate = null,
        string serial = BiosE2eTestHost.CanarySerial) =>
        new(
            Manufacturer: "Microsoft Corporation",
            Model: model,
            SystemSku: "Surface_Pro_9_2038",
            BoardManufacturer: "Microsoft Corporation",
            BoardProduct: boardProduct,
            BoardVersion: "1.0",
            SerialNumber: serial,
            OsVersion: osVersion,
            Architecture: "X64",
            CurrentBios: new BiosCurrentInfo(
                Vendor: "Microsoft Corporation",
                Version: biosVersion,
                ReleaseDate: releaseDate ?? new DateOnly(2024, 5, 10),
                ReleaseDateRaw: (releaseDate ?? new DateOnly(2024, 5, 10)).ToString("yyyy-MM-dd"),
                FirmwareMode: firmwareMode));

    public static BiosSystemIdentity HyperVVm(
        BiosFirmwareMode firmwareMode = BiosFirmwareMode.Legacy,
        string model = "Virtual Machine",
        string serial = BiosE2eTestHost.CanarySerial) =>
        new(
            Manufacturer: "Microsoft Corporation",
            Model: model,
            SystemSku: "None",
            BoardManufacturer: "Microsoft Corporation",
            BoardProduct: model,
            BoardVersion: "7.0",
            SerialNumber: serial,
            OsVersion: "Windows 11 23H2",
            Architecture: "X64",
            CurrentBios: new BiosCurrentInfo(
                Vendor: "Microsoft Corporation",
                Version: "Hyper-V UEFI Release v4.1",
                ReleaseDate: new DateOnly(2024, 1, 1),
                FirmwareMode: firmwareMode));

    public static BiosSystemIdentity FrameworkLaptop13(
        string model = "Laptop 13 (AMD Ryzen 7040Series)",
        string boardProduct = "FRANMDCP07",
        string systemSku = "FRANMDCP07",
        string biosVersion = "3.03",
        BiosFirmwareMode firmwareMode = BiosFirmwareMode.Uefi,
        DateOnly? releaseDate = null,
        string serial = BiosE2eTestHost.CanarySerial) =>
        new(
            Manufacturer: "Framework",
            Model: model,
            SystemSku: systemSku,
            BoardManufacturer: "Framework",
            BoardProduct: boardProduct,
            BoardVersion: "A7",
            SerialNumber: serial,
            OsVersion: "Windows 11 23H2",
            Architecture: "X64",
            CurrentBios: new BiosCurrentInfo(
                Vendor: "INSYDE Corp.",
                Version: biosVersion,
                ReleaseDate: releaseDate ?? new DateOnly(2024, 4, 1),
                ReleaseDateRaw: (releaseDate ?? new DateOnly(2024, 4, 1)).ToString("yyyy-MM-dd"),
                FirmwareMode: firmwareMode));

    public static BiosSystemIdentity GenericPc(
        string manufacturer = "Generic OEM",
        string model = "Custom Box",
        BiosFirmwareMode firmwareMode = BiosFirmwareMode.Uefi,
        string biosVersion = "1.0.0",
        string boardManufacturer = "Generic OEM",
        string boardProduct = "CustomBoard",
        string serial = BiosE2eTestHost.CanarySerial) =>
        new(
            Manufacturer: manufacturer,
            Model: model,
            SystemSku: "",
            BoardManufacturer: boardManufacturer,
            BoardProduct: boardProduct,
            BoardVersion: "1.0",
            SerialNumber: serial,
            OsVersion: "Windows 11 23H2",
            Architecture: "X64",
            CurrentBios: new BiosCurrentInfo(
                Vendor: manufacturer,
                Version: biosVersion,
                ReleaseDate: new DateOnly(2024, 1, 15),
                ReleaseDateRaw: "2024-01-15",
                FirmwareMode: firmwareMode));
}

internal sealed class StubSystemProbe(BiosSystemIdentity identity) : IBiosSystemProbe
{
    public BiosSystemIdentity Identity { get; set; } = identity;
    public Exception? ExceptionToThrow { get; set; }
    public int ProbeCount { get; private set; }

    public Task<BiosSystemIdentity> ProbeAsync(CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        ProbeCount++;
        if (ExceptionToThrow is not null)
            return Task.FromException<BiosSystemIdentity>(ExceptionToThrow);
        return Task.FromResult(Identity);
    }
}

internal sealed class StubSafetyProbe(BiosSafetySnapshot snapshot) : IBiosInstallSafetyProbe
{
    public BiosSafetySnapshot Snapshot { get; set; } = snapshot;
    public int ProbeCount { get; private set; }

    public static BiosSafetySnapshot SafeLaptop(bool bitLockerActive = false, bool bitLockerSuspended = false) =>
        new(OnAcPower: true, HasBattery: true, BatteryPercent: 80, BitLockerActive: bitLockerActive, BitLockerSuspended: bitLockerSuspended, HasElevation: true, PendingReboot: false);

    public static BiosSafetySnapshot SafeDesktop(bool bitLockerActive = false) =>
        new(OnAcPower: false, HasBattery: false, BatteryPercent: null, BitLockerActive: bitLockerActive, BitLockerSuspended: false, HasElevation: true, PendingReboot: false);

    public Task<BiosSafetySnapshot> ProbeAsync(CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        ProbeCount++;
        return Task.FromResult(Snapshot);
    }
}

internal sealed class HermeticElevationSafetyProbe(
    DefaultBiosInstallSafetyProbe realProbe,
    Func<BiosSafetySnapshot, BiosSafetySnapshot> overlay) : IBiosInstallSafetyProbe
{
    public int ProbeCount { get; private set; }
    public BiosSafetySnapshot? LastRealSnapshot { get; private set; }

    public async Task<BiosSafetySnapshot> ProbeAsync(CancellationToken ct = default)
    {
        ProbeCount++;
        var real = await realProbe.ProbeAsync(ct).ConfigureAwait(false);
        LastRealSnapshot = real;
        return overlay(real);
    }
}

internal sealed class StubElevationContext(bool isProcessElevated, bool isAdminHelperConnected) : IElevationContext
{
    private bool _isProcessElevated = isProcessElevated;
    private bool _isAdminHelperConnected = isAdminHelperConnected;

    public bool IsProcessElevated
    {
        get => _isProcessElevated;
        set
        {
            _isProcessElevated = value;
            Changed?.Invoke();
        }
    }

    public bool IsAdminHelperConnected
    {
        get => _isAdminHelperConnected;
        set
        {
            _isAdminHelperConnected = value;
            Changed?.Invoke();
        }
    }

    public event Action? Changed;

    public Task<ElevationResult> EnableAdminModeAsync(CancellationToken ct = default) =>
        Task.FromResult(new ElevationResult(IsAdminHelperConnected, false, "Stub elevation context."));
}

internal sealed class StubSignatureVerifier : IBiosSignatureVerifier
{
    private readonly ConcurrentQueue<string> _verifiedPaths = new();
    public Func<string, bool> Predicate { get; set; }

    public StubSignatureVerifier(bool defaultResult = true)
    {
        Predicate = _ => defaultResult;
    }

    public IReadOnlyList<string> VerifiedFilePaths => _verifiedPaths.ToArray();

    public Task<bool> VerifyAuthenticodeAsync(string filePath, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        Assert.True(File.Exists(filePath), $"Expected file to exist on disk when verifying Authenticode: {filePath}");
        _verifiedPaths.Enqueue(filePath);
        return Task.FromResult(Predicate(filePath));
    }
}

internal sealed class StubWindowsUpdateClient : IBiosWindowsUpdateClient
{
    private readonly ConcurrentQueue<Guid> _installedIds = new();

    public IReadOnlyList<BiosWuaFirmwareUpdate> PendingUpdates { get; set; } = [];
    public Exception? SearchException { get; set; }
    public Exception? InstallException { get; set; }
    public Func<Guid, CancellationToken, Task<BiosWuaInstallOutcome>>? InstallHandler { get; set; }
    public int SearchCount { get; private set; }
    public IReadOnlyList<Guid> InstalledUpdateIds => _installedIds.ToArray();

    public Task<IReadOnlyList<BiosWuaFirmwareUpdate>> SearchPendingFirmwareUpdatesAsync(CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        SearchCount++;
        if (SearchException is not null)
            return Task.FromException<IReadOnlyList<BiosWuaFirmwareUpdate>>(SearchException);
        return Task.FromResult(PendingUpdates);
    }

    public Task<BiosWuaInstallOutcome> InstallUpdateAsync(Guid updateId, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        _installedIds.Enqueue(updateId);
        if (InstallException is not null)
            return Task.FromException<BiosWuaInstallOutcome>(InstallException);
        if (InstallHandler is not null)
            return InstallHandler(updateId, ct);
        return Task.FromResult(new BiosWuaInstallOutcome(true, 2, true, "Firmware update installed."));
    }
}

internal sealed class FakeWuaUpdate(string title, bool eulaAccepted = true, bool isDownloaded = false) : IFoundUpdate
{
    public string Title { get; } = title;
    public bool EulaAccepted { get; private set; } = eulaAccepted;
    public bool IsDownloaded { get; set; } = isDownloaded;
    public void AcceptEula() => EulaAccepted = true;
}

internal sealed class FakeWuaApi : IWindowsUpdateApi
{
    private readonly ConcurrentQueue<string> _searchQueries = new();

    public Func<string, IReadOnlyList<IFoundUpdate>>? SearchHandler { get; set; }
    public UpdateInstallOutcome NextInstallOutcome { get; set; } = new(AgentWindowsUpdate.SucceededCode, 0, true);
    public int DownloadResultCode { get; set; } = AgentWindowsUpdate.SucceededCode;
    public string UpdateTitle { get; set; } = "System Firmware Update";
    public int DownloadedCount { get; private set; }
    public int InstalledCount { get; private set; }
    public IReadOnlyList<string> SearchQueries => _searchQueries.ToArray();

    public IReadOnlyList<IFoundUpdate> Search(string criteria)
    {
        _searchQueries.Enqueue(criteria);
        if (SearchHandler is not null)
            return SearchHandler(criteria);
        return [new FakeWuaUpdate(UpdateTitle, eulaAccepted: false, isDownloaded: false)];
    }

    public int Download(IReadOnlyList<IFoundUpdate> updates)
    {
        DownloadedCount += updates.Count;
        foreach (var u in updates)
        {
            if (u is FakeWuaUpdate fake)
                fake.IsDownloaded = true;
        }
        return DownloadResultCode;
    }

    public UpdateInstallOutcome Install(IReadOnlyList<IFoundUpdate> updates)
    {
        InstalledCount += updates.Count;
        return NextInstallOutcome;
    }

    public void StartInteractiveScan() { }
}

internal sealed record RecordedHttpRequest(HttpMethod Method, Uri RequestUri, IReadOnlyList<string> Headers);

internal sealed class ScriptedHttpHandler : HttpMessageHandler
{
    private readonly ConcurrentQueue<RecordedHttpRequest> _requests = new();
    private readonly List<(Func<HttpRequestMessage, bool> Match, Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> Handler)> _routes = [];
    private readonly object _gate = new();

    public IReadOnlyList<RecordedHttpRequest> Requests => _requests.ToArray();

    public void Map(Func<HttpRequestMessage, bool> match, Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handler)
    {
        lock (_gate)
        {
            _routes.Insert(0, (match, handler));
        }
    }

    public void MapExact(string url, Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handler) =>
        Map(req => string.Equals(req.RequestUri?.AbsoluteUri, url, StringComparison.OrdinalIgnoreCase), handler);

    public void MapPrefix(string prefix, Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handler) =>
        Map(req => req.RequestUri?.AbsoluteUri.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) == true, handler);

    public void MapBytes(string url, byte[] bytes, string mediaType = "application/octet-stream", HttpStatusCode status = HttpStatusCode.OK) =>
        MapExact(url, (_, _) =>
        {
            var resp = new HttpResponseMessage(status)
            {
                Content = new ByteArrayContent(bytes)
            };
            resp.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(mediaType);
            return Task.FromResult(resp);
        });

    public void MapText(string url, string text, string mediaType = "application/xml", HttpStatusCode status = HttpStatusCode.OK) =>
        MapExact(url, (_, _) => Task.FromResult(new HttpResponseMessage(status)
        {
            Content = new StringContent(text, Encoding.UTF8, mediaType)
        }));

    public void MapPrefixText(string prefix, string text, string mediaType = "application/json", HttpStatusCode status = HttpStatusCode.OK) =>
        MapPrefix(prefix, (_, _) => Task.FromResult(new HttpResponseMessage(status)
        {
            Content = new StringContent(text, Encoding.UTF8, mediaType)
        }));

    public void MapStatus(string url, HttpStatusCode status) =>
        MapExact(url, (_, _) => Task.FromResult(new HttpResponseMessage(status)));

    public void MapPrefixStatus(string prefix, HttpStatusCode status) =>
        MapPrefix(prefix, (_, _) => Task.FromResult(new HttpResponseMessage(status)));

    public void MapRedirect(string fromUrl, string location, HttpStatusCode status = HttpStatusCode.Found) =>
        MapExact(fromUrl, (_, _) =>
        {
            var resp = new HttpResponseMessage(status);
            resp.Headers.TryAddWithoutValidation("Location", location);
            return Task.FromResult(resp);
        });

    public void MapException(string url, Exception exception) =>
        MapExact(url, (_, _) => Task.FromException<HttpResponseMessage>(exception));

    public void MapPrefixException(string prefix, Exception exception) =>
        MapPrefix(prefix, (_, _) => Task.FromException<HttpResponseMessage>(exception));

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var uri = request.RequestUri ?? throw new InvalidOperationException("HTTP request missing RequestUri.");
        var headers = request.Headers.Select(h => $"{h.Key}: {string.Join(",", h.Value)}").ToArray();
        _requests.Enqueue(new RecordedHttpRequest(request.Method, uri, headers));

        Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>>? handler = null;
        lock (_gate)
        {
            foreach (var route in _routes)
            {
                if (route.Match(request))
                {
                    handler = route.Handler;
                    break;
                }
            }
        }

        if (handler is null)
            throw new InvalidOperationException($"Unmapped offline E2E HTTP URL: {request.Method} {uri}");

        return await handler(request, cancellationToken).ConfigureAwait(false);
    }
}

internal sealed record RecordedProcessCall(
    string FileName,
    string ToolName,
    IReadOnlyList<string> Arguments,
    string? WorkingDirectory,
    TimeSpan Timeout);

internal sealed class RecordingProcessLauncher(string role = "Host") : IProcessLauncher
{
    private static readonly HashSet<string> ForbiddenShellTools = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
        "cmd",
        "cmd.exe",
        "sh",
        "bash"
    };

    private static readonly string[] ForbiddenScriptExtensions = [".ps1", ".bat", ".cmd", ".sh"];

    private readonly ConcurrentQueue<RecordedProcessCall> _calls = new();
    private readonly List<(Func<RecordedProcessCall, bool> Match, Func<RecordedProcessCall, CancellationToken, Task<ProcessResult>> Handler)> _handlers = [];
    private readonly object _gate = new();

    public string Role { get; } = role;
    public IReadOnlyList<RecordedProcessCall> Calls => _calls.ToArray();
    public ProcessResult DefaultResult { get; set; } = new(0, "", "");

    public void OnTool(string toolName, Func<RecordedProcessCall, ProcessResult> handler) =>
        OnMatch(c => string.Equals(c.ToolName, toolName, StringComparison.OrdinalIgnoreCase), (c, _) => Task.FromResult(handler(c)));

    public void OnTool(string toolName, ProcessResult result) =>
        OnTool(toolName, _ => result);

    public void OnMatch(Func<RecordedProcessCall, bool> match, Func<RecordedProcessCall, CancellationToken, Task<ProcessResult>> handler)
    {
        lock (_gate)
        {
            _handlers.Insert(0, (match, handler));
        }
    }

    public Task<ProcessResult> RunAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        TimeSpan timeout,
        CancellationToken cancellationToken) =>
        RunCoreAsync(fileName, arguments, timeout, cancellationToken, workingDirectory: null);

    public Task<ProcessResult> RunAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        TimeSpan timeout,
        CancellationToken cancellationToken,
        string? workingDirectory) =>
        RunCoreAsync(fileName, arguments, timeout, cancellationToken, workingDirectory);

    public void AssertNoForbiddenShellCalls()
    {
        foreach (var call in _calls)
            AssertNotForbiddenShell(call.FileName, call.ToolName, call.Arguments);
    }

    private Task<ProcessResult> RunCoreAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        TimeSpan timeout,
        CancellationToken cancellationToken,
        string? workingDirectory)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var toolName = Path.GetFileName(fileName ?? "");
        var argsCopy = arguments?.ToArray() ?? [];

        AssertNotForbiddenShell(fileName ?? "", toolName, argsCopy);

        var call = new RecordedProcessCall(fileName ?? "", toolName, argsCopy, workingDirectory, timeout);
        _calls.Enqueue(call);

        Func<RecordedProcessCall, CancellationToken, Task<ProcessResult>>? matched = null;
        lock (_gate)
        {
            foreach (var h in _handlers)
            {
                if (h.Match(call))
                {
                    matched = h.Handler;
                    break;
                }
            }
        }

        return matched is not null
            ? matched(call, cancellationToken)
            : Task.FromResult(DefaultResult);
    }

    private void AssertNotForbiddenShell(string fileName, string toolName, IReadOnlyList<string> arguments)
    {
        if (ForbiddenShellTools.Contains(toolName))
            Assert.Fail($"[{Role}] Pure-C# invariant violated: forbidden shell executable invoked: '{fileName}' (normalized '{toolName}').");

        foreach (var ext in ForbiddenScriptExtensions)
        {
            if (toolName.EndsWith(ext, StringComparison.OrdinalIgnoreCase))
                Assert.Fail($"[{Role}] Pure-C# invariant violated: forbidden script file invoked: '{fileName}'.");
            foreach (var arg in arguments)
            {
                if (arg.TrimEnd('"', '\'').EndsWith(ext, StringComparison.OrdinalIgnoreCase))
                    Assert.Fail($"[{Role}] Pure-C# invariant violated: forbidden script argument passed to '{toolName}': '{arg}'.");
            }
        }
    }
}

internal sealed record CapturedLogEntry(
    string Category,
    Microsoft.Extensions.Logging.LogLevel Level,
    string Message,
    Exception? Exception);

internal sealed class CapturingLoggerFactory : Microsoft.Extensions.Logging.ILoggerFactory
{
    private readonly ConcurrentQueue<CapturedLogEntry> _entries = new();

    public IReadOnlyList<CapturedLogEntry> Entries => _entries.ToArray();

    public void AddProvider(Microsoft.Extensions.Logging.ILoggerProvider provider) { }

    public ILogger CreateLogger(string categoryName) => new CapturingLogger(categoryName, _entries);

    public ILogger CreateLogger<T>() => CreateLogger(typeof(T).FullName ?? typeof(T).Name);

    public void Dispose() { }

    private sealed class CapturingLogger(string category, ConcurrentQueue<CapturedLogEntry> entries) : ILogger
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
            entries.Enqueue(new CapturedLogEntry(category, logLevel, formatter(state, exception), exception));
        }
    }
}

internal sealed class SyncProgress<T> : IProgress<T>
{
    private readonly List<T> _reports = [];
    private readonly object _gate = new();

    public IReadOnlyList<T> Reports
    {
        get
        {
            lock (_gate) return _reports.ToArray();
        }
    }

    public void Report(T value)
    {
        lock (_gate) _reports.Add(value);
    }
}

internal sealed class IsolatedStagingDir : IDisposable
{
    public string Path { get; }

    public IsolatedStagingDir(string prefix = "bios")
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"rpd-bios-e2e-{prefix}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(Path);
    }

    public void AssertNoPartFilesRemain()
    {
        if (!Directory.Exists(Path)) return;
        var partFiles = Directory.GetFiles(Path, "*.part", SearchOption.AllDirectories);
        Assert.Empty(partFiles);
    }

    public void AssertEmpty()
    {
        if (!Directory.Exists(Path)) return;
        Assert.Empty(Directory.GetFileSystemEntries(Path));
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(Path))
                Directory.Delete(Path, recursive: true);
        }
        catch
        {
            // Best-effort cleanup on test teardown.
        }
    }
}

internal sealed class DisconnectedBridgeStub : IElevatedCommandBridge
{
    public bool IsConnected => false;
    public Task<ProcessResult?> RunElevatedAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct, Action<string>? outputLine = null) =>
        Task.FromResult<ProcessResult?>(null);
    public Task<SensorSnapshot?> ReadSensorsAsync(CancellationToken ct = default) => Task.FromResult<SensorSnapshot?>(null);
    public Task<IReadOnlyList<DriveHealth>?> ReadDrivesAsync(CancellationToken ct = default) => Task.FromResult<IReadOnlyList<DriveHealth>?>(null);
}

internal sealed class MinimalLegacyBridgeStub(bool isConnected = true) : IElevatedCommandBridge
{
    public bool IsConnected => isConnected;
    public Task<ProcessResult?> RunElevatedAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct, Action<string>? outputLine = null) =>
        Task.FromResult<ProcessResult?>(null);
    public Task<SensorSnapshot?> ReadSensorsAsync(CancellationToken ct = default) => Task.FromResult<SensorSnapshot?>(null);
    public Task<IReadOnlyList<DriveHealth>?> ReadDrivesAsync(CancellationToken ct = default) => Task.FromResult<IReadOnlyList<DriveHealth>?>(null);
}

/// <summary>
/// Real cross-platform in-process named-pipe fixture wiring <see cref="AdminPipeServer"/>
/// (backed by <see cref="AgentBiosOperations"/>) and <see cref="AdminPipeClient"/>.
/// Always disposes client BEFORE awaiting server shutdown to guarantee zero deadlocks.
/// </summary>
internal sealed class LiveAgentPipeFixture : IAsyncDisposable
{
    private readonly CancellationTokenSource _serverCts;
    private readonly Task _serverTask;
    private readonly IsolatedStagingDir? _toolRootDir;

    public string PipeName { get; }
    public AdminPipeServer Server { get; }
    public AdminPipeClient? Client { get; private set; }
    public RecordingProcessLauncher AgentProcessLauncher { get; }
    public StubSignatureVerifier AgentSignatureVerifier { get; }
    public FakeWuaApi AgentWuaApi { get; }
    public IsolatedStagingDir AgentStagingDir { get; }
    public CapturingLoggerFactory AgentLoggerFactory { get; }
    public IReadOnlyList<string> AllowedToolRoots { get; }
    public string? AllowlistedDcuCliPath { get; }

    private LiveAgentPipeFixture(
        string pipeName,
        AdminPipeServer server,
        AdminPipeClient? client,
        CancellationTokenSource serverCts,
        Task serverTask,
        RecordingProcessLauncher agentProcessLauncher,
        StubSignatureVerifier agentSignatureVerifier,
        FakeWuaApi agentWuaApi,
        IsolatedStagingDir agentStagingDir,
        IsolatedStagingDir? toolRootDir,
        IReadOnlyList<string> allowedToolRoots,
        string? allowlistedDcuCliPath,
        CapturingLoggerFactory agentLoggerFactory)
    {
        PipeName = pipeName;
        Server = server;
        Client = client;
        _serverCts = serverCts;
        _serverTask = serverTask;
        AgentProcessLauncher = agentProcessLauncher;
        AgentSignatureVerifier = agentSignatureVerifier;
        AgentWuaApi = agentWuaApi;
        AgentStagingDir = agentStagingDir;
        _toolRootDir = toolRootDir;
        AllowedToolRoots = allowedToolRoots;
        AllowlistedDcuCliPath = allowlistedDcuCliPath;
        AgentLoggerFactory = agentLoggerFactory;
    }

    public static async Task<LiveAgentPipeFixture> StartAsync(
        bool legacyWithoutBiosOps = false,
        bool agentSignatureResult = true,
        bool createAllowlistedDcuTool = false,
        bool connectClient = true,
        bool includeWindowsSystemProgramFilesToolRoots = false,
        CancellationToken ct = default)
    {
        var pipeName = $"rpd-bios-e2e-{Guid.NewGuid():N}";
        var agentLauncher = new RecordingProcessLauncher("Agent");
        var agentSigVerifier = new StubSignatureVerifier(agentSignatureResult);
        var agentWuaApi = new FakeWuaApi();
        var agentStaging = new IsolatedStagingDir("agent-stage");
        var agentLoggerFactory = new CapturingLoggerFactory();

        IsolatedStagingDir? toolRootDir = null;
        IReadOnlyList<string> allowedToolRoots = [];
        string? dcuPath = null;

        if (createAllowlistedDcuTool)
        {
            toolRootDir = new IsolatedStagingDir("agent-tools");
            var dcuDir = Path.Combine(toolRootDir.Path, "Dell", "CommandUpdate");
            Directory.CreateDirectory(dcuDir);
            dcuPath = Path.Combine(dcuDir, "dcu-cli.exe");
            File.WriteAllBytes(dcuPath, Encoding.UTF8.GetBytes("FAKE-DCU-CLI-BINARY"));

            var roots = new List<string> { toolRootDir.Path };
            if (includeWindowsSystemProgramFilesToolRoots && OperatingSystem.IsWindows())
            {
                foreach (var folder in new[] { Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86 })
                {
                    var programFiles = Environment.GetFolderPath(folder);
                    if (!string.IsNullOrWhiteSpace(programFiles)
                        && Directory.Exists(programFiles)
                        && !roots.Contains(programFiles, StringComparer.OrdinalIgnoreCase))
                    {
                        roots.Add(programFiles);
                    }
                }
            }

            allowedToolRoots = roots;
        }

        IAgentBiosOperations? biosOps = legacyWithoutBiosOps
            ? null
            : new AgentBiosOperations(
                launcher: agentLauncher,
                signatureVerifier: agentSigVerifier,
                wuaApiFactory: () => agentWuaApi,
                stagingRoot: agentStaging.Path,
                allowedToolRoots: allowedToolRoots,
                log: agentLoggerFactory.CreateLogger<AgentBiosOperations>());

        var server = new AdminPipeServer(
            new AdminPipeServerOptions
            {
                PipeName = pipeName,
                ExpectedClientPid = Environment.ProcessId,
                ConnectTimeout = TimeSpan.FromSeconds(15)
            },
            launcher: agentLauncher,
            log: agentLoggerFactory.CreateLogger<AdminPipeServer>(),
            biosOperations: biosOps);

        var serverCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        serverCts.CancelAfter(TimeSpan.FromSeconds(25));
        var serverTask = server.RunSingleSessionAsync(serverCts.Token);

        AdminPipeClient? client = null;
        try
        {
            if (connectClient)
            {
                client = await AdminPipeClient.ConnectAsync(
                    pipeName,
                    TimeSpan.FromSeconds(10),
                    serverCts.Token,
                    log: agentLoggerFactory.CreateLogger<AdminPipeClient>()).ConfigureAwait(false);
            }

            return new LiveAgentPipeFixture(
                pipeName,
                server,
                client,
                serverCts,
                serverTask,
                agentLauncher,
                agentSigVerifier,
                agentWuaApi,
                agentStaging,
                toolRootDir,
                allowedToolRoots,
                dcuPath,
                agentLoggerFactory);
        }
        catch
        {
            if (client is not null)
                await client.DisposeAsync().ConfigureAwait(false);
            await serverCts.CancelAsync().ConfigureAwait(false);
            try { await serverTask.WaitAsync(TimeSpan.FromSeconds(3)).ConfigureAwait(false); } catch { }
            server.Dispose();
            serverCts.Dispose();
            agentStaging.Dispose();
            toolRootDir?.Dispose();
            throw;
        }
    }

    public async Task<AdminPipeResponse> SendRawFrameAsync(AdminPipeRequest request, CancellationToken ct = default)
    {
        using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync(TimeSpan.FromSeconds(10), ct).ConfigureAwait(false);
        await AdminPipeFraming.WriteFrameAsync(pipe, request, ct).ConfigureAwait(false);
        var response = await AdminPipeFraming.ReadFrameAsync<AdminPipeResponse>(pipe, ct).ConfigureAwait(false);
        return response ?? throw new InvalidOperationException("Pipe server closed without returning a response.");
    }

    public async ValueTask DisposeAsync()
    {
        // Always dispose client BEFORE awaiting serverTask so server observes EOF cleanly.
        if (Client is not null)
        {
            await Client.DisposeAsync().ConfigureAwait(false);
            Client = null;
        }

        try
        {
            await _serverTask.WaitAsync(TimeSpan.FromSeconds(3)).ConfigureAwait(false);
        }
        catch
        {
            await _serverCts.CancelAsync().ConfigureAwait(false);
            try { await _serverTask.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false); } catch { }
        }

        Server.Dispose();
        _serverCts.Dispose();
        AgentStagingDir.Dispose();
        _toolRootDir?.Dispose();
    }
}

internal static class E2ePayloads
{
    public static string ComputeSha256Hex(byte[] data) =>
        Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    public static (byte[] Bytes, string Sha256) BuildDummyBinary(string marker, int size = 4096)
    {
        var bytes = new byte[Math.Max(size, marker.Length + 16)];
        var markerBytes = Encoding.UTF8.GetBytes($"MZ-E2E-BIOS-{marker}");
        Buffer.BlockCopy(markerBytes, 0, bytes, 0, markerBytes.Length);
        for (int i = markerBytes.Length; i < bytes.Length; i++)
            bytes[i] = (byte)((i * 31 + marker.Length) & 0xFF);
        return (bytes, ComputeSha256Hex(bytes));
    }

    public static byte[] BuildUtf8BomXml(string xml)
    {
        var utf8 = Encoding.UTF8.GetBytes(xml);
        var result = new byte[3 + utf8.Length];
        result[0] = 0xEF;
        result[1] = 0xBB;
        result[2] = 0xBF;
        Buffer.BlockCopy(utf8, 0, result, 3, utf8.Length);
        return result;
    }

    public static byte[] BuildGzip(byte[] uncompressed)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionLevel.Optimal, leaveOpen: true))
            gz.Write(uncompressed);
        return ms.ToArray();
    }

    public static byte[] BuildGzip(string utf8Text) => BuildGzip(Encoding.UTF8.GetBytes(utf8Text));

    public static byte[] BuildGzipBomb(long uncompressedBytes)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionLevel.Optimal, leaveOpen: true))
        {
            var chunk = new byte[64 * 1024]; // zeroes compress > 1000:1
            long remaining = uncompressedBytes;
            while (remaining > 0)
            {
                int toWrite = (int)Math.Min(chunk.Length, remaining);
                gz.Write(chunk, 0, toWrite);
                remaining -= toWrite;
            }
        }
        return ms.ToArray();
    }

    /// <summary>
    /// Pure-C# Microsoft Cabinet (MSCF v1.3) single-folder archive builder supporting
    /// <c>TYPE_NONE</c> (<paramref name="mszip"/> = false) and <c>TYPE_MSZIP</c> (<paramref name="mszip"/> = true).
    /// </summary>
    public static byte[] BuildCab(IReadOnlyList<(string Name, byte[] Data)> entries, bool mszip = false)
    {
        ArgumentNullException.ThrowIfNull(entries);

        // Concatenate all uncompressed entry bytes into one folder stream.
        using var folderStream = new MemoryStream();
        var fileOffsets = new uint[entries.Count];
        for (int i = 0; i < entries.Count; i++)
        {
            fileOffsets[i] = (uint)folderStream.Length;
            folderStream.Write(entries[i].Data);
        }
        var folderBytes = folderStream.ToArray();

        // Build CFFILE table starting at offset 44 (36 CFHEADER + 8 CFFOLDER).
        using var cfFilesStream = new MemoryStream();
        Span<byte> fileHdr = stackalloc byte[16];
        for (int i = 0; i < entries.Count; i++)
        {
            var nameBytes = Encoding.UTF8.GetBytes(entries[i].Name);
            BinaryPrimitives.WriteUInt32LittleEndian(fileHdr[0..4], (uint)entries[i].Data.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(fileHdr[4..8], fileOffsets[i]);
            BinaryPrimitives.WriteUInt16LittleEndian(fileHdr[8..10], 0); // iFolder
            BinaryPrimitives.WriteUInt16LittleEndian(fileHdr[10..12], 0); // date
            BinaryPrimitives.WriteUInt16LittleEndian(fileHdr[12..14], 0); // time
            BinaryPrimitives.WriteUInt16LittleEndian(fileHdr[14..16], 0x0080); // UTF-8 filename
            cfFilesStream.Write(fileHdr);
            cfFilesStream.Write(nameBytes);
            cfFilesStream.WriteByte(0); // NUL terminator
        }
        var cfFilesBytes = cfFilesStream.ToArray();

        // Build CFDATA blocks (max 32768 uncompressed bytes per block).
        const int maxBlockUncomp = 32768;
        var blocks = new List<(byte[] Payload, ushort UncompLen)>();
        if (folderBytes.Length == 0)
        {
            blocks.Add((mszip ? CompressMsZipBlock([]) : [], 0));
        }
        else
        {
            for (int offset = 0; offset < folderBytes.Length; offset += maxBlockUncomp)
            {
                int len = Math.Min(maxBlockUncomp, folderBytes.Length - offset);
                var slice = folderBytes.AsSpan(offset, len).ToArray();
                var payload = mszip ? CompressMsZipBlock(slice) : slice;
                blocks.Add((payload, (ushort)len));
            }
        }

        const uint coffFiles = 36 + 8;
        uint coffCabStart = coffFiles + (uint)cfFilesBytes.Length;

        using var cab = new MemoryStream();
        Span<byte> header = stackalloc byte[36];
        header.Clear();
        header[0] = (byte)'M';
        header[1] = (byte)'S';
        header[2] = (byte)'C';
        header[3] = (byte)'F';
        // cbCabinet backfilled after writing all blocks
        BinaryPrimitives.WriteUInt32LittleEndian(header[16..20], coffFiles);
        header[24] = 3; // versionMinor
        header[25] = 1; // versionMajor
        BinaryPrimitives.WriteUInt16LittleEndian(header[26..28], 1); // cFolders
        BinaryPrimitives.WriteUInt16LittleEndian(header[28..30], (ushort)entries.Count); // cFiles
        cab.Write(header);

        Span<byte> folderHdr = stackalloc byte[8];
        BinaryPrimitives.WriteUInt32LittleEndian(folderHdr[0..4], coffCabStart);
        BinaryPrimitives.WriteUInt16LittleEndian(folderHdr[4..6], (ushort)blocks.Count);
        BinaryPrimitives.WriteUInt16LittleEndian(folderHdr[6..8], mszip ? (ushort)1 : (ushort)0);
        cab.Write(folderHdr);

        cab.Write(cfFilesBytes);

        Span<byte> dataHdr = stackalloc byte[8];
        foreach (var (payload, uncompLen) in blocks)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(dataHdr[0..4], 0); // csum (0 = omitted)
            BinaryPrimitives.WriteUInt16LittleEndian(dataHdr[4..6], (ushort)payload.Length);
            BinaryPrimitives.WriteUInt16LittleEndian(dataHdr[6..8], uncompLen);
            cab.Write(dataHdr);
            cab.Write(payload);
        }

        var result = cab.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(8, 4), (uint)result.Length);
        return result;
    }

    private static byte[] CompressMsZipBlock(byte[] slice)
    {
        using var ms = new MemoryStream();
        ms.WriteByte((byte)'C');
        ms.WriteByte((byte)'K');
        using (var deflate = new DeflateStream(ms, CompressionLevel.Optimal, leaveOpen: true))
            deflate.Write(slice);
        return ms.ToArray();
    }

    public static string XxeDtdXml =>
        """
        <?xml version="1.0" encoding="utf-8"?>
        <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]>
        <ImagePal><Solutions><UpdateInfo><Name>&xxe;</Name></UpdateInfo></Solutions></ImagePal>
        """;

    public static string HpCatalogXml(
        string version = "01.14.00",
        string family = "U74",
        string url = "https://ftp.hp.com/pub/softpaq/sp151001-151500/sp151234.exe",
        string? sha256 = null,
        string dateReleased = "2025-02-15",
        string id = "sp151234") =>
        $"""
        <?xml version="1.0" encoding="utf-8"?>
        <ImagePal>
          <Solutions>
            <UpdateInfo>
              <Id>{id}</Id>
              <Category>BIOS</Category>
              <Name>HP EliteBook System BIOS ({family})</Name>
              <Version>{version}</Version>
              <DateReleased>{dateReleased}</DateReleased>
              <Severity>Critical</Severity>
              <Size>25165824</Size>
              <Url>{url}</Url>
              {(sha256 is not null ? $"<SHA256>{sha256}</SHA256>" : "")}
              <Description>System BIOS security update.</Description>
            </UpdateInfo>
          </Solutions>
        </ImagePal>
        """;

    public static byte[] HpCatalogCab(
        string version = "01.14.00",
        string family = "U74",
        string url = "https://ftp.hp.com/pub/softpaq/sp151001-151500/sp151234.exe",
        string? sha256 = null,
        bool mszip = false) =>
        BuildCab([("catalog.xml", Encoding.UTF8.GetBytes(HpCatalogXml(version, family, url, sha256)))], mszip);

    public static string DellCatalogXml(
        string systemId = "0A1B",
        string version = "1.18.0",
        string path = "FOLDER12345M/1/Latitude_5430_1.18.0.exe",
        string? sha256 = null,
        string dateTime = "2025-03-01T00:00:00Z",
        string baseLocation = "downloads.dell.com") =>
        $"""
        <?xml version="1.0" encoding="utf-8"?>
        <Manifest baseLocation="{baseLocation}">
          <SoftwareComponent packageID="DELL1" vendorVersion="{version}" dateTime="{dateTime}" size="20971520" {(sha256 is not null ? $"hashSHA256=\"{sha256}\"" : "")} path="{path}">
            <ComponentType value="BIOS" />
            <Name><Display lang="en">Dell Latitude System BIOS {version}</Display></Name>
            <Criticality value="3"><Display lang="en">Urgent</Display></Criticality>
            <ImportantInfo URL="https://www.dell.com/support/home/drivers/driversdetails?driverid=DELL1" />
            <SupportedSystems>
              <Brand><Model systemID="{systemId}" /></Brand>
            </SupportedSystems>
          </SoftwareComponent>
        </Manifest>
        """;

    public static byte[] DellCatalogCab(
        string systemId = "0A1B",
        string version = "1.18.0",
        string path = "FOLDER12345M/1/Latitude_5430_1.18.0.exe",
        string? sha256 = null,
        bool mszip = false) =>
        BuildCab([("CatalogPC.xml", Encoding.UTF8.GetBytes(DellCatalogXml(systemId, version, path, sha256)))], mszip);

    public static string LenovoIndexXml(
        string descriptorUrl = "https://download.lenovo.com/pccbbs/mobiles/n3xuj12w_2_.xml",
        string version = "N3XET52W",
        string release = "2025-03-10") =>
        $"""
        <?xml version="1.0" encoding="utf-8"?>
        <packages>
          <package>
            <category>BIOS UEFI</category>
            <location>{descriptorUrl}</location>
            <version>{version}</version>
            <release>{release}</release>
          </package>
        </packages>
        """;

    public static string LenovoDescriptorXml(
        string version = "N3XET52W",
        string fileName = "winuptp.exe",
        string? sha256 = null,
        string releaseDate = "2025-03-10",
        string cmdline = "winuptp.exe -s",
        string packageId = "n3xuj12w") =>
        $"""
        <?xml version="1.0" encoding="utf-8"?>
        <Package id="{packageId}" version="{version}">
          <Title><Desc id="EN">ThinkPad BIOS Update Utility</Desc></Title>
          <ReleaseDate>{releaseDate}</ReleaseDate>
          <Severity type="1" />
          <Reboot type="3" />
          <Install><Cmdline id="EN">{cmdline}</Cmdline></Install>
          <Files>
            <Installer>
              <File>
                <Name>{fileName}</Name>
                {(sha256 is not null ? $"<SHA256>{sha256}</SHA256>" : "")}
                <Size>31457280</Size>
              </File>
            </Installer>
          </Files>
        </Package>
        """;

    public static string AsusBiosJson(
        string version = "2402",
        string downloadUrl = "https://dlcdnets.asus.com/pub/ASUS/mb/BIOS/ROG-STRIX-Z790-E-GAMING-WIFI-ASUS-2402.ZIP",
        string releaseDate = "2025/02/20",
        string title = "ROG STRIX Z790-E GAMING WIFI BIOS 2402") =>
        $$"""
        {
          "Result": {
            "Obj": [
              {
                "Name": "BIOS",
                "Files": [
                  {
                    "Id": "{{version}}",
                    "Version": "{{version}}",
                    "Title": "{{title}}",
                    "ReleaseDate": "{{releaseDate}}",
                    "FileSize": "18.5 MB",
                    "Description": "Improve system stability and security.",
                    "DownloadUrl": {
                      "Global": "{{downloadUrl}}"
                    }
                  }
                ]
              }
            ]
          }
        }
        """;

    public static string AcerBiosJson(
        string version = "1.15",
        string downloadUrl = "https://global-download.acer.com/GDFiles/BIOS/BIOS/BIOS_Acer_1.15_A_A.zip",
        string releaseDate = "2025-02-10",
        string title = "BIOS Update for Predator PH315-55") =>
        $$"""
        {
          "bios": [
            {
              "id": "acer-bios-{{version}}",
              "category": "BIOS",
              "title": "{{title}}",
              "version": "{{version}}",
              "releaseDate": "{{releaseDate}}",
              "size": "12.4 MB",
              "severity": "Recommended",
              "description": "Update microcode and UEFI security patches.",
              "downloadUrl": "{{downloadUrl}}"
            }
          ]
        }
        """;

    public static string MsiBiosJson(
        string version = "7D75v1G",
        string downloadUrl = "https://download.msi.com/bos_exe/mb/7D75v1G.zip",
        string releaseDate = "2025-02-25",
        string title = "MAG B650 TOMAHAWK WIFI AMI BIOS") =>
        $$"""
        {
          "result": {
            "downloads": {
              "AMI BIOS": [
                {
                  "download_id": "{{version}}",
                  "download_title": "{{title}}",
                  "download_version": "{{version}}",
                  "download_release": "{{releaseDate}}",
                  "download_size": "14.2 MB",
                  "download_description": "AGESA ComboPI update and security fix.",
                  "download_url": "{{downloadUrl}}"
                }
              ]
            }
          }
        }
        """;

    public static string SurfaceFirmwareJson(
        string version = "15.102.143",
        string model = "Surface Pro 9",
        string downloadUrl = "https://download.microsoft.com/download/surface/SurfacePro9_Win11_22631_25.021.12345.0.msi",
        string? sha256 = null,
        string releaseDate = "2025-02-18",
        string os = "win11") =>
        $$"""
        {
          "releases": [
            {
              "id": "SurfacePro9_Win11_22631_25.021.12345.0",
              "model": "{{model}}",
              "os": "{{os}}",
              "category": "Firmware",
              "title": "{{model}} Drivers and Firmware",
              "uefiVersion": "{{version}}",
              "releaseDate": "{{releaseDate}}",
              "sizeBytes": 419430400,
              "severity": "Recommended",
              {{(sha256 is not null ? $"\"sha256\": \"{sha256}\"," : "")}}
              "downloadUrl": "{{downloadUrl}}"
            }
          ]
        }
        """;

    public static string FrameworkLvfsXml(
        string version = "3.05",
        string location = "https://cdn.fwupd.org/downloads/framework-laptop13-amd7040-3.05.cab",
        string? sha256 = null,
        string date = "2025-02-01") =>
        $"""
        <?xml version="1.0" encoding="utf-8"?>
        <components version="0.9">
          <component type="firmware">
            <id>com.framework.laptop13.amd7040.firmware</id>
            <name>Framework Laptop 13 (AMD Ryzen 7040 Series) System Firmware</name>
            <summary>UEFI BIOS update for Framework Laptop 13 AMD Ryzen 7040 Series</summary>
            <developer_name>Framework</developer_name>
            <releases>
              <release version="{version}" date="{date}" urgency="high">
                <description><p>UEFI security and stability update.</p></description>
                <artifacts>
                  <artifact type="binary">
                    <location>{location}</location>
                    {(sha256 is not null ? $"<checksum type=\"sha256\" target=\"container\">{sha256}</checksum>" : "")}
                    <size type="download">16777216</size>
                  </artifact>
                </artifacts>
              </release>
            </releases>
          </component>
        </components>
        """;

    public static byte[] FrameworkLvfsXmlGz(
        string version = "3.05",
        string location = "https://cdn.fwupd.org/downloads/framework-laptop13-amd7040-3.05.cab",
        string? sha256 = null,
        string date = "2025-02-01") =>
        BuildGzip(FrameworkLvfsXml(version, location, sha256, date));

    public static (byte[] CabBytes, string Sha256) FrameworkCabCapsule(
        string infName = "firmware.inf",
        bool includeCat = true,
        bool mszip = false)
    {
        var entries = new List<(string Name, byte[] Data)>
        {
            (infName, Encoding.UTF8.GetBytes("[Version]\r\nSignature=\"$WINDOWS NT$\"\r\nClass=Firmware\r\n")),
            ("firmware.bin", Encoding.UTF8.GetBytes("UEFI-CAPSULE-PAYLOAD-DATA"))
        };
        if (includeCat)
            entries.Add(("firmware.cat", Encoding.UTF8.GetBytes("CATALOG-SIGNATURE-DATA")));
        var bytes = BuildCab(entries, mszip);
        return (bytes, ComputeSha256Hex(bytes));
    }

    public static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (Directory.Exists(Path.Combine(dir.FullName, "src", "RemotePCDiagnostics.Core", "Bios"))
                && File.Exists(Path.Combine(dir.FullName, "docs", "bios-provider-contract.md")))
                return dir.FullName;
            dir = dir.Parent;
        }
        throw new InvalidOperationException($"Could not locate repository root walking up from '{AppContext.BaseDirectory}'.");
    }
}

internal sealed class FailingMidStream : Stream
{
    private bool _firstReadDone;
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        if (!_firstReadDone)
        {
            _firstReadDone = true;
            int n = Math.Min(buffer.Length, 1024);
            buffer[..n].Fill(0x42);
            return n;
        }
        throw new IOException("Simulated mid-stream network reset.");
    }

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
        new(Read(buffer.Span));

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
