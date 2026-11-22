using Bunit;
using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core;
using RemotePCDiagnostics.Core.Bios;
using RemotePCDiagnostics.Core.Session;
using RemotePCDiagnostics.UI;
using RemotePCDiagnostics.UI.Pages;
using RemotePCDiagnostics.UI.Shared;

namespace RemotePCDiagnostics.Tests.Bios;

public sealed class BiosUpdatePageTests : BunitContext
{
    private static BiosSystemIdentity SampleSystem(string manufacturer = "HP", string version = "F.10") =>
        new(
            Manufacturer: manufacturer,
            Model: "HP EliteBook 840 G10",
            SystemSku: "8B41",
            BoardManufacturer: manufacturer,
            BoardProduct: "8B41",
            BoardVersion: "1.0",
            SerialNumber: "SECRET-SERIAL-999",
            OsVersion: "Microsoft Windows 11 Pro 10.0.26100",
            Architecture: "X64",
            CurrentBios: new BiosCurrentInfo(
                Vendor: manufacturer,
                Version: version,
                ReleaseDate: new DateOnly(2024, 1, 15),
                ReleaseDateRaw: "01/15/2024",
                SmbiosRevision: "3.4",
                FirmwareMode: BiosFirmwareMode.Uefi,
                ProviderId: manufacturer.ToLowerInvariant()));

    private static BiosSafetySnapshot SafeSnapshot(bool hasElevation = true, bool onAcPower = true) =>
        new(
            OnAcPower: onAcPower,
            HasBattery: true,
            BatteryPercent: 85,
            BitLockerActive: false,
            BitLockerSuspended: false,
            HasElevation: hasElevation,
            PendingReboot: false);

    private void RegisterUiServices(IBiosUpdateService? bios, IElevationContext? elevation = null)
    {
        Services.AddSingleton<ISessionContext>(new SessionContext(SessionMode.Local));
        Services.AddSingleton(new AppServices(Elevation: elevation, Bios: bios));
    }

    [Fact]
    public void BiosPage_ShowsUnavailableMessage_WhenServiceNotProvided()
    {
        RegisterUiServices(bios: null);

        var cut = Render<BiosUpdatePage>();

        Assert.Contains("not available", cut.Find("[data-testid='bios-unavailable']").TextContent, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(cut.FindAll("[data-testid='bios-check']"));
    }

    [Fact]
    public void BiosPage_LoadsCurrentBiosAndProvidersOnInit_WithoutNetworkCheck_AndNeverExposesSerialNumber()
    {
        var checkCalls = 0;
        var provider = new StubProvider(
            "hp",
            "HP",
            canInstall: true,
            getLatest: (_, _, _) =>
            {
                checkCalls++;
                return Task.FromResult(BiosLatestInfo.UpToDate("hp", "F.10"));
            });
        var service = new BiosUpdateService(
            new StubSystemProbe(SampleSystem()),
            new StubSafetyProbe(SafeSnapshot()),
            [provider]);
        RegisterUiServices(service);

        var cut = Render<BiosUpdatePage>();

        Assert.Equal(0, checkCalls);
        var root = cut.Find("[data-rpcd-page='bios']");
        Assert.Equal(BrowserContract.Bios.ToString(), root.GetAttribute("data-rpcd-contract"));
        Assert.Equal("F.10", cut.Find("[data-testid='bios-current-version']").TextContent);
        Assert.Equal("2024-01-15", cut.Find("[data-testid='bios-current-date']").TextContent);
        Assert.Equal("Uefi", cut.Find("[data-testid='bios-firmware-mode']").TextContent);
        Assert.Contains("HP", cut.Find("[data-testid='bios-provider-row-hp']").TextContent);
        Assert.DoesNotContain("SECRET-SERIAL-999", cut.Markup, StringComparison.Ordinal);

        var agentData = cut.Find("[data-testid='bios-report-data']");
        var json = agentData.GetAttribute("data-report");
        Assert.False(string.IsNullOrWhiteSpace(json));
        Assert.DoesNotContain("SECRET-SERIAL-999", json!, StringComparison.Ordinal);
        using var doc = System.Text.Json.JsonDocument.Parse(json!);
        Assert.Equal(1, doc.RootElement.GetProperty("schema").GetInt32());
        Assert.Equal("F.10", doc.RootElement.GetProperty("current").GetProperty("version").GetString());
        Assert.Equal("hp", doc.RootElement.GetProperty("provider").GetProperty("id").GetString());
    }

    [Fact]
    public async Task BiosPage_CheckForUpdates_ShowsUpToDate()
    {
        var provider = new StubProvider(
            "hp",
            "HP",
            canInstall: true,
            getLatest: (_, cur, _) => Task.FromResult(BiosLatestInfo.UpToDate("hp", cur.Version, new DateOnly(2024, 1, 15))));
        var service = new BiosUpdateService(
            new StubSystemProbe(SampleSystem()),
            new StubSafetyProbe(SafeSnapshot()),
            [provider]);
        RegisterUiServices(service);

        var cut = Render<BiosUpdatePage>();
        await cut.InvokeAsync(() => cut.Find("[data-testid='bios-check']").Click());

        Assert.Contains("up to date", cut.Find("[data-testid='bios-check-status']").TextContent, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(cut.FindAll("[data-testid='bios-install-controls']"));
    }

    [Fact]
    public async Task BiosPage_UpdateAvailable_RequiresApprovalAndInstallsWithProgress()
    {
        var update = BiosLatestInfo.UpdateAvailable(
            providerId: "hp",
            latestVersion: "F.24",
            releaseDate: new DateOnly(2025, 11, 10),
            severity: BiosUpdateSeverity.Recommended,
            packageId: "sp150000",
            releaseSummary: "Security fixes",
            releaseNotesUrl: "https://ftp.hp.com/pub/softpaq/sp150000.html",
            downloadUrl: "https://ftp.hp.com/pub/softpaq/sp150000.exe",
            sha256: new string('a', 64),
            sizeBytes: 16_000_000);

        BiosInstallRequest? capturedRequest = null;
        var provider = new StubProvider(
            "hp",
            "HP",
            canInstall: true,
            getLatest: (_, _, _) => Task.FromResult(update),
            install: (req, progress, _) =>
            {
                capturedRequest = req;
                progress?.Report(new BiosInstallProgress(BiosInstallStage.Downloading, 40, "Downloading SoftPaq…"));
                progress?.Report(new BiosInstallProgress(BiosInstallStage.RebootRequired, 100, "Staged for next restart."));
                return Task.FromResult(BiosInstallResult.StagedForReboot(req.Current.Version, req.Target.LatestVersion, bitLockerSuspended: req.SuspendBitLocker));
            });

        var service = new BiosUpdateService(
            new StubSystemProbe(SampleSystem()),
            new StubSafetyProbe(SafeSnapshot()),
            [provider]);
        RegisterUiServices(service);

        var cut = Render<BiosUpdatePage>();
        await cut.InvokeAsync(() => cut.Find("[data-testid='bios-check']").Click());

        Assert.Contains("F.24", cut.Find("[data-testid='bios-check-status']").TextContent);
        Assert.NotNull(cut.Find("[data-testid='bios-safety-passed']"));
        Assert.NotNull(cut.Find("[data-testid='bios-release-notes-link']"));

        // Install button must stay disabled until explicit approval is checked.
        Assert.True(cut.Find("[data-testid='bios-install']").HasAttribute("disabled"));

        await cut.InvokeAsync(() => cut.Find("[data-testid='bios-approve']").Change(true));
        Assert.False(cut.Find("[data-testid='bios-install']").HasAttribute("disabled"));

        await cut.InvokeAsync(() => cut.Find("[data-testid='bios-install']").Click());

        Assert.NotNull(capturedRequest);
        Assert.True(capturedRequest!.Approved);
        Assert.True(capturedRequest.SuspendBitLocker);
        Assert.False(capturedRequest.AllowReboot);
        Assert.Contains("staged for next restart", cut.Find("[data-testid='bios-install-result']").TextContent, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("BitLocker", cut.Find("[data-testid='bios-install-result']").TextContent, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task BiosPage_ShowsSafetyBlockersAndEnableAdminButton_WhenUnelevated()
    {
        var update = BiosLatestInfo.UpdateAvailable(
            providerId: "dell",
            latestVersion: "1.14.0",
            downloadUrl: "https://downloads.dell.com/bios.exe",
            sha256: new string('b', 64));

        var elevation = new StubElevationContext(hasAdmin: false);
        var provider = new StubProvider(
            "dell",
            "Dell",
            canInstall: true,
            getLatest: (_, _, _) => Task.FromResult(update));

        var service = new BiosUpdateService(
            new StubSystemProbe(SampleSystem("Dell", "1.10.0")),
            new StubSafetyProbe(() => SafeSnapshot(hasElevation: elevation.HasAdminCapabilities, onAcPower: true)),
            [provider]);
        RegisterUiServices(service, elevation);

        var cut = Render<BiosUpdatePage>();
        await cut.InvokeAsync(() => cut.Find("[data-testid='bios-check']").Click());

        Assert.NotNull(cut.Find("[data-testid='bios-safety-blockers']"));
        Assert.NotNull(cut.Find("[data-testid='bios-enable-admin']"));

        // Even with approval checked, install stays disabled while blocked.
        await cut.InvokeAsync(() => cut.Find("[data-testid='bios-approve']").Change(true));
        Assert.True(cut.Find("[data-testid='bios-install']").HasAttribute("disabled"));

        // Enabling Admin Repair Mode clears the elevation blocker and unlocks install.
        await cut.InvokeAsync(() => cut.Find("[data-testid='bios-enable-admin']").Click());
        Assert.Equal(1, elevation.EnableCalls);
        Assert.NotNull(cut.Find("[data-testid='bios-safety-passed']"));
        Assert.False(cut.Find("[data-testid='bios-install']").HasAttribute("disabled"));
    }

    [Fact]
    public async Task BiosPage_ShowsManualInstallNote_ForCheckOnlyVendor()
    {
        var update = BiosLatestInfo.UpdateAvailable(
            providerId: "asus",
            latestVersion: "1401",
            downloadUrl: "https://dlcdnets.asus.com/pub/ASUS/bios/1401.zip");

        var provider = new StubProvider(
            "asus",
            "ASUS",
            canInstall: false,
            getLatest: (_, _, _) => Task.FromResult(update));

        var service = new BiosUpdateService(
            new StubSystemProbe(SampleSystem("ASUS", "1204")),
            new StubSafetyProbe(SafeSnapshot()),
            [provider]);
        RegisterUiServices(service);

        var cut = Render<BiosUpdatePage>();
        await cut.InvokeAsync(() => cut.Find("[data-testid='bios-check']").Click());

        Assert.Contains("not supported", cut.Find("[data-testid='bios-manual-install-note']").TextContent, StringComparison.OrdinalIgnoreCase);
        Assert.NotNull(cut.Find("[data-testid='bios-manual-download-link']"));
        Assert.Empty(cut.FindAll("[data-testid='bios-install']"));
    }

    [Fact]
    public void NavRail_ContainsBiosLink()
    {
        var store = new ResultStore();
        Services.AddSingleton(store);
        Services.AddSingleton(new DiagnosticsService(store, []));

        var cut = Render<NavRail>();

        var biosLink = cut.Find("[data-testid='nav-bios']");
        Assert.Equal("bios", biosLink.GetAttribute("href"));
        Assert.Contains("BIOS", biosLink.TextContent, StringComparison.Ordinal);
    }

    // --- Test doubles ---

    private sealed class StubSystemProbe(BiosSystemIdentity identity) : IBiosSystemProbe
    {
        public Task<BiosSystemIdentity> ProbeAsync(CancellationToken ct = default) => Task.FromResult(identity);
    }

    private sealed class StubSafetyProbe : IBiosInstallSafetyProbe
    {
        private readonly Func<BiosSafetySnapshot> _factory;
        public StubSafetyProbe(BiosSafetySnapshot snapshot) => _factory = () => snapshot;
        public StubSafetyProbe(Func<BiosSafetySnapshot> factory) => _factory = factory;
        public Task<BiosSafetySnapshot> ProbeAsync(CancellationToken ct = default) => Task.FromResult(_factory());
    }

    private sealed class StubElevationContext(bool hasAdmin) : IElevationContext
    {
        public int EnableCalls { get; private set; }
        public bool IsProcessElevated { get; private set; }
        public bool IsAdminHelperConnected { get; private set; } = hasAdmin;
        public bool HasAdminCapabilities => IsProcessElevated || IsAdminHelperConnected;
        public event Action? Changed;

        public Task<ElevationResult> EnableAdminModeAsync(CancellationToken ct = default)
        {
            EnableCalls++;
            IsAdminHelperConnected = true;
            Changed?.Invoke();
            return Task.FromResult(new ElevationResult(true, false, "Enabled"));
        }
    }

    private sealed class StubProvider(
        string vendorId,
        string displayName,
        bool canInstall,
        Func<BiosSystemIdentity, BiosCurrentInfo, CancellationToken, Task<BiosLatestInfo>> getLatest,
        Func<BiosInstallRequest, IProgress<BiosInstallProgress>?, CancellationToken, Task<BiosInstallResult>>? install = null)
        : IBiosUpdateProvider
    {
        public string VendorId => vendorId;
        public string DisplayName => displayName;
        public BiosProviderCapabilities Capabilities { get; } = new(CanCheckLatest: true, CanInstall: canInstall, SupportsSilentInstall: canInstall);
        public bool CanHandle(BiosSystemIdentity system) => true;
        public Task<BiosLatestInfo> GetLatestVersionAsync(BiosSystemIdentity system, BiosCurrentInfo current, CancellationToken ct = default) =>
            getLatest(system, current, ct);

        public Task<BiosInstallResult> InstallAsync(BiosInstallRequest request, IProgress<BiosInstallProgress>? progress = null, CancellationToken ct = default) =>
            install is not null
                ? install(request, progress, ct)
                : Task.FromResult(BiosInstallResult.Unsupported("not supported", request.Current.Version, request.Target.LatestVersion));
    }
}
