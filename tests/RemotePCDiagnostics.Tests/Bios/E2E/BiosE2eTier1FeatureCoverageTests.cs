using System.Net;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core.Bios;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Tests.Bios.E2E;

/// <summary>
/// Tier 1 E2E Feature Coverage (Areas 1.1–1.4: DI &amp; Routing, Enterprise OEMs, Consumer OEMs,
/// Modern &amp; Windows Update Fallback Providers) — 28 test IDs.
/// </summary>
[Trait("Tier", "1")]
public sealed class BiosE2eTier1FeatureCoverageTests
{
    // =========================================================================
    // Area 1.1: DI Registration, Priority Ordering & Routing Matrix (E2E-T1-DI-01..06)
    // =========================================================================

    [Fact]
    public async Task E2E_T1_DI_01_DeterministicNineProviderRegistrationAndPriorityOrder()
    {
        await using var host = BiosE2eTestHost.CreateElevated();

        var actual = host.Service.Providers
            .Select(p => (p.VendorId, p.Priority, p.Capabilities.CanInstall))
            .ToArray();

        var expected = new (string VendorId, int Priority, bool CanInstall)[]
        {
            ("acer", 100, false),
            ("asus", 100, false),
            ("dell", 100, true),
            ("framework", 100, true),
            ("hp", 100, true),
            ("lenovo", 100, true),
            ("microsoft", 100, true),
            ("msi", 100, false),
            ("windows-update", 10, true)
        };

        Assert.Equal(9, actual.Length);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void E2E_T1_DI_02_ZeroOptionalDependenciesHostCompatibility()
    {
        var services = new ServiceCollection();
        services.AddBiosUpdates();
        services.AddBuiltInBiosUpdateProviders();

        using var sp = services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateOnBuild = true,
            ValidateScopes = true
        });

        var svc = sp.GetRequiredService<IBiosUpdateService>();
        Assert.Equal(9, svc.Providers.Count);
        Assert.Equal(
            ["acer", "asus", "dell", "framework", "hp", "lenovo", "microsoft", "msi", "windows-update"],
            svc.Providers.Select(p => p.VendorId).ToArray());
    }

    public static TheoryData<string, BiosSystemIdentity> AllEightOemIdentities => new()
    {
        { "hp", E2eIdentities.HpEliteBook() },
        { "dell", E2eIdentities.DellLatitude() },
        { "lenovo", E2eIdentities.LenovoThinkPad() },
        { "asus", E2eIdentities.AsusRog() },
        { "acer", E2eIdentities.AcerPredator() },
        { "msi", E2eIdentities.MsiMag() },
        { "microsoft", E2eIdentities.SurfacePro9() },
        { "framework", E2eIdentities.FrameworkLaptop13() }
    };

    [Theory]
    [MemberData(nameof(AllEightOemIdentities))]
    public async Task E2E_T1_DI_03_AllEightOemPriority100RoutingEquivalence(string expectedVendorId, BiosSystemIdentity identity)
    {
        await using var host = BiosE2eTestHost.CreateElevated(identity);

        var provider = host.Service.ResolveProvider(identity);

        Assert.NotNull(provider);
        Assert.Equal(expectedVendorId, provider.VendorId);
        Assert.Equal(100, provider.Priority);
        Assert.NotEqual("windows-update", provider.VendorId);
    }

    [Fact]
    public async Task E2E_T1_DI_04_GenericUnknownOemUefiFallbackToWindowsUpdate()
    {
        var identity = E2eIdentities.GenericPc(firmwareMode: BiosFirmwareMode.Uefi);
        await using var host = BiosE2eTestHost.CreateElevated(identity);

        var provider = host.Service.ResolveProvider(identity);

        Assert.NotNull(provider);
        Assert.Equal("windows-update", provider.VendorId);
        Assert.Equal(10, provider.Priority);
    }

    [Theory]
    [InlineData(BiosFirmwareMode.Legacy)]
    [InlineData(BiosFirmwareMode.Unknown)]
    public async Task E2E_T1_DI_05_GenericUnknownOemLegacyAndUnknownUnmatched(BiosFirmwareMode firmwareMode)
    {
        var identity = E2eIdentities.GenericPc(firmwareMode: firmwareMode);
        await using var host = BiosE2eTestHost.CreateElevated(identity);

        Assert.Null(host.Service.ResolveProvider(identity));

        var outcome = await host.Service.CheckForUpdateAsync();
        Assert.Null(outcome.ProviderId);
        Assert.Null(outcome.ProviderDisplayName);
        Assert.Equal(BiosCheckStatus.UnsupportedHardware, outcome.Latest.Status);
        host.AssertNoSerialNumberLeaked();
    }

    [Fact]
    public async Task E2E_T1_DI_06_HostServicesWiringStaticAndDiBoundaryConsistency()
    {
        // 1. Static HostServices.cs wiring verification
        var repoRoot = E2ePayloads.FindRepoRoot();
        var hostServicesPath = Path.Combine(repoRoot, "src", "RemotePCDiagnostics.Host", "HostServices.cs");
        Assert.True(File.Exists(hostServicesPath), $"Expected HostServices.cs at '{hostServicesPath}'.");
        var source = await File.ReadAllTextAsync(hostServicesPath);
        Assert.Matches(new Regex(@"services\.AddBiosUpdates\(\);\s*services\.AddBuiltInBiosUpdateProviders\(\);", RegexOptions.Singleline), source);

        // 2. Runtime DI boundary binding verification across all 6 boundary doubles:
        //    HttpClient/HttpMessageHandler, IBiosWindowsUpdateClient, IElevationContext,
        //    IBiosSignatureVerifier, IElevatedCommandBridge, and SystemCommandRunner.
        await using var host = await BiosE2eTestHost.CreateAsync(new BiosE2eHostOptions
        {
            InitialIdentity = E2eIdentities.GenericPc(firmwareMode: BiosFirmwareMode.Uefi),
            IsProcessElevated = false,
            UseLiveAgentPipe = true,
            UseHermeticRealSafetyProbe = true
        });

        // (a) IBiosWindowsUpdateClient boundary bound via DI
        var guid = Guid.NewGuid();
        host.WindowsUpdateClient.PendingUpdates =
        [
            new BiosWuaFirmwareUpdate(guid.ToString("D"), "System Firmware 2.0", "2.0", new DateOnly(2025, 3, 1), 1024, BiosUpdateSeverity.Critical, true, "Firmware")
        ];

        var check = await host.Service.CheckForUpdateAsync();
        Assert.Equal("windows-update", check.ProviderId);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, check.Latest.Status);
        Assert.Equal(1, host.WindowsUpdateClient.SearchCount);

        // (b) HttpClient/HttpMessageHandler boundary bound via DI
        host.SystemProbe.Identity = E2eIdentities.AsusRog();
        host.HttpHandler.MapPrefixText("https://www.asus.com/support/api/product.asmx/GetPDBIOS", E2ePayloads.AsusBiosJson());
        var asusCheck = await host.Service.CheckForUpdateAsync();
        Assert.Equal("asus", asusCheck.ProviderId);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, asusCheck.Latest.Status);
        Assert.NotEmpty(host.HttpHandler.Requests);

        // (c) IElevationContext + IBiosSignatureVerifier + IElevatedCommandBridge bound via DI
        var hpIdentity = E2eIdentities.HpEliteBook();
        var (pkgBytes, _) = E2ePayloads.BuildDummyBinary("di06-hp-pkg");
        const string hpUrl = "https://ftp.hp.com/pub/softpaq/sp151234.exe";
        host.SystemProbe.Identity = hpIdentity;
        host.HttpHandler.MapBytes(hpUrl, pkgBytes);

        var hpTargetNoHash = BiosLatestInfo.UpdateAvailable("hp", "01.14.00", downloadUrl: hpUrl, sha256: null);
        var bridgedRes = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(hpIdentity, hpIdentity.CurrentBios, hpTargetNoHash, Approved: true, SuspendBitLocker: true, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));
        Assert.True(bridgedRes.Succeeded, bridgedRes.Message);
        Assert.Equal(BiosInstallStatus.StagedForReboot, bridgedRes.Status);
        Assert.NotNull(host.HermeticSafetyProbe?.LastRealSnapshot);
        Assert.True(host.HermeticSafetyProbe!.LastRealSnapshot!.HasElevation);
        Assert.NotEmpty(host.SignatureVerifier.VerifiedFilePaths);
        Assert.NotEmpty(host.LivePipe!.AgentProcessLauncher.Calls);
        Assert.Empty(host.HostProcessLauncher.Calls);

        // (d) SystemCommandRunner bound directly via DI on an elevated host
        await using var elevatedHost = BiosE2eTestHost.CreateElevated(hpIdentity);
        elevatedHost.HttpHandler.MapBytes(hpUrl, pkgBytes);
        var elevatedRes = await elevatedHost.Service.InstallUpdateAsync(
            new BiosInstallRequest(hpIdentity, hpIdentity.CurrentBios, hpTargetNoHash, Approved: true, SuspendBitLocker: true, AllowReboot: false, VerifyHash: true, StagingDirectory: elevatedHost.StagingDir.Path));
        Assert.True(elevatedRes.Succeeded, elevatedRes.Message);
        Assert.NotEmpty(elevatedHost.HostProcessLauncher.Calls);
        Assert.NotEmpty(elevatedHost.SignatureVerifier.VerifiedFilePaths);
    }

    // =========================================================================
    // Area 1.2: Enterprise OEM Providers — HP, Dell, Lenovo (E2E-T1-ENT-01..09)
    // =========================================================================

    [Fact]
    public async Task E2E_T1_ENT_01_HpCheckForUpdateAvailableAndGetCurrentVersionNormalization()
    {
        var identity = E2eIdentities.HpEliteBook(boardProduct: "8B41", biosVersion: "U74 Ver. 01.10.00", osVersion: "Windows 11 23H2");
        var (_, sha256) = E2ePayloads.BuildDummyBinary("hp-sp151234");
        await using var host = BiosE2eTestHost.CreateElevated(identity);

        host.HttpHandler.MapBytes(
            "https://hpia.hpcloud.hp.com/ref/8b41/8b41_64_11.0.cab",
            E2ePayloads.HpCatalogCab(version: "01.14.00", family: "U74", sha256: sha256));

        var normalized = await host.Service.GetCurrentVersionAsync();
        Assert.Equal("hp", normalized.ProviderId);
        Assert.Equal("01.10.00", normalized.Version);
        Assert.Equal("U74", normalized.Family);

        var outcome = await host.Service.CheckForUpdateAsync();
        Assert.Equal("hp", outcome.ProviderId);
        Assert.Equal("HP", outcome.ProviderDisplayName);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, outcome.Latest.Status);
        Assert.Equal("01.14.00", outcome.Latest.LatestVersion);
        Assert.Equal("https://ftp.hp.com/pub/softpaq/sp151001-151500/sp151234.exe", outcome.Latest.DownloadUrl);
        Assert.Equal(sha256, outcome.Latest.Sha256);
        Assert.Empty(host.HostProcessLauncher.Calls);
        host.AssertNoSerialNumberLeaked();
    }

    [Fact]
    public async Task E2E_T1_ENT_02_HpCheckForUpdateUpToDate()
    {
        var identity = E2eIdentities.HpEliteBook(boardProduct: "8B41", biosVersion: "U74 Ver. 01.14.00");
        await using var host = BiosE2eTestHost.CreateElevated(identity);

        host.HttpHandler.MapText(
            "https://hpia.hpcloud.hp.com/ref/8b41/8b41_64_11.0.cab",
            E2ePayloads.HpCatalogXml(version: "01.14.00", family: "U74"));

        var outcome = await host.Service.CheckForUpdateAsync();
        Assert.Equal("hp", outcome.ProviderId);
        Assert.Equal(BiosCheckStatus.UpToDate, outcome.Latest.Status);
        host.AssertNoSerialNumberLeaked();
    }

    [Fact]
    public async Task E2E_T1_ENT_03_HpInstallUpdateHappyPathWithInvertedRebootSuppressionAndBitLocker()
    {
        var identity = E2eIdentities.HpEliteBook(boardProduct: "8B41", biosVersion: "U74 Ver. 01.10.00");
        var (pkgBytes, sha256) = E2ePayloads.BuildDummyBinary("hp-flasher");
        const string pkgUrl = "https://ftp.hp.com/pub/softpaq/sp151001-151500/HPBIOSUPDREC64.exe";

        await using var host = BiosE2eTestHost.CreateElevated(identity);
        host.HttpHandler.MapText("https://hpia.hpcloud.hp.com/ref/8b41/8b41_64_11.0.cab",
            E2ePayloads.HpCatalogXml(version: "01.14.00", family: "U74", url: pkgUrl, sha256: sha256));
        host.HttpHandler.MapBytes(pkgUrl, pkgBytes);

        var check = await host.Service.CheckForUpdateAsync();
        Assert.Equal(BiosCheckStatus.UpdateAvailable, check.Latest.Status);

        var progress = new SyncProgress<BiosInstallProgress>();
        var request = new BiosInstallRequest(
            System: check.System,
            Current: check.Current,
            Target: check.Latest,
            Approved: true,
            ApprovedBy: "operator@contoso.com",
            SuspendBitLocker: true,
            AllowReboot: false,
            VerifyHash: true,
            StagingDirectory: host.StagingDir.Path);

        var result = await host.Service.InstallUpdateAsync(request, progress);

        Assert.True(result.Succeeded);
        Assert.Equal(BiosInstallStatus.StagedForReboot, result.Status);
        Assert.True(result.RequiresReboot);
        Assert.True(result.BitLockerSuspended);

        var manageBde = Assert.Single(host.HostProcessLauncher.Calls, c => c.ToolName.Equals("manage-bde.exe", StringComparison.OrdinalIgnoreCase));
        Assert.Equal("-protectors", manageBde.Arguments[0]);
        Assert.Equal("-disable", manageBde.Arguments[1]);
        Assert.Equal("-RebootCount", manageBde.Arguments[3]);
        Assert.Equal("1", manageBde.Arguments[4]);

        var flasher = Assert.Single(host.HostProcessLauncher.Calls, c => c.ToolName.Equals("HPBIOSUPDREC64.exe", StringComparison.OrdinalIgnoreCase));
        // Inverted polarity: -r SUPPRESSES reboot when AllowReboot == false
        Assert.Equal(["-s", "-r"], flasher.Arguments);

        var stages = progress.Reports.Select(r => r.Stage).ToArray();
        Assert.Contains(BiosInstallStage.CheckingPrerequisites, stages);
        Assert.Contains(BiosInstallStage.Downloading, stages);
        Assert.Contains(BiosInstallStage.Verifying, stages);
        Assert.Contains(BiosInstallStage.SuspendingBitLocker, stages);
        Assert.True(Array.IndexOf(stages, BiosInstallStage.CheckingPrerequisites) < Array.IndexOf(stages, BiosInstallStage.Downloading));
        Assert.True(Array.IndexOf(stages, BiosInstallStage.Downloading) < Array.IndexOf(stages, BiosInstallStage.Verifying));

        host.StagingDir.AssertNoPartFilesRemain();
        host.AssertNoSerialNumberLeaked(result: result);
        host.AssertZeroShellInvocations();
    }

    [Fact]
    public async Task E2E_T1_ENT_04_DellCheckForUpdateAvailable()
    {
        var identity = E2eIdentities.DellLatitude(systemSku: "0A1B", biosVersion: "1.12.0");
        var (_, sha256) = E2ePayloads.BuildDummyBinary("dell-bios");
        await using var host = BiosE2eTestHost.CreateElevated(identity);

        host.HttpHandler.MapBytes(
            "https://downloads.dell.com/catalog/CatalogPC.cab",
            E2ePayloads.DellCatalogCab(systemId: "0A1B", version: "1.18.0", sha256: sha256));

        var outcome = await host.Service.CheckForUpdateAsync();
        Assert.Equal("dell", outcome.ProviderId);
        Assert.Equal("Dell", outcome.ProviderDisplayName);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, outcome.Latest.Status);
        Assert.Equal("1.18.0", outcome.Latest.LatestVersion);
        Assert.Equal("https://downloads.dell.com/FOLDER12345M/1/Latitude_5430_1.18.0.exe", outcome.Latest.DownloadUrl);
        Assert.Equal(sha256, outcome.Latest.Sha256);
        host.AssertNoSerialNumberLeaked();
    }

    [Fact]
    public async Task E2E_T1_ENT_05_DellCheckForUpdateUpToDate()
    {
        var identity = E2eIdentities.DellLatitude(systemSku: "0A1B", biosVersion: "1.18.0");
        await using var host = BiosE2eTestHost.CreateElevated(identity);

        host.HttpHandler.MapText(
            "https://downloads.dell.com/catalog/CatalogPC.cab",
            E2ePayloads.DellCatalogXml(systemId: "0A1B", version: "1.18.0"));

        var outcome = await host.Service.CheckForUpdateAsync();
        Assert.Equal("dell", outcome.ProviderId);
        Assert.Equal(BiosCheckStatus.UpToDate, outcome.Latest.Status);
        host.AssertNoSerialNumberLeaked();
    }

    [Fact]
    public async Task E2E_T1_ENT_06_DellInstallUpdateHappyPathStandardPolarityAndBitLocker()
    {
        var identity = E2eIdentities.DellLatitude(systemSku: "0A1B", biosVersion: "1.12.0");
        var (pkgBytes, sha256) = E2ePayloads.BuildDummyBinary("dell-dup");
        const string pkgUrl = "https://downloads.dell.com/FOLDER12345M/1/Latitude_5430_1.18.0.exe";

        await using var host = BiosE2eTestHost.CreateElevated(identity);
        host.HttpHandler.MapBytes("https://downloads.dell.com/catalog/CatalogPC.cab",
            E2ePayloads.DellCatalogCab(systemId: "0A1B", version: "1.18.0", sha256: sha256));
        host.HttpHandler.MapBytes(pkgUrl, pkgBytes);

        var check = await host.Service.CheckForUpdateAsync();
        Assert.Equal(BiosCheckStatus.UpdateAvailable, check.Latest.Status);

        var progress = new SyncProgress<BiosInstallProgress>();
        var result = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(check.System, check.Current, check.Latest, Approved: true, SuspendBitLocker: true, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path),
            progress);

        Assert.True(result.Succeeded);
        Assert.Equal(BiosInstallStatus.StagedForReboot, result.Status);
        Assert.True(result.RequiresReboot);
        Assert.True(result.BitLockerSuspended);

        Assert.Contains(host.HostProcessLauncher.Calls, c => c.ToolName.Equals("manage-bde.exe", StringComparison.OrdinalIgnoreCase));
        var dup = Assert.Single(host.HostProcessLauncher.Calls, c => c.ToolName.Equals("Latitude_5430_1.18.0.exe", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(["/s"], dup.Arguments);
        Assert.DoesNotContain("/r", dup.Arguments, StringComparer.OrdinalIgnoreCase);

        host.StagingDir.AssertNoPartFilesRemain();
        host.AssertNoSerialNumberLeaked(result: result);
        host.AssertZeroShellInvocations();
    }

    [Fact]
    public async Task E2E_T1_ENT_07_LenovoCheckForUpdateAvailableAndGetCurrentVersionNormalization()
    {
        var identity = E2eIdentities.LenovoThinkPad(biosVersion: "N3XET48W (1.23 )");
        var (_, sha256) = E2ePayloads.BuildDummyBinary("lenovo-winuptp");
        await using var host = BiosE2eTestHost.CreateElevated(identity);

        host.HttpHandler.MapText("https://download.lenovo.com/catalog/21HM_Win11.xml", E2ePayloads.LenovoIndexXml());
        host.HttpHandler.MapText("https://download.lenovo.com/pccbbs/mobiles/n3xuj12w_2_.xml",
            E2ePayloads.LenovoDescriptorXml(version: "N3XET52W", fileName: "winuptp.exe", sha256: sha256));

        var normalized = await host.Service.GetCurrentVersionAsync();
        Assert.Equal("lenovo", normalized.ProviderId);
        Assert.Equal("N3XET48W", normalized.Version);
        Assert.Equal("N3XET", normalized.Family);

        var outcome = await host.Service.CheckForUpdateAsync();
        Assert.Equal("lenovo", outcome.ProviderId);
        Assert.Equal("Lenovo", outcome.ProviderDisplayName);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, outcome.Latest.Status);
        Assert.Equal("N3XET52W", outcome.Latest.LatestVersion);
        Assert.Equal("https://download.lenovo.com/pccbbs/mobiles/winuptp.exe", outcome.Latest.DownloadUrl);
        Assert.Equal(sha256, outcome.Latest.Sha256);
        host.AssertNoSerialNumberLeaked();
    }

    [Fact]
    public async Task E2E_T1_ENT_08_LenovoCheckForUpdateUpToDate()
    {
        var identity = E2eIdentities.LenovoThinkPad(biosVersion: "N3XET52W (1.25 )");
        await using var host = BiosE2eTestHost.CreateElevated(identity);

        host.HttpHandler.MapText("https://download.lenovo.com/catalog/21HM_Win11.xml", E2ePayloads.LenovoIndexXml());
        host.HttpHandler.MapText("https://download.lenovo.com/pccbbs/mobiles/n3xuj12w_2_.xml",
            E2ePayloads.LenovoDescriptorXml(version: "N3XET52W"));

        var outcome = await host.Service.CheckForUpdateAsync();
        Assert.Equal("lenovo", outcome.ProviderId);
        Assert.Equal(BiosCheckStatus.UpToDate, outcome.Latest.Status);
        host.AssertNoSerialNumberLeaked();
    }

    [Fact]
    public async Task E2E_T1_ENT_09_LenovoInstallUpdateHappyPathWinUptpAndBitLocker()
    {
        var identity = E2eIdentities.LenovoThinkPad(biosVersion: "N3XET48W (1.23 )");
        var (pkgBytes, sha256) = E2ePayloads.BuildDummyBinary("lenovo-winuptp");
        const string pkgUrl = "https://download.lenovo.com/pccbbs/mobiles/winuptp.exe";

        await using var host = BiosE2eTestHost.CreateElevated(identity);
        host.HttpHandler.MapText("https://download.lenovo.com/catalog/21HM_Win11.xml", E2ePayloads.LenovoIndexXml());
        host.HttpHandler.MapText("https://download.lenovo.com/pccbbs/mobiles/n3xuj12w_2_.xml",
            E2ePayloads.LenovoDescriptorXml(version: "N3XET52W", fileName: "winuptp.exe", sha256: sha256));
        host.HttpHandler.MapBytes(pkgUrl, pkgBytes);

        var check = await host.Service.CheckForUpdateAsync();
        Assert.Equal(BiosCheckStatus.UpdateAvailable, check.Latest.Status);

        var result = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(check.System, check.Current, check.Latest, Approved: true, SuspendBitLocker: true, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));

        Assert.True(result.Succeeded);
        Assert.Equal(BiosInstallStatus.StagedForReboot, result.Status);
        Assert.True(result.BitLockerSuspended);

        Assert.Contains(host.HostProcessLauncher.Calls, c => c.ToolName.Equals("manage-bde.exe", StringComparison.OrdinalIgnoreCase));
        var winuptp = Assert.Single(host.HostProcessLauncher.Calls, c => c.ToolName.Equals("winuptp.exe", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(["-s"], winuptp.Arguments);
        Assert.DoesNotContain("-r", winuptp.Arguments, StringComparer.OrdinalIgnoreCase);

        host.StagingDir.AssertNoPartFilesRemain();
        host.AssertNoSerialNumberLeaked(result: result);
        host.AssertZeroShellInvocations();
    }

    // =========================================================================
    // Area 1.3: Consumer Check-Only OEM Providers — ASUS, Acer, MSI (E2E-T1-CON-01..06)
    // =========================================================================

    [Fact]
    public async Task E2E_T1_CON_01_AsusCheckForUpdateAvailable()
    {
        var identity = E2eIdentities.AsusRog(biosVersion: "1801");
        await using var host = BiosE2eTestHost.CreateElevated(identity);
        host.HttpHandler.MapPrefixText("https://www.asus.com/support/api/product.asmx/GetPDBIOS", E2ePayloads.AsusBiosJson(version: "2402"));

        var outcome = await host.Service.CheckForUpdateAsync();
        Assert.Equal("asus", outcome.ProviderId);
        Assert.Equal("ASUS", outcome.ProviderDisplayName);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, outcome.Latest.Status);
        Assert.Equal("2402", outcome.Latest.LatestVersion);
        Assert.Equal(new DateOnly(2025, 2, 20), outcome.Latest.ReleaseDate);
        Assert.Contains("dlcdnets.asus.com", outcome.Latest.DownloadUrl, StringComparison.OrdinalIgnoreCase);
        host.AssertNoSerialNumberLeaked();
    }

    [Fact]
    public async Task E2E_T1_CON_02_AsusCheckForUpdateUpToDate()
    {
        var identity = E2eIdentities.AsusRog(biosVersion: "2402");
        await using var host = BiosE2eTestHost.CreateElevated(identity);
        host.HttpHandler.MapPrefixText("https://www.asus.com/support/api/product.asmx/GetPDBIOS", E2ePayloads.AsusBiosJson(version: "2402"));

        var outcome = await host.Service.CheckForUpdateAsync();
        Assert.Equal("asus", outcome.ProviderId);
        Assert.Equal(BiosCheckStatus.UpToDate, outcome.Latest.Status);
        host.AssertNoSerialNumberLeaked();
    }

    [Fact]
    public async Task E2E_T1_CON_03_AcerCheckForUpdateAvailableAndUpToDate()
    {
        await using var host = BiosE2eTestHost.CreateElevated(E2eIdentities.AcerPredator(biosVersion: "1.08"));
        host.HttpHandler.MapPrefixText("https://www.acer.com/us-en/support/api/product/bios", E2ePayloads.AcerBiosJson(version: "1.15"));

        var avail = await host.Service.CheckForUpdateAsync();
        Assert.Equal("acer", avail.ProviderId);
        Assert.Equal("Acer", avail.ProviderDisplayName);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, avail.Latest.Status);
        Assert.Equal("1.15", avail.Latest.LatestVersion);
        Assert.Contains("acer.com", avail.Latest.DownloadUrl, StringComparison.OrdinalIgnoreCase);

        host.SystemProbe.Identity = E2eIdentities.AcerPredator(biosVersion: "1.15");
        var upToDate = await host.Service.CheckForUpdateAsync();
        Assert.Equal("acer", upToDate.ProviderId);
        Assert.Equal(BiosCheckStatus.UpToDate, upToDate.Latest.Status);
        host.AssertNoSerialNumberLeaked();
    }

    [Fact]
    public async Task E2E_T1_CON_04_MsiCheckForUpdateAvailable()
    {
        var identity = E2eIdentities.MsiMag(biosVersion: "1.A0");
        await using var host = BiosE2eTestHost.CreateElevated(identity);
        host.HttpHandler.MapPrefixText("https://www.msi.com/api/v1/product/support/panel", E2ePayloads.MsiBiosJson(version: "7D75v1G"));

        var outcome = await host.Service.CheckForUpdateAsync();
        Assert.Equal("msi", outcome.ProviderId);
        Assert.Equal("MSI", outcome.ProviderDisplayName);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, outcome.Latest.Status);
        Assert.Contains("download.msi.com", outcome.Latest.DownloadUrl, StringComparison.OrdinalIgnoreCase);
        host.AssertNoSerialNumberLeaked();
    }

    [Fact]
    public async Task E2E_T1_CON_05_MsiCheckForUpdateUpToDate()
    {
        var identity = E2eIdentities.MsiMag(biosVersion: "1.G0");
        await using var host = BiosE2eTestHost.CreateElevated(identity);
        host.HttpHandler.MapPrefixText("https://www.msi.com/api/v1/product/support/panel", E2ePayloads.MsiBiosJson(version: "7D75v1G"));

        var outcome = await host.Service.CheckForUpdateAsync();
        Assert.Equal("msi", outcome.ProviderId);
        Assert.Equal(BiosCheckStatus.UpToDate, outcome.Latest.Status);
        host.AssertNoSerialNumberLeaked();
    }

    public static TheoryData<string, BiosSystemIdentity, string> ConsumerInstallIdentities => new()
    {
        { "asus", E2eIdentities.AsusRog(), "https://dlcdnets.asus.com/pub/ASUS/mb/BIOS/2402.ZIP" },
        { "acer", E2eIdentities.AcerPredator(), "https://global-download.acer.com/BIOS_1.15.zip" },
        { "msi", E2eIdentities.MsiMag(), "https://download.msi.com/bos_exe/mb/7D75v1G.zip" }
    };

    [Theory]
    [MemberData(nameof(ConsumerInstallIdentities))]
    public async Task E2E_T1_CON_06_ConsumerProvidersEnforceCheckOnlyUnsupportedOnInstall(
        string vendorId, BiosSystemIdentity identity, string downloadUrl)
    {
        await using var host = BiosE2eTestHost.CreateElevated(identity);
        var target = BiosLatestInfo.UpdateAvailable(vendorId, "99.0", downloadUrl: downloadUrl);
        var progress = new SyncProgress<BiosInstallProgress>();

        var result = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, StagingDirectory: host.StagingDir.Path),
            progress);

        Assert.False(result.Succeeded);
        Assert.Equal(BiosInstallStatus.Unsupported, result.Status);
        Assert.Empty(host.HttpHandler.Requests);
        Assert.Equal(0, host.SafetyProbe.ProbeCount);
        Assert.Empty(host.HostProcessLauncher.Calls);
        Assert.Empty(progress.Reports);
        host.AssertNoSerialNumberLeaked(result: result);
    }

    // =========================================================================
    // Area 1.4: Modern & Fallback Providers — Surface, Framework, Windows Update (E2E-T1-MOD-01..07)
    // =========================================================================

    [Fact]
    public async Task E2E_T1_MOD_01_MicrosoftSurfaceCheckForUpdateAvailableAndUpToDate()
    {
        var (_, sha256) = E2ePayloads.BuildDummyBinary("surface-msi");
        await using var host = BiosE2eTestHost.CreateElevated(E2eIdentities.SurfacePro9(biosVersion: "15.100.143"));
        host.HttpHandler.MapPrefixText("https://www.microsoft.com/surface/api/firmware",
            E2ePayloads.SurfaceFirmwareJson(version: "15.102.143", sha256: sha256));

        var avail = await host.Service.CheckForUpdateAsync();
        Assert.Equal("microsoft", avail.ProviderId);
        Assert.Equal("Microsoft Surface", avail.ProviderDisplayName);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, avail.Latest.Status);
        Assert.Equal("15.102.143", avail.Latest.LatestVersion);
        Assert.EndsWith(".msi", avail.Latest.DownloadUrl, StringComparison.OrdinalIgnoreCase);

        host.SystemProbe.Identity = E2eIdentities.SurfacePro9(biosVersion: "15.102.143");
        var upToDate = await host.Service.CheckForUpdateAsync();
        Assert.Equal("microsoft", upToDate.ProviderId);
        Assert.Equal(BiosCheckStatus.UpToDate, upToDate.Latest.Status);
        host.AssertNoSerialNumberLeaked();
    }

    [Fact]
    public async Task E2E_T1_MOD_02_MicrosoftSurfaceInstallUpdateHappyPathMsiExec3010()
    {
        var identity = E2eIdentities.SurfacePro9(biosVersion: "15.100.143");
        var (msiBytes, sha256) = E2ePayloads.BuildDummyBinary("surface-pro9-msi");
        const string msiUrl = "https://download.microsoft.com/download/surface/SurfacePro9_Win11_22631_25.021.12345.0.msi";

        await using var host = BiosE2eTestHost.CreateElevated(identity);
        host.HttpHandler.MapPrefixText("https://www.microsoft.com/surface/api/firmware",
            E2ePayloads.SurfaceFirmwareJson(version: "15.102.143", downloadUrl: msiUrl, sha256: sha256));
        host.HttpHandler.MapBytes(msiUrl, msiBytes);
        host.HostProcessLauncher.OnTool("msiexec.exe", new ProcessResult(3010, "Reboot required.", ""));

        var check = await host.Service.CheckForUpdateAsync();
        Assert.Equal(BiosCheckStatus.UpdateAvailable, check.Latest.Status);

        var result = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(check.System, check.Current, check.Latest, Approved: true, SuspendBitLocker: true, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));

        Assert.True(result.Succeeded);
        Assert.Equal(BiosInstallStatus.StagedForReboot, result.Status);
        Assert.True(result.RequiresReboot);
        Assert.True(result.BitLockerSuspended);
        Assert.Equal(3010, result.ExitCode);

        var msiexec = Assert.Single(host.HostProcessLauncher.Calls, c => c.ToolName.Equals("msiexec.exe", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(4, msiexec.Arguments.Count);
        Assert.Equal("/i", msiexec.Arguments[0]);
        Assert.EndsWith(".msi", msiexec.Arguments[1], StringComparison.OrdinalIgnoreCase);
        Assert.Equal("/qn", msiexec.Arguments[2]);
        Assert.Equal("/norestart", msiexec.Arguments[3]);

        host.StagingDir.AssertNoPartFilesRemain();
        host.AssertNoSerialNumberLeaked(result: result);
        host.AssertZeroShellInvocations();
    }

    [Fact]
    public async Task E2E_T1_MOD_03_FrameworkCheckForUpdateAvailableAndUpToDateViaLvfsGzip()
    {
        var (_, sha256) = E2ePayloads.FrameworkCabCapsule();
        await using var host = BiosE2eTestHost.CreateElevated(E2eIdentities.FrameworkLaptop13(biosVersion: "3.03"));
        host.HttpHandler.MapBytes("https://cdn.fwupd.org/downloads/firmware.xml.gz",
            E2ePayloads.FrameworkLvfsXmlGz(version: "3.05", sha256: sha256), "application/gzip");

        var avail = await host.Service.CheckForUpdateAsync();
        Assert.Equal("framework", avail.ProviderId);
        Assert.Equal("Framework", avail.ProviderDisplayName);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, avail.Latest.Status);
        Assert.Equal("3.05", avail.Latest.LatestVersion);
        Assert.Equal(sha256, avail.Latest.Sha256);

        host.SystemProbe.Identity = E2eIdentities.FrameworkLaptop13(biosVersion: "3.05");
        var upToDate = await host.Service.CheckForUpdateAsync();
        Assert.Equal("framework", upToDate.ProviderId);
        Assert.Equal(BiosCheckStatus.UpToDate, upToDate.Latest.Status);
        host.AssertNoSerialNumberLeaked();
    }

    [Fact]
    public async Task E2E_T1_MOD_04_FrameworkInstallUpdateHappyPathCabPnputilAndSilentExe()
    {
        // Part A: .cab capsule -> pnputil.exe /add-driver <inf> /install
        var identity = E2eIdentities.FrameworkLaptop13(biosVersion: "3.03");
        var (cabBytes, cabSha) = E2ePayloads.FrameworkCabCapsule();
        const string cabUrl = "https://cdn.fwupd.org/downloads/framework-laptop13-amd7040-3.05.cab";

        await using var cabHost = BiosE2eTestHost.CreateElevated(identity);
        cabHost.HttpHandler.MapBytes(cabUrl, cabBytes);

        var cabTarget = BiosLatestInfo.UpdateAvailable("framework", "3.05", downloadUrl: cabUrl, sha256: cabSha);
        var cabResult = await cabHost.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, cabTarget, Approved: true, SuspendBitLocker: true, AllowReboot: false, VerifyHash: true, StagingDirectory: cabHost.StagingDir.Path));

        Assert.True(cabResult.Succeeded);
        Assert.Equal(BiosInstallStatus.StagedForReboot, cabResult.Status);
        Assert.True(cabResult.BitLockerSuspended);

        var pnputil = Assert.Single(cabHost.HostProcessLauncher.Calls, c => c.ToolName.Equals("pnputil.exe", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(3, pnputil.Arguments.Count);
        Assert.Equal("/add-driver", pnputil.Arguments[0]);
        Assert.EndsWith(".inf", pnputil.Arguments[1], StringComparison.OrdinalIgnoreCase);
        Assert.Equal("/install", pnputil.Arguments[2]);
        cabHost.AssertNoSerialNumberLeaked(result: cabResult);

        // Part B: Silent Windows .exe -> /silent /norestart
        var (exeBytes, exeSha) = E2ePayloads.BuildDummyBinary("framework-exe");
        const string exeUrl = "https://downloads.frame.work/bios/Framework_Laptop_13_AMD7040_BIOS_3.05.exe";

        await using var exeHost = BiosE2eTestHost.CreateElevated(identity);
        exeHost.HttpHandler.MapBytes(exeUrl, exeBytes);

        var exeTarget = BiosLatestInfo.UpdateAvailable("framework", "3.05", downloadUrl: exeUrl, sha256: exeSha);
        var exeResult = await exeHost.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, exeTarget, Approved: true, SuspendBitLocker: true, AllowReboot: false, VerifyHash: true, StagingDirectory: exeHost.StagingDir.Path));

        Assert.True(exeResult.Succeeded);
        Assert.Equal(BiosInstallStatus.StagedForReboot, exeResult.Status);
        Assert.True(exeResult.BitLockerSuspended);

        var exeCall = Assert.Single(exeHost.HostProcessLauncher.Calls, c => c.ToolName.Equals("Framework_Laptop_13_AMD7040_BIOS_3.05.exe", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(["/silent", "/norestart"], exeCall.Arguments);
        exeHost.AssertNoSerialNumberLeaked(result: exeResult);
        exeHost.AssertZeroShellInvocations();
    }

    [Fact]
    public async Task E2E_T1_MOD_05_WindowsUpdateCheckForUpdateAvailableViaPureCSharpWuaClient()
    {
        var identity = E2eIdentities.GenericPc(firmwareMode: BiosFirmwareMode.Uefi);
        var updateGuid = Guid.NewGuid();

        await using var host = BiosE2eTestHost.CreateElevated(identity);
        host.WindowsUpdateClient.PendingUpdates =
        [
            new BiosWuaFirmwareUpdate(
                UpdateId: updateGuid.ToString("D"),
                Title: "Contoso System Firmware - 2.4.0",
                Version: "2.4.0",
                ReleaseDate: new DateOnly(2025, 3, 5),
                SizeBytes: 8_388_608,
                Severity: BiosUpdateSeverity.Critical,
                RebootRequired: true,
                DriverClass: "Firmware",
                Categories: ["Drivers", "System Firmware"])
        ];

        var outcome = await host.Service.CheckForUpdateAsync();
        Assert.Equal("windows-update", outcome.ProviderId);
        Assert.Equal("Windows Update", outcome.ProviderDisplayName);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, outcome.Latest.Status);
        Assert.Equal(updateGuid.ToString("D"), outcome.Latest.PackageId);
        Assert.Equal(1, host.WindowsUpdateClient.SearchCount);
        Assert.Empty(host.HttpHandler.Requests);
        Assert.Empty(host.HostProcessLauncher.Calls);
        host.AssertNoSerialNumberLeaked();
    }

    [Fact]
    public async Task E2E_T1_MOD_06_WindowsUpdateCheckForUpdateUpToDate()
    {
        var identity = E2eIdentities.GenericPc(firmwareMode: BiosFirmwareMode.Uefi);
        await using var host = BiosE2eTestHost.CreateElevated(identity);
        host.WindowsUpdateClient.PendingUpdates = [];

        var outcome = await host.Service.CheckForUpdateAsync();
        Assert.Equal("windows-update", outcome.ProviderId);
        Assert.Equal(BiosCheckStatus.UpToDate, outcome.Latest.Status);
        Assert.Equal(1, host.WindowsUpdateClient.SearchCount);
        host.AssertNoSerialNumberLeaked();
    }

    [Fact]
    public async Task E2E_T1_MOD_07_WindowsUpdateInstallUpdateHappyPathStagedForRebootAndCompleted()
    {
        var identity = E2eIdentities.GenericPc(firmwareMode: BiosFirmwareMode.Uefi);
        var updateGuid = Guid.NewGuid();
        var target = BiosLatestInfo.UpdateAvailable("windows-update", "2.4.0", packageId: updateGuid.ToString("D"));

        // Case 1: RebootRequired == true -> StagedForReboot
        await using var hostReboot = BiosE2eTestHost.CreateElevated(identity);
        hostReboot.WindowsUpdateClient.InstallHandler = (_, _) =>
            Task.FromResult(new BiosWuaInstallOutcome(true, 2, true, "Firmware staged for reboot."));

        var res1 = await hostReboot.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: true, AllowReboot: false));

        Assert.True(res1.Succeeded);
        Assert.Equal(BiosInstallStatus.StagedForReboot, res1.Status);
        Assert.True(res1.RequiresReboot);
        Assert.True(res1.BitLockerSuspended);
        Assert.Equal([updateGuid], hostReboot.WindowsUpdateClient.InstalledUpdateIds);
        Assert.Contains(hostReboot.HostProcessLauncher.Calls, c => c.ToolName.Equals("manage-bde.exe", StringComparison.OrdinalIgnoreCase));
        hostReboot.AssertNoSerialNumberLeaked(result: res1);

        // Case 2: RebootRequired == false -> Completed
        await using var hostCompleted = BiosE2eTestHost.CreateElevated(identity);
        hostCompleted.WindowsUpdateClient.InstallHandler = (_, _) =>
            Task.FromResult(new BiosWuaInstallOutcome(true, 2, false, "Firmware update completed."));

        var res2 = await hostCompleted.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: true, AllowReboot: false));

        Assert.True(res2.Succeeded);
        Assert.Equal(BiosInstallStatus.Completed, res2.Status);
        Assert.False(res2.RequiresReboot);
        Assert.True(res2.BitLockerSuspended);
        Assert.Equal([updateGuid], hostCompleted.WindowsUpdateClient.InstalledUpdateIds);
        hostCompleted.AssertNoSerialNumberLeaked(result: res2);
        hostCompleted.AssertZeroShellInvocations();
    }
}
