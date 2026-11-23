using System.Net;
using System.Text;
using RemotePCDiagnostics.Core.Bios;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Tests.Bios.E2E;

/// <summary>
/// Tier 2 E2E Boundary &amp; Corner Cases (Areas 2.1–2.4: Routing/Matching Boundaries,
/// Malicious SMBIOS Injection, Network/Redirect/HTTP Status Boundaries, Integrity/Archive/XML Hardening) — 30 test IDs.
/// </summary>
[Trait("Tier", "2")]
public sealed class BiosE2eTier2BoundaryAndSecurityTests
{
    // =========================================================================
    // Area 2.1: Routing, OEM Matching & OS Version Boundaries (E2E-T2-RTG-01..07)
    // =========================================================================

    [Theory]
    [InlineData("Ship")]
    [InlineData("Spaceship Corp")]
    [InlineData("Chipset Inc")]
    [InlineData("Alpha Systems")]
    [InlineData("PHP Co")]
    [InlineData("CustomSI Ltd")]
    [InlineData("Comsi")]
    [InlineData("MSInc")]
    [InlineData("Racer PC")]
    [InlineData("Tracer")]
    [InlineData("Odell Systems")]
    [InlineData("Model Co")]
    public async Task E2E_T2_RTG_01_SubstringFalsePositiveOemNamesRejected(string manufacturer)
    {
        var identity = E2eIdentities.GenericPc(
            manufacturer: manufacturer,
            boardManufacturer: manufacturer,
            firmwareMode: BiosFirmwareMode.Legacy);
        await using var host = BiosE2eTestHost.CreateElevated(identity);

        Assert.Null(host.Service.ResolveProvider(identity));
    }

    [Theory]
    [InlineData("Virtual Machine", BiosFirmwareMode.Uefi, "windows-update")]
    [InlineData("Virtual Machine", BiosFirmwareMode.Legacy, null)]
    [InlineData("Xbox", BiosFirmwareMode.Uefi, "windows-update")]
    [InlineData("Xbox", BiosFirmwareMode.Legacy, null)]
    public async Task E2E_T2_RTG_02_HyperVVmAndXboxExclusionOnMicrosoftSurface(
        string model, BiosFirmwareMode firmwareMode, string? expectedVendorId)
    {
        var identity = E2eIdentities.HyperVVm(firmwareMode: firmwareMode, model: model);
        await using var host = BiosE2eTestHost.CreateElevated(identity);

        var provider = host.Service.ResolveProvider(identity);
        Assert.Equal(expectedVendorId, provider?.VendorId);
        Assert.NotEqual("microsoft", provider?.VendorId);
    }

    [Theory]
    [InlineData(BiosFirmwareMode.Legacy)]
    [InlineData(BiosFirmwareMode.Unknown)]
    public async Task E2E_T2_RTG_03_LegacyAndUnknownFirmwareExcludedFromWindowsUpdate(BiosFirmwareMode mode)
    {
        var identity = E2eIdentities.GenericPc(firmwareMode: mode);
        await using var host = BiosE2eTestHost.CreateElevated(identity);

        var wuaProvider = Assert.Single(host.Service.Providers, p => p.VendorId == "windows-update");
        Assert.False(wuaProvider.CanHandle(identity));
        Assert.Null(host.Service.ResolveProvider(identity));
    }

    [Fact]
    public async Task E2E_T2_RTG_04_EmptyWhitespaceAndBoardOnlyIdentitiesNeverThrow()
    {
        await using var host = BiosE2eTestHost.CreateElevated();

        var huge = new string('X', 4096);
        var edgeIdentities = new[]
        {
            BiosSystemIdentity.Empty,
            new BiosSystemIdentity("   ", "\t", "\r\n", "  ", " ", "", "", "", "", BiosCurrentInfo.Empty),
            new BiosSystemIdentity(huge, huge, huge, huge, huge, huge, huge, huge, huge, new BiosCurrentInfo(huge, huge))
        };

        foreach (var id in edgeIdentities)
        {
            foreach (var p in host.Service.Providers)
            {
                var ex = Record.Exception(() => p.CanHandle(id));
                Assert.Null(ex);
            }
            Assert.Null(host.Service.ResolveProvider(id));
        }

        // Board-only identity routes cleanly to ASUS
        var boardOnlyAsus = E2eIdentities.AsusRog(manufacturer: "", boardManufacturer: "ASUSTeK COMPUTER INC.");
        var resolved = host.Service.ResolveProvider(boardOnlyAsus);
        Assert.NotNull(resolved);
        Assert.Equal("asus", resolved.VendorId);
    }

    [Theory]
    [InlineData("Windows 10.0.21999", "https://hpia.hpcloud.hp.com/ref/8b41/8b41_64_10.0.cab")]
    [InlineData("Windows 10.0.22000", "https://hpia.hpcloud.hp.com/ref/8b41/8b41_64_11.0.cab")]
    [InlineData("Windows 10.0.22631", "https://hpia.hpcloud.hp.com/ref/8b41/8b41_64_11.0.cab")]
    [InlineData("Windows 11 Pro", "https://hpia.hpcloud.hp.com/ref/8b41/8b41_64_11.0.cab")]
    public async Task E2E_T2_RTG_05_Windows11Build22000ExactBoundaryOnHpCatalogQuery(string osVersion, string expectedUrl)
    {
        var identity = E2eIdentities.HpEliteBook(boardProduct: "8B41", osVersion: osVersion);
        await using var host = BiosE2eTestHost.CreateElevated(identity);
        host.HttpHandler.MapText(expectedUrl, E2ePayloads.HpCatalogXml(version: "01.14.00", family: "U74"));

        var outcome = await host.Service.CheckForUpdateAsync();
        Assert.Equal(BiosCheckStatus.UpdateAvailable, outcome.Latest.Status);
        var req = Assert.Single(host.HttpHandler.Requests);
        Assert.Equal(expectedUrl, req.RequestUri.AbsoluteUri);
    }

    [Fact]
    public async Task E2E_T2_RTG_06_FaultyCustomProviderThrowingInCanHandleIsIsolated()
    {
        var identity = E2eIdentities.HpEliteBook();
        await using var host = BiosE2eTestHost.CreateElevated(
            identity,
            configureServices: (services, _, _, _, _, _) =>
            {
                services.AddBiosUpdateProvider(_ => new ThrowingCanHandleProvider());
            });

        var resolved = host.Service.ResolveProvider(identity);
        Assert.NotNull(resolved);
        Assert.Equal("hp", resolved.VendorId);
        Assert.Contains(host.LoggerFactory.Entries, e => e.Message.Contains("faulty-custom", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData("nonexistent")]
    [InlineData("hp")]
    public async Task E2E_T2_RTG_07_NonMatchingTargetProviderIdOverrideFallsBackSafely(string overrideProviderId)
    {
        var dellIdentity = E2eIdentities.DellLatitude();
        var (pkgBytes, sha256) = E2ePayloads.BuildDummyBinary("dell-fallback-safe");
        const string dellUrl = "https://downloads.dell.com/FOLDER1/Latitude_1.18.0.exe";

        await using var host = BiosE2eTestHost.CreateElevated(dellIdentity);
        host.HttpHandler.MapBytes(dellUrl, pkgBytes);

        // Dell machine with Target.ProviderId set to nonexistent or "hp" must NOT route to HP; keeps Dell provider
        var target = BiosLatestInfo.UpdateAvailable(overrideProviderId, "1.18.0", downloadUrl: dellUrl, sha256: sha256);
        var result = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(dellIdentity, dellIdentity.CurrentBios, target, Approved: true, SuspendBitLocker: false, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));

        Assert.True(result.Succeeded, result.Message);
        var call = Assert.Single(host.HostProcessLauncher.Calls);
        Assert.Equal(["/s"], call.Arguments); // Dell args, NOT HP ["-s", "-r"]
    }

    // =========================================================================
    // Area 2.2: Malicious SMBIOS Injection & Identifier Boundaries (E2E-T2-INJ-01..07)
    // =========================================================================

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("123")]
    [InlineData("12345")]
    [InlineData("ZZZZ")]
    [InlineData("8B41;calc.exe")]
    [InlineData("8B41&whoami")]
    [InlineData("../8B41")]
    [InlineData("8B41\r\nHost: evil.com")]
    public async Task E2E_T2_INJ_01_HpMaliciousOrInvalidBoardProductRejected(string badBoardProduct)
    {
        var identity = E2eIdentities.HpEliteBook(boardProduct: badBoardProduct, systemSku: "");
        await using var host = BiosE2eTestHost.CreateElevated(identity);

        var outcome = await host.Service.CheckForUpdateAsync();
        Assert.Equal("hp", outcome.ProviderId);
        Assert.Equal(BiosCheckStatus.UnsupportedHardware, outcome.Latest.Status);
        Assert.Empty(host.HttpHandler.Requests);
    }

    [Theory]
    [InlineData("")]
    [InlineData("0xGGGG")]
    [InlineData("0A1B|powershell")]
    [InlineData("$(calc)")]
    public async Task E2E_T2_INJ_02_DellMaliciousOrInvalidSystemSkuRejectedAnd0xPrefixNormalized(string badSku)
    {
        var badIdentity = E2eIdentities.DellLatitude(systemSku: badSku);
        await using var host = BiosE2eTestHost.CreateElevated(badIdentity);

        var badOutcome = await host.Service.CheckForUpdateAsync();
        Assert.Equal("dell", badOutcome.ProviderId);
        Assert.Equal(BiosCheckStatus.UnsupportedHardware, badOutcome.Latest.Status);
        Assert.Empty(host.HttpHandler.Requests);

        // Positive boundary: "0x0A1B" strips 0x and matches catalog systemID="0A1B"
        host.SystemProbe.Identity = E2eIdentities.DellLatitude(systemSku: "0x0A1B", biosVersion: "1.12.0");
        host.HttpHandler.MapText("https://downloads.dell.com/catalog/CatalogPC.cab", E2ePayloads.DellCatalogXml(systemId: "0A1B", version: "1.18.0"));
        var validOutcome = await host.Service.CheckForUpdateAsync();
        Assert.Equal(BiosCheckStatus.UpdateAvailable, validOutcome.Latest.Status);
        Assert.Equal("0A1B", validOutcome.Latest.Metadata?["systemSku"]);
    }

    [Theory]
    [InlineData("", "")]
    [InlineData("AB", "AB")]
    [InlineData("!!@@", "!!@@")]
    [InlineData("21HM;rm -rf /", "21HM;rm -rf /")]
    [InlineData("../../etc", "../../etc")]
    public async Task E2E_T2_INJ_03_LenovoMaliciousOrInvalidMtmRejected(string model, string sku)
    {
        var identity = E2eIdentities.LenovoThinkPad(model: model, systemSku: sku);
        await using var host = BiosE2eTestHost.CreateElevated(identity);

        var outcome = await host.Service.CheckForUpdateAsync();
        Assert.Equal("lenovo", outcome.ProviderId);
        Assert.Equal(BiosCheckStatus.UnsupportedHardware, outcome.Latest.Status);
        Assert.Empty(host.HttpHandler.Requests);
    }

    public static TheoryData<string, BiosSystemIdentity> MaliciousConsumerAndModernModelCases => new()
    {
        { "asus", E2eIdentities.AsusRog(model: "ROG;calc.exe", boardProduct: "ROG;calc.exe") },
        { "asus", E2eIdentities.AsusRog(model: "To Be Filled By O.E.M.", boardProduct: "To Be Filled By O.E.M.") },
        { "acer", E2eIdentities.AcerPredator(model: "Predator&whoami", boardProduct: "Predator&whoami") },
        { "acer", E2eIdentities.AcerPredator(model: "To Be Filled By O.E.M.", boardProduct: "To Be Filled By O.E.M.") },
        { "microsoft", E2eIdentities.SurfacePro9(model: "Surface Pro 9;calc", boardProduct: "Surface Pro 9") },
        { "microsoft", E2eIdentities.SurfacePro9(model: "Surface Pro 9?x=1", boardProduct: "Surface Pro 9") },
        { "framework", E2eIdentities.FrameworkLaptop13(model: "Laptop 13|sh", boardProduct: "FRANMDCP07", systemSku: "FRANMDCP07") },
        { "framework", E2eIdentities.FrameworkLaptop13(model: "To Be Filled By O.E.M.", boardProduct: "To Be Filled By O.E.M.", systemSku: "To Be Filled By O.E.M.") },
        { "asus", E2eIdentities.AsusRog(model: "../evil\r\n", boardProduct: "ROG") },
        { "acer", E2eIdentities.AcerPredator(model: "Acer$(whoami)", boardProduct: "Predator") }
    };

    [Theory]
    [MemberData(nameof(MaliciousConsumerAndModernModelCases))]
    public async Task E2E_T2_INJ_04_AsusAcerSurfaceFrameworkMaliciousModelTokensRejected(string expectedVendor, BiosSystemIdentity identity)
    {
        await using var host = BiosE2eTestHost.CreateElevated(identity);

        var outcome = await host.Service.CheckForUpdateAsync();
        Assert.Equal(expectedVendor, outcome.ProviderId);
        Assert.Equal(BiosCheckStatus.UnsupportedHardware, outcome.Latest.Status);
        Assert.Empty(host.HttpHandler.Requests);
        Assert.Empty(host.HostProcessLauncher.Calls);
    }

    [Theory]
    [InlineData("MS-7D75&whoami", "MAG B650")]
    [InlineData("../../secret", "../../secret")]
    [InlineData("MS-7D75;calc", "MS-7D75")]
    public async Task E2E_T2_INJ_05_MsiMaliciousBoardProductOrModelRejected(string boardProduct, string model)
    {
        var identity = E2eIdentities.MsiMag(model: model, boardProduct: boardProduct);
        await using var host = BiosE2eTestHost.CreateElevated(identity);

        var outcome = await host.Service.CheckForUpdateAsync();
        Assert.Equal("msi", outcome.ProviderId);
        Assert.Equal(BiosCheckStatus.UnsupportedHardware, outcome.Latest.Status);
        Assert.Empty(host.HttpHandler.Requests);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-guid")]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    [InlineData("00000000-0000-0000-0000-000000000000;calc")]
    [InlineData("../evil")]
    public async Task E2E_T2_INJ_06_WindowsUpdateNonGuidPackageIdRejected(string badPackageId)
    {
        var identity = E2eIdentities.GenericPc(firmwareMode: BiosFirmwareMode.Uefi);
        await using var host = BiosE2eTestHost.CreateElevated(identity);

        var target = BiosLatestInfo.UpdateAvailable("windows-update", "2.0", packageId: badPackageId);
        var result = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: true, AllowReboot: false));

        Assert.False(result.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, result.Status);
        Assert.Empty(host.WindowsUpdateClient.InstalledUpdateIds);
        Assert.Empty(host.HostProcessLauncher.Calls);
    }

    [Fact]
    public async Task E2E_T2_INJ_07_BitLockerStrictDriveTokenInvariantAcrossAllSixInstallableProviders()
    {
        var (pkgBytes, sha256) = E2ePayloads.BuildDummyBinary("inj07-drive");
        var (cabBytes, cabSha) = E2ePayloads.FrameworkCabCapsule();
        var wuaGuid = Guid.NewGuid();

        await using var host = BiosE2eTestHost.CreateElevated();
        host.HttpHandler.MapBytes("https://ftp.hp.com/pub/softpaq/sp151234.exe", pkgBytes);
        host.HttpHandler.MapBytes("https://downloads.dell.com/FOLDER1/dell.exe", pkgBytes);
        host.HttpHandler.MapBytes("https://download.lenovo.com/pccbbs/winuptp.exe", pkgBytes);
        host.HttpHandler.MapBytes("https://download.microsoft.com/surface/SurfacePro9.msi", pkgBytes);
        host.HttpHandler.MapBytes("https://cdn.fwupd.org/downloads/fw.cab", cabBytes);

        var cases = new (BiosSystemIdentity Id, BiosLatestInfo Target)[]
        {
            (E2eIdentities.HpEliteBook(), BiosLatestInfo.UpdateAvailable("hp", "01.14.00", downloadUrl: "https://ftp.hp.com/pub/softpaq/sp151234.exe", sha256: sha256)),
            (E2eIdentities.DellLatitude(), BiosLatestInfo.UpdateAvailable("dell", "1.18.0", downloadUrl: "https://downloads.dell.com/FOLDER1/dell.exe", sha256: sha256)),
            (E2eIdentities.LenovoThinkPad(), BiosLatestInfo.UpdateAvailable("lenovo", "N3XET52W", downloadUrl: "https://download.lenovo.com/pccbbs/winuptp.exe", sha256: sha256)),
            (E2eIdentities.SurfacePro9(), BiosLatestInfo.UpdateAvailable("microsoft", "15.102.143", downloadUrl: "https://download.microsoft.com/surface/SurfacePro9.msi", sha256: sha256)),
            (E2eIdentities.FrameworkLaptop13(), BiosLatestInfo.UpdateAvailable("framework", "3.05", downloadUrl: "https://cdn.fwupd.org/downloads/fw.cab", sha256: cabSha)),
            (E2eIdentities.GenericPc(firmwareMode: BiosFirmwareMode.Uefi), BiosLatestInfo.UpdateAvailable("windows-update", "2.0", packageId: wuaGuid.ToString("D")))
        };

        foreach (var (id, target) in cases)
        {
            host.SystemProbe.Identity = id;
            var res = await host.Service.InstallUpdateAsync(
                new BiosInstallRequest(id, id.CurrentBios, target, Approved: true, SuspendBitLocker: true, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));
            Assert.True(res.Succeeded, $"Expected success for {target.ProviderId}: {res.Message}");
        }

        var bdeCalls = host.HostProcessLauncher.Calls.Where(c => c.ToolName.Equals("manage-bde.exe", StringComparison.OrdinalIgnoreCase)).ToArray();
        Assert.Equal(6, bdeCalls.Length);
        foreach (var call in bdeCalls)
        {
            Assert.Equal(5, call.Arguments.Count);
            Assert.Equal("-protectors", call.Arguments[0]);
            Assert.Equal("-disable", call.Arguments[1]);
            Assert.Matches(@"^[A-Za-z]:$", call.Arguments[2]);
            Assert.Equal("-RebootCount", call.Arguments[3]);
            Assert.Equal("1", call.Arguments[4]);
        }
    }

    // =========================================================================
    // Area 2.3: Network, Redirect, Host-Suffix & HTTP Status Boundaries (E2E-T2-NET-01..08)
    // =========================================================================

    [Theory]
    [InlineData("hp", "https://evilhp.com/sp.exe", BiosInstallStatus.Failed)]
    [InlineData("hp", "https://hp.com.attacker.org/sp.exe", BiosInstallStatus.Failed)]
    [InlineData("dell", "https://notdell.com/bios.exe", BiosInstallStatus.Failed)]
    [InlineData("lenovo", "https://lenovo.com@evil.org/bios.exe", BiosInstallStatus.Failed)]
    [InlineData("hp", "http://ftp.hp.com/sp.exe", BiosInstallStatus.BlockedByPrerequisites)]
    [InlineData("hp", "file:///C:/bios.exe", BiosInstallStatus.BlockedByPrerequisites)]
    public async Task E2E_T2_NET_01_HostSuffixSpoofingAndUnsafeSchemesRejected(
        string vendorId, string badUrl, BiosInstallStatus expectedStatus)
    {
        var identity = vendorId switch
        {
            "dell" => E2eIdentities.DellLatitude(),
            "lenovo" => E2eIdentities.LenovoThinkPad(),
            _ => E2eIdentities.HpEliteBook()
        };

        await using var host = BiosE2eTestHost.CreateElevated(identity);
        var (_, sha256) = E2ePayloads.BuildDummyBinary("spoof-unused");
        var target = BiosLatestInfo.UpdateAvailable(vendorId, "9.9.9", downloadUrl: badUrl, sha256: sha256);

        var result = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: false, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));

        Assert.False(result.Succeeded);
        Assert.Equal(expectedStatus, result.Status);
        Assert.Empty(host.HttpHandler.Requests);
        Assert.Empty(host.HostProcessLauncher.Calls);
        host.StagingDir.AssertEmpty();
    }

    [Fact]
    public async Task E2E_T2_NET_02_CrossDomain302RedirectRejected()
    {
        var identity = E2eIdentities.DellLatitude();
        const string startUrl = "https://downloads.dell.com/FOLDER1/bios.exe";
        const string evilUrl = "https://evil-cdn.example.com/bios.exe";
        var (_, sha256) = E2ePayloads.BuildDummyBinary("dell-cross-domain");

        await using var host = BiosE2eTestHost.CreateElevated(identity);
        host.HttpHandler.MapRedirect(startUrl, evilUrl, HttpStatusCode.Found);

        var target = BiosLatestInfo.UpdateAvailable("dell", "1.18.0", downloadUrl: startUrl, sha256: sha256);
        var result = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: false, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));

        Assert.False(result.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, result.Status);
        Assert.Single(host.HttpHandler.Requests);
        Assert.Contains("redirect", result.Message ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(host.HttpHandler.Requests, r => r.RequestUri.Host.Equals("evil-cdn.example.com", StringComparison.OrdinalIgnoreCase));
        Assert.Empty(host.HostProcessLauncher.Calls);
        host.StagingDir.AssertEmpty();
    }

    [Fact]
    public async Task E2E_T2_NET_03_HttpsToHttpDowngrade302RedirectRejected()
    {
        var identity = E2eIdentities.HpEliteBook();
        const string startUrl = "https://ftp.hp.com/pub/softpaq/sp151234.exe";
        const string httpUrl = "http://ftp.hp.com/pub/softpaq/sp151234.exe";
        var (_, sha256) = E2ePayloads.BuildDummyBinary("hp-downgrade");

        await using var host = BiosE2eTestHost.CreateElevated(identity);
        host.HttpHandler.MapRedirect(startUrl, httpUrl, HttpStatusCode.Found);

        var target = BiosLatestInfo.UpdateAvailable("hp", "01.14.00", downloadUrl: startUrl, sha256: sha256);
        var result = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: false, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));

        Assert.False(result.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, result.Status);
        Assert.Single(host.HttpHandler.Requests);
        Assert.Contains("redirect", result.Message ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(host.HttpHandler.Requests, r => r.RequestUri.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase));
        Assert.Empty(host.HostProcessLauncher.Calls);
        host.StagingDir.AssertEmpty();
    }

    [Fact]
    public async Task E2E_T2_NET_04_RedirectLoopExceedingFiveHopsRejected()
    {
        var identity = E2eIdentities.HpEliteBook();
        await using var host = BiosE2eTestHost.CreateElevated(identity);

        // 6 consecutive redirects within hp.com (exceeds cap of 5)
        const string initialUrl = "https://hpia.hpcloud.hp.com/ref/8b41/8b41_64_11.0.cab";
        host.HttpHandler.MapRedirect(initialUrl, "https://ftp.hp.com/hop1.cab");
        host.HttpHandler.MapRedirect("https://ftp.hp.com/hop1.cab", "https://ftp.hp.com/hop2.cab");
        host.HttpHandler.MapRedirect("https://ftp.hp.com/hop2.cab", "https://ftp.hp.com/hop3.cab");
        host.HttpHandler.MapRedirect("https://ftp.hp.com/hop3.cab", "https://ftp.hp.com/hop4.cab");
        host.HttpHandler.MapRedirect("https://ftp.hp.com/hop4.cab", "https://ftp.hp.com/hop5.cab");
        host.HttpHandler.MapRedirect("https://ftp.hp.com/hop5.cab", "https://ftp.hp.com/hop6.cab");
        host.HttpHandler.MapText("https://ftp.hp.com/hop6.cab", E2ePayloads.HpCatalogXml());

        var outcome = await host.Service.CheckForUpdateAsync();
        Assert.True(outcome.Latest.Status is BiosCheckStatus.Failed or BiosCheckStatus.ProviderUnavailable,
            $"Expected Failed or ProviderUnavailable, got {outcome.Latest.Status}");
        Assert.Contains("redirect", outcome.Latest.Message ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.Equal(6, host.HttpHandler.Requests.Count);
        Assert.Equal(
            [
                initialUrl,
                "https://ftp.hp.com/hop1.cab",
                "https://ftp.hp.com/hop2.cab",
                "https://ftp.hp.com/hop3.cab",
                "https://ftp.hp.com/hop4.cab",
                "https://ftp.hp.com/hop5.cab"
            ],
            host.HttpHandler.Requests.Select(r => r.RequestUri.AbsoluteUri).ToArray());
        Assert.DoesNotContain(host.HttpHandler.Requests, r => r.RequestUri.AbsoluteUri.EndsWith("hop6.cab", StringComparison.Ordinal));
    }

    public static TheoryData<string, BiosSystemIdentity, string[]> Http404ProviderCases => new()
    {
        { "hp", E2eIdentities.HpEliteBook(), ["https://hpia.hpcloud.hp.com/ref/8b41/"] },
        { "dell", E2eIdentities.DellLatitude(), ["https://downloads.dell.com/catalog/CatalogPC.cab"] },
        { "lenovo", E2eIdentities.LenovoThinkPad(), ["https://download.lenovo.com/catalog/21HM_Win11.xml", "https://download.lenovo.com/catalog/21HM_Win10.xml"] },
        { "asus", E2eIdentities.AsusRog(), ["https://www.asus.com/support/api/product.asmx/GetPDBIOS"] },
        { "acer", E2eIdentities.AcerPredator(), ["https://www.acer.com/us-en/support/api/product/bios"] },
        { "msi", E2eIdentities.MsiMag(), ["https://www.msi.com/api/v1/product/support/panel"] },
        { "microsoft", E2eIdentities.SurfacePro9(), ["https://www.microsoft.com/surface/api/firmware"] },
        { "framework", E2eIdentities.FrameworkLaptop13(), ["https://cdn.fwupd.org/downloads/firmware.xml.gz"] }
    };

    [Theory]
    [MemberData(nameof(Http404ProviderCases))]
    public async Task E2E_T2_NET_05_Http404MapsToUnsupportedHardwareAcrossAllHttpProviders(
        string expectedVendor, BiosSystemIdentity identity, string[] urlPrefixes)
    {
        await using var host = BiosE2eTestHost.CreateElevated(identity);
        foreach (var prefix in urlPrefixes)
            host.HttpHandler.MapPrefixStatus(prefix, HttpStatusCode.NotFound);

        var outcome = await host.Service.CheckForUpdateAsync();
        Assert.Equal(expectedVendor, outcome.ProviderId);
        Assert.Equal(BiosCheckStatus.UnsupportedHardware, outcome.Latest.Status);
    }

    [Theory]
    [InlineData(HttpStatusCode.TooManyRequests)]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    public async Task E2E_T2_NET_06_Http429And5xxMapToProviderUnavailable(HttpStatusCode statusCode)
    {
        await using var host = BiosE2eTestHost.CreateElevated(E2eIdentities.AsusRog());
        host.HttpHandler.MapPrefixStatus("https://www.asus.com/support/api/product.asmx/GetPDBIOS", statusCode);
        var asusOutcome = await host.Service.CheckForUpdateAsync();
        Assert.Equal(BiosCheckStatus.ProviderUnavailable, asusOutcome.Latest.Status);

        host.SystemProbe.Identity = E2eIdentities.DellLatitude();
        host.HttpHandler.MapStatus("https://downloads.dell.com/catalog/CatalogPC.cab", statusCode);
        var dellOutcome = await host.Service.CheckForUpdateAsync();
        Assert.Equal(BiosCheckStatus.ProviderUnavailable, dellOutcome.Latest.Status);
    }

    [Fact]
    public async Task E2E_T2_NET_07_HttpRequestExceptionAndInternalTimeoutMapToOffline()
    {
        await using var host = BiosE2eTestHost.CreateElevated(E2eIdentities.AcerPredator());

        // HttpRequestException -> Offline
        host.HttpHandler.MapPrefixException("https://www.acer.com/us-en/support/api/product/bios", new HttpRequestException("DNS lookup failed"));
        var offline1 = await host.Service.CheckForUpdateAsync();
        Assert.Equal(BiosCheckStatus.Offline, offline1.Latest.Status);

        // Internal timeout TaskCanceledException (when caller CT is NOT cancelled) -> Offline
        host.HttpHandler.MapPrefixException("https://www.acer.com/us-en/support/api/product/bios", new TaskCanceledException("Request timed out"));
        var offline2 = await host.Service.CheckForUpdateAsync();
        Assert.Equal(BiosCheckStatus.Offline, offline2.Latest.Status);
    }

    [Fact]
    public async Task E2E_T2_NET_08_CallerCancellationPropagatesOperationCanceledException()
    {
        await using var host = BiosE2eTestHost.CreateElevated(E2eIdentities.MsiMag());

        // Pre-cancelled token on CheckForUpdateAsync
        using var cancelledCts = new CancellationTokenSource();
        cancelledCts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => host.Service.CheckForUpdateAsync(cancelledCts.Token));

        // Mid-request cancellation on CheckForUpdateAsync
        using var midCts = new CancellationTokenSource();
        host.HttpHandler.MapPrefix("https://www.msi.com/api/v1/product/support/panel", (_, token) =>
        {
            midCts.Cancel();
            token.ThrowIfCancellationRequested();
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        });
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => host.Service.CheckForUpdateAsync(midCts.Token));

        // Caller cancellation on InstallUpdateAsync
        var hpId = E2eIdentities.HpEliteBook();
        host.SystemProbe.Identity = hpId;
        var target = BiosLatestInfo.UpdateAvailable("hp", "01.14.00", downloadUrl: "https://ftp.hp.com/sp.exe");
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            host.Service.InstallUpdateAsync(
                new BiosInstallRequest(hpId, hpId.CurrentBios, target, Approved: true, StagingDirectory: host.StagingDir.Path),
                ct: cancelledCts.Token));
    }

    // =========================================================================
    // Area 2.4: Integrity, Archive & XML Hardening Boundaries (E2E-T2-INT-01..08)
    // =========================================================================

    [Fact]
    public async Task E2E_T2_INT_01_Sha256MismatchDeletesStagedFileAndNeverExecutes()
    {
        var identity = E2eIdentities.HpEliteBook();
        var (pkgBytes, cleanSha) = E2ePayloads.BuildDummyBinary("hp-tamper");
        var tamperedBytes = (byte[])pkgBytes.Clone();
        tamperedBytes[^1] ^= 0x01; // 1-bit flip
        const string url = "https://ftp.hp.com/pub/softpaq/sp151234.exe";

        await using var host = BiosE2eTestHost.CreateElevated(identity);
        host.HttpHandler.MapBytes(url, tamperedBytes);

        var target = BiosLatestInfo.UpdateAvailable("hp", "01.14.00", downloadUrl: url, sha256: cleanSha);
        var result = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: true, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));

        Assert.False(result.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, result.Status);
        Assert.Single(host.HttpHandler.Requests);
        Assert.Contains("SHA-256", result.Message ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.Empty(host.HostProcessLauncher.Calls);
        host.StagingDir.AssertEmpty();
    }

    [Theory]
    [InlineData("abc123")]
    [InlineData("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")]
    public async Task E2E_T2_INT_02_MalformedOrTruncatedOrNonHexSha256FailsClosed(string malformedSha)
    {
        var identity = E2eIdentities.DellLatitude();
        var (pkgBytes, _) = E2ePayloads.BuildDummyBinary("dell-bad-hash");
        const string url = "https://downloads.dell.com/FOLDER1/Latitude_1.18.0.exe";

        await using var host = BiosE2eTestHost.CreateElevated(identity);
        host.HttpHandler.MapBytes(url, pkgBytes);

        var target = BiosLatestInfo.UpdateAvailable("dell", "1.18.0", downloadUrl: url, sha256: malformedSha);
        var result = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: true, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));

        Assert.False(result.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, result.Status);
        Assert.Single(host.HttpHandler.Requests);
        Assert.Contains("SHA-256", result.Message ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.Empty(host.HostProcessLauncher.Calls);
        host.StagingDir.AssertEmpty();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task E2E_T2_INT_03_MissingSha256AndAuthenticodeFailureFailsClosed(string? sha256)
    {
        var identity = E2eIdentities.LenovoThinkPad();
        var (pkgBytes, _) = E2ePayloads.BuildDummyBinary("lenovo-unsigned");
        const string url = "https://download.lenovo.com/pccbbs/mobiles/winuptp.exe";

        await using var host = BiosE2eTestHost.CreateElevated(identity);
        host.SignatureVerifier.Predicate = _ => false;
        host.HttpHandler.MapBytes(url, pkgBytes);

        var target = BiosLatestInfo.UpdateAvailable("lenovo", "N3XET52W", downloadUrl: url, sha256: sha256);
        var result = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: true, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));

        Assert.False(result.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, result.Status);
        Assert.Single(host.HttpHandler.Requests);
        Assert.Contains("Authenticode", result.Message ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.Single(host.SignatureVerifier.VerifiedFilePaths);
        Assert.Empty(host.HostProcessLauncher.Calls);
        host.StagingDir.AssertEmpty();
    }

    [Theory]
    [InlineData("hp", "https://hpia.hpcloud.hp.com/ref/8b41/8b41_64_11.0.cab")]
    [InlineData("dell", "https://downloads.dell.com/catalog/CatalogPC.cab")]
    [InlineData("lenovo", "https://download.lenovo.com/catalog/21HM_Win11.xml")]
    [InlineData("framework", "https://cdn.fwupd.org/downloads/firmware.xml.gz")]
    public async Task E2E_T2_INT_04_XxeDtdEntityInjectionRejectedInXmlCatalogs(string vendorId, string catalogUrl)
    {
        var identity = vendorId switch
        {
            "dell" => E2eIdentities.DellLatitude(),
            "lenovo" => E2eIdentities.LenovoThinkPad(),
            "framework" => E2eIdentities.FrameworkLaptop13(),
            _ => E2eIdentities.HpEliteBook()
        };

        await using var host = BiosE2eTestHost.CreateElevated(identity);
        if (vendorId == "framework")
            host.HttpHandler.MapBytes(catalogUrl, E2ePayloads.BuildGzip(E2ePayloads.XxeDtdXml), "application/gzip");
        else
            host.HttpHandler.MapText(catalogUrl, E2ePayloads.XxeDtdXml);

        var outcome = await host.Service.CheckForUpdateAsync();
        Assert.Equal(vendorId, outcome.ProviderId);
        Assert.Equal(BiosCheckStatus.Failed, outcome.Latest.Status);
        Assert.Single(host.HttpHandler.Requests);
        Assert.Contains("DTD", outcome.Latest.Message ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("localhost", outcome.Latest.Message ?? "", StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("../../escaped_evil.exe")]
    [InlineData("/tmp/escaped_evil.exe")]
    [InlineData(@"..\escaped_evil.exe")]
    [InlineData(@"C:\escaped_evil.exe")]
    public async Task E2E_T2_INT_05_ArchivePathTraversalRejectedInFrameworkCabExtraction(string maliciousEntryName)
    {
        var identity = E2eIdentities.FrameworkLaptop13();
        const string cabUrl = "https://cdn.fwupd.org/downloads/framework-evil.cab";

        var evilCab = E2ePayloads.BuildCab([
            ("firmware.inf", Encoding.UTF8.GetBytes("[Version]\r\nClass=Firmware\r\n")),
            (maliciousEntryName, Encoding.UTF8.GetBytes("EVIL-ESCAPED-BINARY"))
        ]);
        var cabSha = E2ePayloads.ComputeSha256Hex(evilCab);

        await using var host = BiosE2eTestHost.CreateElevated(identity);
        host.HttpHandler.MapBytes(cabUrl, evilCab);

        var target = BiosLatestInfo.UpdateAvailable("framework", "3.06", downloadUrl: cabUrl, sha256: cabSha);
        var result = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: true, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));

        Assert.False(result.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, result.Status);
        Assert.Single(host.HttpHandler.Requests);
        Assert.Contains("archive safety", result.Message ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.Empty(host.HostProcessLauncher.Calls);
        host.StagingDir.AssertEmpty();
        Assert.False(File.Exists(Path.GetFullPath(Path.Combine(host.StagingDir.Path, "../../escaped_evil.exe"))));
        Assert.False(File.Exists(Path.GetFullPath(Path.Combine(host.StagingDir.Path, "..", "escaped_evil.exe"))));
        Assert.False(File.Exists(Path.Combine(Path.GetTempPath(), "escaped_evil.exe")));
    }

    [Fact]
    public async Task E2E_T2_INT_06_GzipDecompressionBombBoundedAndRejected()
    {
        var identity = E2eIdentities.FrameworkLaptop13();
        // Exceeds Framework's 64 MiB decompressed cap while staying ~65 KiB compressed in memory
        var bombBytes = E2ePayloads.BuildGzipBomb(66L * 1024 * 1024);

        await using var host = BiosE2eTestHost.CreateElevated(identity);
        host.HttpHandler.MapBytes("https://cdn.fwupd.org/downloads/firmware.xml.gz", bombBytes, "application/gzip");

        var outcome = await host.Service.CheckForUpdateAsync();
        Assert.Equal("framework", outcome.ProviderId);
        Assert.Equal(BiosCheckStatus.Failed, outcome.Latest.Status);
        Assert.Single(host.HttpHandler.Requests);
        Assert.Contains("GZip", outcome.Latest.Message ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.Contains("maximum allowed size", outcome.Latest.Message ?? "", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task E2E_T2_INT_07_OversizedDownloadAndMidStreamAbortCleanPartFiles()
    {
        var identity = E2eIdentities.HpEliteBook();
        const string oversizedUrl = "https://ftp.hp.com/pub/softpaq/huge.exe";
        const string truncatedUrl = "https://ftp.hp.com/pub/softpaq/truncated.exe";
        var (_, fakeSha) = E2ePayloads.BuildDummyBinary("unused");

        // Case 1: Declared Content-Length > 512 MiB
        await using (var host1 = BiosE2eTestHost.CreateElevated(identity))
        {
            host1.HttpHandler.MapExact(oversizedUrl, (_, _) =>
            {
                var resp = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new OversizedHeaderContent(600L * 1024 * 1024)
                };
                return Task.FromResult(resp);
            });

            var res1 = await host1.Service.InstallUpdateAsync(
                new BiosInstallRequest(identity, identity.CurrentBios,
                    BiosLatestInfo.UpdateAvailable("hp", "01.14.00", downloadUrl: oversizedUrl, sha256: fakeSha),
                    Approved: true, SuspendBitLocker: false, AllowReboot: false, VerifyHash: true, StagingDirectory: host1.StagingDir.Path));
            Assert.False(res1.Succeeded);
            Assert.Equal(BiosInstallStatus.Failed, res1.Status);
            Assert.Single(host1.HttpHandler.Requests);
            Assert.Contains("exceeds maximum allowed limit", res1.Message ?? "", StringComparison.OrdinalIgnoreCase);
            host1.StagingDir.AssertNoPartFilesRemain();
            Assert.Empty(host1.HostProcessLauncher.Calls);
        }

        // Case 2: Stream throws IOException mid-download
        await using (var host2 = BiosE2eTestHost.CreateElevated(identity))
        {
            host2.HttpHandler.MapExact(truncatedUrl, (_, _) =>
            {
                var resp = new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StreamContent(new FailingMidStream())
                };
                return Task.FromResult(resp);
            });

            var res2 = await host2.Service.InstallUpdateAsync(
                new BiosInstallRequest(identity, identity.CurrentBios,
                    BiosLatestInfo.UpdateAvailable("hp", "01.14.00", downloadUrl: truncatedUrl, sha256: fakeSha),
                    Approved: true, SuspendBitLocker: false, AllowReboot: false, VerifyHash: true, StagingDirectory: host2.StagingDir.Path));
            Assert.False(res2.Succeeded);
            Assert.Equal(BiosInstallStatus.Failed, res2.Status);
            Assert.Single(host2.HttpHandler.Requests);
            Assert.Contains("I/O error", res2.Message ?? "", StringComparison.OrdinalIgnoreCase);
            host2.StagingDir.AssertNoPartFilesRemain();
            Assert.Empty(host2.HostProcessLauncher.Calls);
        }
    }

    [Fact]
    public async Task E2E_T2_INT_08_CorruptMsCabHeaderFailsAndUtf8BomPlainXmlParsesCleanly()
    {
        var identity = E2eIdentities.DellLatitude(systemSku: "0A1B", biosVersion: "1.12.0");
        await using var host = BiosE2eTestHost.CreateElevated(identity);
        // When scripted, corrupt MSCF magic falls back to expand.exe; return non-zero so it fails cleanly
        host.HostProcessLauncher.OnTool("expand.exe", new ProcessResult(1, "", "Invalid cabinet"));

        // 1a. Random non-MSCF corrupt garbage -> Failed (0 process calls)
        host.HttpHandler.MapBytes("https://downloads.dell.com/catalog/CatalogPC.cab", Encoding.UTF8.GetBytes("NOT-A-VALID-CAB-OR-XML-PAYLOAD"));
        var corrupt1 = await host.Service.CheckForUpdateAsync();
        Assert.Equal(BiosCheckStatus.Failed, corrupt1.Latest.Status);
        Assert.Empty(host.HostProcessLauncher.Calls);

        // 1b. Truncated/corrupt MSCF header -> Failed (no crash)
        host.HttpHandler.MapBytes("https://downloads.dell.com/catalog/CatalogPC.cab", [(byte)'M', (byte)'S', (byte)'C', (byte)'F', 0xFF, 0xFF, 0x01, 0x02]);
        var corrupt2 = await host.Service.CheckForUpdateAsync();
        Assert.Equal(BiosCheckStatus.Failed, corrupt2.Latest.Status);

        // 2. Valid UTF-8 BOM + plain XML passthrough -> UpdateAvailable
        var bomXml = E2ePayloads.BuildUtf8BomXml(E2ePayloads.DellCatalogXml(systemId: "0A1B", version: "1.20.0"));
        host.HttpHandler.MapBytes("https://downloads.dell.com/catalog/CatalogPC.cab", bomXml);
        var bomOutcome = await host.Service.CheckForUpdateAsync();
        Assert.Equal(BiosCheckStatus.UpdateAvailable, bomOutcome.Latest.Status);
        Assert.Equal("1.20.0", bomOutcome.Latest.LatestVersion);
    }

    private sealed class ThrowingCanHandleProvider : IBiosUpdateProvider
    {
        public string VendorId => "faulty-custom";
        public string DisplayName => "Faulty Custom";
        public int Priority => 200;
        public BiosProviderCapabilities Capabilities => new();
        public bool CanHandle(BiosSystemIdentity system) => throw new InvalidOperationException("Simulated CanHandle crash.");
        public Task<BiosLatestInfo> GetLatestVersionAsync(BiosSystemIdentity system, BiosCurrentInfo current, CancellationToken ct = default) =>
            Task.FromResult(BiosLatestInfo.Unsupported(VendorId, "Should never run"));
    }

    private sealed class OversizedHeaderContent(long declaredLength) : HttpContent
    {
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => Task.CompletedTask;
        protected override bool TryComputeLength(out long length)
        {
            length = declaredLength;
            return true;
        }
    }
}
