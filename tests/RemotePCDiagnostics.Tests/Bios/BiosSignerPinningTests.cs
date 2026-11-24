using System.Security.Cryptography.X509Certificates;
using System.Text;
using RemotePCDiagnostics.Core.Bios;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;
using Xunit;

namespace RemotePCDiagnostics.Tests.Bios;

/// <summary>The elevated Agent only runs BIOS packages signed by that vendor (Admin security issue 148).</summary>
public sealed class BiosSignerPinningTests
{
    [Theory]
    [InlineData(BiosAgentInstallModes.HpSoftPaq, "HP Inc.")]
    [InlineData(BiosAgentInstallModes.HpBiosUpdRec, "HP Inc.")]
    [InlineData(BiosAgentInstallModes.DellBiosExe, "Dell Inc")]
    [InlineData(BiosAgentInstallModes.DellDcuCli, "Dell Inc")]
    [InlineData(BiosAgentInstallModes.LenovoWinUptp, "Lenovo")]
    [InlineData(BiosAgentInstallModes.LenovoPackageSilent, "lenovo")]
    [InlineData(BiosAgentInstallModes.MicrosoftSurfaceMsi, "Microsoft Corporation")]
    [InlineData(BiosAgentInstallModes.FrameworkBiosExe, "Framework Computer Inc")]
    [InlineData(BiosAgentInstallModes.FrameworkCabCapsule, "Framework Computer Inc")]
    public void Each_mode_accepts_its_own_vendor(string mode, string organization) =>
        Assert.True(WinVerifyTrustSignatureVerifier.IsAllowedSignerOrganization(organization, BiosAgentInstallModes.AllowedSignerOrganizations(mode)));

    [Theory]
    [InlineData("hp", "HP Inc.")]
    [InlineData("dell", "Dell Inc")]
    [InlineData("lenovo", "Lenovo")]
    [InlineData("microsoft", "Microsoft Corporation")]
    [InlineData("framework", "Framework Computer Inc")]
    public void Each_vendor_id_maps_to_its_allowed_signers(string vendorId, string organization) =>
        Assert.True(WinVerifyTrustSignatureVerifier.IsAllowedSignerOrganization(organization, BiosAgentInstallModes.AllowedSignerOrganizationsForVendor(vendorId)));

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("unknown")]
    public void Unknown_vendor_id_returns_empty_signer_allowlist(string? vendorId) =>
        Assert.Empty(BiosAgentInstallModes.AllowedSignerOrganizationsForVendor(vendorId));

    [Theory]
    [InlineData(BiosAgentInstallModes.LenovoPackageSilent, "HP Inc.")]
    [InlineData(BiosAgentInstallModes.LenovoPackageSilent, "Microsoft Corporation")]
    [InlineData(BiosAgentInstallModes.HpSoftPaq, "Dell Inc")]
    [InlineData(BiosAgentInstallModes.DellBiosExe, "Dell")]
    [InlineData(BiosAgentInstallModes.DellBiosExe, "Dell Inc Evil")]
    [InlineData(BiosAgentInstallModes.MicrosoftSurfaceMsi, "Microsoft Corporation Ltd")]
    [InlineData(BiosAgentInstallModes.FrameworkBiosExe, "Some Code Signing LLC")]
    [InlineData(BiosAgentInstallModes.HpSoftPaq, "")]
    [InlineData(BiosAgentInstallModes.HpSoftPaq, null)]
    [InlineData("unknown_mode", "HP Inc.")]
    public void Other_signers_are_refused(string mode, string? organization) =>
        Assert.False(WinVerifyTrustSignatureVerifier.IsAllowedSignerOrganization(organization, BiosAgentInstallModes.AllowedSignerOrganizations(mode)));

    [Fact]
    public void Capsule_catalogs_must_be_signed_by_Microsoft()
    {
        Assert.True(WinVerifyTrustSignatureVerifier.IsAllowedSignerOrganization("Microsoft Corporation", BiosAgentInstallModes.AllowedCatalogSignerOrganizations));
        Assert.False(WinVerifyTrustSignatureVerifier.IsAllowedSignerOrganization("Framework Computer Inc", BiosAgentInstallModes.AllowedCatalogSignerOrganizations));
    }

    [Theory]
    [InlineData("CN=HP Inc., O=HP Inc., L=Palo Alto, S=California, C=US", "HP Inc.")]
    [InlineData("CN=Microsoft Windows Hardware Compatibility Publisher, O=Microsoft Corporation, L=Redmond, S=Washington, C=US", "Microsoft Corporation")]
    [InlineData("CN=Dell Inc, O=Dell Inc, L=Round Rock, S=Texas, C=US", "Dell Inc")]
    [InlineData("CN=No Organization, C=US", null)]
    public void Organization_is_read_from_the_O_field_not_the_CN(string subject, string? expected) =>
        Assert.Equal(expected, WinVerifyTrustSignatureVerifier.OrganizationOf(new X500DistinguishedName(subject)));

    [Fact]
    public async Task Pinned_verification_fails_closed_without_an_allowlist_or_off_Windows()
    {
        var file = Path.GetTempFileName();
        var member = Path.GetTempFileName();
        try
        {
            Assert.False(await WinVerifyTrustSignatureVerifier.Instance.VerifyAuthenticodeAsync(file, Array.Empty<string>()));
            Assert.False(await WinVerifyTrustSignatureVerifier.Instance.VerifyCatalogMemberAsync(file, member, Array.Empty<string>()));
            Assert.False(await WinVerifyTrustSignatureVerifier.Instance.VerifyCatalogMemberAsync(file, Path.Combine(Path.GetTempPath(), $"missing-{Guid.NewGuid():N}.inf"), ["Microsoft Corporation"]));
            if (!OperatingSystem.IsWindows())
            {
                Assert.False(await WinVerifyTrustSignatureVerifier.Instance.VerifyAuthenticodeAsync(file, ["HP Inc."]));
                Assert.False(await WinVerifyTrustSignatureVerifier.Instance.VerifyCatalogMemberAsync(file, member, ["Microsoft Corporation"]));
            }
        }
        finally
        {
            File.Delete(file);
            File.Delete(member);
        }
    }

    [Fact]
    public async Task Capsule_cab_rejected_when_signed_cat_does_not_cover_target_inf()
    {
        using var userDir = new TempStagingDir();
        using var adminRoot = new TempStagingDir();

        var cabBytes = TestCabBuilder.CreateUncompressed(new Dictionary<string, byte[]>
        {
            ["rogue.inf"] = Encoding.UTF8.GetBytes("[Version]\nSignature=\"$WINDOWS NT$\""),
            ["unrelated-ms.cat"] = Encoding.UTF8.GetBytes("validly-signed-by-microsoft-for-other-files"),
            ["firmware.bin"] = Encoding.UTF8.GetBytes("uefi-capsule-payload"),
        });
        var cabPayload = TestPayload.FromBytes(cabBytes);
        var userCabPath = userDir.FilePath("rogue-capsule.cab");
        await File.WriteAllBytesAsync(userCabPath, cabPayload.Bytes);

        // Outer .cab is unsigned; unrelated-ms.cat WOULD pass standalone Authenticode,
        // but does NOT cover rogue.inf when verified via VerifyCatalogMemberAsync.
        var verifier = new FakeSignatureVerifier(
            impl: (path, _) => Task.FromResult(path.EndsWith(".cat", StringComparison.OrdinalIgnoreCase)),
            catalogMemberImpl: (catPath, memberPath, signers, _) => Task.FromResult(false));
        var launcher = new RecordingProcessLauncher(_ => new ProcessResult(0, "OK", ""));
        var ops = new AgentBiosOperations(launcher, verifier, stagingRoot: adminRoot.Path);

        var res = await ops.RunBiosInstallerAsync(new BiosAgentInstallRequest(
            VendorId: "framework",
            InstallMode: BiosAgentInstallModes.FrameworkCabCapsule,
            PackagePath: userCabPath,
            ExpectedSha256: cabPayload.Sha256,
            InfRelativePath: "rogue.inf"));

        Assert.False(res.Executed);
        Assert.False(res.Allowed);
        Assert.Empty(launcher.Calls);
        Assert.Empty(Directory.GetFileSystemEntries(adminRoot.Path));

        var check = Assert.Single(verifier.CatalogMemberChecks);
        Assert.EndsWith("unrelated-ms.cat", check.CatalogPath, StringComparison.OrdinalIgnoreCase);
        Assert.EndsWith("rogue.inf", check.MemberFilePath, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(BiosAgentInstallModes.AllowedCatalogSignerOrganizations, check.AllowedSigners);
    }

    [Fact]
    public async Task Capsule_cab_accepted_when_signed_cat_covers_target_inf()
    {
        using var userDir = new TempStagingDir();
        using var adminRoot = new TempStagingDir();

        var cabBytes = TestCabBuilder.CreateUncompressed(new Dictionary<string, byte[]>
        {
            ["firmware.inf"] = Encoding.UTF8.GetBytes("[Version]\nSignature=\"$WINDOWS NT$\""),
            ["firmware.cat"] = Encoding.UTF8.GetBytes("validly-signed-whql-catalog"),
            ["firmware.bin"] = Encoding.UTF8.GetBytes("uefi-capsule-payload"),
        });
        var cabPayload = TestPayload.FromBytes(cabBytes);
        var userCabPath = userDir.FilePath("valid-capsule.cab");
        await File.WriteAllBytesAsync(userCabPath, cabPayload.Bytes);

        // Outer .cab is unsigned, but firmware.cat is Microsoft-signed AND covers firmware.inf.
        var verifier = new FakeSignatureVerifier(
            impl: (_, _) => Task.FromResult(false),
            catalogMemberImpl: (catPath, memberPath, signers, _) => Task.FromResult(
                catPath.EndsWith("firmware.cat", StringComparison.OrdinalIgnoreCase)
                && memberPath.EndsWith("firmware.inf", StringComparison.OrdinalIgnoreCase)
                && WinVerifyTrustSignatureVerifier.IsAllowedSignerOrganization("Microsoft Corporation", signers)));
        var launcher = new RecordingProcessLauncher(_ => new ProcessResult(3010, "Driver added.", ""));
        var ops = new AgentBiosOperations(launcher, verifier, stagingRoot: adminRoot.Path);

        var res = await ops.RunBiosInstallerAsync(new BiosAgentInstallRequest(
            VendorId: "framework",
            InstallMode: BiosAgentInstallModes.FrameworkCabCapsule,
            PackagePath: userCabPath,
            ExpectedSha256: cabPayload.Sha256,
            InfRelativePath: "firmware.inf"));

        Assert.True(res.Executed);
        Assert.True(res.Allowed);
        Assert.Equal(3010, res.ExitCode);
        Assert.Single(launcher.Calls);
        Assert.Empty(Directory.GetFileSystemEntries(adminRoot.Path));

        var check = Assert.Single(verifier.CatalogMemberChecks);
        Assert.EndsWith("firmware.cat", check.CatalogPath, StringComparison.OrdinalIgnoreCase);
        Assert.EndsWith("firmware.inf", check.MemberFilePath, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task VerifyHash_false_still_requires_pinned_Authenticode_in_DownloadAndVerifyAsync()
    {
        var payload = TestPayload.FromString("bios-package-bytes");
        var url = "https://ftp.hp.com/pub/softpaq/sp150999.exe";
        var handler = new FakeBiosHttpHandler();
        handler.MapBytes(url, payload.Bytes);
        using var client = handler.CreateClient();

        // Unsigned / untrusted signer must be rejected and deleted even when VerifyHash=false.
        using var failStaging = new TempStagingDir();
        var failVerifier = new FakeSignatureVerifier(result: false);
        var failReq = BiosIdentityFactory.CreateInstallRequest(
            downloadUrl: url,
            sha256: payload.Sha256,
            stagingDirectory: failStaging.Path) with
        {
            VerifyHash = false,
        };

        var failRes = await BiosPackageVerification.DownloadAndVerifyAsync(
            client, failReq, "hp", ["ftp.hp.com"], "sp.exe", failVerifier, null, null, CancellationToken.None);

        Assert.False(failRes.Succeeded);
        Assert.Equal(1, failVerifier.CallCount);
        Assert.Equal(BiosAgentInstallModes.AllowedSignerOrganizationsForVendor("hp"), Assert.Single(failVerifier.AllowedSignerSets));
        Assert.Empty(Directory.GetFiles(failStaging.Path));

        // Pinned vendor signature passes when VerifyHash=false.
        using var okStaging = new TempStagingDir();
        var okVerifier = new FakeSignatureVerifier(result: true);
        var okReq = failReq with { StagingDirectory = okStaging.Path };

        var okRes = await BiosPackageVerification.DownloadAndVerifyAsync(
            client, okReq, "hp", ["ftp.hp.com"], "sp.exe", okVerifier, null, null, CancellationToken.None);

        Assert.True(okRes.Succeeded);
        Assert.True(okRes.VerifiedByAuthenticode);
        Assert.False(okRes.VerifiedBySha256);
        Assert.Equal(1, okVerifier.CallCount);
        Assert.Equal(BiosAgentInstallModes.AllowedSignerOrganizationsForVendor("hp"), Assert.Single(okVerifier.AllowedSignerSets));
    }

    [Fact]
    public async Task VerifyHash_false_cannot_bypass_signature_in_Surface_or_Framework_providers()
    {
        var payload = TestPayload.FromString("installer-payload");

        // 1. Microsoft Surface MSI with VerifyHash=false and failing signature -> rejected, never launches msiexec.
        using var surfaceStaging = new TempStagingDir();
        var surfaceUrl = "https://download.microsoft.com/download/surface/SurfaceLaptop5_Win11.msi";
        var surfaceHandler = new FakeBiosHttpHandler();
        surfaceHandler.MapBytes(surfaceUrl, payload.Bytes);
        var surfaceLauncher = new RecordingProcessLauncher(_ => new ProcessResult(0, "OK", ""));
        var surfaceCommands = RecordingProcessLauncher.CreateCommandRunner(surfaceLauncher, isProcessElevated: true);
        var surfaceVerifier = new FakeSignatureVerifier(result: false);
        var surfaceProvider = MicrosoftSurfaceBiosUpdateProvider.CreateWithHandler(
            surfaceHandler,
            commands: surfaceCommands,
            signatureVerifier: surfaceVerifier,
            isProcessElevated: () => true);

        var surfaceId = BiosIdentityFactory.MicrosoftSurface();
        var surfaceReq = new BiosInstallRequest(
            System: surfaceId,
            Current: surfaceId.CurrentBios,
            Target: BiosLatestInfo.UpdateAvailable("microsoft", "12.0.0", downloadUrl: surfaceUrl, sha256: payload.Sha256, packageId: "SurfaceLaptop5_Win11"),
            Approved: true,
            SuspendBitLocker: false,
            AllowReboot: false,
            VerifyHash: false,
            StagingDirectory: surfaceStaging.Path);

        var surfaceRes = await surfaceProvider.InstallAsync(surfaceReq);

        Assert.False(surfaceRes.Succeeded);
        Assert.Equal(1, surfaceVerifier.CallCount);
        Assert.Equal(BiosAgentInstallModes.AllowedSignerOrganizationsForVendor("microsoft"), Assert.Single(surfaceVerifier.AllowedSignerSets));
        Assert.Empty(surfaceLauncher.Calls);
        Assert.Empty(Directory.GetFiles(surfaceStaging.Path));

        // 2. Framework EXE with VerifyHash=false and failing signature -> rejected, never launches installer.
        using var fwStaging = new TempStagingDir();
        var fwUrl = "https://downloads.frame.work/bios/Framework_Laptop_13_BIOS_3.05.exe";
        var fwHandler = new FakeBiosHttpHandler();
        fwHandler.MapBytes(fwUrl, payload.Bytes);
        var fwLauncher = new RecordingProcessLauncher(_ => new ProcessResult(0, "OK", ""));
        var fwCommands = RecordingProcessLauncher.CreateCommandRunner(fwLauncher, isProcessElevated: true);
        var fwVerifier = new FakeSignatureVerifier(result: false);
        var fwProvider = FrameworkBiosUpdateProvider.CreateWithHandler(
            fwHandler,
            commands: fwCommands,
            signatureVerifier: fwVerifier,
            isProcessElevated: () => true);

        var fwId = BiosIdentityFactory.Framework();
        var fwReq = new BiosInstallRequest(
            System: fwId,
            Current: fwId.CurrentBios,
            Target: BiosLatestInfo.UpdateAvailable("framework", "03.05", downloadUrl: fwUrl, sha256: payload.Sha256, packageId: "FW_3.05"),
            Approved: true,
            SuspendBitLocker: false,
            AllowReboot: false,
            VerifyHash: false,
            StagingDirectory: fwStaging.Path);

        var fwRes = await fwProvider.InstallAsync(fwReq);

        Assert.False(fwRes.Succeeded);
        Assert.Equal(1, fwVerifier.CallCount);
        Assert.Equal(BiosAgentInstallModes.AllowedSignerOrganizationsForVendor("framework"), Assert.Single(fwVerifier.AllowedSignerSets));
        Assert.Empty(fwLauncher.Calls);
        Assert.Empty(Directory.GetFiles(fwStaging.Path));
    }

    [Fact]
    public void SafetyEvaluator_warns_when_VerifyHash_is_false_for_downloadable_package()
    {
        var req = BiosIdentityFactory.CreateInstallRequest(
            downloadUrl: "https://ftp.hp.com/pub/softpaq/sp150000.exe",
            sha256: new string('a', 64)) with
        {
            VerifyHash = false,
        };
        var snapshot = new BiosSafetySnapshot(
            HasElevation: true,
            HasBattery: false,
            OnAcPower: true,
            BatteryPercent: null,
            BitLockerActive: false,
            BitLockerSuspended: false,
            PendingReboot: false);
        var caps = new BiosProviderCapabilities(
            CanCheckLatest: true,
            CanInstall: true,
            SupportsSilentInstall: true,
            RequiresReboot: true,
            RequiresElevation: true);

        var eval = BiosInstallSafetyEvaluator.Evaluate(snapshot, req, caps);

        Assert.True(eval.Passed);
        Assert.Contains(eval.Warnings, w => w.Contains("Authenticode", StringComparison.OrdinalIgnoreCase));
    }
}
