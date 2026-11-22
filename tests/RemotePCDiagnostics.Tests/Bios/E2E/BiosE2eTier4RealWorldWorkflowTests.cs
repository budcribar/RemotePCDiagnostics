using System.Net;
using RemotePCDiagnostics.Core.Bios;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests.Bios.E2E;

/// <summary>
/// Tier 4 E2E Real-World Application Scenarios — all 8 full multi-step operator workflows (E2E-T4-01..08).
/// </summary>
[Trait("Tier", "4")]
public sealed class BiosE2eTier4RealWorldWorkflowTests
{
    [Fact]
    public async Task E2E_T4_01_EnterpriseFleetCheckAndStageHpDellLenovoBatteryToAcWithBitLocker()
    {
        var (hpBytes, hpSha) = E2ePayloads.BuildDummyBinary("t401-hp");
        var (dellBytes, dellSha) = E2ePayloads.BuildDummyBinary("t401-dell");
        var (lenBytes, lenSha) = E2ePayloads.BuildDummyBinary("t401-lenovo");

        const string hpPkgUrl = "https://ftp.hp.com/pub/softpaq/sp151001-151500/HPBIOSUPDREC64.exe";
        const string dellPkgUrl = "https://downloads.dell.com/FOLDER12345M/1/Latitude_5430_1.18.0.exe";
        const string lenPkgUrl = "https://download.lenovo.com/pccbbs/mobiles/winuptp.exe";

        await using var host = BiosE2eTestHost.CreateElevated(E2eIdentities.HpEliteBook());
        host.HttpHandler.MapBytes("https://hpia.hpcloud.hp.com/ref/8b41/8b41_64_11.0.cab",
            E2ePayloads.HpCatalogCab(version: "01.14.00", family: "U74", url: hpPkgUrl, sha256: hpSha, mszip: true));
        host.HttpHandler.MapBytes(hpPkgUrl, hpBytes);

        host.HttpHandler.MapBytes("https://downloads.dell.com/catalog/CatalogPC.cab",
            E2ePayloads.DellCatalogCab(systemId: "0A1B", version: "1.18.0", sha256: dellSha, mszip: true));
        host.HttpHandler.MapBytes(dellPkgUrl, dellBytes);

        host.HttpHandler.MapText("https://download.lenovo.com/catalog/21HM_Win11.xml", E2ePayloads.LenovoIndexXml());
        host.HttpHandler.MapText("https://download.lenovo.com/pccbbs/mobiles/n3xuj12w_2_.xml",
            E2ePayloads.LenovoDescriptorXml(version: "N3XET52W", fileName: "winuptp.exe", sha256: lenSha));
        host.HttpHandler.MapBytes(lenPkgUrl, lenBytes);

        var fleet = new (BiosSystemIdentity Identity, string VendorId, string ToolName, string[] ExpectedArgs)[]
        {
            (E2eIdentities.HpEliteBook(), "hp", "HPBIOSUPDREC64.exe", ["-s", "-r"]),
            (E2eIdentities.DellLatitude(), "dell", "Latitude_5430_1.18.0.exe", ["/s"]),
            (E2eIdentities.LenovoThinkPad(), "lenovo", "winuptp.exe", ["-s"])
        };

        foreach (var (identity, vendorId, toolName, expectedArgs) in fleet)
        {
            host.SystemProbe.Identity = identity;

            // Step 1: Discover update via pure-C# HTTPS XML/CAB catalog
            var check = await host.Service.CheckForUpdateAsync();
            Assert.Equal(vendorId, check.ProviderId);
            Assert.Equal(BiosCheckStatus.UpdateAvailable, check.Latest.Status);

            // Step 2: Laptop is on battery (25%) with BitLocker active -> blocked cleanly
            host.SafetyProbe.Snapshot = new BiosSafetySnapshot(
                OnAcPower: false, HasBattery: true, BatteryPercent: 25,
                BitLockerActive: true, BitLockerSuspended: false, HasElevation: true, PendingReboot: false);

            var blockedReq = new BiosInstallRequest(check.System, check.Current, check.Latest,
                Approved: true, ApprovedBy: "it-admin", SuspendBitLocker: true, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path);
            var preFlightBlocked = await host.Service.EvaluateInstallSafetyAsync(blockedReq);
            Assert.False(preFlightBlocked.Passed);
            Assert.True(preFlightBlocked.BlockingReasons.Count >= 2); // Off AC + < 30% battery

            var callsBeforeBlock = host.HostProcessLauncher.Calls.Count;
            var blockedRes = await host.Service.InstallUpdateAsync(blockedReq);
            Assert.False(blockedRes.Succeeded);
            Assert.Equal(BiosInstallStatus.BlockedByPrerequisites, blockedRes.Status);
            Assert.Equal(callsBeforeBlock, host.HostProcessLauncher.Calls.Count);

            // Step 3: User plugs in AC power and charges to 35%
            host.SafetyProbe.Snapshot = new BiosSafetySnapshot(
                OnAcPower: true, HasBattery: true, BatteryPercent: 35,
                BitLockerActive: true, BitLockerSuspended: false, HasElevation: true, PendingReboot: false);

            // Step 4: Approved install stages silently with BitLocker suspended and reboot suppressed
            var progress = new SyncProgress<BiosInstallProgress>();
            var staged = await host.Service.InstallUpdateAsync(blockedReq, progress);
            Assert.True(staged.Succeeded, $"{vendorId}: {staged.Message}");
            Assert.Equal(BiosInstallStatus.StagedForReboot, staged.Status);
            Assert.True(staged.RequiresReboot);
            Assert.True(staged.BitLockerSuspended);

            var flasherCall = Assert.Single(host.HostProcessLauncher.Calls, c => c.ToolName.Equals(toolName, StringComparison.OrdinalIgnoreCase));
            Assert.Equal(expectedArgs, flasherCall.Arguments);

            var stages = progress.Reports.Select(r => r.Stage).ToArray();
            Assert.Equal(BiosInstallStage.CheckingPrerequisites, stages[0]);
            Assert.Contains(BiosInstallStage.Downloading, stages);
            Assert.Contains(BiosInstallStage.Verifying, stages);
            Assert.Contains(BiosInstallStage.SuspendingBitLocker, stages);

            host.AssertNoSerialNumberLeaked(result: staged);
        }

        Assert.Equal(3, host.HostProcessLauncher.Calls.Count(c => c.ToolName.Equals("manage-bde.exe", StringComparison.OrdinalIgnoreCase)));
        host.StagingDir.AssertNoPartFilesRemain();
        host.AssertZeroShellInvocations();
    }

    [Fact]
    public async Task E2E_T4_02_MicrosoftSurfacePro9SilentMsiStagingAndHyperVNeighborIsolation()
    {
        var (msiBytes, msiSha) = E2ePayloads.BuildDummyBinary("t402-surface-msi");
        const string msiUrl = "https://download.microsoft.com/download/surface/SurfacePro9_Win11_22631_25.021.12345.0.msi";

        await using var host = BiosE2eTestHost.CreateElevated(E2eIdentities.HyperVVm(firmwareMode: BiosFirmwareMode.Legacy));

        // Step 1: Hyper-V VM neighbor must NOT match Surface provider
        var vmOutcome = await host.Service.CheckForUpdateAsync();
        Assert.Null(vmOutcome.ProviderId);
        Assert.Equal(BiosCheckStatus.UnsupportedHardware, vmOutcome.Latest.Status);

        // Step 2: Real Surface Pro 9 checks microsoft.com metadata and stages silent MSI with 3010
        host.SystemProbe.Identity = E2eIdentities.SurfacePro9(biosVersion: "15.100.143");
        host.HttpHandler.MapPrefixText("https://www.microsoft.com/surface/api/firmware",
            E2ePayloads.SurfaceFirmwareJson(version: "15.102.143", downloadUrl: msiUrl, sha256: msiSha));
        host.HttpHandler.MapBytes(msiUrl, msiBytes);
        host.HostProcessLauncher.OnTool("msiexec.exe", new ProcessResult(3010, "MSI staged; restart required.", ""));

        var surfaceCheck = await host.Service.CheckForUpdateAsync();
        Assert.Equal("microsoft", surfaceCheck.ProviderId);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, surfaceCheck.Latest.Status);

        var result = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(surfaceCheck.System, surfaceCheck.Current, surfaceCheck.Latest,
                Approved: true, SuspendBitLocker: true, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));

        Assert.True(result.Succeeded, result.Message);
        Assert.Equal(BiosInstallStatus.StagedForReboot, result.Status);
        Assert.True(result.RequiresReboot);
        Assert.True(result.BitLockerSuspended);
        Assert.Equal(3010, result.ExitCode);

        var msiexec = Assert.Single(host.HostProcessLauncher.Calls, c => c.ToolName.Equals("msiexec.exe", StringComparison.OrdinalIgnoreCase));
        Assert.Equal("/i", msiexec.Arguments[0]);
        Assert.Equal("/qn", msiexec.Arguments[2]);
        Assert.Equal("/norestart", msiexec.Arguments[3]);
        host.StagingDir.AssertNoPartFilesRemain();
        host.AssertNoSerialNumberLeaked(result: result);
        host.AssertZeroShellInvocations();
    }

    [Fact]
    public async Task E2E_T4_03_FrameworkLaptop13LvfsGzipAndCabCapsuleStaging()
    {
        var identity = E2eIdentities.FrameworkLaptop13(biosVersion: "3.03");
        var (cabBytes, cabSha) = E2ePayloads.FrameworkCabCapsule(mszip: true);
        const string cabUrl = "https://cdn.fwupd.org/downloads/framework-laptop13-amd7040-3.05.cab";

        await using var host = BiosE2eTestHost.CreateElevated(identity);
        host.HttpHandler.MapBytes("https://cdn.fwupd.org/downloads/firmware.xml.gz",
            E2ePayloads.FrameworkLvfsXmlGz(version: "3.05", location: cabUrl, sha256: cabSha), "application/gzip");
        host.HttpHandler.MapBytes(cabUrl, cabBytes);

        var check = await host.Service.CheckForUpdateAsync();
        Assert.Equal("framework", check.ProviderId);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, check.Latest.Status);
        Assert.Equal("3.05", check.Latest.LatestVersion);

        var result = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(check.System, check.Current, check.Latest,
                Approved: true, SuspendBitLocker: true, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));

        Assert.True(result.Succeeded, result.Message);
        Assert.Equal(BiosInstallStatus.StagedForReboot, result.Status);
        Assert.True(result.RequiresReboot);
        Assert.True(result.BitLockerSuspended);

        var pnputil = Assert.Single(host.HostProcessLauncher.Calls, c => c.ToolName.Equals("pnputil.exe", StringComparison.OrdinalIgnoreCase));
        Assert.Equal("/add-driver", pnputil.Arguments[0]);
        Assert.StartsWith(host.StagingDir.Path, pnputil.Arguments[1], StringComparison.OrdinalIgnoreCase);
        Assert.EndsWith(".inf", pnputil.Arguments[1], StringComparison.OrdinalIgnoreCase);
        Assert.Equal("/install", pnputil.Arguments[2]);

        host.StagingDir.AssertNoPartFilesRemain();
        host.AssertNoSerialNumberLeaked(result: result);
        host.AssertZeroShellInvocations();
    }

    [Fact]
    public async Task E2E_T4_04_GenericUnknownOemUefiFallbackToPureCSharpWindowsUpdateCapsule()
    {
        var identity = E2eIdentities.GenericPc(manufacturer: "WhiteBox Labs", boardManufacturer: "WhiteBox Labs", model: "Custom Workstation", firmwareMode: BiosFirmwareMode.Uefi);
        var firmwareGuid = Guid.NewGuid();

        await using var host = BiosE2eTestHost.CreateElevated(identity);
        host.WindowsUpdateClient.PendingUpdates =
        [
            new BiosWuaFirmwareUpdate(Guid.NewGuid().ToString("D"), "Realtek USB Audio Driver", "10.0.1", new DateOnly(2025, 1, 10), 2048, BiosUpdateSeverity.Optional, false, DriverClass: "MEDIA"),
            new BiosWuaFirmwareUpdate(firmwareGuid.ToString("D"), "WhiteBox System Firmware 4.2", "4.2.0", new DateOnly(2025, 3, 1), 6_291_456, BiosUpdateSeverity.Critical, true, DriverClass: "Firmware", Categories: ["Drivers", "System Firmware"])
        ];
        host.WindowsUpdateClient.InstallHandler = (_, _) =>
            Task.FromResult(new BiosWuaInstallOutcome(true, 2, true, "System Firmware staged via WUA."));

        var check = await host.Service.CheckForUpdateAsync();
        Assert.Equal("windows-update", check.ProviderId);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, check.Latest.Status);
        Assert.Equal(firmwareGuid.ToString("D"), check.Latest.PackageId);

        var result = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(check.System, check.Current, check.Latest, Approved: true, SuspendBitLocker: true, AllowReboot: false));

        Assert.True(result.Succeeded, result.Message);
        Assert.Equal(BiosInstallStatus.StagedForReboot, result.Status);
        Assert.True(result.RequiresReboot);
        Assert.True(result.BitLockerSuspended);
        Assert.Equal([firmwareGuid], host.WindowsUpdateClient.InstalledUpdateIds);
        Assert.Empty(host.HttpHandler.Requests);
        Assert.Single(host.HostProcessLauncher.Calls, c => c.ToolName.Equals("manage-bde.exe", StringComparison.OrdinalIgnoreCase));
        host.AssertNoSerialNumberLeaked(result: result);
        host.AssertZeroShellInvocations();
    }

    [Fact]
    public async Task E2E_T4_05_DiyConsumerDesktopCheckOnlyWorkflowAsusMsiAcer()
    {
        await using var host = BiosE2eTestHost.CreateElevated(E2eIdentities.AsusRog(), StubSafetyProbe.SafeDesktop());
        host.HttpHandler.MapPrefixText("https://www.asus.com/support/api/product.asmx/GetPDBIOS", E2ePayloads.AsusBiosJson(version: "2402"));
        host.HttpHandler.MapPrefixText("https://www.msi.com/api/v1/product/support/panel", E2ePayloads.MsiBiosJson(version: "7D75v1G"));
        host.HttpHandler.MapPrefixText("https://www.acer.com/us-en/support/api/product/bios", E2ePayloads.AcerBiosJson(version: "1.15"));

        var desktops = new (BiosSystemIdentity Id, string VendorId, string ExpectedHost)[]
        {
            (E2eIdentities.AsusRog(biosVersion: "1801"), "asus", "dlcdnets.asus.com"),
            (E2eIdentities.MsiMag(biosVersion: "1.A0"), "msi", "download.msi.com"),
            (E2eIdentities.AcerPredator(biosVersion: "1.08"), "acer", "global-download.acer.com")
        };

        foreach (var (id, vendorId, expectedHost) in desktops)
        {
            host.SystemProbe.Identity = id;
            var check = await host.Service.CheckForUpdateAsync();
            Assert.Equal(vendorId, check.ProviderId);
            Assert.Equal(BiosCheckStatus.UpdateAvailable, check.Latest.Status);
            Assert.NotNull(check.Latest.DownloadUrl);
            Assert.Contains(expectedHost, check.Latest.DownloadUrl!, StringComparison.OrdinalIgnoreCase);
            Assert.NotNull(check.Latest.ReleaseDate);

            var installRes = await host.Service.InstallUpdateAsync(
                new BiosInstallRequest(check.System, check.Current, check.Latest, Approved: true, StagingDirectory: host.StagingDir.Path));
            Assert.False(installRes.Succeeded);
            Assert.Equal(BiosInstallStatus.Unsupported, installRes.Status);
        }

        Assert.Equal(0, host.SafetyProbe.ProbeCount);
        Assert.Empty(host.HostProcessLauncher.Calls);
        host.AssertNoSerialNumberLeaked();
    }

    [Fact]
    public async Task E2E_T4_06_HostileNetworkAndTamperedFirmwareDefenseInDepthWorkflow()
    {
        var identity = E2eIdentities.HpEliteBook();
        const string catalogUrl = "https://hpia.hpcloud.hp.com/ref/8b41/8b41_64_11.0.cab";
        const string pkgUrl = "https://ftp.hp.com/pub/softpaq/sp151234.exe";
        var (cleanBytes, cleanSha) = E2ePayloads.BuildDummyBinary("t406-clean-hp");
        var tamperedBytes = (byte[])cleanBytes.Clone();
        tamperedBytes[^1] ^= 0xAA;

        await using var host = BiosE2eTestHost.CreateElevated(identity);

        // 1. Catalog returns XXE DTD payload -> safely fails
        host.HttpHandler.MapText(catalogUrl, E2ePayloads.XxeDtdXml);
        var xxeCheck = await host.Service.CheckForUpdateAsync();
        Assert.Equal(BiosCheckStatus.Failed, xxeCheck.Latest.Status);
        Assert.Contains("DTD", xxeCheck.Latest.Message ?? "", StringComparison.OrdinalIgnoreCase);

        // 2. Catalog succeeds, but download redirects 302 to evil host -> blocked, 0 evil requests
        host.HttpHandler.MapText(catalogUrl, E2ePayloads.HpCatalogXml(version: "01.14.00", url: pkgUrl, sha256: cleanSha));
        host.HttpHandler.MapRedirect(pkgUrl, "https://evil.example.com/bios.exe", HttpStatusCode.Found);
        var check = await host.Service.CheckForUpdateAsync();
        Assert.Equal(BiosCheckStatus.UpdateAvailable, check.Latest.Status);

        var redirRes = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(check.System, check.Current, check.Latest, Approved: true, SuspendBitLocker: true, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));
        Assert.False(redirRes.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, redirRes.Status);
        Assert.Contains("redirect", redirRes.Message ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(host.HttpHandler.Requests, r => r.RequestUri.Host.Equals("evil.example.com", StringComparison.OrdinalIgnoreCase));
        Assert.Empty(host.HostProcessLauncher.Calls);

        // 3. Download serves tampered bytes failing SHA-256 -> file deleted, .part cleaned, 0 executions
        host.HttpHandler.MapBytes(pkgUrl, tamperedBytes);
        var tamperRes = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(check.System, check.Current, check.Latest, Approved: true, SuspendBitLocker: true, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));
        Assert.False(tamperRes.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, tamperRes.Status);
        Assert.Contains("SHA-256", tamperRes.Message ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.Empty(host.HostProcessLauncher.Calls);
        host.StagingDir.AssertEmpty();

        // 4. Download omits SHA-256 and Authenticode fails -> file deleted, 0 executions
        host.SignatureVerifier.Predicate = _ => false;
        var sigChecksBefore = host.SignatureVerifier.VerifiedFilePaths.Count;
        var noHashTarget = check.Latest with { Sha256 = null };
        var unsignedRes = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(check.System, check.Current, noHashTarget, Approved: true, SuspendBitLocker: true, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));
        Assert.False(unsignedRes.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, unsignedRes.Status);
        Assert.Contains("Authenticode", unsignedRes.Message ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.Equal(sigChecksBefore + 1, host.SignatureVerifier.VerifiedFilePaths.Count);
        Assert.Empty(host.HostProcessLauncher.Calls);
        host.StagingDir.AssertEmpty();

        // 5. Clean signed package succeeds, and zero SerialNumber leaked across entire noisy log history
        host.SignatureVerifier.Predicate = _ => true;
        host.HttpHandler.MapBytes(pkgUrl, cleanBytes);
        host.HostProcessLauncher.OnTool("sp151234.exe", new ProcessResult(0, $"Recovered cleanly on {BiosE2eTestHost.CanarySerial}", ""));
        var cleanRes = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(check.System, check.Current, check.Latest, Approved: true, SuspendBitLocker: true, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));
        Assert.True(cleanRes.Succeeded, cleanRes.Message);
        Assert.Equal(BiosInstallStatus.StagedForReboot, cleanRes.Status);
        host.AssertNoSerialNumberLeaked(BiosE2eTestHost.CanarySerial, cleanRes);
        host.AssertZeroShellInvocations();
    }

    [Fact]
    public async Task E2E_T4_07_MultiVendorEnterpriseFleetTriageSweepAndExplicitWindowsUpdateOverride()
    {
        await using var host = BiosE2eTestHost.CreateElevated();

        // 10 diverse machines swept sequentially by a SINGLE DI-wired IBiosUpdateService instance
        var sweep = new (BiosSystemIdentity Identity, string? ExpectedVendorId)[]
        {
            (E2eIdentities.HpEliteBook(), "hp"),
            (E2eIdentities.DellLatitude(), "dell"),
            (E2eIdentities.LenovoThinkPad(), "lenovo"),
            (E2eIdentities.AsusRog(), "asus"),
            (E2eIdentities.AcerPredator(), "acer"),
            (E2eIdentities.MsiMag(), "msi"),
            (E2eIdentities.SurfacePro9(), "microsoft"),
            (E2eIdentities.FrameworkLaptop13(), "framework"),
            (E2eIdentities.HyperVVm(firmwareMode: BiosFirmwareMode.Uefi), "windows-update"),
            (E2eIdentities.GenericPc(firmwareMode: BiosFirmwareMode.Legacy), null)
        };

        foreach (var (id, expectedVendor) in sweep)
        {
            var resolved = host.Service.ResolveProvider(id);
            Assert.Equal(expectedVendor, resolved?.VendorId);
        }

        // HP UEFI laptop whose HP catalog returns 503 -> operator overrides with Target.ProviderId = "windows-update"
        var hpUefi = E2eIdentities.HpEliteBook(firmwareMode: BiosFirmwareMode.Uefi);
        host.SystemProbe.Identity = hpUefi;
        host.HttpHandler.MapStatus("https://hpia.hpcloud.hp.com/ref/8b41/8b41_64_11.0.cab", HttpStatusCode.ServiceUnavailable);

        var hpCheck = await host.Service.CheckForUpdateAsync();
        Assert.Equal("hp", hpCheck.ProviderId);
        Assert.Equal(BiosCheckStatus.ProviderUnavailable, hpCheck.Latest.Status);

        var wuaGuid = Guid.NewGuid();
        var overrideTarget = BiosLatestInfo.UpdateAvailable("windows-update", "01.14.00", packageId: wuaGuid.ToString("D"));
        var overrideRes = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(hpUefi, hpUefi.CurrentBios, overrideTarget, Approved: true, SuspendBitLocker: true, AllowReboot: false));

        Assert.True(overrideRes.Succeeded, overrideRes.Message);
        Assert.Equal(BiosInstallStatus.StagedForReboot, overrideRes.Status);
        Assert.Equal([wuaGuid], host.WindowsUpdateClient.InstalledUpdateIds);
        host.AssertNoSerialNumberLeaked(result: overrideRes);
    }

    [Fact]
    public async Task E2E_T4_08_StandardUserHostWithConnectedElevatedAgentOemAndWuaAndDisconnectWorkflow()
    {
        var (hpBytes, hpSha) = E2ePayloads.BuildDummyBinary("t408-hp");
        var (dellBytes, dellSha) = E2ePayloads.BuildDummyBinary("t408-dell");
        var (msiBytes, msiSha) = E2ePayloads.BuildDummyBinary("t408-surface");
        const string hpUrl = "https://ftp.hp.com/pub/softpaq/HPBIOSUPDREC64.exe";
        const string dellUrl = "https://downloads.dell.com/FOLDER1/Latitude_1.18.0.exe";
        const string surfaceUrl = "https://download.microsoft.com/surface/SurfacePro9.msi";
        var wuaGuid = Guid.NewGuid();

        await using var host = await BiosE2eTestHost.CreateAsync(new BiosE2eHostOptions
        {
            InitialIdentity = E2eIdentities.HpEliteBook(),
            IsProcessElevated = false,
            UseLiveAgentPipe = true,
            UseHermeticRealSafetyProbe = true,
            HermeticBitLockerActive = true
        });

        host.HttpHandler.MapText("https://hpia.hpcloud.hp.com/ref/8b41/8b41_64_11.0.cab", E2ePayloads.HpCatalogXml(url: hpUrl, sha256: hpSha));
        host.HttpHandler.MapBytes(hpUrl, hpBytes);
        host.HttpHandler.MapBytes("https://downloads.dell.com/catalog/CatalogPC.cab", E2ePayloads.DellCatalogCab(path: "FOLDER1/Latitude_1.18.0.exe", sha256: dellSha));
        host.HttpHandler.MapBytes(dellUrl, dellBytes);
        host.HttpHandler.MapPrefixText("https://www.microsoft.com/surface/api/firmware", E2ePayloads.SurfaceFirmwareJson(downloadUrl: surfaceUrl, sha256: msiSha));
        host.HttpHandler.MapBytes(surfaceUrl, msiBytes);
        host.LivePipe!.AgentProcessLauncher.OnTool("msiexec.exe", new ProcessResult(3010, "Staged", ""));
        host.LivePipe.AgentProcessLauncher.OnTool("HPBIOSUPDREC64.exe", new ProcessResult(0, $"Flashed {BiosE2eTestHost.CanarySerial}", ""));

        // Part A: Standard-user Host + Connected Agent stages HP, Dell, and Surface over live Admin Pipe
        foreach (var oemId in new[] { E2eIdentities.HpEliteBook(), E2eIdentities.DellLatitude(), E2eIdentities.SurfacePro9() })
        {
            host.SystemProbe.Identity = oemId;
            var check = await host.Service.CheckForUpdateAsync();
            Assert.Equal(BiosCheckStatus.UpdateAvailable, check.Latest.Status);

            var res = await host.Service.InstallUpdateAsync(
                new BiosInstallRequest(check.System, check.Current, check.Latest,
                    Approved: true, SuspendBitLocker: true, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));

            Assert.True(res.Succeeded, $"{check.ProviderId}: {res.Message}");
            Assert.Equal(BiosInstallStatus.StagedForReboot, res.Status);
            Assert.True(res.BitLockerSuspended);
            Assert.True(host.HermeticSafetyProbe!.LastRealSnapshot!.HasElevation);
            host.AssertNoSerialNumberLeaked(result: res);
        }

        // Part B: Same Standard-User Host + Connected Agent stages Windows Update UEFI capsule via Agent WUA
        var genericUefi = E2eIdentities.GenericPc(firmwareMode: BiosFirmwareMode.Uefi);
        host.SystemProbe.Identity = genericUefi;
        host.WindowsUpdateClient.PendingUpdates =
        [
            new BiosWuaFirmwareUpdate(wuaGuid.ToString("D"), "System Firmware 5.0", "5.0", new DateOnly(2025, 3, 1), 4096, BiosUpdateSeverity.Critical, true, "Firmware")
        ];

        var wuaCheck = await host.Service.CheckForUpdateAsync();
        Assert.Equal("windows-update", wuaCheck.ProviderId);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, wuaCheck.Latest.Status);

        var wuaRes = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(wuaCheck.System, wuaCheck.Current, wuaCheck.Latest, Approved: true, SuspendBitLocker: true, AllowReboot: false));

        Assert.True(wuaRes.Succeeded, wuaRes.Message);
        Assert.Equal(BiosInstallStatus.StagedForReboot, wuaRes.Status);
        Assert.True(wuaRes.BitLockerSuspended);
        Assert.Equal(1, host.LivePipe.AgentWuaApi.InstalledCount);
        Assert.Empty(host.WindowsUpdateClient.InstalledUpdateIds);

        // Host NEVER executed any elevated binary locally
        Assert.Empty(host.HostProcessLauncher.Calls);
        host.LivePipe.AgentStagingDir.AssertEmpty();

        // Part C: Agent disconnects -> next install attempt blocked cleanly with zero local fallback
        host.ElevationContext.IsAdminHelperConnected = false;
        var blockedAfterDisconnect = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(wuaCheck.System, wuaCheck.Current, wuaCheck.Latest, Approved: true, SuspendBitLocker: true, AllowReboot: false));

        Assert.False(blockedAfterDisconnect.Succeeded);
        Assert.Equal(BiosInstallStatus.BlockedByPrerequisites, blockedAfterDisconnect.Status);
        Assert.False(host.HermeticSafetyProbe!.LastRealSnapshot!.HasElevation);
        Assert.Empty(host.HostProcessLauncher.Calls);
        Assert.Empty(host.WindowsUpdateClient.InstalledUpdateIds);

        host.AssertZeroShellInvocations();
        host.AssertNoSerialNumberLeaked(result: blockedAfterDisconnect);
    }
}
