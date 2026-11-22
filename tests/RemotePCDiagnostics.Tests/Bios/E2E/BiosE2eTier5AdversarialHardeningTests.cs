using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Bios;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests.Bios.E2E;

/// <summary>
/// Tier 5 E2E Adversarial Hardening &amp; Concurrency Suite (T5-SEC-01..06, T5-COR-01..06,
/// T5-CON-01..02, T5-ELV-01, T5-DI-01). Strictly opaque-box over <see cref="IBiosUpdateService"/>,
/// <see cref="BiosE2eTestHost"/>, <see cref="ElevationService"/>, and live <see cref="AdminPipeServer"/>/<see cref="AdminPipeClient"/>.
/// </summary>
[Trait("Tier", "5")]
public sealed class BiosE2eTier5AdversarialHardeningTests
{
    // -------------------------------------------------------------------------
    // T5-SEC-01: AllowAutoRedirect = true defense-in-depth across ALL 8 HTTP providers
    // -------------------------------------------------------------------------

    [Fact]
    public async Task T5_SEC_01_AllowAutoRedirectBypassBlockedAcrossAllEightHttpProviders()
    {
        var (pkgBytes, pkgSha) = E2ePayloads.BuildDummyBinary("t5-sec01-pkg");

        // 1. HP catalog auto-redirect to attacker domain & same-domain path traversal
        await using (var host = BiosE2eTestHost.CreateElevated(E2eIdentities.HpEliteBook()))
        {
            host.HttpHandler.MapExact(
                "https://hpia.hpcloud.hp.com/ref/8b41/8b41_64_11.0.cab",
                (_, _) => Task.FromResult(CreateAutoRedirectedBytesResponse(
                    "https://evil.attacker.example/pwned-hp.cab",
                    E2ePayloads.HpCatalogCab(version: "01.99.00", family: "U74"))));

            var check = await host.Service.CheckForUpdateAsync();
            Assert.Equal("hp", check.ProviderId);
            Assert.Equal(BiosCheckStatus.Failed, check.Latest.Status);
            Assert.Null(check.Latest.LatestVersion);

            host.HttpHandler.MapExact(
                "https://hpia.hpcloud.hp.com/ref/8b41/8b41_64_11.0.cab",
                (_, _) => Task.FromResult(CreateAutoRedirectedBytesResponse(
                    "https://hpia.hpcloud.hp.com/ref/8b41/../../secret.cab",
                    E2ePayloads.HpCatalogCab(version: "01.99.00", family: "U74"))));

            var traversalCheck = await host.Service.CheckForUpdateAsync();
            Assert.Equal("hp", traversalCheck.ProviderId);
            Assert.Equal(BiosCheckStatus.Failed, traversalCheck.Latest.Status);
            Assert.Null(traversalCheck.Latest.LatestVersion);
        }

        // 2. Dell catalog auto-redirect to attacker domain
        await using (var host = BiosE2eTestHost.CreateElevated(E2eIdentities.DellLatitude()))
        {
            host.HttpHandler.MapExact(
                "https://downloads.dell.com/catalog/CatalogPC.cab",
                (_, _) => Task.FromResult(CreateAutoRedirectedBytesResponse(
                    "https://evil.attacker.example/pwned-dell.cab",
                    E2ePayloads.DellCatalogCab(systemId: "0A1B", version: "9.99.0"))));

            var check = await host.Service.CheckForUpdateAsync();
            Assert.Equal("dell", check.ProviderId);
            Assert.Equal(BiosCheckStatus.Failed, check.Latest.Status);
            Assert.Null(check.Latest.LatestVersion);
        }

        // 3. Lenovo catalog auto-redirect to attacker domain
        await using (var host = BiosE2eTestHost.CreateElevated(E2eIdentities.LenovoThinkPad()))
        {
            host.HttpHandler.MapExact(
                "https://download.lenovo.com/catalog/21HM_Win11.xml",
                (_, _) => Task.FromResult(CreateAutoRedirectedTextResponse(
                    "https://evil.attacker.example/pwned-lenovo.xml",
                    E2ePayloads.LenovoIndexXml(version: "N3XET99W"),
                    "application/xml")));

            var check = await host.Service.CheckForUpdateAsync();
            Assert.Equal("lenovo", check.ProviderId);
            Assert.Equal(BiosCheckStatus.Failed, check.Latest.Status);
            Assert.Null(check.Latest.LatestVersion);
        }

        // 4. ASUS catalog auto-redirect to attacker domain
        await using (var host = BiosE2eTestHost.CreateElevated(E2eIdentities.AsusRog()))
        {
            host.HttpHandler.MapPrefix(
                "https://www.asus.com/",
                (_, _) => Task.FromResult(CreateAutoRedirectedTextResponse(
                    "https://evil.attacker.example/pwned-asus.json",
                    E2ePayloads.AsusBiosJson(version: "9999"),
                    "application/json")));

            var check = await host.Service.CheckForUpdateAsync();
            Assert.Equal("asus", check.ProviderId);
            Assert.Equal(BiosCheckStatus.Failed, check.Latest.Status);
            Assert.Null(check.Latest.LatestVersion);
        }

        // 5. Acer catalog auto-redirect HTTP downgrade
        await using (var host = BiosE2eTestHost.CreateElevated(E2eIdentities.AcerPredator()))
        {
            host.HttpHandler.MapPrefix(
                "https://www.acer.com/",
                (_, _) => Task.FromResult(CreateAutoRedirectedTextResponse(
                    "http://www.acer.com/downgrade-acer.json",
                    E2ePayloads.AcerBiosJson(version: "9.99"),
                    "application/json")));

            var check = await host.Service.CheckForUpdateAsync();
            Assert.Equal("acer", check.ProviderId);
            Assert.Equal(BiosCheckStatus.Failed, check.Latest.Status);
            Assert.Null(check.Latest.LatestVersion);
        }

        // 6. MSI catalog auto-redirect to attacker domain
        await using (var host = BiosE2eTestHost.CreateElevated(E2eIdentities.MsiMag()))
        {
            host.HttpHandler.MapPrefix(
                "https://www.msi.com/",
                (_, _) => Task.FromResult(CreateAutoRedirectedTextResponse(
                    "https://evil.attacker.example/pwned-msi.json",
                    E2ePayloads.MsiBiosJson(version: "7D75v9Z"),
                    "application/json")));

            var check = await host.Service.CheckForUpdateAsync();
            Assert.Equal("msi", check.ProviderId);
            Assert.Equal(BiosCheckStatus.Failed, check.Latest.Status);
            Assert.Null(check.Latest.LatestVersion);
        }

        // 7. Microsoft Surface catalog auto-redirect AND package auto-redirect (evil domain + same-domain wrong extension .exe)
        await using (var host = BiosE2eTestHost.CreateElevated(E2eIdentities.SurfacePro9()))
        {
            host.HttpHandler.MapPrefix(
                "https://www.microsoft.com/",
                (_, _) => Task.FromResult(CreateAutoRedirectedTextResponse(
                    "https://evil.attacker.example/surface.json",
                    E2ePayloads.SurfaceFirmwareJson(version: "18.200.0"),
                    "application/json")));

            var catCheck = await host.Service.CheckForUpdateAsync();
            Assert.Equal("microsoft", catCheck.ProviderId);
            Assert.Equal(BiosCheckStatus.Failed, catCheck.Latest.Status);

            const string msiUrl = "https://download.microsoft.com/download/surface/SurfacePro9_Win11.msi";
            host.HttpHandler.MapPrefixText(
                "https://www.microsoft.com/",
                E2ePayloads.SurfaceFirmwareJson(version: "18.200.0", downloadUrl: msiUrl, sha256: pkgSha),
                "application/json");
            var goodCheck = await host.Service.CheckForUpdateAsync();
            Assert.Equal(BiosCheckStatus.UpdateAvailable, goodCheck.Latest.Status);

            // 7a. Package auto-redirect to attacker domain
            host.HttpHandler.MapExact(msiUrl, (_, _) => Task.FromResult(
                CreateAutoRedirectedBytesResponse("https://evil.attacker.example/malware.msi", pkgBytes)));
            var evilInstall = await host.Service.InstallUpdateAsync(new BiosInstallRequest(
                goodCheck.System, goodCheck.Current, goodCheck.Latest,
                Approved: true, ApprovedBy: "sec-test", SuspendBitLocker: false, AllowReboot: false, VerifyHash: true,
                StagingDirectory: host.StagingDir.Path));
            Assert.False(evilInstall.Succeeded);
            Assert.Empty(host.HostProcessLauncher.Calls);

            // 7b. Package auto-redirect on same Microsoft domain to wrong extension (.exe instead of .msi)
            host.HttpHandler.MapExact(msiUrl, (_, _) => Task.FromResult(
                CreateAutoRedirectedBytesResponse("https://download.microsoft.com/download/surface/malware.exe", pkgBytes)));
            var wrongExtInstall = await host.Service.InstallUpdateAsync(new BiosInstallRequest(
                goodCheck.System, goodCheck.Current, goodCheck.Latest,
                Approved: true, ApprovedBy: "sec-test", SuspendBitLocker: false, AllowReboot: false, VerifyHash: true,
                StagingDirectory: host.StagingDir.Path));
            Assert.False(wrongExtInstall.Succeeded);
            Assert.Empty(host.HostProcessLauncher.Calls);
        }

        // 8. Framework catalog auto-redirect AND package auto-redirect (evil domain + same-domain wrong extension .msi)
        await using (var host = BiosE2eTestHost.CreateElevated(E2eIdentities.FrameworkLaptop13()))
        {
            host.HttpHandler.MapPrefix(
                "https://cdn.fwupd.org/",
                (_, _) => Task.FromResult(CreateAutoRedirectedBytesResponse(
                    "https://evil.attacker.example/firmware.xml.gz",
                    E2ePayloads.FrameworkLvfsXmlGz(version: "3.99"))));

            var catCheck = await host.Service.CheckForUpdateAsync();
            Assert.Equal("framework", catCheck.ProviderId);
            Assert.Equal(BiosCheckStatus.Failed, catCheck.Latest.Status);

            const string fwExeUrl = "https://downloads.frame.work/bios-03.05.exe";
            host.HttpHandler.MapPrefix(
                "https://cdn.fwupd.org/",
                (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(E2ePayloads.FrameworkLvfsXmlGz(
                        version: "3.05",
                        location: fwExeUrl,
                        sha256: pkgSha))
                }));
            var goodCheck = await host.Service.CheckForUpdateAsync();
            Assert.Equal(BiosCheckStatus.UpdateAvailable, goodCheck.Latest.Status);

            // 8a. Package auto-redirect to attacker domain
            host.HttpHandler.MapExact(fwExeUrl, (_, _) => Task.FromResult(
                CreateAutoRedirectedBytesResponse("https://evil.attacker.example/malware.exe", pkgBytes)));
            var evilInstall = await host.Service.InstallUpdateAsync(new BiosInstallRequest(
                goodCheck.System, goodCheck.Current, goodCheck.Latest,
                Approved: true, ApprovedBy: "sec-test", SuspendBitLocker: false, AllowReboot: false, VerifyHash: true,
                StagingDirectory: host.StagingDir.Path));
            Assert.False(evilInstall.Succeeded);
            Assert.Empty(host.HostProcessLauncher.Calls);

            // 8b. Package auto-redirect on same Framework domain to wrong extension (.msi instead of .exe)
            host.HttpHandler.MapExact(fwExeUrl, (_, _) => Task.FromResult(
                CreateAutoRedirectedBytesResponse("https://downloads.frame.work/malware.msi", pkgBytes)));
            var wrongExtInstall = await host.Service.InstallUpdateAsync(new BiosInstallRequest(
                goodCheck.System, goodCheck.Current, goodCheck.Latest,
                Approved: true, ApprovedBy: "sec-test", SuspendBitLocker: false, AllowReboot: false, VerifyHash: true,
                StagingDirectory: host.StagingDir.Path));
            Assert.False(wrongExtInstall.Succeeded);
            Assert.Empty(host.HostProcessLauncher.Calls);
        }
    }

    // -------------------------------------------------------------------------
    // T5-SEC-02: Shared HTTP redirect hardening (duplicate Location, RFC 3986 colon, traversal)
    // -------------------------------------------------------------------------

    [Fact]
    public async Task T5_SEC_02_SharedHttpRedirectHardeningBlocksDuplicateLocationColonAndTraversal()
    {
        const string hpCatalogUrl = "https://hpia.hpcloud.hp.com/ref/8b41/8b41_64_11.0.cab";
        const string dellCatalogUrl = "https://downloads.dell.com/catalog/CatalogPC.cab";
        const string lenovoCatalogUrl = "https://download.lenovo.com/catalog/21HM_Win11.xml";

        await using var host = BiosE2eTestHost.CreateElevated(E2eIdentities.HpEliteBook());

        // 1. Duplicate Location headers (valid first, attacker second) -> rejected on HP
        host.HttpHandler.MapExact(hpCatalogUrl, (_, _) =>
        {
            var resp = new HttpResponseMessage(HttpStatusCode.Found);
            resp.Headers.TryAddWithoutValidation("Location", "https://hpia.hpcloud.hp.com/ref/8b41/ok.cab");
            resp.Headers.TryAddWithoutValidation("Location", "https://evil.example/pwn.cab");
            return Task.FromResult(resp);
        });
        host.HttpHandler.MapBytes("https://hpia.hpcloud.hp.com/ref/8b41/ok.cab", E2ePayloads.HpCatalogCab());
        var dupCheck = await host.Service.CheckForUpdateAsync();
        Assert.Equal(BiosCheckStatus.Failed, dupCheck.Latest.Status);

        // 2. RFC 3986 colon / same-scheme relative & protocol-relative redirects -> rejected on HP, Dell, Lenovo
        var badLocations = new[]
        {
            "https:../secret.cab",
            "https:foo.cab",
            "https:/evil.com/pwn.cab",
            "//evil.com/pwn.cab",
            "https://hpia.hpcloud.hp.com/ref/../../secret.cab",
            "../other/secret.cab",
            "/ref/%2e%2e/secret.cab",
            "/ref/%252e%252e/secret.cab",
            "https://hpia.hpcloud.hp.com/ref/%2f/evil.cab",
            "https://hpia.hpcloud.hp.com/ref/%5c/evil.cab",
            "https://hpia.hpcloud.hp.com/ref/%00.cab",
        };

        foreach (var badLoc in badLocations)
        {
            host.HttpHandler.MapRedirect(hpCatalogUrl, badLoc);
            var res = await host.Service.CheckForUpdateAsync();
            Assert.Equal(BiosCheckStatus.Failed, res.Latest.Status);
        }

        // 3. Dell catalog rejects encoded traversal redirect
        host.SystemProbe.Identity = E2eIdentities.DellLatitude();
        host.HttpHandler.MapRedirect(dellCatalogUrl, "https://downloads.dell.com/catalog/%2e%2e/secret.cab");
        var dellRes = await host.Service.CheckForUpdateAsync();
        Assert.Equal(BiosCheckStatus.Failed, dellRes.Latest.Status);

        // 4. Lenovo catalog rejects colon-relative redirect
        host.SystemProbe.Identity = E2eIdentities.LenovoThinkPad();
        host.HttpHandler.MapRedirect(lenovoCatalogUrl, "https:../evil.xml");
        var lenovoRes = await host.Service.CheckForUpdateAsync();
        Assert.Equal(BiosCheckStatus.Failed, lenovoRes.Latest.Status);

        // 5. Package download redirect hardening on HP InstallAsync (duplicate Location + %2e%2e)
        var (pkgBytes, pkgSha) = E2ePayloads.BuildDummyBinary("t5-sec02-hp-pkg");
        const string pkgUrl = "https://ftp.hp.com/pub/softpaq/sp151001-151500/sp151234.exe";
        host.SystemProbe.Identity = E2eIdentities.HpEliteBook();
        host.HttpHandler.MapBytes(hpCatalogUrl, E2ePayloads.HpCatalogCab(url: pkgUrl, sha256: pkgSha));
        var checkOk = await host.Service.CheckForUpdateAsync();
        Assert.Equal(BiosCheckStatus.UpdateAvailable, checkOk.Latest.Status);

        host.HttpHandler.MapRedirect(pkgUrl, "/pub/%2e%2e/secret.exe");
        var badPkgInstall = await host.Service.InstallUpdateAsync(new BiosInstallRequest(
            checkOk.System, checkOk.Current, checkOk.Latest,
            Approved: true, ApprovedBy: "sec-test", SuspendBitLocker: false, AllowReboot: false, VerifyHash: true,
            StagingDirectory: host.StagingDir.Path));
        Assert.False(badPkgInstall.Succeeded);
        Assert.Empty(host.HostProcessLauncher.Calls);
        host.StagingDir.AssertNoPartFilesRemain();
    }

    // -------------------------------------------------------------------------
    // T5-SEC-03: Staging symlink clobber rejected + concurrent identical-URL installs succeed
    // -------------------------------------------------------------------------

    [Fact]
    public async Task T5_SEC_03_StagingSymlinkClobberRejectedAndConcurrentIdenticalUrlDownloadsSucceed()
    {
        var (pkgBytes, pkgSha) = E2ePayloads.BuildDummyBinary("t5-sec03-shared-pkg");
        const string hpCatalogUrl = "https://hpia.hpcloud.hp.com/ref/8b41/8b41_64_11.0.cab";
        const string hpPkgUrl = "https://ftp.hp.com/pub/softpaq/sp151001-151500/sp151234.exe";

        await using var host = BiosE2eTestHost.CreateElevated(E2eIdentities.HpEliteBook());
        host.HttpHandler.MapBytes(hpCatalogUrl, E2ePayloads.HpCatalogCab(url: hpPkgUrl, sha256: pkgSha));
        host.HttpHandler.MapBytes(hpPkgUrl, pkgBytes);

        var check = await host.Service.CheckForUpdateAsync();
        Assert.Equal(BiosCheckStatus.UpdateAvailable, check.Latest.Status);

        var attackRoot = Path.Combine(Path.GetTempPath(), $"rpd-bios-t5-sym-{Guid.NewGuid():N}");
        Directory.CreateDirectory(attackRoot);
        try
        {
            var outsideDir = Path.Combine(attackRoot, "outside");
            Directory.CreateDirectory(outsideDir);
            var victimFile = Path.Combine(outsideDir, "victim.txt");
            await File.WriteAllTextAsync(victimFile, "ORIGINAL_SAFE_CONTENT");

            // 1. Symlinked staging directory -> rejected, nothing written outside
            var symlinkStage = Path.Combine(attackRoot, "stage-link");
            Directory.CreateSymbolicLink(symlinkStage, outsideDir);

            var symDirRes = await host.Service.InstallUpdateAsync(new BiosInstallRequest(
                check.System, check.Current, check.Latest,
                Approved: true, ApprovedBy: "sec-test", SuspendBitLocker: false, AllowReboot: false, VerifyHash: true,
                StagingDirectory: symlinkStage));
            Assert.False(symDirRes.Succeeded);
            Assert.False(File.Exists(Path.Combine(outsideDir, "sp151234.exe")));
            Assert.Empty(host.HostProcessLauncher.Calls);

            // 2. Symlinked ancestor directory with non-existent child staging dir -> rejected
            var childUnderSymlink = Path.Combine(symlinkStage, "nested-stage");
            var symAncRes = await host.Service.InstallUpdateAsync(new BiosInstallRequest(
                check.System, check.Current, check.Latest,
                Approved: true, ApprovedBy: "sec-test", SuspendBitLocker: false, AllowReboot: false, VerifyHash: true,
                StagingDirectory: childUnderSymlink));
            Assert.False(symAncRes.Succeeded);
            Assert.False(Directory.Exists(Path.Combine(outsideDir, "nested-stage")));
            Assert.Empty(host.HostProcessLauncher.Calls);

            // 3. Pre-existing symlink at finalPath (sp151234.exe -> victim.txt) -> rejected, victim untouched
            var realStage = Path.Combine(attackRoot, "real-stage");
            Directory.CreateDirectory(realStage);
            var finalSymlink = Path.Combine(realStage, "sp151234.exe");
            File.CreateSymbolicLink(finalSymlink, victimFile);

            var finalSymRes = await host.Service.InstallUpdateAsync(new BiosInstallRequest(
                check.System, check.Current, check.Latest,
                Approved: true, ApprovedBy: "sec-test", SuspendBitLocker: false, AllowReboot: false, VerifyHash: true,
                StagingDirectory: realStage));
            Assert.False(finalSymRes.Succeeded);
            Assert.Equal("ORIGINAL_SAFE_CONTENT", await File.ReadAllTextAsync(victimFile));
            Assert.Empty(host.HostProcessLauncher.Calls);

            // 4. Pre-existing dangling symlink at finalPath -> rejected
            var danglingStage = Path.Combine(attackRoot, "dangling-stage");
            Directory.CreateDirectory(danglingStage);
            File.CreateSymbolicLink(Path.Combine(danglingStage, "sp151234.exe"), Path.Combine(outsideDir, "does-not-exist.bin"));

            var danglingRes = await host.Service.InstallUpdateAsync(new BiosInstallRequest(
                check.System, check.Current, check.Latest,
                Approved: true, ApprovedBy: "sec-test", SuspendBitLocker: false, AllowReboot: false, VerifyHash: true,
                StagingDirectory: danglingStage));
            Assert.False(danglingRes.Succeeded);
            Assert.False(File.Exists(Path.Combine(outsideDir, "does-not-exist.bin")));
            Assert.Empty(host.HostProcessLauncher.Calls);

            // 5. Concurrent identical-URL installs into the SAME shared staging directory -> both succeed cleanly
            //    Verified across HP, Microsoft Surface, AND Framework with synchronized mid-stream barrier overlap.
            var sharedStage = Path.Combine(attackRoot, "concurrent-stage");
            Directory.CreateDirectory(sharedStage);

            var hpBarrier = new ConcurrentStreamBarrier(2);
            host.HttpHandler.MapExact(hpPkgUrl, (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new BarrierStreamContent(pkgBytes, hpBarrier)
            }));

            var hpReq = new BiosInstallRequest(
                check.System, check.Current, check.Latest,
                Approved: true, ApprovedBy: "sec-test", SuspendBitLocker: false, AllowReboot: false, VerifyHash: true,
                StagingDirectory: sharedStage);

            var hpResults = await Task.WhenAll(
                host.Service.InstallUpdateAsync(hpReq),
                host.Service.InstallUpdateAsync(hpReq));

            Assert.All(hpResults, r =>
            {
                Assert.True(r.Succeeded, r.Message);
                Assert.Equal(BiosInstallStatus.StagedForReboot, r.Status);
            });
            Assert.Empty(Directory.GetFiles(sharedStage, "*.part", SearchOption.AllDirectories));
            Assert.Equal(2, host.HostProcessLauncher.Calls.Count(c => c.ToolName.Equals("sp151234.exe", StringComparison.OrdinalIgnoreCase)));

            // 5b. Microsoft Surface concurrent identical-URL installs into a shared staging directory
            var surfaceStage = Path.Combine(attackRoot, "concurrent-surface");
            Directory.CreateDirectory(surfaceStage);
            var (surfBytes, surfSha) = E2ePayloads.BuildDummyBinary("t5-sec03-surface-msi");
            const string surfUrl = "https://download.microsoft.com/download/surface/SurfacePro9_Win11.msi";

            await using (var surfHost = BiosE2eTestHost.CreateElevated(E2eIdentities.SurfacePro9()))
            {
                surfHost.HttpHandler.MapPrefixText(
                    "https://www.microsoft.com/",
                    E2ePayloads.SurfaceFirmwareJson(version: "18.200.0", downloadUrl: surfUrl, sha256: surfSha),
                    "application/json");
                var surfBarrier = new ConcurrentStreamBarrier(2);
                surfHost.HttpHandler.MapExact(surfUrl, (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new BarrierStreamContent(surfBytes, surfBarrier)
                }));

                var surfCheck = await surfHost.Service.CheckForUpdateAsync();
                Assert.Equal("microsoft", surfCheck.ProviderId);
                Assert.Equal(BiosCheckStatus.UpdateAvailable, surfCheck.Latest.Status);

                var surfReq = new BiosInstallRequest(
                    surfCheck.System, surfCheck.Current, surfCheck.Latest,
                    Approved: true, ApprovedBy: "sec-test", SuspendBitLocker: false, AllowReboot: false, VerifyHash: true,
                    StagingDirectory: surfaceStage);

                var surfResults = await Task.WhenAll(
                    surfHost.Service.InstallUpdateAsync(surfReq),
                    surfHost.Service.InstallUpdateAsync(surfReq));

                Assert.All(surfResults, r =>
                {
                    Assert.True(r.Succeeded, r.Message);
                    Assert.Equal(BiosInstallStatus.StagedForReboot, r.Status);
                });
                Assert.Empty(Directory.GetFiles(surfaceStage, "*.part", SearchOption.AllDirectories));
                Assert.Equal(2, surfHost.HostProcessLauncher.Calls.Count(c => c.ToolName.Equals("msiexec.exe", StringComparison.OrdinalIgnoreCase)));
            }

            // 5c. Framework concurrent identical-URL installs into a shared staging directory
            var fwStage = Path.Combine(attackRoot, "concurrent-framework");
            Directory.CreateDirectory(fwStage);
            var (fwBytes, fwSha) = E2ePayloads.BuildDummyBinary("t5-sec03-framework-exe");
            const string fwUrl = "https://downloads.frame.work/bios-03.05.exe";

            await using (var fwHost = BiosE2eTestHost.CreateElevated(E2eIdentities.FrameworkLaptop13()))
            {
                fwHost.HttpHandler.MapPrefix(
                    "https://cdn.fwupd.org/",
                    (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new ByteArrayContent(E2ePayloads.FrameworkLvfsXmlGz(
                            version: "3.05",
                            location: fwUrl,
                            sha256: fwSha))
                    }));
                var fwBarrier = new ConcurrentStreamBarrier(2);
                fwHost.HttpHandler.MapExact(fwUrl, (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new BarrierStreamContent(fwBytes, fwBarrier)
                }));

                var fwCheck = await fwHost.Service.CheckForUpdateAsync();
                Assert.Equal("framework", fwCheck.ProviderId);
                Assert.Equal(BiosCheckStatus.UpdateAvailable, fwCheck.Latest.Status);

                var fwReq = new BiosInstallRequest(
                    fwCheck.System, fwCheck.Current, fwCheck.Latest,
                    Approved: true, ApprovedBy: "sec-test", SuspendBitLocker: false, AllowReboot: false, VerifyHash: true,
                    StagingDirectory: fwStage);

                var fwResults = await Task.WhenAll(
                    fwHost.Service.InstallUpdateAsync(fwReq),
                    fwHost.Service.InstallUpdateAsync(fwReq));

                Assert.All(fwResults, r =>
                {
                    Assert.True(r.Succeeded, r.Message);
                    Assert.Equal(BiosInstallStatus.StagedForReboot, r.Status);
                });
                Assert.Empty(Directory.GetFiles(fwStage, "*.part", SearchOption.AllDirectories));
                Assert.Equal(2, fwHost.HostProcessLauncher.Calls.Count(c => c.ToolName.Equals("bios-03.05.exe", StringComparison.OrdinalIgnoreCase)));
            }
        }
        finally
        {
            if (Directory.Exists(attackRoot))
                Directory.Delete(attackRoot, recursive: true);
        }
    }

    // -------------------------------------------------------------------------
    // T5-SEC-04: Traversal / bomb CAB NEVER invokes expand.exe on Host OR live elevated Agent
    // -------------------------------------------------------------------------

    [Fact]
    public async Task T5_SEC_04_UnsafeCabTraversalAndBombNeverInvokeExpandExeOnHostOrLiveAgent()
    {
        var xmlBytes = Encoding.UTF8.GetBytes(E2ePayloads.HpCatalogXml(version: "01.14.00"));
        var traversalCab = BuildCabWithCompression([("../../evil.xml", xmlBytes)], typeCompress: 0);
        var traversalLzxCab = BuildCabWithCompression([("../../evil.xml", xmlBytes)], typeCompress: 3);
        var corruptCab = new byte[] { (byte)'M', (byte)'S', (byte)'C', (byte)'F', 0xFF, 0xFF, 0x01, 0x02 };

        // Part A: Host catalog extraction (HP & Dell)
        await using (var host = BiosE2eTestHost.CreateElevated(E2eIdentities.HpEliteBook()))
        {
            host.HostProcessLauncher.OnTool("expand.exe", new ProcessResult(0, "should-never-run", ""));

            foreach (var badCab in new[] { traversalCab, traversalLzxCab, corruptCab })
            {
                host.HttpHandler.MapBytes("https://hpia.hpcloud.hp.com/ref/8b41/8b41_64_11.0.cab", badCab);
                var hpRes = await host.Service.CheckForUpdateAsync();
                Assert.Equal(BiosCheckStatus.Failed, hpRes.Latest.Status);
            }

            host.SystemProbe.Identity = E2eIdentities.DellLatitude();
            foreach (var badCab in new[] { traversalCab, traversalLzxCab, corruptCab })
            {
                host.HttpHandler.MapBytes("https://downloads.dell.com/catalog/CatalogPC.cab", badCab);
                var dellRes = await host.Service.CheckForUpdateAsync();
                Assert.Equal(BiosCheckStatus.Failed, dellRes.Latest.Status);
            }

            Assert.DoesNotContain(host.HostProcessLauncher.Calls,
                c => c.ToolName.Equals("expand.exe", StringComparison.OrdinalIgnoreCase));
        }

        // Part B: Live elevated Agent (Framework CAB capsule over LiveAgentPipeFixture)
        await using (var host = await BiosE2eTestHost.CreateAsync(new BiosE2eHostOptions
        {
            InitialIdentity = E2eIdentities.FrameworkLaptop13(),
            IsProcessElevated = false,
            UseLiveAgentPipe = true,
        }))
        {
            var infBytes = Encoding.UTF8.GetBytes("[Version]\r\nSignature=\"$WINDOWS NT$\"\r\nClass=Firmware\r\n");
            var evilAgentCabs = new[]
            {
                BuildCabWithCompression([("../../evil.inf", infBytes)], typeCompress: 0),
                BuildCabWithCompression([("../../evil.inf", infBytes)], typeCompress: 3),
            };

            const string cabUrl = "https://cdn.fwupd.org/downloads/framework-laptop13-amd7040-3.05.cab";

            foreach (var badCab in evilAgentCabs)
            {
                var sha = E2ePayloads.ComputeSha256Hex(badCab);
                host.HttpHandler.MapPrefix(
                    "https://cdn.fwupd.org/downloads/firmware.xml.gz",
                    (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new ByteArrayContent(E2ePayloads.FrameworkLvfsXmlGz(
                            version: "3.05",
                            location: cabUrl,
                            sha256: sha))
                    }));
                host.HttpHandler.MapBytes(cabUrl, badCab);

                var check = await host.Service.CheckForUpdateAsync();
                Assert.Equal(BiosCheckStatus.UpdateAvailable, check.Latest.Status);

                var install = await host.Service.InstallUpdateAsync(new BiosInstallRequest(
                    check.System, check.Current, check.Latest,
                    Approved: true, ApprovedBy: "sec-test", SuspendBitLocker: false, AllowReboot: false, VerifyHash: true,
                    StagingDirectory: host.StagingDir.Path));

                Assert.False(install.Succeeded);
                Assert.Equal(BiosInstallStatus.Failed, install.Status);
            }

            Assert.NotNull(host.LivePipe);
            Assert.NotNull(host.LivePipe!.Client);

            // Part B2: Direct live named-pipe invocation of AgentBiosOperations.RunBiosInstallerAsync
            // so the Agent-side CAB parser & expand.exe guard are directly exercised (not short-circuited by Host).
            var directAgentAttackCabs = new (string Label, byte[] Bytes)[]
            {
                ("trav-none", BuildCabWithCompression([("../../evil.inf", infBytes)], typeCompress: 0)),
                ("trav-lzx", BuildCabWithCompression([("../../evil.inf", infBytes)], typeCompress: 3)),
                ("lzx-ads", BuildCabWithCompression([("evil.xml:ads", infBytes)], typeCompress: 3)),
                ("lzx-ws-trav", BuildCabWithCompression([(".. /evil.xml", infBytes)], typeCompress: 3)),
                ("lzx-reserved", BuildCabWithCompression([("CON.xml", infBytes)], typeCompress: 3)),
                ("bomb-none", BuildCabBomb([("firmware.inf", infBytes)], typeCompress: 0, declaredFileSize: 0x30000000u)),
                ("bomb-lzx", BuildCabBomb([("firmware.inf", infBytes)], typeCompress: 3, declaredFileSize: 0x30000000u)),
            };

            foreach (var (label, cabBytes) in directAgentAttackCabs)
            {
                var cabPath = Path.Combine(host.StagingDir.Path, $"direct-{label}.cab");
                await File.WriteAllBytesAsync(cabPath, cabBytes);
                var sha = E2ePayloads.ComputeSha256Hex(cabBytes);

                var outcome = await host.LivePipe.Client!.RunBiosInstallerAsync(new BiosAgentInstallRequest(
                    VendorId: "framework",
                    InstallMode: BiosAgentInstallModes.FrameworkCabCapsule,
                    PackagePath: cabPath,
                    ExpectedSha256: sha,
                    AllowReboot: false,
                    InfRelativePath: "firmware.inf",
                    TimeoutMs: 10_000));

                Assert.False(outcome.Allowed, $"Expected Agent to deny '{label}' CAB, but Allowed=true.");
                Assert.False(outcome.Executed, $"Expected Agent not to execute '{label}' CAB, but Executed=true.");
            }

            Assert.Empty(host.LivePipe.AgentProcessLauncher.Calls);
            host.AssertZeroShellInvocations();
        }
    }

    // -------------------------------------------------------------------------
    // T5-SEC-05: SerialNumber redaction parity across all leak paths
    // -------------------------------------------------------------------------

    [Fact]
    public async Task T5_SEC_05_SerialNumberRedactionParityAcrossDownloadErrorsLenovoHttp500AndM3Providers()
    {
        const string secret = "SN-TEST-9999-SECRET";

        // Part A: HP, Dell, Lenovo download failures carrying SerialNumber in HttpRequestException
        var enterpriseVendors = new (BiosSystemIdentity Identity, string CatalogUrl, Func<byte[]> CatalogBytes, string PkgUrl)[]
        {
            (
                E2eIdentities.HpEliteBook(serial: secret),
                "https://hpia.hpcloud.hp.com/ref/8b41/8b41_64_11.0.cab",
                () => E2ePayloads.HpCatalogCab(url: "https://ftp.hp.com/pub/softpaq/sp151234.exe"),
                "https://ftp.hp.com/pub/softpaq/sp151234.exe"
            ),
            (
                E2eIdentities.DellLatitude(serial: secret),
                "https://downloads.dell.com/catalog/CatalogPC.cab",
                () => E2ePayloads.DellCatalogCab(path: "FOLDER1/1/Lat.exe"),
                "https://downloads.dell.com/FOLDER1/1/Lat.exe"
            ),
        };

        foreach (var (identity, catalogUrl, buildCatalog, pkgUrl) in enterpriseVendors)
        {
            await using var host = BiosE2eTestHost.CreateElevated(identity);
            host.HttpHandler.MapBytes(catalogUrl, buildCatalog());
            host.HttpHandler.MapException(pkgUrl, new HttpRequestException($"Upstream rejected {secret}"));

            var check = await host.Service.CheckForUpdateAsync();
            Assert.Equal(BiosCheckStatus.UpdateAvailable, check.Latest.Status);

            var progress = new SyncProgress<BiosInstallProgress>();
            var install = await host.Service.InstallUpdateAsync(new BiosInstallRequest(
                check.System, check.Current, check.Latest,
                Approved: true, ApprovedBy: "sec-test", SuspendBitLocker: false, AllowReboot: false, VerifyHash: true,
                StagingDirectory: host.StagingDir.Path), progress);

            Assert.False(install.Succeeded);
            Assert.DoesNotContain(secret, install.Message ?? "", StringComparison.OrdinalIgnoreCase);
            foreach (var report in progress.Reports)
                Assert.DoesNotContain(secret, report.Detail ?? "", StringComparison.OrdinalIgnoreCase);
            host.AssertNoSerialNumberLeaked(secret, install);
        }

        // Part B: Lenovo download error AND Lenovo descriptor HTTP 500 error containing SerialNumber in descriptor URL
        await using (var host = BiosE2eTestHost.CreateElevated(E2eIdentities.LenovoThinkPad(serial: secret)))
        {
            var descUrlWithSecret = $"https://download.lenovo.com/pccbbs/mobiles/{secret}.xml";
            host.HttpHandler.MapText("https://download.lenovo.com/catalog/21HM_Win11.xml",
                E2ePayloads.LenovoIndexXml(descriptorUrl: descUrlWithSecret));
            host.HttpHandler.MapStatus(descUrlWithSecret, HttpStatusCode.InternalServerError);

            var check500 = await host.Service.CheckForUpdateAsync();
            Assert.Equal(BiosCheckStatus.ProviderUnavailable, check500.Latest.Status);
            Assert.DoesNotContain(secret, check500.Latest.Message ?? "", StringComparison.OrdinalIgnoreCase);

            // Also verify Lenovo download error redaction
            const string safeDescUrl = "https://download.lenovo.com/pccbbs/mobiles/n3xuj12w_2_.xml";
            host.HttpHandler.MapText("https://download.lenovo.com/catalog/21HM_Win11.xml",
                E2ePayloads.LenovoIndexXml(descriptorUrl: safeDescUrl));
            host.HttpHandler.MapText(safeDescUrl, E2ePayloads.LenovoDescriptorXml(fileName: "winuptp.exe"));
            host.HttpHandler.MapException("https://download.lenovo.com/pccbbs/mobiles/winuptp.exe",
                new HttpRequestException($"Gateway blocked {secret}"));

            var checkOk = await host.Service.CheckForUpdateAsync();
            Assert.Equal(BiosCheckStatus.UpdateAvailable, checkOk.Latest.Status);

            var progress = new SyncProgress<BiosInstallProgress>();
            var install = await host.Service.InstallUpdateAsync(new BiosInstallRequest(
                checkOk.System, checkOk.Current, checkOk.Latest,
                Approved: true, ApprovedBy: "sec-test", SuspendBitLocker: false, AllowReboot: false, VerifyHash: true,
                StagingDirectory: host.StagingDir.Path), progress);

            Assert.False(install.Succeeded);
            Assert.DoesNotContain(secret, install.Message ?? "", StringComparison.OrdinalIgnoreCase);
            foreach (var report in progress.Reports)
                Assert.DoesNotContain(secret, report.Detail ?? "", StringComparison.OrdinalIgnoreCase);
            foreach (var entry in host.LoggerFactory.Entries)
                Assert.DoesNotContain(secret, entry.Message, StringComparison.OrdinalIgnoreCase);
        }

        // Part C: ASUS, Acer, MSI GetCurrentVersionAsync redacts Vendor, ReleaseDateRaw, SmbiosRevision
        var m3CurrentIdentities = new[]
        {
            E2eIdentities.AsusRog(serial: secret) with
            {
                CurrentBios = new BiosCurrentInfo(
                    Vendor: $"AMI ({secret})",
                    Version: "1801",
                    ReleaseDate: new DateOnly(2024, 1, 1),
                    ReleaseDateRaw: $"01/01/2024-{secret}",
                    SmbiosRevision: $"5.24-{secret}",
                    FirmwareMode: BiosFirmwareMode.Uefi)
            },
            E2eIdentities.AcerPredator(serial: secret) with
            {
                CurrentBios = new BiosCurrentInfo(
                    Vendor: $"Insyde ({secret})",
                    Version: "1.08",
                    ReleaseDate: new DateOnly(2024, 1, 1),
                    ReleaseDateRaw: $"01/01/2024-{secret}",
                    SmbiosRevision: $"5.24-{secret}",
                    FirmwareMode: BiosFirmwareMode.Uefi)
            },
            E2eIdentities.MsiMag(serial: secret) with
            {
                CurrentBios = new BiosCurrentInfo(
                    Vendor: $"AMI ({secret})",
                    Version: "1.A0",
                    ReleaseDate: new DateOnly(2024, 1, 1),
                    ReleaseDateRaw: $"01/01/2024-{secret}",
                    SmbiosRevision: $"5.24-{secret}",
                    FirmwareMode: BiosFirmwareMode.Uefi)
            },
        };

        await using (var host = BiosE2eTestHost.CreateElevated(m3CurrentIdentities[0]))
        {
            host.HttpHandler.MapPrefixText("https://www.asus.com/", E2ePayloads.AsusBiosJson(), "application/json");
            host.HttpHandler.MapPrefixText("https://www.acer.com/", E2ePayloads.AcerBiosJson(), "application/json");
            host.HttpHandler.MapPrefixText("https://www.msi.com/", E2ePayloads.MsiBiosJson(), "application/json");

            foreach (var id in m3CurrentIdentities)
            {
                host.SystemProbe.Identity = id;
                var check = await host.Service.CheckForUpdateAsync();
                Assert.DoesNotContain(secret, check.Current.Vendor ?? "", StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain(secret, check.Current.ReleaseDateRaw ?? "", StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain(secret, check.Current.SmbiosRevision ?? "", StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain(secret, check.Current.Version ?? "", StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain(secret, check.Current.Family ?? "", StringComparison.OrdinalIgnoreCase);
                host.AssertNoSerialNumberLeaked(secret);
            }
        }

        // Part D: ASUS, Acer, MSI strip SN+123/456 in URL paths when SerialNumber = "SN 123/456"
        const string slashSpaceSerial = "SN 123/456";
        await using (var host = BiosE2eTestHost.CreateElevated(E2eIdentities.AsusRog(serial: slashSpaceSerial)))
        {
            host.HttpHandler.MapPrefixText("https://www.asus.com/",
                E2ePayloads.AsusBiosJson(downloadUrl: "https://dlcdnets.asus.com/pub/SN+123/456/bios.zip"), "application/json");
            var asusCheck = await host.Service.CheckForUpdateAsync();
            Assert.Equal(BiosCheckStatus.UpdateAvailable, asusCheck.Latest.Status);
            Assert.Null(asusCheck.Latest.DownloadUrl);

            host.SystemProbe.Identity = E2eIdentities.AcerPredator(serial: slashSpaceSerial);
            host.HttpHandler.MapPrefixText("https://www.acer.com/",
                E2ePayloads.AcerBiosJson(downloadUrl: "https://global-download.acer.com/SN+123/456/bios.zip"), "application/json");
            var acerCheck = await host.Service.CheckForUpdateAsync();
            Assert.Equal(BiosCheckStatus.UpdateAvailable, acerCheck.Latest.Status);
            Assert.Null(acerCheck.Latest.DownloadUrl);

            host.SystemProbe.Identity = E2eIdentities.MsiMag(serial: slashSpaceSerial);
            host.HttpHandler.MapPrefixText("https://www.msi.com/",
                E2ePayloads.MsiBiosJson(downloadUrl: "https://download.msi.com/SN+123/456/7D75v1G.zip"), "application/json");
            var msiCheck = await host.Service.CheckForUpdateAsync();
            Assert.Equal(BiosCheckStatus.UpdateAvailable, msiCheck.Latest.Status);
            Assert.Null(msiCheck.Latest.DownloadUrl);
        }
    }

    // -------------------------------------------------------------------------
    // T5-SEC-06: Hop-0 traversal URLs rejected with ZERO HTTP requests sent (302 & null RequestMessage bypass blocked)
    // -------------------------------------------------------------------------

    [Fact]
    public async Task T5_SEC_06_Hop0TraversalUrlsRejectedWithZeroOutboundHttpRequestsAcrossEnterpriseProviders()
    {
        var (pkgBytes, pkgSha) = E2ePayloads.BuildDummyBinary("t5-sec06-clean-pkg");
        var traversalPaths = new[]
        {
            "/pub/../../secret.exe",
            "/pub/%2e%2e/secret.exe",
            "/pub/%252e%252e/secret.exe",
            "/pub/%5c/evil.exe",
            "/pub/%00.exe",
        };

        var vendors = new (string VendorId, BiosSystemIdentity Identity, string Host, string CleanUrl)[]
        {
            ("hp", E2eIdentities.HpEliteBook(), "https://ftp.hp.com", "https://ftp.hp.com/pub/softpaq/clean.exe"),
            ("dell", E2eIdentities.DellLatitude(), "https://downloads.dell.com", "https://downloads.dell.com/FOLDER1/1/clean.exe"),
            ("lenovo", E2eIdentities.LenovoThinkPad(), "https://download.lenovo.com", "https://download.lenovo.com/pccbbs/mobiles/clean.exe"),
        };

        foreach (var (vendorId, identity, origin, cleanUrl) in vendors)
        {
            await using var host = BiosE2eTestHost.CreateElevated(identity);
            host.HttpHandler.MapBytes(cleanUrl, pkgBytes);

            foreach (var badPath in traversalPaths)
            {
                var badUrl = origin + badPath;
                var latest = BiosLatestInfo.UpdateAvailable(
                    providerId: vendorId,
                    latestVersion: "9.99.0",
                    downloadUrl: badUrl,
                    sha256: pkgSha,
                    requiresReboot: true);

                // Scenario A: Handler would respond with 302 -> clean.exe if hop 0 were ever sent
                host.HttpHandler.Map(_ => true, (req, _) =>
                {
                    if (string.Equals(req.RequestUri?.AbsoluteUri, cleanUrl, StringComparison.OrdinalIgnoreCase))
                    {
                        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                        {
                            Content = new ByteArrayContent(pkgBytes)
                        });
                    }

                    var redirect = new HttpResponseMessage(HttpStatusCode.Found);
                    redirect.Headers.TryAddWithoutValidation("Location", cleanUrl);
                    return Task.FromResult(redirect);
                });

                var before302 = host.HttpHandler.Requests.Count;
                var res302 = await host.Service.InstallUpdateAsync(new BiosInstallRequest(
                    identity, identity.CurrentBios, latest,
                    Approved: true, ApprovedBy: "sec-test", SuspendBitLocker: false, AllowReboot: false, VerifyHash: true,
                    StagingDirectory: host.StagingDir.Path));

                Assert.False(res302.Succeeded, $"[{vendorId}] Expected 302-backed hop-0 traversal '{badUrl}' to fail.");
                Assert.Equal(before302, host.HttpHandler.Requests.Count);
                Assert.Empty(host.HostProcessLauncher.Calls);

                // Scenario B: Handler would respond with 200 OK and RequestMessage = null if hop 0 were ever sent
                host.HttpHandler.Map(_ => true, (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    RequestMessage = null,
                    Content = new ByteArrayContent(pkgBytes)
                }));

                var beforeNullReq = host.HttpHandler.Requests.Count;
                var resNullReq = await host.Service.InstallUpdateAsync(new BiosInstallRequest(
                    identity, identity.CurrentBios, latest,
                    Approved: true, ApprovedBy: "sec-test", SuspendBitLocker: false, AllowReboot: false, VerifyHash: true,
                    StagingDirectory: host.StagingDir.Path));

                Assert.False(resNullReq.Succeeded, $"[{vendorId}] Expected null-RequestMessage hop-0 traversal '{badUrl}' to fail.");
                Assert.Equal(beforeNullReq, host.HttpHandler.Requests.Count);
                Assert.Empty(host.HostProcessLauncher.Calls);
            }
        }
    }

    // -------------------------------------------------------------------------
    // T5-COR-01: Lenovo U+017F (ſ) 6-permutation sort determinism
    // -------------------------------------------------------------------------

    [Fact]
    public async Task T5_COR_01_LenovoUnicodeLongSSortDeterminismAcrossAllSixPermutations()
    {
        var entries = new (string Version, string Release, string DescUrl, string PkgId, string FileName)[]
        {
            ("X10S", "2025-01-03", "https://download.lenovo.com/pccbbs/mobiles/a.xml", "pkg_a", "a.exe"),
            ("X20\u017F", "2025-01-02", "https://download.lenovo.com/pccbbs/mobiles/b.xml", "pkg_b", "b.exe"),
            ("X30S", "2025-01-01", "https://download.lenovo.com/pccbbs/mobiles/c.xml", "pkg_c", "c.exe"),
        };

        var permutations = new[]
        {
            new[] { 0, 1, 2 },
            new[] { 0, 2, 1 },
            new[] { 1, 0, 2 },
            new[] { 1, 2, 0 },
            new[] { 2, 0, 1 },
            new[] { 2, 1, 0 },
        };

        await using var host = BiosE2eTestHost.CreateElevated(E2eIdentities.LenovoThinkPad(biosVersion: "X05S"));
        foreach (var e in entries)
        {
            host.HttpHandler.MapText(e.DescUrl,
                E2ePayloads.LenovoDescriptorXml(version: e.Version, fileName: e.FileName, releaseDate: e.Release, packageId: e.PkgId));
        }

        string? expectedVersion = null;
        string? expectedDescriptorUrl = null;
        BiosCheckStatus? expectedStatus = null;
        string[]? expectedFetchOrder = null;

        foreach (var perm in permutations)
        {
            var sb = new StringBuilder();
            sb.AppendLine("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
            sb.AppendLine("<packages>");
            foreach (var idx in perm)
            {
                var e = entries[idx];
                sb.AppendLine($"  <package><category>BIOS UEFI</category><location>{e.DescUrl}</location><version>{e.Version}</version><release>{e.Release}</release></package>");
            }
            sb.AppendLine("</packages>");

            var requestsBefore = host.HttpHandler.Requests.Count;
            host.HttpHandler.MapText("https://download.lenovo.com/catalog/21HM_Win11.xml", sb.ToString());
            var check = await host.Service.CheckForUpdateAsync();
            Assert.Equal("lenovo", check.ProviderId);
            Assert.False(string.IsNullOrEmpty(check.Latest.LatestVersion));
            Assert.NotNull(check.Latest.Metadata);
            Assert.True(check.Latest.Metadata!.TryGetValue("descriptorUrl", out var selectedDescUrl));

            var fetchedDescriptors = host.HttpHandler.Requests
                .Skip(requestsBefore)
                .Select(r => r.RequestUri.AbsoluteUri)
                .Where(u => u.Contains("/pccbbs/mobiles/", StringComparison.Ordinal))
                .ToArray();
            Assert.Equal(3, fetchedDescriptors.Length);

            if (expectedVersion is null)
            {
                expectedVersion = check.Latest.LatestVersion;
                expectedDescriptorUrl = selectedDescUrl;
                expectedStatus = check.Latest.Status;
                expectedFetchOrder = fetchedDescriptors;
            }
            else
            {
                Assert.Equal(expectedStatus, check.Latest.Status);
                Assert.Equal(expectedVersion, check.Latest.LatestVersion);
                Assert.Equal(expectedDescriptorUrl, selectedDescUrl);
                Assert.Equal(expectedFetchOrder, fetchedDescriptors);
            }
        }
    }

    // -------------------------------------------------------------------------
    // T5-COR-02: >128-char URL with version dots preserves .exe and installs cleanly
    // -------------------------------------------------------------------------

    [Fact]
    public async Task T5_COR_02_Over128CharVersionDottedPackageUrlPreservesExeAndInstallsCleanly()
    {
        var (pkgBytes, pkgSha) = E2ePayloads.BuildDummyBinary("t5-cor02-long-hp-exe");
        var longFileName = "HP_EliteBook_840_G10_BIOS_v01.14.00_" + new string('a', 100) + ".exe";
        Assert.True(longFileName.Length > 128);
        var longPkgUrl = "https://ftp.hp.com/pub/softpaq/" + longFileName;

        await using var host = BiosE2eTestHost.CreateElevated(E2eIdentities.HpEliteBook());
        host.HttpHandler.MapBytes(
            "https://hpia.hpcloud.hp.com/ref/8b41/8b41_64_11.0.cab",
            E2ePayloads.HpCatalogCab(version: "01.14.00", family: "U74", url: longPkgUrl, sha256: pkgSha));
        host.HttpHandler.MapBytes(longPkgUrl, pkgBytes);

        var check = await host.Service.CheckForUpdateAsync();
        Assert.Equal(BiosCheckStatus.UpdateAvailable, check.Latest.Status);

        var install = await host.Service.InstallUpdateAsync(new BiosInstallRequest(
            check.System, check.Current, check.Latest,
            Approved: true, ApprovedBy: "cor-test", SuspendBitLocker: false, AllowReboot: false, VerifyHash: true,
            StagingDirectory: host.StagingDir.Path));

        Assert.True(install.Succeeded, install.Message);
        Assert.Equal(BiosInstallStatus.StagedForReboot, install.Status);
        var call = Assert.Single(host.HostProcessLauncher.Calls);
        Assert.EndsWith(".exe", call.ToolName, StringComparison.OrdinalIgnoreCase);
        Assert.True(call.ToolName.Length <= 128);
        host.AssertZeroShellInvocations();
    }

    // -------------------------------------------------------------------------
    // T5-COR-03: Lenovo 302 redirect resolves relative <location> and <File><Name> against post-redirect URI
    // -------------------------------------------------------------------------

    [Fact]
    public async Task T5_COR_03_LenovoPostRedirectBaseUriResolvesRelativeDescriptorAndInstaller()
    {
        await using var host = BiosE2eTestHost.CreateElevated(E2eIdentities.LenovoThinkPad());

        // Index redirects to a new directory and lists a relative descriptor location
        host.HttpHandler.MapRedirect(
            "https://download.lenovo.com/catalog/21HM_Win11.xml",
            "https://download.lenovo.com/catalog/v2/21HM_Win11.xml");
        host.HttpHandler.MapText(
            "https://download.lenovo.com/catalog/v2/21HM_Win11.xml",
            E2ePayloads.LenovoIndexXml(descriptorUrl: "old/n32.xml", version: "N3XET52W"));

        // Descriptor redirects from /catalog/v2/old/n32.xml to /pccbbs/newdir/n32.xml and uses relative <File><Name>
        host.HttpHandler.MapRedirect(
            "https://download.lenovo.com/catalog/v2/old/n32.xml",
            "https://download.lenovo.com/pccbbs/newdir/n32.xml");
        host.HttpHandler.MapText(
            "https://download.lenovo.com/pccbbs/newdir/n32.xml",
            E2ePayloads.LenovoDescriptorXml(version: "N3XET52W", fileName: "n32uj20w.exe"));

        var check = await host.Service.CheckForUpdateAsync();
        Assert.Equal("lenovo", check.ProviderId);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, check.Latest.Status);
        Assert.Equal("https://download.lenovo.com/pccbbs/newdir/n32uj20w.exe", check.Latest.DownloadUrl);
    }

    // -------------------------------------------------------------------------
    // T5-COR-04: Cellular Surface LTE models succeed while LTE peripheral packages stay rejected
    // -------------------------------------------------------------------------

    [Fact]
    public async Task T5_COR_04_SurfaceCellularLteModelsSucceedWhileLtePeripheralsStayRejected()
    {
        var lteModels = new[]
        {
            "Surface Pro 9 with LTE Advanced",
            "Surface Pro 7+ with LTE Advanced",
            "Surface Go 3 with LTE Advanced",
        };

        await using var host = BiosE2eTestHost.CreateElevated(E2eIdentities.SurfacePro9());

        foreach (var model in lteModels)
        {
            host.SystemProbe.Identity = E2eIdentities.SurfacePro9(model: model, boardProduct: model);
            host.HttpHandler.MapPrefixText(
                "https://www.microsoft.com/",
                E2ePayloads.SurfaceFirmwareJson(version: "18.200.0", model: model),
                "application/json");

            var check = await host.Service.CheckForUpdateAsync();
            Assert.Equal("microsoft", check.ProviderId);
            Assert.Equal(BiosCheckStatus.UpdateAvailable, check.Latest.Status);
            Assert.Equal("18.200.0", check.Latest.LatestVersion);
        }

        // Standalone LTE peripheral firmware/driver packages remain rejected
        var peripheralTitles = new[]
        {
            "Surface LTE Modem Firmware",
            "Surface Pro 9 LTE Driver",
            "Surface LTE Firmware",
        };

        host.SystemProbe.Identity = E2eIdentities.SurfacePro9();
        foreach (var peripheralTitle in peripheralTitles)
        {
            var json = $$"""
                {
                  "releases": [
                    {
                      "id": "peripheral-lte",
                      "model": "Surface Pro 9",
                      "os": "win11",
                      "category": "Firmware",
                      "title": "{{peripheralTitle}}",
                      "uefiVersion": "18.200.0",
                      "releaseDate": "2025-03-01",
                      "downloadUrl": "https://download.microsoft.com/download/surface/SurfacePro9_LTE.msi"
                    }
                  ]
                }
                """;
            host.HttpHandler.MapPrefixText("https://www.microsoft.com/", json, "application/json");

            var check = await host.Service.CheckForUpdateAsync();
            Assert.Equal("microsoft", check.ProviderId);
            Assert.Equal(BiosCheckStatus.UnsupportedHardware, check.Latest.Status);
            Assert.Null(check.Latest.LatestVersion);
        }
    }

    // -------------------------------------------------------------------------
    // T5-COR-05: Framework JSON poisoned downloadUrl fails closed despite valid fallback url
    // -------------------------------------------------------------------------

    [Fact]
    public async Task T5_COR_05_FrameworkPoisonedExplicitDownloadUrlFailsClosedDespiteValidFallbackUrl()
    {
        var poisonedPayloads = new[]
        {
            """
            {
              "releases": [
                {
                  "model": "Laptop 13 (AMD Ryzen 7040Series)",
                  "version": "3.05",
                  "releaseDate": "2025-02-01",
                  "downloadUrl": "https://evil.com/backdoor.exe",
                  "url": "https://downloads.frame.work/bios-03.05.exe"
                }
              ]
            }
            """,
            """
            {
              "releases": [
                {
                  "model": "Laptop 13 (AMD Ryzen 7040Series)",
                  "version": "3.05",
                  "releaseDate": "2025-02-01",
                  "downloadUrl": "http://downloads.frame.work/bios-03.05.exe",
                  "url": "https://downloads.frame.work/bios-03.05.exe"
                }
              ]
            }
            """,
            """
            {
              "releases": [
                {
                  "model": "Laptop 13 (AMD Ryzen 7040Series)",
                  "version": "3.05",
                  "releaseDate": "2025-02-01",
                  "downloadUrl": 12345,
                  "url": "https://downloads.frame.work/bios-03.05.exe"
                }
              ]
            }
            """,
        };

        await using var host = BiosE2eTestHost.CreateElevated(E2eIdentities.FrameworkLaptop13());

        foreach (var payload in poisonedPayloads)
        {
            host.HttpHandler.MapPrefixText("https://cdn.fwupd.org/", payload, "application/json");
            var check = await host.Service.CheckForUpdateAsync();
            Assert.Equal("framework", check.ProviderId);
            Assert.Equal(BiosCheckStatus.Failed, check.Latest.Status);
            Assert.Null(check.Latest.DownloadUrl);
        }
    }

    // -------------------------------------------------------------------------
    // T5-COR-06: Extensionless package URL where <name>.exe conflicts with directory or symlink fails cleanly
    // -------------------------------------------------------------------------

    [Fact]
    public async Task T5_COR_06_ExtensionlessPackageConflictWithDirectoryOrSymlinkFailsCleanlyAcrossEnterpriseProviders()
    {
        const string secret = "SN-COR06-SECRET-77";
        var (pkgBytes, pkgSha) = E2ePayloads.BuildDummyBinary("t5-cor06-extensionless");

        var vendors = new (string VendorId, BiosSystemIdentity Identity, string ExtensionlessUrl)[]
        {
            ("hp", E2eIdentities.HpEliteBook(serial: secret), "https://ftp.hp.com/pub/softpaq/download_pkg"),
            ("dell", E2eIdentities.DellLatitude(serial: secret), "https://downloads.dell.com/FOLDER12345M/1/download_pkg"),
            ("lenovo", E2eIdentities.LenovoThinkPad(serial: secret), "https://download.lenovo.com/pccbbs/mobiles/download_pkg"),
        };

        var root = Path.Combine(Path.GetTempPath(), $"rpd-bios-t5-cor06-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            var victimFile = Path.Combine(root, "victim.txt");
            await File.WriteAllTextAsync(victimFile, "ORIGINAL-VICTIM");

            foreach (var (vendorId, identity, url) in vendors)
            {
                await using var host = BiosE2eTestHost.CreateElevated(identity);
                host.HttpHandler.MapBytes(url, pkgBytes);

                var latest = BiosLatestInfo.UpdateAvailable(
                    providerId: vendorId,
                    latestVersion: "9.99.0",
                    downloadUrl: url,
                    sha256: pkgSha,
                    requiresReboot: true);

                // Case A: <stagingDir>/download_pkg.exe already exists as a directory
                var dirConflictStage = Path.Combine(root, $"dir-{vendorId}-{secret}");
                Directory.CreateDirectory(Path.Combine(dirConflictStage, "download_pkg.exe"));

                var dirProgress = new SyncProgress<BiosInstallProgress>();
                var dirRes = await host.Service.InstallUpdateAsync(new BiosInstallRequest(
                    identity, identity.CurrentBios, latest,
                    Approved: true, ApprovedBy: "cor-test", SuspendBitLocker: false, AllowReboot: false, VerifyHash: true,
                    StagingDirectory: dirConflictStage), dirProgress);

                Assert.False(dirRes.Succeeded, $"[{vendorId}] Expected directory conflict at download_pkg.exe to fail cleanly.");
                Assert.Equal(BiosInstallStatus.Failed, dirRes.Status);
                Assert.False(File.Exists(Path.Combine(dirConflictStage, "download_pkg")));
                Assert.Empty(host.HostProcessLauncher.Calls);
                Assert.DoesNotContain(secret, dirRes.Message ?? "", StringComparison.OrdinalIgnoreCase);
                foreach (var report in dirProgress.Reports)
                    Assert.DoesNotContain(secret, report.Detail ?? "", StringComparison.OrdinalIgnoreCase);
                host.AssertNoSerialNumberLeaked(secret, dirRes);

                // Case B: <stagingDir>/download_pkg.exe already exists as a symlink to victim.txt
                var symConflictStage = Path.Combine(root, $"sym-{vendorId}-{secret}");
                Directory.CreateDirectory(symConflictStage);
                File.CreateSymbolicLink(Path.Combine(symConflictStage, "download_pkg.exe"), victimFile);

                var symProgress = new SyncProgress<BiosInstallProgress>();
                var symRes = await host.Service.InstallUpdateAsync(new BiosInstallRequest(
                    identity, identity.CurrentBios, latest,
                    Approved: true, ApprovedBy: "cor-test", SuspendBitLocker: false, AllowReboot: false, VerifyHash: true,
                    StagingDirectory: symConflictStage), symProgress);

                Assert.False(symRes.Succeeded, $"[{vendorId}] Expected symlink conflict at download_pkg.exe to fail cleanly.");
                Assert.Equal(BiosInstallStatus.Failed, symRes.Status);
                Assert.False(File.Exists(Path.Combine(symConflictStage, "download_pkg")));
                Assert.Equal("ORIGINAL-VICTIM", await File.ReadAllTextAsync(victimFile));
                Assert.Empty(host.HostProcessLauncher.Calls);
                Assert.DoesNotContain(secret, symRes.Message ?? "", StringComparison.OrdinalIgnoreCase);
                foreach (var report in symProgress.Reports)
                    Assert.DoesNotContain(secret, report.Detail ?? "", StringComparison.OrdinalIgnoreCase);
                host.AssertNoSerialNumberLeaked(secret, symRes);
            }
        }
        finally
        {
            if (Directory.Exists(root))
                Directory.Delete(root, recursive: true);
        }
    }

    // -------------------------------------------------------------------------
    // T5-CON-01: Concurrent Task.WhenAll checks & installs across singleton IBiosUpdateService & all 9 providers
    // -------------------------------------------------------------------------

    [Fact]
    public async Task T5_CON_01_ConcurrentChecksAndInstallsAcrossAllNineProvidersShareSingletonServiceSafely()
    {
        var (hpBytes, hpSha) = E2ePayloads.BuildDummyBinary("t5-con01-hp");
        var (dellBytes, dellSha) = E2ePayloads.BuildDummyBinary("t5-con01-dell");
        var (lenBytes, lenSha) = E2ePayloads.BuildDummyBinary("t5-con01-lenovo");
        var (surfBytes, surfSha) = E2ePayloads.BuildDummyBinary("t5-con01-surface");
        var (fwBytes, fwSha) = E2ePayloads.BuildDummyBinary("t5-con01-framework");
        var wuaUpdateId = Guid.NewGuid();

        const string hpUrl = "https://ftp.hp.com/pub/softpaq/sp151001-151500/HPBIOSUPDREC64.exe";
        const string dellUrl = "https://downloads.dell.com/FOLDER12345M/1/Latitude_5430_1.18.0.exe";
        const string lenUrl = "https://download.lenovo.com/pccbbs/mobiles/winuptp.exe";
        const string surfUrl = "https://download.microsoft.com/download/surface/SurfacePro9_Win11.msi";
        const string fwUrl = "https://downloads.frame.work/bios-03.05.exe";

        var asyncProbe = new AsyncLocalSystemProbe();

        await using var host = BiosE2eTestHost.CreateElevated(
            E2eIdentities.HpEliteBook(),
            configureServices: (services, _, http, _, wua, _) =>
            {
                services.AddSingleton<IBiosSystemProbe>(asyncProbe);

                http.MapBytes("https://hpia.hpcloud.hp.com/ref/8b41/8b41_64_11.0.cab",
                    E2ePayloads.HpCatalogCab(url: hpUrl, sha256: hpSha));
                http.MapBytes(hpUrl, hpBytes);

                http.MapBytes("https://downloads.dell.com/catalog/CatalogPC.cab",
                    E2ePayloads.DellCatalogCab(sha256: dellSha));
                http.MapBytes(dellUrl, dellBytes);

                http.MapText("https://download.lenovo.com/catalog/21HM_Win11.xml", E2ePayloads.LenovoIndexXml());
                http.MapText("https://download.lenovo.com/pccbbs/mobiles/n3xuj12w_2_.xml",
                    E2ePayloads.LenovoDescriptorXml(sha256: lenSha));
                http.MapBytes(lenUrl, lenBytes);

                http.MapPrefixText("https://www.asus.com/", E2ePayloads.AsusBiosJson(), "application/json");
                http.MapPrefixText("https://www.acer.com/", E2ePayloads.AcerBiosJson(), "application/json");
                http.MapPrefixText("https://www.msi.com/", E2ePayloads.MsiBiosJson(), "application/json");

                http.MapPrefixText("https://www.microsoft.com/",
                    E2ePayloads.SurfaceFirmwareJson(downloadUrl: surfUrl, sha256: surfSha), "application/json");
                http.MapBytes(surfUrl, surfBytes);

                http.MapPrefix("https://cdn.fwupd.org/", (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(E2ePayloads.FrameworkLvfsXmlGz(version: "3.05", location: fwUrl, sha256: fwSha))
                }));
                http.MapBytes(fwUrl, fwBytes);

                wua.PendingUpdates =
                [
                    new BiosWuaFirmwareUpdate(
                        UpdateId: wuaUpdateId.ToString("D"),
                        Title: "Generic System Firmware 2.0.0",
                        Version: "2.0.0",
                        ReleaseDate: new DateOnly(2025, 3, 1),
                        SizeBytes: 8_388_608,
                        Severity: BiosUpdateSeverity.Recommended,
                        RebootRequired: true,
                        DriverClass: "Firmware",
                        Categories: ["Drivers", "Firmware"]),
                ];
            });

        var fleet = new (string ExpectedProvider, BiosSystemIdentity Identity, bool CanInstall)[]
        {
            ("hp", E2eIdentities.HpEliteBook(serial: "SN-CONC-HP-0001"), true),
            ("dell", E2eIdentities.DellLatitude(serial: "SN-CONC-DELL-0002"), true),
            ("lenovo", E2eIdentities.LenovoThinkPad(serial: "SN-CONC-LENOVO-0003"), true),
            ("asus", E2eIdentities.AsusRog(serial: "SN-CONC-ASUS-0004"), false),
            ("acer", E2eIdentities.AcerPredator(serial: "SN-CONC-ACER-0005"), false),
            ("msi", E2eIdentities.MsiMag(serial: "SN-CONC-MSI-0006"), false),
            ("microsoft", E2eIdentities.SurfacePro9(serial: "SN-CONC-SURF-0007"), true),
            ("framework", E2eIdentities.FrameworkLaptop13(serial: "SN-CONC-FW-0008"), true),
            ("windows-update", E2eIdentities.GenericPc(serial: "SN-CONC-WUA-0009"), true),
        };

        // Phase 1: Concurrent checks across all 9 providers through the singleton IBiosUpdateService
        var checkTasks = fleet.Select(async item =>
        {
            asyncProbe.Current = item.Identity;
            var check = await host.Service.CheckForUpdateAsync();
            return (item, check);
        }).ToArray();

        var checkResults = await Task.WhenAll(checkTasks);
        foreach (var (item, check) in checkResults)
        {
            Assert.Equal(item.ExpectedProvider, check.ProviderId);
            Assert.Equal(BiosCheckStatus.UpdateAvailable, check.Latest.Status);
            foreach (var other in fleet)
            {
                Assert.DoesNotContain(other.Identity.SerialNumber, check.Latest.Message ?? "", StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain(other.Identity.SerialNumber, check.Current.Vendor ?? "", StringComparison.OrdinalIgnoreCase);
            }
        }

        // Phase 2: Concurrent installs (auto-staging isolation) across all 6 installable providers
        var installTasks = checkResults
            .Where(x => x.item.CanInstall)
            .Select(async x =>
            {
                asyncProbe.Current = x.item.Identity;
                var req = new BiosInstallRequest(
                    x.check.System, x.check.Current, x.check.Latest,
                    Approved: true, ApprovedBy: "conc-admin", SuspendBitLocker: false, AllowReboot: false, VerifyHash: true,
                    StagingDirectory: null);
                var res = await host.Service.InstallUpdateAsync(req);
                return (x.item, res);
            })
            .ToArray();

        var installResults = await Task.WhenAll(installTasks);
        foreach (var (item, res) in installResults)
        {
            Assert.True(res.Succeeded, $"{item.ExpectedProvider}: {res.Message}");
            Assert.Equal(BiosInstallStatus.StagedForReboot, res.Status);
            foreach (var other in fleet)
                host.AssertNoSerialNumberLeaked(other.Identity.SerialNumber, res);
        }

        // Verify all 5 file-based providers used distinct auto-staging directories and cleaned every single one up
        var autoStagingDirs = host.HostProcessLauncher.Calls
            .Select(ExtractStagedDirectoryFromCall)
            .Where(static d => !string.IsNullOrWhiteSpace(d))
            .Select(static d => d!)
            .ToArray();
        Assert.Equal(5, autoStagingDirs.Length);
        Assert.Equal(5, autoStagingDirs.Distinct(StringComparer.OrdinalIgnoreCase).Count());
        foreach (var dir in autoStagingDirs)
            Assert.False(Directory.Exists(dir), $"Auto-staging directory leaked: {dir}");

        host.AssertZeroShellInvocations();
    }

    // -------------------------------------------------------------------------
    // T5-CON-02: Concurrent multi-request serialization & mid-flight cancellation recovery on live AdminPipe
    // -------------------------------------------------------------------------

    [Fact]
    public async Task T5_CON_02_LiveAdminPipeConcurrentRequestsSerializeCleanlyAndMidFlightCancelRecovers()
    {
        // Part A: Concurrent BitLocker + Installer + WUA requests serialize cleanly without frame interleaving
        await using (var fixture = await LiveAgentPipeFixture.StartAsync())
        {
            fixture.AgentProcessLauncher.OnMatch(
                _ => true,
                async (call, ct) =>
                {
                    await Task.Delay(20, ct);
                    return new ProcessResult(0, $"ran:{call.ToolName}", "");
                });

            var (pkgBytes, pkgSha) = E2ePayloads.BuildDummyBinary("t5-con02-pkg");
            var pkgPath = Path.Combine(fixture.AgentStagingDir.Path, "hp-bios.exe");
            await File.WriteAllBytesAsync(pkgPath, pkgBytes);

            var client = fixture.Client!;
            var installReq = new BiosAgentInstallRequest(
                VendorId: "hp",
                InstallMode: BiosAgentInstallModes.HpBiosUpdRec,
                PackagePath: pkgPath,
                ExpectedSha256: pkgSha,
                AllowReboot: false,
                InfRelativePath: null,
                TimeoutMs: 30_000);

            var blTask = client.SuspendBitLockerAsync("C:");
            var instTask = client.RunBiosInstallerAsync(installReq);
            var wuaTask = client.InstallBiosWindowsUpdateAsync(Guid.NewGuid());
            var blTask2 = client.SuspendBitLockerAsync("C:");

            await Task.WhenAll(blTask, instTask, wuaTask, blTask2);

            Assert.True((await blTask).Suspended);
            Assert.True((await blTask2).Suspended);
            var instRes = await instTask;
            Assert.True(instRes.Executed, instRes.Error);
            Assert.True(instRes.Allowed);
            Assert.Equal(0, instRes.ExitCode);
            var wuaRes = await wuaTask;
            Assert.True(wuaRes.Succeeded, wuaRes.Message);
        }

        // Part B: Mid-flight cancellation disposes client cleanly without corrupting subsequent sessions on multi-session server
        var pipeName = $"rpd-bios-t5-cancel-{Guid.NewGuid():N}";
        using var serverCts = new CancellationTokenSource(TimeSpan.FromSeconds(25));
        using var agentStaging = new IsolatedStagingDir("t5-cancel-stage");
        var agentLauncher = new RecordingProcessLauncher("AgentCancel");
        var agentSig = new StubSignatureVerifier(true);
        var agentWua = new FakeWuaApi();
        var agentLogs = new CapturingLoggerFactory();

        var enteredSlowInstall = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseSlowInstall = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        agentLauncher.OnMatch(
            c => c.ToolName.Equals("hp-slow.exe", StringComparison.OrdinalIgnoreCase),
            async (_, ct) =>
            {
                enteredSlowInstall.TrySetResult();
                await releaseSlowInstall.Task.WaitAsync(TimeSpan.FromSeconds(10), ct);
                return new ProcessResult(0, "done", "");
            });

        var biosOps = new AgentBiosOperations(
            launcher: agentLauncher,
            signatureVerifier: agentSig,
            wuaApiFactory: () => agentWua,
            stagingRoot: agentStaging.Path,
            log: agentLogs.CreateLogger<AgentBiosOperations>());

        await using var server = new AdminPipeServer(
            new AdminPipeServerOptions
            {
                PipeName = pipeName,
                ExpectedClientPid = Environment.ProcessId,
                ConnectTimeout = TimeSpan.FromSeconds(10),
            },
            launcher: agentLauncher,
            log: agentLogs.CreateLogger<AdminPipeServer>(),
            biosOperations: biosOps);

        var serverTask = server.RunUntilCancelledAsync(serverCts.Token);
        try
        {
            var (slowBytes, slowSha) = E2ePayloads.BuildDummyBinary("t5-con02-slow");
            var slowPkg = Path.Combine(agentStaging.Path, "hp-slow.exe");
            await File.WriteAllBytesAsync(slowPkg, slowBytes);

            // Session 1: Cancel mid-flight while installer request is in progress
            await using (var client1 = await AdminPipeClient.ConnectAsync(pipeName, TimeSpan.FromSeconds(10), serverCts.Token))
            {
                using var callCts = new CancellationTokenSource();
                var inFlight = client1.RunBiosInstallerAsync(
                    new BiosAgentInstallRequest("hp", BiosAgentInstallModes.HpBiosUpdRec, slowPkg, slowSha, false, null, 30_000),
                    callCts.Token);

                await enteredSlowInstall.Task.WaitAsync(TimeSpan.FromSeconds(5));
                await callCts.CancelAsync();

                await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await inFlight);
                releaseSlowInstall.TrySetResult();
            }

            // Wait for server to finish unwinding the cancelled session and re-open the listening pipe
            var sessionEndedDeadline = DateTime.UtcNow + TimeSpan.FromSeconds(8);
            while (DateTime.UtcNow < sessionEndedDeadline
                   && !agentLogs.Entries.Any(e => e.Message.Contains("Listening again", StringComparison.Ordinal)))
            {
                await Task.Delay(50, serverCts.Token);
            }

            // Session 2: Fresh client connects to the SAME server and completes BIOS requests cleanly
            AdminPipeClient? client2 = null;
            var reconnectDeadline = DateTime.UtcNow + TimeSpan.FromSeconds(10);
            while (client2 is null)
            {
                try
                {
                    client2 = await AdminPipeClient.ConnectAsync(pipeName, TimeSpan.FromSeconds(5), serverCts.Token);
                }
                catch (Exception) when (DateTime.UtcNow < reconnectDeadline)
                {
                    await Task.Delay(100, serverCts.Token);
                }
            }

            await using (client2)
            {
                var bl = await client2.SuspendBitLockerAsync("C:", serverCts.Token);
                Assert.True(bl.Suspended, bl.Error);

                var wua = await client2.InstallBiosWindowsUpdateAsync(Guid.NewGuid(), ct: serverCts.Token);
                Assert.True(wua.Succeeded, wua.Message);
            }
        }
        finally
        {
            releaseSlowInstall.TrySetResult();
            await serverCts.CancelAsync();
            try { await serverTask.WaitAsync(TimeSpan.FromSeconds(5)); } catch { }
        }
    }

    // -------------------------------------------------------------------------
    // T5-ELV-01: ElevationService BIOS bridge forwarding (connected) & AdminRequiredException (disconnected)
    // -------------------------------------------------------------------------

    [Fact]
    public async Task T5_ELV_01_ElevationServiceForwardsBiosBridgeOperationsAndFailsClosedWhenDisconnected()
    {
        var (pkgBytes, pkgSha) = E2ePayloads.BuildDummyBinary("t5-elv01-hp-pkg");
        const string hpCatalogUrl = "https://hpia.hpcloud.hp.com/ref/8b41/8b41_64_11.0.cab";
        const string hpPkgUrl = "https://ftp.hp.com/pub/softpaq/sp151001-151500/HPBIOSUPDREC64.exe";

        // Part A: Disconnected ElevationService throws AdminRequiredException on all 3 BIOS bridge methods
        using (var disconnected = new ElevationService(
            new SessionContext(SessionMode.Local),
            isProcessElevated: () => false))
        {
            IElevatedCommandBridge bridge = disconnected;
            Assert.False(bridge.IsConnected);

            await Assert.ThrowsAsync<AdminRequiredException>(() => bridge.SuspendBitLockerAsync("C:"));
            await Assert.ThrowsAsync<AdminRequiredException>(() => bridge.RunBiosInstallerAsync(
                new BiosAgentInstallRequest("hp", BiosAgentInstallModes.HpBiosUpdRec, "/tmp/fake.exe", pkgSha, false, null, 10_000)));
            await Assert.ThrowsAsync<AdminRequiredException>(() => bridge.InstallBiosWindowsUpdateAsync(Guid.NewGuid()));
        }

        // Part B: Connected ElevationService forwards all 3 BIOS bridge ops to live AdminPipeServer AND routes full E2E install
        await using var pipeFixture = await LiveAgentPipeFixture.StartAsync(connectClient: false);
        using var elevation = new ElevationService(
            new SessionContext(SessionMode.Local),
            isProcessElevated: () => false,
            customConnector: (_, ct) => AdminPipeClient.ConnectAsync(pipeFixture.PipeName, TimeSpan.FromSeconds(10), ct));

        var enabled = await elevation.EnableAdminModeAsync();
        Assert.True(enabled.Success, enabled.Message);
        Assert.True(elevation.IsAdminHelperConnected);
        Assert.True(((IElevatedCommandBridge)elevation).IsConnected);

        // 1. Direct forwarding via ElevationService as IElevatedCommandBridge
        IElevatedCommandBridge connectedBridge = elevation;
        var blResult = await connectedBridge.SuspendBitLockerAsync("C:");
        Assert.True(blResult.Suspended, blResult.Error);
        Assert.Contains(pipeFixture.AgentProcessLauncher.Calls,
            c => c.ToolName.Equals("manage-bde.exe", StringComparison.OrdinalIgnoreCase));

        var directPkg = Path.Combine(pipeFixture.AgentStagingDir.Path, "direct-hp.exe");
        await File.WriteAllBytesAsync(directPkg, pkgBytes);
        var instResult = await connectedBridge.RunBiosInstallerAsync(new BiosAgentInstallRequest(
            "hp", BiosAgentInstallModes.HpBiosUpdRec, directPkg, pkgSha, false, null, 30_000));
        Assert.True(instResult.Executed, instResult.Error);
        Assert.True(instResult.Allowed);
        Assert.Equal(0, instResult.ExitCode);

        var wuaResult = await connectedBridge.InstallBiosWindowsUpdateAsync(Guid.NewGuid());
        Assert.True(wuaResult.Succeeded, wuaResult.Message);
        Assert.Equal(1, pipeFixture.AgentWuaApi.InstalledCount);

        // 2. End-to-end non-elevated host using ElevationService as both IElevationContext & IElevatedCommandBridge
        await using var host = await BiosE2eTestHost.CreateAsync(new BiosE2eHostOptions
        {
            InitialIdentity = E2eIdentities.HpEliteBook(),
            InitialSafetySnapshot = StubSafetyProbe.SafeLaptop(bitLockerActive: true),
            IsProcessElevated = false,
            RegisterElevationContext = false,
            CustomBridge = elevation,
            ConfigureServices = (services, _, http, _, _, _) =>
            {
                services.AddSingleton<IElevationContext>(elevation);
                http.MapBytes(hpCatalogUrl, E2ePayloads.HpCatalogCab(url: hpPkgUrl, sha256: pkgSha));
                http.MapBytes(hpPkgUrl, pkgBytes);
            }
        });

        var check = await host.Service.CheckForUpdateAsync();
        Assert.Equal(BiosCheckStatus.UpdateAvailable, check.Latest.Status);

        var staged = await host.Service.InstallUpdateAsync(new BiosInstallRequest(
            check.System, check.Current, check.Latest,
            Approved: true, ApprovedBy: "elv-admin", SuspendBitLocker: true, AllowReboot: false, VerifyHash: true,
            StagingDirectory: host.StagingDir.Path));

        Assert.True(staged.Succeeded, staged.Message);
        Assert.Equal(BiosInstallStatus.StagedForReboot, staged.Status);
        Assert.True(staged.BitLockerSuspended);
        Assert.Empty(host.HostProcessLauncher.Calls);
        Assert.Contains(pipeFixture.AgentProcessLauncher.Calls,
            c => c.ToolName.Equals("HPBIOSUPDREC64.exe", StringComparison.OrdinalIgnoreCase));
        host.AssertZeroShellInvocations();
    }

    // -------------------------------------------------------------------------
    // T5-DI-01: Repeated ServiceProvider lifecycles respect HttpMessageHandler / HttpClient ownership & leak zero temp dirs
    // -------------------------------------------------------------------------

    [Fact]
    public async Task T5_DI_01_RepeatedServiceProviderLifecyclesRespectHttpOwnershipAndLeakZeroTempDirs()
    {
        var (hpBytes, hpSha) = E2ePayloads.BuildDummyBinary("t5-di01-hp");
        const string hpCatalogUrl = "https://hpia.hpcloud.hp.com/ref/8b41/8b41_64_11.0.cab";
        const string hpPkgUrl = "https://ftp.hp.com/pub/softpaq/sp151001-151500/HPBIOSUPDREC64.exe";

        var observedAutoDirs = new List<string>();

        // Cycle A: Caller-owned HttpMessageHandler survives repeated ServiceProvider build/use/dispose cycles
        using var trackingHandler = new OwnershipTrackingHttpHandler();
        trackingHandler.Inner.MapBytes(hpCatalogUrl, E2ePayloads.HpCatalogCab(url: hpPkgUrl, sha256: hpSha));
        trackingHandler.Inner.MapBytes(hpPkgUrl, hpBytes);

        for (var i = 0; i < 3; i++)
        {
            var launcher = new RecordingProcessLauncher($"DI-A-{i}");
            var services = new ServiceCollection();
            services.AddSingleton<IBiosSystemProbe>(new StubSystemProbe(E2eIdentities.HpEliteBook()));
            services.AddSingleton<IBiosInstallSafetyProbe>(new StubSafetyProbe(StubSafetyProbe.SafeLaptop()));
            services.AddSingleton<HttpMessageHandler>(trackingHandler);
            services.AddSingleton<IBiosSignatureVerifier>(new StubSignatureVerifier(true));
            services.AddSingleton(new SystemCommandRunner(launcher: launcher, isProcessElevated: () => true));
            services.AddBiosUpdates();
            services.AddBuiltInBiosUpdateProviders();

            await using (var sp = services.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true }))
            {
                var svc = sp.GetRequiredService<IBiosUpdateService>();
                var check = await svc.CheckForUpdateAsync();
                Assert.Equal(BiosCheckStatus.UpdateAvailable, check.Latest.Status);

                var res = await svc.InstallUpdateAsync(new BiosInstallRequest(
                    check.System, check.Current, check.Latest,
                    Approved: true, ApprovedBy: "di-test", SuspendBitLocker: false, AllowReboot: false, VerifyHash: true,
                    StagingDirectory: null));
                Assert.True(res.Succeeded, res.Message);
            }

            Assert.Equal(0, trackingHandler.DisposeCount);
            var autoDir = ExtractStagedDirectoryFromCall(Assert.Single(launcher.Calls));
            Assert.False(string.IsNullOrWhiteSpace(autoDir));
            observedAutoDirs.Add(autoDir!);
        }

        // Cycle B: Caller-owned HttpClient survives ServiceProvider disposal and stays usable
        using var callerClient = new HttpClient(trackingHandler, disposeHandler: false);
        for (var i = 0; i < 2; i++)
        {
            var services = new ServiceCollection();
            services.AddSingleton<IBiosSystemProbe>(new StubSystemProbe(E2eIdentities.HpEliteBook()));
            services.AddSingleton<IBiosInstallSafetyProbe>(new StubSafetyProbe(StubSafetyProbe.SafeLaptop()));
            services.AddSingleton(callerClient);
            services.AddBiosUpdates();
            services.AddBuiltInBiosUpdateProviders();

            await using (var sp = services.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true }))
            {
                var svc = sp.GetRequiredService<IBiosUpdateService>();
                var check = await svc.CheckForUpdateAsync();
                Assert.Equal(BiosCheckStatus.UpdateAvailable, check.Latest.Status);
            }

            // Caller-owned HttpClient must NOT have been disposed by ServiceProvider
            using var probeResp = await callerClient.GetAsync(hpCatalogUrl);
            Assert.Equal(HttpStatusCode.OK, probeResp.StatusCode);
            Assert.Equal(0, trackingHandler.DisposeCount);
        }

        // Cycle C: Default shared client path (no HttpClient / HttpMessageHandler registered) survives repeated container lifecycles
        for (var i = 0; i < 3; i++)
        {
            var services = new ServiceCollection();
            services.AddSingleton<IBiosSystemProbe>(new StubSystemProbe(E2eIdentities.GenericPc(firmwareMode: BiosFirmwareMode.Legacy)));
            services.AddSingleton<IBiosInstallSafetyProbe>(new StubSafetyProbe(StubSafetyProbe.SafeLaptop()));
            services.AddBiosUpdates();
            services.AddBuiltInBiosUpdateProviders();

            await using var sp = services.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true });
            var svc = sp.GetRequiredService<IBiosUpdateService>();
            Assert.Equal(9, svc.Providers.Count);
            var check = await svc.CheckForUpdateAsync();
            Assert.Equal(BiosCheckStatus.UnsupportedHardware, check.Latest.Status);
        }

        Assert.Equal(3, observedAutoDirs.Distinct(StringComparer.OrdinalIgnoreCase).Count());
        foreach (var dir in observedAutoDirs)
            Assert.False(Directory.Exists(dir), $"Auto-staging directory leaked across DI lifecycle: {dir}");
    }

    // -------------------------------------------------------------------------
    // Private opaque-box test helpers
    // -------------------------------------------------------------------------

    private static HttpResponseMessage CreateAutoRedirectedBytesResponse(string finalUrl, byte[] bytes)
    {
        var resp = new HttpResponseMessage(HttpStatusCode.OK)
        {
            RequestMessage = new HttpRequestMessage(HttpMethod.Get, new Uri(finalUrl, UriKind.Absolute)),
            Content = new ByteArrayContent(bytes)
        };
        return resp;
    }

    private static HttpResponseMessage CreateAutoRedirectedTextResponse(string finalUrl, string text, string mediaType)
    {
        var resp = new HttpResponseMessage(HttpStatusCode.OK)
        {
            RequestMessage = new HttpRequestMessage(HttpMethod.Get, new Uri(finalUrl, UriKind.Absolute)),
            Content = new StringContent(text, Encoding.UTF8, mediaType)
        };
        return resp;
    }

    private static byte[] BuildCabWithCompression(IReadOnlyList<(string Name, byte[] Data)> entries, ushort typeCompress)
    {
        var raw = E2ePayloads.BuildCab(entries, mszip: false);
        // CFFOLDER starts at offset 36; typeCompress is a uint16 at offset 36 + 6 = 42.
        BinaryPrimitives.WriteUInt16LittleEndian(raw.AsSpan(42, 2), typeCompress);
        return raw;
    }

    private static byte[] BuildCabBomb(IReadOnlyList<(string Name, byte[] Data)> entries, ushort typeCompress, uint declaredFileSize)
    {
        var raw = BuildCabWithCompression(entries, typeCompress);
        // CFHEADER.coffFiles is at offset 16; first CFFILE.cbFile is a uint32 at coffFiles.
        var coffFiles = (int)BinaryPrimitives.ReadUInt32LittleEndian(raw.AsSpan(16, 4));
        BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(coffFiles, 4), declaredFileSize);
        return raw;
    }

    private sealed class ConcurrentStreamBarrier(int participants)
    {
        private int _arrived;
        private readonly TaskCompletionSource _released = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task SignalAndWaitAsync(CancellationToken ct)
        {
            if (Interlocked.Increment(ref _arrived) >= participants)
                _released.TrySetResult();
            return _released.Task.WaitAsync(TimeSpan.FromSeconds(5), ct);
        }
    }

    private sealed class BarrierStreamContent(byte[] data, ConcurrentStreamBarrier barrier) : HttpContent
    {
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
            stream.WriteAsync(data, 0, data.Length);

        protected override Task<Stream> CreateContentReadStreamAsync(CancellationToken cancellationToken) =>
            Task.FromResult<Stream>(new BarrierReadStream(data, barrier));

        protected override bool TryComputeLength(out long length)
        {
            length = data.Length;
            return true;
        }
    }

    private sealed class BarrierReadStream(byte[] data, ConcurrentStreamBarrier barrier) : Stream
    {
        private int _offset;
        private bool _waited;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => data.Length;
        public override long Position { get => _offset; set => throw new NotSupportedException(); }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_offset >= data.Length)
                return 0;

            if (!_waited)
            {
                var firstChunk = Math.Min(buffer.Length, Math.Max(1, data.Length / 2));
                data.AsMemory(_offset, firstChunk).CopyTo(buffer);
                _offset += firstChunk;
                _waited = true;
                return firstChunk;
            }

            if (_offset < data.Length)
            {
                await barrier.SignalAndWaitAsync(cancellationToken).ConfigureAwait(false);
                var remaining = Math.Min(buffer.Length, data.Length - _offset);
                data.AsMemory(_offset, remaining).CopyTo(buffer);
                _offset += remaining;
                return remaining;
            }

            return 0;
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private static string? ExtractStagedDirectoryFromCall(RecordedProcessCall call)
    {
        // msiexec.exe /i <path-to-msi> /qn /norestart
        if (call.ToolName.Equals("msiexec.exe", StringComparison.OrdinalIgnoreCase))
        {
            for (var i = 0; i < call.Arguments.Count - 1; i++)
            {
                if (call.Arguments[i].Equals("/i", StringComparison.OrdinalIgnoreCase))
                    return Path.GetDirectoryName(call.Arguments[i + 1]);
            }
        }

        return Path.GetDirectoryName(call.FileName);
    }

    private sealed class AsyncLocalSystemProbe : IBiosSystemProbe
    {
        private readonly AsyncLocal<BiosSystemIdentity?> _current = new();

        public BiosSystemIdentity Current
        {
            get => _current.Value ?? E2eIdentities.GenericPc();
            set => _current.Value = value;
        }

        public Task<BiosSystemIdentity> ProbeAsync(CancellationToken ct = default)
        {
            ct.ThrowIfCancellationRequested();
            return Task.FromResult(Current);
        }
    }

    private sealed class OwnershipTrackingHttpHandler : HttpMessageHandler
    {
        private int _disposeCount;

        public ScriptedHttpHandler Inner { get; } = new();
        public int DisposeCount => Volatile.Read(ref _disposeCount);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            ObjectDisposedException.ThrowIf(DisposeCount > 0, this);
            using var invoker = new HttpMessageInvoker(Inner, disposeHandler: false);
            return invoker.SendAsync(request, cancellationToken);
        }

        protected override void Dispose(bool disposing)
        {
            Interlocked.Increment(ref _disposeCount);
            if (disposing)
                Inner.Dispose();
            base.Dispose(disposing);
        }
    }
}
