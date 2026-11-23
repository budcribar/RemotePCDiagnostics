using System.Net;
using RemotePCDiagnostics.Core.Bios;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests.Bios.E2E;

/// <summary>
/// Tier 3 E2E Cross-Feature Combinations — all 11 pairwise interaction matrices (E2E-T3-01..11).
/// </summary>
[Trait("Tier", "3")]
public sealed class BiosE2eTier3CrossFeatureCombinationTests
{
    // =========================================================================
    // E2E-T3-01: DI Priority Resolution × Target.ProviderId Override × FirmwareMode
    // =========================================================================

    public static TheoryData<string, BiosSystemIdentity, bool> T3_01_Cases => new()
    {
        { "hp", E2eIdentities.HpEliteBook(firmwareMode: BiosFirmwareMode.Uefi), true },
        { "hp", E2eIdentities.HpEliteBook(firmwareMode: BiosFirmwareMode.Legacy), false },
        { "dell", E2eIdentities.DellLatitude(firmwareMode: BiosFirmwareMode.Uefi), true },
        { "dell", E2eIdentities.DellLatitude(firmwareMode: BiosFirmwareMode.Legacy), false },
        { "lenovo", E2eIdentities.LenovoThinkPad(firmwareMode: BiosFirmwareMode.Uefi), true },
        { "lenovo", E2eIdentities.LenovoThinkPad(firmwareMode: BiosFirmwareMode.Legacy), false },
        { "asus", E2eIdentities.AsusRog(firmwareMode: BiosFirmwareMode.Uefi), true },
        { "asus", E2eIdentities.AsusRog(firmwareMode: BiosFirmwareMode.Legacy), false }
    };

    [Theory]
    [MemberData(nameof(T3_01_Cases))]
    public async Task E2E_T3_01_DiPriorityResolutionByTargetProviderIdOverrideAndFirmwareMode(
        string expectedOemVendor, BiosSystemIdentity identity, bool expectWuaOverride)
    {
        await using var host = BiosE2eTestHost.CreateElevated(identity);

        // Normal resolution ALWAYS picks Priority-100 OEM provider
        var resolved = host.Service.ResolveProvider(identity);
        Assert.NotNull(resolved);
        Assert.Equal(expectedOemVendor, resolved.VendorId);
        Assert.Equal(100, resolved.Priority);

        // Explicit Target.ProviderId = "windows-update" overrides IFF FirmwareMode == Uefi
        var wuaGuid = Guid.NewGuid();
        var wuaTarget = BiosLatestInfo.UpdateAvailable("windows-update", "2.0", packageId: wuaGuid.ToString("D"));
        var res = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, wuaTarget, Approved: true, SuspendBitLocker: false, AllowReboot: false));

        if (expectWuaOverride)
        {
            Assert.True(res.Succeeded, res.Message);
            Assert.Equal([wuaGuid], host.WindowsUpdateClient.InstalledUpdateIds);
        }
        else
        {
            Assert.False(res.Succeeded);
            Assert.Empty(host.WindowsUpdateClient.InstalledUpdateIds);
            if (expectedOemVendor == "asus")
                Assert.Equal(BiosInstallStatus.Unsupported, res.Status);
            else
                Assert.Equal(BiosInstallStatus.Failed, res.Status); // OEM rejects WUA target without download URL
        }
    }

    // =========================================================================
    // E2E-T3-02: BiosUpdateService Safety Gate × All 6 Installable Providers
    // =========================================================================

    public static TheoryData<string, BiosSystemIdentity, string?, string?, string, BiosSafetySnapshot, bool> T3_02_Cases => new()
    {
        { "hp", E2eIdentities.HpEliteBook(), "https://ftp.hp.com/sp.exe", null, "LowBattery", new BiosSafetySnapshot(true, true, 15, false, false, true, false), true },
        { "dell", E2eIdentities.DellLatitude(), "https://downloads.dell.com/a.exe", null, "OffAc", new BiosSafetySnapshot(false, true, 80, false, false, true, false), true },
        { "lenovo", E2eIdentities.LenovoThinkPad(), "https://download.lenovo.com/winuptp.exe", null, "PendingReboot", new BiosSafetySnapshot(true, true, 90, false, false, true, true), true },
        { "microsoft", E2eIdentities.SurfacePro9(), "https://download.microsoft.com/s.msi", null, "NoElevation", new BiosSafetySnapshot(true, true, 90, false, false, false, false), true },
        { "framework", E2eIdentities.FrameworkLaptop13(), "https://cdn.fwupd.org/f.cab", null, "BitLockerBlocked", new BiosSafetySnapshot(true, true, 90, true, false, true, false), false },
        { "windows-update", E2eIdentities.GenericPc(firmwareMode: BiosFirmwareMode.Uefi), null, "748279c7-4309-452c-8b30-e02ec52e498f", "NoElevation", new BiosSafetySnapshot(true, true, 90, false, false, false, false), true },
        { "windows-update", E2eIdentities.GenericPc(firmwareMode: BiosFirmwareMode.Uefi), null, "748279c7-4309-452c-8b30-e02ec52e498f", "LowBattery", new BiosSafetySnapshot(true, true, 20, false, false, true, false), true }
    };

    [Theory]
    [MemberData(nameof(T3_02_Cases))]
    public async Task E2E_T3_02_SafetyGateShortCircuitsAcrossAllSixInstallableProvidersAndBlockers(
        string vendorId, BiosSystemIdentity identity, string? url, string? pkgId, string blocker, BiosSafetySnapshot snap, bool suspendBitLocker)
    {
        Assert.False(string.IsNullOrWhiteSpace(blocker));
        await using var host = BiosE2eTestHost.CreateElevated(identity, snap);
        var target = BiosLatestInfo.UpdateAvailable(vendorId, "9.9.9", packageId: pkgId, downloadUrl: url);

        var res = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: suspendBitLocker, StagingDirectory: host.StagingDir.Path));

        Assert.False(res.Succeeded);
        Assert.Equal(BiosInstallStatus.BlockedByPrerequisites, res.Status);
        Assert.Empty(host.HttpHandler.Requests);
        Assert.Empty(host.HostProcessLauncher.Calls);
        Assert.Empty(host.WindowsUpdateClient.InstalledUpdateIds);
    }

    // =========================================================================
    // E2E-T3-03: GetCurrentVersionAsync Normalization × BiosVersionComparer × Catalog Comparison
    // =========================================================================

    [Theory]
    [InlineData("hp", "U74 Ver. 01.09.00", "01.14.00", BiosCheckStatus.UpdateAvailable)]
    [InlineData("hp", "U74 Ver. 01.09.00", "01.09.00", BiosCheckStatus.UpToDate)]
    [InlineData("lenovo", "N3XET48W (1.23 )", "N3XET52W", BiosCheckStatus.UpdateAvailable)]
    [InlineData("lenovo", "N3XET48W (1.23 )", "N3XET48W", BiosCheckStatus.UpToDate)]
    public async Task E2E_T3_03_GetCurrentVersionNormalizationFeedsBiosVersionComparerAndCatalogComparison(
        string vendorId, string rawCurrentVersion, string catalogVersion, BiosCheckStatus expectedStatus)
    {
        var identity = vendorId == "hp"
            ? E2eIdentities.HpEliteBook(biosVersion: rawCurrentVersion)
            : E2eIdentities.LenovoThinkPad(biosVersion: rawCurrentVersion);

        await using var host = BiosE2eTestHost.CreateElevated(identity);
        if (vendorId == "hp")
        {
            host.HttpHandler.MapText("https://hpia.hpcloud.hp.com/ref/8b41/8b41_64_11.0.cab",
                E2ePayloads.HpCatalogXml(version: catalogVersion, family: "U74"));
        }
        else
        {
            host.HttpHandler.MapText("https://download.lenovo.com/catalog/21HM_Win11.xml", E2ePayloads.LenovoIndexXml(version: catalogVersion));
            host.HttpHandler.MapText("https://download.lenovo.com/pccbbs/mobiles/n3xuj12w_2_.xml", E2ePayloads.LenovoDescriptorXml(version: catalogVersion));
        }

        var outcome = await host.Service.CheckForUpdateAsync();
        Assert.Equal(vendorId, outcome.ProviderId);
        Assert.Equal(expectedStatus, outcome.Latest.Status);
        Assert.NotEqual(rawCurrentVersion, outcome.Current.Version); // Normalized by GetCurrentVersionAsync
    }

    // =========================================================================
    // E2E-T3-04: SuspendBitLocker × VerifyHash/Sha256 × Authenticode × AllowReboot Matrix
    // =========================================================================

    [Theory]
    [InlineData(true, "absent", true, false, true, true, new[] { "-s", "-r" })]
    [InlineData(true, "absent", false, false, false, false, new string[0])]
    [InlineData(false, "valid", true, true, true, false, new[] { "-s" })]
    [InlineData(true, "mismatch", true, false, false, false, new string[0])]
    public async Task E2E_T3_04_SuspendBitLockerByVerifyHashByAuthenticodeByAllowRebootMatrix(
        bool suspendBitLocker, string hashMode, bool authenticodeValid, bool allowReboot,
        bool expectedSucceeded, bool expectedBitLockerSuspended, string[] expectedFlasherArgs)
    {
        var identity = E2eIdentities.HpEliteBook();
        var (pkgBytes, validSha) = E2ePayloads.BuildDummyBinary($"t304-{hashMode}-{allowReboot}");
        const string url = "https://ftp.hp.com/pub/softpaq/HPBIOSUPDREC64.exe";

        string? targetSha = hashMode switch
        {
            "valid" => validSha,
            "mismatch" => new string('0', 64),
            _ => null
        };

        await using var host = BiosE2eTestHost.CreateElevated(identity, StubSafetyProbe.SafeLaptop(bitLockerActive: suspendBitLocker));
        host.SignatureVerifier.Predicate = _ => authenticodeValid;
        host.HttpHandler.MapBytes(url, pkgBytes);

        var target = BiosLatestInfo.UpdateAvailable("hp", "01.14.00", downloadUrl: url, sha256: targetSha);
        var result = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: suspendBitLocker, AllowReboot: allowReboot, VerifyHash: true, StagingDirectory: host.StagingDir.Path));

        Assert.Equal(expectedSucceeded, result.Succeeded);
        Assert.Equal(expectedBitLockerSuspended, result.BitLockerSuspended);

        if (expectedSucceeded)
        {
            Assert.Equal(BiosInstallStatus.StagedForReboot, result.Status);
            var flasher = Assert.Single(host.HostProcessLauncher.Calls, c => c.ToolName.Equals("HPBIOSUPDREC64.exe", StringComparison.OrdinalIgnoreCase));
            Assert.Equal(expectedFlasherArgs, flasher.Arguments);
        }
        else
        {
            Assert.Equal(BiosInstallStatus.Failed, result.Status);
            // Must fail BEFORE manage-bde.exe and BEFORE installer, deleting unverified file
            Assert.Empty(host.HostProcessLauncher.Calls);
            host.StagingDir.AssertEmpty();
        }
    }

    // =========================================================================
    // E2E-T3-05: Custom StagingDirectory × Download/Hash/Authenticode Failure × Cleanup
    // =========================================================================

    [Fact]
    public async Task E2E_T3_05_CustomStagingDirectoryWithDownloadHashAuthenticodeFailureCleanup()
    {
        var identity = E2eIdentities.DellLatitude();
        var (pkgBytes, validSha) = E2ePayloads.BuildDummyBinary("t305-staging");
        const string url = "https://downloads.dell.com/FOLDER1/Latitude_1.18.0.exe";

        // 1. Success writes inside custom StagingDirectory
        using var successDir = new IsolatedStagingDir("t305-ok");
        await using (var hostOk = BiosE2eTestHost.CreateElevated(identity))
        {
            hostOk.HttpHandler.MapBytes(url, pkgBytes);
            var res = await hostOk.Service.InstallUpdateAsync(
                new BiosInstallRequest(identity, identity.CurrentBios,
                    BiosLatestInfo.UpdateAvailable("dell", "1.18.0", downloadUrl: url, sha256: validSha),
                    Approved: true, SuspendBitLocker: false, AllowReboot: false, VerifyHash: true, StagingDirectory: successDir.Path));
            Assert.True(res.Succeeded);
            var call = Assert.Single(hostOk.HostProcessLauncher.Calls);
            Assert.StartsWith(successDir.Path, call.FileName, StringComparison.OrdinalIgnoreCase);
            successDir.AssertNoPartFilesRemain();
        }

        // 2. SHA-256 mismatch leaves 0 .part and 0 binaries in custom StagingDirectory
        using var badHashDir = new IsolatedStagingDir("t305-badhash");
        await using (var hostBadHash = BiosE2eTestHost.CreateElevated(identity))
        {
            hostBadHash.HttpHandler.MapBytes(url, pkgBytes);
            var res = await hostBadHash.Service.InstallUpdateAsync(
                new BiosInstallRequest(identity, identity.CurrentBios,
                    BiosLatestInfo.UpdateAvailable("dell", "1.18.0", downloadUrl: url, sha256: new string('f', 64)),
                    Approved: true, SuspendBitLocker: false, AllowReboot: false, VerifyHash: true, StagingDirectory: badHashDir.Path));
            Assert.False(res.Succeeded);
            badHashDir.AssertEmpty();
        }

        // 3. Authenticode failure leaves 0 .part and 0 binaries in custom StagingDirectory
        using var badSigDir = new IsolatedStagingDir("t305-badsig");
        await using (var hostBadSig = BiosE2eTestHost.CreateElevated(identity))
        {
            hostBadSig.SignatureVerifier.Predicate = _ => false;
            hostBadSig.HttpHandler.MapBytes(url, pkgBytes);
            var res = await hostBadSig.Service.InstallUpdateAsync(
                new BiosInstallRequest(identity, identity.CurrentBios,
                    BiosLatestInfo.UpdateAvailable("dell", "1.18.0", downloadUrl: url, sha256: null),
                    Approved: true, SuspendBitLocker: false, AllowReboot: false, VerifyHash: true, StagingDirectory: badSigDir.Path));
            Assert.False(res.Succeeded);
            badSigDir.AssertEmpty();
        }

        // 4. Mid-stream HTTP abort leaves 0 .part and 0 binaries in custom StagingDirectory
        using var abortDir = new IsolatedStagingDir("t305-abort");
        await using (var hostAbort = BiosE2eTestHost.CreateElevated(identity))
        {
            hostAbort.HttpHandler.MapExact(url, (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StreamContent(new FailingMidStream())
            }));
            var res = await hostAbort.Service.InstallUpdateAsync(
                new BiosInstallRequest(identity, identity.CurrentBios,
                    BiosLatestInfo.UpdateAvailable("dell", "1.18.0", downloadUrl: url, sha256: validSha),
                    Approved: true, SuspendBitLocker: false, AllowReboot: false, VerifyHash: true, StagingDirectory: abortDir.Path));
            Assert.False(res.Succeeded);
            Assert.Single(hostAbort.HttpHandler.Requests);
            Assert.Contains("I/O error", res.Message ?? "", StringComparison.OrdinalIgnoreCase);
            abortDir.AssertEmpty();
        }
    }

    // =========================================================================
    // E2E-T3-06: All 6 Installable Providers × AllowReboot × SuspendBitLocker × ExitCode
    // =========================================================================

    public static TheoryData<string, bool, bool, int, BiosInstallStatus, string[]> T3_06_Cases => new()
    {
        { "hp", false, true, 0, BiosInstallStatus.StagedForReboot, ["-s", "-r"] },
        { "hp", true, false, 3010, BiosInstallStatus.StagedForReboot, ["-s"] },
        { "hp", false, false, 99, BiosInstallStatus.Failed, ["-s", "-r"] },
        { "dell", false, true, 0, BiosInstallStatus.StagedForReboot, ["/s"] },
        { "dell", true, false, 3010, BiosInstallStatus.StagedForReboot, ["/s", "/r"] },
        { "lenovo", false, true, 0, BiosInstallStatus.StagedForReboot, ["-s"] },
        { "lenovo", true, false, 3010, BiosInstallStatus.StagedForReboot, ["-s", "-r"] },
        { "microsoft", false, true, 3010, BiosInstallStatus.StagedForReboot, ["/i", "/qn", "/norestart"] },
        { "microsoft", true, false, 1603, BiosInstallStatus.Failed, ["/i", "/qn"] },
        { "framework", false, true, 0, BiosInstallStatus.StagedForReboot, ["/silent", "/norestart"] },
        { "framework", true, false, 3010, BiosInstallStatus.StagedForReboot, ["/silent"] },
        { "windows-update", false, true, 2, BiosInstallStatus.StagedForReboot, [] },
        { "windows-update", true, false, 200, BiosInstallStatus.Completed, [] }, // 200 sentinel -> ResultCode=2, RebootRequired=false
        { "windows-update", false, false, 4, BiosInstallStatus.Failed, [] }
    };

    [Theory]
    [MemberData(nameof(T3_06_Cases))]
    public async Task E2E_T3_06_SixInstallableProvidersByAllowRebootBySuspendBitLockerByExitCodeMatrix(
        string vendorId, bool allowReboot, bool suspendBitLocker, int exitCodeOrSentinel,
        BiosInstallStatus expectedStatus, string[] expectedArgTokens)
    {
        var (identity, url, toolName) = vendorId switch
        {
            "hp" => (E2eIdentities.HpEliteBook(), "https://ftp.hp.com/pub/softpaq/HPBIOSUPDREC64.exe", "HPBIOSUPDREC64.exe"),
            "dell" => (E2eIdentities.DellLatitude(), "https://downloads.dell.com/FOLDER1/dell.exe", "dell.exe"),
            "lenovo" => (E2eIdentities.LenovoThinkPad(), "https://download.lenovo.com/pccbbs/winuptp.exe", "winuptp.exe"),
            "microsoft" => (E2eIdentities.SurfacePro9(), "https://download.microsoft.com/surface/SurfacePro9.msi", "msiexec.exe"),
            "framework" => (E2eIdentities.FrameworkLaptop13(), "https://downloads.frame.work/bios/fw.exe", "fw.exe"),
            _ => (E2eIdentities.GenericPc(firmwareMode: BiosFirmwareMode.Uefi), (string?)null, "")
        };

        await using var host = BiosE2eTestHost.CreateElevated(identity, StubSafetyProbe.SafeLaptop(bitLockerActive: suspendBitLocker));
        string? sha = null;
        string? pkgId = null;

        if (url is not null)
        {
            var (bytes, hash) = E2ePayloads.BuildDummyBinary($"t306-{vendorId}-{allowReboot}-{exitCodeOrSentinel}");
            sha = hash;
            host.HttpHandler.MapBytes(url, bytes);
            host.HostProcessLauncher.OnTool(toolName, new ProcessResult(exitCodeOrSentinel, "", ""));
        }
        else
        {
            pkgId = Guid.NewGuid().ToString("D");
            host.WindowsUpdateClient.InstallHandler = (_, _) => exitCodeOrSentinel switch
            {
                2 => Task.FromResult(new BiosWuaInstallOutcome(true, 2, true, "Staged")),
                200 => Task.FromResult(new BiosWuaInstallOutcome(true, 2, false, "Completed")),
                _ => Task.FromResult(new BiosWuaInstallOutcome(false, exitCodeOrSentinel, false, "Failed"))
            };
        }

        var target = BiosLatestInfo.UpdateAvailable(vendorId, "9.9.9", packageId: pkgId, downloadUrl: url, sha256: sha);
        var res = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: suspendBitLocker, AllowReboot: allowReboot, VerifyHash: true, StagingDirectory: host.StagingDir.Path));

        Assert.Equal(expectedStatus, res.Status);
        Assert.Equal(suspendBitLocker, res.BitLockerSuspended);

        var bdeCalls = host.HostProcessLauncher.Calls.Where(c => c.ToolName.Equals("manage-bde.exe", StringComparison.OrdinalIgnoreCase)).ToArray();
        Assert.Equal(suspendBitLocker ? 1 : 0, bdeCalls.Length);

        if (toolName.Length > 0)
        {
            var installerCall = Assert.Single(host.HostProcessLauncher.Calls, c => c.ToolName.Equals(toolName, StringComparison.OrdinalIgnoreCase));
            foreach (var token in expectedArgTokens)
                Assert.Contains(token, installerCall.Arguments, StringComparer.OrdinalIgnoreCase);

            // Explicit absence of opposite-polarity reboot flags across all OEM providers
            switch (vendorId)
            {
                case "hp" when allowReboot:
                    Assert.DoesNotContain("-r", installerCall.Arguments, StringComparer.OrdinalIgnoreCase);
                    break;
                case "dell" when !allowReboot:
                    Assert.DoesNotContain("/r", installerCall.Arguments, StringComparer.OrdinalIgnoreCase);
                    break;
                case "lenovo" when !allowReboot:
                    Assert.DoesNotContain("-r", installerCall.Arguments, StringComparer.OrdinalIgnoreCase);
                    break;
                case "microsoft" when allowReboot:
                    Assert.DoesNotContain("/norestart", installerCall.Arguments, StringComparer.OrdinalIgnoreCase);
                    break;
                case "framework" when allowReboot:
                    Assert.DoesNotContain("/norestart", installerCall.Arguments, StringComparer.OrdinalIgnoreCase);
                    break;
            }
        }
    }

    // =========================================================================
    // E2E-T3-07: All 9 Providers × Failure Mode × SerialNumber Redaction
    // =========================================================================

    public static TheoryData<string, BiosSystemIdentity, string> T3_07_Cases => new()
    {
        { "hp", E2eIdentities.HpEliteBook(), "404" },
        { "dell", E2eIdentities.DellLatitude(), "503" },
        { "lenovo", E2eIdentities.LenovoThinkPad(), "429" },
        { "asus", E2eIdentities.AsusRog(), "offline" },
        { "acer", E2eIdentities.AcerPredator(), "malformed" },
        { "msi", E2eIdentities.MsiMag(), "cancel" },
        { "microsoft", E2eIdentities.SurfacePro9(), "503" },
        { "framework", E2eIdentities.FrameworkLaptop13(), "malformed" },
        { "windows-update", E2eIdentities.GenericPc(firmwareMode: BiosFirmwareMode.Uefi), "wua-fail" }
    };

    [Theory]
    [MemberData(nameof(T3_07_Cases))]
    public async Task E2E_T3_07_AllNineProvidersByFailureModeWithSerialNumberRedaction(
        string vendorId, BiosSystemIdentity identity, string failureMode)
    {
        await using var host = BiosE2eTestHost.CreateElevated(identity);
        using var cts = new CancellationTokenSource();

        switch (failureMode)
        {
            case "404":
                host.HttpHandler.Map(_ => true, (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound)));
                break;
            case "429":
                host.HttpHandler.Map(_ => true, (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.TooManyRequests)));
                break;
            case "503":
                host.HttpHandler.Map(_ => true, (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)));
                break;
            case "offline":
                host.HttpHandler.Map(_ => true, (_, _) => Task.FromException<HttpResponseMessage>(new HttpRequestException("Offline")));
                break;
            case "malformed":
                host.HttpHandler.Map(_ => true, (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("<<<NOT-VALID-PAYLOAD>>>")
                }));
                break;
            case "cancel":
                cts.Cancel();
                break;
            case "wua-fail":
                host.WindowsUpdateClient.SearchException = new InvalidOperationException("WUA search unavailable");
                break;
        }

        if (failureMode == "cancel")
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => host.Service.CheckForUpdateAsync(cts.Token));
        }
        else
        {
            var outcome = await host.Service.CheckForUpdateAsync();
            Assert.Equal(vendorId, outcome.ProviderId);
            var expectedStatus = failureMode switch
            {
                "404" => BiosCheckStatus.UnsupportedHardware,
                "429" or "503" or "wua-fail" => BiosCheckStatus.ProviderUnavailable,
                "offline" => BiosCheckStatus.Offline,
                _ => BiosCheckStatus.Failed
            };
            Assert.Equal(expectedStatus, outcome.Latest.Status);
            Assert.DoesNotContain(BiosE2eTestHost.CanarySerial, outcome.Latest.Message ?? "", StringComparison.OrdinalIgnoreCase);
        }

        host.AssertNoSerialNumberLeaked();
    }

    // =========================================================================
    // E2E-T3-08: EvaluateInstallSafetyAsync Pre-Flight × InstallUpdateAsync Enforcement Parity
    // =========================================================================

    public static TheoryData<string, bool, BiosSafetySnapshot, bool, string, BiosInstallStatus> T3_08_Cases => new()
    {
        { "Approved", false, StubSafetyProbe.SafeLaptop(false), true, "https://ftp.hp.com/sp.exe", BiosInstallStatus.Refused },
        { "Elevation", true, new BiosSafetySnapshot(true, true, 80, false, false, false, false), true, "https://ftp.hp.com/sp.exe", BiosInstallStatus.BlockedByPrerequisites },
        { "AC", true, new BiosSafetySnapshot(false, true, 80, false, false, true, false), true, "https://ftp.hp.com/sp.exe", BiosInstallStatus.BlockedByPrerequisites },
        { "Battery", true, new BiosSafetySnapshot(true, true, 25, false, false, true, false), true, "https://ftp.hp.com/sp.exe", BiosInstallStatus.BlockedByPrerequisites },
        { "BitLocker", true, new BiosSafetySnapshot(true, true, 80, true, false, true, false), false, "https://ftp.hp.com/sp.exe", BiosInstallStatus.BlockedByPrerequisites },
        { "PendingReboot", true, new BiosSafetySnapshot(true, true, 80, false, false, true, true), true, "https://ftp.hp.com/sp.exe", BiosInstallStatus.BlockedByPrerequisites },
        { "UrlScheme", true, StubSafetyProbe.SafeLaptop(false), true, "http://ftp.hp.com/sp.exe", BiosInstallStatus.BlockedByPrerequisites }
    };

    [Theory]
    [MemberData(nameof(T3_08_Cases))]
    public async Task E2E_T3_08_EvaluateInstallSafetyPreFlightAndInstallUpdateEnforcementParity(
        string condition, bool approved, BiosSafetySnapshot snapshot, bool suspendBitLocker,
        string downloadUrl, BiosInstallStatus expectedInstallStatus)
    {
        Assert.False(string.IsNullOrWhiteSpace(condition));
        var identity = E2eIdentities.HpEliteBook();
        await using var host = BiosE2eTestHost.CreateElevated(identity, snapshot);

        var target = BiosLatestInfo.UpdateAvailable("hp", "01.14.00", downloadUrl: downloadUrl);
        var req = new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: approved, SuspendBitLocker: suspendBitLocker);

        var preFlight = await host.Service.EvaluateInstallSafetyAsync(req);
        Assert.False(preFlight.Passed);
        Assert.NotEmpty(preFlight.BlockingReasons);

        var installRes = await host.Service.InstallUpdateAsync(req);
        Assert.False(installRes.Succeeded);
        Assert.Equal(expectedInstallStatus, installRes.Status);
    }

    // =========================================================================
    // E2E-T3-09: CheckForUpdateAsync Outcome × InstallUpdateAsync Lifecycle Transitions
    // =========================================================================

    [Fact]
    public async Task E2E_T3_09_CheckForUpdateOutcomeToInstallUpdateLifecycleTransitions()
    {
        await using var host = BiosE2eTestHost.CreateElevated(E2eIdentities.HpEliteBook(biosVersion: "U74 Ver. 01.14.00"));

        // 1. UpToDate -> AlreadyUpToDate (Succeeded = true)
        host.HttpHandler.MapText("https://hpia.hpcloud.hp.com/ref/8b41/8b41_64_11.0.cab", E2ePayloads.HpCatalogXml(version: "01.14.00"));
        var c1 = await host.Service.CheckForUpdateAsync();
        Assert.Equal(BiosCheckStatus.UpToDate, c1.Latest.Status);
        var r1 = await host.Service.InstallUpdateAsync(new BiosInstallRequest(c1.System, c1.Current, c1.Latest, Approved: true));
        Assert.True(r1.Succeeded);
        Assert.Equal(BiosInstallStatus.AlreadyUpToDate, r1.Status);

        // 2. UpdateAvailable (check-only ASUS) -> Unsupported
        host.SystemProbe.Identity = E2eIdentities.AsusRog(biosVersion: "1801");
        host.HttpHandler.MapPrefixText("https://www.asus.com/support/api/product.asmx/GetPDBIOS", E2ePayloads.AsusBiosJson(version: "2402"));
        var c2 = await host.Service.CheckForUpdateAsync();
        Assert.Equal(BiosCheckStatus.UpdateAvailable, c2.Latest.Status);
        var r2 = await host.Service.InstallUpdateAsync(new BiosInstallRequest(c2.System, c2.Current, c2.Latest, Approved: true));
        Assert.False(r2.Succeeded);
        Assert.Equal(BiosInstallStatus.Unsupported, r2.Status);

        // 3. UpdateAvailable (installable, unapproved) -> Refused
        host.SystemProbe.Identity = E2eIdentities.HpEliteBook(biosVersion: "U74 Ver. 01.10.00");
        var c3 = await host.Service.CheckForUpdateAsync();
        Assert.Equal(BiosCheckStatus.UpdateAvailable, c3.Latest.Status);
        var r3 = await host.Service.InstallUpdateAsync(new BiosInstallRequest(c3.System, c3.Current, c3.Latest, Approved: false));
        Assert.False(r3.Succeeded);
        Assert.Equal(BiosInstallStatus.Refused, r3.Status);

        // 4. Offline / Failed -> Refused
        host.HttpHandler.MapException("https://hpia.hpcloud.hp.com/ref/8b41/8b41_64_11.0.cab", new HttpRequestException("Offline"));
        var c4 = await host.Service.CheckForUpdateAsync();
        Assert.Equal(BiosCheckStatus.Offline, c4.Latest.Status);
        var r4 = await host.Service.InstallUpdateAsync(new BiosInstallRequest(c4.System, c4.Current, c4.Latest, Approved: true));
        Assert.False(r4.Succeeded);
        Assert.Equal(BiosInstallStatus.Refused, r4.Status);
    }

    // =========================================================================
    // E2E-T3-10: Custom Priority-200 Provider Coexistence × Built-In OEMs × WUA
    // =========================================================================

    [Fact]
    public async Task E2E_T3_10_CustomPriority200ProviderCoexistenceWithBuiltInOemsAndWua()
    {
        await using var host = BiosE2eTestHost.CreateElevated(
            configureServices: (services, _, _, _, _, _) =>
            {
                services.AddBiosUpdateProvider(_ => new CustomEnterpriseHpOverrideProvider());
            });

        Assert.Equal(10, host.Service.Providers.Count);
        Assert.Equal("custom-hp-enterprise", host.Service.Providers[0].VendorId);
        Assert.Equal(200, host.Service.Providers[0].Priority);

        // Preempts HP EliteBook ONLY
        Assert.Equal("custom-hp-enterprise", host.Service.ResolveProvider(E2eIdentities.HpEliteBook())?.VendorId);

        // All other 7 built-in OEMs + WUA fallback remain intact
        Assert.Equal("dell", host.Service.ResolveProvider(E2eIdentities.DellLatitude())?.VendorId);
        Assert.Equal("lenovo", host.Service.ResolveProvider(E2eIdentities.LenovoThinkPad())?.VendorId);
        Assert.Equal("asus", host.Service.ResolveProvider(E2eIdentities.AsusRog())?.VendorId);
        Assert.Equal("acer", host.Service.ResolveProvider(E2eIdentities.AcerPredator())?.VendorId);
        Assert.Equal("msi", host.Service.ResolveProvider(E2eIdentities.MsiMag())?.VendorId);
        Assert.Equal("microsoft", host.Service.ResolveProvider(E2eIdentities.SurfacePro9())?.VendorId);
        Assert.Equal("framework", host.Service.ResolveProvider(E2eIdentities.FrameworkLaptop13())?.VendorId);
        Assert.Equal("windows-update", host.Service.ResolveProvider(E2eIdentities.GenericPc(firmwareMode: BiosFirmwareMode.Uefi))?.VendorId);
    }

    // =========================================================================
    // E2E-T3-11: Elevation Matrix: IsProcessElevated × BridgeConnected × Provider × BitLocker × AllowReboot
    // =========================================================================

    public static TheoryData<bool, bool, string, bool, bool> T3_11_Cases => new()
    {
        // (!Elevated, Connected) -> routes through Live Agent Pipe across ALL 6 installable providers
        { false, true, "hp", true, false },
        { false, true, "dell", false, true },
        { false, true, "lenovo", true, false },
        { false, true, "microsoft", true, false },
        { false, true, "framework", true, false },
        { false, true, "windows-update", true, false },
        // (!Elevated, Disconnected) -> BlockedByPrerequisites (0 downloads, 0 pipe, 0 local)
        { false, false, "hp", true, false },
        { false, false, "windows-update", true, false },
        // (Elevated, Disconnected) -> also BlockedByPrerequisites: the app never does admin work itself, only the Agent does
        { true, false, "hp", true, false },
        { true, false, "windows-update", true, false }
    };

    [Theory]
    [MemberData(nameof(T3_11_Cases))]
    public async Task E2E_T3_11_ElevationMatrixProcessElevatedByBridgeConnectedByProviderByBitLockerByAllowReboot(
        bool isProcessElevated, bool bridgeConnected, string vendorId, bool suspendBitLocker, bool allowReboot)
    {
        var (identity, url, expectedToolName) = vendorId switch
        {
            "hp" => (E2eIdentities.HpEliteBook(), "https://ftp.hp.com/pub/softpaq/HPBIOSUPDREC64.exe", "HPBIOSUPDREC64.exe"),
            "dell" => (E2eIdentities.DellLatitude(), "https://downloads.dell.com/FOLDER1/dell.exe", "dell.exe"),
            "lenovo" => (E2eIdentities.LenovoThinkPad(), "https://download.lenovo.com/pccbbs/mobiles/winuptp.exe", "winuptp.exe"),
            "microsoft" => (E2eIdentities.SurfacePro9(), "https://download.microsoft.com/surface/SurfacePro9.msi", "msiexec.exe"),
            "framework" => (E2eIdentities.FrameworkLaptop13(), "https://cdn.fwupd.org/downloads/fw.cab", "pnputil.exe"),
            _ => (E2eIdentities.GenericPc(firmwareMode: BiosFirmwareMode.Uefi), (string?)null, "")
        };

        await using var host = await BiosE2eTestHost.CreateAsync(new BiosE2eHostOptions
        {
            InitialIdentity = identity,
            IsProcessElevated = isProcessElevated,
            IsAdminHelperConnected = bridgeConnected,
            UseLiveAgentPipe = !isProcessElevated && bridgeConnected,
            UseDisconnectedBridge = !bridgeConnected,
            UseHermeticRealSafetyProbe = true,
            HermeticBitLockerActive = suspendBitLocker
        });

        string? sha = null;
        string? pkgId = null;
        if (url is not null)
        {
            var (bytes, hash) = vendorId == "framework"
                ? E2ePayloads.FrameworkCabCapsule()
                : E2ePayloads.BuildDummyBinary($"t311-{vendorId}");
            sha = hash;
            host.HttpHandler.MapBytes(url, bytes);
        }
        else
        {
            pkgId = Guid.NewGuid().ToString("D");
        }

        var target = BiosLatestInfo.UpdateAvailable(vendorId, "9.9.9", packageId: pkgId, downloadUrl: url, sha256: sha);
        var res = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: suspendBitLocker, AllowReboot: allowReboot, VerifyHash: true, StagingDirectory: host.StagingDir.Path));

        if (!bridgeConnected)
        {
            Assert.False(res.Succeeded);
            Assert.Equal(BiosInstallStatus.BlockedByPrerequisites, res.Status);
            Assert.False(host.HermeticSafetyProbe!.LastRealSnapshot!.HasElevation);
            Assert.Empty(host.HttpHandler.Requests);
            Assert.Empty(host.HostProcessLauncher.Calls);
            Assert.Empty(host.WindowsUpdateClient.InstalledUpdateIds);
        }
        else if (!isProcessElevated && bridgeConnected)
        {
            Assert.True(res.Succeeded, res.Message);
            Assert.True(host.HermeticSafetyProbe!.LastRealSnapshot!.HasElevation);
            Assert.Empty(host.HostProcessLauncher.Calls);
            Assert.Empty(host.WindowsUpdateClient.InstalledUpdateIds);

            var agentBdeCalls = host.LivePipe!.AgentProcessLauncher.Calls
                .Where(c => c.ToolName.Equals("manage-bde.exe", StringComparison.OrdinalIgnoreCase))
                .ToArray();
            Assert.Equal(suspendBitLocker ? 1 : 0, agentBdeCalls.Length);

            if (vendorId == "windows-update")
            {
                Assert.Equal(1, host.LivePipe.AgentWuaApi.InstalledCount);
            }
            else
            {
                var agentInstaller = Assert.Single(
                    host.LivePipe.AgentProcessLauncher.Calls,
                    c => c.ToolName.Equals(expectedToolName, StringComparison.OrdinalIgnoreCase));

                switch (vendorId)
                {
                    case "hp":
                        Assert.Equal(allowReboot ? ["-s"] : ["-s", "-r"], agentInstaller.Arguments);
                        break;
                    case "dell":
                        Assert.Equal(allowReboot ? ["/s", "/r"] : ["/s"], agentInstaller.Arguments);
                        break;
                    case "lenovo":
                        Assert.Equal(allowReboot ? ["-s", "-r"] : ["-s"], agentInstaller.Arguments);
                        break;
                    case "microsoft":
                        Assert.Contains("/i", agentInstaller.Arguments, StringComparer.OrdinalIgnoreCase);
                        Assert.Contains("/qn", agentInstaller.Arguments, StringComparer.OrdinalIgnoreCase);
                        if (allowReboot)
                            Assert.DoesNotContain("/norestart", agentInstaller.Arguments, StringComparer.OrdinalIgnoreCase);
                        else
                            Assert.Contains("/norestart", agentInstaller.Arguments, StringComparer.OrdinalIgnoreCase);
                        break;
                    case "framework":
                        Assert.Contains("/add-driver", agentInstaller.Arguments, StringComparer.OrdinalIgnoreCase);
                        Assert.Contains("/install", agentInstaller.Arguments, StringComparer.OrdinalIgnoreCase);
                        break;
                }
            }

            Assert.Equal(suspendBitLocker, res.BitLockerSuspended);
        }

        host.AssertZeroShellInvocations();
        host.AssertNoSerialNumberLeaked(result: res);
    }

    private sealed class CustomEnterpriseHpOverrideProvider : IBiosUpdateProvider
    {
        public string VendorId => "custom-hp-enterprise";
        public string DisplayName => "Custom Enterprise HP";
        public int Priority => 200;
        public BiosProviderCapabilities Capabilities => new();
        public bool CanHandle(BiosSystemIdentity system) =>
            system.Manufacturer.Equals("HP", StringComparison.OrdinalIgnoreCase);
        public Task<BiosLatestInfo> GetLatestVersionAsync(BiosSystemIdentity system, BiosCurrentInfo current, CancellationToken ct = default) =>
            Task.FromResult(BiosLatestInfo.UpToDate(VendorId, current.Version));
    }
}
