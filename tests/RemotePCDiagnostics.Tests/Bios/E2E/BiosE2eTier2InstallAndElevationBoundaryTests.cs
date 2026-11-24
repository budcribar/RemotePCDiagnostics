using System.Net;
using System.Text;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Bios;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests.Bios.E2E;

/// <summary>
/// Tier 2 E2E Boundary &amp; Corner Cases (Areas 2.5–2.8: Reboot Policy/BitLocker/PII Redaction,
/// Safety Evaluator &amp; BitLocker Probe Boundaries, Version/Provider Edge Boundaries, and
/// Agent Elevation Security Boundaries) — 30 test IDs.
/// </summary>
[Trait("Tier", "2")]
public sealed class BiosE2eTier2InstallAndElevationBoundaryTests
{
    // =========================================================================
    // Area 2.5: Reboot Policy, BitLocker & PII Redaction Boundaries (E2E-T2-INS-01..09)
    // =========================================================================

    [Theory]
    [InlineData(false, new[] { "-s", "-r" })]
    [InlineData(true, new[] { "-s" })]
    public async Task E2E_T2_INS_01_HpInvertedDashRPolarityBoundary(bool allowReboot, string[] expectedArgs)
    {
        var identity = E2eIdentities.HpEliteBook();
        var (pkgBytes, sha256) = E2ePayloads.BuildDummyBinary($"hp-reboot-{allowReboot}");
        const string url = "https://ftp.hp.com/pub/softpaq/HPBIOSUPDREC64.exe";

        await using var host = BiosE2eTestHost.CreateElevated(identity);
        host.HttpHandler.MapBytes(url, pkgBytes);

        var target = BiosLatestInfo.UpdateAvailable("hp", "01.14.00", downloadUrl: url, sha256: sha256);
        var result = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: false, AllowReboot: allowReboot, VerifyHash: true, StagingDirectory: host.StagingDir.Path));

        Assert.True(result.Succeeded, result.Message);
        var call = Assert.Single(host.HostProcessLauncher.Calls);
        Assert.Equal(expectedArgs, call.Arguments);
    }

    [Fact]
    public async Task E2E_T2_INS_02_DellStandardPolarityBoundaryExeAndDcuCli()
    {
        var identity = E2eIdentities.DellLatitude();
        var (pkgBytes, sha256) = E2ePayloads.BuildDummyBinary("dell-ins02");
        const string url = "https://downloads.dell.com/FOLDER1/Latitude_1.18.0.exe";

        // Part A: Dell EXE polarity (AllowReboot=false -> ["/s"], AllowReboot=true -> ["/s", "/r"])
        foreach (var (allowReboot, expectedArgs) in new[] { (false, new[] { "/s" }), (true, new[] { "/s", "/r" }) })
        {
            await using var host = BiosE2eTestHost.CreateElevated(identity);
            host.HttpHandler.MapBytes(url, pkgBytes);

            var target = BiosLatestInfo.UpdateAvailable("dell", "1.18.0", downloadUrl: url, sha256: sha256);
            var res = await host.Service.InstallUpdateAsync(
                new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: false, AllowReboot: allowReboot, VerifyHash: true, StagingDirectory: host.StagingDir.Path));

            Assert.True(res.Succeeded, res.Message);
            var call = Assert.Single(host.HostProcessLauncher.Calls);
            Assert.Equal(expectedArgs, call.Arguments);
        }

        // Part B: Dell DCU CLI polarity over live Agent Pipe (cross-platform hermetic via allowlisted tool root)
        foreach (var (allowReboot, expectedRebootArg) in new[] { (false, "-reboot=disable"), (true, "-reboot=enable") })
        {
            await using var host = await BiosE2eTestHost.CreateAsync(new BiosE2eHostOptions
            {
                InitialIdentity = identity,
                IsProcessElevated = false,
                UseLiveAgentPipe = true,
                CreateAllowlistedDcuTool = true,
                IncludeWindowsSystemProgramFilesToolRoots = true,
                UseHermeticRealSafetyProbe = true
            });

            var dcuTarget = BiosLatestInfo.UpdateAvailable(
                "dell",
                "1.18.0",
                metadata: new Dictionary<string, string> { ["installMode"] = BiosAgentInstallModes.DellDcuCli });

            var res = await host.Service.InstallUpdateAsync(
                new BiosInstallRequest(identity, identity.CurrentBios, dcuTarget, Approved: true, SuspendBitLocker: false, AllowReboot: allowReboot, VerifyHash: true));

            Assert.True(res.Succeeded, res.Message);
            Assert.Equal(BiosInstallStatus.StagedForReboot, res.Status);
            var dcuCall = Assert.Single(host.LivePipe!.AgentProcessLauncher.Calls, c => c.ToolName.Equals("dcu-cli.exe", StringComparison.OrdinalIgnoreCase));
            Assert.Equal(["/applyUpdates", "-updateType=bios", "-silent", expectedRebootArg], dcuCall.Arguments);
        }

        // Part C: Dell DCU CLI exit code 500 -> AlreadyUpToDate
        await using var host500 = await BiosE2eTestHost.CreateAsync(new BiosE2eHostOptions
        {
            InitialIdentity = identity,
            IsProcessElevated = false,
            UseLiveAgentPipe = true,
            CreateAllowlistedDcuTool = true,
            IncludeWindowsSystemProgramFilesToolRoots = true,
            UseHermeticRealSafetyProbe = true
        });
        host500.LivePipe!.AgentProcessLauncher.OnTool("dcu-cli.exe", new ProcessResult(500, "No updates found.", ""));
        var dcuTarget500 = BiosLatestInfo.UpdateAvailable(
            "dell", "1.18.0", metadata: new Dictionary<string, string> { ["installMode"] = BiosAgentInstallModes.DellDcuCli });
        var res500 = await host500.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, dcuTarget500, Approved: true, SuspendBitLocker: false, AllowReboot: false));
        Assert.True(res500.Succeeded);
        Assert.Equal(BiosInstallStatus.AlreadyUpToDate, res500.Status);
        Assert.Equal(500, res500.ExitCode);
    }

    [Theory]
    [InlineData(false, new[] { "-s" })]
    [InlineData(true, new[] { "-s", "-r" })]
    public async Task E2E_T2_INS_03_LenovoStandardPolarityBoundary(bool allowReboot, string[] expectedArgs)
    {
        var identity = E2eIdentities.LenovoThinkPad();
        var (pkgBytes, sha256) = E2ePayloads.BuildDummyBinary($"lenovo-reboot-{allowReboot}");
        const string url = "https://download.lenovo.com/pccbbs/mobiles/winuptp.exe";

        await using var host = BiosE2eTestHost.CreateElevated(identity);
        host.HttpHandler.MapBytes(url, pkgBytes);

        var target = BiosLatestInfo.UpdateAvailable("lenovo", "N3XET52W", downloadUrl: url, sha256: sha256);
        var result = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: false, AllowReboot: allowReboot, VerifyHash: true, StagingDirectory: host.StagingDir.Path));

        Assert.True(result.Succeeded, result.Message);
        var call = Assert.Single(host.HostProcessLauncher.Calls);
        Assert.Equal(expectedArgs, call.Arguments);
    }

    [Theory]
    [InlineData(0, true, BiosInstallStatus.StagedForReboot)]
    [InlineData(3010, true, BiosInstallStatus.StagedForReboot)]
    [InlineData(1603, false, BiosInstallStatus.Failed)]
    [InlineData(1618, false, BiosInstallStatus.Failed)]
    public async Task E2E_T2_INS_04_SurfaceMsiExitCodesAndNoRestartBoundary(
        int exitCode, bool expectedSucceeded, BiosInstallStatus expectedStatus)
    {
        var identity = E2eIdentities.SurfacePro9();
        var (msiBytes, sha256) = E2ePayloads.BuildDummyBinary($"surface-rc-{exitCode}");
        const string msiUrl = "https://download.microsoft.com/download/surface/SurfacePro9.msi";

        await using var host = BiosE2eTestHost.CreateElevated(identity);
        host.HttpHandler.MapBytes(msiUrl, msiBytes);
        host.HostProcessLauncher.OnTool("msiexec.exe", new ProcessResult(exitCode, $"msiexec exit {exitCode}", ""));

        var target = BiosLatestInfo.UpdateAvailable("microsoft", "15.102.143", downloadUrl: msiUrl, sha256: sha256);
        var result = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: false, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));

        Assert.Equal(expectedSucceeded, result.Succeeded);
        Assert.Equal(expectedStatus, result.Status);
        Assert.Equal(exitCode, result.ExitCode);

        var msiCall = Assert.Single(host.HostProcessLauncher.Calls);
        Assert.Equal("/i", msiCall.Arguments[0]);
        Assert.Equal("/qn", msiCall.Arguments[2]);
        Assert.Equal("/norestart", msiCall.Arguments[3]);
    }

    [Fact]
    public async Task E2E_T2_INS_05_FrameworkAllowRebootFalseAndInstallerErrorExitCode()
    {
        var identity = E2eIdentities.FrameworkLaptop13();

        // Part A: Silent .exe with AllowReboot=false & non-zero exit code -> Failed with ExitCode preserved
        var (exeBytes, exeSha) = E2ePayloads.BuildDummyBinary("fw-exe-fail");
        const string exeUrl = "https://downloads.frame.work/bios/Framework_BIOS_3.05.exe";
        await using var exeHost = BiosE2eTestHost.CreateElevated(identity);
        exeHost.HttpHandler.MapBytes(exeUrl, exeBytes);
        exeHost.HostProcessLauncher.OnTool("Framework_BIOS_3.05.exe", new ProcessResult(17, "", "Flash rejected"));

        var exeRes = await exeHost.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios,
                BiosLatestInfo.UpdateAvailable("framework", "3.05", downloadUrl: exeUrl, sha256: exeSha),
                Approved: true, SuspendBitLocker: false, AllowReboot: false, VerifyHash: true, StagingDirectory: exeHost.StagingDir.Path));
        Assert.False(exeRes.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, exeRes.Status);
        Assert.Equal(17, exeRes.ExitCode);
        var exeCall = Assert.Single(exeHost.HostProcessLauncher.Calls);
        Assert.Equal(["/silent", "/norestart"], exeCall.Arguments);

        // Part B: .cab capsule with pnputil.exe returning non-zero exit code -> Failed with ExitCode preserved
        var (cabBytes, cabSha) = E2ePayloads.FrameworkCabCapsule();
        const string cabUrl = "https://cdn.fwupd.org/downloads/framework-3.05.cab";
        await using var cabHost = BiosE2eTestHost.CreateElevated(identity);
        cabHost.HttpHandler.MapBytes(cabUrl, cabBytes);
        cabHost.HostProcessLauncher.OnTool("pnputil.exe", new ProcessResult(5, "", "Access denied"));

        var cabRes = await cabHost.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios,
                BiosLatestInfo.UpdateAvailable("framework", "3.05", downloadUrl: cabUrl, sha256: cabSha),
                Approved: true, SuspendBitLocker: false, AllowReboot: false, VerifyHash: true, StagingDirectory: cabHost.StagingDir.Path));
        Assert.False(cabRes.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, cabRes.Status);
        Assert.Equal(5, cabRes.ExitCode);
        var pnpCall = Assert.Single(cabHost.HostProcessLauncher.Calls);
        Assert.Equal("/add-driver", pnpCall.Arguments[0]);
        Assert.Equal("/install", pnpCall.Arguments[2]);
    }

    [Theory]
    [InlineData(4, "WUA install failed.")]
    [InlineData(5, "WUA install aborted.")]
    public async Task E2E_T2_INS_06_WindowsUpdateErrorResultCodesAndExceptionHandledCleanly(int resultCode, string message)
    {
        var identity = E2eIdentities.GenericPc(firmwareMode: BiosFirmwareMode.Uefi);
        var guid = Guid.NewGuid();
        var target = BiosLatestInfo.UpdateAvailable("windows-update", "2.0", packageId: guid.ToString("D"));

        // Non-success ResultCode (4=Failed, 5=Aborted) -> BiosInstallStatus.Failed
        await using var host1 = BiosE2eTestHost.CreateElevated(identity);
        host1.WindowsUpdateClient.InstallHandler = (_, _) =>
            Task.FromResult(new BiosWuaInstallOutcome(false, resultCode, false, message));

        var res1 = await host1.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: false, AllowReboot: false));
        Assert.False(res1.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, res1.Status);
        Assert.Equal(resultCode, res1.ExitCode);

        // Exception thrown by IBiosWindowsUpdateClient -> BiosInstallStatus.Failed (no unhandled exception)
        await using var host2 = BiosE2eTestHost.CreateElevated(identity);
        host2.WindowsUpdateClient.InstallException = new InvalidOperationException("WUA COM service crashed.");

        var res2 = await host2.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: false, AllowReboot: false));
        Assert.False(res2.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, res2.Status);
    }

    [Fact]
    public async Task E2E_T2_INS_07_SuspendBitLockerTrueOnUnencryptedDriveNonZeroManageBdeContinuesInstall()
    {
        var identity = E2eIdentities.HpEliteBook();
        var (pkgBytes, sha256) = E2ePayloads.BuildDummyBinary("hp-unencrypted-bde");
        const string url = "https://ftp.hp.com/pub/softpaq/sp151234.exe";

        await using var host = BiosE2eTestHost.CreateElevated(identity);
        host.HttpHandler.MapBytes(url, pkgBytes);
        host.HostProcessLauncher.OnTool("manage-bde.exe", new ProcessResult(1, "", "ERROR: Volume C: is not encrypted."));

        var target = BiosLatestInfo.UpdateAvailable("hp", "01.14.00", downloadUrl: url, sha256: sha256);
        var result = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: true, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));

        Assert.True(result.Succeeded, result.Message);
        Assert.Equal(BiosInstallStatus.StagedForReboot, result.Status);
        Assert.False(result.BitLockerSuspended);
        Assert.Contains(host.HostProcessLauncher.Calls, c => c.ToolName.Equals("manage-bde.exe", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(host.HostProcessLauncher.Calls, c => c.ToolName.Equals("sp151234.exe", StringComparison.OrdinalIgnoreCase));
    }

    public static TheoryData<string, BiosSystemIdentity, string?, string?> SixInstallableProvidersNoBitLocker => new()
    {
        { "hp", E2eIdentities.HpEliteBook(), "https://ftp.hp.com/pub/softpaq/sp151234.exe", null },
        { "dell", E2eIdentities.DellLatitude(), "https://downloads.dell.com/FOLDER1/dell.exe", null },
        { "lenovo", E2eIdentities.LenovoThinkPad(), "https://download.lenovo.com/pccbbs/winuptp.exe", null },
        { "microsoft", E2eIdentities.SurfacePro9(), "https://download.microsoft.com/surface/SurfacePro9.msi", null },
        { "framework", E2eIdentities.FrameworkLaptop13(), "https://cdn.fwupd.org/downloads/fw.cab", null },
        { "windows-update", E2eIdentities.GenericPc(firmwareMode: BiosFirmwareMode.Uefi), null, "748279c7-4309-452c-8b30-e02ec52e498f" }
    };

    [Theory]
    [MemberData(nameof(SixInstallableProvidersNoBitLocker))]
    public async Task E2E_T2_INS_08_SuspendBitLockerFalseNeverRunsManageBdeAcrossAllSixInstallableProviders(
        string vendorId, BiosSystemIdentity identity, string? downloadUrl, string? packageId)
    {
        await using var host = BiosE2eTestHost.CreateElevated(identity, StubSafetyProbe.SafeLaptop(bitLockerActive: false));

        string? sha256 = null;
        if (downloadUrl is not null)
        {
            var (bytes, hash) = vendorId == "framework"
                ? E2ePayloads.FrameworkCabCapsule()
                : E2ePayloads.BuildDummyBinary($"nobde-{vendorId}");
            sha256 = hash;
            host.HttpHandler.MapBytes(downloadUrl, bytes);
        }

        var target = BiosLatestInfo.UpdateAvailable(vendorId, "9.9.9", packageId: packageId, downloadUrl: downloadUrl, sha256: sha256);
        var result = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: false, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));

        Assert.True(result.Succeeded, $"Vendor {vendorId} failed: {result.Message}");
        Assert.False(result.BitLockerSuspended);
        Assert.DoesNotContain(host.HostProcessLauncher.Calls, c => c.ToolName.Equals("manage-bde.exe", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task E2E_T2_INS_09_SerialNumberRedactionAndBoundedLogTailOn64KbNoisyOutput()
    {
        var identity = E2eIdentities.HpEliteBook(serial: BiosE2eTestHost.CanarySerial);
        var (pkgBytes, sha256) = E2ePayloads.BuildDummyBinary("hp-noisy");
        const string url = "https://ftp.hp.com/pub/softpaq/sp151234.exe";

        var noisyBuilder = new StringBuilder(90_000);
        for (int i = 0; i < 1000; i++)
            noisyBuilder.AppendLine($"Line {i:D4}: Flashing BIOS on unit serial={BiosE2eTestHost.CanarySerial} progress={i % 100}% ...");
        var noisyOutput = noisyBuilder.ToString();
        Assert.True(noisyOutput.Length > 65_536);

        await using var host = BiosE2eTestHost.CreateElevated(identity);
        host.HttpHandler.MapBytes(url, pkgBytes);
        host.HostProcessLauncher.OnTool("sp151234.exe", new ProcessResult(0, noisyOutput, $"STDERR {BiosE2eTestHost.CanarySerial}"));

        var target = BiosLatestInfo.UpdateAvailable("hp", "01.14.00", downloadUrl: url, sha256: sha256);
        var result = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: false, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));

        Assert.True(result.Succeeded);
        Assert.NotNull(result.LogTail);
        Assert.True(result.LogTail.Length <= 2000, $"Expected LogTail <= 2000 chars, got {result.LogTail.Length}.");
        Assert.Contains("[REDACTED]", result.LogTail, StringComparison.Ordinal);
        host.AssertNoSerialNumberLeaked(BiosE2eTestHost.CanarySerial, result);
    }

    // =========================================================================
    // Area 2.6: Safety Evaluator & Pure-C# BitLocker Probe Boundaries (E2E-T2-SAF-01..06)
    // =========================================================================

    [Theory]
    [InlineData(29, false)]
    [InlineData(30, true)]
    [InlineData(null, true)]
    public void E2E_T2_SAF_01_BatteryExact30PercentBoundary(int? batteryPercent, bool expectedPassed)
    {
        var identity = E2eIdentities.HpEliteBook();
        var target = BiosLatestInfo.UpdateAvailable("hp", "01.14.00", downloadUrl: "https://ftp.hp.com/sp.exe", sha256: new string('a', 64));
        var req = new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: true);
        var snapshot = new BiosSafetySnapshot(OnAcPower: true, HasBattery: true, BatteryPercent: batteryPercent, BitLockerActive: false, BitLockerSuspended: false, HasElevation: true, PendingReboot: false);

        var eval = BiosInstallSafetyEvaluator.Evaluate(snapshot, req, new BiosProviderCapabilities(CanInstall: true, RequiresElevation: true));
        Assert.Equal(expectedPassed, eval.Passed);
    }

    [Fact]
    public void E2E_T2_SAF_02_DesktopWithoutBatteryBoundary()
    {
        var identity = E2eIdentities.DellLatitude();
        var target = BiosLatestInfo.UpdateAvailable("dell", "1.18.0", downloadUrl: "https://downloads.dell.com/a.exe", sha256: new string('a', 64));
        var req = new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: false);
        var desktop = new BiosSafetySnapshot(OnAcPower: false, HasBattery: false, BatteryPercent: null, BitLockerActive: false, BitLockerSuspended: false, HasElevation: true, PendingReboot: false);

        var eval = BiosInstallSafetyEvaluator.Evaluate(desktop, req, new BiosProviderCapabilities(CanInstall: true, RequiresElevation: true));
        Assert.True(eval.Passed);
        Assert.Empty(eval.BlockingReasons);
    }

    [Fact]
    public void E2E_T2_SAF_03_UnknownAcStateWarningBoundary()
    {
        var identity = E2eIdentities.HpEliteBook();
        var target = BiosLatestInfo.UpdateAvailable("hp", "01.14.00", downloadUrl: "https://ftp.hp.com/sp.exe", sha256: new string('a', 64));
        var req = new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true);
        var snapshot = new BiosSafetySnapshot(OnAcPower: null, HasBattery: true, BatteryPercent: 80, BitLockerActive: false, BitLockerSuspended: false, HasElevation: true, PendingReboot: false);

        var eval = BiosInstallSafetyEvaluator.Evaluate(snapshot, req, new BiosProviderCapabilities(CanInstall: true, RequiresElevation: true));
        Assert.True(eval.Passed);
        Assert.NotEmpty(eval.Warnings);
    }

    [Fact]
    public void E2E_T2_SAF_04_AlreadySuspendedBitLockerAndMissingHashWarningBoundaries()
    {
        var identity = E2eIdentities.HpEliteBook();
        var caps = new BiosProviderCapabilities(CanInstall: true, RequiresElevation: true);

        // (a) Already suspended BitLocker passes even when SuspendBitLocker == false
        var targetWithHash = BiosLatestInfo.UpdateAvailable("hp", "01.14.00", downloadUrl: "https://ftp.hp.com/sp.exe", sha256: new string('a', 64));
        var reqNoSuspend = new BiosInstallRequest(identity, identity.CurrentBios, targetWithHash, Approved: true, SuspendBitLocker: false);
        var suspendedSnap = new BiosSafetySnapshot(true, true, 90, BitLockerActive: true, BitLockerSuspended: true, HasElevation: true, PendingReboot: false);
        var evalA = BiosInstallSafetyEvaluator.Evaluate(suspendedSnap, reqNoSuspend, caps);
        Assert.True(evalA.Passed);
        Assert.Empty(evalA.BlockingReasons);

        // (b) VerifyHash=true + HTTPS DownloadUrl + Sha256=null -> passes with Authenticode warning
        var targetNoHash = BiosLatestInfo.UpdateAvailable("hp", "01.14.00", downloadUrl: "https://ftp.hp.com/sp.exe", sha256: null);
        var reqVerify = new BiosInstallRequest(identity, identity.CurrentBios, targetNoHash, Approved: true, VerifyHash: true);
        var evalB = BiosInstallSafetyEvaluator.Evaluate(StubSafetyProbe.SafeLaptop(bitLockerActive: false), reqVerify, caps);
        Assert.True(evalB.Passed);
        Assert.Contains(evalB.Warnings, w => w.Contains("Authenticode", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData(null, null, null)]
    [InlineData("", null, null)]
    [InlineData("   ", null, null)]
    [InlineData("99", null, null)]
    [InlineData("-1", null, null)]
    [InlineData("NaN", null, null)]
    [InlineData("5 foo", null, null)]
    [InlineData("foo\r\n5", null, null)]
    [InlineData("5\r\nnoise", true, true)]
    public void E2E_T2_SAF_05_MalformedAndMultiLineBitLockerStatusCodes(string? raw, bool? expectedActive, bool? expectedSuspended)
    {
        var (active, suspended) = DefaultBiosInstallSafetyProbe.ParseBitLockerProtectionCode(raw);
        Assert.Equal(expectedActive, active);
        Assert.Equal(expectedSuspended, suspended);
    }

    [Fact]
    public async Task E2E_T2_SAF_06_MultipleSimultaneousSafetyBlockersAggregated()
    {
        var identity = E2eIdentities.HpEliteBook();
        var worstSnapshot = new BiosSafetySnapshot(
            OnAcPower: false,
            HasBattery: true,
            BatteryPercent: 10,
            BitLockerActive: true,
            BitLockerSuspended: false,
            HasElevation: false,
            PendingReboot: true);

        await using var host = BiosE2eTestHost.CreateElevated(identity, worstSnapshot);
        var target = BiosLatestInfo.UpdateAvailable("hp", "01.14.00", downloadUrl: "http://ftp.hp.com/sp.exe");
        var req = new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: false, SuspendBitLocker: false);

        var eval = await host.Service.EvaluateInstallSafetyAsync(req);
        Assert.False(eval.Passed);
        Assert.Equal(7, eval.BlockingReasons.Count);
        Assert.Equal(7, eval.BlockingReasons.Distinct(StringComparer.Ordinal).Count());
    }

    // =========================================================================
    // Area 2.7: Version Comparer & Provider Edge Boundaries (E2E-T2-VER-01..07)
    // =========================================================================

    [Fact]
    public void E2E_T2_VER_01_DifferentVersionFamiliesWithAndWithoutDates()
    {
        Assert.Null(BiosVersionComparer.Compare("F.10", "P.20"));
        Assert.True(BiosVersionComparer.IsNewer("F.10", "P.20", new DateOnly(2024, 1, 1), new DateOnly(2024, 6, 1)));
        Assert.False(BiosVersionComparer.IsNewer("F.10", "P.20", null, null));
    }

    [Fact]
    public void E2E_T2_VER_02_EqualComparableVersionsIgnoreNewerDate()
    {
        Assert.Equal(0, BiosVersionComparer.Compare("1.14", "1.14.0"));
        Assert.False(BiosVersionComparer.IsNewer("1.14", "1.14.0", new DateOnly(2023, 1, 1), new DateOnly(2025, 1, 1)));
    }

    [Fact]
    public async Task E2E_T2_VER_03_CatalogDowngradeReturnsUpToDate()
    {
        // HP: current F.24 vs catalog F.10 -> UpToDate
        await using var hpHost = BiosE2eTestHost.CreateElevated(E2eIdentities.HpEliteBook(biosVersion: "F.24 Rev.A"));
        hpHost.HttpHandler.MapText("https://hpia.hpcloud.hp.com/ref/8b41/8b41_64_11.0.cab",
            E2ePayloads.HpCatalogXml(version: "F.10", family: "F"));
        var hpOut = await hpHost.Service.CheckForUpdateAsync();
        Assert.Equal(BiosCheckStatus.UpToDate, hpOut.Latest.Status);

        // Lenovo: current N3XET52W vs catalog N3XET48W -> UpToDate
        await using var lenHost = BiosE2eTestHost.CreateElevated(E2eIdentities.LenovoThinkPad(biosVersion: "N3XET52W (1.25 )"));
        lenHost.HttpHandler.MapText("https://download.lenovo.com/catalog/21HM_Win11.xml", E2ePayloads.LenovoIndexXml(version: "N3XET48W"));
        lenHost.HttpHandler.MapText("https://download.lenovo.com/pccbbs/mobiles/n3xuj12w_2_.xml", E2ePayloads.LenovoDescriptorXml(version: "N3XET48W"));
        var lenOut = await lenHost.Service.CheckForUpdateAsync();
        Assert.Equal(BiosCheckStatus.UpToDate, lenOut.Latest.Status);
    }

    [Theory]
    [InlineData("asus", "{not json", BiosCheckStatus.Failed)]
    [InlineData("asus", "", BiosCheckStatus.Failed)]
    [InlineData("asus", "[]", BiosCheckStatus.UnsupportedHardware)]
    [InlineData("acer", "{not json", BiosCheckStatus.Failed)]
    [InlineData("acer", "[]", BiosCheckStatus.UnsupportedHardware)]
    [InlineData("msi", "{not json", BiosCheckStatus.Failed)]
    [InlineData("msi", "[]", BiosCheckStatus.UnsupportedHardware)]
    [InlineData("microsoft", "{not json", BiosCheckStatus.Failed)]
    [InlineData("microsoft", "[]", BiosCheckStatus.UnsupportedHardware)]
    public async Task E2E_T2_VER_04_MalformedEmptyOrTruncatedJsonCatalogsHandledCleanly(
        string vendorId, string payload, BiosCheckStatus expectedStatus)
    {
        var (identity, prefix) = vendorId switch
        {
            "asus" => (E2eIdentities.AsusRog(), "https://www.asus.com/support/api/product.asmx/GetPDBIOS"),
            "acer" => (E2eIdentities.AcerPredator(), "https://www.acer.com/us-en/support/api/product/bios"),
            "msi" => (E2eIdentities.MsiMag(), "https://www.msi.com/api/v1/product/support/panel"),
            _ => (E2eIdentities.SurfacePro9(), "https://www.microsoft.com/surface/api/firmware")
        };

        await using var host = BiosE2eTestHost.CreateElevated(identity);
        host.HttpHandler.MapPrefixText(prefix, payload, "application/json");

        var outcome = await host.Service.CheckForUpdateAsync();
        Assert.Equal(vendorId, outcome.ProviderId);
        Assert.Equal(expectedStatus, outcome.Latest.Status);
    }

    [Theory]
    [InlineData("asus")]
    [InlineData("acer")]
    [InlineData("msi")]
    public async Task E2E_T2_VER_05_ConsumerProviderCatalogReturningMaliciousNonVendorUrlFailsClosed(string vendorId)
    {
        var (identity, prefix, body) = vendorId switch
        {
            "asus" => (E2eIdentities.AsusRog(), "https://www.asus.com/support/api/product.asmx/GetPDBIOS", E2ePayloads.AsusBiosJson(downloadUrl: "http://evil.com/bios.zip")),
            "acer" => (E2eIdentities.AcerPredator(), "https://www.acer.com/us-en/support/api/product/bios", E2ePayloads.AcerBiosJson(downloadUrl: "http://evil.com/bios.zip")),
            _ => (E2eIdentities.MsiMag(), "https://www.msi.com/api/v1/product/support/panel", E2ePayloads.MsiBiosJson(downloadUrl: "http://evil.com/bios.zip"))
        };

        await using var host = BiosE2eTestHost.CreateElevated(identity);
        host.HttpHandler.MapPrefixText(prefix, body, "application/json");

        var outcome = await host.Service.CheckForUpdateAsync();
        Assert.Equal(vendorId, outcome.ProviderId);
        Assert.NotEqual(BiosCheckStatus.UpdateAvailable, outcome.Latest.Status);
        Assert.Equal(BiosCheckStatus.Failed, outcome.Latest.Status);
        Assert.Null(outcome.Latest.DownloadUrl);
    }

    [Fact]
    public async Task E2E_T2_VER_06_FrameworkCabMissingInfFileFailsWithoutCallingPnputil()
    {
        var identity = E2eIdentities.FrameworkLaptop13();
        var cabNoInf = E2ePayloads.BuildCab([("firmware.bin", Encoding.UTF8.GetBytes("ONLY-BINARY-NO-INF"))]);
        var cabSha = E2ePayloads.ComputeSha256Hex(cabNoInf);
        const string cabUrl = "https://cdn.fwupd.org/downloads/framework-no-inf.cab";

        await using var host = BiosE2eTestHost.CreateElevated(identity);
        host.HttpHandler.MapBytes(cabUrl, cabNoInf);

        var target = BiosLatestInfo.UpdateAvailable("framework", "3.05", downloadUrl: cabUrl, sha256: cabSha);
        var result = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: true, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));

        Assert.False(result.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, result.Status);
        Assert.Empty(host.HostProcessLauncher.Calls);
        host.StagingDir.AssertEmpty();
    }

    [Fact]
    public async Task E2E_T2_VER_07_WindowsUpdateNonFirmwareFilteringAndNullClientOnNonWindows()
    {
        var identity = E2eIdentities.GenericPc(firmwareMode: BiosFirmwareMode.Uefi);
        var firmwareGuid = Guid.NewGuid();

        // (a) Mixed updates -> selects ONLY System Firmware
        await using var host = BiosE2eTestHost.CreateElevated(identity);
        host.WindowsUpdateClient.PendingUpdates =
        [
            new BiosWuaFirmwareUpdate(Guid.NewGuid().ToString("D"), "Realtek High Definition Audio Driver", "6.0.1", new DateOnly(2025, 2, 1), 1024, BiosUpdateSeverity.Optional, false, DriverClass: "MEDIA"),
            new BiosWuaFirmwareUpdate(Guid.NewGuid().ToString("D"), "NVIDIA GeForce Display Driver", "550.0", new DateOnly(2025, 2, 1), 1024, BiosUpdateSeverity.Optional, false, DriverClass: "Display"),
            new BiosWuaFirmwareUpdate(Guid.NewGuid().ToString("D"), "2025-02 Cumulative Update for Windows 11", "22631.4890", new DateOnly(2025, 2, 1), 1024, BiosUpdateSeverity.Critical, true, DriverClass: null, Categories: ["Security Updates"]),
            new BiosWuaFirmwareUpdate(firmwareGuid.ToString("D"), "OEM System Firmware - 3.1.0", "3.1.0", new DateOnly(2025, 2, 15), 4_194_304, BiosUpdateSeverity.Critical, true, DriverClass: "Firmware", Categories: ["Drivers", "System Firmware"])
        ];

        var outcome = await host.Service.CheckForUpdateAsync();
        Assert.Equal("windows-update", outcome.ProviderId);
        Assert.Equal(BiosCheckStatus.UpdateAvailable, outcome.Latest.Status);
        Assert.Equal(firmwareGuid.ToString("D"), outcome.Latest.PackageId);

        // (b) Cross-platform hermetic verification: PlatformNotSupportedException -> ProviderUnavailable
        await using var hostPlatformUnsupported = BiosE2eTestHost.CreateElevated(identity);
        hostPlatformUnsupported.WindowsUpdateClient.SearchException =
            new PlatformNotSupportedException("Simulated non-Windows WUA host.");
        var unsupportedOutcome = await hostPlatformUnsupported.Service.CheckForUpdateAsync();
        Assert.Equal("windows-update", unsupportedOutcome.ProviderId);
        Assert.Equal(BiosCheckStatus.ProviderUnavailable, unsupportedOutcome.Latest.Status);
        Assert.Equal(1, hostPlatformUnsupported.WindowsUpdateClient.SearchCount);

        // (c) Default WUA client (not injected in DI) on non-Windows -> ProviderUnavailable without throwing PlatformNotSupportedException.
        // Strictly guarded with !OperatingSystem.IsWindows() so Windows NEVER instantiates live Microsoft.Update.Session COM or hits the network.
        if (!OperatingSystem.IsWindows())
        {
            await using var hostNoWua = BiosE2eTestHost.CreateElevated(identity, registerWindowsUpdateClient: false);
            var noWuaOutcome = await hostNoWua.Service.CheckForUpdateAsync();
            Assert.Equal("windows-update", noWuaOutcome.ProviderId);
            Assert.Equal(BiosCheckStatus.ProviderUnavailable, noWuaOutcome.Latest.Status);
        }
    }

    // =========================================================================
    // Area 2.8: Agent Elevation Security Boundary & Pipe Rejections (E2E-T2-ELV-01..08)
    // =========================================================================

    [Fact]
    public async Task E2E_T2_ELV_01_AgentSideTamperedSha256AndToctouProtection()
    {
        await using var pipe = await LiveAgentPipeFixture.StartAsync();
        using var userDir = new IsolatedStagingDir("elv01-user");

        var (cleanBytes, cleanSha) = E2ePayloads.BuildDummyBinary("elv01-clean");
        var tamperedBytes = (byte[])cleanBytes.Clone();
        tamperedBytes[^1] ^= 0xFF;

        // (a) Wrong 64-hex SHA-256 & malformed SHA-256
        var filePath = Path.Combine(userDir.Path, "sp151234.exe");
        await File.WriteAllBytesAsync(filePath, tamperedBytes);

        var wrongHashRes = await pipe.Client!.RunBiosInstallerAsync(new BiosAgentInstallRequest(
            "hp", BiosAgentInstallModes.HpSoftPaq, filePath, ExpectedSha256: cleanSha, AllowReboot: false));
        Assert.False(wrongHashRes.Executed);
        Assert.False(wrongHashRes.Allowed);
        Assert.Contains("SHA-256", wrongHashRes.Error ?? "", StringComparison.OrdinalIgnoreCase);

        var malformedHashRes = await pipe.Client.RunBiosInstallerAsync(new BiosAgentInstallRequest(
            "hp", BiosAgentInstallModes.HpSoftPaq, filePath, ExpectedSha256: "abc123", AllowReboot: false));
        Assert.False(malformedHashRes.Executed);
        Assert.False(malformedHashRes.Allowed);
        Assert.Empty(pipe.AgentProcessLauncher.Calls);
        pipe.AgentStagingDir.AssertEmpty();

        // (b) Post-copy TOCTOU immunity: user overwrites source file DURING Agent verification,
        //     yet Agent executes its immutable admin-owned staging copy with the verified clean SHA-256!
        await File.WriteAllBytesAsync(filePath, cleanBytes);
        string? observedStagedSha = null;
        string? observedStagedPath = null;
        pipe.AgentSignatureVerifier.Predicate = stagedCopyPath =>
        {
            // Simulate malicious standard-user swapping the user-owned file mid-flight!
            File.WriteAllBytes(filePath, tamperedBytes);
            return true;
        };
        pipe.AgentProcessLauncher.OnTool("sp151234.exe", call =>
        {
            observedStagedPath = call.FileName;
            observedStagedSha = E2ePayloads.ComputeSha256Hex(File.ReadAllBytes(call.FileName));
            return new ProcessResult(0, "ok", "");
        });

        var toctouSafeRes = await pipe.Client.RunBiosInstallerAsync(new BiosAgentInstallRequest(
            "hp", BiosAgentInstallModes.HpSoftPaq, filePath, ExpectedSha256: cleanSha, AllowReboot: false));
        Assert.True(toctouSafeRes.Allowed, toctouSafeRes.Error);
        Assert.True(toctouSafeRes.Executed);
        Assert.NotNull(observedStagedPath);
        Assert.StartsWith(pipe.AgentStagingDir.Path, observedStagedPath!, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(cleanSha, observedStagedSha);
        pipe.AgentStagingDir.AssertEmpty();
    }

    [Fact]
    public async Task E2E_T2_ELV_02_AgentSideUncNetworkTraversalAndNonRegularPathRejection()
    {
        await using var pipe = await LiveAgentPipeFixture.StartAsync();
        using var dir = new IsolatedStagingDir("elv02-paths");

        // Create a real directory named "dir.exe" to exercise regular-file enforcement
        var fakeDirExe = Path.Combine(dir.Path, "dir.exe");
        Directory.CreateDirectory(fakeDirExe);
        var missingFile = Path.Combine(dir.Path, "missing.exe");
        var traversalPath = Path.Combine(dir.Path, "sub", "..", "bios.exe");

        var badPaths = new (string PathValue, string ExpectedErrorToken)[]
        {
            (@"\\evil-server\share\bios.exe", "UNC"),
            ("//evil-server/share/bios.exe", "UNC"),
            (@"\\?\UNC\evil\share\bios.exe", "UNC"),
            (@"\??\C:\bios.exe", "UNC"),
            (@"..\bios.exe", "fully qualified"),
            ("bios.exe", "fully qualified"),
            (traversalPath, "traversal"),
            (missingFile, "does not exist"),
            (fakeDirExe, "directory")
        };

        foreach (var (badPath, expectedErrorToken) in badPaths)
        {
            var res = await pipe.Client!.RunBiosInstallerAsync(new BiosAgentInstallRequest(
                "dell", BiosAgentInstallModes.DellBiosExe, badPath, AllowReboot: false));
            Assert.False(res.Executed, $"Path should be rejected: {badPath}");
            Assert.False(res.Allowed, $"Path should be disallowed: {badPath}");
            Assert.Contains(expectedErrorToken, res.Error ?? "", StringComparison.OrdinalIgnoreCase);
        }

        Assert.Empty(pipe.AgentProcessLauncher.Calls);
        pipe.AgentStagingDir.AssertEmpty();
    }

    [Fact]
    public async Task E2E_T2_ELV_03_AgentSideShellMetacharactersInPathInfOrBitLockerDriveRejected()
    {
        await using var pipe = await LiveAgentPipeFixture.StartAsync();
        using var dir = new IsolatedStagingDir("elv03-meta");

        // (a) Shell metacharacters / control characters in PackagePath
        var badPackagePaths = new (string PathValue, string ExpectedErrorToken)[]
        {
            (Path.Combine(dir.Path, "bios;calc.exe"), "special characters"),
            (Path.Combine(dir.Path, "bios&whoami.exe"), "special characters"),
            (Path.Combine(dir.Path, "bios|sh.exe"), "special characters"),
            (Path.Combine(dir.Path, "bios>out.exe"), "special characters"),
            (Path.Combine(dir.Path, "bios<in.exe"), "special characters"),
            (Path.Combine(dir.Path, "bios`id`.exe"), "special characters"),
            (Path.Combine(dir.Path, "bios$(id).exe"), "special characters"),
            (Path.Combine(dir.Path, "%COMSPEC%.exe"), "special characters"),
            (Path.Combine(dir.Path, "bios\"q.exe"), "special characters"),
            (Path.Combine(dir.Path, "bios\r\n.exe"), "control characters")
        };

        foreach (var (bad, expectedErrorToken) in badPackagePaths)
        {
            var res = await pipe.Client!.RunBiosInstallerAsync(new BiosAgentInstallRequest(
                "hp", BiosAgentInstallModes.HpSoftPaq, bad, AllowReboot: false));
            Assert.False(res.Executed);
            Assert.False(res.Allowed);
            Assert.Contains(expectedErrorToken, res.Error ?? "", StringComparison.OrdinalIgnoreCase);
        }

        // (b) Shell metacharacters / traversal in InfRelativePath on Framework CAB mode
        var (cabBytes, cabSha) = E2ePayloads.FrameworkCabCapsule();
        var cabPath = Path.Combine(dir.Path, "fw.cab");
        await File.WriteAllBytesAsync(cabPath, cabBytes);

        foreach (var badInf in new[] { "firmware;calc.inf", "firmware|sh.inf", "../evil.inf", "/abs.inf", "fw\r\n.inf" })
        {
            var res = await pipe.Client!.RunBiosInstallerAsync(new BiosAgentInstallRequest(
                "framework", BiosAgentInstallModes.FrameworkCabCapsule, cabPath, cabSha, AllowReboot: false, InfRelativePath: badInf));
            Assert.False(res.Executed);
            Assert.False(res.Allowed);
            Assert.Contains("INF relative path is invalid", res.Error ?? "", StringComparison.OrdinalIgnoreCase);
        }

        // (c) Malformed BitLocker drive strings
        foreach (var badDrive in new[] { "C:; calc", "C:&whoami", "CC:", "", "   ", @"C:\", "1:" })
        {
            var res = await pipe.Client!.SuspendBitLockerAsync(badDrive);
            Assert.False(res.Suspended);
            Assert.False(res.Allowed);
            Assert.Equal(-1, res.ExitCode);
            Assert.Contains("Invalid system drive", res.Error ?? "", StringComparison.OrdinalIgnoreCase);
        }

        Assert.Empty(pipe.AgentProcessLauncher.Calls);
        pipe.AgentStagingDir.AssertEmpty();
    }

    [Fact]
    public async Task E2E_T2_ELV_04_AgentSideDisallowedFlagsModesAndRebootEnforcement()
    {
        await using var pipe = await LiveAgentPipeFixture.StartAsync();
        using var dir = new IsolatedStagingDir("elv04-modes");
        var (exeBytes, exeSha) = E2ePayloads.BuildDummyBinary("elv04-bin");
        var exePath = Path.Combine(dir.Path, "bios.exe");
        await File.WriteAllBytesAsync(exePath, exeBytes);

        // (a) Unknown / injected InstallMode
        foreach (var badMode in new[] { "dell_bios_exe /c whoami", "custom_shell", "" })
        {
            var res = await pipe.Client!.RunBiosInstallerAsync(new BiosAgentInstallRequest("dell", badMode, exePath, exeSha));
            Assert.False(res.Allowed);
            Assert.False(res.Executed);
        }

        // (b) Vendor-mode mismatch and check-only vendor
        var mismatch = await pipe.Client!.RunBiosInstallerAsync(new BiosAgentInstallRequest("hp", BiosAgentInstallModes.DellBiosExe, exePath, exeSha));
        Assert.False(mismatch.Allowed);
        Assert.False(mismatch.Executed);

        var checkOnly = await pipe.Client.RunBiosInstallerAsync(new BiosAgentInstallRequest("asus", BiosAgentInstallModes.DellBiosExe, exePath, exeSha));
        Assert.False(checkOnly.Allowed);
        Assert.False(checkOnly.Executed);

        // (c) InfRelativePath rejected on non-CAB mode
        var badInfMode = await pipe.Client.RunBiosInstallerAsync(new BiosAgentInstallRequest("dell", BiosAgentInstallModes.DellBiosExe, exePath, exeSha, InfRelativePath: "firmware.inf"));
        Assert.False(badInfMode.Allowed);
        Assert.False(badInfMode.Executed);

        // (d) Raw OpRunCommand arbitrary shell rejected by AdminCommandAllowlist
        var shellResp = await pipe.Client.RunCommandAsync("cmd.exe", ["/c", "whoami"], TimeSpan.FromSeconds(5), CancellationToken.None);
        Assert.False(shellResp.Allowed);
        Assert.False(shellResp.Ok);
        var shellElevated = await pipe.Client.RunElevatedAsync("cmd.exe", ["/c", "whoami"], TimeSpan.FromSeconds(5), CancellationToken.None);
        Assert.Null(shellElevated);

        Assert.Empty(pipe.AgentProcessLauncher.Calls);

        // (e) Valid AllowReboot=false enforces canonical flags on Agent
        var hpOk = await pipe.Client.RunBiosInstallerAsync(new BiosAgentInstallRequest("hp", BiosAgentInstallModes.HpSoftPaq, exePath, exeSha, AllowReboot: false));
        Assert.True(hpOk.Allowed);
        Assert.True(hpOk.Executed);
        var hpCall = pipe.AgentProcessLauncher.Calls[^1];
        Assert.Equal(["-s"], hpCall.Arguments);
    }

    [Fact]
    public async Task E2E_T2_ELV_05_AgentSideUnsignedExecutableAndNonAllowlistedToolRejection()
    {
        await using var pipe = await LiveAgentPipeFixture.StartAsync(agentSignatureResult: false, createAllowlistedDcuTool: true);
        using var dir = new IsolatedStagingDir("elv05-unsigned");

        // (a) Unsigned .exe and .msi rejected even when SHA-256 matches
        var (exeBytes, exeSha) = E2ePayloads.BuildDummyBinary("elv05-exe");
        var exePath = Path.Combine(dir.Path, "sp.exe");
        await File.WriteAllBytesAsync(exePath, exeBytes);

        var exeRes = await pipe.Client!.RunBiosInstallerAsync(new BiosAgentInstallRequest("hp", BiosAgentInstallModes.HpSoftPaq, exePath, exeSha));
        Assert.False(exeRes.Executed);
        Assert.False(exeRes.Allowed);
        Assert.Contains("Authenticode", exeRes.Error ?? "", StringComparison.OrdinalIgnoreCase);

        var (msiBytes, msiSha) = E2ePayloads.BuildDummyBinary("elv05-msi");
        var msiPath = Path.Combine(dir.Path, "surface.msi");
        await File.WriteAllBytesAsync(msiPath, msiBytes);

        var msiRes = await pipe.Client.RunBiosInstallerAsync(new BiosAgentInstallRequest("microsoft", BiosAgentInstallModes.MicrosoftSurfaceMsi, msiPath, msiSha));
        Assert.False(msiRes.Executed);
        Assert.False(msiRes.Allowed);
        Assert.Contains("Authenticode", msiRes.Error ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.Equal(2, pipe.AgentSignatureVerifier.VerifiedFilePaths.Count);

        // (b) DellDcuCli outside allowlisted roots AND sibling-prefix trick rejected BEFORE reaching Authenticode
        var rogueDcu = Path.Combine(dir.Path, "dcu-cli.exe");
        await File.WriteAllBytesAsync(rogueDcu, Encoding.UTF8.GetBytes("ROGUE-DCU"));
        var rogueRes = await pipe.Client.RunBiosInstallerAsync(new BiosAgentInstallRequest("dell", BiosAgentInstallModes.DellDcuCli, rogueDcu));
        Assert.False(rogueRes.Executed);
        Assert.False(rogueRes.Allowed);
        Assert.Contains("allowlisted", rogueRes.Error ?? "", StringComparison.OrdinalIgnoreCase);

        var siblingRoot = pipe.AllowedToolRoots[0] + "Evil";
        var siblingDir = Path.Combine(siblingRoot, "Dell", "CommandUpdate");
        Directory.CreateDirectory(siblingDir);
        try
        {
            var siblingDcu = Path.Combine(siblingDir, "dcu-cli.exe");
            await File.WriteAllBytesAsync(siblingDcu, Encoding.UTF8.GetBytes("SIBLING-DCU"));
            var siblingRes = await pipe.Client.RunBiosInstallerAsync(new BiosAgentInstallRequest("dell", BiosAgentInstallModes.DellDcuCli, siblingDcu));
            Assert.False(siblingRes.Executed);
            Assert.False(siblingRes.Allowed);
            Assert.Contains("allowlisted", siblingRes.Error ?? "", StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            try { Directory.Delete(siblingRoot, recursive: true); } catch { }
        }

        // Neither rogue nor sibling-prefix DCU paths ever reached Agent Authenticode verification
        Assert.Equal(2, pipe.AgentSignatureVerifier.VerifiedFilePaths.Count);
        Assert.Empty(pipe.AgentProcessLauncher.Calls);
        pipe.AgentStagingDir.AssertEmpty();
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task E2E_T2_ELV_06_UnElevatedHostWithDisconnectedOrNullBridgeFailsCleanly(bool registerDisconnectedBridge)
    {
        var identity = E2eIdentities.DellLatitude();
        var (pkgBytes, sha256) = E2ePayloads.BuildDummyBinary("elv06-nobridge");
        const string url = "https://downloads.dell.com/FOLDER1/Latitude_1.18.0.exe";

        await using var host = await BiosE2eTestHost.CreateAsync(new BiosE2eHostOptions
        {
            InitialIdentity = identity,
            IsProcessElevated = false,
            IsAdminHelperConnected = false,
            UseDisconnectedBridge = registerDisconnectedBridge,
            UseHermeticRealSafetyProbe = true
        });
        host.HttpHandler.MapBytes(url, pkgBytes);

        var target = BiosLatestInfo.UpdateAvailable("dell", "1.18.0", downloadUrl: url, sha256: sha256);
        var req = new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: true, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path);

        // (a) Through IBiosUpdateService -> BlockedByPrerequisites (0 downloads, 0 local calls)
        var serviceRes = await host.Service.InstallUpdateAsync(req);
        Assert.False(serviceRes.Succeeded);
        Assert.Equal(BiosInstallStatus.BlockedByPrerequisites, serviceRes.Status);
        Assert.Contains("Administrator", serviceRes.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(host.HttpHandler.Requests);
        Assert.Empty(host.HostProcessLauncher.Calls);

        // (b) Direct provider invocation (both SuspendBitLocker=true & false, plus WindowsUpdate) -> fails cleanly with 0 local launches
        var dellProvider = Assert.Single(host.Service.Providers, p => p.VendorId == "dell");
        var directSuspendTrue = await dellProvider.InstallAsync(req);
        Assert.False(directSuspendTrue.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, directSuspendTrue.Status);
        Assert.Equal(SystemCommandRunner.AgentFailedExitCode, directSuspendTrue.ExitCode);

        var directSuspendFalse = await dellProvider.InstallAsync(req with { SuspendBitLocker = false });
        Assert.False(directSuspendFalse.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, directSuspendFalse.Status);
        Assert.Equal(SystemCommandRunner.AgentFailedExitCode, directSuspendFalse.ExitCode);

        var wuaProvider = Assert.Single(host.Service.Providers, p => p.VendorId == "windows-update");
        var wuaId = E2eIdentities.GenericPc(firmwareMode: BiosFirmwareMode.Uefi);
        var wuaRes = await wuaProvider.InstallAsync(new BiosInstallRequest(
            wuaId, wuaId.CurrentBios, BiosLatestInfo.UpdateAvailable("windows-update", "2.0", packageId: Guid.NewGuid().ToString("D")), Approved: true));
        Assert.False(wuaRes.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, wuaRes.Status);
        Assert.Equal(SystemCommandRunner.AgentFailedExitCode, wuaRes.ExitCode);

        Assert.Empty(host.HostProcessLauncher.Calls);
        Assert.Empty(host.WindowsUpdateClient.InstalledUpdateIds);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task E2E_T2_ELV_07_LegacyAgentWithoutBiosPipeOpsFailsCleanlyWithZeroLocalFallback(bool useRealLegacyPipe)
    {
        var identity = E2eIdentities.HpEliteBook();
        var (pkgBytes, sha256) = E2ePayloads.BuildDummyBinary("elv07-legacy");
        const string url = "https://ftp.hp.com/pub/softpaq/sp151234.exe";

        await using var host = await BiosE2eTestHost.CreateAsync(new BiosE2eHostOptions
        {
            InitialIdentity = identity,
            IsProcessElevated = false,
            IsAdminHelperConnected = true,
            UseLegacyAgentPipe = useRealLegacyPipe,
            UseMinimalLegacyBridge = !useRealLegacyPipe,
            UseHermeticRealSafetyProbe = true
        });
        host.HttpHandler.MapBytes(url, pkgBytes);

        // Direct bridge check on real legacy pipe throws AdminRequiredException
        if (useRealLegacyPipe)
        {
            await Assert.ThrowsAsync<AdminRequiredException>(() => host.LivePipe!.Client!.SuspendBitLockerAsync("C:"));
            await Assert.ThrowsAsync<AdminRequiredException>(() => host.LivePipe!.Client!.InstallBiosWindowsUpdateAsync(Guid.NewGuid()));
        }

        // Through IBiosUpdateService -> fails cleanly, NEVER falls back to un-elevated local execution
        var target = BiosLatestInfo.UpdateAvailable("hp", "01.14.00", downloadUrl: url, sha256: sha256);
        var res = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: true, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));

        Assert.False(res.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, res.Status);
        Assert.Empty(host.HostProcessLauncher.Calls);
    }

    [Fact]
    public async Task E2E_T2_ELV_08_AgentSideNonGuidWuaUpdateIdRejectedAndPipeSerialNumberRedacted()
    {
        // (a) Raw wire frames with invalid WUA UpdateId rejected by AdminPipeServer with 0 WUA calls
        var badIds = new string?[]
        {
            null,
            "",
            "not-a-guid",
            "00000000-0000-0000-0000-000000000000",
            "748279c7-4309-452c-8b30-e02ec52e498f;calc",
            "{748279c7-4309-452c-8b30-e02ec52e498f}"
        };

        foreach (var badId in badIds)
        {
            await using var rawPipe = await LiveAgentPipeFixture.StartAsync(connectClient: false);
            var resp = await rawPipe.SendRawFrameAsync(new AdminPipeRequest(
                AdminPipeFraming.OpBiosInstallWua,
                TimeoutMs: 30_000,
                BiosWuaUpdateId: badId));

            Assert.False(resp.Ok, $"Expected rejection for BiosWuaUpdateId='{badId}'.");
            Assert.False(resp.Allowed, $"Expected Allowed=false for BiosWuaUpdateId='{badId}'.");
            Assert.NotNull(resp.BiosWuaOutcome);
            Assert.False(resp.BiosWuaOutcome.Succeeded);
            Assert.Empty(rawPipe.AgentWuaApi.SearchQueries);
        }

        // (b) SerialNumber redaction end-to-end across Host -> Live Agent Pipe -> Returned LogTail/Message
        var identity = E2eIdentities.HpEliteBook(serial: BiosE2eTestHost.CanarySerial);
        var (pkgBytes, sha256) = E2ePayloads.BuildDummyBinary("elv08-pii");
        const string url = "https://ftp.hp.com/pub/softpaq/sp151234.exe";

        await using var host = await BiosE2eTestHost.CreateAsync(new BiosE2eHostOptions
        {
            InitialIdentity = identity,
            IsProcessElevated = false,
            UseLiveAgentPipe = true,
            UseHermeticRealSafetyProbe = true
        });
        host.HttpHandler.MapBytes(url, pkgBytes);
        host.LivePipe!.AgentProcessLauncher.OnTool("sp151234.exe",
            new ProcessResult(0, $"Agent stdout echoed {BiosE2eTestHost.CanarySerial}", $"Agent stderr {BiosE2eTestHost.CanarySerial}"));

        var target = BiosLatestInfo.UpdateAvailable("hp", "01.14.00", downloadUrl: url, sha256: sha256);
        var res = await host.Service.InstallUpdateAsync(
            new BiosInstallRequest(identity, identity.CurrentBios, target, Approved: true, SuspendBitLocker: true, AllowReboot: false, VerifyHash: true, StagingDirectory: host.StagingDir.Path));

        Assert.True(res.Succeeded, res.Message);
        Assert.Contains("[REDACTED]", res.LogTail ?? "", StringComparison.Ordinal);
        host.AssertNoSerialNumberLeaked(BiosE2eTestHost.CanarySerial, res);
    }
}
