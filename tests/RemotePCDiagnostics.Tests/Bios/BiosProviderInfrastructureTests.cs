using System.Buffers.Binary;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Xml;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Bios;
using RemotePCDiagnostics.Core.Osquery;

namespace RemotePCDiagnostics.Tests.Bios;

public sealed class BiosProviderInfrastructureTests
{
    private static readonly string[] HpHosts = ["hp.com", "hpcloud.hp.com"];

    // -------------------------------------------------------------------------
    // F2: DefaultBiosInstallSafetyProbe (Pure C# BitLocker probe + parsers)
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData(1, true, false)]
    [InlineData(3, true, false)]
    [InlineData(6, true, false)]
    [InlineData(5, true, true)]
    [InlineData(0, false, false)]
    [InlineData(2, false, false)]
    [InlineData(4, false, false)]
    [InlineData(7, false, false)]
    [InlineData(8, false, false)]
    [InlineData(-1, null, null)]
    [InlineData(9, null, null)]
    [InlineData(99, null, null)]
    public void SafetyProbe_ParseBitLockerProtectionCode_Int_MapsShellCodes(int code, bool? expectedActive, bool? expectedSuspended)
    {
        var (active, suspended) = DefaultBiosInstallSafetyProbe.ParseBitLockerProtectionCode(code);
        Assert.Equal(expectedActive, active);
        Assert.Equal(expectedSuspended, suspended);
    }

    [Theory]
    [InlineData(1, null, true, false)]
    [InlineData(1, 1, true, false)]
    [InlineData(0, 1, true, true)]
    [InlineData(0, 2, true, true)]
    [InlineData(0, 4, true, true)]
    [InlineData(0, 0, false, false)]
    [InlineData(0, 3, false, false)]
    [InlineData(0, 5, false, false)]
    [InlineData(0, null, false, false)]
    [InlineData(2, null, null, null)] // WMI 2 = UNKNOWN (must NOT be confused with Shell 2 = Off)
    [InlineData(2, 1, null, null)]
    [InlineData(99, null, null, null)]
    public void SafetyProbe_ParseWmiBitLockerProtectionStatus_MapsWmiSeparatelyFromShell(
        int protectionStatus,
        int? conversionStatus,
        bool? expectedActive,
        bool? expectedSuspended)
    {
        var (active, suspended) = DefaultBiosInstallSafetyProbe.ParseWmiBitLockerProtectionStatus(protectionStatus, conversionStatus);
        Assert.Equal(expectedActive, active);
        Assert.Equal(expectedSuspended, suspended);
    }

    [Theory]
    [InlineData("C:", "C:")]
    [InlineData("d:", "D:")]
    [InlineData("  e:  ", "E:")]
    [InlineData(null, "C:")]
    [InlineData("", "C:")]
    [InlineData("C:\\", "C:")]
    [InlineData("C:; calc", "C:")]
    [InlineData("1:", "C:")]
    public void SafetyProbe_ResolveSystemDrive_ValidatesAndFallsBackToC(string? raw, string expected)
    {
        Assert.Equal(expected, DefaultBiosInstallSafetyProbe.ResolveSystemDrive(raw));
    }

    [Theory]
    [InlineData(1, true, false)]
    [InlineData(5, true, true)]
    [InlineData(0, false, false)]
    [InlineData(null, null, null)]
    [InlineData(99, null, null)]
    public async Task SafetyProbe_ProbeAsync_UsesInjectedBitLockerProbe(int? code, bool? expectedActive, bool? expectedSuspended)
    {
        var probe = new DefaultBiosInstallSafetyProbe(
            elevation: null,
            commands: null,
            log: null,
            bitLockerProbe: _ => Task.FromResult(code));

        var snap = await probe.ProbeAsync();
        Assert.Equal(expectedActive, snap.BitLockerActive);
        Assert.Equal(expectedSuspended, snap.BitLockerSuspended);
    }

    [Fact]
    public async Task SafetyProbe_ProbeAsync_CatchesNonCancelExceptionAndLogsWarning()
    {
        var log = new CapturedLog();
        var probe = new DefaultBiosInstallSafetyProbe(
            elevation: null,
            commands: null,
            log: log.Logger,
            bitLockerProbe: _ => throw new InvalidOperationException("COM unavailable"));

        var snap = await probe.ProbeAsync();
        Assert.Null(snap.BitLockerActive);
        Assert.Null(snap.BitLockerSuspended);
        Assert.True(log.Contains("COM unavailable"));
    }

    [Fact]
    public async Task SafetyProbe_ProbeAsync_PropagatesCancellationAndSupportsThreeArgCtor()
    {
        var cts = new CancellationTokenSource();
        cts.Cancel();

        var cancellingProbe = new DefaultBiosInstallSafetyProbe(
            bitLockerProbe: ct =>
            {
                ct.ThrowIfCancellationRequested();
                return Task.FromResult<int?>(1);
            });

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancellingProbe.ProbeAsync(cts.Token));

        var legacyCtorProbe = new DefaultBiosInstallSafetyProbe(null, null, null);
        var snap = await legacyCtorProbe.ProbeAsync();
        Assert.NotNull(snap);
    }

    // -------------------------------------------------------------------------
    // F3: BiosProviderHttp (redirects, streaming download, classification)
    // -------------------------------------------------------------------------

    [Fact]
    public async Task ProviderHttp_GetFollowingAllowedRedirects_FollowsAbsoluteRootRelativeAndRelativeHops()
    {
        var handler = new FakeBiosHttpHandler();
        handler.MapRedirect("https://ftp.hp.com/start", "/mid/step2", HttpStatusCode.MovedPermanently);
        handler.MapRedirect("https://ftp.hp.com/mid/step2", "step3.xml", HttpStatusCode.Found);
        handler.MapRedirect("https://ftp.hp.com/mid/step3.xml", "https://cdn.hpcloud.hp.com/final.xml", HttpStatusCode.TemporaryRedirect);
        handler.MapText("https://cdn.hpcloud.hp.com/final.xml", "<ok/>", "application/xml");

        using var client = handler.CreateClient();
        using var response = await BiosProviderHttp.GetFollowingAllowedRedirectsAsync(
            client,
            "https://ftp.hp.com/start",
            HpHosts);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("<ok/>", await response.Content.ReadAsStringAsync());
        Assert.Equal(4, handler.Requests.Count);
    }

    [Fact]
    public async Task ProviderHttp_GetFollowingAllowedRedirects_DisposesIntermediateResponses()
    {
        var intermediate = new TrackingHttpResponseMessage(HttpStatusCode.Found);
        intermediate.Headers.Location = new Uri("https://ftp.hp.com/final");

        var handler = new FakeBiosHttpHandler();
        handler.Map("https://ftp.hp.com/start", (_, _) => Task.FromResult<HttpResponseMessage>(intermediate));
        handler.MapText("https://ftp.hp.com/final", "done");

        using var client = handler.CreateClient();
        using var final = await BiosProviderHttp.GetFollowingAllowedRedirectsAsync(client, "https://ftp.hp.com/start", HpHosts);

        Assert.Equal(HttpStatusCode.OK, final.StatusCode);
        Assert.True(intermediate.WasDisposed);
    }

    [Theory]
    [InlineData("http://ftp.hp.com/file.exe")]
    [InlineData("https://evil.example.com/file.exe")]
    [InlineData("https://user:pass@ftp.hp.com/file.exe")]
    [InlineData("https://ftp.hp.com/bad\\path")]
    public async Task ProviderHttp_GetFollowingAllowedRedirects_RejectsUnsafeInitialUrls(string unsafeUrl)
    {
        var handler = new FakeBiosHttpHandler();
        using var client = handler.CreateClient();

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            BiosProviderHttp.GetFollowingAllowedRedirectsAsync(client, unsafeUrl, HpHosts));
        Assert.Empty(handler.Requests);
    }

    [Theory]
    [InlineData("http://ftp.hp.com/downgrade.exe")]
    [InlineData("https://attacker.example.com/payload.exe")]
    [InlineData("//attacker.example.com/payload.exe")]
    [InlineData(null)]
    public async Task ProviderHttp_GetFollowingAllowedRedirects_RejectsUnsafeRedirectTargets(string? badLocation)
    {
        var handler = new FakeBiosHttpHandler();
        handler.MapRedirect("https://ftp.hp.com/start", badLocation, HttpStatusCode.Found);

        using var client = handler.CreateClient();
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            BiosProviderHttp.GetFollowingAllowedRedirectsAsync(client, "https://ftp.hp.com/start", HpHosts));
    }

    [Fact]
    public async Task ProviderHttp_GetFollowingAllowedRedirects_RejectsLoopAndExcessiveHops()
    {
        var loopHandler = new FakeBiosHttpHandler();
        loopHandler.MapRedirect("https://ftp.hp.com/a", "https://ftp.hp.com/b", HttpStatusCode.Found);
        loopHandler.MapRedirect("https://ftp.hp.com/b", "https://ftp.hp.com/a", HttpStatusCode.Found);

        using var loopClient = loopHandler.CreateClient();
        var loopEx = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            BiosProviderHttp.GetFollowingAllowedRedirectsAsync(loopClient, "https://ftp.hp.com/a", HpHosts));
        Assert.Contains("loop", loopEx.Message, StringComparison.OrdinalIgnoreCase);

        var chainHandler = new FakeBiosHttpHandler();
        chainHandler.MapRedirect("https://ftp.hp.com/0", "https://ftp.hp.com/1", HttpStatusCode.Found);
        chainHandler.MapRedirect("https://ftp.hp.com/1", "https://ftp.hp.com/2", HttpStatusCode.Found);
        chainHandler.MapRedirect("https://ftp.hp.com/2", "https://ftp.hp.com/3", HttpStatusCode.Found);
        chainHandler.MapText("https://ftp.hp.com/3", "ok");

        using var chainClient = chainHandler.CreateClient();
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            BiosProviderHttp.GetFollowingAllowedRedirectsAsync(chainClient, "https://ftp.hp.com/0", HpHosts, maxRedirects: 2));
    }

    [Fact]
    public async Task ProviderHttp_DownloadToStagingAsync_StreamsMovesAtomicallyAndReportsProgress()
    {
        using var staging = new TempStagingDir();
        var payload = TestPayload.Random(200_000);
        var handler = new FakeBiosHttpHandler();
        handler.MapBytes("https://ftp.hp.com/pub/softpaq/sp150000.exe?token=abc", payload.Bytes);

        var progress = new SyncProgress<BiosInstallProgress>();
        using var client = handler.CreateClient();

        var result = await BiosProviderHttp.DownloadToStagingAsync(
            client,
            "https://ftp.hp.com/pub/softpaq/sp150000.exe?token=abc",
            HpHosts,
            staging.Path,
            "fallback.exe",
            progress,
            CancellationToken.None);

        Assert.True(result.Succeeded);
        Assert.Equal(payload.Length, result.BytesDownloaded);
        Assert.NotNull(result.FilePath);
        Assert.Equal("sp150000.exe", Path.GetFileName(result.FilePath));
        Assert.True(File.Exists(result.FilePath));
        Assert.Equal(payload.Bytes, await File.ReadAllBytesAsync(result.FilePath));
        Assert.Empty(Directory.GetFiles(staging.Path, "*.part"));
        Assert.NotEmpty(progress.Reports);
        Assert.All(progress.Reports, r =>
        {
            Assert.Equal(BiosInstallStage.Downloading, r.Stage);
            Assert.InRange(r.Percent, 0, 100);
        });
        Assert.Equal(100, progress.Reports[^1].Percent);
    }

    [Fact]
    public async Task ProviderHttp_DownloadToStagingAsync_RejectsOversizeAndZeroByteAndCleansPartFile()
    {
        using var staging = new TempStagingDir();
        var bigPayload = TestPayload.Random(2048);

        var handler = new FakeBiosHttpHandler();
        handler.MapBytes("https://ftp.hp.com/big-known.exe", bigPayload.Bytes, includeContentLength: true);
        handler.MapBytes("https://ftp.hp.com/big-unknown.exe", bigPayload.Bytes, includeContentLength: false);
        handler.MapBytes("https://ftp.hp.com/empty.exe", [], includeContentLength: true);

        using var client = handler.CreateClient();

        var knownOver = await BiosProviderHttp.DownloadToStagingAsync(
            client, "https://ftp.hp.com/big-known.exe", HpHosts, staging.Path, "a.exe", null, CancellationToken.None, maxBytes: 1024);
        Assert.False(knownOver.Succeeded);

        var streamOver = await BiosProviderHttp.DownloadToStagingAsync(
            client, "https://ftp.hp.com/big-unknown.exe", HpHosts, staging.Path, "b.exe", null, CancellationToken.None, maxBytes: 1024);
        Assert.False(streamOver.Succeeded);

        var emptyRes = await BiosProviderHttp.DownloadToStagingAsync(
            client, "https://ftp.hp.com/empty.exe", HpHosts, staging.Path, "c.exe", null, CancellationToken.None);
        Assert.False(emptyRes.Succeeded);

        Assert.Empty(Directory.GetFiles(staging.Path));
    }

    [Fact]
    public void ProviderHttp_ClassifyHttpFailure_HandlesCancellationOfflineAndParseErrors()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        Assert.Throws<OperationCanceledException>(() =>
            BiosProviderHttp.ClassifyHttpFailure("hp", "HP", new OperationCanceledException(cts.Token), cts.Token));

        var timeout = BiosProviderHttp.ClassifyHttpFailure("hp", "HP", new TaskCanceledException("Request timed out"), CancellationToken.None);
        Assert.Equal(BiosCheckStatus.Offline, timeout.Status);

        var net = BiosProviderHttp.ClassifyHttpFailure("hp", "HP", new HttpRequestException("DNS failed"), CancellationToken.None);
        Assert.Equal(BiosCheckStatus.Offline, net.Status);

        var sock = BiosProviderHttp.ClassifyHttpFailure("hp", "HP", new SocketException(), CancellationToken.None);
        Assert.Equal(BiosCheckStatus.Offline, sock.Status);

        var io = BiosProviderHttp.ClassifyHttpFailure("hp", "HP", new IOException("Connection reset"), CancellationToken.None);
        Assert.Equal(BiosCheckStatus.Offline, io.Status);

        var invalidData = BiosProviderHttp.ClassifyHttpFailure("hp", "HP", new InvalidDataException("Bad CAB"), CancellationToken.None);
        Assert.Equal(BiosCheckStatus.Failed, invalidData.Status);

        var json = BiosProviderHttp.ClassifyHttpFailure("hp", "HP", new JsonException("Bad JSON"), CancellationToken.None);
        Assert.Equal(BiosCheckStatus.Failed, json.Status);

        var xml = BiosProviderHttp.ClassifyHttpFailure("hp", "HP", new XmlException("Bad XML"), CancellationToken.None);
        Assert.Equal(BiosCheckStatus.Failed, xml.Status);
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound, BiosCheckStatus.UnsupportedHardware)]
    [InlineData(HttpStatusCode.TooManyRequests, BiosCheckStatus.ProviderUnavailable)]
    [InlineData(HttpStatusCode.InternalServerError, BiosCheckStatus.ProviderUnavailable)]
    [InlineData(HttpStatusCode.BadGateway, BiosCheckStatus.ProviderUnavailable)]
    [InlineData(HttpStatusCode.ServiceUnavailable, BiosCheckStatus.ProviderUnavailable)]
    [InlineData(HttpStatusCode.GatewayTimeout, BiosCheckStatus.ProviderUnavailable)]
    [InlineData(HttpStatusCode.BadRequest, BiosCheckStatus.Failed)]
    [InlineData(HttpStatusCode.Forbidden, BiosCheckStatus.Failed)]
    public void ProviderHttp_ClassifyHttpStatus_MapsExpectedStatus(HttpStatusCode code, BiosCheckStatus expected)
    {
        var result = BiosProviderHttp.ClassifyHttpStatus("hp", "HP", code, "880D");
        Assert.Equal(expected, result.Status);
        Assert.Equal("hp", result.ProviderId);
    }

    // -------------------------------------------------------------------------
    // F4: BiosPackageVerification & WinVerifyTrustSignatureVerifier & WUA contracts
    // -------------------------------------------------------------------------

    [Fact]
    public async Task WinVerifyTrustSignatureVerifier_FailsClosedOnMissingOrNonWindowsAndHonorsCancellation()
    {
        var missingResult = await WinVerifyTrustSignatureVerifier.Instance.VerifyAuthenticodeAsync(
            Path.Combine(Path.GetTempPath(), $"does-not-exist-{Guid.NewGuid():N}.exe"));
        Assert.False(missingResult);

        using var staging = new TempStagingDir();
        var unsignedFile = staging.FilePath("unsigned.exe");
        await File.WriteAllBytesAsync(unsignedFile, [0x4D, 0x5A, 0x00, 0x00]);
        var unsignedResult = await WinVerifyTrustSignatureVerifier.Instance.VerifyAuthenticodeAsync(unsignedFile);
        Assert.False(unsignedResult);

        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            WinVerifyTrustSignatureVerifier.Instance.VerifyAuthenticodeAsync(unsignedFile, cts.Token));
    }

    [Fact]
    public async Task PackageVerification_RejectsDisallowedUrlBeforeNetworkCall()
    {
        var handler = new FakeBiosHttpHandler();
        using var client = handler.CreateClient();
        var log = new CapturedLog();
        var request = BiosIdentityFactory.CreateInstallRequest(downloadUrl: "https://evil.example.com/sp150000.exe");

        var result = await BiosPackageVerification.DownloadAndVerifyAsync(
            client, request, "hp", HpHosts, "sp.exe", new FakeSignatureVerifier(true), null, log.Logger, CancellationToken.None);

        Assert.False(result.Succeeded);
        Assert.Empty(handler.Requests);
        log.AssertDoesNotContainSecret();
    }

    [Fact]
    public async Task PackageVerification_Sha256MatchPassesAndMismatchDeletesFile()
    {
        using var staging = new TempStagingDir();
        var payload = TestPayload.FromString("valid hp bios firmware image");
        var url = "https://ftp.hp.com/pub/softpaq/sp150000.exe";

        var handler = new FakeBiosHttpHandler();
        handler.MapBytes(url, payload.Bytes);
        using var client = handler.CreateClient();

        var log = new CapturedLog();
        var verifier = new FakeSignatureVerifier(false);
        var progress = new SyncProgress<BiosInstallProgress>();

        var goodReq = BiosIdentityFactory.CreateInstallRequest(downloadUrl: url, sha256: payload.Sha256, stagingDirectory: staging.Path);
        var ok = await BiosPackageVerification.DownloadAndVerifyAsync(
            client, goodReq, "hp", HpHosts, "sp.exe", verifier, progress, log.Logger, CancellationToken.None);

        Assert.True(ok.Succeeded);
        Assert.True(ok.VerifiedBySha256);
        Assert.False(ok.VerifiedByAuthenticode);
        Assert.Equal(payload.Sha256, ok.ActualSha256);
        Assert.Equal(0, verifier.CallCount);
        Assert.True(File.Exists(ok.FilePath));
        Assert.Contains(progress.Reports, r => r.Stage == BiosInstallStage.Verifying && r.Percent == 100);

        // Mismatch must delete file immediately
        using var badStaging = new TempStagingDir();
        var badReq = BiosIdentityFactory.CreateInstallRequest(
            downloadUrl: url,
            sha256: new string('0', 64),
            stagingDirectory: badStaging.Path);

        var failed = await BiosPackageVerification.DownloadAndVerifyAsync(
            client, badReq, "hp", HpHosts, "sp.exe", verifier, null, log.Logger, CancellationToken.None);

        Assert.False(failed.Succeeded);
        Assert.Equal(payload.Sha256, failed.ActualSha256);
        Assert.Empty(Directory.GetFiles(badStaging.Path));
        log.AssertDoesNotContainSecret();
    }

    [Fact]
    public async Task PackageVerification_MissingSha256DelegatesToSignatureVerifierAndDeletesOnFailure()
    {
        var payload = TestPayload.FromString("signed vendor installer");
        var url = "https://ftp.hp.com/pub/softpaq/sp150001.exe";

        var handler = new FakeBiosHttpHandler();
        handler.MapBytes(url, payload.Bytes);
        using var client = handler.CreateClient();
        var log = new CapturedLog();

        // Pass with null StagingDirectory (verifies isolated temp staging directory creation)
        var passVerifier = new FakeSignatureVerifier(true);
        var passReq = BiosIdentityFactory.CreateInstallRequest(downloadUrl: url, sha256: null, stagingDirectory: null);
        var passRes = await BiosPackageVerification.DownloadAndVerifyAsync(
            client, passReq, "hp", HpHosts, "sp.exe", passVerifier, null, log.Logger, CancellationToken.None);

        try
        {
            Assert.True(passRes.Succeeded);
            Assert.False(passRes.VerifiedBySha256);
            Assert.True(passRes.VerifiedByAuthenticode);
            Assert.Equal(1, passVerifier.CallCount);
            Assert.NotNull(passRes.FilePath);
            Assert.True(File.Exists(passRes.FilePath));
        }
        finally
        {
            if (passRes.FilePath is not null)
            {
                var dir = Path.GetDirectoryName(passRes.FilePath);
                if (dir is not null && Directory.Exists(dir))
                    Directory.Delete(dir, recursive: true);
            }
        }

        // Fail deletes downloaded file
        using var staging = new TempStagingDir();
        var failVerifier = new FakeSignatureVerifier(false);
        var failReq = BiosIdentityFactory.CreateInstallRequest(downloadUrl: url, sha256: null, stagingDirectory: staging.Path);
        var failRes = await BiosPackageVerification.DownloadAndVerifyAsync(
            client, failReq, "hp", HpHosts, "sp.exe", failVerifier, null, log.Logger, CancellationToken.None);

        Assert.False(failRes.Succeeded);
        Assert.Equal(1, failVerifier.CallCount);
        Assert.Empty(Directory.GetFiles(staging.Path));
        log.AssertDoesNotContainSecret();
    }

    // -------------------------------------------------------------------------
    // F5: BiosBitLockerSuspender
    // -------------------------------------------------------------------------

    [Fact]
    public async Task BitLockerSuspender_SkipsWhenNotRequestedAndInvokesManageBdeWhenRequested()
    {
        var launcher = new RecordingProcessLauncher(_ => new ProcessResult(0, "Protectors disabled", ""));
        var commands = RecordingProcessLauncher.CreateCommandRunner(launcher);
        var progress = new SyncProgress<BiosInstallProgress>();
        var log = new CapturedLog();

        var skipReq = BiosIdentityFactory.CreateInstallRequest(suspendBitLocker: false);
        var skipped = await BiosBitLockerSuspender.SuspendForOneRebootIfRequestedAsync(
            skipReq, commands, progress, log.Logger, CancellationToken.None);
        Assert.False(skipped);
        Assert.Empty(launcher.Calls);
        Assert.Empty(progress.Reports);

        var runReq = BiosIdentityFactory.CreateInstallRequest(suspendBitLocker: true);
        var suspended = await BiosBitLockerSuspender.SuspendForOneRebootIfRequestedAsync(
            runReq, commands, progress, log.Logger, CancellationToken.None, systemDriveOverride: "d:");

        Assert.True(suspended);
        Assert.Single(launcher.Calls);
        var call = launcher.Calls[0];
        Assert.Equal("manage-bde.exe", call.BaseName, ignoreCase: true);
        Assert.Equal(["-protectors", "-disable", "D:", "-RebootCount", "1"], call.Arguments);
        Assert.Contains(progress.Reports, r => r.Stage == BiosInstallStage.SuspendingBitLocker && r.Percent == 0);
        Assert.Contains(progress.Reports, r => r.Stage == BiosInstallStage.SuspendingBitLocker && r.Percent == 100);
    }

    [Fact]
    public async Task BitLockerSuspender_HandlesMaliciousDriveNonZeroAndNullRunnerSafely()
    {
        var launcher = new RecordingProcessLauncher(_ => new ProcessResult(1, "", "Volume not encrypted"));
        var commands = RecordingProcessLauncher.CreateCommandRunner(launcher);
        var req = BiosIdentityFactory.CreateInstallRequest(suspendBitLocker: true);

        var nonZero = await BiosBitLockerSuspender.SuspendForOneRebootIfRequestedAsync(
            req, commands, null, null, CancellationToken.None, systemDriveOverride: "C:; calc.exe");

        Assert.False(nonZero);
        Assert.Single(launcher.Calls);
        Assert.Equal("C:", launcher.Calls[0].Arguments[2]);

        var nullRunner = await BiosBitLockerSuspender.SuspendForOneRebootIfRequestedAsync(
            req, null, null, null, CancellationToken.None);
        Assert.False(nullRunner);
    }

    // -------------------------------------------------------------------------
    // F6: BiosInstallerRunner
    // -------------------------------------------------------------------------

    [Fact]
    public async Task InstallerRunner_MapsExitCodesRedactsSerialNumberAndForwardsWorkingDirectory()
    {
        var req = BiosIdentityFactory.CreateInstallRequest(targetVersion: "01.18.00");
        var rebootCodes = new HashSet<int> { 0, 3010 };
        var completedCodes = new HashSet<int> { 2 };
        var log = new CapturedLog();

        var rebootLauncher = new RecordingProcessLauncher(_ => new ProcessResult(
            3010,
            $"Flashing system serial={BiosIdentityFactory.SentinelSerialNumber.ToLowerInvariant()} complete",
            ""));
        var rebootRes = await BiosInstallerRunner.RunInstallerAsync(
            RecordingProcessLauncher.CreateCommandRunner(rebootLauncher),
            @"C:\Stage\HPBIOSUPDREC64.exe",
            ["-s", "-r"],
            req,
            bitLockerSuspended: true,
            rebootSuccessExitCodes: rebootCodes,
            completedSuccessExitCodes: completedCodes,
            timeout: TimeSpan.FromMinutes(5),
            log: log.Logger,
            ct: CancellationToken.None,
            workingDirectory: @"C:\Stage");

        Assert.True(rebootRes.Succeeded);
        Assert.Equal(BiosInstallStatus.StagedForReboot, rebootRes.Status);
        Assert.True(rebootRes.RequiresReboot);
        Assert.True(rebootRes.BitLockerSuspended);
        Assert.Equal(3010, rebootRes.ExitCode);
        Assert.NotNull(rebootRes.LogTail);
        Assert.Contains("[REDACTED]", rebootRes.LogTail);
        Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, rebootRes.LogTail, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(@"C:\Stage", rebootLauncher.Calls[0].WorkingDirectory);
        log.AssertDoesNotContainSecret();

        var completedLauncher = new RecordingProcessLauncher(_ => new ProcessResult(2, "Applied live", ""));
        var completedRes = await BiosInstallerRunner.RunInstallerAsync(
            RecordingProcessLauncher.CreateCommandRunner(completedLauncher),
            "flash.exe",
            ["-s"],
            req,
            bitLockerSuspended: false,
            rebootSuccessExitCodes: rebootCodes,
            completedSuccessExitCodes: completedCodes,
            timeout: TimeSpan.FromMinutes(5),
            log: log.Logger,
            ct: CancellationToken.None);

        Assert.True(completedRes.Succeeded);
        Assert.Equal(BiosInstallStatus.Completed, completedRes.Status);
        Assert.False(completedRes.RequiresReboot);

        var failLauncher = new RecordingProcessLauncher(_ => new ProcessResult(1603, "", "Fatal error"));
        var failRes = await BiosInstallerRunner.RunInstallerAsync(
            RecordingProcessLauncher.CreateCommandRunner(failLauncher),
            "flash.exe",
            ["-s"],
            req,
            bitLockerSuspended: true,
            rebootSuccessExitCodes: rebootCodes,
            completedSuccessExitCodes: completedCodes,
            timeout: TimeSpan.FromMinutes(5),
            log: log.Logger,
            ct: CancellationToken.None);

        Assert.False(failRes.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, failRes.Status);
        Assert.True(failRes.BitLockerSuspended);
        Assert.Equal(1603, failRes.ExitCode);

        var timeoutLauncher = new RecordingProcessLauncher(_ => new ProcessResult(-1, "", "", TimedOut: true));
        var timeoutRes = await BiosInstallerRunner.RunInstallerAsync(
            RecordingProcessLauncher.CreateCommandRunner(timeoutLauncher),
            "flash.exe",
            ["-s"],
            req,
            bitLockerSuspended: true,
            rebootSuccessExitCodes: rebootCodes,
            completedSuccessExitCodes: null,
            timeout: TimeSpan.FromSeconds(5),
            log: log.Logger,
            ct: CancellationToken.None);

        Assert.False(timeoutRes.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, timeoutRes.Status);
        Assert.True(timeoutRes.BitLockerSuspended);
        Assert.Null(timeoutRes.ExitCode);
    }

    [Fact]
    public void InstallerRunner_BuildSanitizedLogTail_TruncatesAndRedactsSafely()
    {
        var longOut = new string('A', 300) + BiosIdentityFactory.SentinelSerialNumber + "END";
        var tail = BiosInstallerRunner.BuildSanitizedLogTail(longOut, "err", BiosIdentityFactory.SentinelSerialNumber, maxChars: 40);

        Assert.NotNull(tail);
        Assert.True(tail.Length <= 40);
        Assert.StartsWith("...", tail);
        Assert.Contains("[REDACTED]", tail);
        Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, tail, StringComparison.OrdinalIgnoreCase);

        // Short placeholder serial (<3 chars) must not corrupt digits
        var shortSerialTail = BiosInstallerRunner.BuildSanitizedLogTail("Code 01 ok", null, "01");
        Assert.Equal("Code 01 ok", shortSerialTail);
    }

    // -------------------------------------------------------------------------
    // F7: BiosArchiveAndXml (XML, GZip, ZIP, pure C# MS-CAB, expand.exe fallback)
    // -------------------------------------------------------------------------

    [Fact]
    public void ArchiveAndXml_ParseXmlSafe_ParsesValidBomXmlAndBlocksXxeAndOversize()
    {
        var doc = BiosArchiveAndXml.ParseXmlSafe("\uFEFF<Catalog><Bios Version=\"1.2.3\" /></Catalog>");
        Assert.Equal("1.2.3", doc.Root?.Element("Bios")?.Attribute("Version")?.Value);

        using var ms = new MemoryStream(Encoding.UTF8.GetBytes("<Root><Item>ok</Item></Root>"));
        var streamDoc = BiosArchiveAndXml.ParseXmlSafe(ms);
        Assert.Equal("ok", streamDoc.Root?.Element("Item")?.Value);

        const string xxe = """
            <?xml version="1.0"?>
            <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
            <Root>&xxe;</Root>
            """;
        Assert.Throws<XmlException>(() => BiosArchiveAndXml.ParseXmlSafe(xxe));

        var bigXml = "<Root>" + new string('X', 500) + "</Root>";
        Assert.Throws<XmlException>(() => BiosArchiveAndXml.ParseXmlSafe(bigXml, maxCharactersInDocument: 100));
    }

    [Fact]
    public async Task ArchiveAndXml_DecompressGzipBoundedAsync_RoundTripsAndBlocksBombs()
    {
        var raw = Encoding.UTF8.GetBytes(new string('Z', 4096));
        var gz = TestPayload.CreateGzip(raw);

        using var okStream = new MemoryStream(gz);
        var roundTrip = await BiosArchiveAndXml.DecompressGzipBoundedAsync(okStream, maxBytes: 8192);
        Assert.Equal(raw, roundTrip);

        using var bombStream = new MemoryStream(gz);
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            BiosArchiveAndXml.DecompressGzipBoundedAsync(bombStream, maxBytes: 1024));
    }

    [Fact]
    public void ArchiveAndXml_ExtractZipSafe_ExtractsNestedAndBlocksZipSlipSymlinksAndBombs()
    {
        using var dir = new TempStagingDir();
        var goodZip = dir.FilePath("good.zip");
        using (var z = ZipFile.Open(goodZip, ZipArchiveMode.Create))
        {
            z.CreateEntry("sub/");
            var e = z.CreateEntry("sub/bios.bin");
            using var s = e.Open();
            s.Write("BIOSDATA"u8);
        }

        var outDir = dir.FilePath("out");
        var extracted = BiosArchiveAndXml.ExtractZipSafe(goodZip, outDir, maxTotalBytes: 1024);
        Assert.Single(extracted);
        Assert.Equal("BIOSDATA", File.ReadAllText(extracted[0]));

        string[] maliciousNames = ["../evil.txt", "sub/../../evil.txt", "..\\evil.txt", "/abs/evil.txt", "C:\\evil.txt"];
        foreach (var badName in maliciousNames)
        {
            var badZip = dir.FilePath($"bad-{Guid.NewGuid():N}.zip");
            using (var z = ZipFile.Open(badZip, ZipArchiveMode.Create))
            {
                var e = z.CreateEntry(badName);
                using var s = e.Open();
                s.Write("pwn"u8);
            }

            Assert.Throws<InvalidDataException>(() => BiosArchiveAndXml.ExtractZipSafe(badZip, dir.FilePath($"o-{Guid.NewGuid():N}")));
        }

        // Unix symlink entry (0xA000 << 16)
        var symlinkZip = dir.FilePath("symlink.zip");
        using (var z = ZipFile.Open(symlinkZip, ZipArchiveMode.Create))
        {
            var e = z.CreateEntry("link.txt");
            e.ExternalAttributes = unchecked((int)(0xA1FFu << 16));
            using var s = e.Open();
            s.Write("/etc/passwd"u8);
        }
        Assert.Throws<InvalidDataException>(() => BiosArchiveAndXml.ExtractZipSafe(symlinkZip, dir.FilePath("out-sym")));

        // Zip bomb cap
        var bombZip = dir.FilePath("bomb.zip");
        using (var z = ZipFile.Open(bombZip, ZipArchiveMode.Create))
        {
            var e = z.CreateEntry("big.bin");
            using var s = e.Open();
            s.Write(new byte[4096]);
        }
        Assert.Throws<InvalidDataException>(() => BiosArchiveAndXml.ExtractZipSafe(bombZip, dir.FilePath("out-bomb"), maxTotalBytes: 1024));
    }

    [Fact]
    public void ArchiveAndXml_TryExtractCabEntries_ReadsUncompressedMsZipMultiBlockAndReserves()
    {
        var files = new Dictionary<string, byte[]>
        {
            ["Catalog.xml"] = Encoding.UTF8.GetBytes("<Catalog><Pkg>1</Pkg></Catalog>"),
            ["readme.txt"] = Encoding.UTF8.GetBytes("hello cabinet"),
        };

        var rawCab = TestCabBuilder.CreateUncompressed(files);
        Assert.True(BiosArchiveAndXml.TryExtractCabEntries(rawCab, out var rawEntries));
        Assert.Equal(2, rawEntries.Count);
        Assert.Equal(files["Catalog.xml"], rawEntries["Catalog.xml"]);
        Assert.Equal(files["readme.txt"], rawEntries["readme.txt"]);

        // Multi-block MSZIP (>32 KB) with FLAG_RESERVE_PRESENT
        var largeXml = "<Catalog>" + string.Concat(Enumerable.Repeat("<Entry>0123456789ABCDEF</Entry>", 2500)) + "</Catalog>";
        var largeFiles = new Dictionary<string, byte[]>
        {
            ["sub\\CatalogPC.xml"] = Encoding.UTF8.GetBytes(largeXml),
        };
        var mszipCab = TestCabBuilder.CreateMsZip(largeFiles, headerReserve: 12, folderReserve: 4, dataReserve: 2, maxBlockSize: 16384);
        Assert.True(BiosArchiveAndXml.TryExtractCabEntries(mszipCab, out var mszipEntries));
        Assert.Single(mszipEntries);
        Assert.Equal(largeXml, Encoding.UTF8.GetString(mszipEntries["sub/CatalogPC.xml"]));
    }

    [Fact]
    public void ArchiveAndXml_TryExtractCabEntries_ReturnsFalseCleanlyOnLzxCorruptBombAndTraversal()
    {
        var xmlBytes = Encoding.UTF8.GetBytes("<Catalog/>");

        // Unsupported LZX compression (type 3)
        var lzxCab = TestCabBuilder.CreateWithUnsupportedCompression("Catalog.xml", xmlBytes, typeCompress: 3);
        Assert.False(BiosArchiveAndXml.TryExtractCabEntries(lzxCab, out _));

        // Bad signature & truncated input
        Assert.False(BiosArchiveAndXml.TryExtractCabEntries("NOT_A_CAB"u8.ToArray(), out _));
        Assert.False(BiosArchiveAndXml.TryExtractCabEntries(lzxCab[..20], out _));

        // Corrupt MSZIP (overwrite 'C','K' magic)
        var badMsZip = TestCabBuilder.CreateMsZip(new Dictionary<string, byte[]> { ["a.xml"] = xmlBytes });
        var coffCabStart = BinaryPrimitives.ReadUInt32LittleEndian(badMsZip.AsSpan(36));
        badMsZip[coffCabStart + 8] = (byte)'X';
        Assert.False(BiosArchiveAndXml.TryExtractCabEntries(badMsZip, out _));

        // Traversal entry name
        var traversalCab = TestCabBuilder.CreateUncompressed(new Dictionary<string, byte[]> { ["../evil.xml"] = xmlBytes });
        Assert.False(BiosArchiveAndXml.TryExtractCabEntries(traversalCab, out _));

        // Bomb exceeding maxTotalBytes
        var bigCab = TestCabBuilder.CreateUncompressed(new Dictionary<string, byte[]> { ["big.xml"] = new byte[4096] });
        Assert.False(BiosArchiveAndXml.TryExtractCabEntries(bigCab, out _, maxTotalBytes: 1024));
    }

    [Fact]
    public async Task ArchiveAndXml_ExtractXmlFromCabOrPlainAsync_HandlesPlainCabAndLzxFallback()
    {
        const string expectedXml = "<Catalog><Bios>2.0</Bios></Catalog>";

        // Direct UTF-8, UTF-8 BOM, whitespace, UTF-16 LE passthrough
        Assert.Equal(expectedXml, await BiosArchiveAndXml.ExtractXmlFromCabOrPlainAsync(Encoding.UTF8.GetBytes(expectedXml), "hp"));
        var bomBytes = Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes("  " + expectedXml)).ToArray();
        Assert.Equal("  " + expectedXml, await BiosArchiveAndXml.ExtractXmlFromCabOrPlainAsync(bomBytes, "hp"));
        var utf16Bytes = Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes(expectedXml)).ToArray();
        Assert.Equal(expectedXml, await BiosArchiveAndXml.ExtractXmlFromCabOrPlainAsync(utf16Bytes, "dell"));

        // Pure C# MSZIP CAB (does NOT invoke expand.exe)
        var cab = TestCabBuilder.CreateMsZip(new Dictionary<string, byte[]> { ["CatalogPC.xml"] = Encoding.UTF8.GetBytes(expectedXml) });
        var unusedLauncher = new RecordingProcessLauncher(_ => new ProcessResult(0, "", ""));
        var unusedCommands = RecordingProcessLauncher.CreateCommandRunner(unusedLauncher);
        var fromCab = await BiosArchiveAndXml.ExtractXmlFromCabOrPlainAsync(cab, "dell", unusedCommands);
        Assert.Equal(expectedXml, fromCab);
        Assert.Empty(unusedLauncher.Calls);

        // Pure C# CAB with NO .xml entry returns null WITHOUT calling expand.exe
        var noXmlCab = TestCabBuilder.CreateUncompressed(new Dictionary<string, byte[]> { ["notes.txt"] = "hi"u8.ToArray() });
        Assert.Null(await BiosArchiveAndXml.ExtractXmlFromCabOrPlainAsync(noXmlCab, "dell", unusedCommands));
        Assert.Empty(unusedLauncher.Calls);

        // Non-XML, non-CAB garbage returns null WITHOUT calling expand.exe
        Assert.Null(await BiosArchiveAndXml.ExtractXmlFromCabOrPlainAsync("random binary"u8.ToArray(), "dell", unusedCommands));
        Assert.Empty(unusedLauncher.Calls);

        // LZX CAB with null commands -> null
        var lzxCab = TestCabBuilder.CreateWithUnsupportedCompression("CatalogPC.xml", Encoding.UTF8.GetBytes(expectedXml), typeCompress: 3);
        Assert.Null(await BiosArchiveAndXml.ExtractXmlFromCabOrPlainAsync(lzxCab, "dell", commands: null));

        // LZX CAB with scripted expand.exe launcher -> writes XML into outDir, returns it, and cleans tempDir
        string? observedOutDir = null;
        var expandLauncher = new RecordingProcessLauncher(call =>
        {
            observedOutDir = call.Arguments[2];
            File.WriteAllText(Path.Combine(observedOutDir, "CatalogPC.xml"), expectedXml, Encoding.UTF8);
            return new ProcessResult(0, "Expanded 1 file", "");
        });
        var expandCommands = RecordingProcessLauncher.CreateCommandRunner(expandLauncher);
        var expanded = await BiosArchiveAndXml.ExtractXmlFromCabOrPlainAsync(lzxCab, "dell", expandCommands);

        Assert.Equal(expectedXml, expanded);
        Assert.Single(expandLauncher.Calls);
        Assert.Equal("expand.exe", expandLauncher.Calls[0].BaseName, ignoreCase: true);
        Assert.Equal("-F:*.xml", expandLauncher.Calls[0].Arguments[0]);
        Assert.NotNull(observedOutDir);
        Assert.False(Directory.Exists(Path.GetDirectoryName(observedOutDir)!));
    }

    // -------------------------------------------------------------------------
    // F8: BiosVendorIdentity
    // -------------------------------------------------------------------------

    [Fact]
    public void VendorIdentity_WordBoundaryMatchersAvoidFalsePositives()
    {
        Assert.True(BiosVendorIdentity.IsHp(BiosIdentityFactory.Hp("HP")));
        Assert.True(BiosVendorIdentity.IsHp(BiosIdentityFactory.Hp("Hewlett-Packard")));
        Assert.False(BiosVendorIdentity.IsHp(BiosIdentityFactory.GenericUefi("Ship Corp")));
        Assert.False(BiosVendorIdentity.IsHp(BiosIdentityFactory.GenericUefi("ShopHP LLC")));

        Assert.True(BiosVendorIdentity.IsDell(BiosIdentityFactory.Dell("Dell Inc.")));
        Assert.True(BiosVendorIdentity.IsDell(BiosIdentityFactory.Dell("Alienware")));
        Assert.False(BiosVendorIdentity.IsDell(BiosIdentityFactory.GenericUefi("Odell Systems")));

        Assert.True(BiosVendorIdentity.IsLenovo(BiosIdentityFactory.Lenovo()));
        Assert.True(BiosVendorIdentity.IsAsus(BiosIdentityFactory.Asus()));
        Assert.False(BiosVendorIdentity.IsAsus(BiosIdentityFactory.GenericUefi("Pegasus Corp")));

        Assert.True(BiosVendorIdentity.IsAcer(BiosIdentityFactory.Acer()));
        Assert.False(BiosVendorIdentity.IsAcer(BiosIdentityFactory.GenericUefi("Racer Tech")));

        Assert.True(BiosVendorIdentity.IsMsi(BiosIdentityFactory.Msi()));
        Assert.False(BiosVendorIdentity.IsMsi(BiosIdentityFactory.GenericUefi("CustomSI Inc.")));

        Assert.True(BiosVendorIdentity.IsFramework(BiosIdentityFactory.Framework()));
    }

    [Fact]
    public void VendorIdentity_IsMicrosoftSurface_ExcludesHyperVAndNonSurface()
    {
        Assert.True(BiosVendorIdentity.IsMicrosoftSurface(BiosIdentityFactory.MicrosoftSurface()));
        Assert.False(BiosVendorIdentity.IsMicrosoftSurface(BiosIdentityFactory.HyperVVm()));
        Assert.False(BiosVendorIdentity.IsMicrosoftSurface(BiosIdentityFactory.MicrosoftSurface(model: "Surface Virtual Machine")));
        Assert.False(BiosVendorIdentity.IsMicrosoftSurface(BiosIdentityFactory.GenericUefi("Contoso") with { Model = "Surface Clone" }));
        Assert.False(BiosVendorIdentity.IsMicrosoftSurface(null));
    }

    [Theory]
    [InlineData("8b41", true, "8B41")]
    [InlineData("0x0A5E", true, "0A5E")]
    [InlineData("0Xabcd", true, "ABCD")]
    [InlineData("8B4", false, "")]
    [InlineData("8B410", false, "")]
    [InlineData("8B4Z", false, "")]
    [InlineData("8B41;calc", false, "")]
    [InlineData("", false, "")]
    public void VendorIdentity_TryExtractFourHex_EnforcesStrictAllowlist(string raw, bool expectedOk, string expectedHex)
    {
        var ok = BiosVendorIdentity.TryExtractFourHex(raw, out var hex);
        Assert.Equal(expectedOk, ok);
        Assert.Equal(expectedHex, hex);
    }

    [Fact]
    public void VendorIdentity_TryExtractLenovoMtm_PrioritizesSystemSkuAndRejectsProseOrInjection()
    {
        var skuSystem = BiosIdentityFactory.Lenovo(
            model: "ThinkPad X1 Carbon Gen 9",
            systemSku: "LENOVO_MT_20XW_BU_Think_FM_ThinkPad X1 Carbon Gen 9");
        Assert.True(BiosVendorIdentity.TryExtractLenovoMtm(skuSystem, out var mtm1));
        Assert.Equal("20XW", mtm1);

        var model10 = BiosIdentityFactory.Lenovo(model: "20xw-003gus", systemSku: "");
        Assert.True(BiosVendorIdentity.TryExtractLenovoMtm(model10, out var mtm2));
        Assert.Equal("20XW", mtm2);

        var model4 = BiosIdentityFactory.Lenovo(model: "21cb", systemSku: "");
        Assert.True(BiosVendorIdentity.TryExtractLenovoMtm(model4, out var mtm3));
        Assert.Equal("21CB", mtm3);

        Assert.False(BiosVendorIdentity.TryExtractLenovoMtm(BiosIdentityFactory.Lenovo(model: "ThinkPad X1 Carbon", systemSku: ""), out _));
        Assert.False(BiosVendorIdentity.TryExtractLenovoMtm(BiosIdentityFactory.Lenovo(model: "ThinkBooks", systemSku: ""), out _));
        Assert.False(BiosVendorIdentity.TryExtractLenovoMtm(BiosIdentityFactory.Lenovo(model: "20;X003GUS", systemSku: ""), out _));
        Assert.False(BiosVendorIdentity.TryExtractLenovoMtm(BiosIdentityFactory.Lenovo(model: "", systemSku: "LENOVO_MT_20XW;rm"), out _));
    }

    [Theory]
    [InlineData("ROG STRIX Z690-E GAMING WIFI", true)]
    [InlineData("Surface Laptop 5 13.5/15", true)]
    [InlineData("PRO Z690-A WIFI (MS-7D25)", true)]
    [InlineData("A/../../etc/passwd", false)]
    [InlineData("Model; calc", false)]
    [InlineData("$(whoami)", false)]
    [InlineData("-leading-dash", false)]
    [InlineData("", false)]
    public void VendorIdentity_TrySanitizeModelToken_RejectsTraversalAndInjection(string raw, bool expected)
    {
        var ok = BiosVendorIdentity.TrySanitizeModelToken(raw, out var token);
        Assert.Equal(expected, ok);
        if (expected)
            Assert.Equal(raw.Trim(), token);
    }

    [Theory]
    [InlineData("Microsoft Windows 11 Pro 10.0.22631", true)]
    [InlineData("10.0.22000", true)]
    [InlineData("10.0.26100.123", true)]
    [InlineData("Microsoft Windows 10 Pro 10.0.19045", false)]
    [InlineData("10.0.21999", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void VendorIdentity_IsWindows11_DetectsWin11AndBuild22000(string? osVersion, bool expected)
    {
        Assert.Equal(expected, BiosVendorIdentity.IsWindows11(osVersion));
    }

    [Theory]
    [InlineData("https://ftp.hp.com/pub/softpaq/sp150000.exe?sig=123#frag", "fallback.exe", "sp150000.exe")]
    [InlineData("../../../etc/passwd", "fallback.exe", "passwd")]
    [InlineData("..\\..\\evil.exe", "fallback.exe", "evil.exe")]
    [InlineData("CON.exe", "fallback.exe", "fallback.exe")]
    [InlineData("NUL", "fallback.exe", "fallback.exe")]
    [InlineData("COM1.bin", "fallback.exe", "fallback.exe")]
    [InlineData("...", "fallback.exe", "fallback.exe")]
    [InlineData("", "fallback.exe", "fallback.exe")]
    public void VendorIdentity_SanitizeFileName_SanitizesCrossPlatformAndBlocksReservedNames(string raw, string fallback, string expected)
    {
        Assert.Equal(expected, BiosVendorIdentity.SanitizeFileName(raw, fallback));
    }

    // -------------------------------------------------------------------------
    // Iteration 2 Security, Leak & Hardening Regression Tests
    // -------------------------------------------------------------------------

    [Fact]
    public async Task InstallerRunner_NullWorkingDirectory_NeverLeaksSerialNumberToCommandsLogOrInstallerLog()
    {
        var secretSerial = "5CG-SECRET-SERIAL-98765";
        var req = BiosIdentityFactory.CreateInstallRequest(
            system: BiosIdentityFactory.Hp(serialNumber: secretSerial),
            targetVersion: "01.19.00");
        var rebootCodes = new HashSet<int> { 0, 3010 };

        // Case 1: Normal exit with serial in both stdout and stderr (mixed case), workingDirectory: null
        var commandsLog = new CapturedLog();
        var installerLog = new CapturedLog();
        var normalLauncher = new RecordingProcessLauncher(_ => new ProcessResult(
            0,
            $"HP BIOS Update Utility\nSystem Serial Number: {secretSerial}\nStaged successfully.",
            $"Diagnostic warning for {secretSerial.ToLowerInvariant()}"));
        var normalCommands = RecordingProcessLauncher.CreateCommandRunner(normalLauncher, log: commandsLog.Logger);

        var normalRes = await BiosInstallerRunner.RunInstallerAsync(
            normalCommands,
            "/tmp/sp150000.exe",
            ["-s", "-r"],
            req,
            bitLockerSuspended: false,
            rebootSuccessExitCodes: rebootCodes,
            completedSuccessExitCodes: null,
            timeout: TimeSpan.FromSeconds(10),
            log: installerLog.Logger,
            ct: CancellationToken.None,
            workingDirectory: null);

        Assert.True(normalRes.Succeeded);
        Assert.NotNull(normalRes.LogTail);
        Assert.Contains("[REDACTED]", normalRes.LogTail);
        Assert.DoesNotContain(secretSerial, normalRes.LogTail, StringComparison.OrdinalIgnoreCase);
        commandsLog.AssertDoesNotContainSecret(secretSerial);
        installerLog.AssertDoesNotContainSecret(secretSerial);

        // Case 2: AgentFailure result with serial in both stdout and stderr, workingDirectory: null
        var agentCommandsLog = new CapturedLog();
        var agentInstallerLog = new CapturedLog();
        var agentLauncher = new RecordingProcessLauncher(_ => new ProcessResult(
            SystemCommandRunner.AgentFailedExitCode,
            $"out {secretSerial}",
            $"Agent error for {secretSerial.ToLowerInvariant()}"));
        var agentCommands = RecordingProcessLauncher.CreateCommandRunner(agentLauncher, log: agentCommandsLog.Logger);

        var agentRes = await BiosInstallerRunner.RunInstallerAsync(
            agentCommands,
            "/tmp/sp150000.exe",
            ["-s"],
            req,
            bitLockerSuspended: true,
            rebootSuccessExitCodes: rebootCodes,
            completedSuccessExitCodes: null,
            timeout: TimeSpan.FromSeconds(10),
            log: agentInstallerLog.Logger,
            ct: CancellationToken.None,
            workingDirectory: null);

        Assert.False(agentRes.Succeeded);
        Assert.Equal(SystemCommandRunner.AgentFailedExitCode, agentRes.ExitCode);
        Assert.DoesNotContain(secretSerial, agentRes.Message ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(secretSerial, agentRes.LogTail ?? "", StringComparison.OrdinalIgnoreCase);
        agentCommandsLog.AssertDoesNotContainSecret(secretSerial);
        agentInstallerLog.AssertDoesNotContainSecret(secretSerial);

        // Case 3: Launcher throws exception whose message includes serial number
        var exCommandsLog = new CapturedLog();
        var exInstallerLog = new CapturedLog();
        var exLauncher = new RecordingProcessLauncher((_, _) =>
            Task.FromException<ProcessResult>(new InvalidOperationException($"Launch failed for {secretSerial}")));
        var exCommands = RecordingProcessLauncher.CreateCommandRunner(exLauncher, log: exCommandsLog.Logger);

        var exRes = await BiosInstallerRunner.RunInstallerAsync(
            exCommands,
            "/tmp/sp150000.exe",
            ["-s"],
            req,
            bitLockerSuspended: false,
            rebootSuccessExitCodes: rebootCodes,
            completedSuccessExitCodes: null,
            timeout: TimeSpan.FromSeconds(10),
            log: exInstallerLog.Logger,
            ct: CancellationToken.None,
            workingDirectory: null);

        Assert.False(exRes.Succeeded);
        exCommandsLog.AssertDoesNotContainSecret(secretSerial);
        exInstallerLog.AssertDoesNotContainSecret(secretSerial);
    }

    [Fact]
    public async Task PackageVerificationAndProviderHttp_AutoCreatedTempDirsAreDeletedOnCancelAndFailure()
    {
        var tempRoot = Path.GetTempPath();
        var stageBefore = Directory.GetDirectories(tempRoot, "rpd-bios-stage-*").ToHashSet(StringComparer.Ordinal);
        var dlBefore = Directory.GetDirectories(tempRoot, "rpd-bios-dl-*").ToHashSet(StringComparer.Ordinal);

        // 1. BiosPackageVerification.DownloadAndVerifyAsync with StagingDirectory: null + mid-stream cancellation
        using var cts = new CancellationTokenSource();
        var cancelUrl = "https://ftp.hp.com/pub/softpaq/sp-cancel.exe";
        var cancelHandler = new FakeBiosHttpHandler();
        cancelHandler.Map(cancelUrl, (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new CancellingStreamContent(cts),
        }));
        using var cancelClient = cancelHandler.CreateClient();
        var cancelReq = BiosIdentityFactory.CreateInstallRequest(downloadUrl: cancelUrl, stagingDirectory: null);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            BiosPackageVerification.DownloadAndVerifyAsync(
                cancelClient, cancelReq, "hp", HpHosts, "sp.exe", new FakeSignatureVerifier(true), null, null, cts.Token));

        var leakedStageDirs = Directory.GetDirectories(tempRoot, "rpd-bios-stage-*")
            .Where(d => !stageBefore.Contains(d))
            .ToList();
        Assert.Empty(leakedStageDirs);

        // 2. BiosProviderHttp.DownloadToStagingAsync with empty stagingDir + HTTP 404
        var notFoundUrl = "https://ftp.hp.com/pub/softpaq/sp-missing.exe";
        var notFoundHandler = new FakeBiosHttpHandler();
        notFoundHandler.MapStatus(notFoundUrl, HttpStatusCode.NotFound);
        using var notFoundClient = notFoundHandler.CreateClient();

        var dlResult = await BiosProviderHttp.DownloadToStagingAsync(
            notFoundClient, notFoundUrl, HpHosts, "", "sp.exe", null, CancellationToken.None);

        Assert.False(dlResult.Succeeded);
        Assert.Equal(HttpStatusCode.NotFound, dlResult.StatusCode);

        var leakedDlDirs = Directory.GetDirectories(tempRoot, "rpd-bios-dl-*")
            .Where(d => !dlBefore.Contains(d))
            .ToList();
        Assert.Empty(leakedDlDirs);
    }

    [Fact]
    public void VendorIdentity_SanitizeFileName_BlocksPaddedTruncatedAndSpacedReservedNamesAndStripsDel()
    {
        Assert.Equal("bios-update.bin", BiosVendorIdentity.SanitizeFileName("CON" + new string(' ', 130) + "x.exe"));
        Assert.Equal("bios-update.bin", BiosVendorIdentity.SanitizeFileName("NUL" + new string(' ', 126) + "a.bin"));
        Assert.Equal("bios-update.bin", BiosVendorIdentity.SanitizeFileName("CON .exe"));
        Assert.Equal("bios-update.bin", BiosVendorIdentity.SanitizeFileName("https://dl.hp.com/CON%20.exe"));
        Assert.Equal("bios-update.bin", BiosVendorIdentity.SanitizeFileName("NUL   .bin"));
        Assert.Equal("bios-update.bin", BiosVendorIdentity.SanitizeFileName("COM1 .txt"));
        Assert.Equal("filename.bin", BiosVendorIdentity.SanitizeFileName("file\x7Fname.bin"));
    }

    [Theory]
    [InlineData("None")]
    [InlineData("Yoga")]
    [InlineData("Idea")]
    [InlineData("Flex")]
    public void VendorIdentity_TryExtractLenovoMtm_RejectsFourLetterDigitlessWords(string fourLetterWord)
    {
        var modelOnly = BiosIdentityFactory.Lenovo(model: fourLetterWord, systemSku: "");
        Assert.False(BiosVendorIdentity.TryExtractLenovoMtm(modelOnly, out _));

        var skuFallback = BiosIdentityFactory.Lenovo(model: "ThinkPad X1 Carbon", systemSku: fourLetterWord);
        Assert.False(BiosVendorIdentity.TryExtractLenovoMtm(skuFallback, out _));
    }

    [Fact]
    public void ArchiveAndXml_ExtractZipSafe_RejectsPreExistingSymlinkSubdirAndDeletesPartialOnCorruptDeflate()
    {
        using var dir = new TempStagingDir();

        // 1. Pre-existing directory symlink inside destinationDir must be rejected without writing outside
        var outsideDir = dir.FilePath("outside");
        var extractDir = dir.FilePath("dest");
        Directory.CreateDirectory(outsideDir);
        Directory.CreateDirectory(extractDir);
        Directory.CreateSymbolicLink(Path.Combine(extractDir, "sub"), outsideDir);

        var symlinkSubdirZip = dir.FilePath("sub-escape.zip");
        using (var z = ZipFile.Open(symlinkSubdirZip, ZipArchiveMode.Create))
        {
            var e = z.CreateEntry("sub/pwned.txt");
            using var s = e.Open();
            s.Write("escaped"u8);
        }

        Assert.Throws<InvalidDataException>(() => BiosArchiveAndXml.ExtractZipSafe(symlinkSubdirZip, extractDir));
        Assert.False(File.Exists(Path.Combine(outsideDir, "pwned.txt")));
        Assert.Empty(Directory.GetFiles(outsideDir));

        // 2. Corrupt deflate stream throws InvalidDataException and deletes partial/0-byte file on disk
        var corruptZip = dir.FilePath("corrupt.zip");
        using (var z = ZipFile.Open(corruptZip, ZipArchiveMode.Create))
        {
            var e = z.CreateEntry("partial.bin", CompressionLevel.Optimal);
            using var s = e.Open();
            var content = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("BIOS-PAYLOAD-DATA-", 256)));
            s.Write(content, 0, content.Length);
        }

        var zipBytes = File.ReadAllBytes(corruptZip);
        var fileNameLen = BinaryPrimitives.ReadUInt16LittleEndian(zipBytes.AsSpan(26));
        var extraLen = BinaryPrimitives.ReadUInt16LittleEndian(zipBytes.AsSpan(28));
        var deflateStart = 30 + fileNameLen + extraLen;
        zipBytes[deflateStart] = 0x06; // RFC 1951 invalid deflate block type 11 (btype = 3)
        zipBytes[deflateStart + 1] = 0xFF;
        File.WriteAllBytes(corruptZip, zipBytes);

        var corruptOutDir = dir.FilePath("corrupt-out");
        Assert.Throws<InvalidDataException>(() => BiosArchiveAndXml.ExtractZipSafe(corruptZip, corruptOutDir));
        Assert.False(File.Exists(Path.Combine(corruptOutDir, "partial.bin")));
        Assert.Empty(Directory.GetFiles(corruptOutDir));
    }

    [Fact]
    public async Task ArchiveAndXml_CabMalformedZeroFilesLeadingSlashAndMaxByteHardening()
    {
        // 1. Malformed cFiles == 0 CAB with FLAG_RESERVE_PRESENT and impossible cbCFHeader = 0xFFFF
        var malformedZeroFilesCab = new byte[40];
        "MSCF"u8.CopyTo(malformedZeroFilesCab);
        BinaryPrimitives.WriteUInt32LittleEndian(malformedZeroFilesCab.AsSpan(8), 40);      // cbCabinet
        BinaryPrimitives.WriteUInt32LittleEndian(malformedZeroFilesCab.AsSpan(16), 36);     // coffFiles
        malformedZeroFilesCab[24] = 3;                                                      // versionMinor
        malformedZeroFilesCab[25] = 1;                                                      // versionMajor
        BinaryPrimitives.WriteUInt16LittleEndian(malformedZeroFilesCab.AsSpan(26), 1);      // cFolders
        BinaryPrimitives.WriteUInt16LittleEndian(malformedZeroFilesCab.AsSpan(28), 0);      // cFiles = 0
        BinaryPrimitives.WriteUInt16LittleEndian(malformedZeroFilesCab.AsSpan(30), 0x0004); // FLAG_RESERVE_PRESENT
        BinaryPrimitives.WriteUInt16LittleEndian(malformedZeroFilesCab.AsSpan(36), 0xFFFF); // cbCFHeader = 65535 (invalid)

        Assert.False(BiosArchiveAndXml.TryExtractCabEntries(malformedZeroFilesCab, out _));

        // 2. Leading slash CAB entry "/evil.xml" and "\\evil.xml" rejected
        var leadingSlashCab = TestCabBuilder.CreateUncompressed(new Dictionary<string, byte[]>
        {
            ["/evil.xml"] = "<Catalog/>"u8.ToArray(),
        });
        Assert.False(BiosArchiveAndXml.TryExtractCabEntries(leadingSlashCab, out _));

        var leadingBackslashCab = TestCabBuilder.CreateUncompressed(new Dictionary<string, byte[]>
        {
            ["\\evil.xml"] = "<Catalog/>"u8.ToArray(),
        });
        Assert.False(BiosArchiveAndXml.TryExtractCabEntries(leadingBackslashCab, out _));

        // 3. DecompressGzipBoundedAsync with maxBytes == long.MaxValue does not overflow remaining + 1
        var raw = Encoding.UTF8.GetBytes("hello-max-long");
        var gz = TestPayload.CreateGzip(raw);
        using var gzStream = new MemoryStream(gz);
        var decompressed = await BiosArchiveAndXml.DecompressGzipBoundedAsync(gzStream, maxBytes: long.MaxValue);
        Assert.Equal(raw, decompressed);

        // 4. Plain XML passthrough in ExtractXmlFromCabOrPlainAsync enforces maxDecompressedBytes
        var bigPlainXml = Encoding.UTF8.GetBytes("<Catalog>" + new string('A', 200) + "</Catalog>");
        Assert.Null(await BiosArchiveAndXml.ExtractXmlFromCabOrPlainAsync(bigPlainXml, "hp", maxDecompressedBytes: 64));
    }

    [Fact]
    public void ArchiveAndXml_ExtractZipSafe_RejectsSymlinkedAncestorDirectory()
    {
        var tempRoot = Path.Combine(Path.GetTempPath(), $"rpd-bios-zip-anc-{Guid.NewGuid():N}");
        try
        {
            var outsideDir = Path.Combine(tempRoot, "outside");
            var linkParent = Path.Combine(tempRoot, "link-parent");
            var zipPath = Path.Combine(tempRoot, "pkg.zip");
            Directory.CreateDirectory(outsideDir);
            Directory.CreateSymbolicLink(linkParent, outsideDir);

            using (var archive = ZipFile.Open(zipPath, ZipArchiveMode.Create))
            {
                var entry = archive.CreateEntry("bios.bin");
                using var s = entry.Open();
                s.Write("PAYLOAD"u8);
            }

            var childDest = Path.Combine(linkParent, "newSubdir");
            Assert.Throws<InvalidDataException>(() => BiosArchiveAndXml.ExtractZipSafe(zipPath, childDest));
            Assert.False(Directory.Exists(Path.Combine(outsideDir, "newSubdir")));
            Assert.Empty(Directory.GetFileSystemEntries(outsideDir));

            var deepChildDest = Path.Combine(linkParent, "a", "b", "c");
            Assert.Throws<InvalidDataException>(() => BiosArchiveAndXml.ExtractZipSafe(zipPath, deepChildDest));
            Assert.Empty(Directory.GetFileSystemEntries(outsideDir));
        }
        finally
        {
            if (Directory.Exists(tempRoot))
                Directory.Delete(tempRoot, recursive: true);
        }
    }

    [Fact]
    public async Task ArchiveAndXml_TryExtractCabEntriesWithStatus_DistinguishesUnsupportedCompressionFromUnsafeAndNeverCallsExpandOnUnsafe()
    {
        var xmlBytes = Encoding.UTF8.GetBytes("<Catalog><Bios>3.0</Bios></Catalog>");

        // Valid NONE and MSZIP succeed
        var rawCab = TestCabBuilder.CreateUncompressed(new Dictionary<string, byte[]> { ["Catalog.xml"] = xmlBytes });
        Assert.Equal(CabExtractionStatus.Succeeded, BiosArchiveAndXml.TryExtractCabEntriesWithStatus(rawCab, out var rawEntries));
        Assert.Single(rawEntries);

        var mszipCab = TestCabBuilder.CreateMsZip(new Dictionary<string, byte[]> { ["Catalog.xml"] = xmlBytes });
        Assert.Equal(CabExtractionStatus.Succeeded, BiosArchiveAndXml.TryExtractCabEntriesWithStatus(mszipCab, out var mszipEntries));
        Assert.Single(mszipEntries);

        // Valid LZX (3) and Quantum (2) return UnsupportedCompression
        var lzxCab = TestCabBuilder.CreateWithUnsupportedCompression("Catalog.xml", xmlBytes, typeCompress: 3);
        Assert.Equal(CabExtractionStatus.UnsupportedCompression, BiosArchiveAndXml.TryExtractCabEntriesWithStatus(lzxCab, out _));

        var quantumCab = TestCabBuilder.CreateWithUnsupportedCompression("Catalog.xml", xmlBytes, typeCompress: 2);
        Assert.Equal(CabExtractionStatus.UnsupportedCompression, BiosArchiveAndXml.TryExtractCabEntriesWithStatus(quantumCab, out _));

        // Unsafe CABs — EVEN WHEN FOLDER IS LZX (typeCompress = 3) — MUST return UnsafeOrInvalid and NEVER call expand.exe
        var unsafeCabs = new[]
        {
            TestCabBuilder.CreateUncompressed(new Dictionary<string, byte[]> { ["../../evil.xml"] = xmlBytes }),
            TestCabBuilder.CreateWithUnsupportedCompression("../../evil.xml", xmlBytes, typeCompress: 3),
            TestCabBuilder.CreateWithUnsupportedCompression("/abs.xml", xmlBytes, typeCompress: 3),
            TestCabBuilder.CreateWithUnsupportedCompression("\\abs.xml", xmlBytes, typeCompress: 3),
            TestCabBuilder.CreateWithUnsupportedCompression("C:drive.xml", xmlBytes, typeCompress: 3),
            TestCabBuilder.CreateWithUnsupportedCompression("bad\u0001name.xml", xmlBytes, typeCompress: 3),
            TestCabBuilder.CreateUncompressed(new Dictionary<string, byte[]> { ["bomb.xml"] = new byte[512] }),
            TestCabBuilder.CreateWithUnsupportedCompression("bomb.xml", new byte[512], typeCompress: 3),
            [(byte)'M', (byte)'S', (byte)'C', (byte)'F', 0xFF, 0xFF, 0x01, 0x02],
        };

        var expandLauncher = new RecordingProcessLauncher(_ => new ProcessResult(0, "should never run", ""));
        var expandCommands = RecordingProcessLauncher.CreateCommandRunner(expandLauncher);

        foreach (var badCab in unsafeCabs)
        {
            Assert.Equal(
                CabExtractionStatus.UnsafeOrInvalid,
                BiosArchiveAndXml.TryExtractCabEntriesWithStatus(badCab, out _, maxTotalBytes: 128));

            var extracted = await BiosArchiveAndXml.ExtractXmlFromCabOrPlainAsync(
                badCab,
                "unsafe-test",
                expandCommands,
                maxDecompressedBytes: 128);
            Assert.Null(extracted);
        }

        Assert.Empty(expandLauncher.Calls);

        // Post-expand.exe hardening: if expand.exe drops an XML inside a symlinked subdir, reject it cleanly
        var tempOutside = Path.Combine(Path.GetTempPath(), $"rpd-bios-cab-sym-out-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempOutside);
        try
        {
            var outsideXml = Path.Combine(tempOutside, "evil.xml");
            await File.WriteAllTextAsync(outsideXml, "<Catalog><Bios>9.9</Bios></Catalog>");

            var symlinkExpandLauncher = new RecordingProcessLauncher(call =>
            {
                var outDir = call.Arguments[2];
                Directory.CreateSymbolicLink(Path.Combine(outDir, "linked"), tempOutside);
                return new ProcessResult(0, "ok", "");
            });
            var symlinkCommands = RecordingProcessLauncher.CreateCommandRunner(symlinkExpandLauncher);
            var rejected = await BiosArchiveAndXml.ExtractXmlFromCabOrPlainAsync(lzxCab, "sym-test", symlinkCommands);
            Assert.Null(rejected);
            Assert.Single(symlinkExpandLauncher.Calls);
        }
        finally
        {
            if (Directory.Exists(tempOutside))
                Directory.Delete(tempOutside, recursive: true);
        }
    }

    [Fact]
    public void VendorIdentity_SanitizeFileName_Over128CharsPreservesValidExtensionAndBlocksReservedNames()
    {
        // Long filename with version dots + .exe preserves .exe and stays <= 128 chars
        var longHp = "https://ftp.hp.com/pub/softpaq/HP_EliteBook_840_G10_BIOS_v01.14.00_" + new string('a', 100) + ".exe";
        var sanitizedHp = BiosVendorIdentity.SanitizeFileName(longHp, "fallback.exe");
        Assert.True(sanitizedHp.Length <= 128);
        Assert.Equal(".exe", Path.GetExtension(sanitizedHp));
        Assert.StartsWith("HP_EliteBook_840_G10_BIOS_v01.14.00_", sanitizedHp, StringComparison.Ordinal);

        // Other valid short extensions (.msi, .cab, .zip, .xml) preserved
        foreach (var ext in new[] { ".msi", ".cab", ".zip", ".xml" })
        {
            var longName = "Vendor_Firmware_v2.3.4_" + new string('z', 130) + ext;
            var sanitized = BiosVendorIdentity.SanitizeFileName(longName, "fallback.bin");
            Assert.True(sanitized.Length <= 128);
            Assert.Equal(ext, Path.GetExtension(sanitized));
        }

        // Windows reserved device names remain blocked even after truncation
        Assert.Equal("fallback.exe", BiosVendorIdentity.SanitizeFileName("CON." + new string('a', 140) + ".exe", "fallback.exe"));
        Assert.Equal("fallback.exe", BiosVendorIdentity.SanitizeFileName("CON" + new string('.', 135) + "exe", "fallback.exe"));
        Assert.Equal("fallback.msi", BiosVendorIdentity.SanitizeFileName("NUL   ." + new string('x', 130) + ".msi", "fallback.msi"));

        // Overly-long fake extension (>16 chars) or non-alphanumeric extension is NOT preserved
        var fakeLongExt = "bios." + new string('a', 140);
        var sanitizedFakeLong = BiosVendorIdentity.SanitizeFileName(fakeLongExt, "fallback.bin");
        Assert.Equal(128, sanitizedFakeLong.Length);

        var nonAlnumExt = "bios_" + new string('a', 130) + ".ex_e";
        var sanitizedNonAlnum = BiosVendorIdentity.SanitizeFileName(nonAlnumExt, "fallback.bin");
        Assert.Equal(128, sanitizedNonAlnum.Length);
        Assert.DoesNotContain(".ex_e", sanitizedNonAlnum, StringComparison.Ordinal);

        // Extensionless >128-char filename truncates cleanly to 128
        var noExt = new string('b', 160);
        Assert.Equal(128, BiosVendorIdentity.SanitizeFileName(noExt, "fallback.bin").Length);
    }

    [Fact]
    public async Task Archive_LzxCabWithAdsWhitespaceTraversalWildcardsOrReservedNames_ReturnsUnsafeAndNeverInvokesExpandExe()
    {
        var xmlBytes = Encoding.UTF8.GetBytes("<Catalog><Bios>1.2.3</Bios></Catalog>");
        var unsafeEntryNames = new[]
        {
            "evil.xml:ads",
            "sub/C:evil.xml",
            ".. /evil.xml",
            "sub/ .. /evil.xml",
            ". /evil.xml",
            "sub/evil.xml.",
            "sub/*.xml",
            "sub/evil?.xml",
            "sub/evil|pipe.xml",
            "sub/evil\"quote.xml",
            "sub/<evil>.xml",
            "CON.xml",
            "NUL/evil.xml",
            "PRN.xml",
            "AUX/test.xml",
            "COM1.xml",
            "LPT9/catalog.xml",
        };

        var expandLauncher = new RecordingProcessLauncher(_ => new ProcessResult(0, "should-never-run", ""));
        var expandCommands = RecordingProcessLauncher.CreateCommandRunner(expandLauncher);

        foreach (var badName in unsafeEntryNames)
        {
            var lzxCab = TestCabBuilder.CreateWithUnsupportedCompression(badName, xmlBytes, typeCompress: 3);
            Assert.Equal(
                CabExtractionStatus.UnsafeOrInvalid,
                BiosArchiveAndXml.TryExtractCabEntriesWithStatus(lzxCab, out _));

            var extracted = await BiosArchiveAndXml.ExtractXmlFromCabOrPlainAsync(
                lzxCab,
                "lzx-unsafe-name-test",
                expandCommands);
            Assert.Null(extracted);
        }

        Assert.Empty(expandLauncher.Calls);
    }

    [Fact]
    public async Task Http_Hop0TraversalUrls_RejectedBeforeSendingAnyRequestEvenWith302OrNullRequestMessage()
    {
        var traversalUrls = new[]
        {
            "https://ftp.hp.com/pub/../../secret.exe",
            "https://ftp.hp.com/pub/%2e%2e/secret.exe",
            "https://ftp.hp.com/pub/%252e%252e/secret.exe",
            "https://ftp.hp.com/pub/%5c/evil.exe",
            "https://ftp.hp.com/pub/%00.exe",
            "https://ftp.hp.com/pub/%2f/evil.exe",
        };

        var sentCount = 0;
        var nullReqHandler = new FakeBiosHttpHandler().MapPredicate(_ => true, (_, _) =>
        {
            Interlocked.Increment(ref sentCount);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                RequestMessage = null,
                Content = new ByteArrayContent("payload"u8.ToArray()),
            });
        });

        var redirectHandler = new FakeBiosHttpHandler().MapPredicate(_ => true, (_, _) =>
        {
            Interlocked.Increment(ref sentCount);
            var resp = new HttpResponseMessage(HttpStatusCode.Found);
            resp.Headers.TryAddWithoutValidation("Location", "https://ftp.hp.com/pub/clean.exe");
            return Task.FromResult(resp);
        });

        using var nullReqClient = BiosProviderHttp.CreateClient(nullReqHandler);
        using var redirectClient = BiosProviderHttp.CreateClient(redirectHandler);
        var stage = Path.Combine(Path.GetTempPath(), $"rpd-bios-hop0-{Guid.NewGuid():N}");

        try
        {
            foreach (var badUrl in traversalUrls)
            {
                await Assert.ThrowsAsync<InvalidOperationException>(() =>
                    BiosProviderHttp.GetFollowingAllowedRedirectsAsync(nullReqClient, badUrl, ["hp.com"]));
                await Assert.ThrowsAsync<InvalidOperationException>(() =>
                    BiosProviderHttp.GetFollowingAllowedRedirectsAsync(redirectClient, badUrl, ["hp.com"]));

                var dl1 = await BiosProviderHttp.DownloadToStagingAsync(
                    nullReqClient, badUrl, ["hp.com"], stage, "pkg.exe", null, CancellationToken.None);
                Assert.False(dl1.Succeeded);

                var dl2 = await BiosProviderHttp.DownloadToStagingAsync(
                    redirectClient, badUrl, ["hp.com"], stage, "pkg.exe", null, CancellationToken.None);
                Assert.False(dl2.Succeeded);
            }

            Assert.Equal(0, sentCount);
            Assert.False(Directory.Exists(stage));
        }
        finally
        {
            if (Directory.Exists(stage))
                Directory.Delete(stage, recursive: true);
        }
    }

    [Fact]
    public void Archive_ExtractZipSafe_RejectsAdsTraversalWhitespaceControlWildcardsReservedAndBadDirEntries_WhileAllowingValidDirsAndFiles()
    {
        using var dir = new TempStagingDir();

        var maliciousEntryNames = new[]
        {
            "evil.txt:ads",
            "sub/C:evil.txt",
            ".. /evil.txt",
            "sub/ .. /evil.txt",
            ". /evil.txt",
            "..\u00A0/evil.txt",
            "CON.txt",
            "CON\u00A0.txt",
            "NUL/evil.txt",
            "PRN",
            "AUX",
            "COM1.bin",
            "COM9/evil.txt",
            "LPT1.txt",
            "LPT9/evil.txt",
            "sub/evil.txt.",
            "sub./evil.txt",
            "sub/*.txt",
            "sub/a?b.txt",
            "sub/a|b.txt",
            "sub/a\"b.txt",
            "sub/a<b.txt",
            "sub/a>b.txt",
            "sub/a\tb.txt",
            "sub/a\0b.txt",
            "sub/a\nb.txt",
            "sub/a\u007Fb.txt",
            "CON/",
            "/",
            "//",
            ".. /",
            "a//b/",
            "sub//",
            "sub//file.txt",
        };

        foreach (var badName in maliciousEntryNames)
        {
            var badZip = dir.FilePath($"bad-parity-{Guid.NewGuid():N}.zip");
            using (var z = ZipFile.Open(badZip, ZipArchiveMode.Create))
            {
                var entry = z.CreateEntry(badName);
                if (!badName.EndsWith('/'))
                {
                    using var s = entry.Open();
                    s.Write("pwn"u8);
                }
            }

            var outDir = dir.FilePath($"out-bad-{Guid.NewGuid():N}");
            var ex = Record.Exception(() => BiosArchiveAndXml.ExtractZipSafe(badZip, outDir));
            Assert.True(
                ex is InvalidDataException,
                $"Expected InvalidDataException for ZIP entry '{badName.Replace("\0", "\\0").Replace("\t", "\\t").Replace("\n", "\\n")}', but got {ex?.GetType().FullName ?? "no exception"}.");
            if (Directory.Exists(outDir))
                Assert.Empty(Directory.GetFiles(outDir, "*", SearchOption.AllDirectories));
        }

        // Mixed archive (valid entry followed by malicious entry) must reject before extracting any file
        var mixedZip = dir.FilePath("mixed-bad.zip");
        using (var z = ZipFile.Open(mixedZip, ZipArchiveMode.Create))
        {
            var goodEntry = z.CreateEntry("good.txt");
            using (var s = goodEntry.Open())
                s.Write("ok"u8);

            var badEntry = z.CreateEntry("CON.txt");
            using (var s = badEntry.Open())
                s.Write("pwn"u8);
        }

        var mixedOutDir = dir.FilePath("out-mixed");
        Assert.Throws<InvalidDataException>(() => BiosArchiveAndXml.ExtractZipSafe(mixedZip, mixedOutDir));
        if (Directory.Exists(mixedOutDir))
            Assert.Empty(Directory.GetFiles(mixedOutDir, "*", SearchOption.AllDirectories));

        // Valid files and valid directory entries ("sub/", "a/b/") continue to extract cleanly
        var validZip = dir.FilePath("valid-parity.zip");
        using (var z = ZipFile.Open(validZip, ZipArchiveMode.Create))
        {
            z.CreateEntry("sub/");
            z.CreateEntry("a/b/");

            var e1 = z.CreateEntry("sub/bios.bin");
            using (var s1 = e1.Open())
                s1.Write("BIOS-SUB"u8);

            var e2 = z.CreateEntry("a/b/firmware_v1.2.3.bin");
            using (var s2 = e2.Open())
                s2.Write("BIOS-AB"u8);
        }

        var validOutDir = dir.FilePath("out-valid");
        var extracted = BiosArchiveAndXml.ExtractZipSafe(validZip, validOutDir, maxTotalBytes: 4096);
        Assert.Equal(2, extracted.Count);
        Assert.Equal("BIOS-SUB", File.ReadAllText(Path.Combine(validOutDir, "sub", "bios.bin")));
        Assert.Equal("BIOS-AB", File.ReadAllText(Path.Combine(validOutDir, "a", "b", "firmware_v1.2.3.bin")));
    }

    private sealed class CancellingStreamContent(CancellationTokenSource cts) : HttpContent
    {
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
            Task.FromException(new NotSupportedException());

        protected override Task<Stream> CreateContentReadStreamAsync(CancellationToken cancellationToken) =>
            Task.FromResult<Stream>(new CancellingReadStream(cts));

        protected override bool TryComputeLength(out long length)
        {
            length = 8192;
            return true;
        }
    }

    private sealed class CancellingReadStream(CancellationTokenSource cts) : Stream
    {
        private int _reads;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => 8192;
        public override long Position { get; set; }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_reads++ == 0)
            {
                var n = Math.Min(buffer.Length, 1024);
                buffer[..n].Span.Fill(0x41);
                return ValueTask.FromResult(n);
            }

            cts.Cancel();
            cancellationToken.ThrowIfCancellationRequested();
            throw new OperationCanceledException(cancellationToken);
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class TrackingHttpResponseMessage(HttpStatusCode statusCode) : HttpResponseMessage(statusCode)
    {
        public bool WasDisposed { get; private set; }

        protected override void Dispose(bool disposing)
        {
            WasDisposed = true;
            base.Dispose(disposing);
        }
    }
}
