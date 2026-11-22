using System.Net;
using System.Net.Sockets;
using System.Text;
using RemotePCDiagnostics.Core.Areas;
using RemotePCDiagnostics.Core.Bios;
using RemotePCDiagnostics.Core.Osquery;
using RemotePCDiagnostics.Core.Sensors;
using RemotePCDiagnostics.Core.Session;

namespace RemotePCDiagnostics.Tests.Bios;

public sealed class DellBiosUpdateProviderTests
{
    private static readonly HashSet<string> ForbiddenShellBinaries = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell", "powershell.exe", "pwsh", "pwsh.exe",
        "cmd", "cmd.exe", "sh", "bash", "zsh",
    };

    private static readonly string[] ForbiddenScriptExtensions = [".ps1", ".bat", ".cmd", ".sh"];

    private const string SampleSha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    private const string SampleDellCatalogXml = """
        <?xml version="1.0" encoding="utf-8"?>
        <Manifest baseLocation="downloads.dell.com" releaseID="R12345">
          <SoftwareComponent packageID="DRVR01" path="FOLDER1/audio.exe" vendorVersion="6.0.9500" size="5000000" dateTime="2024-05-01T00:00:00Z">
            <ComponentType value="DRVR"><Display lang="en">Driver</Display></ComponentType>
            <SupportedSystems>
              <Brand key="1"><Model systemID="0B1A"><Display lang="en">Latitude 7430</Display></Model></Brand>
            </SupportedSystems>
          </SoftwareComponent>
          <SoftwareComponent packageID="BIOSLNX" path="FOLDER1/Latitude_7430_1.99.0.bin" vendorVersion="1.99.0" size="25000000" dateTime="2024-08-01T00:00:00Z">
            <ComponentType value="BIOS"><Display lang="en">BIOS</Display></ComponentType>
            <SupportedSystems>
              <Brand key="1"><Model systemID="0B1A"><Display lang="en">Latitude 7430</Display></Model></Brand>
            </SupportedSystems>
          </SoftwareComponent>
          <SoftwareComponent packageID="BIOSOLD" path="FOLDER1/Latitude_7430_1.15.0.exe" vendorVersion="1.15.0" size="22000000" dateTime="2024-01-15T00:00:00Z">
            <ComponentType value="BIOS"><Display lang="en">BIOS</Display></ComponentType>
            <Criticality value="2"><Display lang="en">Recommended</Display></Criticality>
            <SupportedSystems>
              <Brand key="1"><Model systemID="0B1A"><Display lang="en">Latitude 7430</Display></Model></Brand>
            </SupportedSystems>
          </SoftwareComponent>
          <SoftwareComponent packageID="BIOSNEW" path="FOLDER2/Latitude_7430_1.18.0.exe" vendorVersion="1.18.0" size="26214400" dateTime="2024-06-20T00:00:00Z" hashSHA256="ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789">
            <Name><Display lang="en">Dell Latitude 7430 System BIOS</Display></Name>
            <ComponentType value="BIOS"><Display lang="en">BIOS</Display></ComponentType>
            <Criticality value="3"><Display lang="en">Urgent</Display></Criticality>
            <ImportantInfo URL="https://www.dell.com/support/home/drivers/driversdetails?driverId=BIOSNEW" />
            <SupportedSystems>
              <Brand key="1"><Model systemID="0B1A"><Display lang="en">Latitude 7430</Display></Model></Brand>
            </SupportedSystems>
          </SoftwareComponent>
        </Manifest>
        """;

    // -------------------------------------------------------------------------
    // D1 — Metadata & Capabilities
    // -------------------------------------------------------------------------

    [Fact]
    public void Metadata_MatchesContract()
    {
        var provider = new DellBiosUpdateProvider();

        Assert.Equal("dell", provider.VendorId);
        Assert.Equal("Dell", provider.DisplayName);
        Assert.Equal(100, provider.Priority);
        Assert.True(provider.Capabilities.CanCheckLatest);
        Assert.True(provider.Capabilities.CanInstall);
        Assert.True(provider.Capabilities.SupportsSilentInstall);
        Assert.True(provider.Capabilities.RequiresReboot);
        Assert.True(provider.Capabilities.RequiresElevation);
        Assert.True(provider.Capabilities.RequiresInternet);
    }

    // -------------------------------------------------------------------------
    // D2 — CanHandle & GetCurrentVersionAsync
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData("Dell Inc.", "")]
    [InlineData("Dell", "")]
    [InlineData("Alienware", "")]
    [InlineData("Generic OEM", "Dell Inc.")]
    [InlineData("", "Alienware")]
    public void CanHandle_DellAndAlienware_ReturnsTrue(string manufacturer, string boardManufacturer)
    {
        var provider = new DellBiosUpdateProvider();
        var identity = BiosIdentityFactory.Dell(manufacturer: manufacturer) with
        {
            BoardManufacturer = boardManufacturer,
        };

        Assert.True(provider.CanHandle(identity));
    }

    [Theory]
    [InlineData("HP")]
    [InlineData("LENOVO")]
    [InlineData("Dellusion Corp")]
    [InlineData("NotADellCorp")]
    public void CanHandle_NonDell_ReturnsFalse(string manufacturer)
    {
        var provider = new DellBiosUpdateProvider();
        Assert.False(provider.CanHandle(BiosIdentityFactory.GenericUefi(manufacturer)));
    }

    [Fact]
    public void CanHandle_UnknownAndNull_ReturnsFalseWithoutThrowing()
    {
        var provider = new DellBiosUpdateProvider();
        Assert.False(provider.CanHandle(BiosIdentityFactory.Unknown()));
        Assert.False(provider.CanHandle(null!));
    }

    [Fact]
    public async Task GetCurrentVersionAsync_SetsProviderIdAndValidSku_NeverExposesSerialNumber()
    {
        var provider = new DellBiosUpdateProvider();
        var identity = BiosIdentityFactory.Dell(systemSku: "0x0b1a", biosVersion: " 1.14.0 ");

        var current = await provider.GetCurrentVersionAsync(identity);

        Assert.Equal("dell", current.ProviderId);
        Assert.Equal("1.14.0", current.Version);
        Assert.Equal("0B1A", current.Metadata?["systemSku"]);
        Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, string.Join(";", current.Metadata!.Values), StringComparison.OrdinalIgnoreCase);

        var invalidSku = BiosIdentityFactory.Dell(systemSku: "INVALID;calc");
        var currentInvalid = await provider.GetCurrentVersionAsync(invalidSku);
        Assert.True(currentInvalid.Metadata is null || !currentInvalid.Metadata.ContainsKey("systemSku"));
    }

    // -------------------------------------------------------------------------
    // D3 & D4 — Direct HTTPS Catalog (Plain XML & MS-CAB), Multi-Component & UpToDate
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData("plain")]
    [InlineData("cab-none")]
    [InlineData("cab-mszip")]
    public async Task GetLatestVersionAsync_CatalogXmlAndCab_FindsNewestBiosForSku(string encoding)
    {
        var xmlBytes = Encoding.UTF8.GetBytes(SampleDellCatalogXml);
        byte[] payload = encoding switch
        {
            "plain" => xmlBytes,
            "cab-none" => TestCabBuilder.CreateUncompressed(new Dictionary<string, byte[]> { ["CatalogPC.xml"] = xmlBytes }),
            "cab-mszip" => TestCabBuilder.CreateMsZip(new Dictionary<string, byte[]> { ["CatalogPC.xml"] = xmlBytes }),
            _ => throw new ArgumentOutOfRangeException(nameof(encoding)),
        };

        var handler = new FakeBiosHttpHandler()
            .MapBytes(DellBiosUpdateProvider.DefaultCatalogUrl, payload);

        var log = new CapturedLog();
        var provider = DellBiosUpdateProvider.CreateWithHandler(handler, log: log.Logger);
        var identity = BiosIdentityFactory.Dell(systemSku: "0B1A", biosVersion: "1.14.0");

        var latest = await provider.GetLatestVersionAsync(identity, identity.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal("dell", latest.ProviderId);
        Assert.Equal("1.18.0", latest.LatestVersion);
        Assert.Equal(new DateOnly(2024, 6, 20), latest.ReleaseDate);
        Assert.Equal(BiosUpdateSeverity.Critical, latest.Severity);
        Assert.Equal("BIOSNEW", latest.PackageId);
        Assert.Equal("Dell Latitude 7430 System BIOS", latest.ReleaseSummary);
        Assert.Equal("https://downloads.dell.com/FOLDER2/Latitude_7430_1.18.0.exe", latest.DownloadUrl);
        Assert.Equal("https://www.dell.com/support/home/drivers/driversdetails?driverId=BIOSNEW", latest.ReleaseNotesUrl);
        Assert.Equal(SampleSha256, latest.Sha256);
        Assert.Equal(26214400, latest.SizeBytes);
        Assert.Equal(BiosAgentInstallModes.DellBiosExe, latest.Metadata?["installMode"]);
        log.AssertDoesNotContainSecret();
    }

    [Fact]
    public async Task GetLatestVersionAsync_CryptographySha256Element_IsExtracted()
    {
        const string xml = """
            <Manifest baseLocation="downloads.dell.com">
              <SoftwareComponent packageID="A12PKG" path="bios/OptiPlex_A12.exe" dellVersion="A12">
                <ComponentType value="BIOS"/>
                <Cryptography><Hash algorithm="SHA-256">0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef</Hash></Cryptography>
                <SupportedSystems><Brand><Model systemID="0B1A"/></Brand></SupportedSystems>
              </SoftwareComponent>
            </Manifest>
            """;

        var handler = new FakeBiosHttpHandler().MapText(DellBiosUpdateProvider.DefaultCatalogUrl, xml, "application/xml");
        var provider = DellBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Dell(systemSku: "0B1A", biosVersion: "A09");

        var latest = await provider.GetLatestVersionAsync(identity, identity.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal("A12", latest.LatestVersion);
        Assert.Equal("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", latest.Sha256);
    }

    [Fact]
    public async Task GetLatestVersionAsync_CurrentUpToDate_AndUnmatchedSku()
    {
        var handler = new FakeBiosHttpHandler()
            .MapText(DellBiosUpdateProvider.DefaultCatalogUrl, SampleDellCatalogXml, "application/xml");
        var provider = DellBiosUpdateProvider.CreateWithHandler(handler);

        var upToDateId = BiosIdentityFactory.Dell(systemSku: "0B1A", biosVersion: "1.18.0");
        var upToDate = await provider.GetLatestVersionAsync(upToDateId, upToDateId.CurrentBios);
        Assert.Equal(BiosCheckStatus.UpToDate, upToDate.Status);

        var unmatchedId = BiosIdentityFactory.Dell(systemSku: "9999", biosVersion: "1.0.0");
        var unmatched = await provider.GetLatestVersionAsync(unmatchedId, unmatchedId.CurrentBios);
        Assert.Equal(BiosCheckStatus.UnsupportedHardware, unmatched.Status);
    }

    // -------------------------------------------------------------------------
    // D5 & D6 — Invalid SystemSku, HTTP/Network/XXE & Malicious baseLocation/path
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData("")]
    [InlineData("ZZZZ")]
    [InlineData("0B1A; whoami")]
    [InlineData("../../etc")]
    public async Task GetLatestVersionAsync_InvalidOrMaliciousSystemSku_ZeroHttpCalls(string badSku)
    {
        var handler = new FakeBiosHttpHandler();
        var provider = DellBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Dell(systemSku: badSku);

        var latest = await provider.GetLatestVersionAsync(identity, identity.CurrentBios);

        Assert.Equal(BiosCheckStatus.UnsupportedHardware, latest.Status);
        Assert.Empty(handler.Requests);
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound, BiosCheckStatus.UnsupportedHardware)]
    [InlineData(HttpStatusCode.TooManyRequests, BiosCheckStatus.ProviderUnavailable)]
    [InlineData(HttpStatusCode.InternalServerError, BiosCheckStatus.ProviderUnavailable)]
    public async Task GetLatestVersionAsync_HttpStatusMapping(HttpStatusCode status, BiosCheckStatus expected)
    {
        var handler = new FakeBiosHttpHandler().MapStatus(DellBiosUpdateProvider.DefaultCatalogUrl, status);
        var provider = DellBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Dell();

        var latest = await provider.GetLatestVersionAsync(identity, identity.CurrentBios);
        Assert.Equal(expected, latest.Status);
    }

    [Fact]
    public async Task GetLatestVersionAsync_NetworkTimeoutCancelAndXxe()
    {
        var netHandler = new FakeBiosHttpHandler()
            .MapException(DellBiosUpdateProvider.DefaultCatalogUrl, () => new HttpRequestException("offline", new SocketException()));
        var provider = DellBiosUpdateProvider.CreateWithHandler(netHandler);
        var identity = BiosIdentityFactory.Dell();

        Assert.Equal(BiosCheckStatus.Offline, (await provider.GetLatestVersionAsync(identity, identity.CurrentBios)).Status);

        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => provider.GetLatestVersionAsync(identity, identity.CurrentBios, cts.Token));

        const string xxe = """
            <?xml version="1.0"?>
            <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/hosts"> ]>
            <Manifest><SoftwareComponent vendorVersion="&xxe;"/></Manifest>
            """;
        var xxeHandler = new FakeBiosHttpHandler().MapText(DellBiosUpdateProvider.DefaultCatalogUrl, xxe, "application/xml");
        var xxeProvider = DellBiosUpdateProvider.CreateWithHandler(xxeHandler);
        Assert.Equal(BiosCheckStatus.Failed, (await xxeProvider.GetLatestVersionAsync(identity, identity.CurrentBios)).Status);
    }

    [Theory]
    [InlineData("evil.com", "bios/update.exe")]
    [InlineData("http://downloads.dell.com", "bios/update.exe")]
    [InlineData("downloads.dell.com@evil.com", "bios/update.exe")]
    [InlineData("downloads.dell.com", "https://evil.com/update.exe")]
    [InlineData("downloads.dell.com", "//evil.com/update.exe")]
    [InlineData("downloads.dell.com", "../../evil.exe")]
    public async Task GetLatestVersionAsync_UnsafeBaseLocationOrPath_ReturnsFailed(string baseLocation, string path)
    {
        var xml = $"""
            <Manifest baseLocation="{baseLocation}">
              <SoftwareComponent packageID="BAD" path="{path}" vendorVersion="2.0.0">
                <ComponentType value="BIOS"/>
                <SupportedSystems><Brand><Model systemID="0B1A"/></Brand></SupportedSystems>
              </SoftwareComponent>
            </Manifest>
            """;

        var handler = new FakeBiosHttpHandler().MapText(DellBiosUpdateProvider.DefaultCatalogUrl, xml, "application/xml");
        var provider = DellBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Dell();

        var latest = await provider.GetLatestVersionAsync(identity, identity.CurrentBios);

        Assert.Equal(BiosCheckStatus.Failed, latest.Status);
    }

    [Fact]
    public async Task GetLatestVersionAsync_OffDomainRedirect_ReturnsFailed()
    {
        var handler = new FakeBiosHttpHandler()
            .MapRedirect(DellBiosUpdateProvider.DefaultCatalogUrl, "https://evil.com/CatalogPC.cab");
        var provider = DellBiosUpdateProvider.CreateWithHandler(handler);

        var latest = await provider.GetLatestVersionAsync(BiosIdentityFactory.Dell(), BiosIdentityFactory.Dell().CurrentBios);

        Assert.Equal(BiosCheckStatus.Failed, latest.Status);
        Assert.Single(handler.Requests);
    }

    // -------------------------------------------------------------------------
    // D7 — Direct dcu-cli.exe Scan Mode (Pure C# ArgumentList)
    // -------------------------------------------------------------------------

    [Fact]
    public async Task GetLatestVersionAsync_DcuCliScan_ParsesReportAndCleansTempDir()
    {
        string? observedReportDir = null;
        var launcher = CreateGuardedLauncher(async (call, ct) =>
        {
            var reportArg = Assert.Single(call.Arguments, a => a.StartsWith("-report=", StringComparison.Ordinal));
            observedReportDir = reportArg["-report=".Length..];
            const string reportXml = """
                <?xml version="1.0" encoding="utf-8"?>
                <updates>
                  <update>
                    <release>ABC12</release>
                    <name>Dell Latitude 7430 System BIOS</name>
                    <version>1.19.0</version>
                    <date>2024-07-01</date>
                    <urgency>Urgent</urgency>
                    <type>BIOS</type>
                    <category>BI</category>
                    <bytes>27000000</bytes>
                  </update>
                </updates>
                """;
            await File.WriteAllTextAsync(Path.Combine(observedReportDir, "DCUApplicableUpdates.xml"), reportXml, ct);
            return new ProcessResult(0, "Scan complete", "");
        });

        var commands = RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: true);
        var provider = new DellBiosUpdateProvider(
            commands: commands,
            dcuCliPath: @"C:\Program Files\Dell\CommandUpdate\dcu-cli.exe");

        var identity = BiosIdentityFactory.Dell(biosVersion: "1.14.0");
        var latest = await provider.GetLatestVersionAsync(identity, identity.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal("1.19.0", latest.LatestVersion);
        Assert.Equal("ABC12", latest.PackageId);
        Assert.Equal(BiosUpdateSeverity.Critical, latest.Severity);
        Assert.Null(latest.DownloadUrl);
        Assert.Equal(BiosAgentInstallModes.DellDcuCli, latest.Metadata?["installMode"]);

        var call = Assert.Single(launcher.Calls);
        Assert.Equal("dcu-cli.exe", call.BaseName, ignoreCase: true);
        Assert.Equal("/scan", call.Arguments[0]);
        Assert.Equal("-updateType=bios", call.Arguments[1]);
        Assert.Equal("-silent", call.Arguments[2]);
        Assert.NotNull(observedReportDir);
        Assert.False(Directory.Exists(observedReportDir!));
    }

    [Fact]
    public async Task GetLatestVersionAsync_DcuCliExit500_ReturnsUpToDate_AndXxeReturnsFailed()
    {
        var launcher500 = CreateGuardedLauncher((_, _) => Task.FromResult(new ProcessResult(500, "No updates", "")));
        var provider500 = new DellBiosUpdateProvider(
            commands: RecordingProcessLauncher.CreateCommandRunner(launcher500),
            dcuCliPath: @"C:\Program Files\Dell\CommandUpdate\dcu-cli.exe");

        var identity = BiosIdentityFactory.Dell();
        var upToDate = await provider500.GetLatestVersionAsync(identity, identity.CurrentBios);
        Assert.Equal(BiosCheckStatus.UpToDate, upToDate.Status);

        var launcherXxe = CreateGuardedLauncher(async (call, ct) =>
        {
            var reportDir = call.Arguments.Single(a => a.StartsWith("-report=", StringComparison.Ordinal))["-report=".Length..];
            await File.WriteAllTextAsync(
                Path.Combine(reportDir, "DCUApplicableUpdates.xml"),
                """<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><updates><update><type>BIOS</type><version>&xxe;</version></update></updates>""",
                ct);
            return new ProcessResult(0, "", "");
        });
        var providerXxe = new DellBiosUpdateProvider(
            commands: RecordingProcessLauncher.CreateCommandRunner(launcherXxe),
            dcuCliPath: @"C:\Program Files\Dell\CommandUpdate\dcu-cli.exe");

        var failed = await providerXxe.GetLatestVersionAsync(identity, identity.CurrentBios);
        Assert.Equal(BiosCheckStatus.Failed, failed.Status);
    }

    [Theory]
    [InlineData(@"\\evil\share\dcu-cli.exe")]
    [InlineData(@"relative\dcu-cli.exe")]
    [InlineData(@"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")]
    [InlineData(@"C:\Program Files\Dell\CommandUpdate\dcu-cli.exe;calc.exe")]
    [InlineData(@"C:\Program Files\Dell\..\CommandUpdate\dcu-cli.exe")]
    public async Task GetLatestVersionAsync_InvalidDcuCliPath_FailsWithZeroProcessCalls(string badPath)
    {
        var launcher = CreateGuardedLauncher();
        var provider = new DellBiosUpdateProvider(
            commands: RecordingProcessLauncher.CreateCommandRunner(launcher),
            dcuCliPath: badPath);

        var latest = await provider.GetLatestVersionAsync(BiosIdentityFactory.Dell(), BiosIdentityFactory.Dell().CurrentBios);

        Assert.Equal(BiosCheckStatus.Failed, latest.Status);
        Assert.Empty(launcher.Calls);
    }

    // -------------------------------------------------------------------------
    // D8 — InstallAsync Direct Dell BIOS .exe Elevated Happy Path & /r Polarity
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData(false, 0, new[] { "/s" })]
    [InlineData(false, 2, new[] { "/s" })]
    [InlineData(false, 3010, new[] { "/s" })]
    [InlineData(true, 2, new[] { "/s", "/r" })]
    public async Task InstallAsync_DirectExe_ElevatedHappyPath_EnforcesRebootFlagAndCleansAutoStaging(
        bool allowReboot,
        int exitCode,
        string[] expectedArgs)
    {
        const string url = "https://downloads.dell.com/FOLDER2/Latitude_7430_1.18.0.exe";
        var payload = TestPayload.FromString($"dell-bios-{allowReboot}-{exitCode}");
        var handler = new FakeBiosHttpHandler().MapBytes(url, payload.Bytes);

        string? observedAutoDir = null;
        var launcher = CreateGuardedLauncher((call, _) =>
        {
            if (call.BaseName.Equals("manage-bde.exe", StringComparison.OrdinalIgnoreCase))
                return Task.FromResult(new ProcessResult(0, "Suspended", ""));

            observedAutoDir = Path.GetDirectoryName(call.FileName);
            return Task.FromResult(new ProcessResult(exitCode, "Dell BIOS staged", ""));
        });

        var commands = RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: true);
        var progress = new SyncProgress<BiosInstallProgress>();
        var log = new CapturedLog();
        var provider = DellBiosUpdateProvider.CreateWithHandler(handler, commands: commands, log: log.Logger);

        var request = CreateDellExeInstallRequest(url, payload.Sha256, allowReboot: allowReboot);
        var result = await provider.InstallAsync(request, progress);

        Assert.True(result.Succeeded);
        Assert.Equal(BiosInstallStatus.StagedForReboot, result.Status);
        Assert.True(result.RequiresReboot);
        Assert.True(result.BitLockerSuspended);
        Assert.Equal(exitCode, result.ExitCode);

        Assert.Equal(2, launcher.Calls.Count);
        Assert.Equal("manage-bde.exe", launcher.Calls[0].BaseName, ignoreCase: true);
        Assert.Equal(expectedArgs, launcher.Calls[1].Arguments);

        Assert.NotNull(observedAutoDir);
        Assert.False(Directory.Exists(observedAutoDir!));
        Assert.Equal(BiosInstallStage.RebootRequired, progress.Reports[^1].Stage);
        log.AssertDoesNotContainSecret();
    }

    // -------------------------------------------------------------------------
    // D9 — InstallAsync DCU CLI Mode (Elevated & Exit 500 -> AlreadyUpToDate)
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData(false, 0, "-reboot=disable", BiosInstallStatus.StagedForReboot, true)]
    [InlineData(false, 1, "-reboot=disable", BiosInstallStatus.StagedForReboot, true)]
    [InlineData(true, 1, "-reboot=enable", BiosInstallStatus.StagedForReboot, true)]
    [InlineData(false, 500, "-reboot=disable", BiosInstallStatus.AlreadyUpToDate, false)]
    public async Task InstallAsync_DcuCliElevated_MapsArgsAndExitCodes(
        bool allowReboot,
        int exitCode,
        string expectedRebootFlag,
        BiosInstallStatus expectedStatus,
        bool expectedRequiresReboot)
    {
        var launcher = CreateGuardedLauncher((call, _) =>
        {
            if (call.BaseName.Equals("manage-bde.exe", StringComparison.OrdinalIgnoreCase))
                return Task.FromResult(new ProcessResult(0, "Suspended", ""));
            return Task.FromResult(new ProcessResult(exitCode, "DCU completed", ""));
        });

        var commands = RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: true);
        var provider = new DellBiosUpdateProvider(
            commands: commands,
            dcuCliPath: @"C:\Program Files\Dell\CommandUpdate\dcu-cli.exe");

        var request = CreateDellDcuInstallRequest(allowReboot: allowReboot);
        var result = await provider.InstallAsync(request);

        Assert.True(result.Succeeded);
        Assert.Equal(expectedStatus, result.Status);
        Assert.Equal(expectedRequiresReboot, result.RequiresReboot);
        Assert.Equal(exitCode, result.ExitCode);

        Assert.Equal(2, launcher.Calls.Count);
        Assert.Equal("dcu-cli.exe", launcher.Calls[1].BaseName, ignoreCase: true);
        Assert.Equal(["/applyUpdates", "-updateType=bios", "-silent", expectedRebootFlag], launcher.Calls[1].Arguments);
    }

    // -------------------------------------------------------------------------
    // D10 — Verification Security, SuspendBitLocker=false & SerialNumber Redaction
    // -------------------------------------------------------------------------

    [Fact]
    public async Task InstallAsync_DirectExe_VerificationFailuresAndSerialNumberRedaction()
    {
        using var staging = new TempStagingDir();
        const string url = "https://downloads.dell.com/FOLDER2/Latitude_7430_1.18.0.exe";
        var payload = TestPayload.FromString("dell-tampered-binary");
        var handler = new FakeBiosHttpHandler().MapBytes(url, payload.Bytes);
        var launcher = CreateGuardedLauncher();
        var commands = RecordingProcessLauncher.CreateCommandRunner(launcher, isProcessElevated: true);
        var provider = DellBiosUpdateProvider.CreateWithHandler(handler, commands: commands);

        // 1. Unsafe URL rejected before download
        var badUrlRes = await provider.InstallAsync(CreateDellExeInstallRequest("https://evil.com/bios.exe", payload.Sha256));
        Assert.False(badUrlRes.Succeeded);
        Assert.Empty(launcher.Calls);

        // 2. SHA-256 mismatch deletes staged file and never executes
        var mismatchRes = await provider.InstallAsync(CreateDellExeInstallRequest(url, new string('f', 64), stagingDir: staging.Path));
        Assert.False(mismatchRes.Succeeded);
        Assert.Empty(launcher.Calls);
        Assert.Empty(Directory.GetFiles(staging.Path));

        // 3. No SHA-256 + unsigned fails and deletes staged file
        var unsignedProvider = DellBiosUpdateProvider.CreateWithHandler(
            handler,
            commands: commands,
            signatureVerifier: new FakeSignatureVerifier(false));
        var unsignedRes = await unsignedProvider.InstallAsync(CreateDellExeInstallRequest(url, sha256: null, stagingDir: staging.Path));
        Assert.False(unsignedRes.Succeeded);
        Assert.Empty(launcher.Calls);
        Assert.Empty(Directory.GetFiles(staging.Path));

        // 4. Non-zero exit code with SerialNumber in stderr is redacted
        var failLauncher = CreateGuardedLauncher((_, _) =>
            Task.FromResult(new ProcessResult(13, "", $"Flash error SN={BiosIdentityFactory.SentinelSerialNumber}")));
        var log = new CapturedLog();
        var failProvider = DellBiosUpdateProvider.CreateWithHandler(
            handler,
            commands: RecordingProcessLauncher.CreateCommandRunner(failLauncher, isProcessElevated: true),
            log: log.Logger);

        var failRes = await failProvider.InstallAsync(
            CreateDellExeInstallRequest(url, payload.Sha256, suspendBitLocker: false, stagingDir: staging.Path));
        Assert.False(failRes.Succeeded);
        Assert.Equal(13, failRes.ExitCode);
        Assert.Contains("[REDACTED]", failRes.LogTail ?? "");
        Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, failRes.LogTail ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, failRes.Message, StringComparison.OrdinalIgnoreCase);
        log.AssertDoesNotContainSecret();
        Assert.True(Directory.Exists(staging.Path));
    }

    // -------------------------------------------------------------------------
    // D11 — Un-Elevated Agent Bridge (Direct EXE, DCU CLI, Live Pipe, Disconnected)
    // -------------------------------------------------------------------------

    [Fact]
    public async Task InstallAsync_UnElevatedBridge_RoutesBothDirectExeAndDcuCliWithCorrectSha256Semantics()
    {
        const string url = "https://downloads.dell.com/FOLDER2/Latitude_7430_1.18.0.exe";
        var payload = TestPayload.FromString("dell-agent-exe-payload");
        var handler = new FakeBiosHttpHandler().MapBytes(url, payload.Bytes);
        var localLauncher = CreateGuardedLauncher();
        var bridge = new RecordingBiosBridge(exitCode: 2);

        var exeProvider = DellBiosUpdateProvider.CreateWithHandler(
            handler,
            commands: RecordingProcessLauncher.CreateCommandRunner(localLauncher, isProcessElevated: false, elevatedBridge: bridge),
            signatureVerifier: new FakeSignatureVerifier(true));

        var exeRes = await exeProvider.InstallAsync(CreateDellExeInstallRequest(url, sha256: null, allowReboot: false));
        Assert.True(exeRes.Succeeded);
        Assert.Equal(BiosInstallStatus.StagedForReboot, exeRes.Status);
        Assert.Empty(localLauncher.Calls);
        var exeAgentReq = Assert.Single(bridge.InstallRequests);
        Assert.Equal("dell", exeAgentReq.VendorId);
        Assert.Equal(BiosAgentInstallModes.DellBiosExe, exeAgentReq.InstallMode);
        Assert.Equal(payload.Sha256, exeAgentReq.ExpectedSha256);

        // DCU CLI over bridge: ExpectedSha256 MUST be null and exit 500 -> AlreadyUpToDate
        var dcuBridge = new RecordingBiosBridge(exitCode: 500);
        var dcuProvider = new DellBiosUpdateProvider(
            commands: RecordingProcessLauncher.CreateCommandRunner(localLauncher, isProcessElevated: false, elevatedBridge: dcuBridge));

        var dcuRes = await dcuProvider.InstallAsync(CreateDellDcuInstallRequest(allowReboot: true));
        Assert.True(dcuRes.Succeeded);
        Assert.Equal(BiosInstallStatus.AlreadyUpToDate, dcuRes.Status);
        Assert.False(dcuRes.RequiresReboot);
        Assert.Empty(localLauncher.Calls);

        var dcuAgentReq = Assert.Single(dcuBridge.InstallRequests);
        Assert.Equal("dell", dcuAgentReq.VendorId);
        Assert.Equal(BiosAgentInstallModes.DellDcuCli, dcuAgentReq.InstallMode);
        Assert.Null(dcuAgentReq.ExpectedSha256);
        Assert.True(dcuAgentReq.AllowReboot);
    }

    [Fact]
    public async Task InstallAsync_UnElevatedLiveNamedPipe_DirectExeAndDcuCliRoundTrip()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var adminRoot = new TempStagingDir();
        using var fakeProgramFiles = new TempStagingDir();

        var dcuDir = Path.Combine(fakeProgramFiles.Path, "Dell", "CommandUpdate");
        Directory.CreateDirectory(dcuDir);
        var dcuExe = Path.Combine(dcuDir, "dcu-cli.exe");
        await File.WriteAllBytesAsync(dcuExe, Encoding.UTF8.GetBytes("fake-dcu-cli-binary"), cts.Token);

        const string url = "https://downloads.dell.com/FOLDER2/Latitude_7430_1.18.0.exe";
        var payload = TestPayload.FromString("dell-live-pipe-bios");
        var handler = new FakeBiosHttpHandler().MapBytes(url, payload.Bytes);

        var localLauncher = CreateGuardedLauncher();
        var agentLauncher = CreateGuardedLauncher((call, _) =>
        {
            if (call.BaseName.Equals("manage-bde.exe", StringComparison.OrdinalIgnoreCase))
                return Task.FromResult(new ProcessResult(0, "Protectors disabled.", ""));
            if (call.BaseName.Equals("dcu-cli.exe", StringComparison.OrdinalIgnoreCase))
                return Task.FromResult(new ProcessResult(1, "DCU reboot required", ""));
            return Task.FromResult(new ProcessResult(2, "Dell BIOS staged", ""));
        });

        var ops = new AgentBiosOperations(
            agentLauncher,
            new FakeSignatureVerifier(true),
            stagingRoot: adminRoot.Path,
            allowedToolRoots: [fakeProgramFiles.Path]);

        var (server, serverTask, client) = await StartPipeAsync(agentLauncher, ops, cts.Token);
        using (server)
        {
            await using (client)
            {
                var provider = DellBiosUpdateProvider.CreateWithHandler(
                    handler,
                    commands: RecordingProcessLauncher.CreateCommandRunner(localLauncher, isProcessElevated: false),
                    elevatedBridge: client,
                    isProcessElevated: () => false);

                var exeResult = await provider.InstallAsync(
                    CreateDellExeInstallRequest(url, payload.Sha256, allowReboot: false),
                    ct: cts.Token);

                Assert.True(exeResult.Succeeded);
                Assert.Equal(BiosInstallStatus.StagedForReboot, exeResult.Status);
                Assert.Equal(2, exeResult.ExitCode);

                var dcuResult = await provider.InstallAsync(
                    CreateDellDcuInstallRequest(allowReboot: false, suspendBitLocker: false),
                    ct: cts.Token);

                Assert.True(dcuResult.Succeeded);
                Assert.Equal(BiosInstallStatus.StagedForReboot, dcuResult.Status);
                Assert.Equal(1, dcuResult.ExitCode);
            }

            await serverTask;
        }

        Assert.Empty(localLauncher.Calls);
        Assert.Equal(3, agentLauncher.Calls.Count);
        Assert.Equal("manage-bde.exe", agentLauncher.Calls[0].BaseName, ignoreCase: true);
        Assert.Equal(["/s"], agentLauncher.Calls[1].Arguments);
        Assert.Equal("dcu-cli.exe", agentLauncher.Calls[2].BaseName, ignoreCase: true);
        Assert.Equal(["/applyUpdates", "-updateType=bios", "-silent", "-reboot=disable"], agentLauncher.Calls[2].Arguments);
        Assert.Empty(Directory.GetFileSystemEntries(adminRoot.Path));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task InstallAsync_UnElevatedDisconnectedBridge_FailsClosed(bool suspendBitLocker)
    {
        const string url = "https://downloads.dell.com/FOLDER2/Latitude_7430_1.18.0.exe";
        var payload = TestPayload.FromString("dell-disconnected");
        var handler = new FakeBiosHttpHandler().MapBytes(url, payload.Bytes);
        var localLauncher = CreateGuardedLauncher();
        var disconnected = new RecordingBiosBridge(isConnected: false);

        var provider = DellBiosUpdateProvider.CreateWithHandler(
            handler,
            commands: RecordingProcessLauncher.CreateCommandRunner(localLauncher, isProcessElevated: false, elevatedBridge: disconnected));

        var result = await provider.InstallAsync(CreateDellExeInstallRequest(url, payload.Sha256, suspendBitLocker: suspendBitLocker));

        Assert.False(result.Succeeded);
        Assert.Equal(BiosInstallStatus.Failed, result.Status);
        Assert.Equal(SystemCommandRunner.AgentFailedExitCode, result.ExitCode);
        Assert.Empty(localLauncher.Calls);
        Assert.Empty(disconnected.InstallRequests);
    }

    // -------------------------------------------------------------------------
    // D12 — Iteration 2 Hardening Regressions (DCU Symlinks, Percent-Encoded Traversal, SerialNumber Redaction)
    // -------------------------------------------------------------------------

    [Theory]
    [InlineData("downloads.dell.com", "FOLDER/%2e%2e/other/evil.exe")]
    [InlineData("downloads.dell.com/catalog/sub", "%2e%2e/%2e%2e/evil.exe")]
    [InlineData("downloads.dell.com", "FOLDER/..%2fother/evil.exe")]
    [InlineData("downloads.dell.com", "%2e%2e%2fother/evil.exe")]
    [InlineData("downloads.dell.com", "FOLDER/..%5cother/evil.exe")]
    [InlineData("downloads.dell.com", "FOLDER/%252e%252e/other/evil.exe")]
    [InlineData("downloads.dell.com/catalog/sub", "https://downloads.dell.com/catalog/sub/%2e%2e/%2e%2e/evil.exe")]
    [InlineData("downloads.dell.com", "FOLDER/bios%00.exe")]
    public async Task GetLatestVersionAsync_PercentEncodedTraversalInCatalogPath_ReturnsFailed(string baseLocation, string badPath)
    {
        var xml = $"""
            <Manifest baseLocation="{baseLocation}">
              <SoftwareComponent packageID="BAD" path="{badPath}" vendorVersion="2.0.0">
                <ComponentType value="BIOS"/>
                <SupportedSystems><Brand><Model systemID="0B1A"/></Brand></SupportedSystems>
              </SoftwareComponent>
            </Manifest>
            """;

        var handler = new FakeBiosHttpHandler().MapText(DellBiosUpdateProvider.DefaultCatalogUrl, xml, "application/xml");
        var provider = DellBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Dell();

        var latest = await provider.GetLatestVersionAsync(identity, identity.CurrentBios);

        Assert.Equal(BiosCheckStatus.Failed, latest.Status);
    }

    [Fact]
    public async Task GetLatestVersionAsync_BaseLocationWithPathPrefix_RetainsPrefix()
    {
        const string xml = """
            <Manifest baseLocation="downloads.dell.com/catalog/sub">
              <SoftwareComponent packageID="SUB1" path="FOLDER2/Latitude_7430_1.18.0.exe" vendorVersion="1.18.0">
                <ComponentType value="BIOS"/>
                <SupportedSystems><Brand><Model systemID="0B1A"/></Brand></SupportedSystems>
              </SoftwareComponent>
            </Manifest>
            """;

        var handler = new FakeBiosHttpHandler().MapText(DellBiosUpdateProvider.DefaultCatalogUrl, xml, "application/xml");
        var provider = DellBiosUpdateProvider.CreateWithHandler(handler);
        var identity = BiosIdentityFactory.Dell(biosVersion: "1.14.0");

        var latest = await provider.GetLatestVersionAsync(identity, identity.CurrentBios);

        Assert.Equal(BiosCheckStatus.UpdateAvailable, latest.Status);
        Assert.Equal("https://downloads.dell.com/catalog/sub/FOLDER2/Latitude_7430_1.18.0.exe", latest.DownloadUrl);
    }

    [Fact]
    public async Task DcuCli_LeafSymlinkAndAncestorDirSymlink_RejectedOnBothScanAndElevatedInstall()
    {
        using var workDir = new TempStagingDir();
        var outsideDir = Path.Combine(workDir.Path, "outside");
        var trustedDir = Path.Combine(workDir.Path, "trusted");
        Directory.CreateDirectory(outsideDir);
        Directory.CreateDirectory(trustedDir);

        var outsideTarget = Path.Combine(outsideDir, "dcu-cli.exe");
        await File.WriteAllTextAsync(outsideTarget, "fake-outside-binary");

        // 1. Leaf symlink: trusted/dcu-cli.exe -> outside/dcu-cli.exe
        var leafSymlink = Path.Combine(trustedDir, "dcu-cli.exe");
        File.CreateSymbolicLink(leafSymlink, outsideTarget);

        // 2. Ancestor directory symlink: parentLink -> outside (contains dcu-cli.exe)
        var ancestorLinkDir = Path.Combine(workDir.Path, "parentLink");
        Directory.CreateSymbolicLink(ancestorLinkDir, outsideDir);
        var ancestorSymlinkExe = Path.Combine(ancestorLinkDir, "dcu-cli.exe");

        // 3. Dangling symlink
        var danglingDir = Path.Combine(workDir.Path, "dangling");
        Directory.CreateDirectory(danglingDir);
        var danglingSymlink = Path.Combine(danglingDir, "dcu-cli.exe");
        File.CreateSymbolicLink(danglingSymlink, Path.Combine(outsideDir, "missing-target.exe"));

        // 4. Directory masquerading as dcu-cli.exe
        var dirAsFileRoot = Path.Combine(workDir.Path, "dirmasquerade");
        var dirNamedExe = Path.Combine(dirAsFileRoot, "dcu-cli.exe");
        Directory.CreateDirectory(dirNamedExe);

        string[] unsafePaths = [leafSymlink, ancestorSymlinkExe, danglingSymlink, dirNamedExe];
        var identity = BiosIdentityFactory.Dell();

        foreach (var unsafePath in unsafePaths)
        {
            // Verify with both non-scripted real SystemProcessLauncher AND scripted RecordingProcessLauncher.
            var realCommands = new SystemCommandRunner(new SystemProcessLauncher(), isProcessElevated: () => true);
            var realProvider = new DellBiosUpdateProvider(
                commands: realCommands,
                signatureVerifier: new FakeSignatureVerifier(true),
                isProcessElevated: () => true,
                dcuCliPath: unsafePath);

            var scanReal = await realProvider.GetLatestVersionAsync(identity, identity.CurrentBios);
            Assert.Equal(BiosCheckStatus.Failed, scanReal.Status);

            var installReal = await realProvider.InstallAsync(CreateDellDcuInstallRequest(suspendBitLocker: false));
            Assert.False(installReal.Succeeded);
            Assert.Equal(BiosInstallStatus.Failed, installReal.Status);

            var scriptedLauncher = CreateGuardedLauncher();
            var scriptedCommands = RecordingProcessLauncher.CreateCommandRunner(scriptedLauncher, isProcessElevated: true);
            var scriptedProvider = new DellBiosUpdateProvider(
                commands: scriptedCommands,
                signatureVerifier: new FakeSignatureVerifier(true),
                isProcessElevated: () => true,
                dcuCliPath: unsafePath);

            var scanScripted = await scriptedProvider.GetLatestVersionAsync(identity, identity.CurrentBios);
            Assert.Equal(BiosCheckStatus.Failed, scanScripted.Status);

            var installScripted = await scriptedProvider.InstallAsync(CreateDellDcuInstallRequest(suspendBitLocker: false));
            Assert.False(installScripted.Succeeded);
            Assert.Equal(BiosInstallStatus.Failed, installScripted.Status);
            Assert.Empty(scriptedLauncher.Calls);
        }
    }

    [Fact]
    public async Task GetLatestVersionAsync_DcuMalformedXmlAndCatalogMalformedXml_RedactSerialNumber()
    {
        var malformedDcuXml = $"<updates><{BiosIdentityFactory.SentinelSerialNumber}></updates>";
        var launcher = CreateGuardedLauncher(async (call, ct) =>
        {
            var reportDir = call.Arguments.Single(a => a.StartsWith("-report=", StringComparison.Ordinal))["-report=".Length..];
            await File.WriteAllTextAsync(Path.Combine(reportDir, "DCUApplicableUpdates.xml"), malformedDcuXml, ct);
            return new ProcessResult(0, "", "");
        });

        var identity = BiosIdentityFactory.Dell();
        var dcuProvider = new DellBiosUpdateProvider(
            commands: RecordingProcessLauncher.CreateCommandRunner(launcher),
            dcuCliPath: @"C:\Program Files\Dell\CommandUpdate\dcu-cli.exe");

        var dcuLatest = await dcuProvider.GetLatestVersionAsync(identity, identity.CurrentBios);
        Assert.Equal(BiosCheckStatus.Failed, dcuLatest.Status);
        Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, dcuLatest.Message, StringComparison.OrdinalIgnoreCase);

        var malformedCatalog = $"<Manifest><{BiosIdentityFactory.SentinelSerialNumber}></Manifest>";
        var handler = new FakeBiosHttpHandler().MapText(DellBiosUpdateProvider.DefaultCatalogUrl, malformedCatalog, "application/xml");
        var catalogProvider = DellBiosUpdateProvider.CreateWithHandler(handler);

        var catalogLatest = await catalogProvider.GetLatestVersionAsync(identity, identity.CurrentBios);
        Assert.Equal(BiosCheckStatus.Failed, catalogLatest.Status);
        Assert.DoesNotContain(BiosIdentityFactory.SentinelSerialNumber, catalogLatest.Message, StringComparison.OrdinalIgnoreCase);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static BiosInstallRequest CreateDellExeInstallRequest(
        string downloadUrl,
        string? sha256,
        bool suspendBitLocker = true,
        bool allowReboot = false,
        string? stagingDir = null)
    {
        var system = BiosIdentityFactory.Dell();
        var target = BiosLatestInfo.UpdateAvailable(
            providerId: "dell",
            latestVersion: "1.18.0",
            downloadUrl: downloadUrl,
            sha256: sha256);

        return new BiosInstallRequest(
            System: system,
            Current: system.CurrentBios,
            Target: target,
            Approved: true,
            ApprovedBy: "operator@contoso.com",
            SuspendBitLocker: suspendBitLocker,
            AllowReboot: allowReboot,
            VerifyHash: true,
            StagingDirectory: stagingDir);
    }

    private static BiosInstallRequest CreateDellDcuInstallRequest(
        bool allowReboot = false,
        bool suspendBitLocker = true)
    {
        var system = BiosIdentityFactory.Dell();
        var target = BiosLatestInfo.UpdateAvailable(
            providerId: "dell",
            latestVersion: "1.19.0",
            downloadUrl: null,
            sha256: null,
            metadata: new Dictionary<string, string> { ["installMode"] = BiosAgentInstallModes.DellDcuCli });

        return new BiosInstallRequest(
            System: system,
            Current: system.CurrentBios,
            Target: target,
            Approved: true,
            ApprovedBy: "operator@contoso.com",
            SuspendBitLocker: suspendBitLocker,
            AllowReboot: allowReboot,
            VerifyHash: true);
    }

    private static RecordingProcessLauncher CreateGuardedLauncher(
        Func<RecordedProcessCall, CancellationToken, Task<ProcessResult>>? inner = null) =>
        new((call, ct) =>
        {
            if (ForbiddenShellBinaries.Contains(call.BaseName))
                throw new InvalidOperationException($"Pure-C# violation: forbidden shell binary '{call.FileName}' invoked.");

            foreach (var arg in call.Arguments)
            {
                foreach (var ext in ForbiddenScriptExtensions)
                {
                    if (arg.EndsWith(ext, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException($"Pure-C# violation: forbidden script argument '{arg}' passed.");
                }
            }

            return inner is not null ? inner(call, ct) : Task.FromResult(new ProcessResult(0, "", ""));
        });

    private static async Task<(AdminPipeServer Server, Task ServerTask, AdminPipeClient Client)> StartPipeAsync(
        IProcessLauncher agentLauncher,
        IAgentBiosOperations biosOps,
        CancellationToken ct)
    {
        var pipeName = $"rpd-bios-dell-test-{Guid.NewGuid():N}";
        var server = new AdminPipeServer(
            new AdminPipeServerOptions
            {
                PipeName = pipeName,
                ExpectedClientPid = Environment.ProcessId,
            },
            launcher: agentLauncher,
            biosOperations: biosOps);

        var serverTask = server.RunSingleSessionAsync(ct);
        var client = await AdminPipeClient.ConnectAsync(pipeName, TimeSpan.FromSeconds(10), ct);
        return (server, serverTask, client);
    }

    private sealed class RecordingBiosBridge(bool isConnected = true, int exitCode = 0) : IElevatedCommandBridge
    {
        public bool IsConnected => isConnected;
        public List<string> BitLockerDrives { get; } = [];
        public List<BiosAgentInstallRequest> InstallRequests { get; } = [];

        public Task<ProcessResult?> RunElevatedAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct, Action<string>? outputLine = null) =>
            Task.FromResult<ProcessResult?>(null);

        public Task<SensorSnapshot?> ReadSensorsAsync(CancellationToken ct = default) => Task.FromResult<SensorSnapshot?>(null);
        public Task<IReadOnlyList<DriveHealth>?> ReadDrivesAsync(CancellationToken ct = default) => Task.FromResult<IReadOnlyList<DriveHealth>?>(null);

        public Task<BiosAgentBitLockerResult> SuspendBitLockerAsync(string systemDrive, CancellationToken ct = default)
        {
            BitLockerDrives.Add(systemDrive);
            return Task.FromResult(new BiosAgentBitLockerResult(Suspended: true, Allowed: true, ExitCode: 0));
        }

        public Task<BiosAgentInstallResult> RunBiosInstallerAsync(BiosAgentInstallRequest request, CancellationToken ct = default)
        {
            InstallRequests.Add(request);
            return Task.FromResult(new BiosAgentInstallResult(Executed: true, Allowed: true, ExitCode: exitCode, TimedOut: false, LogTail: "Agent Dell OK"));
        }
    }
}
